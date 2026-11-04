package relay

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"postern/internal/envelope"
)

// Store errors.
var (
	errDuplicate = errors.New("relay store: duplicate id")
	errQueueFull = errors.New("relay store: recipient queue full")
)

// Store is the relay's SQLite database. It holds envelopes exactly as the
// relay accepted them (routing fields readable, content sealed) and the ids
// seen in the retention window. There are no backups by design.
type Store struct {
	db *sql.DB
}

// storedEnvelope is one row handed to a poller.
type storedEnvelope struct {
	Seq int64
	Raw []byte
}

const schema = `
CREATE TABLE IF NOT EXISTS envelopes (
	seq         INTEGER PRIMARY KEY AUTOINCREMENT,
	id          TEXT    NOT NULL UNIQUE,
	from_peer   TEXT    NOT NULL,
	to_peer     TEXT    NOT NULL,
	thread      TEXT    NOT NULL,
	ts          INTEGER NOT NULL,
	received_at INTEGER NOT NULL,
	raw         BLOB    NOT NULL
);
CREATE INDEX IF NOT EXISTS envelopes_to_seq ON envelopes (to_peer, seq);
CREATE INDEX IF NOT EXISTS envelopes_received_at ON envelopes (received_at);
CREATE TABLE IF NOT EXISTS seen_ids (
	id      TEXT    PRIMARY KEY,
	seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS seen_ids_seen_at ON seen_ids (seen_at);
`

// OpenStore opens (creating if needed) the relay database at path. A
// missing parent directory is created with mode 0700 and the database
// file is kept at 0600; SQLite gives its -wal and -shm files the same
// mode as the database file.
func OpenStore(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("relay store: empty path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("relay store: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return nil, fmt.Errorf("relay store: %w", err)
	}
	f, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("relay store: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, fmt.Errorf("relay store: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("relay store: %w", err)
	}

	// secure_delete zeroes freed pages so acked and expired ciphertext
	// does not linger; temp_store keeps temporary tables off the
	// (read-only) container filesystem.
	dsn := "file:" + (&url.URL{Path: abs}).EscapedPath() +
		"?_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=secure_delete(1)" +
		"&_pragma=temp_store(MEMORY)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("relay store: %w", err)
	}
	// One connection: the relay is tiny, writes serialize anyway, and
	// this rules out SQLITE_BUSY between our own connections.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("relay store: schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// seen reports whether id was accepted within the retention window
// (whether or not it has been acked since).
func (s *Store) seen(ctx context.Context, id string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM seen_ids WHERE id = ?`, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// insert stores e (raw is its JSON) and records its id, atomically. It
// returns errDuplicate if the id was already seen and errQueueFull if the
// recipient already has maxQueued unacked envelopes.
func (s *Store) insert(ctx context.Context, e envelope.Envelope, raw []byte, now int64, maxQueued int) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var one int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM seen_ids WHERE id = ?`, e.ID).Scan(&one)
	switch {
	case err == nil:
		return 0, errDuplicate
	case !errors.Is(err, sql.ErrNoRows):
		return 0, err
	}
	var queued int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM envelopes WHERE to_peer = ?`, e.To).Scan(&queued); err != nil {
		return 0, err
	}
	if queued >= maxQueued {
		return 0, errQueueFull
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO envelopes (id, from_peer, to_peer, thread, ts, received_at, raw) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.From, e.To, e.Thread, e.TS, now, raw)
	if err != nil {
		return 0, err
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO seen_ids (id, seen_at) VALUES (?, ?)`, e.ID, now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return seq, nil
}

// pending returns up to limit unacked envelopes for to with seq > after,
// received at or after notBefore, ordered by seq.
func (s *Store) pending(ctx context.Context, to string, after, notBefore int64, limit int) ([]storedEnvelope, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT seq, raw FROM envelopes WHERE to_peer = ? AND seq > ? AND received_at >= ? ORDER BY seq LIMIT ?`,
		to, after, notBefore, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storedEnvelope
	for rows.Next() {
		var se storedEnvelope
		if err := rows.Scan(&se.Seq, &se.Raw); err != nil {
			return nil, err
		}
		out = append(out, se)
	}
	return out, rows.Err()
}

// ack deletes the envelope id if it is addressed to to. The id stays in
// seen_ids so a replay is still rejected.
func (s *Store) ack(ctx context.Context, id, to string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM envelopes WHERE id = ? AND to_peer = ?`, id, to)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// expire deletes envelopes received, and ids seen, before cutoff (unix
// seconds).
func (s *Store) expire(ctx context.Context, cutoff int64) (envelopes, ids int64, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM envelopes WHERE received_at < ?`, cutoff)
	if err != nil {
		return 0, 0, err
	}
	envelopes, _ = res.RowsAffected()
	res, err = tx.ExecContext(ctx, `DELETE FROM seen_ids WHERE seen_at < ?`, cutoff)
	if err != nil {
		return 0, 0, err
	}
	ids, _ = res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return envelopes, ids, nil
}
