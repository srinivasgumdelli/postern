package bridge

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"postern/internal/envelope"
	"postern/internal/ulid"
)

// The local database holds plaintext by design: it is this machine's
// inbox and outbox. It lives in a 0700 directory with 0600 permissions;
// SQLite gives the -wal and -shm files the same mode as the main file.

const schemaVersion = 1

var schema = []string{
	`CREATE TABLE IF NOT EXISTS messages (
		seq             INTEGER PRIMARY KEY AUTOINCREMENT,
		id              TEXT    NOT NULL UNIQUE,
		direction       TEXT    NOT NULL CHECK (direction IN ('in', 'out')),
		peer            TEXT    NOT NULL,
		session         TEXT    NOT NULL,
		thread          TEXT    NOT NULL,
		subject         TEXT    NOT NULL,
		body            TEXT    NOT NULL,
		reply_to        TEXT,
		created_at      INTEGER NOT NULL,
		ts              INTEGER NOT NULL DEFAULT 0,
		read_at         INTEGER,
		state           TEXT    CHECK (state IS NULL OR state IN ('pending', 'sent', 'failed')),
		attempts        INTEGER NOT NULL DEFAULT 0,
		next_attempt_at INTEGER NOT NULL DEFAULT 0,
		lease_until     INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX IF NOT EXISTS messages_thread_created ON messages (thread, created_at)`,
	`CREATE INDEX IF NOT EXISTS messages_dir_session_created ON messages (direction, session, created_at)`,
	`CREATE INDEX IF NOT EXISTS messages_dir_created ON messages (direction, created_at)`,
	`CREATE INDEX IF NOT EXISTS messages_outbox ON messages (state, next_attempt_at)`,
	`CREATE TABLE IF NOT EXISTS threads (
		thread      TEXT    PRIMARY KEY,
		peer        TEXT    NOT NULL,
		created_at  INTEGER NOT NULL,
		reset_at    INTEGER,
		reset_seq   INTEGER NOT NULL DEFAULT 0,
		tripped_at  INTEGER,
		trip_reason TEXT
	)`,
}

var (
	errNoDatabase   = errors.New("database does not exist")
	errNotRegular   = errors.New("database path is not a regular file")
	errSchemaTooNew = errors.New("database schema is newer than this binary")
)

// dsn builds a modernc.org/sqlite DSN. Every connection gets a busy
// timeout and WAL mode, and every BeginTx is BEGIN IMMEDIATE so that
// check-then-insert sequences take the write lock up front (a deferred
// transaction upgrading to a writer can fail with SQLITE_BUSY no matter
// how long the busy timeout is).
func dsn(absPath string) string {
	q := []string{
		"_pragma=busy_timeout(10000)",
		"_pragma=journal_mode(WAL)",
		"_pragma=synchronous(NORMAL)",
		"_pragma=foreign_keys(1)",
		"_txlock=immediate",
	}
	return "file:" + (&url.URL{Path: absPath}).EscapedPath() + "?" + strings.Join(q, "&")
}

// openDB opens the shared database. With create it makes the directory
// (0700) and the file (0600) if missing; without it a missing file is
// errNoDatabase.
func openDB(path string, create bool) (*sql.DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if create {
		if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return nil, err
		}
		f.Close()
	}
	fi, err := os.Stat(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errNoDatabase
		}
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errNotRegular
	}
	for _, p := range []string{abs, abs + "-wal", abs + "-shm"} {
		if fi, err := os.Stat(p); err == nil && fi.Mode().Perm()&0o077 != 0 {
			if err := os.Chmod(p, 0o600); err != nil {
				return nil, err
			}
		}
	}
	db, err := sql.Open("sqlite", dsn(abs))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := migrate(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var v int
	if err := tx.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	switch {
	case v == schemaVersion:
		return nil
	case v > schemaVersion:
		return errSchemaTooNew
	}
	for _, s := range schema {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion)); err != nil {
		return err
	}
	return tx.Commit()
}

type threadRow struct {
	peer       string
	resetSeq   int64
	tripped    bool
	tripReason string
}

func getThread(ctx context.Context, tx *sql.Tx, thread string) (threadRow, bool, error) {
	var (
		t       threadRow
		tripped sql.NullInt64
		reason  sql.NullString
	)
	err := tx.QueryRowContext(ctx,
		`SELECT peer, reset_seq, tripped_at, trip_reason FROM threads WHERE thread = ?`, thread).
		Scan(&t.peer, &t.resetSeq, &tripped, &reason)
	if errors.Is(err, sql.ErrNoRows) {
		return threadRow{}, false, nil
	}
	if err != nil {
		return threadRow{}, false, err
	}
	t.tripped = tripped.Valid
	t.tripReason = reason.String
	return t, true, nil
}

func tripThread(ctx context.Context, tx *sql.Tx, thread, reason string, now time.Time) error {
	_, err := tx.ExecContext(ctx,
		`UPDATE threads SET tripped_at = ?, trip_reason = ? WHERE thread = ?`,
		now.UnixMilli(), reason, thread)
	return err
}

type threadInfo struct {
	peer         string
	firstSubject string
	lastInbound  string
}

// threadInfo loads what Reply needs about a local thread.
func (b *Bridge) threadInfo(ctx context.Context, thread string) (threadInfo, bool, error) {
	var ti threadInfo
	err := b.db.QueryRowContext(ctx, `SELECT peer FROM threads WHERE thread = ?`, thread).Scan(&ti.peer)
	if errors.Is(err, sql.ErrNoRows) {
		return threadInfo{}, false, nil
	}
	if err != nil {
		return threadInfo{}, false, b.internal(ctx, "load thread", err)
	}
	err = b.db.QueryRowContext(ctx,
		`SELECT subject FROM messages WHERE thread = ? ORDER BY seq LIMIT 1`, thread).Scan(&ti.firstSubject)
	if errors.Is(err, sql.ErrNoRows) {
		return threadInfo{}, false, nil
	}
	if err != nil {
		return threadInfo{}, false, b.internal(ctx, "load thread subject", err)
	}
	err = b.db.QueryRowContext(ctx,
		`SELECT id FROM messages WHERE thread = ? AND direction = 'in' ORDER BY seq DESC LIMIT 1`, thread).
		Scan(&ti.lastInbound)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return threadInfo{}, false, b.internal(ctx, "load thread reply_to", err)
	}
	return ti, true, nil
}

// storeInbound inserts an opened inbound message. It returns inserted =
// false for a duplicate id, and a non-empty drop reason when the thread
// already belongs to a different peer (a peer may not inject into
// another peer's thread).
func (b *Bridge) storeInbound(ctx context.Context, m envelope.Message) (inserted bool, drop string, err error) {
	now := b.now()
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return false, "", b.internal(ctx, "begin inbound", err)
	}
	defer tx.Rollback()
	th, found, err := getThread(ctx, tx, m.Thread)
	if err != nil {
		return false, "", b.internal(ctx, "load thread", err)
	}
	if found && th.peer != m.From {
		return false, "thread_peer_mismatch", nil
	}
	if !found {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO threads (thread, peer, created_at) VALUES (?, ?, ?)`,
			m.Thread, m.From, now.UnixMilli()); err != nil {
			return false, "", b.internal(ctx, "insert thread", err)
		}
	}
	res, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO messages (id, direction, peer, session, thread, subject, body, reply_to, created_at, ts)
		VALUES (?, 'in', ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.ID, m.From, m.Session, m.Thread, m.Subject, m.Body, nullable(m.ReplyTo), now.UnixMilli(), m.TS)
	if err != nil {
		return false, "", b.internal(ctx, "insert inbound", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, "", b.internal(ctx, "insert inbound", err)
	}
	if err := tx.Commit(); err != nil {
		return false, "", b.internal(ctx, "commit inbound", err)
	}
	return n == 1, "", nil
}

const (
	defaultInboxLimit = 20
	maxInboxLimit     = 100
	maxMarkReadIDs    = 1000
)

// CheckInbox returns inbound messages in local arrival order.
func (b *Bridge) CheckInbox(ctx context.Context, q InboxQuery) ([]InboxMessage, error) {
	limit := q.Limit
	switch {
	case limit < 0:
		return nil, fmt.Errorf("%w: limit must not be negative", ErrInvalid)
	case limit == 0:
		limit = defaultInboxLimit
	case limit > maxInboxLimit:
		limit = maxInboxLimit
	}
	where := []string{`direction = 'in'`}
	var args []any
	if q.SinceID != "" {
		if !ulid.Valid(q.SinceID) {
			return nil, fmt.Errorf("%w: since_id is not a valid message id", ErrInvalid)
		}
		var seq int64
		err := b.db.QueryRowContext(ctx,
			`SELECT seq FROM messages WHERE id = ? AND direction = 'in'`, q.SinceID).Scan(&seq)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: since_id is not a message in this inbox", ErrInvalid)
		}
		if err != nil {
			return nil, b.internal(ctx, "inbox since", err)
		}
		where = append(where, `seq > ?`)
		args = append(args, seq)
	}
	if q.Thread != "" {
		if !envelope.ValidThreadID(q.Thread) {
			return nil, fmt.Errorf("%w: thread is not a valid thread id", ErrInvalid)
		}
		where = append(where, `thread = ?`)
		args = append(args, q.Thread)
	}
	if !q.IncludeRead {
		where = append(where, `read_at IS NULL`)
	}
	args = append(args, limit)
	rows, err := b.db.QueryContext(ctx, `
		SELECT id, thread, peer, session, subject, body, created_at, read_at
		FROM messages WHERE `+strings.Join(where, " AND ")+`
		ORDER BY seq LIMIT ?`, args...)
	if err != nil {
		return nil, b.internal(ctx, "inbox query", err)
	}
	defer rows.Close()
	out := []InboxMessage{}
	for rows.Next() {
		var (
			m       InboxMessage
			created int64
			readAt  sql.NullInt64
		)
		if err := rows.Scan(&m.ID, &m.Thread, &m.FromPeer, &m.FromSession, &m.Subject, &m.Body, &created, &readAt); err != nil {
			return nil, b.internal(ctx, "inbox scan", err)
		}
		m.ReceivedAt = time.UnixMilli(created)
		m.Read = readAt.Valid
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, b.internal(ctx, "inbox rows", err)
	}
	return out, nil
}

// MarkRead marks inbound messages read and returns how many changed.
// Outbound ids and already-read ids are left alone and not counted.
func (b *Bridge) MarkRead(ctx context.Context, ids []string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	if len(ids) > maxMarkReadIDs {
		return 0, fmt.Errorf("%w: at most %d ids at once", ErrInvalid, maxMarkReadIDs)
	}
	for _, id := range ids {
		if !ulid.Valid(id) {
			return 0, fmt.Errorf("%w: ids must be message ids", ErrInvalid)
		}
	}
	now := b.now().UnixMilli()
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, b.internal(ctx, "begin mark read", err)
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx,
		`UPDATE messages SET read_at = ? WHERE id = ? AND direction = 'in' AND read_at IS NULL`)
	if err != nil {
		return 0, b.internal(ctx, "mark read", err)
	}
	defer stmt.Close()
	total := 0
	for _, id := range ids {
		res, err := stmt.ExecContext(ctx, now, id)
		if err != nil {
			return 0, b.internal(ctx, "mark read", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, b.internal(ctx, "mark read", err)
		}
		total += int(n)
	}
	if err := tx.Commit(); err != nil {
		return 0, b.internal(ctx, "commit mark read", err)
	}
	return total, nil
}

// ResetThread clears a thread's circuit breaker and restarts its cap and
// burst counts from now. It needs no keys, only the database, so a human
// can run it from the CLI (`postern thread reset THREAD`).
//
// The restart point is recorded both as a time (reset_at, informational)
// and as the highest message sequence number at that moment (reset_seq).
// Counts use the sequence number, so they do not depend on clocks agreeing
// between the CLI and the bridge processes.
func ResetThread(ctx context.Context, dbPath, thread string) error {
	if !envelope.ValidThreadID(thread) {
		return fmt.Errorf("%w: thread is not a valid thread id", ErrInvalid)
	}
	db, err := openDB(dbPath, false)
	if errors.Is(err, errNoDatabase) {
		return fmt.Errorf("%w: no local thread with that id", ErrUnknownThread)
	}
	if err != nil {
		return fmt.Errorf("bridge: cannot open database: %s", safeFSError(err))
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return resetErr(ctx)
	}
	defer tx.Rollback()
	var maxSeq int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) FROM messages`).Scan(&maxSeq); err != nil {
		return resetErr(ctx)
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE threads SET tripped_at = NULL, trip_reason = NULL, reset_at = ?, reset_seq = ?
		WHERE thread = ?`, time.Now().UnixMilli(), maxSeq, thread)
	if err != nil {
		return resetErr(ctx)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return resetErr(ctx)
	}
	if n == 0 {
		return fmt.Errorf("%w: no local thread with that id", ErrUnknownThread)
	}
	if err := tx.Commit(); err != nil {
		return resetErr(ctx)
	}
	return nil
}

func resetErr(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errInternal
}
