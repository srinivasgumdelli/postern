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

// The local database is this machine's inbox and outbox. Subjects,
// bodies and session names are sealed per row (see seal.go); routing
// metadata (ids, peers, threads, times, states) is plain. It lives in a
// 0700 directory with 0600 permissions; SQLite gives the -wal and -shm
// files the same mode as the main file.
//
// Schema 1 (plaintext content) is refused, not migrated: nothing was
// deployed with it. Schema 2 is migrated in place to 3, which adds the
// seen_ids tombstones (inbound dedup that outlives pruned messages; see
// prune.go) and the per-thread count of pruned messages.
//
// secure_delete is on for every connection, so deleted rows (sealed
// content, ids, routing metadata) are overwritten with zeros instead of
// lingering in free pages.

const schemaVersion = 3

var schema = []string{
	`CREATE TABLE IF NOT EXISTS messages (
		seq             INTEGER PRIMARY KEY AUTOINCREMENT,
		id              TEXT    NOT NULL UNIQUE,
		direction       TEXT    NOT NULL CHECK (direction IN ('in', 'out')),
		peer            TEXT    NOT NULL,
		session_tag     BLOB,
		thread          TEXT    NOT NULL,
		sealed          BLOB    NOT NULL,
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
	`CREATE INDEX IF NOT EXISTS messages_dir_session_created ON messages (direction, session_tag, created_at)`,
	`CREATE INDEX IF NOT EXISTS messages_dir_created ON messages (direction, created_at)`,
	`CREATE INDEX IF NOT EXISTS messages_outbox ON messages (state, next_attempt_at)`,
	`CREATE TABLE IF NOT EXISTS threads (
		thread      TEXT    PRIMARY KEY,
		peer        TEXT    NOT NULL,
		created_at  INTEGER NOT NULL,
		reset_at    INTEGER,
		reset_seq   INTEGER NOT NULL DEFAULT 0,
		tripped_at  INTEGER,
		trip_reason TEXT,
		pruned      INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE TABLE IF NOT EXISTS meta (
		k TEXT PRIMARY KEY,
		v BLOB NOT NULL
	)`,
	seenIDsTable,
	seenIDsIndex,
}

// threads.pruned counts the thread's messages after reset_seq that
// retention deleted, so the thread cap still counts them.
//
// seen_ids holds every inbound id for tombstoneRetention after it was
// received, whether or not its message is still stored.
const (
	seenIDsTable = `CREATE TABLE IF NOT EXISTS seen_ids (
		id      TEXT    PRIMARY KEY,
		seen_at INTEGER NOT NULL
	) WITHOUT ROWID`
	seenIDsIndex = `CREATE INDEX IF NOT EXISTS seen_ids_seen_at ON seen_ids (seen_at)`
)

// migrateV2 upgrades a schema 2 database to 3 in place. Every inbound id
// still stored becomes a tombstone dated by its arrival.
var migrateV2 = []string{
	seenIDsTable,
	seenIDsIndex,
	`INSERT OR IGNORE INTO seen_ids (id, seen_at)
		SELECT id, created_at FROM messages WHERE direction = 'in'`,
	`ALTER TABLE threads ADD COLUMN pruned INTEGER NOT NULL DEFAULT 0`,
}

var (
	errNoDatabase   = errors.New("database does not exist")
	errNotRegular   = errors.New("database path is not a regular file")
	errSchemaTooNew = errors.New("database schema is newer than this binary")
	errSchemaV1     = errors.New("database uses the old plaintext format (schema 1); move it aside and start a new one")
	errWrongKey     = errors.New("inbox key does not match this database")
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
		"_pragma=secure_delete(1)",
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
	case v == 1:
		return errSchemaV1
	}
	stmts := schema
	if v == 2 {
		stmts = migrateV2
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion)); err != nil {
		return err
	}
	return tx.Commit()
}

// checkInboxKey proves the inbox key matches the database: the first
// Open stores a sealed marker, later Opens must be able to open it. A
// wrong key fails Open instead of silently hiding every row.
func checkInboxKey(ctx context.Context, db *sql.DB, c *inboxCrypto) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var blob []byte
	err = tx.QueryRowContext(ctx, `SELECT v FROM meta WHERE k = 'key_check'`).Scan(&blob)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		sealed, err := c.seal(keyCheckID, "", "", "")
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO meta (k, v) VALUES ('key_check', ?)`, sealed); err != nil {
			return err
		}
		return tx.Commit()
	case err != nil:
		return err
	}
	if _, err := c.open(keyCheckID, blob); err != nil {
		return errWrongKey
	}
	return nil
}

type threadRow struct {
	peer       string
	resetSeq   int64
	pruned     int64 // messages after resetSeq deleted by retention
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
		`SELECT peer, reset_seq, pruned, tripped_at, trip_reason FROM threads WHERE thread = ?`, thread).
		Scan(&t.peer, &t.resetSeq, &t.pruned, &tripped, &reason)
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
	// The first message whose row opens gives the subject; rows that do
	// not open are skipped (and logged by id once).
	rows, err := b.db.QueryContext(ctx,
		`SELECT id, sealed FROM messages WHERE thread = ? ORDER BY seq LIMIT 20`, thread)
	if err != nil {
		return threadInfo{}, false, b.internal(ctx, "load thread subject", err)
	}
	seen, got := false, false
	for rows.Next() {
		var (
			id   string
			blob []byte
		)
		if err := rows.Scan(&id, &blob); err != nil {
			rows.Close()
			return threadInfo{}, false, b.internal(ctx, "load thread subject", err)
		}
		seen = true
		rc, err := b.crypt.open(id, blob)
		if err != nil {
			b.logUnreadable(id)
			continue
		}
		ti.firstSubject, got = rc.Subject, true
		break
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return threadInfo{}, false, b.internal(ctx, "load thread subject", err)
	}
	if !seen {
		return threadInfo{}, false, nil
	}
	if !got {
		return threadInfo{}, false, fmt.Errorf("%w: messages in that thread cannot be read", errInternal)
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
//
// An id is a duplicate while it is in messages or in the seen_ids
// tombstones. Tombstones outlive the relay's replay horizon, so an id is
// never accepted twice even after retention pruned its message.
func (b *Bridge) storeInbound(ctx context.Context, m envelope.Message) (inserted bool, drop string, err error) {
	now := b.now()
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return false, "", b.internal(ctx, "begin inbound", err)
	}
	defer tx.Rollback()
	var seen bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM seen_ids WHERE id = ?)
			OR EXISTS (SELECT 1 FROM messages WHERE id = ?)`, m.ID, m.ID).Scan(&seen); err != nil {
		return false, "", b.internal(ctx, "inbound dedup", err)
	}
	if seen {
		return false, "", nil
	}
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
	sealed, err := b.crypt.seal(m.ID, m.Session, m.Subject, m.Body)
	if err != nil {
		return false, "", b.internal(ctx, "seal inbound", err)
	}
	res, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO messages (id, direction, peer, thread, sealed, reply_to, created_at, ts)
		VALUES (?, 'in', ?, ?, ?, ?, ?, ?)`,
		m.ID, m.From, m.Thread, sealed, nullable(m.ReplyTo), now.UnixMilli(), m.TS)
	if err != nil {
		return false, "", b.internal(ctx, "insert inbound", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, "", b.internal(ctx, "insert inbound", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO seen_ids (id, seen_at) VALUES (?, ?)`, m.ID, now.UnixMilli()); err != nil {
		return false, "", b.internal(ctx, "insert seen id", err)
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
		SELECT id, thread, peer, sealed, created_at, read_at
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
			blob    []byte
			created int64
			readAt  sql.NullInt64
		)
		if err := rows.Scan(&m.ID, &m.Thread, &m.FromPeer, &blob, &created, &readAt); err != nil {
			return nil, b.internal(ctx, "inbox scan", err)
		}
		rc, err := b.crypt.open(m.ID, blob)
		if err != nil {
			b.logUnreadable(m.ID)
			continue
		}
		m.FromSession, m.Subject, m.Body = rc.Session, rc.Subject, rc.Body
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
		UPDATE threads SET tripped_at = NULL, trip_reason = NULL, reset_at = ?, reset_seq = ?, pruned = 0
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
