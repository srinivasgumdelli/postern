package bridge

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"postern/internal/envelope"
)

const day = 24 * time.Hour

func mustPrune(t *testing.T, b *Bridge) pruneStats {
	t.Helper()
	st, err := b.prune(ctxT(t))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	return st
}

func hasRow(t *testing.T, b *Bridge, table, col, val string) bool {
	t.Helper()
	var ok bool
	if err := b.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM `+table+` WHERE `+col+` = ?)`, val).Scan(&ok); err != nil {
		t.Fatal(err)
	}
	return ok
}

// The tombstones must cover the relay's replay horizon, or a redelivery
// after pruning would be stored twice.
func TestTombstonesOutliveReplayHorizon(t *testing.T) {
	if tombstoneRetention <= envelope.Retention+envelope.ClockSkew {
		t.Fatalf("tombstoneRetention %v does not cover the replay horizon %v",
			tombstoneRetention, envelope.Retention+envelope.ClockSkew)
	}
	if minMessageRetention <= rateWindow {
		t.Fatal("message retention shorter than the rate limit window")
	}
}

func TestSecureDeleteOn(t *testing.T) {
	w := newWorld(t)
	a, _ := w.pair()
	// Every pooled connection gets the pragma, not only the first.
	conns := make([]*sql.Conn, 3)
	for i := range conns {
		c, err := a.db.Conn(ctxT(t))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		conns[i] = c
		var v int
		if err := c.QueryRowContext(ctxT(t), `PRAGMA secure_delete`).Scan(&v); err != nil || v != 1 {
			t.Fatalf("conn %d: secure_delete = %d, %v; want 1", i, v, err)
		}
	}
}

// TestPruneRetention: inbound and sent messages go after 30 days, failed
// ones after 7, pending ones never; recent messages stay; threads go with
// their last message, and replying to one is ErrUnknownThread.
func TestPruneRetention(t *testing.T) {
	w := newWorld(t)
	a, b := w.pair()
	ctx := ctxT(t)
	subject, body := msg("retain", "retain")

	sent := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	pollAll(t, b)
	w.relay.setPostCode(400)
	if _, err := a.Send(ctx, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body}); !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v; want ErrRejected", err)
	}
	w.relay.setPostCode(0)
	w.relay.setOffline(true)
	pending := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	w.relay.setOffline(false)
	if pending.Status != StatusQueued {
		t.Fatalf("status = %s; want queued", pending.Status)
	}
	if countRows(t, a, `state = 'failed'`) != 1 {
		t.Fatal("no failed row")
	}

	// Day 6: nothing is old enough.
	w.clock.Advance(6 * day)
	if st := mustPrune(t, a); st.total() != 0 {
		t.Fatalf("day 6 pruned %+v", st)
	}
	// Day 8: only the failed row goes.
	w.clock.Advance(2 * day)
	if st := mustPrune(t, a); st.messages != 1 || st.threads != 1 {
		t.Fatalf("day 8 pruned %+v; want the failed message and its thread", st)
	}
	if countRows(t, a, `state = 'failed'`) != 0 || countRows(t, a, "") != 2 {
		t.Fatalf("day 8: %d rows left", countRows(t, a, ""))
	}

	// Day 29: still everything else.
	w.clock.Advance(21 * day)
	mustPrune(t, a)
	mustPrune(t, b)
	if countRows(t, a, "") != 2 || countRows(t, b, "") != 1 {
		t.Fatal("rows pruned before 30 days")
	}
	recent := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	pollAll(t, b)

	// Day 31: the first sent and inbound copies go; the pending row and
	// the recent message stay.
	w.clock.Advance(2 * day)
	mustPrune(t, a)
	mustPrune(t, b)
	if hasRow(t, a, "messages", "id", sent.ID) || hasRow(t, b, "messages", "id", sent.ID) {
		t.Fatal("30 day old message kept")
	}
	if got := rowState(t, a, pending.ID); got != "pending" {
		t.Fatalf("pending row state = %s", got)
	}
	if !hasRow(t, a, "messages", "id", recent.ID) || !hasRow(t, b, "messages", "id", recent.ID) {
		t.Fatal("recent message pruned")
	}
	for _, br := range []*Bridge{a, b} {
		if hasRow(t, br, "threads", "thread", sent.Thread) {
			t.Fatal("thread with no messages kept")
		}
	}
	if !hasRow(t, a, "threads", "thread", pending.Thread) {
		t.Fatal("thread of a pending message pruned")
	}
	if _, err := b.Reply(ctx, sess2, sent.Thread, plainMarker+" late"); !errors.Is(err, ErrUnknownThread) {
		t.Fatalf("reply to pruned thread err = %v; want ErrUnknownThread", err)
	}
	if _, err := b.Reply(ctx, sess2, recent.Thread, plainMarker+" ok"); err != nil {
		t.Fatalf("reply to kept thread: %v", err)
	}

	// Pending rows are never deleted, however old.
	w.clock.Advance(400 * day)
	mustPrune(t, a)
	if got := rowState(t, a, pending.ID); got != "pending" {
		t.Fatalf("pending row state = %s", got)
	}
}

// A thread whose breaker tripped recently is kept after its messages are
// pruned, so the breaker still holds; it goes 7 days after the trip.
func TestPruneKeepsRecentlyTrippedThread(t *testing.T) {
	w := newWorld(t)
	a, b := w.pair()
	ctx := ctxT(t)
	subject, body := msg("trip", "trip")
	first := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	pollAll(t, b)

	w.clock.Advance(29 * day)
	if _, err := b.db.Exec(`UPDATE threads SET tripped_at = ?, trip_reason = 'cap' WHERE thread = ?`,
		w.clock.Now().UnixMilli(), first.Thread); err != nil {
		t.Fatal(err)
	}
	w.clock.Advance(2 * day)
	mustPrune(t, b)
	if countRows(t, b, "") != 0 || !hasRow(t, b, "threads", "thread", first.Thread) {
		t.Fatal("tripped thread not kept after its messages were pruned")
	}
	_, err := b.Send(ctx, sess2, SendRequest{To: "peer-a", Subject: subject, Body: body, Thread: first.Thread})
	if !errors.Is(err, ErrThreadTripped) {
		t.Fatalf("send on tripped, pruned thread err = %v; want ErrThreadTripped", err)
	}
	w.clock.Advance(6 * day)
	mustPrune(t, b)
	if hasRow(t, b, "threads", "thread", first.Thread) {
		t.Fatal("thread kept more than 7 days after its trip")
	}
}

// TestDedupAfterPrune: with a 1 day retention the message is pruned well
// inside the relay's 72h replay horizon; a redelivery of the same id is
// still a duplicate because of the tombstone.
func TestDedupAfterPrune(t *testing.T) {
	w := newWorld(t)
	o := w.options(w.b, "", w.a)
	o.MessageRetention = day
	b := w.open(o)
	e := sealFrom(t, w.a, "peer-b", w.b.pub, w.clock.Now(), nil)
	w.relay.inject("peer-b", e)
	if n := pollAll(t, b); n != 1 {
		t.Fatalf("stored %d; want 1", n)
	}

	w.clock.Advance(day + time.Hour)
	mustPrune(t, b)
	if countRows(t, b, "") != 0 {
		t.Fatal("message not pruned")
	}
	if !hasRow(t, b, "seen_ids", "id", e.ID) {
		t.Fatal("tombstone missing")
	}
	w.relay.inject("peer-b", e)
	if n := pollAll(t, b); n != 0 {
		t.Fatalf("redelivery after prune stored %d; want 0", n)
	}
	if countRows(t, b, "") != 0 || w.relay.pending("peer-b") != 0 {
		t.Fatal("redelivery stored or not acked")
	}

	// Past the tombstone window the relay's replay check (72h) already
	// refuses the envelope, and the tombstone goes.
	w.clock.Advance(tombstoneRetention)
	if st := mustPrune(t, b); st.tombstones != 1 {
		t.Fatalf("pruned %+v; want 1 tombstone", st)
	}
	w.relay.inject("peer-b", e)
	if n := pollAll(t, b); n != 0 || countRows(t, b, "") != 0 {
		t.Fatalf("stale redelivery stored %d", n)
	}
}

func TestMessageRetentionConfigurable(t *testing.T) {
	w := newWorld(t)
	for _, d := range []time.Duration{-time.Hour, time.Hour, day - time.Second, 3651 * day} {
		o := w.options(w.b, "", w.a)
		o.MessageRetention = d
		if b, err := Open(o); err == nil {
			b.Close()
			t.Fatalf("Open accepted retention %v", d)
		}
	}

	short := w.options(w.b, "", w.a)
	short.MessageRetention = 2 * day
	bShort := w.open(short)
	bDefault := w.open(w.options(w.b, "", w.a))
	if bDefault.retention != defaultMessageRetention {
		t.Fatalf("default retention = %v", bDefault.retention)
	}
	e := sealFrom(t, w.a, "peer-b", w.b.pub, w.clock.Now(), nil)
	w.relay.inject("peer-b", e)
	pollAll(t, bShort)
	w.relay.inject("peer-b", e)
	pollAll(t, bDefault)

	w.clock.Advance(2*day - time.Minute)
	mustPrune(t, bShort)
	if countRows(t, bShort, "") != 1 {
		t.Fatal("pruned before the configured retention")
	}
	w.clock.Advance(2 * time.Minute)
	mustPrune(t, bShort)
	mustPrune(t, bDefault)
	if countRows(t, bShort, "") != 0 {
		t.Fatal("not pruned after the configured retention")
	}
	if countRows(t, bDefault, "") != 1 {
		t.Fatal("default retention pruned a 2 day old message")
	}
}

// schemaV2 is the schema 2 layout, for the migration test.
var schemaV2 = []string{
	`CREATE TABLE messages (
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
	`CREATE INDEX messages_thread_created ON messages (thread, created_at)`,
	`CREATE INDEX messages_dir_session_created ON messages (direction, session_tag, created_at)`,
	`CREATE INDEX messages_dir_created ON messages (direction, created_at)`,
	`CREATE INDEX messages_outbox ON messages (state, next_attempt_at)`,
	`CREATE TABLE threads (
		thread      TEXT    PRIMARY KEY,
		peer        TEXT    NOT NULL,
		created_at  INTEGER NOT NULL,
		reset_at    INTEGER,
		reset_seq   INTEGER NOT NULL DEFAULT 0,
		tripped_at  INTEGER,
		trip_reason TEXT
	)`,
	`CREATE TABLE meta (k TEXT PRIMARY KEY, v BLOB NOT NULL)`,
	`PRAGMA user_version = 2`,
}

// TestMigrateV2: a schema 2 inbox is upgraded in place; its messages stay
// readable and their ids stay deduplicated, also after they are pruned.
func TestMigrateV2(t *testing.T) {
	w := newWorld(t)
	path := filepath.Join(t.TempDir(), "v2.db")
	var m envelope.Message
	e := sealFrom(t, w.a, "peer-b", w.b.pub, w.clock.Now(), func(x *envelope.Message) { m = *x })
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range schemaV2 {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	sealed, err := newInboxCrypto(w.b.inboxKey).seal(m.ID, m.Session, m.Subject, m.Body)
	if err != nil {
		t.Fatal(err)
	}
	created := w.clock.Now().UnixMilli()
	if _, err := db.Exec(`INSERT INTO threads (thread, peer, created_at) VALUES (?, ?, ?)`, m.Thread, m.From, created); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO messages (id, direction, peer, thread, sealed, created_at, ts)
		VALUES (?, 'in', ?, ?, ?, ?, ?)`, m.ID, m.From, m.Thread, sealed, created, m.TS); err != nil {
		t.Fatal(err)
	}
	db.Close()

	o := w.options(w.b, path, w.a)
	b := w.open(o)
	var v, pruned int
	if err := b.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil || v != schemaVersion {
		t.Fatalf("user_version = %d, %v; want %d", v, err, schemaVersion)
	}
	if err := b.db.QueryRow(`SELECT pruned FROM threads WHERE thread = ?`, m.Thread).Scan(&pruned); err != nil || pruned != 0 {
		t.Fatalf("threads.pruned = %d, %v", pruned, err)
	}
	if !hasRow(t, b, "seen_ids", "id", m.ID) {
		t.Fatal("migration did not backfill the tombstone")
	}
	msgs, err := b.CheckInbox(ctxT(t), InboxQuery{})
	if err != nil || len(msgs) != 1 || msgs[0].ID != m.ID || msgs[0].Subject != m.Subject {
		t.Fatalf("CheckInbox after migration = %+v, %v", msgs, err)
	}
	w.relay.inject("peer-b", e)
	if n := pollAll(t, b); n != 0 {
		t.Fatalf("redelivery after migration stored %d", n)
	}
	b.Close()

	// Reopen (already v3) with a 1 day retention a day later: Open prunes
	// the message, and the backfilled tombstone still dedups it.
	w.clock.Advance(day + time.Hour)
	o.MessageRetention = day
	b2 := w.open(o)
	if countRows(t, b2, "") != 0 {
		t.Fatal("Open did not prune")
	}
	w.relay.inject("peer-b", e)
	if n := pollAll(t, b2); n != 0 || countRows(t, b2, "") != 0 {
		t.Fatalf("redelivery after migration and prune stored %d", n)
	}
}

// TestPrunedRowsGoneFromFiles: once pruned (secure_delete plus the
// checkpoint), a row's sealed content, nonce and ids are nowhere in the
// database, WAL or shared-memory files.
func TestPrunedRowsGoneFromFiles(t *testing.T) {
	w := newWorld(t)
	a, b := w.pair()
	subject, body := msg("gone", "gone")
	var ids, threads []string
	for range 5 {
		r := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
		ids = append(ids, r.ID)
		threads = append(threads, r.Thread)
	}
	pollAll(t, b)

	type marker struct {
		what string
		b    []byte
	}
	markers := func(br *Bridge) []marker {
		var ms []marker
		for _, id := range ids {
			var blob []byte
			if err := br.db.QueryRow(`SELECT sealed FROM messages WHERE id = ?`, id).Scan(&blob); err != nil {
				t.Fatal(err)
			}
			ms = append(ms,
				marker{"nonce of " + id, bytes.Clone(blob[:nonceLen])},
				marker{"ciphertext of " + id, bytes.Clone(blob[len(blob)/2 : len(blob)/2+32])},
				marker{"id " + id, []byte(id)})
		}
		for _, th := range threads {
			ms = append(ms, marker{"thread " + th, []byte(th)})
		}
		return ms
	}
	files := func(br *Bridge) []byte {
		path := br.dbPathForTest(t)
		var all []byte
		for _, p := range []string{path, path + "-wal", path + "-shm"} {
			raw, err := os.ReadFile(p)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			all = append(all, raw...)
		}
		return all
	}
	ma, mb := markers(a), markers(b)
	// Sanity: the search finds them before pruning.
	for _, c := range []struct {
		br *Bridge
		ms []marker
	}{{a, ma}, {b, mb}} {
		raw := files(c.br)
		for _, m := range c.ms {
			if !bytes.Contains(raw, m.b) {
				t.Fatalf("before prune: %s not found in files", m.what)
			}
		}
	}

	// Past message retention and the tombstone window.
	w.clock.Advance(31 * day)
	for _, c := range []struct {
		name string
		br   *Bridge
		ms   []marker
	}{{"A", a, ma}, {"B", b, mb}} {
		st := mustPrune(t, c.br)
		if st.messages != len(ids) {
			t.Fatalf("%s pruned %+v", c.name, st)
		}
		raw := files(c.br)
		for _, m := range c.ms {
			if bytes.Contains(raw, m.b) {
				t.Errorf("%s: %s still in the database files after prune", c.name, m.what)
			}
		}
		if bytes.Contains(raw, []byte(plainMarker)) || bytes.Contains(raw, []byte(sessionMarker)) {
			t.Errorf("%s: plaintext in the database files", c.name)
		}
	}
}

// TestConcurrentPrune: several processes pruning one large database at
// once delete each row exactly once and count pruned thread messages once.
func TestConcurrentPrune(t *testing.T) {
	w := newWorld(t)
	shared := w.options(w.b, "", w.a).DBPath
	o := w.options(w.b, shared, w.a)
	o.Limits.ThreadMax = 301 // 300 pruned + 2 kept: one more trips the cap
	bs := []*Bridge{w.open(o), w.open(o), w.open(o)}

	now := w.clock.Now()
	old, fresh := now.Add(-31*day).UnixMilli(), now.UnixMilli()
	t1, t2 := envelope.NewThreadID(), envelope.NewThreadID()
	const n1, n2 = 1100, 300
	tx, err := bs[0].db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for _, th := range []string{t1, t2} {
		if _, err := tx.Exec(`INSERT INTO threads (thread, peer, created_at) VALUES (?, 'peer-a', ?)`, th, old); err != nil {
			t.Fatal(err)
		}
	}
	insert := func(thread string, created int64) {
		id := newID()
		if _, err := tx.Exec(`INSERT INTO messages (id, direction, peer, thread, sealed, created_at)
			VALUES (?, 'in', 'peer-a', ?, randomblob(64), ?)`, id, thread, created); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO seen_ids (id, seen_at) VALUES (?, ?)`, id, created); err != nil {
			t.Fatal(err)
		}
	}
	for range n1 {
		insert(t1, old)
	}
	for range n2 {
		insert(t2, old)
	}
	insert(t2, fresh)
	insert(t2, fresh)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		total pruneStats
		errs  []error
	)
	for i := range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, err := bs[i%len(bs)].prune(ctxT(t))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
			}
			total.messages += st.messages
			total.threads += st.threads
			total.tombstones += st.tombstones
		}()
	}
	wg.Wait()
	if len(errs) > 0 {
		t.Fatalf("prune errors: %v", errs)
	}
	if want := (pruneStats{messages: n1 + n2, threads: 1, tombstones: n1 + n2}); total != want {
		t.Fatalf("pruned %+v in total; want %+v", total, want)
	}
	b := bs[0]
	if countRows(t, b, "") != 2 || hasRow(t, b, "threads", "thread", t1) {
		t.Fatalf("%d rows left", countRows(t, b, ""))
	}
	var pruned int
	if err := b.db.QueryRow(`SELECT pruned FROM threads WHERE thread = ?`, t2).Scan(&pruned); err != nil || pruned != n2 {
		t.Fatalf("t2 pruned = %d, %v; want %d", pruned, err, n2)
	}
	// The thread cap still counts the pruned messages.
	subject, body := msg("cap", "cap")
	_, err = b.Send(ctxT(t), sess2, SendRequest{To: "peer-a", Subject: subject, Body: body, Thread: t2})
	if !errors.Is(err, ErrThreadTripped) {
		t.Fatalf("send over the cap err = %v; want ErrThreadTripped", err)
	}
	// A reset clears the pruned count too.
	if err := ResetThread(ctxT(t), shared, t2); err != nil {
		t.Fatal(err)
	}
	if err := b.db.QueryRow(`SELECT pruned FROM threads WHERE thread = ?`, t2).Scan(&pruned); err != nil || pruned != 0 {
		t.Fatalf("pruned after reset = %d, %v", pruned, err)
	}
	if _, err := b.Send(ctxT(t), sess2, SendRequest{To: "peer-a", Subject: subject, Body: body, Thread: t2}); err != nil {
		t.Fatalf("send after reset: %v", err)
	}
}
