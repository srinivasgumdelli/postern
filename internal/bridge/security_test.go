package bridge

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"postern/internal/envelope"
)

// TestInboxEncryptedAtRest: after messages go out and come in, the raw
// database, WAL and shared-memory files hold no subject, body or session
// name, so a session reading the file directly learns nothing.
func TestInboxEncryptedAtRest(t *testing.T) {
	w := newWorld(t)
	a, b := w.pair()
	ctx := ctxT(t)
	subject, body := msg("at rest subject", "at rest body\nsecond line")

	r := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	pollAll(t, b)
	if _, err := b.Reply(ctx, sess2, r.Thread, plainMarker+" reply at rest"); err != nil {
		t.Fatal(err)
	}
	pollAll(t, a)
	w.relay.setOffline(true)
	mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body}) // queued row too
	w.relay.setOffline(false)
	// Sanity: the content is all still readable through the API.
	if msgs, _ := a.CheckInbox(ctx, InboxQuery{}); len(msgs) != 1 || msgs[0].FromSession != sess2 {
		t.Fatalf("A inbox = %+v", msgs)
	}

	check := func(when string, br *Bridge) {
		t.Helper()
		path := br.dbPathForTest(t)
		files := 0
		for _, p := range []string{path, path + "-wal", path + "-shm"} {
			raw, err := os.ReadFile(p)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			files++
			for _, m := range []string{plainMarker, sessionMarker, "at rest", "second line"} {
				if bytes.Contains(raw, []byte(m)) {
					t.Errorf("%s: %s contains %q", when, filepath.Base(p), m)
				}
			}
		}
		if files == 0 {
			t.Fatalf("%s: no database files found", when)
		}
	}
	check("open A", a)
	check("open B", b)
	pa, pb := a.dbPathForTest(t), b.dbPathForTest(t)
	a.Close()
	b.Close()
	for _, p := range []string{pa, pb} {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(plainMarker)) || bytes.Contains(raw, []byte(sessionMarker)) {
			t.Errorf("closed %s contains plaintext", filepath.Base(p))
		}
	}
}

func TestWrongInboxKeyFailsSafely(t *testing.T) {
	w := newWorld(t)
	o := w.options(w.b, "", w.a)
	b := w.open(o)
	w.relay.inject("peer-b", sealFrom(t, w.a, "peer-b", w.b.pub, w.clock.Now(), nil))
	pollAll(t, b)
	b.Close()

	other := newIdentity(t, w.ca, "peer-b")
	o2 := o
	o2.InboxKey = other.inboxKey
	b2, err := Open(o2)
	if err == nil {
		b2.Close()
		t.Fatal("Open with the wrong inbox key succeeded")
	}
	if !strings.Contains(err.Error(), "inbox key does not match") {
		t.Fatalf("err = %v", err)
	}
	// The right key still works and sees the message.
	b3 := w.open(o)
	if msgs, err := b3.CheckInbox(ctxT(t), InboxQuery{}); err != nil || len(msgs) != 1 {
		t.Fatalf("right key: %d messages, %v", len(msgs), err)
	}
}

// Rows that fail to decrypt (corruption, or a key mixup) are skipped and
// logged by id; nothing crashes and nothing garbled is sent.
func TestUnreadableRowsSkipped(t *testing.T) {
	var logs syncBuffer
	w := newWorld(t)
	ob := w.options(w.b, "", w.a)
	ob.Logger = testLogger(&logs)
	b := w.open(ob)
	a := w.open(w.options(w.a, "", w.b))
	ctx := ctxT(t)
	subject, body := msg("u", "u")

	r1 := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	r2 := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body, Thread: r1.Thread})
	pollAll(t, b)
	// Corrupt the first row.
	if _, err := b.db.Exec(`UPDATE messages SET sealed = randomblob(80) WHERE id = ?`, r1.ID); err != nil {
		t.Fatal(err)
	}
	msgs, err := b.CheckInbox(ctx, InboxQuery{})
	if err != nil || len(msgs) != 1 || msgs[0].ID != r2.ID {
		t.Fatalf("CheckInbox = %+v, %v", msgs, err)
	}
	if _, err := b.CheckInbox(ctx, InboxQuery{}); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(logs.String(), "cannot be decrypted"); n != 1 || !strings.Contains(logs.String(), r1.ID) {
		t.Fatalf("unreadable row logged %d times; want once, with its id", n)
	}
	// Reply still finds the thread's subject from the readable row.
	if _, err := b.Reply(ctx, sess2, r1.Thread, plainMarker+" ok"); err != nil {
		t.Fatalf("Reply: %v", err)
	}
	// A blob only opens under its own row id.
	var blob2 []byte
	if err := b.db.QueryRow(`SELECT sealed FROM messages WHERE id = ?`, r2.ID).Scan(&blob2); err != nil {
		t.Fatal(err)
	}
	if _, err := b.crypt.open(r1.ID, blob2); err == nil {
		t.Fatal("a blob opened under another row's id")
	}

	// A corrupted outbound row is failed, not posted.
	w.relay.setOffline(true)
	q := mustSend(t, b, sess2, SendRequest{To: "peer-a", Subject: subject, Body: body})
	w.relay.setOffline(false)
	if _, err := b.db.Exec(`UPDATE messages SET sealed = x'00' WHERE id = ?`, q.ID); err != nil {
		t.Fatal(err)
	}
	before := len(w.relay.acceptedPosts())
	if n, err := b.FlushOutbox(ctx); err != nil || n != 0 {
		t.Fatalf("FlushOutbox = %d, %v", n, err)
	}
	if len(w.relay.acceptedPosts()) != before {
		t.Fatal("unreadable row was posted")
	}
	if got := rowState(t, b, q.ID); got != "failed" {
		t.Fatalf("state = %s; want failed", got)
	}
	if bad := forbiddenInLogs(logs.String()); len(bad) > 0 {
		t.Fatalf("logs contain %q", bad)
	}
}

func TestSchemaVersion1Refused(t *testing.T) {
	w := newWorld(t)
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE messages (seq INTEGER PRIMARY KEY, subject TEXT); PRAGMA user_version = 1`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	b, err := Open(w.options(w.a, path, w.b))
	if err == nil {
		b.Close()
		t.Fatal("Open accepted a schema 1 database")
	}
	if !strings.Contains(err.Error(), "schema 1") || strings.Contains(err.Error(), path) {
		t.Fatalf("err = %v", err)
	}
}

// TestCertReloadAfter403: the edge revokes the client certificate. Sends
// stay queued (no error), the bridge reloads its certificate at most once
// a minute, and queued messages deliver once a new one is in place.
func TestCertReloadAfter403(t *testing.T) {
	w := newWorld(t)
	newCert := w.ca.ClientCert(t, "peer-a")
	w.relay.bind(newCert.Fingerprint, "peer-a")
	var calls atomic.Int32
	current := newCert.TLS
	o := w.options(w.a, "", w.b)
	o.ReloadClientCert = func() (tls.Certificate, error) {
		calls.Add(1)
		return current, nil
	}
	a := w.open(o)
	b := w.open(w.options(w.b, "", w.a))
	ctx := ctxT(t)
	subject, body := msg("revoked", "revoked")

	w.relay.revoke(w.a.cert.Fingerprint, true)
	res, err := a.Send(ctx, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	if err != nil || res.Status != StatusQueued {
		t.Fatalf("Send after revocation = %+v, %v; want queued, no error", res, err)
	}
	if s := a.RelayStatus(); s != RelayAuthFailed {
		t.Fatalf("RelayStatus = %q; want %q", s, RelayAuthFailed)
	}
	if calls.Load() != 1 {
		t.Fatalf("reload calls = %d; want 1", calls.Load())
	}
	// The reloaded certificate is used on a new connection.
	if n, err := a.FlushOutbox(ctx); err != nil || n != 1 {
		t.Fatalf("FlushOutbox after reload = %d, %v; want 1", n, err)
	}
	if s := a.RelayStatus(); s != "" {
		t.Fatalf("RelayStatus after delivery = %q", s)
	}
	if n := pollAll(t, b); n != 1 {
		t.Fatalf("B stored %d", n)
	}

	// Revoke the new one too. Reload is rate limited to once a minute,
	// and an unchanged certificate is not swapped in.
	w.relay.revoke(newCert.Fingerprint, true)
	for i := 0; i < 3; i++ {
		if r, err := a.Send(ctx, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body}); err != nil || r.Status != StatusQueued {
			t.Fatalf("Send %d = %+v, %v", i, r, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("reload calls within a minute = %d; want 1", calls.Load())
	}
	w.clock.Advance(61 * time.Second)
	if n, _ := a.FlushOutbox(ctx); n != 0 {
		t.Fatalf("delivered %d with a revoked cert", n)
	}
	if calls.Load() != 2 {
		t.Fatalf("reload calls after a minute = %d; want 2", calls.Load())
	}
	third := w.ca.ClientCert(t, "peer-a")
	w.relay.bind(third.Fingerprint, "peer-a")
	current = third.TLS
	w.clock.Advance(61 * time.Second)
	if n, _ := a.FlushOutbox(ctx); n != 0 { // 403, reload swaps in the third cert
		t.Fatalf("first flush delivered %d", n)
	}
	if n, err := a.FlushOutbox(ctx); err != nil || n != 3 {
		t.Fatalf("FlushOutbox with third cert = %d, %v; want 3", n, err)
	}
	if s := a.RelayStatus(); s != "" {
		t.Fatalf("RelayStatus = %q", s)
	}
}

func TestRelayStatusTransitions(t *testing.T) {
	w := newWorld(t)
	a, _ := w.pair()
	ctx := ctxT(t)
	subject, body := msg("status", "status")

	if s := a.RelayStatus(); s != "" {
		t.Fatalf("initial = %q", s)
	}
	w.relay.setOffline(true)
	if _, err := a.PollOnce(ctx); err == nil {
		t.Fatal("poll against offline relay succeeded")
	}
	if s := a.RelayStatus(); s != "" {
		t.Fatalf("after one failed poll = %q; want \"\" (under 2 minutes)", s)
	}
	w.clock.Advance(90 * time.Second)
	_, _ = a.PollOnce(ctx)
	if s := a.RelayStatus(); s != "" {
		t.Fatalf("after 90s of failures = %q", s)
	}
	w.clock.Advance(60 * time.Second)
	_, _ = a.PollOnce(ctx)
	if s := a.RelayStatus(); s != RelayUnreachable {
		t.Fatalf("after 150s of failures = %q; want %q", s, RelayUnreachable)
	}
	w.relay.setOffline(false)
	if _, err := a.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if s := a.RelayStatus(); s != "" {
		t.Fatalf("after recovery = %q", s)
	}

	w.relay.revoke(w.a.cert.Fingerprint, true)
	if _, err := a.PollOnce(ctx); err == nil {
		t.Fatal("poll with revoked cert succeeded")
	}
	if s := a.RelayStatus(); s != RelayAuthFailed {
		t.Fatalf("after poll 403 = %q", s)
	}
	w.relay.revoke(w.a.cert.Fingerprint, false)
	if _, err := a.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if s := a.RelayStatus(); s != "" {
		t.Fatalf("after good poll = %q", s)
	}

	w.relay.setPostCode(401)
	if r, err := a.Send(ctx, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body}); err != nil || r.Status != StatusQueued {
		t.Fatalf("Send on 401 = %+v, %v", r, err)
	}
	if s := a.RelayStatus(); s != RelayAuthFailed {
		t.Fatalf("after post 401 = %q", s)
	}
	w.relay.setPostCode(0)
	if r := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body}); r.Status != StatusSent {
		t.Fatalf("status = %s", r.Status)
	}
	if s := a.RelayStatus(); s != "" {
		t.Fatalf("after good post = %q", s)
	}
}

// TestFutureDatedInboundNotAcked: the receiver's clock lags by 20
// minutes, so an authentic envelope looks more than ClockSkew in the
// future. It must be neither stored nor acked (dropping it would lose it
// for good), logged once, and picked up once the clock catches up.
func TestFutureDatedInboundNotAcked(t *testing.T) {
	var logs syncBuffer
	w := newWorld(t)
	bclock := &testClock{offset: -20 * time.Minute}
	ob := w.options(w.b, "", w.a)
	ob.Now = bclock.Now
	ob.Logger = testLogger(&logs)
	b := w.open(ob)
	a := w.open(w.options(w.a, "", w.b))
	subject, body := msg("future", "future")
	r := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})

	if n := pollAll(t, b); n != 0 {
		t.Fatalf("stored %d; want 0", n)
	}
	if w.relay.isAcked(r.ID) || w.relay.pending("peer-b") != 1 {
		t.Fatal("future-dated envelope was acked")
	}
	pollAll(t, b) // cursor moved past it: not fetched again yet
	bclock.Advance(6 * time.Minute)
	pollAll(t, b) // cursor reset: fetched again, still 14 min in the future
	if w.relay.isAcked(r.ID) || countRows(t, b, "") != 0 {
		t.Fatal("future-dated envelope stored or acked")
	}
	if n := strings.Count(logs.String(), "inbound deferred"); n != 1 {
		t.Fatalf("deferred logged %d times; want once", n)
	}
	if !strings.Contains(logs.String(), r.ID) {
		t.Fatal("deferred log line has no id")
	}

	bclock.Advance(15 * time.Minute) // within skew now; cursor resets again
	if n := pollAll(t, b); n != 1 {
		t.Fatalf("after clock catch-up stored %d; want 1", n)
	}
	if !w.relay.isAcked(r.ID) {
		t.Fatal("not acked after storing")
	}

	// Too old is still dropped and acked.
	old := sealFrom(t, w.a, "peer-b", w.b.pub, bclock.Now().Add(-envelope.Retention-time.Hour), nil)
	w.relay.inject("peer-b", old)
	if n := pollAll(t, b); n != 0 || !w.relay.isAcked(old.ID) {
		t.Fatalf("old envelope: stored %d, acked %v", n, w.relay.isAcked(old.ID))
	}
	if bad := forbiddenInLogs(logs.String()); len(bad) > 0 {
		t.Fatalf("logs contain %q", bad)
	}
}
