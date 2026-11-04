package bridge

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"postern/internal/envelope"
)

// TestOutboxResealsAfterStaleWindow: the relay is down for longer than
// its 10 minute ts window. The queued message must be resealed with a
// fresh ts (same id) when it is retried, not rejected as stale.
func TestOutboxResealsAfterStaleWindow(t *testing.T) {
	w := newWorld(t)
	a, b := w.pair()
	subject, body := msg("stale", "stale")

	w.relay.setOffline(true)
	res := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	if res.Status != StatusQueued {
		t.Fatalf("status = %s; want queued", res.Status)
	}
	queuedAt := w.clock.Now()
	if got := rowState(t, a, res.ID); got != "pending" {
		t.Fatalf("state = %s; want pending", got)
	}

	w.clock.Advance(15 * time.Minute) // relay and bridge clocks both move
	w.relay.setOffline(false)
	n, err := a.FlushOutbox(ctxT(t))
	if err != nil || n != 1 {
		t.Fatalf("FlushOutbox = %d, %v; want 1", n, err)
	}
	posts := w.relay.acceptedPosts()
	if len(posts) != 1 || posts[0].ID != res.ID {
		t.Fatalf("relay saw %d posts", len(posts))
	}
	relayNow := w.clock.Now()
	ts := time.Unix(posts[0].TS, 0)
	if d := relayNow.Sub(ts); d < -envelope.ClockSkew || d > envelope.ClockSkew {
		t.Fatalf("ts %v is outside the relay window (relay now %v)", ts, relayNow)
	}
	if ts.Before(queuedAt.Add(14 * time.Minute)) {
		t.Fatalf("ts %v was not refreshed (queued at %v)", ts, queuedAt)
	}
	if got := rowState(t, a, res.ID); got != "sent" {
		t.Fatalf("state = %s; want sent", got)
	}
	if n := pollAll(t, b); n != 1 {
		t.Fatalf("B stored %d; want 1", n)
	}
	msgs, _ := b.CheckInbox(ctxT(t), InboxQuery{})
	if len(msgs) != 1 || msgs[0].ID != res.ID {
		t.Fatalf("B inbox = %+v", msgs)
	}
}

func TestPermanentRejection(t *testing.T) {
	for _, code := range []int{400, 413, 422} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			w := newWorld(t)
			a, _ := w.pair()
			subject, body := msg("reject", "reject")
			w.relay.setPostCode(code)
			_, err := a.Send(ctxT(t), sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
			if !errors.Is(err, ErrRejected) {
				t.Fatalf("err = %v; want ErrRejected", err)
			}
			var id, state string
			if err := a.db.QueryRow(`SELECT id, state FROM messages WHERE direction = 'out'`).Scan(&id, &state); err != nil {
				t.Fatal(err)
			}
			if state != "failed" {
				t.Fatalf("state = %s; want failed", state)
			}
			// Failed rows are not retried.
			w.relay.setPostCode(0)
			before := len(w.relay.acceptedPosts())
			if n, err := a.FlushOutbox(ctxT(t)); err != nil || n != 0 {
				t.Fatalf("FlushOutbox = %d, %v", n, err)
			}
			if len(w.relay.acceptedPosts()) != before {
				t.Fatal("failed row was posted again")
			}
		})
	}
}

func TestTransientStatusesQueue(t *testing.T) {
	for _, code := range []int{429, 500, 502, 503, 401, 403, 404} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			w := newWorld(t)
			a, b := w.pair()
			subject, body := msg("transient", "transient")
			w.relay.setPostCode(code)
			res := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
			if res.Status != StatusQueued {
				t.Fatalf("status = %s; want queued", res.Status)
			}
			var attempts int
			var next int64
			if err := a.db.QueryRow(`SELECT attempts, next_attempt_at FROM messages WHERE id = ?`, res.ID).Scan(&attempts, &next); err != nil {
				t.Fatal(err)
			}
			delay := time.UnixMilli(next).Sub(w.clock.Now())
			if attempts != 1 || delay < time.Second || delay > 3*time.Second {
				t.Fatalf("attempts = %d, next in %v; want 1 and ~2s", attempts, delay)
			}
			w.relay.setPostCode(0)
			if n, err := a.FlushOutbox(ctxT(t)); err != nil || n != 1 {
				t.Fatalf("FlushOutbox = %d, %v", n, err)
			}
			if n := pollAll(t, b); n != 1 {
				t.Fatalf("B stored %d", n)
			}
		})
	}
}

// A post that reached the relay but whose response was lost is retried;
// the relay answers 409, which counts as delivered.
func TestLostResponseThenConflictCountsAsDelivered(t *testing.T) {
	w := newWorld(t)
	a, b := w.pair()
	subject, body := msg("lost", "lost")
	w.relay.setStoreFail(true)
	res := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	if res.Status != StatusQueued {
		t.Fatalf("status = %s", res.Status)
	}
	w.relay.setStoreFail(false)
	if n, err := a.FlushOutbox(ctxT(t)); err != nil || n != 1 {
		t.Fatalf("FlushOutbox = %d, %v", n, err)
	}
	if got := rowState(t, a, res.ID); got != "sent" {
		t.Fatalf("state = %s", got)
	}
	if n := pollAll(t, b); n != 1 {
		t.Fatalf("B stored %d; want exactly 1", n)
	}
}

func TestOutboxGivesUpAfterRetention(t *testing.T) {
	w := newWorld(t)
	a, _ := w.pair()
	subject, body := msg("old", "old")
	w.relay.setOffline(true)
	res := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	w.clock.Advance(envelope.Retention + time.Minute)
	w.relay.setOffline(false)
	if n, err := a.FlushOutbox(ctxT(t)); err != nil || n != 0 {
		t.Fatalf("FlushOutbox = %d, %v; want 0", n, err)
	}
	if got := rowState(t, a, res.ID); got != "failed" {
		t.Fatalf("state = %s; want failed", got)
	}
	if len(w.relay.acceptedPosts()) != 0 {
		t.Fatal("expired message was posted")
	}
}

func TestOutboxRespectsBackoffAndLeases(t *testing.T) {
	w := newWorld(t)
	a, _ := w.pair()
	subject, body := msg("lease", "lease")
	w.relay.setOffline(true)
	res := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	w.relay.setOffline(false)

	// Not due yet: the loop's flush skips it, an explicit flush does not.
	if n, _, err := a.flush(ctxT(t), false); err != nil || n != 0 {
		t.Fatalf("due-only flush = %d, %v; want 0", n, err)
	}
	// Leased by another process: even a forced flush skips it.
	if _, err := a.db.Exec(`UPDATE messages SET lease_until = ? WHERE id = ?`,
		w.clock.Now().Add(time.Minute).UnixMilli(), res.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := a.FlushOutbox(ctxT(t)); err != nil || n != 0 {
		t.Fatalf("flush of leased row = %d, %v; want 0", n, err)
	}
	w.clock.Advance(2 * time.Minute)
	if n, _, err := a.flush(ctxT(t), false); err != nil || n != 1 {
		t.Fatalf("flush after lease and backoff = %d, %v; want 1", n, err)
	}
}

func TestFlushStopsAtFirstTransientFailure(t *testing.T) {
	w := newWorld(t)
	a, _ := w.pair()
	subject, body := msg("batch", "batch")
	w.relay.setOffline(true)
	for i := 0; i < 5; i++ {
		mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	}
	before := w.relay.requestCount()
	if n, err := a.FlushOutbox(ctxT(t)); err != nil || n != 0 {
		t.Fatalf("FlushOutbox = %d, %v", n, err)
	}
	if got := w.relay.requestCount() - before; got != 1 {
		t.Fatalf("flush made %d requests to a down relay; want 1", got)
	}
	if n := countRows(t, a, `lease_until != 0`); n != 0 {
		t.Fatalf("%d rows left leased", n)
	}
	w.relay.setOffline(false)
	if n, err := a.FlushOutbox(ctxT(t)); err != nil || n != 5 {
		t.Fatalf("FlushOutbox after recovery = %d, %v; want 5", n, err)
	}
}

func TestRetryDelayBounds(t *testing.T) {
	for attempts := 1; attempts < 40; attempts++ {
		d := retryDelay(attempts)
		if d <= 0 || d > outboxMaxBackoff {
			t.Fatalf("retryDelay(%d) = %v", attempts, d)
		}
	}
	if d := retryDelay(1); d < 1500*time.Millisecond || d > 2500*time.Millisecond {
		t.Fatalf("first retry = %v; want about 2s", d)
	}
	if d := retryDelay(30); d < outboxMaxBackoff*3/4 {
		t.Fatalf("late retry = %v; want near the 5 min cap", d)
	}
	bo := backoff{min: pollMinBackoff, max: pollMaxBackoff}
	var last time.Duration
	for i := 0; i < 20; i++ {
		last = bo.next()
		if last > pollMaxBackoff {
			t.Fatalf("poll backoff %v over cap", last)
		}
	}
	if last < pollMaxBackoff*3/4 {
		t.Fatalf("poll backoff did not grow: %v", last)
	}
	bo.reset()
	if d := bo.next(); d > 2*pollMinBackoff {
		t.Fatalf("reset backoff = %v", d)
	}
}
