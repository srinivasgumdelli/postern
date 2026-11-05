package bridge

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// waitShort runs WaitForNew with a short deadline and reports what it got.
func waitShort(t *testing.T, b *Bridge, session string, d time.Duration) (Arrival, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return b.WaitForNew(ctx, session)
}

func TestWaitForNewReportsEachMessageOncePerSession(t *testing.T) {
	w := newWorld(t)
	c := newIdentity(t, w.ca, "peer-c")
	w.relay.bind(c.cert.Fingerprint, c.name)
	b := w.open(w.options(w.b, "", w.a, c))
	s1, s2 := sessionMarker+"1", sessionMarker+"2"

	// Nothing stored: the wait times out.
	if _, err := waitShort(t, b, s1, 300*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("empty inbox: err = %v, want deadline exceeded", err)
	}

	// A wait that is already running returns once a message is stored.
	got := make(chan Arrival, 1)
	go func() {
		a, err := waitShort(t, b, s1, 20*time.Second)
		if err != nil {
			t.Error(err)
		}
		got <- a
	}()
	time.Sleep(100 * time.Millisecond)
	w.relay.inject("peer-b", sealFrom(t, w.a, "peer-b", w.b.pub, w.clock.Now(), nil))
	w.relay.inject("peer-b", sealFrom(t, w.a, "peer-b", w.b.pub, w.clock.Now(), nil))
	w.relay.inject("peer-b", sealFrom(t, c, "peer-b", w.b.pub, w.clock.Now(), nil))
	if n := pollAll(t, b); n != 3 {
		t.Fatalf("stored %d, want 3", n)
	}
	select {
	case a := <-got:
		if a.Count != 3 || !slices.Equal(a.Peers, []string{"peer-a", "peer-c"}) {
			t.Fatalf("arrival = %+v, want 3 from peer-a, peer-c", a)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("wait did not return after messages were stored")
	}

	// Reported to s1 already: the next wait for s1 blocks, even though the
	// messages are still unread. Another session is told separately.
	if _, err := waitShort(t, b, s1, 300*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second wait for the same session: err = %v, want deadline exceeded", err)
	}
	if a, err := waitShort(t, b, s2, 5*time.Second); err != nil || a.Count != 3 {
		t.Fatalf("other session: %+v, %v", a, err)
	}

	// A message that arrives while no wait runs is reported by the next
	// one; messages already read are not.
	msgs, err := b.CheckInbox(ctxT(t), InboxQuery{})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, m := range msgs {
		ids = append(ids, m.ID)
	}
	if _, err := b.MarkRead(ctxT(t), ids); err != nil {
		t.Fatal(err)
	}
	w.relay.inject("peer-b", sealFrom(t, w.a, "peer-b", w.b.pub, w.clock.Now(), nil))
	pollAll(t, b)
	read := sealFrom(t, c, "peer-b", w.b.pub, w.clock.Now(), nil)
	w.relay.inject("peer-b", read)
	pollAll(t, b)
	if _, err := b.MarkRead(ctxT(t), []string{read.ID}); err != nil {
		t.Fatal(err)
	}
	if a, err := waitShort(t, b, s1, 5*time.Second); err != nil || a.Count != 1 || !slices.Equal(a.Peers, []string{"peer-a"}) {
		t.Fatalf("message stored between waits: %+v, %v", a, err)
	}
}

// The watermark lives in the shared database, so a second process (here a
// second Bridge on the same file) sees messages the first one stored, and
// a restart does not report them again.
func TestWaitForNewSharedAcrossProcesses(t *testing.T) {
	w := newWorld(t)
	opts := w.options(w.b, "", w.a)
	poller := w.open(opts)
	waiter := w.open(opts)
	w.relay.inject("peer-b", sealFrom(t, w.a, "peer-b", w.b.pub, w.clock.Now(), nil))
	if n := pollAll(t, poller); n != 1 {
		t.Fatalf("stored %d, want 1", n)
	}
	s := sessionMarker + "1"
	if a, err := waitShort(t, waiter, s, 5*time.Second); err != nil || a.Count != 1 {
		t.Fatalf("message stored by another process: %+v, %v", a, err)
	}
	if _, err := waitShort(t, poller, s, 300*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("reported again by another process: %v", err)
	}
}

func TestWaitForNewRejectsBadSessionAndLogsNoContent(t *testing.T) {
	w := newWorld(t)
	_, b := w.pair()
	if _, err := waitShort(t, b, "Not A Session!", time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid session name: %v", err)
	}
	w.relay.inject("peer-b", sealFrom(t, w.a, "peer-b", w.b.pub, w.clock.Now(), nil))
	pollAll(t, b)
	if _, err := waitShort(t, b, sessionMarker+"1", 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if bad := forbiddenInLogs(testLogs.String()); len(bad) > 0 {
		t.Fatalf("logs contain %v", bad)
	}
}

func TestWaitForNewStopsWhenClosed(t *testing.T) {
	w := newWorld(t)
	_, b := w.pair()
	done := make(chan error, 1)
	go func() { _, err := b.WaitForNew(context.Background(), sessionMarker+"1"); done <- err }()
	time.Sleep(100 * time.Millisecond)
	b.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("wait returned no error after Close")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("wait did not stop after Close")
	}
}
