package relay

import (
	"testing"
	"time"
)

func (l *concurrencyLimiter) inUse(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.n[key]
}

func TestWindowLimiterSlides(t *testing.T) {
	l := newWindowLimiter(2, time.Hour)
	t0 := time.Unix(1_800_000_000, 0)
	if !l.allow("peer-a", t0) || !l.allow("peer-a", t0.Add(30*time.Minute)) {
		t.Fatal("first two events rejected")
	}
	if l.allow("peer-a", t0.Add(59*time.Minute)) {
		t.Fatal("third event in the window allowed")
	}
	if !l.allow("peer-b", t0) {
		t.Fatal("limit leaked across keys")
	}
	// The first event leaves the window; one slot opens.
	if !l.allow("peer-a", t0.Add(61*time.Minute)) {
		t.Fatal("event after the window moved was rejected")
	}
	if l.allow("peer-a", t0.Add(62*time.Minute)) {
		t.Fatal("rejected events must not have been recorded, but the window should be full again")
	}
}

func TestConcurrencyLimiter(t *testing.T) {
	l := newConcurrencyLimiter(2)
	if !l.acquire("p") || !l.acquire("p") {
		t.Fatal("acquire under limit failed")
	}
	if l.acquire("p") {
		t.Fatal("acquire over limit succeeded")
	}
	if !l.acquire("q") {
		t.Fatal("limit leaked across keys")
	}
	l.release("p")
	if !l.acquire("p") {
		t.Fatal("release did not free a slot")
	}
	l.release("p")
	l.release("p")
	l.release("p") // extra release is harmless
	if len(l.n) != 1 {
		t.Fatalf("state not cleaned up: %v", l.n)
	}
}

func TestNotifierWakesOnlyThatPeer(t *testing.T) {
	n := newNotifier()
	a1, a2, b := n.wait("peer-a"), n.wait("peer-a"), n.wait("peer-b")
	n.notify("peer-a")
	for _, c := range []<-chan struct{}{a1, a2} {
		select {
		case <-c:
		default:
			t.Fatal("peer-a waiter not woken")
		}
	}
	select {
	case <-b:
		t.Fatal("peer-b waiter woken by peer-a's message")
	default:
	}
	// A new wait after the notify blocks until the next one.
	a3 := n.wait("peer-a")
	select {
	case <-a3:
		t.Fatal("fresh waiter already closed")
	default:
	}
	n.notify("peer-c") // nobody waiting: no panic
}
