package relay

import (
	"sync"
	"time"
)

// windowLimiter allows at most limit events per key in any sliding
// window. Keys are configured peer names, so state stays bounded.
type windowLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string][]time.Time
}

func newWindowLimiter(limit int, window time.Duration) *windowLimiter {
	return &windowLimiter{limit: limit, window: window, hits: make(map[string][]time.Time)}
}

// allow records an event for key at now and reports whether it is within
// the limit. A rejected event is not recorded.
func (l *windowLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-l.window)
	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.limit {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}

// concurrencyLimiter caps simultaneous long-polls per peer, so one
// authenticated peer cannot pin an unbounded number of goroutines and
// connections.
type concurrencyLimiter struct {
	mu    sync.Mutex
	limit int
	n     map[string]int
}

func newConcurrencyLimiter(limit int) *concurrencyLimiter {
	return &concurrencyLimiter{limit: limit, n: make(map[string]int)}
}

func (l *concurrencyLimiter) acquire(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.n[key] >= l.limit {
		return false
	}
	l.n[key]++
	return true
}

func (l *concurrencyLimiter) release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.n[key] <= 1 {
		delete(l.n, key)
		return
	}
	l.n[key]--
}
