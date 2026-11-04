package relay

import "sync"

// notifier wakes long-pollers when an envelope arrives for their peer.
// Each peer has a channel that is closed (and replaced) on every new
// envelope. A poller takes the channel before it queries the store, so
// an envelope committed after the query always closes a channel the
// poller is already holding: no lost wakeups and no busy loops.
type notifier struct {
	mu sync.Mutex
	ch map[string]chan struct{}
}

func newNotifier() *notifier {
	return &notifier{ch: make(map[string]chan struct{})}
}

// wait returns the channel that will be closed on the next envelope for
// peer.
func (n *notifier) wait(peer string) <-chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	c, ok := n.ch[peer]
	if !ok {
		c = make(chan struct{})
		n.ch[peer] = c
	}
	return c
}

// notify wakes every poller waiting for peer.
func (n *notifier) notify(peer string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if c, ok := n.ch[peer]; ok {
		close(c)
		delete(n.ch, peer)
	}
}
