package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"postern/internal/audit"
	"postern/internal/envelope"
	"postern/internal/ulid"
)

const (
	pollMinBackoff = time.Second
	pollMaxBackoff = time.Minute
	// minPollGap keeps a relay that answers empty polls instantly from
	// turning the poll loop into a busy loop.
	minPollGap = 500 * time.Millisecond
	// cursorRefresh: every so often a poll starts again from cursor 0.
	// Acked envelopes are deleted by the relay, so this only re-fetches
	// envelopes nobody has acked yet (for example after a failed ack, or
	// if the relay's sequence numbers were reset). Re-fetched envelopes
	// are deduplicated by id.
	cursorRefresh = 5 * time.Minute

	reasonFuture = "future_ts"
)

// PollOnce makes one poll request, stores new inbound messages and acks
// every envelope it handled. It returns how many new inbox rows it stored
// (duplicates are not counted).
//
// Envelopes that are invalid, wrongly addressed, from an unknown sender,
// undecryptable, tampered with or older than Retention are dropped (logged
// by id and reason only) and acked so they do not come back. Valid
// envelopes are acked only after the insert commits. An authentic
// envelope dated more than ClockSkew ahead of this machine's clock is
// neither stored nor acked: it is fetched again after the periodic cursor
// reset, by which time the clock may have caught up.
func (b *Bridge) PollOnce(ctx context.Context) (int, error) {
	n, _, err := b.pollOnce(ctx)
	return n, err
}

func (b *Bridge) pollOnce(ctx context.Context) (stored, seen int, err error) {
	after := b.cursorForPoll()
	resp, status, err := b.client.poll(ctx, b.self, after)
	if ctx.Err() == nil {
		b.noteRelay(status, err, true)
	}
	if err != nil {
		if ctx.Err() != nil {
			return 0, 0, ctx.Err()
		}
		reason := netReason(err)
		b.log.Warn("poll failed", "reason", reason)
		return 0, 0, fmt.Errorf("bridge: poll failed (%s)", reason)
	}
	if status != http.StatusOK {
		b.log.Warn("poll failed", "status", status)
		return 0, 0, fmt.Errorf("bridge: poll failed (relay status %d)", status)
	}
	seen = len(resp.Envelopes)
	complete := true
	for _, raw := range resp.Envelopes {
		handled, isNew := b.process(ctx, raw)
		if isNew {
			stored++
		}
		if !handled {
			complete = false
		}
	}
	if seen > 0 {
		b.log.Info("poll", "envelopes", seen, "stored", stored)
	}
	if !complete {
		// Keep the cursor so the next poll sees the unfinished envelopes
		// again; finished ones are deduplicated by id.
		if ctx.Err() != nil {
			return stored, seen, ctx.Err()
		}
		return stored, seen, errors.New("bridge: some inbound envelopes were not finished; will retry")
	}
	b.advanceCursor(resp.Cursor)
	return stored, seen, nil
}

// process handles one envelope from a poll. handled is false when the
// envelope must be seen again (a local store failure or a failed ack).
func (b *Bridge) process(ctx context.Context, raw json.RawMessage) (handled, isNew bool) {
	var e envelope.Envelope
	id := ""
	reason := ""
	// Decode leniently (the relay may add fields); ValidateOuter below
	// enforces the protocol limits, including the box size cap.
	if err := json.Unmarshal(raw, &e); err != nil {
		reason = "parse"
		var probe struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(raw, &probe) == nil {
			e.ID = probe.ID
		}
	}
	if ulid.Valid(e.ID) {
		id = e.ID
	}
	if reason == "" {
		var err error
		reason, isNew, err = b.accept(ctx, e)
		if err != nil {
			return false, false
		}
		if reason == reasonFuture {
			// Authentic but dated ahead of our clock: our clock probably
			// lags. Neither store nor ack it; it stays at the relay and is
			// fetched again after the periodic cursor reset. Treated as
			// handled so the cursor still moves past it meanwhile.
			if b.logOnce("future:" + id) {
				b.log.Warn("inbound deferred", "id", id, "reason", reasonFuture)
			}
			return true, false
		}
	}
	if reason != "" {
		b.log.Warn("inbound dropped", "id", id, "reason", reason)
		// The outer from is chosen by whoever posted the envelope; record
		// it only if it names a pinned peer.
		peer := ""
		if _, ok := b.peers[e.From]; ok {
			peer = e.From
		}
		b.audit(audit.Event{Event: audit.EventDropped, Peer: peer, ID: id, Reason: reason})
	}
	if id == "" {
		// Without a valid id it cannot be acked; it expires at the relay.
		return true, isNew
	}
	if !b.ackEnvelope(ctx, id) {
		return false, isNew
	}
	return true, isNew
}

// accept validates, opens and stores one envelope. A non-empty reason
// means the envelope is dropped; err means a local failure.
func (b *Bridge) accept(ctx context.Context, e envelope.Envelope) (reason string, isNew bool, err error) {
	if err := e.ValidateOuter(); err != nil {
		return "invalid_outer", false, nil
	}
	if e.To != b.self {
		return "wrong_recipient", false, nil
	}
	key, ok := b.peers[e.From]
	if !ok {
		return "unknown_sender", false, nil
	}
	m, err := envelope.Open(e, key, b.priv)
	switch {
	case errors.Is(err, envelope.ErrDecrypt):
		return "decrypt", false, nil
	case errors.Is(err, envelope.ErrMismatch):
		return "mismatch", false, nil
	case err != nil:
		return "invalid_inner", false, nil
	}
	now := b.now()
	if time.Unix(m.TS, 0).After(now.Add(envelope.ClockSkew)) {
		return reasonFuture, false, nil
	}
	if err := envelope.CheckTime(m.TS, now, envelope.Retention); err != nil {
		return "stale", false, nil
	}
	inserted, drop, err := b.storeInbound(ctx, m)
	if err != nil {
		return "", false, err
	}
	if drop != "" {
		return drop, false, nil
	}
	if inserted {
		b.log.Info("inbound stored", "id", m.ID, "thread", m.Thread, "peer", m.From)
		// No session: the sending session's name is the other machine's
		// content (sealed in the inbox), not local metadata.
		b.audit(audit.Event{
			Event: audit.EventReceived, Peer: m.From, Thread: m.Thread, ID: m.ID,
			SizeBytes: int64(len(m.Body)),
		})
	} else {
		b.log.Debug("inbound duplicate", "id", m.ID)
	}
	return "", inserted, nil
}

// ackEnvelope acks id. 404 means it is already gone (another process
// acked it, or it expired), which is fine.
func (b *Bridge) ackEnvelope(ctx context.Context, id string) bool {
	status, err := b.client.ack(ctx, b.self, id)
	if ctx.Err() == nil {
		b.noteRelay(status, err, false)
	}
	if err != nil {
		if ctx.Err() == nil {
			b.log.Warn("ack failed", "id", id, "reason", netReason(err))
		}
		return false
	}
	switch status {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return true
	}
	b.log.Warn("ack failed", "id", id, "status", status)
	return false
}

func (b *Bridge) cursorForPoll() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if b.cursorAt.IsZero() || now.Sub(b.cursorAt) >= cursorRefresh || now.Before(b.cursorAt) {
		b.cursor = 0
		b.cursorAt = now
	}
	return b.cursor
}

func (b *Bridge) advanceCursor(next int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if next > b.cursor {
		b.cursor = next
	}
}

// pollLoop polls until ctx is done, backing off 1s doubling to 60s (with
// jitter) after errors.
func (b *Bridge) pollLoop(ctx context.Context) {
	bo := backoff{min: pollMinBackoff, max: pollMaxBackoff}
	for ctx.Err() == nil {
		start := time.Now()
		_, seen, err := b.pollOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			if !sleepCtx(ctx, bo.next()) {
				return
			}
			continue
		}
		bo.reset()
		b.kickOutbox()
		if seen == 0 {
			if el := time.Since(start); el < minPollGap && !sleepCtx(ctx, minPollGap-el) {
				return
			}
		}
	}
}
