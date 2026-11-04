package bridge

import (
	"context"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"postern/internal/envelope"
)

const (
	outboxTick       = time.Second
	outboxMinBackoff = 2 * time.Second
	outboxMaxBackoff = 5 * time.Minute
	outboxBatch      = 20
)

// outRow is a pending outbound message.
type outRow struct {
	id, peer, thread, session, subject, body, replyTo string
	attempts                                          int
	createdAt                                         time.Time
}

type outcome int

const (
	outDelivered outcome = iota + 1
	outTransient
	outPermanent
)

type attemptResult struct {
	outcome outcome
	status  int    // HTTP status, 0 if there was no response
	reason  string // short log-safe code
}

// attempt reseals r with ts = now (same id) and posts it once. Every
// attempt reseals because the relay rejects a ts more than 10 minutes
// from its clock; a message queued during an outage would otherwise be
// stale by the time the relay is back.
func (b *Bridge) attempt(ctx context.Context, r outRow) attemptResult {
	key, ok := b.peers[r.peer]
	if !ok {
		return attemptResult{outcome: outPermanent, reason: "unknown_peer"}
	}
	m := envelope.Message{
		ID: r.id, From: b.self, To: r.peer, Thread: r.thread, TS: b.now().Unix(),
		Session: r.session, Subject: r.subject, Body: r.body, ReplyTo: r.replyTo,
	}
	e, err := envelope.Seal(m, key, b.priv)
	if err != nil {
		return attemptResult{outcome: outPermanent, reason: "seal"}
	}
	status, err := b.client.post(ctx, e)
	if err != nil {
		return attemptResult{outcome: outTransient, reason: netReason(err)}
	}
	switch status {
	case http.StatusCreated, http.StatusConflict: // 409: the relay already has this id
		return attemptResult{outcome: outDelivered, status: status}
	case http.StatusBadRequest, http.StatusForbidden, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		// The envelope was freshly sealed just now, so a 422 (stale) is
		// a clock problem, not a queueing delay; retrying will not help.
		return attemptResult{outcome: outPermanent, status: status, reason: "rejected"}
	default:
		return attemptResult{outcome: outTransient, status: status, reason: "status"}
	}
}

// record stores the result of an attempt. It runs even if ctx was
// cancelled, so a delivered message is not left looking pending.
func (b *Bridge) record(ctx context.Context, r outRow, res attemptResult) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()
	now := b.now()
	attempts := r.attempts + 1
	var err error
	switch res.outcome {
	case outDelivered:
		// A row another process gave up on may still have been delivered.
		_, err = b.db.ExecContext(ctx, `
			UPDATE messages SET state = 'sent', attempts = attempts + 1, lease_until = 0
			WHERE id = ? AND direction = 'out' AND state IN ('pending', 'failed')`, r.id)
		b.log.Info("outbound delivered", "id", r.id, "thread", r.thread, "peer", r.peer,
			"status", res.status, "attempts", attempts)
	case outPermanent:
		_, err = b.db.ExecContext(ctx, `
			UPDATE messages SET state = 'failed', attempts = attempts + 1, lease_until = 0
			WHERE id = ? AND direction = 'out' AND state = 'pending'`, r.id)
		b.log.Warn("outbound rejected", "id", r.id, "thread", r.thread, "peer", r.peer,
			"status", res.status, "reason", res.reason, "attempts", attempts)
	default:
		delay := retryDelay(attempts)
		_, err = b.db.ExecContext(ctx, `
			UPDATE messages SET attempts = attempts + 1, lease_until = 0, next_attempt_at = ?
			WHERE id = ? AND direction = 'out' AND state = 'pending'`,
			now.Add(delay).UnixMilli(), r.id)
		b.log.Info("outbound deferred", "id", r.id, "thread", r.thread, "peer", r.peer,
			"status", res.status, "reason", res.reason, "attempts", attempts,
			"retry_in", delay.Round(time.Millisecond).String())
	}
	if err != nil {
		// The row keeps its lease and is retried once the lease expires;
		// a repeat post of a delivered id gets 409, which counts as sent.
		b.log.Error("store error", "op", "record attempt", "id", r.id, "err", err.Error())
	}
}

// claim leases up to limit pending rows to this process. With force it
// ignores the retry backoff (but never another process's lease). Rows
// older than the relay's retention are given up on (failed) instead.
func (b *Bridge) claim(ctx context.Context, force bool, limit int) ([]outRow, error) {
	now := b.now()
	nowMs := now.UnixMilli()

	// Every session process runs this every second. A read-only check
	// first keeps idle processes from taking the shared write lock.
	// (Expired rows become due within the 5 minute backoff cap and are
	// given up on then.)
	pre := `SELECT EXISTS (SELECT 1 FROM messages
		WHERE state = 'pending' AND direction = 'out' AND lease_until <= ?`
	preArgs := []any{nowMs}
	if !force {
		pre += ` AND next_attempt_at <= ?`
		preArgs = append(preArgs, nowMs)
	}
	var due bool
	if err := b.db.QueryRowContext(ctx, pre+`)`, preArgs...).Scan(&due); err != nil {
		return nil, b.internal(ctx, "claim check", err)
	}
	if !due {
		return nil, nil
	}

	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, b.internal(ctx, "begin claim", err)
	}
	defer tx.Rollback()

	cutoff := now.Add(-envelope.Retention).UnixMilli()
	expired, err := tx.QueryContext(ctx, `
		SELECT id, thread, peer FROM messages
		WHERE direction = 'out' AND state = 'pending' AND created_at < ? AND lease_until <= ?`, cutoff, nowMs)
	if err != nil {
		return nil, b.internal(ctx, "claim expired", err)
	}
	var gaveUp []string
	for expired.Next() {
		var id, thread, peer string
		if err := expired.Scan(&id, &thread, &peer); err != nil {
			expired.Close()
			return nil, b.internal(ctx, "claim expired", err)
		}
		gaveUp = append(gaveUp, id)
		b.log.Warn("outbound expired", "id", id, "thread", thread, "peer", peer)
	}
	expired.Close()
	if err := expired.Err(); err != nil {
		return nil, b.internal(ctx, "claim expired", err)
	}
	for _, id := range gaveUp {
		if _, err := tx.ExecContext(ctx, `
			UPDATE messages SET state = 'failed', lease_until = 0
			WHERE id = ? AND state = 'pending'`, id); err != nil {
			return nil, b.internal(ctx, "claim expire", err)
		}
	}

	q := `SELECT id, peer, thread, session, subject, body, COALESCE(reply_to, ''), attempts, created_at
		FROM messages
		WHERE direction = 'out' AND state = 'pending' AND lease_until <= ?`
	args := []any{nowMs}
	if !force {
		q += ` AND next_attempt_at <= ?`
		args = append(args, nowMs)
	}
	q += ` ORDER BY seq LIMIT ?`
	args = append(args, limit)
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, b.internal(ctx, "claim select", err)
	}
	var out []outRow
	for rows.Next() {
		var (
			r       outRow
			created int64
		)
		if err := rows.Scan(&r.id, &r.peer, &r.thread, &r.session, &r.subject, &r.body, &r.replyTo, &r.attempts, &created); err != nil {
			rows.Close()
			return nil, b.internal(ctx, "claim scan", err)
		}
		r.createdAt = time.UnixMilli(created)
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, b.internal(ctx, "claim rows", err)
	}
	lease := now.Add(leaseDuration).UnixMilli()
	for _, r := range out {
		if _, err := tx.ExecContext(ctx, `UPDATE messages SET lease_until = ? WHERE id = ?`, lease, r.id); err != nil {
			return nil, b.internal(ctx, "claim lease", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, b.internal(ctx, "commit claim", err)
	}
	return out, nil
}

// release drops this process's lease on rows it claimed but did not try.
func (b *Bridge) release(ctx context.Context, rows []outRow) {
	if len(rows) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()
	args := make([]any, 0, len(rows))
	for _, r := range rows {
		args = append(args, r.id)
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(rows)), ",")
	if _, err := b.db.ExecContext(ctx,
		`UPDATE messages SET lease_until = 0 WHERE state = 'pending' AND id IN (`+ph+`)`, args...); err != nil {
		b.log.Error("store error", "op", "release lease", "count", len(rows), "err", err.Error())
	}
}

// flush attempts pending rows in batches. It stops at the first transient
// failure (the relay is likely down for all of them) and releases the
// rest. deferred reports whether that happened.
func (b *Bridge) flush(ctx context.Context, force bool) (delivered int, deferred bool, err error) {
	for {
		rows, err := b.claim(ctx, force, outboxBatch)
		if err != nil {
			return delivered, deferred, err
		}
		for i, r := range rows {
			if ctx.Err() != nil {
				b.release(ctx, rows[i:])
				return delivered, deferred, ctx.Err()
			}
			actx, cancel := context.WithTimeout(ctx, sendAttemptTimeout)
			res := b.attempt(actx, r)
			cancel()
			b.record(ctx, r, res)
			switch res.outcome {
			case outDelivered:
				delivered++
			case outTransient:
				b.release(ctx, rows[i+1:])
				return delivered, true, nil
			}
		}
		if len(rows) < outboxBatch {
			return delivered, false, nil
		}
	}
}

// FlushOutbox attempts every pending outbound message now, ignoring the
// retry backoff (rows another process is attempting are skipped). It
// returns how many were delivered. Transient failures are not errors:
// those messages stay queued.
func (b *Bridge) FlushOutbox(ctx context.Context) (int, error) {
	n, _, err := b.flush(ctx, true)
	return n, err
}

// kickOutbox wakes the outbox loop (after a sign that the relay is up).
func (b *Bridge) kickOutbox() {
	select {
	case b.kick <- struct{}{}:
	default:
	}
}

// outboxLoop retries due rows every tick. After a transient failure it
// backs off (2s doubling to 5 min, with jitter) until a kick (successful
// poll or send) shows the relay is reachable again.
func (b *Bridge) outboxLoop(ctx context.Context) {
	bo := backoff{min: outboxMinBackoff, max: outboxMaxBackoff}
	wait := time.Duration(0)
	for {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-b.kick:
			t.Stop()
			bo.reset()
		case <-t.C:
		}
		_, deferred, err := b.flush(ctx, false)
		if ctx.Err() != nil {
			return
		}
		if err != nil || deferred {
			wait = bo.next()
		} else {
			bo.reset()
			wait = outboxTick
		}
	}
}

// retryDelay is the per-message backoff after attempts failed attempts.
func retryDelay(attempts int) time.Duration {
	d := outboxMinBackoff
	for i := 1; i < attempts && d < outboxMaxBackoff; i++ {
		d *= 2
	}
	return jitter(min(d, outboxMaxBackoff), outboxMaxBackoff)
}

// jitter spreads d over [0.75d, 1.25d], capped at ceiling.
func jitter(d, ceiling time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	j := d*3/4 + time.Duration(rand.Int64N(int64(d/2)+1))
	return min(j, ceiling)
}

type backoff struct {
	min, max, cur time.Duration
}

func (b *backoff) next() time.Duration {
	if b.cur == 0 {
		b.cur = b.min
	} else {
		b.cur = min(b.cur*2, b.max)
	}
	return jitter(b.cur, b.max)
}

func (b *backoff) reset() { b.cur = 0 }

// sleepCtx waits d or until ctx is done; it reports whether d elapsed.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
