package bridge

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Retention. The local database is decryptable history for anyone holding
// the inbox key, so it is not kept forever:
//
//   - inbound messages, and outbound messages the relay accepted, are
//     deleted MessageRetention after they were stored (default 30 days);
//   - failed outbound messages are deleted after failedRetention (7 days),
//     or MessageRetention if that is shorter;
//   - pending outbound messages are never deleted: the outbox gives up on
//     them after the relay's retention (72h) and marks them failed first;
//   - every inbound id is kept as a tombstone in seen_ids for
//     tombstoneRetention, so a redelivery within the relay's replay
//     horizon (72h plus clock skew) is still a duplicate after its message
//     was pruned;
//   - a thread row is deleted once none of its messages remain, unless its
//     breaker tripped less than trippedThreadRetention ago. Replying to a
//     deleted thread is ErrUnknownThread, as for any unknown thread.
//
// Pruning runs once at Open and then hourly in Run. Each batch of up to
// pruneBatch rows is one immediate transaction, so a large prune never
// holds the write lock for long and processes sharing the database can
// prune at the same time (the second one simply finds less to do).
// secure_delete zeroes the deleted rows; after a pass that deleted
// anything, a WAL checkpoint moves the zeroed pages into the main file and
// truncates the WAL.
const (
	defaultMessageRetention = 30 * 24 * time.Hour
	minMessageRetention     = 24 * time.Hour
	maxMessageRetention     = 3650 * 24 * time.Hour
	failedRetention         = 7 * 24 * time.Hour
	tombstoneRetention      = 7 * 24 * time.Hour
	trippedThreadRetention  = 7 * 24 * time.Hour

	pruneInterval = time.Hour
	pruneBatch    = 500
	// pruneTimeout bounds one pruning pass; whatever is left is done on
	// the next pass.
	pruneTimeout = 2 * time.Minute
)

func messageRetention(d time.Duration) (time.Duration, error) {
	switch {
	case d == 0:
		return defaultMessageRetention, nil
	case d < minMessageRetention || d > maxMessageRetention:
		return 0, errors.New("bridge: message retention must be between 1 and 3650 days")
	}
	return d, nil
}

type pruneStats struct {
	messages, threads, tombstones int
}

func (s pruneStats) total() int { return s.messages + s.threads + s.tombstones }

// prune deletes everything past retention (see above). It is safe to run
// in several processes at once.
func (b *Bridge) prune(ctx context.Context) (pruneStats, error) {
	now := b.now()
	keepFailed := min(failedRetention, b.retention)
	var st pruneStats
	for _, c := range []struct {
		op, where string
		cutoff    time.Time
	}{
		{"prune inbound", `m.direction = 'in' AND m.created_at < ?`, now.Add(-b.retention)},
		{"prune sent", `m.direction = 'out' AND m.state = 'sent' AND m.created_at < ?`, now.Add(-b.retention)},
		{"prune failed", `m.direction = 'out' AND m.state = 'failed' AND m.created_at < ?`, now.Add(-keepFailed)},
	} {
		n, err := batched(func() (int, error) { return b.pruneMessageBatch(ctx, c.where, c.cutoff.UnixMilli()) })
		st.messages += n
		if err != nil {
			return st, b.pruneErr(ctx, c.op, err, st)
		}
	}
	n, err := batched(func() (int, error) {
		return b.pruneExec(ctx, `
			DELETE FROM threads WHERE thread IN (
				SELECT t.thread FROM threads t
				WHERE NOT EXISTS (SELECT 1 FROM messages m WHERE m.thread = t.thread)
					AND (t.tripped_at IS NULL OR t.tripped_at < ?)
				LIMIT ?)`, now.Add(-trippedThreadRetention).UnixMilli(), pruneBatch)
	})
	st.threads += n
	if err != nil {
		return st, b.pruneErr(ctx, "prune threads", err, st)
	}
	n, err = batched(func() (int, error) {
		return b.pruneExec(ctx, `
			DELETE FROM seen_ids WHERE id IN (
				SELECT id FROM seen_ids WHERE seen_at < ? LIMIT ?)`,
			now.Add(-tombstoneRetention).UnixMilli(), pruneBatch)
	})
	st.tombstones += n
	if err != nil {
		return st, b.pruneErr(ctx, "prune tombstones", err, st)
	}
	b.afterPrune(ctx, st)
	return st, nil
}

// batched runs one batch at a time until a batch comes back short.
func batched(batch func() (int, error)) (int, error) {
	total := 0
	for {
		n, err := batch()
		total += n
		if err != nil || n < pruneBatch {
			return total, err
		}
	}
}

// pruneMessageBatch deletes up to pruneBatch messages matching where (one
// cutoff argument, columns qualified with m.) in one immediate
// transaction. Messages after their thread's last reset are added to the
// thread's pruned count first, so the thread cap keeps counting them.
func (b *Bridge) pruneMessageBatch(ctx context.Context, where string, cutoff int64) (int, error) {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `
		SELECT m.seq, m.thread, COALESCE(t.reset_seq, 0)
		FROM messages m LEFT JOIN threads t ON t.thread = m.thread
		WHERE `+where+` ORDER BY m.seq LIMIT ?`, cutoff, pruneBatch)
	if err != nil {
		return 0, err
	}
	var seqs []int64
	afterReset := map[string]int64{}
	for rows.Next() {
		var (
			seq, resetSeq int64
			thread        string
		)
		if err := rows.Scan(&seq, &thread, &resetSeq); err != nil {
			rows.Close()
			return 0, err
		}
		seqs = append(seqs, seq)
		if seq > resetSeq {
			afterReset[thread]++
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(seqs) == 0 {
		return 0, nil
	}
	for thread, n := range afterReset {
		if _, err := tx.ExecContext(ctx,
			`UPDATE threads SET pruned = pruned + ? WHERE thread = ?`, n, thread); err != nil {
			return 0, err
		}
	}
	del, err := tx.PrepareContext(ctx, `DELETE FROM messages WHERE seq = ?`)
	if err != nil {
		return 0, err
	}
	defer del.Close()
	for _, seq := range seqs {
		if _, err := del.ExecContext(ctx, seq); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(seqs), nil
}

// pruneExec runs one bounded DELETE in its own immediate transaction and
// returns how many rows it deleted.
func (b *Bridge) pruneExec(ctx context.Context, q string, args ...any) (int, error) {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(n), nil
}

func (b *Bridge) pruneErr(ctx context.Context, op string, err error, st pruneStats) error {
	b.afterPrune(context.WithoutCancel(ctx), st)
	return b.internal(ctx, op, err)
}

// afterPrune logs what a pass deleted and, if it deleted anything,
// checkpoints the WAL so the zeroed pages replace the old ones in the main
// file and the WAL (which still holds old page images) is truncated. The
// checkpoint is best effort: if readers keep it from finishing, the next
// pass tries again.
func (b *Bridge) afterPrune(ctx context.Context, st pruneStats) {
	if st.total() == 0 {
		return
	}
	b.log.Info("inbox pruned", "messages", st.messages, "threads", st.threads, "tombstones", st.tombstones)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := b.checkpoint(ctx); err != nil {
		b.log.Warn("checkpoint after prune incomplete", "err", err.Error())
	}
}

var errCheckpointBusy = errors.New("database busy")

// checkpoint runs a truncating WAL checkpoint.
func (b *Bridge) checkpoint(ctx context.Context) error {
	var busy, logFrames, done int
	err := b.db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &done)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("database error")
	case busy != 0:
		return errCheckpointBusy
	}
	return nil
}

// runPrune runs one bounded pruning pass and logs (metadata only) if it
// did not finish.
func (b *Bridge) runPrune(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, pruneTimeout)
	defer cancel()
	if _, err := b.prune(ctx); err != nil && !errors.Is(err, context.Canceled) {
		b.log.Warn("prune incomplete; will retry", "err", err.Error())
	}
}

// pruneLoop prunes every pruneInterval until ctx is done.
func (b *Bridge) pruneLoop(ctx context.Context) {
	t := time.NewTicker(pruneInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		b.runPrune(ctx)
	}
}
