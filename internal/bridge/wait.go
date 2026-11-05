package bridge

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"postern/internal/envelope"
)

// waitCheckEvery is how often WaitForNew looks at the shared database. It
// reads a few indexed integers, so checking often is cheap, and it picks up
// messages any process stored (this one's poller included).
const waitCheckEvery = 500 * time.Millisecond

// Arrival describes new unread inbound messages by routing metadata only:
// how many, and which configured peers sent them.
type Arrival struct {
	Count int
	Peers []string // distinct, sorted
}

// WaitForNew blocks until the shared inbox holds at least one unread
// inbound message that has not been reported to session before, records
// those messages as reported, and returns their count and peers. It
// returns ctx.Err() if ctx ends first.
//
// It never opens a sealed row: it reads sequence numbers, peer names and
// read flags, so nothing it returns comes from a subject, a body or the
// sender's session name.
//
// What was reported is a per-session watermark in the database (the
// highest inbound sequence number reported, keyed by the session's tag).
// It survives restarts, so a message that arrives while no wait is running
// is reported by the next one, and each message is reported once per
// session whether or not it has been read. The first wait for a session
// reports every unread message already stored.
func (b *Bridge) WaitForNew(ctx context.Context, session string) (Arrival, error) {
	if !envelope.ValidSessionName(session) {
		return Arrival{}, errInvalidSession
	}
	key := "wait_reported:" + hex.EncodeToString(b.crypt.sessionTag(session))
	t := time.NewTicker(waitCheckEvery)
	defer t.Stop()
	for {
		a, err := b.takeNew(ctx, key)
		if err != nil {
			return Arrival{}, err
		}
		if a.Count > 0 {
			return a, nil
		}
		select {
		case <-ctx.Done():
			return Arrival{}, ctx.Err()
		case <-b.closed:
			return Arrival{}, errors.New("bridge: closed")
		case <-t.C:
		}
	}
}

// takeNew reports unread inbound messages above the watermark at key and
// moves the watermark past them. The cheap check runs without the write
// lock; only when there is something to report does it take an immediate
// transaction, check again and update the watermark.
func (b *Bridge) takeNew(ctx context.Context, key string) (Arrival, error) {
	mark, err := waitMark(ctx, b.db, key)
	if err != nil {
		return Arrival{}, b.internal(ctx, "wait mark", err)
	}
	var found bool
	if err := b.db.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM messages
			WHERE direction = 'in' AND read_at IS NULL AND seq > ?)`, mark).Scan(&found); err != nil {
		return Arrival{}, b.internal(ctx, "wait check", err)
	}
	if !found {
		return Arrival{}, nil
	}

	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return Arrival{}, b.internal(ctx, "begin wait", err)
	}
	defer tx.Rollback()
	if mark, err = waitMark(ctx, tx, key); err != nil {
		return Arrival{}, b.internal(ctx, "wait mark", err)
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT peer, COUNT(*), MAX(seq) FROM messages
		WHERE direction = 'in' AND read_at IS NULL AND seq > ?
		GROUP BY peer ORDER BY peer`, mark)
	if err != nil {
		return Arrival{}, b.internal(ctx, "wait query", err)
	}
	var a Arrival
	top := mark
	for rows.Next() {
		var (
			peer    string
			n, last int64
		)
		if err := rows.Scan(&peer, &n, &last); err != nil {
			rows.Close()
			return Arrival{}, b.internal(ctx, "wait scan", err)
		}
		a.Count += int(n)
		a.Peers = append(a.Peers, peer)
		if last > top {
			top = last
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return Arrival{}, b.internal(ctx, "wait rows", err)
	}
	rows.Close()
	if a.Count == 0 {
		return Arrival{}, nil
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v`,
		key, []byte(strconv.FormatInt(top, 10))); err != nil {
		return Arrival{}, b.internal(ctx, "wait mark update", err)
	}
	if err := tx.Commit(); err != nil {
		return Arrival{}, b.internal(ctx, "commit wait", err)
	}
	return a, nil
}

type queryRower interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// waitMark reads the watermark at key; a missing one is 0.
func waitMark(ctx context.Context, q queryRower, key string) (int64, error) {
	var v []byte
	err := q.QueryRowContext(ctx, `SELECT v FROM meta WHERE k = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(string(v), 10, 64)
	if err != nil || n < 0 {
		return 0, errors.New("bad wait watermark")
	}
	return n, nil
}
