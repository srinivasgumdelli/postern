package bridge

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Limits are the outbound limits. Zero fields take the defaults.
//
//   - SessionPerHour: outbound messages one session may create per hour.
//   - GlobalPerHour: outbound messages all sessions on this machine may
//     create per hour (counted in the shared database, so across processes).
//   - ThreadMax: messages in both directions in one thread since its last
//     reset. Going over trips the thread's circuit breaker ("cap").
//   - ThreadBurst: messages in one thread within ThreadBurstWindow. Going
//     over trips the breaker ("burst").
//
// A tripped thread stays tripped until a human runs ResetThread.
type Limits struct {
	SessionPerHour    int
	GlobalPerHour     int
	ThreadMax         int
	ThreadBurst       int
	ThreadBurstWindow time.Duration
}

const (
	defaultSessionPerHour    = 30
	defaultGlobalPerHour     = 60
	defaultThreadMax         = 50
	defaultThreadBurst       = 10
	defaultThreadBurstWindow = 10 * time.Minute

	rateWindow = time.Hour
)

func (l Limits) withDefaults() (Limits, error) {
	if l.SessionPerHour < 0 || l.GlobalPerHour < 0 || l.ThreadMax < 0 ||
		l.ThreadBurst < 0 || l.ThreadBurstWindow < 0 {
		return l, errors.New("bridge: limits must not be negative")
	}
	if l.SessionPerHour == 0 {
		l.SessionPerHour = defaultSessionPerHour
	}
	if l.GlobalPerHour == 0 {
		l.GlobalPerHour = defaultGlobalPerHour
	}
	if l.ThreadMax == 0 {
		l.ThreadMax = defaultThreadMax
	}
	if l.ThreadBurst == 0 {
		l.ThreadBurst = defaultThreadBurst
	}
	if l.ThreadBurstWindow == 0 {
		l.ThreadBurstWindow = defaultThreadBurstWindow
	}
	return l, nil
}

// threadLimitReason reports "cap" or "burst" if one more message in thread
// would go over the limit, counting messages in both directions after the
// thread's last reset. It must run inside the immediate transaction that
// inserts the message.
func threadLimitReason(ctx context.Context, tx *sql.Tx, lim Limits, thread string, resetSeq int64, now time.Time) (string, error) {
	var total int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM messages WHERE thread = ? AND seq > ?`, thread, resetSeq).
		Scan(&total); err != nil {
		return "", err
	}
	if total+1 > lim.ThreadMax {
		return "cap", nil
	}
	var burst int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM messages WHERE thread = ? AND seq > ? AND created_at >= ?`,
		thread, resetSeq, now.Add(-lim.ThreadBurstWindow).UnixMilli()).
		Scan(&burst); err != nil {
		return "", err
	}
	if burst+1 > lim.ThreadBurst {
		return "burst", nil
	}
	return "", nil
}

// rateLimitScope reports "session" or "global" if one more outbound
// message would go over the hourly limit. It must run inside the
// immediate transaction that inserts the message.
func rateLimitScope(ctx context.Context, tx *sql.Tx, lim Limits, session string, now time.Time) (string, error) {
	since := now.Add(-rateWindow).UnixMilli()
	var n int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM messages WHERE direction = 'out' AND session = ? AND created_at >= ?`,
		session, since).Scan(&n); err != nil {
		return "", err
	}
	if n+1 > lim.SessionPerHour {
		return "session", nil
	}
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM messages WHERE direction = 'out' AND created_at >= ?`,
		since).Scan(&n); err != nil {
		return "", err
	}
	if n+1 > lim.GlobalPerHour {
		return "global", nil
	}
	return "", nil
}
