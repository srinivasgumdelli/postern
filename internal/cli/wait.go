package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"postern/internal/bridge"
	"postern/internal/envelope"
	"postern/internal/mcpserver"
)

// exitWaitTimeout is the exit code of `postern wait` when the timeout
// passes with no new message.
const exitWaitTimeout = 3

// errWaitTimeout makes Run exit with exitWaitTimeout.
var errWaitTimeout = errors.New("no new messages before the timeout")

// relayCheckEvery is how often `postern wait` looks at the relay status.
const relayCheckEvery = 2 * time.Second

// cmdWait blocks until the inbox holds at least one unread message not yet
// reported to this session, then prints a one-line notice and exits 0.
//
// It is meant to run outside the guarded tool path, as a shell watcher (a
// Claude Code background task, a terminal), so it prints metadata only: the
// count and the configured peer names. Never a subject, a body or the
// sender's session name; the session reads those with check_inbox, where
// the guard sees them.
//
// It runs its own poller (the same bridge as `postern mcp`), so it works
// with no MCP server running, and it sees messages any other process on
// this machine stored.
func cmdWait(ctx context.Context, env Env, args []string) error {
	fs, cfgFlag := newFlags(env, "wait")
	session := fs.String("session", "", "name of the agent session to wait for (must be allowed in the config)")
	timeout := fs.Duration("timeout", 0, "give up after this long and exit 3 (0 waits until a message arrives)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *session == "" {
		return errors.New("--session is required")
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if *timeout < 0 {
		return errors.New("--timeout must not be negative")
	}
	l, err := loadPinned(env, *cfgFlag)
	if err != nil {
		return err
	}
	if !l.cfg.HasSession(*session) {
		return fmt.Errorf("session %q is not allowed to use this bridge; the human can add it with `postern session add %s`", *session, *session)
	}
	if len(l.cfg.Peers) == 0 {
		return errors.New("no peers configured (postern peer add)")
	}
	configured := make([]string, 0, len(l.cfg.Peers))
	for _, p := range l.cfg.Peers {
		configured = append(configured, p.Name)
	}
	// Errors only: a watcher's output is read by the session, so keep it to
	// the one line that matters. The bridge never logs content anyway.
	logger := slog.New(slog.NewJSONHandler(env.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	opts, err := bridgeOptions(l, logger)
	if err != nil {
		return err
	}
	b, err := bridge.Open(opts)
	if err != nil {
		return err
	}
	defer b.Close()

	runCtx, stopRun := context.WithCancel(ctx)
	defer stopRun()
	ran := make(chan error, 1)
	go func() { ran <- b.Run(runCtx) }()
	defer func() { stopRun(); <-ran }()

	var (
		waitCtx  context.Context
		stopWait context.CancelFunc
	)
	if *timeout > 0 {
		waitCtx, stopWait = context.WithTimeout(ctx, *timeout)
	} else {
		waitCtx, stopWait = context.WithCancel(ctx)
	}
	defer stopWait()
	type result struct {
		a   bridge.Arrival
		err error
	}
	got := make(chan result, 1)
	go func() {
		a, err := b.WaitForNew(waitCtx, *session)
		got <- result{a, err}
	}()

	tick := time.NewTicker(relayCheckEvery)
	defer tick.Stop()
	lastStatus := ""
	for {
		select {
		case r := <-got:
			if r.err != nil {
				if errors.Is(r.err, context.DeadlineExceeded) && ctx.Err() == nil {
					fmt.Fprintf(env.Stdout, "No new Postern messages within %s.\n", *timeout)
					return errWaitTimeout
				}
				return r.err
			}
			fmt.Fprintln(env.Stdout, arrivalNotice(r.a, configured))
			return nil
		case <-tick.C:
			// A rejected or unreachable relay would otherwise look like a
			// quiet inbox. Say so once each time the status changes.
			if code := b.RelayStatus(); code != lastStatus {
				lastStatus = code
				if c, detail := mcpserver.DescribeRelayStatus(code); c != "" {
					fmt.Fprintf(env.Stderr, "postern wait: relay_status %s: %s\n", c, detail)
				}
			}
		}
	}
}

// arrivalNotice is the only line `postern wait` prints for new messages:
// the count and the sending peers, which are names from this bridge's own
// pinned config (anything else is not printed).
func arrivalNotice(a bridge.Arrival, configured []string) string {
	var peers []string
	for _, p := range a.Peers {
		if envelope.ValidPeerName(p) && slices.Contains(configured, p) && !slices.Contains(peers, p) {
			peers = append(peers, p)
		}
	}
	from := "a configured peer"
	if len(peers) > 0 {
		from = strings.Join(peers, ", ")
	}
	if a.Count == 1 {
		return fmt.Sprintf("1 new Postern message from %s. Read it with check_inbox.", from)
	}
	return fmt.Sprintf("%d new Postern messages from %s. Read them with check_inbox.", a.Count, from)
}
