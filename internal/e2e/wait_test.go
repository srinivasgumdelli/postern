package e2e

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"postern/internal/cli"
)

// waitRun is one `postern wait` run: its exit code and what it printed.
type waitRun struct {
	code           int
	stdout, stderr string
}

// startWait runs `postern wait` for n in-process, with its own stdout and
// stderr so the test sees exactly what a shell watcher would.
func (n *node) startWait(ctx context.Context, args ...string) <-chan waitRun {
	done := make(chan waitRun, 1)
	go func() {
		var out, errOut syncBuffer
		env := n.env(&out)
		env.Stderr = &errOut
		code := cli.Run(ctx, append([]string{"wait", "--config", n.cfg}, args...), env)
		done <- waitRun{code, out.String(), errOut.String()}
	}()
	return done
}

func awaitWait(t *testing.T, ch <-chan waitRun, within time.Duration) waitRun {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(within):
		t.Fatal("postern wait did not exit")
		return waitRun{}
	}
}

// noContent fails if a wait's output holds anything from the message
// other than the count and the peer name.
func noContent(t *testing.T, r waitRun, sender string) {
	t.Helper()
	for _, s := range []string{subjectMarker, bodyMarker, "please review", "UNTRUSTED", "untrusted_content", `"origin"`, sender} {
		if strings.Contains(r.stdout, s) || strings.Contains(r.stderr, s) {
			t.Fatalf("postern wait output contains %q:\nstdout: %s\nstderr: %s", s, r.stdout, r.stderr)
		}
	}
}

// TestWaitReturnsWhenAMessageArrives runs `postern wait` on machine B with
// no MCP server there, so its own poller has to fetch the message from the
// real relay.
func TestWaitReturnsWhenAMessageArrives(t *testing.T) {
	w := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sa := w.a.connect(t, ctx)

	running := w.b.startWait(ctx, "--session", "review", "--timeout", "45s")
	time.Sleep(300 * time.Millisecond) // the wait is blocked on an empty inbox
	if text, isErr := call(t, ctx, sa, "send", map[string]any{
		"to": "peer-b", "subject": subjectMarker, "body": "please review " + bodyMarker,
	}); isErr {
		t.Fatalf("send failed: %s", text)
	}
	r := awaitWait(t, running, 50*time.Second)
	if r.code != 0 {
		t.Fatalf("wait exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	if want := "1 new Postern message from peer-a. Read it with check_inbox.\n"; r.stdout != want {
		t.Fatalf("wait printed %q, want %q", r.stdout, want)
	}
	// "build" is peer-a's session name: a sender's claim, never printed.
	noContent(t, r, "build")

	// Already reported to this session: the next wait times out (exit 3)
	// even though the message is still unread.
	r = awaitWait(t, w.b.startWait(ctx, "--session", "review", "--timeout", "1s"), 20*time.Second)
	if r.code != 3 || r.stdout != "No new Postern messages within 1s.\n" {
		t.Fatalf("second wait: exit %d, stdout %q, stderr %s", r.code, r.stdout, r.stderr)
	}

	// A message stored by another process (B's MCP server, which acks it
	// at the relay, so the wait's own poller never sees it there) still
	// ends the next wait.
	sb := w.b.connect(t, ctx)
	if text, isErr := call(t, ctx, sa, "send", map[string]any{"to": "peer-b", "subject": subjectMarker, "body": bodyMarker}); isErr {
		t.Fatalf("send failed: %s", text)
	}
	waitDelivered(t, ctx, sb, 2)
	r = awaitWait(t, w.b.startWait(ctx, "--session", "review", "--timeout", "20s"), 30*time.Second)
	if r.code != 0 || r.stdout != "1 new Postern message from peer-a. Read it with check_inbox.\n" {
		t.Fatalf("wait after another process stored a message: exit %d, stdout %q, stderr %s", r.code, r.stdout, r.stderr)
	}
	noContent(t, r, "build")
}

func TestWaitTimesOutWithExit3(t *testing.T) {
	w := setup(t)
	start := time.Now()
	r := awaitWait(t, w.b.startWait(context.Background(), "--session", "review", "--timeout", "500ms"), 20*time.Second)
	if r.code != 3 {
		t.Fatalf("exit %d, want 3\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	if r.stdout != "No new Postern messages within 500ms.\n" || r.stderr != "" {
		t.Fatalf("stdout %q, stderr %q", r.stdout, r.stderr)
	}
	if el := time.Since(start); el < 500*time.Millisecond {
		t.Fatalf("returned after %s, before the timeout", el)
	}
}

func TestWaitRefusesUnlistedSession(t *testing.T) {
	w := setup(t)
	for _, args := range [][]string{
		{"--session", "intruder", "--timeout", "1s"},
		{"--timeout", "1s"},
		{"--session", "review", "--timeout", "-1s"},
	} {
		r := awaitWait(t, w.b.startWait(context.Background(), args...), 20*time.Second)
		if r.code != 1 {
			t.Fatalf("%v: exit %d, want 1\nstdout: %s\nstderr: %s", args, r.code, r.stdout, r.stderr)
		}
		if args[0] == "--session" && args[1] == "intruder" && !strings.Contains(r.stderr, "not allowed") {
			t.Fatalf("unexpected error: %s", r.stderr)
		}
		if r.stdout != "" {
			t.Fatalf("%v printed %q", args, r.stdout)
		}
	}
}

// TestWaitReportsRelayStatus checks that a rejected certificate does not
// look like a quiet inbox: the wait says so on stderr.
func TestWaitReportsRelayStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the relay status check")
	}
	w := setup(t, func(peers map[string][]string) { peers["peer-b"] = []string{strings.Repeat("0", 64)} })
	r := awaitWait(t, w.b.startWait(context.Background(), "--session", "review", "--timeout", "4s"), 30*time.Second)
	if r.code != 3 {
		t.Fatalf("exit %d, want 3\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stderr, "relay_status relay_auth_failed") || !strings.Contains(r.stderr, "postern edge-check") {
		t.Fatalf("stderr does not report the relay status: %q", r.stderr)
	}
	if n := strings.Count(r.stderr, "relay_status"); n != 1 {
		t.Fatalf("relay status reported %d times, want once:\n%s", n, r.stderr)
	}
	if !bytes.Contains([]byte(r.stdout), []byte("No new Postern messages")) {
		t.Fatalf("stdout %q", r.stdout)
	}
}
