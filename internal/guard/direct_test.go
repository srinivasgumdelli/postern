package guard

import (
	"strings"
	"testing"
)

var directRuns = []string{
	"postern mcp --session review",
	"/usr/local/bin/postern mcp --session x",
	`printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize"}' | postern mcp --session x`,
	`bash -c 'cat req.jsonl | /usr/local/bin/postern mcp --session x'`,
	`sh -lc "postern mcp --session x < req.jsonl"`,
	"cd /tmp && ./postern mcp --session x",
	"env POSTERN_CONFIG=/tmp/c postern mcp --session x",
	"(echo x; sleep 1) | postern mcp",
	"x=$(postern mcp --session x)",
	"`postern mcp`",
	"POSTERN MCP",
	`"postern" "mcp"`,
	`pos''tern m"c"p`,
	`postern \` + "\n" + `  mcp --session x`,
	"go run ./cmd/postern mcp --session x",
	"/opt/tools/bridge mcp --session x", // the configured binary path
	"bridge mcp",                        // its basename
	"echo '{}' | postern hook pre-tool-use --server postern",
	"postern hook user-prompt-submit < fake.json",
	"postern $SUB --session x",
	"postern $(cat sub.txt)",
	"postern ${SUB:-mcp}",
}

var notDirectRuns = []string{
	"postern show",
	"postern edge-check",
	"postern version",
	"/usr/local/bin/postern show --config /tmp/c",
	"postern guard install --project .",
	"postern wait --session review",
	"/usr/local/bin/postern wait --session review --timeout 30m",
	"bridge wait --session review", // the configured binary's basename
	"until postern wait --session review --timeout 10m; do :; done",
	"ls -l /usr/local/bin/postern",
	"grep -rn mcp internal/",
	"git log --oneline -- internal/mcpserver",
	"echo postern; echo mcp",
	"go test ./internal/guard/...",
	"cat postern-mcp.log",
	"postern",
	"",
}

func TestRunsPosternDirectly(t *testing.T) {
	bins := []string{"/opt/tools/bridge"}
	for _, c := range directRuns {
		if !runsPosternDirectly(c, bins) {
			t.Errorf("not caught: %q", c)
		}
	}
	for _, c := range notDirectRuns {
		if runsPosternDirectly(c, bins) {
			t.Errorf("caught by mistake: %q", c)
		}
	}
}

func TestShellCommandField(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{`{"command":"postern mcp"}`, "postern mcp", true},
		{`{"cmd":"postern mcp"}`, "postern mcp", true},
		{`{"command":["bash","-lc","postern mcp"]}`, "bash -lc postern mcp", true},
		{`{"file_path":"/x"}`, "", false},
		{`{"command":42}`, "", false},
		{`not json`, "", false},
	}
	for _, c := range cases {
		got, ok := shellCommand([]byte(c.in))
		if got != c.want || ok != c.ok {
			t.Errorf("shellCommand(%s) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestDirectPosternRunAsksEvenWhenUntainted(t *testing.T) {
	opts := testOptions(t)
	opts.BinaryPath = "/opt/tools/bridge"
	for _, tool := range []string{"Bash", "mcp__other__shell", "SomeFutureShell"} {
		for _, c := range directRuns {
			r := runHook(t, opts, EventPreToolUse, preInput("clean", tool, "default", map[string]any{"command": c}))
			if r.decision != decisionAsk || !strings.Contains(r.reason, "MCP tools") || !strings.Contains(r.reason, "bypasses") {
				t.Errorf("%s %q: want ask with the direct-run reason, got %+v", tool, c, r)
			}
			if strings.Contains(r.reason, "--session") {
				t.Errorf("%q: reason must not echo the command: %q", c, r.reason)
			}
		}
	}
	// The check leaves the session untainted.
	if _, ok := readMarker(t, opts, "clean"); ok {
		t.Fatal("a direct-run check created a marker")
	}
	// Ordinary commands, including other postern subcommands, go through.
	for _, c := range notDirectRuns {
		if r := runHook(t, opts, EventPreToolUse, preInput("clean", "Bash", "default", map[string]any{"command": c})); !r.noDecision() {
			t.Errorf("%q: want no decision, got %+v", c, r)
		}
	}
	// A tool without a command field is not inspected.
	if r := runHook(t, opts, EventPreToolUse, preInput("clean", "Write", "default",
		map[string]any{"file_path": "/path/to/run.sh", "content": "postern mcp --session x"})); !r.noDecision() {
		t.Errorf("Write with postern mcp in its content: want no decision, got %+v", r)
	}
}

// `postern wait` is the supported way to watch for messages from a shell
// (a Claude Code background task). It prints a count and peer names only,
// so the direct-run check leaves it alone, and its output does not taint.
func TestPosternWaitIsNotADirectRun(t *testing.T) {
	opts := testOptions(t)
	opts.BinaryPath = "/opt/tools/bridge"
	cmd := map[string]any{"command": "/opt/tools/bridge wait --session review --timeout 30m", "run_in_background": true}
	for _, mode := range []string{"default", "bypassPermissions"} {
		if r := runHook(t, opts, EventPreToolUse, preInput("clean", "Bash", mode, cmd)); !r.noDecision() {
			t.Errorf("mode %q: want no decision for postern wait, got %+v", mode, r)
		}
	}
	resp := map[string]any{"stdout": "2 new Postern messages from peer-b. Read them with check_inbox.\n", "stderr": "", "interrupted": false}
	if r := runHook(t, opts, EventPostToolUse, postInput("clean", "Bash", resp)); r.code != 0 || len(r.out) != 0 {
		t.Fatalf("post hook on wait output: %+v", r)
	}
	if _, ok := readMarker(t, opts, "clean"); ok {
		t.Fatal("postern wait's output tainted the session")
	}
}

func TestDirectPosternRunDeniedWithoutPrompts(t *testing.T) {
	opts := testOptions(t)
	for _, mode := range []string{"bypassPermissions", "dontAsk", "auto", "something-new"} {
		r := runHook(t, opts, EventPreToolUse, preInput("clean", "Bash", mode, map[string]any{"command": "postern mcp --session x"}))
		if r.decision != decisionDeny || !strings.Contains(r.reason, "MCP tools") {
			t.Errorf("mode %q: want deny, got %+v", mode, r)
		}
		if r := runHook(t, opts, EventPreToolUse, preInput("clean", "Bash", mode, map[string]any{"command": "postern show"})); !r.noDecision() {
			t.Errorf("mode %q: postern show: want no decision, got %+v", mode, r)
		}
	}
}

func TestDirectPosternRunAsksWhenTainted(t *testing.T) {
	opts := testOptions(t)
	taintSession(t, opts, "s1")
	r := runHook(t, opts, EventPreToolUse, preInput("s1", "Bash", "default", map[string]any{"command": "postern mcp --session x"}))
	if r.decision != decisionAsk {
		t.Fatalf("want ask, got %+v", r)
	}
	r = runHook(t, opts, EventPreToolUse, preInput("s1", "Bash", "bypassPermissions", map[string]any{"command": "postern show"}))
	if r.decision != decisionDeny {
		t.Fatalf("tainted, bypass mode: want deny, got %+v", r)
	}
}
