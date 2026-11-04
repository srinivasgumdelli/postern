package guard

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Transcript lines shaped like Claude Code's JSONL. Only the tool name and
// tool_use id matter to the guard.
const (
	lineUser       = `{"type":"user","message":{"role":"user","content":"please review the change"}}` + "\n"
	lineOtherTool  = `{"type":"assistant","message":{"content":[{"type":"tool_use","id":"toolu_A1","name":"Bash","input":{"command":"ls"}}]}}` + "\n"
	lineInboxCall  = `{"type":"assistant","message":{"content":[{"type":"tool_use","id":"toolu_PARENT","name":"mcp__postern__check_inbox","input":{}}]}}` + "\n"
	lineInboxResul = `{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"toolu_PARENT","content":"..."}]}}` + "\n"
)

func writeTranscript(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "")), 0o600); err != nil {
		t.Fatal(err)
	}
}

func appendTranscript(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(strings.Join(lines, "")); err != nil {
		t.Fatal(err)
	}
}

func preT(session, tool, mode, transcript, toolUseID string) map[string]any {
	in := preInput(session, tool, mode, map[string]any{"command": "ls"})
	in["transcript_path"] = transcript
	in["tool_use_id"] = toolUseID
	return in
}

func TestPreToolUseTaintsForkWithoutMarker(t *testing.T) {
	opts := testOptions(t)
	tr := filepath.Join(t.TempDir(), "fork.jsonl")
	// A forked session: new id, history copied from a session that read
	// its inbox. No SessionStart ran (or it failed): there is no marker.
	writeTranscript(t, tr, lineUser, lineInboxCall, lineInboxResul, lineUser)

	r := runHook(t, opts, EventPreToolUse, preT("forked", "Bash", "default", tr, "toolu_NEW"))
	if r.decision != decisionAsk {
		t.Fatalf("want ask, got %+v", r)
	}
	if m, ok := readMarker(t, opts, "forked"); !ok || m.State != stateTainted {
		t.Fatalf("want a tainted marker written, got %+v %v", m, ok)
	}
	if r := runHook(t, opts, EventPreToolUse, preT("forked", "Bash", "bypassPermissions", tr, "toolu_NEW2")); r.decision != decisionDeny {
		t.Fatalf("bypass: want deny, got %+v", r)
	}

	// Same for a fork whose first call is check_inbox: the inherited taint
	// is picked up before this call is armed, so an empty result cannot
	// clear it.
	opts2 := testOptions(t)
	runHook(t, opts2, EventPreToolUse, preT("forked", "mcp__postern__check_inbox", "default", tr, "toolu_NEW"))
	runHook(t, opts2, EventPostToolUse, postInput("forked", "mcp__postern__check_inbox", inboxBlocks()))
	if m, ok := readMarker(t, opts2, "forked"); !ok || m.State != stateTainted {
		t.Fatalf("fork's own empty check_inbox cleared inherited taint: %+v %v", m, ok)
	}
}

func TestSessionStartForkWriteFailureIsCoveredByPreToolUse(t *testing.T) {
	old := lockWait
	lockWait = 50 * time.Millisecond
	defer func() { lockWait = old }()
	opts := testOptions(t)
	tr := filepath.Join(t.TempDir(), "fork.jsonl")
	writeTranscript(t, tr, lineInboxCall, lineInboxResul)

	// SessionStart cannot write the marker (lock held by a live process).
	if err := os.MkdirAll(opts.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(opts.StateDir, sessionKey("forked")+".lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := runHook(t, opts, EventSessionStart, startInput("forked", "fork", tr)); r.code != 2 {
		t.Fatalf("SessionStart: want exit 2 (marker not written), got %+v", r)
	}
	if _, ok := readMarker(t, opts, "forked"); ok {
		t.Fatal("marker unexpectedly written")
	}
	// Exit 2 does not block a SessionStart, so the session goes on. The
	// next tool call must still be gated, even while the marker cannot be
	// written yet.
	if r := runHook(t, opts, EventPreToolUse, preT("forked", "Bash", "default", tr, "toolu_X")); r.decision != decisionAsk {
		t.Fatalf("want ask while the marker cannot be written, got %+v", r)
	}
	os.Remove(lock)
	if r := runHook(t, opts, EventPreToolUse, preT("forked", "Bash", "default", tr, "toolu_Y")); r.decision != decisionAsk {
		t.Fatalf("want ask, got %+v", r)
	}
	if m, ok := readMarker(t, opts, "forked"); !ok || m.State != stateTainted {
		t.Fatalf("want tainted, got %+v %v", m, ok)
	}
}

func TestClearThenMoreCallsDoNotRetaint(t *testing.T) {
	for _, how := range []string{"postern clear", "/postern-clear", "session-start clear"} {
		t.Run(how, func(t *testing.T) {
			opts := testOptions(t)
			tr := filepath.Join(t.TempDir(), "s.jsonl")
			writeTranscript(t, tr, lineUser, lineInboxCall, lineInboxResul)
			if r := runHook(t, opts, EventPreToolUse, preT("s1", "Bash", "default", tr, "toolu_1")); r.decision != decisionAsk {
				t.Fatalf("before clear: want ask, got %+v", r)
			}
			if how == "session-start clear" {
				runHook(t, opts, EventSessionStart, startInput("s1", "clear", tr))
			} else if r := runHook(t, opts, EventUserPromptSubmit, promptInput("s1", how)); !r.block {
				t.Fatalf("want block, got %+v", r)
			}
			// The transcript still names check_inbox, and keeps growing.
			for i, line := range []string{lineOtherTool, lineInboxCall, lineUser} {
				appendTranscript(t, tr, line)
				if r := runHook(t, opts, EventPreToolUse, preT("s1", "Bash", "default", tr, "toolu_after")); !r.noDecision() {
					t.Fatalf("call %d after clear re-tainted: %+v", i, r)
				}
			}
			if m, _ := readMarker(t, opts, "s1"); m.State != stateCleared {
				t.Fatalf("want cleared, got %+v", m)
			}
			// A later check_inbox arms the guard again as usual.
			runHook(t, opts, EventPreToolUse, preT("s1", "mcp__postern__check_inbox", "default", tr, "toolu_2"))
			runHook(t, opts, EventPostToolUse, postInput("s1", "mcp__postern__check_inbox", inboxBlocks(testMessage("s", "b"))))
			if r := runHook(t, opts, EventPreToolUse, preT("s1", "Bash", "default", tr, "toolu_3")); r.decision != decisionAsk {
				t.Fatalf("after a new message: want ask, got %+v", r)
			}
		})
	}
}

func TestOwnEmptyCheckInboxDoesNotTaintViaTranscript(t *testing.T) {
	opts := testOptions(t)
	tr := filepath.Join(t.TempDir(), "s.jsonl")
	writeTranscript(t, tr, lineUser)
	if r := runHook(t, opts, EventPreToolUse, preT("s1", "Bash", "default", tr, "toolu_0")); !r.noDecision() {
		t.Fatalf("clean session: got %+v", r)
	}
	// Claude Code has already written this call's tool_use line when the
	// hook runs. The scan ignores the line carrying the current id.
	own := `{"type":"assistant","message":{"content":[{"type":"tool_use","id":"toolu_OWN","name":"mcp__postern__check_inbox","input":{}}]}}` + "\n"
	appendTranscript(t, tr, own)
	if r := runHook(t, opts, EventPreToolUse, preT("s1", "mcp__postern__check_inbox", "default", tr, "toolu_OWN")); !r.noDecision() {
		t.Fatalf("check_inbox: got %+v", r)
	}
	if m, _ := readMarker(t, opts, "s1"); m.State != statePending {
		t.Fatalf("the call's own line tainted the session: %+v", m)
	}
	runHook(t, opts, EventPostToolUse, postInput("s1", "mcp__postern__check_inbox", inboxBlocks()))
	appendTranscript(t, tr, lineUser)
	if r := runHook(t, opts, EventPreToolUse, preT("s1", "Bash", "default", tr, "toolu_9")); !r.noDecision() {
		t.Fatalf("after an empty inbox the transcript scan re-tainted: %+v", r)
	}
}

func TestUnreadableTranscriptAsks(t *testing.T) {
	dir := t.TempDir()
	t.Run("directory", func(t *testing.T) {
		opts := testOptions(t)
		r := runHook(t, opts, EventPreToolUse, preT("s1", "Bash", "default", dir, "toolu_1"))
		if r.decision != decisionAsk || !strings.Contains(r.reason, "transcript") {
			t.Fatalf("want ask, got %+v", r)
		}
		if r := runHook(t, opts, EventPreToolUse, preT("s1", "Bash", "dontAsk", dir, "toolu_1")); r.decision != decisionDeny {
			t.Fatalf("dontAsk: want deny, got %+v", r)
		}
		// check_inbox runs, but the unknown history counts as tainted.
		if r := runHook(t, opts, EventPreToolUse, preT("s1", "mcp__postern__check_inbox", "default", dir, "toolu_2")); !r.noDecision() {
			t.Fatalf("check_inbox: got %+v", r)
		}
		runHook(t, opts, EventPostToolUse, postInput("s1", "mcp__postern__check_inbox", inboxBlocks()))
		if m, ok := readMarker(t, opts, "s1"); !ok || m.State != stateTainted {
			t.Fatalf("want tainted, got %+v %v", m, ok)
		}
	})
	t.Run("no permission", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("file modes do not restrict this user")
		}
		opts := testOptions(t)
		tr := filepath.Join(dir, "locked.jsonl")
		writeTranscript(t, tr, lineUser)
		if err := os.Chmod(tr, 0o000); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(tr, 0o600)
		if r := runHook(t, opts, EventPreToolUse, preT("s1", "Bash", "default", tr, "toolu_1")); r.decision != decisionAsk {
			t.Fatalf("want ask, got %+v", r)
		}
	})
}

func TestMissingTranscriptStaysUntainted(t *testing.T) {
	opts := testOptions(t)
	for _, tr := range []string{"", filepath.Join(t.TempDir(), "not-yet-written.jsonl")} {
		if r := runHook(t, opts, EventPreToolUse, preT("s1", "Bash", "default", tr, "toolu_1")); !r.noDecision() {
			t.Fatalf("transcript %q: want no decision, got %+v", tr, r)
		}
	}
	if _, ok := readMarker(t, opts, "s1"); ok {
		t.Fatal("no transcript should not create a marker")
	}
}

func TestOffsetScanCatchesLaterAppend(t *testing.T) {
	opts := testOptions(t)
	tr := filepath.Join(t.TempDir(), "fork.jsonl")
	writeTranscript(t, tr, lineUser, lineOtherTool)
	if r := runHook(t, opts, EventPreToolUse, preT("forked", "Bash", "default", tr, "toolu_1")); !r.noDecision() {
		t.Fatalf("clean transcript: got %+v", r)
	}
	m, ok := readMarker(t, opts, "forked")
	fi, _ := os.Stat(tr)
	if !ok || m.State != stateClean || m.Scanned != fi.Size() || m.Transcript == "" || strings.Contains(m.Transcript, "fork") {
		t.Fatalf("want clean marker at offset %d with a hashed path, got %+v", fi.Size(), m)
	}
	// The copied history lands after SessionStart and the first call.
	appendTranscript(t, tr, lineInboxCall, lineInboxResul)
	if r := runHook(t, opts, EventPreToolUse, preT("forked", "Bash", "default", tr, "toolu_2")); r.decision != decisionAsk {
		t.Fatalf("appended check_inbox: want ask, got %+v", r)
	}
}

func TestOffsetScanOnlyReadsNewBytes(t *testing.T) {
	opts := testOptions(t)
	tr := filepath.Join(t.TempDir(), "s.jsonl")
	writeTranscript(t, tr, lineUser, lineOtherTool)
	runHook(t, opts, EventPreToolUse, preT("s1", "Bash", "default", tr, "toolu_1"))
	first, _ := readMarker(t, opts, "s1")

	// Rewrite the already-scanned region in place (same length): an
	// offset scan does not read it again.
	b, _ := os.ReadFile(tr)
	copy(b, []byte(strings.Repeat("z", len(b)-1)))
	os.WriteFile(tr, b, 0o600)
	appendTranscript(t, tr, lineUser)
	if r := runHook(t, opts, EventPreToolUse, preT("s1", "Bash", "default", tr, "toolu_2")); !r.noDecision() {
		t.Fatalf("got %+v", r)
	}
	second, _ := readMarker(t, opts, "s1")
	if second.Scanned != first.Scanned+int64(len(lineUser)) {
		t.Fatalf("offset %d -> %d, want +%d", first.Scanned, second.Scanned, len(lineUser))
	}

	// A shorter file (replaced or truncated) is rescanned from the start.
	writeTranscript(t, tr, lineInboxCall)
	if r := runHook(t, opts, EventPreToolUse, preT("s1", "Bash", "default", tr, "toolu_3")); r.decision != decisionAsk {
		t.Fatalf("shrunk transcript: want ask, got %+v", r)
	}

	// A different transcript path is scanned from the start too.
	opts2 := testOptions(t)
	a := filepath.Join(t.TempDir(), "a.jsonl")
	c := filepath.Join(t.TempDir(), "c.jsonl")
	writeTranscript(t, a, lineUser, lineUser, lineUser)
	writeTranscript(t, c, lineInboxCall, lineUser, lineUser, lineUser)
	runHook(t, opts2, EventPreToolUse, preT("s2", "Bash", "default", a, "toolu_1"))
	if r := runHook(t, opts2, EventPreToolUse, preT("s2", "Bash", "default", c, "toolu_2")); r.decision != decisionAsk {
		t.Fatalf("new transcript path: want ask, got %+v", r)
	}
}

func TestPartialLastLineIsRescanned(t *testing.T) {
	opts := testOptions(t)
	tr := filepath.Join(t.TempDir(), "s.jsonl")
	// The last line is still being written: no newline yet, and the name
	// has not arrived.
	writeTranscript(t, tr, lineUser, `{"type":"assistant","message":{"content":[{"type":"tool_use","id":"toolu_P","name":"mcp__postern__check_`)
	runHook(t, opts, EventPreToolUse, preT("s1", "Bash", "default", tr, "toolu_1"))
	if m, _ := readMarker(t, opts, "s1"); m.Scanned != int64(len(lineUser)) {
		t.Fatalf("offset should stop at the last complete line, got %d", m.Scanned)
	}
	appendTranscript(t, tr, `inbox","input":{}}]}}`+"\n")
	if r := runHook(t, opts, EventPreToolUse, preT("s1", "Bash", "default", tr, "toolu_2")); r.decision != decisionAsk {
		t.Fatalf("completed line: want ask, got %+v", r)
	}
}

func scanString(t *testing.T, data, exclude string) bool {
	t.Helper()
	found, _, err := scanLines(strings.NewReader(data), []byte(exclude), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func TestScanMatchesOnlyRealToolCalls(t *testing.T) {
	cases := []struct {
		name, line string
		want       bool
	}{
		{"tool_use line", lineInboxCall, true},
		{"plugin-scoped server", `{"type":"assistant","message":{"content":[{"type":"tool_use","id":"toolu_P","name":"mcp__plugin_x_postern__check_inbox","input":{}}]}}`, true},
		{"whitespace around colons", `{"message": {"content": [{"type" : "tool_use", "id": "toolu_P", "name" :  "mcp__postern__check_inbox", "input": {}}]}}`, true},
		{"name before type", `{"content":[{"name":"mcp__postern__check_inbox","id":"toolu_P","type":"tool_use"}]}`, true},
		{"deferred-tool listing in a system message",
			`{"type":"system","content":"The following deferred tools are now available via ToolSearch:\nmcp__postern__check_inbox\nmcp__postern__mark_read\nmcp__postern__send"}`, false},
		{"listing with escaped JSON in text",
			`{"type":"user","message":{"content":[{"type":"text","text":"tools: [{\"type\":\"tool_use\",\"name\":\"mcp__postern__check_inbox\"}]"}]}}`, false},
		{"tool_result mentioning check_inbox",
			`{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"toolu_PARENT","content":"I will call mcp__postern__check_inbox next (tool_use)"}]}}`, false},
		{"other tool call", lineOtherTool, false},
		{"tool name in a non-tool block", `{"type":"attachment","name":"mcp__postern__check_inbox"}`, false},
		{"tool_use and name on different lines", `{"type":"tool_use","name":"Bash"}` + "\n" + `{"name":"mcp__postern__check_inbox"}`, false},
	}
	for _, c := range cases {
		if got := scanString(t, c.line+"\n", ""); got != c.want {
			t.Errorf("%s: matched=%v, want %v", c.name, got, c.want)
		}
	}
	// The current call's own line is skipped; another call on another line
	// still counts.
	if scanString(t, lineInboxCall, "toolu_PARENT") {
		t.Error("the excluded tool_use_id's line matched")
	}
	if !scanString(t, lineInboxCall+lineUser+strings.Replace(lineInboxCall, "toolu_PARENT", "toolu_OLD", 1), "toolu_PARENT") {
		t.Error("a different call was skipped")
	}
}

func TestScanOverlongLineIsConservative(t *testing.T) {
	old := maxScanLine
	maxScanLine = 4096
	defer func() { maxScanLine = old }()
	pad := strings.Repeat("x", 70*1024) // also spans several read chunks
	// Too long to match exactly: any line naming both tokens counts...
	long := `{"type":"user","message":{"content":"` + pad + ` tool_use ` + pad + ` mcp__postern__check_inbox"}}`
	if !scanString(t, long+"\n", "") {
		t.Error("overlong line with both tokens should count")
	}
	// ...unless it is the current call's own line...
	if scanString(t, long+` "id":"toolu_SELF"`+"\n", "toolu_SELF") {
		t.Error("overlong excluded line should not count")
	}
	// ...and one token alone is not enough.
	if scanString(t, `{"text":"`+pad+` mcp__postern__check_inbox"}`+"\n", "") {
		t.Error("overlong line without tool_use should not count")
	}
	// Short lines still use the exact structural match.
	if !scanString(t, lineInboxCall, "") {
		t.Error("short tool_use line should match")
	}
}

func TestScanLinesOffsetsAndLimits(t *testing.T) {
	found, n, err := scanLines(strings.NewReader("x\nyy\nzzz"), nil, 1<<30)
	if err != nil || found || n != 5 {
		t.Fatalf("got %v %d %v; want false, 5 (last complete line)", found, n, err)
	}
	if _, _, err := scanLines(strings.NewReader(strings.Repeat("a", 100)), nil, 10); err == nil {
		t.Fatal("over the limit should be an error")
	}
}

func TestDeferredToolListingDoesNotArmSession(t *testing.T) {
	opts := testOptions(t)
	tr := filepath.Join(t.TempDir(), "s.jsonl")
	listing := `{"type":"system","subtype":"informational","content":"<system-reminder>The following deferred tools are now available via ToolSearch:\nmcp__postern__check_inbox\nmcp__postern__mark_read\nmcp__postern__reply\nmcp__postern__send\n</system-reminder>"}` + "\n"
	result := `{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"toolu_A1","content":"see mcp__postern__check_inbox in the tool list"}]}}` + "\n"
	writeTranscript(t, tr, lineUser, listing, lineOtherTool, result)
	if r := runHook(t, opts, EventPreToolUse, preT("s1", "Bash", "default", tr, "toolu_1")); !r.noDecision() {
		t.Fatalf("listing armed the guard: %+v", r)
	}
	if m, _ := readMarker(t, opts, "s1"); m.State != stateClean {
		t.Fatalf("want clean, got %+v", m)
	}
	appendTranscript(t, tr, lineInboxCall)
	if r := runHook(t, opts, EventPreToolUse, preT("s1", "Bash", "default", tr, "toolu_2")); r.decision != decisionAsk {
		t.Fatalf("real tool_use: want ask, got %+v", r)
	}
}
