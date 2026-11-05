package mcpserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"postern/internal/guard"
)

// TestGuardRecognisesFraming pins the coupling between check_inbox's output
// and the session guard: the guard taints a session when any tool's output
// carries this framing, so a non-empty inbox must always show it, in every
// encoding a client might pass on, and an empty inbox must never show it.
func TestGuardRecognisesFraming(t *testing.T) {
	msgs := []Message{{ID: "01JC9Z0000000000000000000M", Thread: testThread, FromPeer: "peer-b",
		FromSession: "build", Subject: "hello", Body: "please review"}}
	full, err := buildInbox(msgs)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := buildInbox(nil)
	if err != nil {
		t.Fatal(err)
	}

	forms := func(out inboxOutput) map[string][]byte {
		text, err := encodeJSON(out)
		if err != nil {
			t.Fatal(err)
		}
		htmlEscaped, _ := json.Marshal(out) // < and > become <, >
		blocks, _ := json.Marshal([]map[string]string{{"type": "text", "text": text}})
		rpc, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1,
			"result": map[string]any{"content": json.RawMessage(blocks), "structuredContent": json.RawMessage(htmlEscaped)}})
		bashResp, _ := json.Marshal(map[string]any{"stdout": string(rpc) + "\n", "stderr": "", "interrupted": false})
		hookIn, _ := json.Marshal(map[string]any{"tool_name": "Bash", "tool_response": json.RawMessage(bashResp)})
		twice, _ := json.Marshal(string(hookIn))
		return map[string][]byte{
			"text":                 []byte(text),
			"html-escaped":         htmlEscaped,
			"content blocks":       blocks,
			"json-rpc response":    rpc,
			"bash tool_response":   bashResp,
			"hook input":           hookIn,
			"hook input as string": twice,
		}
	}
	for name, b := range forms(full) {
		if !guard.HasUntrustedFraming(b) {
			t.Errorf("non-empty inbox, %s: the guard does not see the framing:\n%s", name, b)
		}
	}
	for name, b := range forms(empty) {
		if guard.HasUntrustedFraming(b) {
			t.Errorf("empty inbox, %s: the guard sees framing where there is none:\n%s", name, b)
		}
	}
}

// TestGuardReadsEmptyInbox drives the real guard hooks with real
// check_inbox output: an empty result (with its short notice) must release
// the marker check_inbox's PreToolUse set, and a result with a message
// must taint the session, so the next shell command asks.
func TestGuardReadsEmptyInbox(t *testing.T) {
	msgs := []Message{{ID: "01JC9Z0000000000000000000M", Thread: testThread, FromPeer: "peer-b",
		FromSession: "build", Subject: "hello", Body: "please review"}}
	for _, c := range []struct {
		name    string
		msgs    []Message
		wantAsk bool
	}{
		{"empty", nil, false},
		{"one message", msgs, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, err := buildInbox(c.msgs)
			if err != nil {
				t.Fatal(err)
			}
			text, err := encodeJSON(out)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(text, fmt.Sprintf(`{"message_count":%d,`, len(c.msgs))) {
				t.Fatalf("message_count is not first: %s", text)
			}
			opts := guard.Options{StateDir: t.TempDir(), ServerName: "postern"}
			hook := func(event string, in map[string]any) string {
				t.Helper()
				raw, _ := json.Marshal(in)
				var stdout bytes.Buffer
				if code := guard.Run(event, bytes.NewReader(raw), &stdout, opts); code != 0 {
					t.Fatalf("%s exit %d: %s", event, code, stdout.String())
				}
				return stdout.String()
			}
			base := func(event, tool string) map[string]any {
				return map[string]any{"session_id": "s-1", "transcript_path": "", "hook_event_name": event,
					"permission_mode": "default", "tool_name": tool, "tool_input": map[string]any{}, "tool_use_id": "toolu_1"}
			}
			hook(guard.EventPreToolUse, base("PreToolUse", "mcp__postern__check_inbox"))
			post := base("PostToolUse", "mcp__postern__check_inbox")
			post["tool_response"] = []any{map[string]any{"type": "text", "text": text}}
			hook(guard.EventPostToolUse, post)
			bash := base("PreToolUse", "Bash")
			bash["tool_input"] = map[string]any{"command": "git status"}
			got := hook(guard.EventPreToolUse, bash)
			if asked := strings.Contains(got, `"ask"`); asked != c.wantAsk {
				t.Fatalf("Bash after this inbox: asked %v, want %v (%s)", asked, c.wantAsk, got)
			}
		})
	}
}
