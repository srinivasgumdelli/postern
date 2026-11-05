package mcpserver

import (
	"encoding/json"
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
