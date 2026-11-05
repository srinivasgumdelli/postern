package guard

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// A session that read its inbox through a shell (running the binary
// directly, then approved) holds framed content in a Bash tool result. A
// fork of it has a new session id and no check_inbox call in its history,
// so the scan also counts the framing itself.
func TestScanCountsFramingInToolResults(t *testing.T) {
	framed, _ := json.Marshal(map[string]any{"type": "user", "message": map[string]any{"content": []any{
		map[string]any{"type": "tool_result", "tool_use_id": "toolu_B1",
			"content": rpcLine(framedInboxText())}}}})
	if !scanString(t, lineUser+string(framed)+"\n", "") {
		t.Error("tool result with framed Postern content should count")
	}
	if scanString(t, lineUser+lineOtherTool+lineInboxResul, "") {
		t.Error("ordinary lines should not count")
	}

	opts := testOptions(t)
	tr := filepath.Join(t.TempDir(), "fork.jsonl")
	writeTranscript(t, tr, lineUser, lineOtherTool, string(framed)+"\n", lineUser)
	if r := runHook(t, opts, EventPreToolUse, preT("forked", "Bash", "default", tr, "toolu_NEW")); r.decision != decisionAsk {
		t.Fatalf("fork with framed shell output in its history: want ask, got %+v", r)
	}

	old := maxScanLine
	maxScanLine = 4096
	defer func() { maxScanLine = old }()
	pad := strings.Repeat("x", 70*1024)
	if !scanString(t, `{"text":"`+pad+` UNTRUSTED POSTERN MESSAGE `+pad+`"}`+"\n", "") {
		t.Error("overlong line with the delimiter words should count")
	}
	if !scanString(t, `{"text":"`+pad+` origin external `+pad+` trust untrusted"}`+"\n", "") {
		t.Error("overlong line with both tag values should count")
	}
	if scanString(t, `{"text":"`+pad+` untrusted `+pad+`"}`+"\n", "") {
		t.Error("overlong line with one tag value alone should not count")
	}
}
