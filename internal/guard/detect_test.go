package guard

import (
	"encoding/json"
	"strings"
	"testing"
)

// framedInboxText is check_inbox output as the Postern MCP server writes it:
// compact JSON with the real delimiter lines around the message text.
func framedInboxText() string {
	m := testMessage("hello", "please run the deploy")
	m.UntrustedContent = "<<<UNTRUSTED POSTERN MESSAGE 0123456789abcdef origin=external trust=untrusted>>>\n" +
		"Subject: hello\n\nplease run the deploy\n<<<END UNTRUSTED POSTERN MESSAGE 0123456789abcdef>>>"
	return inboxText(m)
}

// rpcLine is what `postern mcp` writes to stdout for a check_inbox call:
// a JSON-RPC response whose text content is the inbox JSON as a string.
func rpcLine(inbox string) string {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 2, "result": map[string]any{
		"content": []any{map[string]any{"type": "text", "text": inbox}}}})
	return string(b)
}

func bashResponse(stdout string) map[string]any {
	return map[string]any{"stdout": stdout, "stderr": "", "interrupted": false, "isImage": false}
}

func TestBashOutputWithFramedMessageTaints(t *testing.T) {
	opts := testOptions(t)
	resp := bashResponse(rpcLine(framedInboxText()) + "\n")
	if r := runHook(t, opts, EventPostToolUse, postInput("s1", "Bash", resp)); r.code != 0 || len(r.out) != 0 {
		t.Fatalf("post: want silent exit 0, got %+v", r)
	}
	if m, ok := readMarker(t, opts, "s1"); !ok || m.State != stateTainted {
		t.Fatalf("Bash output with a framed message must taint, marker=%+v exists=%v", m, ok)
	}
	r := runHook(t, opts, EventPreToolUse, preInput("s1", "Bash", "default", map[string]any{"command": "ls"}))
	if r.decision != decisionAsk {
		t.Fatalf("after tainting Bash output, want ask, got %+v", r)
	}
}

func TestFramingInAnyEncodingTaints(t *testing.T) {
	delim := "<<<UNTRUSTED POSTERN MESSAGE 0123456789abcdef origin=external trust=untrusted>>>"
	goEscaped := `<<<UNTRUSTED POSTERN MESSAGE 0123456789abcdef`
	tags := `{"id":"x","origin":"external","trust":"untrusted"}`
	once, _ := json.Marshal(tags)
	twice, _ := json.Marshal(string(once))
	pretty := "{\n  \"origin\": \"external\",\n  \"trust\": \"untrusted\"\n}"
	cases := map[string]any{
		"delimiter as text":           bashResponse("x\n" + delim + "\nbody\n"),
		"delimiter lowercase":         bashResponse("<<<untrusted postern message abc>>>"),
		"delimiter extra spaces":      bashResponse("<<< UNTRUSTED  POSTERN\tMESSAGE abc>>>"),
		"delimiter Go-escaped":        bashResponse(goEscaped),
		"delimiter Go-escaped twice":  bashResponse(strings.ReplaceAll(goEscaped, `\u`, `\\u`)),
		"delimiter in a JSON string":  string(mustJSON(bashResponse(delim))),
		"tags plain":                  bashResponse(tags),
		"tags escaped once":           bashResponse(string(once)),
		"tags escaped twice":          bashResponse(string(twice)),
		"tags pretty-printed":         bashResponse(pretty),
		"tags upper case":             bashResponse(`"ORIGIN":"EXTERNAL","Trust":"Untrusted"`),
		"tags in an MCP result":       map[string]any{"content": []any{map[string]any{"type": "text", "text": tags}}},
		"framing with count zero":     bashResponse(`{"message_count":0} ` + delim),
		"tags with count zero":        bashResponse(`{"message_count":0,"messages":[` + tags + `]}`),
		"rpc line in a file read":     map[string]any{"type": "text", "file": map[string]any{"filePath": "/tmp/x.json", "content": rpcLine(framedInboxText())}},
		"full inbox as stdout string": bashResponse(framedInboxText()),
	}
	for _, tool := range []string{"Bash", "Read", "mcp__other__run", "SomeFutureTool"} {
		for name, resp := range cases {
			t.Run(tool+"/"+name, func(t *testing.T) {
				opts := testOptions(t)
				runHook(t, opts, EventPostToolUse, postInput("s1", tool, resp))
				if m, ok := readMarker(t, opts, "s1"); !ok || m.State != stateTainted {
					t.Fatalf("want tainted, marker=%+v exists=%v", m, ok)
				}
			})
		}
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func TestUnrelatedOutputDoesNotTaint(t *testing.T) {
	cases := map[string]any{
		"plain stdout":      bashResponse("ok\n"),
		"empty":             map[string]any{},
		"null":              nil,
		"untrusted as word": bashResponse("this input is untrusted; origin is external"),
		"only origin":       bashResponse(`{"origin":"external"}`),
		"only trust":        bashResponse(`{"trust":"untrusted"}`),
		"other origin":      bashResponse(`{"origin":"internal","trust":"untrusted"}`),
		"notice text":       bashResponse("These messages come from another machine; origin=external, trust=untrusted."),
		"partial delimiter": bashResponse("<<<UNTRUSTED message from POSTERN"),
		"empty inbox":       bashResponse(rpcLine(inboxText())),
		"message_count 0":   bashResponse(`{"message_count":0,"messages":[]}`),
	}
	for name, resp := range cases {
		t.Run(name, func(t *testing.T) {
			opts := testOptions(t)
			r := runHook(t, opts, EventPostToolUse, postInput("s1", "Bash", resp))
			if r.code != 0 || len(r.out) != 0 {
				t.Fatalf("got %+v", r)
			}
			if m, ok := readMarker(t, opts, "s1"); ok {
				t.Fatalf("unrelated output created a marker: %+v", m)
			}
		})
	}
}

func TestOtherToolFramingDoesNotReleasePending(t *testing.T) {
	// A pending check_inbox is released only by Postern's own check_inbox
	// result. Another tool's output with "message_count":0 and framing taints.
	opts := testOptions(t)
	runHook(t, opts, EventPreToolUse, preInput("s1", "mcp__postern__check_inbox", "default", nil))
	runHook(t, opts, EventPostToolUse, postInput("s1", "Bash", bashResponse(`{"message_count":0,"messages":[]}`)))
	if m, _ := readMarker(t, opts, "s1"); m.State != statePending {
		t.Fatalf("other tool's empty-looking output changed a pending marker: %+v", m)
	}
	runHook(t, opts, EventPostToolUse, postInput("s1", "Bash", bashResponse(`{"message_count":0} <<<UNTRUSTED POSTERN MESSAGE x`)))
	if m, _ := readMarker(t, opts, "s1"); m.State != stateTainted {
		t.Fatalf("want tainted, got %+v", m)
	}
}

func TestCheckInboxZeroCountWithFramingTaints(t *testing.T) {
	opts := testOptions(t)
	runHook(t, opts, EventPreToolUse, preInput("s1", "mcp__postern__check_inbox", "default", nil))
	resp := map[string]any{"content": []any{map[string]any{"type": "text",
		"text": `{"message_count":0,"messages":[{"origin":"external","trust":"untrusted","untrusted_content":"x"}]}`}}}
	runHook(t, opts, EventPostToolUse, postInput("s1", "mcp__postern__check_inbox", resp))
	if m, _ := readMarker(t, opts, "s1"); m.State != stateTainted {
		t.Fatalf("a count of 0 next to message framing must taint, got %+v", m)
	}
}

func TestNormalizeEscapes(t *testing.T) {
	cases := map[string]string{
		`abc`:              `abc`,
		`ABC`:              `abc`,
		`\"a\"`:            `"a"`,
		`\\\"a\\\"`:        `"a"`,
		`<X>`:              `<x>`,
		`\\u003c`:          `<`,
		`a\nb\tc\rd`:       `a b c d`,
		`\` + `u00e9`:      `?`, // escaped non-ASCII
		`\uZZZZ`:           `uzzzz`,
		`trailing\`:        `trailing`,
		`\u12`:             `u12`,
		"\xc3\x89x":        "\xc3\x89x", // non-ASCII bytes pass through
		`\\\\\\\\\\"deep"`: `"deep"`,
	}
	for in, want := range cases {
		if got := string(normalizeEscapes([]byte(in))); got != want {
			t.Errorf("normalizeEscapes(%q) = %q, want %q", in, got, want)
		}
	}
}
