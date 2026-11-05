package guard

import (
	"strings"
	"testing"
)

// A message can ask the human to type "postern clear". The notice shown on
// clearing must say plainly what that gives up, warn against the message
// that asked for it, and point to /clear.
func TestClearedNoticeWarnsTheHuman(t *testing.T) {
	for _, prompt := range []string{"postern clear", "/postern-clear"} {
		opts := testOptions(t)
		taintSession(t, opts, "s1")
		r := runHook(t, opts, EventUserPromptSubmit, promptInput("s1", prompt))
		if !r.block {
			t.Fatalf("%s: want block, got %+v", prompt, r)
		}
		for _, want := range []string{
			"Untrusted Postern content is still in the conversation",
			"tool calls will now run without per-call approval",
			"If a message asked you to type this, do not trust that message",
			"Use /clear for a fresh context instead",
		} {
			if !strings.Contains(r.reason, want) {
				t.Errorf("%s: cleared notice lacks %q: %q", prompt, want, r.reason)
			}
		}
	}
}
