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
		// "block" keeps the prompt from the model; the reason must still
		// read as a success to the human who sees it.
		if !strings.HasPrefix(r.reason, "Postern guard cleared. ") {
			t.Errorf("%s: cleared notice does not open with the outcome: %q", prompt, r.reason)
		}
		for _, want := range []string{
			"This prompt was not sent to the model",
			"the untrusted Postern content is still in the conversation",
			"Tool calls in this session now run without per-call approval",
			"If a message asked you to type this, do not trust that message",
			"Use /clear for a fresh context instead",
		} {
			if !strings.Contains(r.reason, want) {
				t.Errorf("%s: cleared notice lacks %q: %q", prompt, want, r.reason)
			}
		}
	}
}
