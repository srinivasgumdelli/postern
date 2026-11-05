package guard

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestCodexExamples keeps the Codex example config and rules from drifting
// away from what docs/session-guard.md promises. The examples were checked
// against a real codex-cli by hand; this test only pins their content.
func TestCodexExamples(t *testing.T) {
	cfg, err := os.ReadFile(filepath.Join("..", "..", "examples", "codex", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	settings := regexp.MustCompile(`(?m)^\s*([a-z_.]+)\s*=\s*"([^"]*)"`).FindAllStringSubmatch(string(cfg), -1)
	got := map[string][]string{}
	for _, m := range settings {
		got[m[1]] = append(got[m[1]], m[2])
	}
	if v := got["sandbox_mode"]; len(v) != 1 || v[0] != "read-only" {
		t.Errorf("sandbox_mode = %v, want read-only", v)
	}
	if v := got["approval_policy"]; len(v) != 0 {
		t.Errorf("approval_policy must be left unset (derived from the untrusted project), got %v", v)
	}
	if v := got["trust_level"]; len(v) != 1 || v[0] != "untrusted" {
		t.Errorf("trust_level = %v, want untrusted", v)
	}
	if v := got["approvals_reviewer"]; len(v) != 1 || v[0] != "user" {
		t.Errorf("approvals_reviewer = %v, want user", v)
	}
	if !strings.Contains(string(cfg), "rules/postern.rules") {
		t.Error("config.toml does not point to the rules file")
	}

	rules, err := os.ReadFile(filepath.Join("..", "..", "examples", "codex", "rules", "postern.rules"))
	if err != nil {
		t.Fatal(err)
	}
	r := string(rules)
	if strings.Contains(r, `"allow"`) || strings.Contains(r, `"forbidden"`) {
		t.Error("the rules file should only add prompts")
	}
	if n := strings.Count(r, `decision = "prompt"`); n != strings.Count(r, "prefix_rule(") || n == 0 {
		t.Errorf("every prefix_rule must prompt (%d prompts)", n)
	}
	for _, cmd := range []string{"cat", "head", "tail", "less", "grep", "rg", "find", "ls", "sed", "awk"} {
		if !strings.Contains(r, `"`+cmd+`"`) {
			t.Errorf("rules file does not cover %s", cmd)
		}
	}
}
