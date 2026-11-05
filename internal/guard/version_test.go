package guard

import (
	"errors"
	"testing"
)

func TestCheckClaudeCodeVersion(t *testing.T) {
	ok := []string{
		"2.1.295 (Claude Code)",
		"2.1.318 (Claude Code)",
		"2.1.295",
		"2.1.295\n",
		"  2.1.300 (Claude Code)\n",
		"v2.1.295",
		"2.2.0 (Claude Code)",
		"2.1.1000",
		"3.0.0",
		"2.1.295-beta.1 (Claude Code)",
	}
	old := []string{
		"2.1.294 (Claude Code)",
		"2.1.0",
		"2.0.999",
		"1.9.400 (Claude Code)",
		"0.0.1",
	}
	garbage := []string{
		"",
		"Claude Code",
		"claude: command not found",
		"2.1",
		"2.1.x",
		"version 2.1.318",
		"2.1.295.4",
		"99999999999.0.0",
	}
	for _, s := range ok {
		if err := CheckClaudeCodeVersion(s); err != nil {
			t.Errorf("%q: want ok, got %v", s, err)
		}
	}
	for _, s := range old {
		err := CheckClaudeCodeVersion(s)
		if !errors.Is(err, ErrClaudeCodeTooOld) || errors.Is(err, ErrUnknownVersion) {
			t.Errorf("%q: want ErrClaudeCodeTooOld, got %v", s, err)
		}
	}
	for _, s := range garbage {
		if err := CheckClaudeCodeVersion(s); !errors.Is(err, ErrUnknownVersion) {
			t.Errorf("%q: want ErrUnknownVersion, got %v", s, err)
		}
	}
	if _, ok := parseVersion(MinClaudeCodeVersion); !ok {
		t.Fatal("MinClaudeCodeVersion does not parse")
	}
}
