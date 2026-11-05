package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGuardInstallChecksClaudeVersion(t *testing.T) {
	cases := []struct {
		name    string
		version func() (string, error)
		args    []string
		wantOK  bool
		wantErr string
	}{
		{"newer", func() (string, error) { return "2.1.318 (Claude Code)\n", nil }, nil, true, ""},
		{"older", func() (string, error) { return "2.1.200 (Claude Code)\n", nil }, nil, false, "2.1.295"},
		{"unknown", func() (string, error) { return "something else\n", nil }, nil, false, "--skip-claude-version-check"},
		{"missing", func() (string, error) { return "", errors.New("not found") }, nil, false, "--skip-claude-version-check"},
		{"skipped", func() (string, error) { return "", errors.New("not found") }, []string{"--skip-claude-version-check"}, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			// Never look at a real config on the machine running the tests.
			t.Setenv("POSTERN_CONFIG", filepath.Join(dir, "no-config.json"))
			var stderr bytes.Buffer
			env := Env{
				Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &stderr,
				Executable:    func() (string, error) { return "/usr/local/bin/postern", nil },
				ClaudeVersion: c.version,
			}
			args := append([]string{"guard", "install", "--project", dir}, c.args...)
			code := Run(context.Background(), args, env)
			_, statErr := os.Stat(filepath.Join(dir, ".claude", "settings.json"))
			if c.wantOK {
				if code != 0 || statErr != nil {
					t.Fatalf("exit %d, settings %v, stderr %s", code, statErr, stderr.String())
				}
				return
			}
			if code == 0 {
				t.Fatal("installed despite the version check")
			}
			if statErr == nil {
				t.Fatal("wrote settings before refusing")
			}
			if !strings.Contains(stderr.String(), c.wantErr) {
				t.Fatalf("stderr %q does not mention %q", stderr.String(), c.wantErr)
			}
		})
	}
}
