package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSkillFrontmatter(t *testing.T) {
	if !strings.HasPrefix(SkillFile, "---\nname: postern\ndescription: ") {
		t.Fatalf("skill frontmatter:\n%s", SkillFile[:80])
	}
	for _, must := range []string{"untrusted", "Stop and wait", "Do not rephrase, split, encode", "/postern-clear", "config pin"} {
		if !strings.Contains(SkillFile, must) {
			t.Errorf("skill does not mention %q", must)
		}
	}
}

func TestInstallClaudeCodeWritesSkill(t *testing.T) {
	dir := t.TempDir()
	for range 2 { // idempotent
		if err := InstallClaudeCode(dir, "/usr/local/bin/postern", "postern"); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(filepath.Join(dir, ".claude", "skills", "postern", "SKILL.md"))
	if err != nil || string(got) != SkillFile {
		t.Fatalf("skill not installed: %v", err)
	}
}

func TestInstallSkillKeepsLocalEdits(t *testing.T) {
	dir := t.TempDir()
	path, err := InstallSkill(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("edited"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallSkill(dir); err == nil {
		t.Fatal("edited skill overwritten without an error")
	}
	if b, _ := os.ReadFile(path); string(b) != "edited" {
		t.Fatal("edited skill changed")
	}
	// The Claude installer refuses before touching anything.
	proj := t.TempDir()
	skill := filepath.Join(proj, ".claude", "skills", "postern", "SKILL.md")
	os.MkdirAll(filepath.Dir(skill), 0o755)
	os.WriteFile(skill, []byte("edited"), 0o644)
	if err := InstallClaudeCode(proj, "/usr/local/bin/postern", "postern"); err == nil {
		t.Fatal("installer ignored an edited skill")
	}
	if _, err := os.Stat(filepath.Join(proj, ".claude", "settings.json")); err == nil {
		t.Fatal("installer half-installed")
	}
	if _, err := InstallSkill("relative"); err == nil {
		t.Fatal("relative skills dir accepted")
	}
}

func TestDefaultCodexSkillsDir(t *testing.T) {
	t.Setenv("CODEX_HOME", "/opt/codex")
	if d, err := DefaultCodexSkillsDir(); err != nil || d != "/opt/codex/skills" {
		t.Fatalf("got %q %v", d, err)
	}
	t.Setenv("CODEX_HOME", "")
	d, err := DefaultCodexSkillsDir()
	if err != nil || !strings.HasSuffix(d, filepath.Join(".codex", "skills")) {
		t.Fatalf("got %q %v", d, err)
	}
}
