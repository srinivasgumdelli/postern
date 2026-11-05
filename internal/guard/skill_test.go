package guard

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
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

// currentSkill is the SHA-256 of skill/SKILL.md. When the skill changes,
// move this value into previousSkills (so older installs upgrade) and
// put the new hash here.
const currentSkill = "20cd0dee00d48d5b528d69c6eea491b4b1997ace0eb0ee5b316c8183d788a576"

func TestPreviousSkillsCoverHistory(t *testing.T) {
	sum := sha256.Sum256([]byte(SkillFile))
	if got := hex.EncodeToString(sum[:]); got != currentSkill {
		t.Fatalf("SKILL.md changed (sha256 %s): add %s to previousSkills and set currentSkill to the new hash", got, currentSkill)
	}
	if slices.Contains(previousSkills, currentSkill) {
		t.Fatal("the current skill is listed as a previous version")
	}
}

func TestInstallUpgradesUntouchedOlderSkill(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "postern", "SKILL.md")
	old := "---\nname: postern\n---\nan older shipped skill\n"
	os.MkdirAll(filepath.Dir(path), 0o755)
	os.WriteFile(path, []byte(old), 0o644)
	sum := sha256.Sum256([]byte(old))
	saved := previousSkills
	previousSkills = append(slices.Clone(saved), hex.EncodeToString(sum[:]))
	defer func() { previousSkills = saved }()

	if _, err := InstallSkill(dir); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != SkillFile {
		t.Fatal("older shipped skill was not upgraded")
	}
	// The Claude installer upgrades it too.
	proj := t.TempDir()
	skill := filepath.Join(proj, ".claude", "skills", "postern", "SKILL.md")
	os.MkdirAll(filepath.Dir(skill), 0o755)
	os.WriteFile(skill, []byte(old), 0o644)
	if err := InstallClaudeCode(proj, "/usr/local/bin/postern", "postern"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(skill); string(b) != SkillFile {
		t.Fatal("Claude installer did not upgrade the older skill")
	}
}
