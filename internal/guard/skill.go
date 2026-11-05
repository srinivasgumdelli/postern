package guard

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SkillFile is the postern skill (SKILL.md) for Claude Code and Codex.
// Both read the same format: name and description frontmatter plus
// instructions the agent loads when it uses the Postern tools.
//
//go:embed skill/SKILL.md
var SkillFile string

// previousSkills lists the SHA-256 of every earlier SKILL.md that postern
// shipped, so an install over an untouched older copy upgrades it instead
// of refusing. Add the current hash here whenever skill/SKILL.md changes;
// TestPreviousSkillsCoverHistory fails until you do.
var previousSkills = []string{
	"2429e110f45cfbfb8343ff9730ad356e13a8950a08eda2aa8833efb013b7e133",
}

// InstallSkill writes skillsDir/postern/SKILL.md. Like the clear
// command, an existing file with different content is left alone and
// reported, so local edits are never overwritten silently.
func InstallSkill(skillsDir string) (string, error) {
	if !filepath.IsAbs(skillsDir) {
		return "", fmt.Errorf("guard: skills directory %q must be absolute", skillsDir)
	}
	path := filepath.Join(skillsDir, "postern", "SKILL.md")
	need, err := fileNeeded(path, SkillFile, previousSkills...)
	if err != nil || !need {
		return path, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return path, fmt.Errorf("guard: %w", err)
	}
	if err := writeFileAtomic(path, []byte(SkillFile), 0o644); err != nil {
		return path, fmt.Errorf("guard: writing %s: %w", path, err)
	}
	return path, nil
}

// DefaultCodexSkillsDir is $CODEX_HOME/skills, or ~/.codex/skills.
func DefaultCodexSkillsDir() (string, error) {
	if h := os.Getenv("CODEX_HOME"); h != "" {
		if !filepath.IsAbs(h) {
			return "", errors.New("guard: CODEX_HOME must be absolute")
		}
		return filepath.Join(h, "skills"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("guard: %w", err)
	}
	return filepath.Join(home, ".codex", "skills"), nil
}
