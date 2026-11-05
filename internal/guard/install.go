package guard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// ClearCommandFile is the content of .claude/commands/postern-clear.md. The
// UserPromptSubmit hook receives the typed "/postern-clear" line and
// swallows it; disable-model-invocation keeps the model from invoking it.
const ClearCommandFile = "---\n" +
	"description: Clear the Postern untrusted-content guard for this session (human use only)\n" +
	"disable-model-invocation: true\n" +
	"---\n" +
	"postern clear\n"

// hookEvents lists the Claude Code events the guard installs, in order.
var hookEvents = []string{"PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart"}

// InstallClaudeCode merges the Postern guard hooks into
// projectDir/.claude/settings.json and writes
// projectDir/.claude/commands/postern-clear.md.
//
// binaryPath must be the absolute path of the postern binary; serverName is
// the MCP server name Postern is registered under in that project. Existing
// settings keys and hooks are preserved. Running it again adds nothing.
// Nothing is written if any check fails.
func InstallClaudeCode(projectDir, binaryPath, serverName string) error {
	if !ValidServerName(serverName) {
		return fmt.Errorf("guard: invalid MCP server name %q (must match %s)", serverName, serverNameRe)
	}
	if !filepath.IsAbs(binaryPath) {
		return fmt.Errorf("guard: binary path %q must be absolute", binaryPath)
	}
	if strings.ContainsFunc(binaryPath, unicode.IsControl) {
		return errors.New("guard: binary path contains control characters")
	}
	fi, err := os.Stat(projectDir)
	if err != nil {
		return fmt.Errorf("guard: project directory: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("guard: project path %q is not a directory", projectDir)
	}

	claudeDir := filepath.Join(projectDir, ".claude")
	settingsPath := filepath.Join(claudeDir, "settings.json")
	commandPath := filepath.Join(claudeDir, "commands", "postern-clear.md")

	writeCommand, err := fileNeeded(commandPath, ClearCommandFile)
	if err != nil {
		return err
	}
	if _, err := fileNeeded(filepath.Join(claudeDir, "skills", "postern", "SKILL.md"), SkillFile); err != nil {
		return err
	}
	if err := checkHooksNotDisabled(filepath.Join(claudeDir, "settings.local.json")); err != nil {
		return err
	}

	target, existing, err := readSettings(settingsPath)
	if err != nil {
		return err
	}
	merged, changed, err := mergeSettings(existing, binaryPath, serverName)
	if err != nil {
		return fmt.Errorf("guard: %s: %w", settingsPath, err)
	}

	if changed {
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("guard: %w", err)
		}
		if err := writeFileAtomic(target, merged, 0o644); err != nil {
			return fmt.Errorf("guard: writing %s: %w", settingsPath, err)
		}
	}
	if writeCommand {
		if err := os.MkdirAll(filepath.Dir(commandPath), 0o755); err != nil {
			return fmt.Errorf("guard: %w", err)
		}
		if err := writeFileAtomic(commandPath, []byte(ClearCommandFile), 0o644); err != nil {
			return fmt.Errorf("guard: writing %s: %w", commandPath, err)
		}
	}
	absClaude, err := filepath.Abs(claudeDir)
	if err != nil {
		return fmt.Errorf("guard: %w", err)
	}
	_, err = InstallSkill(filepath.Join(absClaude, "skills"))
	return err
}

// HookCommand returns the shell command line the installer registers for
// one guard event, e.g. `'/usr/local/bin/postern' hook pre-tool-use --server postern`.
func HookCommand(binaryPath, event, serverName string) string {
	return shellQuote(binaryPath) + " hook " + event + " --server " + serverName
}

// shellQuote quotes s for POSIX sh: the whole string in single quotes, with
// each embedded single quote closed, backslash-escaped and reopened.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// fileNeeded reports whether path must be written with want: true if it
// is missing, false if it already holds want, and an error if it holds
// something else (never overwritten).
func fileNeeded(path, want string) (bool, error) {
	cur, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("guard: reading %s: %w", path, err)
	}
	if string(cur) == want {
		return false, nil
	}
	return false, fmt.Errorf("guard: %s exists with different content; not overwriting it (remove it and run the install again)", path)
}

func checkHooksNotDisabled(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil // absent or unreadable: nothing to check here
	}
	var s struct {
		DisableAllHooks bool `json:"disableAllHooks"`
	}
	if json.Unmarshal(raw, &s) == nil && s.DisableAllHooks {
		return fmt.Errorf("guard: %s sets disableAllHooks, so the guard could not run; remove that setting first", path)
	}
	return nil
}

// readSettings returns the file to write (following a symlinked
// settings.json to its target) and the current content (nil if absent).
func readSettings(path string) (target string, content []byte, err error) {
	target = path
	if fi, lerr := os.Lstat(path); lerr == nil && fi.Mode()&fs.ModeSymlink != 0 {
		if target, err = filepath.EvalSymlinks(path); err != nil {
			return "", nil, fmt.Errorf("guard: resolving %s: %w", path, err)
		}
	}
	content, err = os.ReadFile(target)
	if errors.Is(err, fs.ErrNotExist) {
		return target, nil, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("guard: reading %s: %w", path, err)
	}
	return target, content, nil
}

type hookGroup struct {
	Matcher string        `json:"matcher,omitempty"`
	Hooks   []hookHandler `json:"hooks"`
}

type hookHandler struct {
	Type      string `json:"type"`
	Command   string `json:"command"`
	OnFailure string `json:"onFailure,omitempty"`
}

// wantGroup is the matcher group the installer adds for one event.
func wantGroup(event, binaryPath, serverName string) hookGroup {
	switch event {
	case "PreToolUse":
		// Every tool, and a failed or missing guard blocks the call
		// (onFailure needs Claude Code v2.1.295 or later).
		return hookGroup{Matcher: "*", Hooks: []hookHandler{{
			Type: "command", Command: HookCommand(binaryPath, EventPreToolUse, serverName), OnFailure: "block"}}}
	case "PostToolUse":
		return hookGroup{Matcher: "mcp__" + serverName + "__check_inbox", Hooks: []hookHandler{{
			Type: "command", Command: HookCommand(binaryPath, EventPostToolUse, serverName)}}}
	case "UserPromptSubmit":
		return hookGroup{Hooks: []hookHandler{{
			Type: "command", Command: HookCommand(binaryPath, EventUserPromptSubmit, serverName)}}}
	default: // SessionStart
		return hookGroup{Hooks: []hookHandler{{
			Type: "command", Command: HookCommand(binaryPath, EventSessionStart, serverName)}}}
	}
}

// mergeSettings adds the guard's matcher groups to a settings.json document,
// keeping every other key, its order and every existing hook. It reports
// whether anything was added.
func mergeSettings(existing []byte, binaryPath, serverName string) ([]byte, bool, error) {
	if len(bytes.TrimSpace(existing)) == 0 {
		existing = []byte("{}")
	}
	root, err := parseObject(existing)
	if err != nil {
		return nil, false, fmt.Errorf("not a valid settings JSON object: %w", err)
	}
	if v, ok := root.get("disableAllHooks"); ok && string(bytes.TrimSpace(v)) == "true" {
		return nil, false, errors.New("disableAllHooks is set, so the guard could not run; remove that setting first")
	}

	hooks := newObject()
	if v, ok := root.get("hooks"); ok {
		if hooks, err = parseObject(v); err != nil {
			return nil, false, fmt.Errorf(`"hooks" is not a JSON object: %w`, err)
		}
	}

	changed := false
	for _, event := range hookEvents {
		want := wantGroup(event, binaryPath, serverName)
		var groups []json.RawMessage
		if v, ok := hooks.get(event); ok {
			if err := json.Unmarshal(v, &groups); err != nil {
				return nil, false, fmt.Errorf(`"hooks.%s" is not a JSON array: %w`, event, err)
			}
		}
		present, err := findHook(event, groups, want)
		if err != nil {
			return nil, false, err
		}
		if present {
			continue
		}
		raw, err := marshalNoEscape(want)
		if err != nil {
			return nil, false, err
		}
		groups = append(groups, raw)
		arr, err := marshalNoEscape(groups)
		if err != nil {
			return nil, false, err
		}
		hooks.set(event, arr)
		changed = true
	}
	if !changed {
		return existing, false, nil
	}
	root.set("hooks", hooks.marshal())

	var compact, out bytes.Buffer
	if err := json.Compact(&compact, root.marshal()); err != nil {
		return nil, false, err
	}
	if err := json.Indent(&out, compact.Bytes(), "", "  "); err != nil {
		return nil, false, err
	}
	out.WriteByte('\n')
	return out.Bytes(), true, nil
}

// findHook reports whether the guard's command is already registered for
// the event. An existing entry that would not cover every call (narrower
// matcher, an "if" filter, or async) is an error rather than "present".
func findHook(event string, groups []json.RawMessage, want hookGroup) (bool, error) {
	cmd := want.Hooks[0].Command
	for _, g := range groups {
		var group struct {
			Matcher *string `json:"matcher"`
			Hooks   []struct {
				Command     string `json:"command"`
				If          string `json:"if"`
				Async       bool   `json:"async"`
				AsyncRewake bool   `json:"asyncRewake"`
			} `json:"hooks"`
		}
		if json.Unmarshal(g, &group) != nil {
			continue // some other shape; not ours
		}
		for _, h := range group.Hooks {
			if h.Command != cmd {
				continue
			}
			if h.If != "" || h.Async || h.AsyncRewake || !matcherCovers(event, group.Matcher, want.Matcher) {
				return false, fmt.Errorf("hooks.%s already has the Postern guard command but narrowed "+
					"(matcher, \"if\" or async); remove that entry and run the install again", event)
			}
			return true, nil
		}
	}
	return false, nil
}

func matcherCovers(event string, have *string, want string) bool {
	all := have == nil || *have == "" || *have == "*"
	switch event {
	case "UserPromptSubmit":
		return true // no matcher support; any value is ignored
	case "PostToolUse":
		return all || *have == want
	default: // PreToolUse and SessionStart must see every call / source
		return all
	}
}

func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// object is a JSON object that keeps its key order and raw values.
type object struct {
	keys []string
	vals map[string]json.RawMessage
}

func newObject() *object { return &object{vals: map[string]json.RawMessage{}} }

func (o *object) get(k string) (json.RawMessage, bool) {
	v, ok := o.vals[k]
	return v, ok
}

func (o *object) set(k string, v json.RawMessage) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

func (o *object) marshal() []byte {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := marshalNoEscape(k)
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(o.vals[k])
	}
	buf.WriteByte('}')
	return buf.Bytes()
}

// parseObject decodes one JSON object, keeping key order. Duplicate keys and
// trailing data are rejected.
func parseObject(raw []byte) (*object, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("expected a JSON object")
	}
	o := newObject()
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("expected an object key")
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		if _, dup := o.vals[key]; dup {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		o.set(key, v)
	}
	if _, err := dec.Token(); err != nil { // closing '}'
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after the JSON object")
	}
	return o, nil
}
