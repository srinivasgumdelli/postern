package guard

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testBinary = "/usr/local/bin/postern"

func readSettingsFile(t *testing.T, project string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(project, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("settings.json is not valid JSON: %v\n%s", err, raw)
	}
	return m
}

// groupsFor returns the matcher groups for one event.
func groupsFor(t *testing.T, settings map[string]any, event string) []map[string]any {
	t.Helper()
	hooks, _ := settings["hooks"].(map[string]any)
	arr, _ := hooks[event].([]any)
	var out []map[string]any
	for _, g := range arr {
		out = append(out, g.(map[string]any))
	}
	return out
}

func commandsFor(t *testing.T, settings map[string]any, event string) []string {
	t.Helper()
	var cmds []string
	for _, g := range groupsFor(t, settings, event) {
		for _, h := range g["hooks"].([]any) {
			cmds = append(cmds, h.(map[string]any)["command"].(string))
		}
	}
	return cmds
}

func TestInstallFreshProjectMatchesExample(t *testing.T) {
	project := t.TempDir()
	if err := InstallClaudeCode(project, testBinary, "postern"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(project, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("..", "..", "examples", "claude-code", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("installer output differs from examples/claude-code/settings.json\n--- got\n%s--- want\n%s", got, want)
	}
	if !strings.HasPrefix(string(got), "{\n  \"hooks\": {\n    \"PreToolUse\": [") {
		t.Fatalf("want 2-space indentation, got\n%s", got)
	}

	s := readSettingsFile(t, project)
	pre := groupsFor(t, s, "PreToolUse")
	if len(pre) != 1 || pre[0]["matcher"] != "*" {
		t.Fatalf("PreToolUse groups: %v", pre)
	}
	h := pre[0]["hooks"].([]any)[0].(map[string]any)
	if h["type"] != "command" || h["command"] != "'/usr/local/bin/postern' hook pre-tool-use --server postern" || h["onFailure"] != "block" {
		t.Fatalf("PreToolUse handler: %v", h)
	}
	post := groupsFor(t, s, "PostToolUse")
	if len(post) != 1 || post[0]["matcher"] != "*" {
		t.Fatalf("PostToolUse groups: %v", post)
	}
	for event, sub := range map[string]string{"PostToolUse": "post-tool-use", "UserPromptSubmit": "user-prompt-submit", "SessionStart": "session-start"} {
		cmds := commandsFor(t, s, event)
		if len(cmds) != 1 || cmds[0] != "'/usr/local/bin/postern' hook "+sub+" --server postern" {
			t.Errorf("%s commands: %v", event, cmds)
		}
	}

	fi, err := os.Stat(filepath.Join(project, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("settings.json mode %v, want 0644", fi.Mode().Perm())
	}

	cmd, err := os.ReadFile(filepath.Join(project, ".claude", "commands", "postern-clear.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(cmd) != ClearCommandFile {
		t.Fatalf("postern-clear.md = %q", cmd)
	}
	example, err := os.ReadFile(filepath.Join("..", "..", "examples", "claude-code", "commands", "postern-clear.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(example) != ClearCommandFile {
		t.Fatalf("examples/claude-code/commands/postern-clear.md differs from what the installer writes")
	}
	for _, want := range []string{"disable-model-invocation: true", "description: Clear the Postern untrusted-content guard for this session (human use only)"} {
		if !strings.Contains(string(cmd), want) {
			t.Errorf("command file lacks %q", want)
		}
	}
	body := strings.SplitN(string(cmd), "---\n", 3)[2]
	if strings.TrimSpace(body) != "postern clear" || !isClearPrompt(body) {
		t.Errorf("command body = %q, want exactly %q", body, "postern clear")
	}
}

func TestInstallIsIdempotent(t *testing.T) {
	project := t.TempDir()
	for i := 0; i < 3; i++ {
		if err := InstallClaudeCode(project, testBinary, "postern"); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	s := readSettingsFile(t, project)
	for _, event := range hookEvents {
		if n := len(groupsFor(t, s, event)); n != 1 {
			t.Errorf("%s has %d groups after three installs, want 1", event, n)
		}
	}
	// A second install must not rewrite a file it has nothing to add to.
	path := filepath.Join(project, ".claude", "settings.json")
	custom := []byte("{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"*\",\"hooks\":[{\"type\":\"command\",\"command\":\"'/usr/local/bin/postern' hook pre-tool-use --server postern\",\"onFailure\":\"block\"}]}]," +
		"\"PostToolUse\":[{\"matcher\":\"*\",\"hooks\":[{\"type\":\"command\",\"command\":\"'/usr/local/bin/postern' hook post-tool-use --server postern\"}]}]," +
		"\"UserPromptSubmit\":[{\"hooks\":[{\"type\":\"command\",\"command\":\"'/usr/local/bin/postern' hook user-prompt-submit --server postern\"}]}]," +
		"\"SessionStart\":[{\"hooks\":[{\"type\":\"command\",\"command\":\"'/usr/local/bin/postern' hook session-start --server postern\"}]}]}}")
	if err := os.WriteFile(path, custom, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := InstallClaudeCode(project, testBinary, "postern"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, custom) {
		t.Fatalf("install rewrote a complete settings file:\n%s", after)
	}
}

func TestInstallPreservesExistingSettings(t *testing.T) {
	project := t.TempDir()
	dir := filepath.Join(project, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	existing := `{
	"$schema": "https://json.schemastore.org/claude-code-settings.json",
	"permissions": {"allow": ["Bash(make test)"], "deny": ["Read(./.env)"]},
	"hooks": {
		"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "/path/to/lint.sh", "timeout": 30}]}],
		"Stop": [{"hooks": [{"type": "command", "command": "/path/to/notify.sh"}]}]
	},
	"env": {"FOO": "bar & <baz>"},
	"model": "some-model"
}
`
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := InstallClaudeCode(project, testBinary, "postern"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "settings.json"))

	// Top-level key order is kept.
	keys, err := parseObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(keys.keys, ","); got != "$schema,permissions,hooks,env,model" {
		t.Fatalf("top-level key order = %s", got)
	}
	var before, after map[string]any
	json.Unmarshal([]byte(existing), &before)
	json.Unmarshal(raw, &after)
	for _, k := range []string{"$schema", "permissions", "env", "model"} {
		b, _ := json.Marshal(before[k])
		a, _ := json.Marshal(after[k])
		if !bytes.Equal(a, b) {
			t.Errorf("key %s changed: %s -> %s", k, b, a)
		}
	}
	if !strings.Contains(string(raw), `"bar & <baz>"`) {
		t.Errorf("values were re-escaped:\n%s", raw)
	}
	pre := groupsFor(t, after, "PreToolUse")
	if len(pre) != 2 || pre[0]["matcher"] != "Bash" || pre[1]["matcher"] != "*" {
		t.Fatalf("PreToolUse groups = %v", pre)
	}
	if h := pre[0]["hooks"].([]any)[0].(map[string]any); h["command"] != "/path/to/lint.sh" || h["timeout"] != float64(30) {
		t.Fatalf("existing PreToolUse hook changed: %v", h)
	}
	if cmds := commandsFor(t, after, "Stop"); len(cmds) != 1 || cmds[0] != "/path/to/notify.sh" {
		t.Fatalf("Stop hooks = %v", cmds)
	}
	hooks, err := parseObject(mustGet(t, keys, "hooks"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(hooks.keys, ","); got != "PreToolUse,Stop,PostToolUse,UserPromptSubmit,SessionStart" {
		t.Fatalf("hooks key order = %s", got)
	}
	if err := InstallClaudeCode(project, testBinary, "postern"); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(filepath.Join(dir, "settings.json"))
	if !bytes.Equal(again, raw) {
		t.Fatal("second install changed the merged file")
	}
}

func mustGet(t *testing.T, o *object, k string) json.RawMessage {
	t.Helper()
	v, ok := o.get(k)
	if !ok {
		t.Fatalf("missing key %s", k)
	}
	return v
}

func TestInstallQuotesPathWithSpaces(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell quoting")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	base := t.TempDir()
	binDir := filepath.Join(base, "my tools", "it's $HOME `here`")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(binDir, "postern")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$OUT\"\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	project := t.TempDir()
	if err := InstallClaudeCode(project, bin, "postern"); err != nil {
		t.Fatal(err)
	}
	s := readSettingsFile(t, project)
	cmds := commandsFor(t, s, "PreToolUse")
	if len(cmds) != 1 {
		t.Fatalf("PreToolUse commands = %v", cmds)
	}
	out := filepath.Join(base, "args.txt")
	c := exec.Command(sh, "-c", cmds[0])
	c.Env = append(os.Environ(), "OUT="+out)
	if b, err := c.CombinedOutput(); err != nil {
		t.Fatalf("running %q: %v\n%s", cmds[0], err, b)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hook\npre-tool-use\n--server\npostern\n" {
		t.Fatalf("binary received args %q", got)
	}
	if want := HookCommand(bin, EventPreToolUse, "postern"); cmds[0] != want {
		t.Fatalf("command %q, want %q", cmds[0], want)
	}
}

func TestInstallCustomServerName(t *testing.T) {
	project := t.TempDir()
	if err := InstallClaudeCode(project, testBinary, "review-bus"); err != nil {
		t.Fatal(err)
	}
	s := readSettingsFile(t, project)
	if post := groupsFor(t, s, "PostToolUse"); post[0]["matcher"] != "*" {
		t.Fatalf("PostToolUse matcher = %v", post[0]["matcher"])
	}
	for _, event := range hookEvents {
		for _, c := range commandsFor(t, s, event) {
			if !strings.HasSuffix(c, " --server review-bus") {
				t.Errorf("%s command %q lacks --server review-bus", event, c)
			}
		}
	}
}

func TestInstallRejectsBadArguments(t *testing.T) {
	project := t.TempDir()
	file := filepath.Join(project, "file")
	os.WriteFile(file, []byte("x"), 0o644)
	cases := []struct{ project, bin, server string }{
		{project, "postern", "postern"},
		{project, "./bin/postern", "postern"},
		{project, "/usr/local/bin/post\nern", "postern"},
		{project, testBinary, ""},
		{project, testBinary, "Postern"},
		{project, testBinary, "a b"},
		{project, testBinary, "x;rm"},
		{project, testBinary, "-x"},
		{project, testBinary, strings.Repeat("a", 33)},
		{filepath.Join(project, "missing"), testBinary, "postern"},
		{file, testBinary, "postern"},
	}
	for _, c := range cases {
		if err := InstallClaudeCode(c.project, c.bin, c.server); err == nil {
			t.Errorf("InstallClaudeCode(%q, %q, %q) succeeded", c.project, c.bin, c.server)
		}
	}
	if _, err := os.Stat(filepath.Join(project, ".claude")); err == nil {
		t.Fatal("a rejected install wrote files")
	}
}

func TestInstallRefusesUnusableSettings(t *testing.T) {
	cases := map[string]string{
		"invalid json":      `{ "hooks": `,
		"array":             `[]`,
		"duplicate key":     `{"hooks":{},"hooks":{}}`,
		"trailing data":     `{} {}`,
		"hooks not object":  `{"hooks":[]}`,
		"event not array":   `{"hooks":{"PreToolUse":{}}}`,
		"hooks disabled":    `{"disableAllHooks":true}`,
		"narrowed matcher":  `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"'/usr/local/bin/postern' hook pre-tool-use --server postern"}]}]}}`,
		"if filter":         `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","if":"Bash(git *)","command":"'/usr/local/bin/postern' hook pre-tool-use --server postern"}]}]}}`,
		"async":             `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","async":true,"command":"'/usr/local/bin/postern' hook pre-tool-use --server postern"}]}]}}`,
		"post wrong match":  `{"hooks":{"PostToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"'/usr/local/bin/postern' hook post-tool-use --server postern"}]}]}}`,
		"start narrowed":    `{"hooks":{"SessionStart":[{"matcher":"startup","hooks":[{"type":"command","command":"'/usr/local/bin/postern' hook session-start --server postern"}]}]}}`,
		"hooks null object": `{"hooks":null}`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			project := t.TempDir()
			dir := filepath.Join(project, ".claude")
			os.MkdirAll(dir, 0o755)
			path := filepath.Join(dir, "settings.json")
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := InstallClaudeCode(project, testBinary, "postern"); err == nil {
				t.Fatal("install succeeded")
			}
			after, _ := os.ReadFile(path)
			if string(after) != content {
				t.Fatalf("settings.json was modified: %s", after)
			}
			if _, err := os.Stat(filepath.Join(dir, "commands")); err == nil {
				t.Fatal("command file written despite the error")
			}
		})
	}
}

func TestInstallAcceptsBroaderPostMatcherAndEmptyFile(t *testing.T) {
	project := t.TempDir()
	dir := filepath.Join(project, ".claude")
	os.MkdirAll(dir, 0o755)
	path := filepath.Join(dir, "settings.json")
	os.WriteFile(path, []byte("  \n"), 0o644)
	if err := InstallClaudeCode(project, testBinary, "postern"); err != nil {
		t.Fatalf("empty settings file: %v", err)
	}
	content := `{"hooks":{"PostToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"'/usr/local/bin/postern' hook post-tool-use --server postern"}]}]}}`
	os.WriteFile(path, []byte(content), 0o644)
	if err := InstallClaudeCode(project, testBinary, "postern"); err != nil {
		t.Fatalf("match-all PostToolUse: %v", err)
	}
	if n := len(groupsFor(t, readSettingsFile(t, project), "PostToolUse")); n != 1 {
		t.Fatalf("PostToolUse groups = %d, want 1 (existing match-all entry counts)", n)
	}
}

// Earlier installers matched PostToolUse to check_inbox only. Installing
// again upgrades that exact entry to the match-all group, keeps the other
// PostToolUse hooks, and ends up identical to a fresh install.
func TestInstallUpgradesLegacyPostMatcher(t *testing.T) {
	legacy := `{"matcher":"mcp__postern__check_inbox","hooks":[{"type":"command","command":"'/usr/local/bin/postern' hook post-tool-use --server postern"}]}`
	other := `{"matcher":"Edit","hooks":[{"type":"command","command":"/path/to/fmt.sh"}]}`

	fresh := t.TempDir()
	if err := InstallClaudeCode(fresh, testBinary, "postern"); err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile(filepath.Join(fresh, ".claude", "settings.json"))
	old := strings.Replace(string(want), `"matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "'/usr/local/bin/postern' hook post-tool-use`, `"matcher": "mcp__postern__check_inbox",
        "hooks": [
          {
            "type": "command",
            "command": "'/usr/local/bin/postern' hook post-tool-use`, 1)
	if old == string(want) {
		t.Fatal("test setup: could not build the legacy settings file")
	}

	for name, tc := range map[string]struct{ content, want string }{
		"legacy install":   {old, string(want)},
		"with other hooks": {`{"hooks":{"PostToolUse":[` + other + `,` + legacy + `]}}`, ""},
	} {
		t.Run(name, func(t *testing.T) {
			project := t.TempDir()
			dir := filepath.Join(project, ".claude")
			os.MkdirAll(dir, 0o755)
			path := filepath.Join(dir, "settings.json")
			os.WriteFile(path, []byte(tc.content), 0o644)
			if err := InstallClaudeCode(project, testBinary, "postern"); err != nil {
				t.Fatal(err)
			}
			got, _ := os.ReadFile(path)
			if tc.want != "" && string(got) != tc.want {
				t.Fatalf("upgraded file differs from a fresh install:\n%s", got)
			}
			post := groupsFor(t, readSettingsFile(t, project), "PostToolUse")
			var matchers []string
			for _, g := range post {
				m, _ := g["matcher"].(string)
				matchers = append(matchers, m)
			}
			wantM := "*"
			if name == "with other hooks" {
				wantM = "Edit,*"
			}
			if strings.Join(matchers, ",") != wantM {
				t.Fatalf("PostToolUse matchers = %v, want %s", matchers, wantM)
			}
		})
	}

	// A legacy-matcher entry that was edited by hand is not touched.
	project := t.TempDir()
	dir := filepath.Join(project, ".claude")
	os.MkdirAll(dir, 0o755)
	path := filepath.Join(dir, "settings.json")
	edited := `{"hooks":{"PostToolUse":[{"matcher":"mcp__postern__check_inbox","hooks":[{"type":"command","command":"'/usr/local/bin/postern' hook post-tool-use --server postern","timeout":5}]}]}}`
	os.WriteFile(path, []byte(edited), 0o644)
	if err := InstallClaudeCode(project, testBinary, "postern"); err == nil {
		t.Fatal("install accepted a hand-edited narrowed PostToolUse entry")
	}
	if got, _ := os.ReadFile(path); string(got) != edited {
		t.Fatalf("settings.json was modified: %s", got)
	}
}

func TestInstallRefusesLocalDisableAllHooks(t *testing.T) {
	project := t.TempDir()
	dir := filepath.Join(project, ".claude")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "settings.local.json"), []byte(`{"disableAllHooks": true}`), 0o644)
	if err := InstallClaudeCode(project, testBinary, "postern"); err == nil || !strings.Contains(err.Error(), "disableAllHooks") {
		t.Fatalf("want a disableAllHooks error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "settings.json")); err == nil {
		t.Fatal("settings.json written despite the error")
	}
}

func TestInstallCommandFileConflict(t *testing.T) {
	project := t.TempDir()
	cmdDir := filepath.Join(project, ".claude", "commands")
	os.MkdirAll(cmdDir, 0o755)
	os.WriteFile(filepath.Join(cmdDir, "postern-clear.md"), []byte("---\ndescription: something else\n---\nrun rm -rf\n"), 0o644)
	if err := InstallClaudeCode(project, testBinary, "postern"); err == nil {
		t.Fatal("install overwrote or ignored a different postern-clear.md")
	}
	if _, err := os.Stat(filepath.Join(project, ".claude", "settings.json")); err == nil {
		t.Fatal("settings.json written despite the conflict")
	}
	// An identical file is fine.
	os.WriteFile(filepath.Join(cmdDir, "postern-clear.md"), []byte(ClearCommandFile), 0o644)
	if err := InstallClaudeCode(project, testBinary, "postern"); err != nil {
		t.Fatal(err)
	}
}

func TestInstallFollowsSymlinkedSettings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	project := t.TempDir()
	dir := filepath.Join(project, ".claude")
	os.MkdirAll(dir, 0o755)
	real := filepath.Join(t.TempDir(), "shared-settings.json")
	os.WriteFile(real, []byte(`{"model":"some-model"}`), 0o644)
	link := filepath.Join(dir, "settings.json")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := InstallClaudeCode(project, testBinary, "postern"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(link)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("settings.json symlink was replaced")
	}
	raw, _ := os.ReadFile(real)
	if !strings.Contains(string(raw), "pre-tool-use") || !strings.Contains(string(raw), "some-model") {
		t.Fatalf("symlink target not updated: %s", raw)
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"/usr/local/bin/postern": `'/usr/local/bin/postern'`,
		"/a b/c":                 `'/a b/c'`,
		"/o'x/p":                 `'/o'\''x/p'`,
		"/$(x)/`y`":              "'/$(x)/`y`'",
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}
