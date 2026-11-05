package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"postern/internal/audit"
	"postern/internal/bridge"
	"postern/internal/guard"
	"postern/internal/tlsutil"
)

func cmdThreadReset(ctx context.Context, env Env, args []string) error {
	fs, cfgFlag := newFlags(env, "thread reset")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("expected one thread id")
	}
	l, err := loadPinned(env, *cfgFlag)
	if err != nil {
		return err
	}
	if err := bridge.ResetThread(ctx, l.cfg.DBPath(), fs.Arg(0)); err != nil {
		return err
	}
	recordTrust(env, l.cfg, false, audit.Event{Event: audit.EventThreadReset, Thread: fs.Arg(0)})
	fmt.Fprintf(env.Stdout, "Thread %s reset; its message counts start over now.\n", fs.Arg(0))
	return nil
}

func cmdGuardInstall(env Env, args []string) error {
	fs := flag.NewFlagSet("postern guard install", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	project := fs.String("project", ".", "project directory of the Claude Code session")
	server := fs.String("server", "postern", "name the Postern MCP server was added under")
	cfgFlag := fs.String("config", "", "config file, for the audit log (default $POSTERN_CONFIG or the user config dir)")
	skip := fs.Bool("skip-claude-version-check", false, "install even if `claude --version` cannot confirm a release that blocks on hook failure")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Older Claude Code releases run the tool call when a hook fails, so
	// the guard would fail open. Check before writing anything.
	if !*skip {
		if err := checkClaudeVersion(env); err != nil {
			return err
		}
	}
	exe, err := env.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	dir, err := filepath.Abs(*project)
	if err != nil {
		return err
	}
	if err := guard.InstallClaudeCode(dir, exe, *server); err != nil {
		return err
	}
	recordGuardInstall(env, *cfgFlag, "claude-code")
	fmt.Fprintf(env.Stdout, "Installed Postern hooks in %s, the /postern-clear command and the postern skill.\n",
		filepath.Join(dir, ".claude", "settings.json"))
	fmt.Fprintln(env.Stdout, "Also add the session rule (examples/session-rule.md) to the project's CLAUDE.md, and never run this session in bypass mode.")
	return nil
}

// cmdGuardInstallCodex installs the postern skill for Codex. Codex has
// no hooks that can force a prompt; its guard is the approval policy in
// examples/codex/config.toml.
func cmdGuardInstallCodex(env Env, args []string) error {
	fs := flag.NewFlagSet("postern guard install-codex", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	dir := fs.String("skills-dir", "", "Codex skills directory (default $CODEX_HOME/skills or ~/.codex/skills)")
	cfgFlag := fs.String("config", "", "config file, for the audit log (default $POSTERN_CONFIG or the user config dir)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	d := *dir
	if d == "" {
		var err error
		if d, err = guard.DefaultCodexSkillsDir(); err != nil {
			return err
		}
	}
	d, err := filepath.Abs(d)
	if err != nil {
		return err
	}
	path, err := guard.InstallSkill(d)
	if err != nil {
		return err
	}
	recordGuardInstall(env, *cfgFlag, "codex")
	fmt.Fprintf(env.Stdout, "Installed the postern skill at %s.\n", path)
	fmt.Fprintln(env.Stdout, "Also mark the project untrusted and set Postern's tool approvals as in examples/codex/config.toml.")
	return nil
}

func checkClaudeVersion(env Env) error {
	if env.ClaudeVersion == nil {
		return errors.New("cannot check the Claude Code version; rerun with --skip-claude-version-check after checking it yourself")
	}
	out, err := env.ClaudeVersion()
	if err != nil {
		return fmt.Errorf("could not run `claude --version`; the guard needs Claude Code %s or newer (older releases run the tool call when the guard fails). Check it yourself and rerun with --skip-claude-version-check", guard.MinClaudeCodeVersion)
	}
	if err := guard.CheckClaudeCodeVersion(out); err != nil {
		if errors.Is(err, guard.ErrUnknownVersion) {
			return fmt.Errorf("%v; the guard needs Claude Code %s or newer. Check it yourself and rerun with --skip-claude-version-check", err, guard.MinClaudeCodeVersion)
		}
		return err
	}
	return nil
}

func claudeVersion() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "claude", "--version").Output()
	return string(out), err
}

// cmdHook runs a Claude Code hook. Exit codes follow the hook protocol:
// 2 blocks the tool call, so argument errors fail closed.
func cmdHook(env Env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(env.Stderr, "postern hook: missing event")
		return 2
	}
	event := args[0]
	fs := flag.NewFlagSet("postern hook", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	server := fs.String("server", "postern", "Postern MCP server name")
	stateDir := fs.String("state-dir", "", "taint marker directory (default: user config dir)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	dir := *stateDir
	if dir == "" {
		d, err := guard.DefaultStateDir()
		if err != nil {
			fmt.Fprintln(env.Stderr, "postern hook: no state dir")
			return 2
		}
		dir = d
	}
	return guard.Run(event, env.Stdin, env.Stdout, guard.Options{StateDir: dir, ServerName: *server})
}

// cmdEdgeCheck verifies, against the live relay hostname, the properties
// the edge must enforce. Run it after setup, after any edge change, and
// during the revocation drill.
func cmdEdgeCheck(ctx context.Context, env Env, args []string) error {
	fs, cfgFlag := newFlags(env, "edge-check")
	if err := fs.Parse(args); err != nil {
		return err
	}
	l, err := loadPinned(env, *cfgFlag)
	if err != nil {
		return err
	}
	opts, err := bridgeOptions(l, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return err
	}
	base := l.cfg.RelayURL
	self := l.cfg.PeerName
	other := ""
	for _, p := range l.cfg.Peers {
		other = p.Name
		break
	}
	ownFP := tlsutil.Fingerprint(opts.ClientCert.Leaf.Raw)

	noCert := edgeClient(opts, false)
	withCert := edgeClient(opts, true)
	pollURL := func(to string) string {
		return base + "/v1/poll?" + url.Values{"to": {to}, "timeout": {"0"}}.Encode()
	}

	type check struct {
		name   string
		client *http.Client
		url    string
		header map[string]string
		want   func(status int, body []byte, err error) bool
	}
	// Blocked means stopped before the relay: a refused TLS handshake, or
	// an edge 403 page. A JSON error from the relay itself means the
	// request got through the edge, which is a failure here.
	blocked := func(status int, body []byte, err error) bool {
		return err != nil || (status == 403 && !relayError(body))
	}
	ok := func(s int, _ []byte, err error) bool { return err == nil && s == 200 }
	bogusFP := strings.Repeat("0", 64)
	checks := []check{
		{"request without a client certificate is blocked", noCert, base + "/healthz", nil, blocked},
		{"forged fingerprint header without a certificate is blocked", noCert, pollURL(self),
			map[string]string{"X-Postern-Client-Cert-Sha256": ownFP}, blocked},
		{"request with this bridge's certificate reaches the relay", withCert, base + "/healthz", nil, ok},
		{"relay binds this certificate to " + self, withCert, pollURL(self), nil, ok},
		{"a forged fingerprint header cannot override this certificate", withCert, pollURL(self),
			map[string]string{"X-Postern-Client-Cert-Sha256": bogusFP}, ok},
	}
	if other != "" {
		checks = append(checks, check{"this certificate cannot read " + other + "'s mailbox", withCert, pollURL(other), nil,
			func(s int, body []byte, err error) bool { return err == nil && s == 403 && relayError(body) }})
	}

	failed := 0
	for _, c := range checks {
		status, body, err := edgeGet(ctx, c.client, c.url, c.header)
		mark := "PASS"
		if !c.want(status, body, err) {
			mark = "FAIL"
			failed++
		}
		detail := fmt.Sprintf("HTTP %d", status)
		if err != nil {
			detail = "connection refused or TLS rejected"
		}
		fmt.Fprintf(env.Stdout, "%s  %s (%s)\n", mark, c.name, detail)
	}
	if failed > 0 {
		return fmt.Errorf("%d edge check(s) failed", failed)
	}
	return nil
}

func edgeClient(opts bridge.Options, withCert bool) *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:           nil,
			TLSClientConfig: clientTLS(opts, withCert),
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func edgeGet(ctx context.Context, c *http.Client, u string, header map[string]string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, body, nil
}

// relayError reports whether body is the relay's own JSON error.
func relayError(body []byte) bool {
	var e struct {
		Error string `json:"error"`
	}
	return json.Unmarshal(body, &e) == nil && e.Error != ""
}
