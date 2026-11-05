package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"postern/internal/config"
	"postern/internal/envelope"
	"postern/internal/presence"
	"postern/internal/secrets"
	"postern/internal/secrets/secretstest"
	"postern/internal/tlsutil/tlstest"
)

// relayURL is never reached by these tests except by edge-check, which
// gets a refused connection on the loopback interface.
const relayURL = "https://127.0.0.1:1"

var csrRe = regexp.MustCompile(`(?s)-----BEGIN CERTIFICATE REQUEST-----.*?-----END CERTIFICATE REQUEST-----\n`)

// countingStore is a memory store that counts writes, so a test can
// prove a refused command changed no keychain item.
type countingStore struct {
	*secretstest.Memory
	writes int
}

func (c *countingStore) Set(name string, v []byte) error {
	c.writes++
	return c.Memory.Set(name, v)
}

func (c *countingStore) Delete(name string) error {
	c.writes++
	return c.Memory.Delete(name)
}

type ask struct{ reason, summary string }

// harness drives the CLI in-process with one memory store per keychain
// service, like the real keychain, and records every confirmation.
type harness struct {
	t      *testing.T
	dir    string
	cfg    string
	ca     *tlstest.CA
	stores map[string]*countingStore
	asks   []ask
	refuse bool
	stderr bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	dir := t.TempDir()
	return &harness{t: t, dir: dir, cfg: filepath.Join(dir, "config.json"), ca: tlstest.NewCA(t), stores: map[string]*countingStore{}}
}

func (h *harness) store(service string) *countingStore {
	if h.stores[service] == nil {
		h.stores[service] = &countingStore{Memory: secretstest.NewMemory()}
	}
	return h.stores[service]
}

func (h *harness) writes() int {
	n := 0
	for _, s := range h.stores {
		n += s.writes
	}
	return n
}

func (h *harness) env(stdout *bytes.Buffer) Env {
	return Env{
		Stdin:      strings.NewReader(""),
		Stdout:     stdout,
		Stderr:     &h.stderr,
		OpenStore:  func(s string) (secrets.Store, error) { return h.store(s), nil },
		Executable: os.Executable,
		Confirm: func(reason, summary string) error {
			h.asks = append(h.asks, ask{reason, summary})
			if h.refuse {
				return errNotConfirmed
			}
			return nil
		},
		Version: "test",
	}
}

// run executes a command with --config inserted after the command
// words and returns stdout.
func (h *harness) run(wantCode int, args ...string) string {
	h.t.Helper()
	words := 1
	switch args[0] {
	case "peer", "session", "cert", "config", "thread":
		words = 2
	}
	all := append(append(append([]string{}, args[:words]...), "--config", h.cfg), args[words:]...)
	var out bytes.Buffer
	h.stderr.Reset()
	if code := Run(context.Background(), all, h.env(&out)); code != wantCode {
		h.t.Fatalf("%v: exit %d, want %d\nstdout: %s\nstderr: %s", all, code, wantCode, out.String(), h.stderr.String())
	}
	return out.String()
}

// initialised returns a harness with an initialised bridge (peer-a), an
// imported client certificate and one peer (peer-b), and no recorded
// confirmations.
func initialised(t *testing.T) *harness {
	h := newHarness(t)
	out := h.run(0, "init", "--peer-name", "peer-a", "--relay-url", relayURL, "--session", "build")
	h.importCert(csrRe.FindString(out))
	pub, _, err := envelope.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	h.run(0, "peer", "add", "--name", "peer-b", "--public-key", envelope.EncodeKey(pub), "--fingerprint", envelope.Fingerprint(pub))
	// init and peer add asked; importing a certificate for the current
	// key did not.
	if len(h.asks) != 2 {
		t.Fatalf("setup asked %d times, want 2 (init, peer add)", len(h.asks))
	}
	h.asks = nil
	return h
}

func (h *harness) importCert(csr string) {
	h.t.Helper()
	if csr == "" {
		h.t.Fatal("no CSR in output")
	}
	file := filepath.Join(h.t.TempDir(), "cert.pem")
	if err := os.WriteFile(file, h.ca.SignCSR(h.t, []byte(csr)), 0o600); err != nil {
		h.t.Fatal(err)
	}
	h.run(0, "cert", "import", file)
}

func (h *harness) signedFile(csr string) string {
	h.t.Helper()
	file := filepath.Join(h.t.TempDir(), "next.pem")
	if err := os.WriteFile(file, h.ca.SignCSR(h.t, []byte(csr)), 0o600); err != nil {
		h.t.Fatal(err)
	}
	return file
}

// gated is one command that changes what the bridge trusts.
type gated struct {
	name string
	// prepare builds the state before the command and returns its args.
	prepare func(t *testing.T) (*harness, []string)
	// summary and reason must mention these.
	inSummary []string
	inReason  []string
}

func gatedCommands() []gated {
	newPeer := func(t *testing.T) (string, string) {
		pub, _, err := envelope.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		return envelope.EncodeKey(pub), envelope.Fingerprint(pub)
	}
	return []gated{
		{
			name: "init",
			prepare: func(t *testing.T) (*harness, []string) {
				return newHarness(t), []string{"init", "--peer-name", "peer-a", "--relay-url", relayURL, "--session", "build"}
			},
			inSummary: []string{"Initialise", "peer-a", relayURL, "build"},
			inReason:  []string{"peer-a"},
		},
		{
			name: "init --force",
			prepare: func(t *testing.T) (*harness, []string) {
				return initialised(t), []string{"init", "--force", "--peer-name", "peer-a", "--relay-url", relayURL}
			},
			inSummary: []string{"REPLACE", "peer-a"},
			inReason:  []string{"replace", "peer-a"},
		},
		{
			name: "peer add",
			prepare: func(t *testing.T) (*harness, []string) {
				h := initialised(t)
				key, fp := newPeer(t)
				return h, []string{"peer", "add", "--name", "peer-c", "--public-key", key, "--fingerprint", fp}
			},
			inSummary: []string{"Trust peer peer-c with fingerprint", "out of band"},
			inReason:  []string{"trust peer peer-c"},
		},
		{
			name: "peer remove",
			prepare: func(t *testing.T) (*harness, []string) {
				return initialised(t), []string{"peer", "remove", "--name", "peer-b"}
			},
			inSummary: []string{"Stop trusting peer peer-b"},
			inReason:  []string{"stop trusting peer peer-b"},
		},
		{
			name: "session add",
			prepare: func(t *testing.T) (*harness, []string) {
				return initialised(t), []string{"session", "add", "review"}
			},
			inSummary: []string{"session add review", "build, review"},
			inReason:  []string{"allow session review"},
		},
		{
			name: "session remove",
			prepare: func(t *testing.T) (*harness, []string) {
				return initialised(t), []string{"session", "remove", "build"}
			},
			inSummary: []string{"session remove build"},
			inReason:  []string{"remove session build"},
		},
		{
			name: "config pin",
			prepare: func(t *testing.T) (*harness, []string) {
				h := initialised(t)
				raw, err := os.ReadFile(h.cfg)
				if err != nil {
					t.Fatal(err)
				}
				// The human edited the file by hand.
				edited := strings.Replace(string(raw), `"build"`, `"build", "docs"`, 1)
				if err := os.WriteFile(h.cfg, []byte(edited), 0o600); err != nil {
					t.Fatal(err)
				}
				return h, []string{"config", "pin"}
			},
			inSummary: []string{"Pin this config", "docs"},
			inReason:  []string{"pin"},
		},
		{
			name: "cert import (rotated key)",
			prepare: func(t *testing.T) (*harness, []string) {
				h := initialised(t)
				csr := h.run(0, "cert", "csr", "--new-key")
				return h, []string{"cert", "import", h.signedFile(csr)}
			},
			inSummary: []string{"new client key", "SHA-256", "peer-a"},
			inReason:  []string{"new client key"},
		},
	}
}

// TestGatedCommandsAskWithSummary checks that every command that
// changes what the bridge trusts asks exactly once, with a summary and
// a dialog reason that name the change.
func TestGatedCommandsAskWithSummary(t *testing.T) {
	for _, g := range gatedCommands() {
		t.Run(g.name, func(t *testing.T) {
			h, args := g.prepare(t)
			h.run(0, args...)
			if len(h.asks) != 1 {
				t.Fatalf("asked %d times, want 1", len(h.asks))
			}
			a := h.asks[0]
			for _, s := range g.inSummary {
				if !strings.Contains(a.summary, s) {
					t.Errorf("summary does not mention %q:\n%s", s, a.summary)
				}
			}
			for _, s := range g.inReason {
				if !strings.Contains(a.reason, s) {
					t.Errorf("reason %q does not mention %q", a.reason, s)
				}
			}
			if len(a.reason) > presence.MaxReasonBytes || strings.Contains(a.reason, "\n") {
				t.Errorf("reason too long or multi-line for the system dialog: %q", a.reason)
			}
		})
	}
}

// TestRefusalChangesNothing checks that when the human does not approve,
// the config file, the pin and every keychain item stay as they were.
func TestRefusalChangesNothing(t *testing.T) {
	for _, g := range gatedCommands() {
		t.Run(g.name, func(t *testing.T) {
			h, args := g.prepare(t)
			before, beforeErr := os.ReadFile(h.cfg)
			writes := h.writes()
			h.refuse = true
			h.run(1, args...)
			if len(h.asks) != 1 {
				t.Fatalf("asked %d times, want 1", len(h.asks))
			}
			if !strings.Contains(h.stderr.String(), "nothing changed") {
				t.Errorf("error does not say nothing changed: %s", h.stderr.String())
			}
			after, afterErr := os.ReadFile(h.cfg)
			if !bytes.Equal(before, after) || (beforeErr == nil) != (afterErr == nil) {
				t.Fatal("config file changed without approval")
			}
			if got := h.writes(); got != writes {
				t.Fatalf("%d keychain writes without approval", got-writes)
			}
			if beforeErr == nil {
				// The pin still matches whatever was trusted before.
				err := config.VerifyPin(h.store(config.PinService), h.cfg, before)
				if g.name == "config pin" {
					if !errors.Is(err, config.ErrPinMismatch) {
						t.Fatalf("hand-edited config became pinned: %v", err)
					}
				} else if err != nil {
					t.Fatalf("pin no longer verifies: %v", err)
				}
			}
		})
	}
}

// TestUngatedCommandsNeverAsk checks that read-only commands never ask
// for approval, so the dialog only ever appears for a real change.
func TestUngatedCommandsNeverAsk(t *testing.T) {
	h := initialised(t)
	h.run(0, "show")
	if out := h.run(0, "cert", "csr"); !strings.Contains(out, "CERTIFICATE REQUEST") {
		t.Fatalf("cert csr: %s", out)
	}
	h.run(0, "cert", "csr", "--out", filepath.Join(t.TempDir(), "req.pem"))
	// These two fail (no relay, unknown thread); they must still not ask.
	h.run(1, "edge-check")
	h.run(1, "thread", "reset", envelope.NewThreadID())
	h.run(0, "version")
	if len(h.asks) != 0 {
		t.Fatalf("ungated commands asked %d times: %+v", len(h.asks), h.asks)
	}
}

func TestNoConfirmFunctionRefuses(t *testing.T) {
	h := initialised(t)
	before, _ := os.ReadFile(h.cfg)
	writes := h.writes()
	var out bytes.Buffer
	env := h.env(&out)
	env.Confirm = nil
	if code := Run(context.Background(), []string{"session", "add", "--config", h.cfg, "review"}, env); code == 0 {
		t.Fatal("change accepted with no way to ask the human")
	}
	after, _ := os.ReadFile(h.cfg)
	if !bytes.Equal(before, after) || h.writes() != writes {
		t.Fatal("state changed")
	}
}

// TestPresenceConfirm checks the production confirmation: the full
// summary goes to the terminal first, the short reason goes to the
// system dialog, and every failure refuses the change with no fallback.
func TestPresenceConfirm(t *testing.T) {
	const summary = "Trust peer peer-b with fingerprint\n  abcd"
	for _, tc := range []struct {
		name    string
		result  error
		wantErr bool
		inErr   string
	}{
		{"approved", nil, false, ""},
		{"denied", presence.ErrDenied, true, "not approved"},
		{"unsupported", presence.ErrUnsupported, true, "Touch ID"},
		{"unavailable", presence.ErrUnavailable, true, "GUI session"},
		{"other", errors.New("boom"), true, "nothing changed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			var gotReason string
			confirm := presenceConfirm(&out, func(reason string) error {
				gotReason = reason
				if !strings.Contains(out.String(), summary) {
					t.Error("summary not printed before the dialog")
				}
				return tc.result
			})
			err := confirm("trust peer peer-b", summary)
			if gotReason != "trust peer peer-b" {
				t.Errorf("dialog reason = %q", gotReason)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), tc.inErr) {
				t.Errorf("error %q does not mention %q", err, tc.inErr)
			}
		})
	}
}

func TestDefaultEnvConfirmsWithPresence(t *testing.T) {
	if DefaultEnv("test").Confirm == nil {
		t.Fatal("production environment has no confirmation")
	}
}

// TestUsageMatchesConfigFlag checks the usage text's claim about --config
// against each command's real flags (as -h lists them).
func TestUsageMatchesConfigFlag(t *testing.T) {
	if !strings.Contains(usage, "guard and hook do not read it") {
		t.Fatalf("usage no longer says which commands take --config:\n%s", usage)
	}
	cases := []struct {
		args       []string
		wantConfig bool
	}{
		{[]string{"init"}, true},
		{[]string{"show"}, true},
		{[]string{"peer", "add"}, true},
		{[]string{"peer", "remove"}, true},
		{[]string{"session", "add"}, true},
		{[]string{"session", "remove"}, true},
		{[]string{"cert", "csr"}, true},
		{[]string{"cert", "import"}, true},
		{[]string{"config", "pin"}, true},
		{[]string{"edge-check"}, true},
		{[]string{"thread", "reset"}, true},
		{[]string{"mcp"}, true},
		{[]string{"guard", "install"}, false},
		{[]string{"guard", "install-codex"}, false},
		{[]string{"hook", "pre-tool-use"}, false},
	}
	for _, c := range cases {
		var stderr bytes.Buffer
		env := Env{Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &stderr}
		if code := Run(context.Background(), append(append([]string{}, c.args...), "-h"), env); code != 2 {
			t.Errorf("%v -h: exit %d, want 2", c.args, code)
		}
		if has := strings.Contains(stderr.String(), "-config"); has != c.wantConfig {
			t.Errorf("%v: --config accepted = %v, want %v\n%s", c.args, has, c.wantConfig, stderr.String())
		}
	}
}
