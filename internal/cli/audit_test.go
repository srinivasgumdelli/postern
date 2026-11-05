package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"postern/internal/audit"
	"postern/internal/bridge"
	"postern/internal/config"
	"postern/internal/secrets"
)

func (h *harness) auditPath() string { return filepath.Join(h.dir, "audit", "audit.jsonl") }

// auditEntries reads h's audit log, checking its chain first.
func (h *harness) auditEntries() []audit.Entry {
	h.t.Helper()
	if _, err := audit.Verify(h.auditPath()); err != nil {
		h.t.Fatalf("audit chain: %v", err)
	}
	es, err := audit.Tail(h.auditPath(), 10000)
	if err != nil {
		h.t.Fatal(err)
	}
	return es
}

func (h *harness) lastAudit() audit.Entry {
	h.t.Helper()
	es := h.auditEntries()
	if len(es) == 0 {
		h.t.Fatal("audit log is empty")
	}
	return es[len(es)-1]
}

func TestSetupIsAudited(t *testing.T) {
	h := initialised(t)
	es := h.auditEntries()
	var got []string
	for _, e := range es {
		got = append(got, e.Event)
		if e.Actor != audit.ActorCLI {
			t.Errorf("%s recorded by %q", e.Event, e.Actor)
		}
	}
	if strings.Join(got, ",") != "init,cert_import,peer_add" {
		t.Fatalf("setup events = %v", got)
	}
	if es[0].Peer != "peer-a" || es[1].Peer != "peer-a" || es[2].Peer != "peer-b" {
		t.Fatalf("setup entries = %+v", es)
	}
	for p, want := range map[string]os.FileMode{filepath.Dir(h.auditPath()): 0o700, h.auditPath(): 0o600} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s mode %04o, want %04o", filepath.Base(p), fi.Mode().Perm(), want)
		}
	}
	// No keys, certificates, fingerprints, relay URL or paths.
	raw, err := os.ReadFile(h.auditPath())
	if err != nil {
		t.Fatal(err)
	}
	cfg, _, err := config.Load(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{"BEGIN", "127.0.0.1", h.dir, "config.json", cfg.Peers[0].PublicKey, cfg.Peers[0].Fingerprint}
	for _, s := range forbidden {
		if bytes.Contains(raw, []byte(s)) {
			t.Fatalf("audit log contains %q", s)
		}
	}
}

// TestTrustChangesAreAudited: every command that changes what the bridge
// trusts leaves one event after it succeeds, and none when the human
// refuses.
func TestTrustChangesAreAudited(t *testing.T) {
	want := map[string]audit.Entry{
		"init":                      {Event: audit.EventInit, Peer: "peer-a"},
		"init --force":              {Event: audit.EventInit, Peer: "peer-a", Reason: "force"},
		"peer add":                  {Event: audit.EventPeerAdd, Peer: "peer-c"},
		"peer remove":               {Event: audit.EventPeerRemove, Peer: "peer-b"},
		"session add":               {Event: audit.EventSessionAdd, Session: "review"},
		"session remove":            {Event: audit.EventSessionRemove, Session: "build"},
		"config pin":                {Event: audit.EventConfigPin, Peer: "peer-a"},
		"cert import (rotated key)": {Event: audit.EventCertRotate, Peer: "peer-a"},
	}
	for _, g := range gatedCommands() {
		w, ok := want[g.name]
		if !ok {
			t.Fatalf("no expected audit event for %q", g.name)
		}
		t.Run(g.name, func(t *testing.T) {
			h, args := g.prepare(t)
			before := 0
			if _, err := os.Stat(h.auditPath()); err == nil {
				before = len(h.auditEntries())
			}
			h.run(0, args...)
			es := h.auditEntries()
			if len(es) != before+1 {
				t.Fatalf("%d new events, want 1", len(es)-before)
			}
			e := es[len(es)-1]
			if e.Event != w.Event || e.Actor != audit.ActorCLI || e.Peer != w.Peer || e.Session != w.Session || e.Reason != w.Reason {
				t.Fatalf("event = %+v, want %+v", e, w)
			}
		})
		t.Run(g.name+" refused", func(t *testing.T) {
			h, args := g.prepare(t)
			before, _ := os.ReadFile(h.auditPath())
			h.refuse = true
			h.run(1, args...)
			after, _ := os.ReadFile(h.auditPath())
			if !bytes.Equal(before, after) {
				t.Fatal("a refused change was recorded")
			}
		})
	}
}

func TestThreadResetIsAudited(t *testing.T) {
	h := initialised(t)
	l, err := loadPinned(h.env(&bytes.Buffer{}), h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	opts, err := bridgeOptions(l, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := bridge.Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	// The relay is unreachable, so this queues, which is enough to make
	// the thread exist.
	res, err := b.Send(context.Background(), "build", bridge.SendRequest{To: "peer-b", Subject: "s", Body: "b"})
	b.Close()
	if err != nil {
		t.Fatal(err)
	}
	h.run(0, "thread", "reset", res.Thread)
	if e := h.lastAudit(); e.Event != audit.EventThreadReset || e.Thread != res.Thread {
		t.Fatalf("event = %+v", e)
	}
}

func TestGuardInstallIsAudited(t *testing.T) {
	h := initialised(t)
	h.run(0, "guard", "install", "--project", t.TempDir(), "--skip-claude-version-check")
	if e := h.lastAudit(); e.Event != audit.EventGuardInstall || e.Reason != "claude-code" {
		t.Fatalf("event = %+v", e)
	}
	h.run(0, "guard", "install-codex", "--skills-dir", t.TempDir())
	if e := h.lastAudit(); e.Event != audit.EventGuardInstall || e.Reason != "codex" {
		t.Fatalf("event = %+v", e)
	}
	// The project path is not recorded.
	raw, _ := os.ReadFile(h.auditPath())
	if bytes.Contains(raw, []byte(os.TempDir())) || bytes.Contains(raw, []byte("/")) {
		t.Fatalf("audit log contains a path: %s", raw)
	}
}

func TestAuditOff(t *testing.T) {
	h := initialised(t)
	raw, err := os.ReadFile(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	off := strings.Replace(string(raw), `"enabled": true`, `"enabled": false`, 1)
	if off == string(raw) {
		t.Fatalf("config does not state the audit setting:\n%s", raw)
	}
	if err := os.WriteFile(h.cfg, []byte(off), 0o600); err != nil {
		t.Fatal(err)
	}
	h.run(0, "config", "pin")
	// Turning the log off is the last thing it shows.
	if e := h.lastAudit(); e.Event != audit.EventConfigPin || e.Reason != "audit_off" {
		t.Fatalf("event = %+v", e)
	}
	n := len(h.auditEntries())
	h.run(0, "session", "add", "review")
	if got := len(h.auditEntries()); got != n {
		t.Fatalf("recorded %d events with the audit log off", got-n)
	}
	if out := h.run(0, "audit", "tail"); !strings.Contains(out, "config_pin") {
		t.Fatalf("tail with the log off: %s", out)
	}
	if !strings.Contains(h.stderr.String(), "turned off") {
		t.Fatalf("tail does not say the log is off: %s", h.stderr.String())
	}
}

var tailLineRe = regexp.MustCompile(`^\s*\d+  \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ  [a-z_]+ +cli`)

func TestAuditTailAndVerify(t *testing.T) {
	h := initialised(t)

	out := h.run(0, "audit", "tail")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("tail printed %d lines:\n%s", len(lines), out)
	}
	for _, l := range lines {
		if !tailLineRe.MatchString(l) {
			t.Fatalf("tail line %q", l)
		}
	}
	if !strings.Contains(lines[2], "peer_add") || !strings.Contains(lines[2], "peer=peer-b") {
		t.Fatalf("last line %q", lines[2])
	}
	out = h.run(0, "audit", "tail", "-n", "1", "--json")
	var e audit.Entry
	if err := json.Unmarshal([]byte(out), &e); err != nil || e.Event != audit.EventPeerAdd || e.Seq != 3 {
		t.Fatalf("tail --json = %q (%v)", out, err)
	}
	h.run(1, "audit", "tail", "-n", "0")

	out = h.run(0, "audit", "verify")
	if !strings.Contains(out, "OK: 3 events, seq 1 to 3") || !strings.Contains(out, "first event ever recorded") {
		t.Fatalf("verify: %s", out)
	}
	m := regexp.MustCompile(`Last hash: ([0-9a-f]{64})`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("verify does not print the last hash: %s", out)
	}
	h.run(0, "session", "add", "review")
	if out := h.run(0, "audit", "verify", "--hash", m[1]); !strings.Contains(out, "is entry seq 3") {
		t.Fatalf("verify --hash: %s", out)
	}

	// Edit the second entry: verify fails and names seq 3 and the file.
	raw, _ := os.ReadFile(h.auditPath())
	all := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	all[1] = strings.Replace(all[1], `"peer":"peer-a"`, `"peer":"peer-x"`, 1)
	if err := os.WriteFile(h.auditPath(), []byte(strings.Join(all, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.run(1, "audit", "verify")
	msg := h.stderr.String()
	if !strings.Contains(msg, "seq 3") || !strings.Contains(msg, "audit.jsonl") || strings.Contains(msg, h.dir) {
		t.Fatalf("verify error %q does not name the seq and file (and only the file)", msg)
	}

	// Cut the end: the chain still holds, the noted hash does not.
	if err := os.WriteFile(h.auditPath(), []byte(strings.Join(all[:2], "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.run(1, "audit", "verify", "--hash", m[1])
	if !strings.Contains(h.stderr.String(), "not the hash of any entry") {
		t.Fatalf("verify --hash after a cut: %s", h.stderr.String())
	}
}

// TestAuditCommandsNeedNoBridgeKeys: tail and verify read local files;
// they never open the bridge's keychain items. The pin check applies.
func TestAuditCommandsNeedNoBridgeKeys(t *testing.T) {
	h := initialised(t)
	var out bytes.Buffer
	env := h.env(&out)
	env.OpenStore = func(service string) (secrets.Store, error) {
		if service != config.PinService {
			return nil, errors.New("bridge keychain opened")
		}
		return h.store(service), nil
	}
	for _, args := range [][]string{{"audit", "tail", "--config", h.cfg}, {"audit", "verify", "--config", h.cfg}} {
		out.Reset()
		h.stderr.Reset()
		if code := Run(context.Background(), args, env); code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, h.stderr.String())
		}
	}

	raw, _ := os.ReadFile(h.cfg)
	if err := os.WriteFile(h.cfg, append(raw, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"tail", "verify"} {
		h.run(1, "audit", sub)
		if !strings.Contains(h.stderr.String(), "config changed") {
			t.Fatalf("audit %s with an edited config: %s", sub, h.stderr.String())
		}
	}
}
