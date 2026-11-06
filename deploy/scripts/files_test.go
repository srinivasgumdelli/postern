package scripts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"postern/internal/relay"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}\n$`)

// --- gen-edge-secret.sh ---

func readSecret(t *testing.T, path string) string {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o400 {
		t.Fatalf("%s mode = %o, want 0400", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !hex64.Match(b) {
		t.Fatalf("%s is not one line of 64 lowercase hex", path)
	}
	return strings.TrimSpace(string(b))
}

func TestGenEdgeSecret(t *testing.T) {
	requireTools(t, "openssl")
	h := newHarness(t)
	dir := filepath.Join(h.dir, "deploy", "secrets")
	cur := filepath.Join(dir, "edge-secret")
	next := filepath.Join(dir, "edge-secret-next")

	// --next needs a current secret first.
	h.mustFail("", "gen-edge-secret.sh", "--next", "--secrets-dir", dir)

	r := h.mustRun("", "gen-edge-secret.sh", "--dry-run", "--secrets-dir", dir)
	if !strings.Contains(r.stdout, cur) {
		t.Fatalf("dry run: %s", r.stdout)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Fatal("dry run created the secrets directory")
	}

	r = h.mustRun("", "gen-edge-secret.sh", "--secrets-dir", dir)
	v1 := readSecret(t, cur)
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("secrets dir mode: %v %v", fi.Mode().Perm(), err)
	}
	mustNotLeak(t, r, v1)

	// No overwrite without --force; the file is unchanged.
	r = h.mustFail("", "gen-edge-secret.sh", "--secrets-dir", dir)
	if !strings.Contains(r.stderr, "refusing to overwrite") || !strings.Contains(r.stderr, "--next") {
		t.Fatalf("stderr: %s", r.stderr)
	}
	if readSecret(t, cur) != v1 {
		t.Fatal("refused run changed the secret")
	}

	r = h.mustRun("", "gen-edge-secret.sh", "--next", "--secrets-dir", dir)
	n1 := readSecret(t, next)
	mustNotLeak(t, r, v1, n1)
	if n1 == v1 || readSecret(t, cur) != v1 {
		t.Fatal("--next must leave the current secret alone and write a different one")
	}
	if !strings.Contains(r.stdout, "edge_secret_next_file") || !strings.Contains(r.stdout, "compose.edge-secret-next.yml") {
		t.Errorf("--next does not explain the rotation:\n%s", r.stdout)
	}
	h.mustFail("", "gen-edge-secret.sh", "--next", "--secrets-dir", dir)
	if readSecret(t, next) != n1 {
		t.Fatal("refused --next run changed the next secret")
	}

	// The relay accepts the pair: both files pass its checks.
	cfg := filepath.Join(h.dir, "relay.json")
	writeJSON(t, cfg, map[string]any{
		"identity": "header", "db": filepath.Join(h.dir, "relay.db"),
		"edge_secret_file": cur, "edge_secret_next_file": next,
		"peers": map[string][]string{"peer-a": {strings.Repeat("a", 64)}, "peer-b": {strings.Repeat("b", 64)}},
	})
	c, err := relay.LoadConfig(cfg)
	if err != nil {
		t.Fatalf("relay refuses the generated secrets: %v", err)
	}
	if c.EdgeSecretSlots() != 2 {
		t.Fatalf("EdgeSecretSlots = %d", c.EdgeSecretSlots())
	}

	r = h.mustRun("", "gen-edge-secret.sh", "--next", "--force", "--secrets-dir", dir)
	if n2 := readSecret(t, next); n2 == n1 {
		t.Fatal("--force did not replace the next secret")
	} else {
		mustNotLeak(t, r, n1, n2)
	}

	// Nothing but the two secrets is left in the directory.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("secrets dir holds %v", entries)
	}
}

func TestGenEdgeSecretRefusesLinksAndDirectories(t *testing.T) {
	requireTools(t, "openssl")
	h := newHarness(t)
	dir := filepath.Join(h.dir, "secrets")
	os.MkdirAll(filepath.Join(dir, "edge-secret"), 0o700)
	h.mustFail("", "gen-edge-secret.sh", "--force", "--secrets-dir", dir)

	dir2 := filepath.Join(h.dir, "secrets2")
	os.MkdirAll(dir2, 0o700)
	target := filepath.Join(h.dir, "elsewhere")
	os.WriteFile(target, []byte("keep\n"), 0o600)
	os.Symlink(target, filepath.Join(dir2, "edge-secret"))
	h.mustFail("", "gen-edge-secret.sh", "--force", "--secrets-dir", dir2)
	if b, _ := os.ReadFile(target); string(b) != "keep\n" {
		t.Fatal("followed a symlink")
	}
}

func mustNotLeak(t *testing.T, r result, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		for _, part := range []string{s, s[:16], s[len(s)-16:]} {
			if strings.Contains(r.out(), part) {
				t.Fatalf("output contains (part of) a secret:\n%s", r.out())
			}
		}
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// --- add-fingerprint.sh ---

func copyExample(t *testing.T, src, dst string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", src))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o640); err != nil {
		t.Fatal(err)
	}
	return dst
}

func relayPeers(t *testing.T, path string) map[string][]string {
	t.Helper()
	var doc struct {
		Peers map[string][]string `json:"peers"`
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("%s is no longer JSON: %v", path, err)
	}
	return doc.Peers
}

func TestAddFingerprintRelayJSON(t *testing.T) {
	requireTools(t, "python3")
	h := newHarness(t)
	cfg := copyExample(t, "deploy/relay.example.json", filepath.Join(h.dir, "relay.json"))
	fa1, fa2, fa3, fb1 := randHex(t, 32), randHex(t, 32), randHex(t, 32), randHex(t, 32)
	add := func(args ...string) []string { return append([]string{"--relay-json", cfg}, args...) }

	// Dry run changes nothing.
	before, _ := os.ReadFile(cfg)
	r := h.mustRun("", "add-fingerprint.sh", add("--peer", "peer-a", "--fingerprint", fa1, "--dry-run")...)
	if after, _ := os.ReadFile(cfg); string(after) != string(before) || !strings.Contains(r.stdout, fa1) {
		t.Fatalf("dry run wrote the file or did not show the change:\n%s", r.stdout)
	}

	// The first real fingerprint replaces the placeholder.
	h.mustRun("", "add-fingerprint.sh", add("--peer", "peer-a", "--fingerprint", fa1)...)
	if got := relayPeers(t, cfg); len(got["peer-a"]) != 1 || got["peer-a"][0] != fa1 || got["peer-b"][0] != "<PEER_B_CERT_SHA256>" {
		t.Fatalf("peers = %v", got)
	}
	r = h.mustRun("", "add-fingerprint.sh", add("--peer", "peer-b", "--fingerprint", fb1)...)
	if strings.Contains(r.stdout, "Warning") {
		t.Errorf("warning with every placeholder replaced:\n%s", r.stdout)
	}
	// Mode and the other settings survive.
	if fi, _ := os.Stat(cfg); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode changed to %o", fi.Mode().Perm())
	}
	var doc map[string]any
	b, _ := os.ReadFile(cfg)
	json.Unmarshal(b, &doc)
	if doc["edge_secret_file"] != "/run/secrets/edge_secret" || doc["posts_per_hour"] != float64(120) || doc["identity"] != "header" {
		t.Fatalf("other settings changed: %v", doc)
	}

	// Rotation overlap: a second fingerprint is fine, a third is refused.
	h.mustRun("", "add-fingerprint.sh", add("--peer", "peer-a", "--fingerprint", fa2)...)
	before, _ = os.ReadFile(cfg)
	r = h.mustFail("", "add-fingerprint.sh", add("--peer", "peer-a", "--fingerprint", fa3)...)
	if !strings.Contains(r.stderr, "already lists 2") || !strings.Contains(r.stderr, "--remove") {
		t.Fatalf("stderr: %s", r.stderr)
	}
	// Adding the same one again is a no-op.
	h.mustRun("", "add-fingerprint.sh", add("--peer", "peer-a", "--fingerprint", fa2)...)

	for name, args := range map[string][]string{
		"uppercase":          {"--peer", "peer-a", "--fingerprint", strings.ToUpper(fa3)},
		"colons":             {"--peer", "peer-a", "--fingerprint", fa3[:2] + ":" + fa3[2:]},
		"short":              {"--peer", "peer-a", "--fingerprint", fa3[:63]},
		"another peer's":     {"--peer", "peer-b", "--fingerprint", fa1},
		"unknown peer":       {"--peer", "peer-c", "--fingerprint", fa3},
		"bad peer name":      {"--peer", "Peer_A", "--fingerprint", fa3},
		"remove a stranger":  {"--peer", "peer-a", "--remove", "--fingerprint", fa3},
		"remove the last":    {"--peer", "peer-b", "--remove", "--fingerprint", fb1},
		"replace a stranger": {"--peer", "peer-a", "--replace", fa3, "--fingerprint", randHex(t, 32)},
		"replace with owned": {"--peer", "peer-a", "--replace", fa1, "--fingerprint", fb1},
	} {
		t.Run(name, func(t *testing.T) {
			r := h.mustFail("", "add-fingerprint.sh", add(args...)...)
			if after, _ := os.ReadFile(cfg); string(after) != string(before) {
				t.Fatal("a refused edit changed the file")
			}
			if name == "remove the last" && !strings.Contains(r.stderr, "--replace") {
				t.Errorf("stderr: %s", r.stderr)
			}
		})
	}

	// Remove the old one after a rotation; replace a revoked one in place.
	h.mustRun("", "add-fingerprint.sh", add("--peer", "peer-a", "--remove", "--fingerprint", fa1)...)
	unmatchable := randHex(t, 32)
	h.mustRun("", "add-fingerprint.sh", add("--peer", "peer-b", "--replace", fb1, "--fingerprint", unmatchable)...)
	got := relayPeers(t, cfg)
	if strings.Join(got["peer-a"], ",") != fa2 || strings.Join(got["peer-b"], ",") != unmatchable {
		t.Fatalf("peers = %v", got)
	}
	// A new peer needs --new-peer.
	h.mustRun("", "add-fingerprint.sh", add("--peer", "peer-c", "--fingerprint", fa3, "--new-peer")...)

	// The relay accepts the result.
	secret := filepath.Join(h.dir, "edge-secret")
	os.WriteFile(secret, []byte(randHex(t, 32)+"\n"), 0o400)
	b, _ = os.ReadFile(cfg)
	b = []byte(strings.Replace(string(b), "/run/secrets/edge_secret", secret, 1))
	b = []byte(strings.Replace(string(b), "/data/relay.db", filepath.Join(h.dir, "relay.db"), 1))
	final := filepath.Join(h.dir, "final.json")
	os.WriteFile(final, b, 0o600)
	c, err := relay.LoadConfig(final)
	if err != nil {
		t.Fatalf("relay refuses the edited config: %v", err)
	}
	if len(c.Peers) != 3 || c.Peers["peer-a"][0] != fa2 {
		t.Fatalf("relay peers = %v", c.Peers)
	}
	if left, _ := filepath.Glob(filepath.Join(h.dir, ".add-fingerprint.*")); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}

func TestAddFingerprintRefusesBrokenJSON(t *testing.T) {
	requireTools(t, "python3")
	h := newHarness(t)
	for name, body := range map[string]string{
		"not json":      "{",
		"no peers":      `{"identity":"header"}`,
		"duplicate key": `{"peers":{"peer-a":[],"peer-a":[]}}`,
		"peers a list":  `{"peers":["peer-a"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(h.dir, strings.ReplaceAll(name, " ", "-")+".json")
			os.WriteFile(p, []byte(body), 0o600)
			h.mustFail("", "add-fingerprint.sh", "--relay-json", p, "--peer", "peer-a", "--fingerprint", randHex(t, 32))
			if b, _ := os.ReadFile(p); string(b) != body {
				t.Fatal("file changed")
			}
		})
	}
	h.mustFail("", "add-fingerprint.sh", "--relay-json", filepath.Join(h.dir, "missing.json"), "--peer", "peer-a", "--fingerprint", randHex(t, 32))
}

var peersLine = regexp.MustCompile(`(?m)^PEERS = '([^'\n]*)'$`)

func workerPeers(t *testing.T, path string) map[string][]string {
	t.Helper()
	b, _ := os.ReadFile(path)
	m := peersLine.FindAllStringSubmatch(string(b), -1)
	if len(m) != 1 {
		t.Fatalf("PEERS lines: %v", m)
	}
	var peers map[string][]string
	if err := json.Unmarshal([]byte(m[0][1]), &peers); err != nil {
		t.Fatal(err)
	}
	return peers
}

func TestAddFingerprintWorkerPeers(t *testing.T) {
	requireTools(t, "python3")
	h := newHarness(t)
	toml := copyExample(t, "relay-worker/wrangler.toml.example", filepath.Join(h.dir, "wrangler.toml"))
	original, _ := os.ReadFile(toml)
	fa, fb, fa2 := randHex(t, 32), randHex(t, 32), randHex(t, 32)
	w := func(args ...string) []string { return append([]string{"--worker-peers", toml}, args...) }

	h.mustRun("", "add-fingerprint.sh", w("--peer", "peer-a", "--fingerprint", fa)...)
	r := h.mustRun("", "add-fingerprint.sh", w("--peer", "peer-b", "--fingerprint", fb)...)
	if !strings.Contains(r.stdout, "wrangler deploy") {
		t.Errorf("output does not say to redeploy:\n%s", r.stdout)
	}
	h.mustRun("", "add-fingerprint.sh", w("--peer", "peer-a", "--fingerprint", fa2)...)
	h.mustFail("", "add-fingerprint.sh", w("--peer", "peer-a", "--fingerprint", randHex(t, 32))...)

	got := workerPeers(t, toml)
	if strings.Join(got["peer-a"], ",") != fa+","+fa2 || strings.Join(got["peer-b"], ",") != fb {
		t.Fatalf("PEERS = %v", got)
	}
	// Only the PEERS line changed.
	edited, _ := os.ReadFile(toml)
	ol, el := strings.Split(string(original), "\n"), strings.Split(string(edited), "\n")
	if len(ol) != len(el) {
		t.Fatalf("line count changed: %d -> %d", len(ol), len(el))
	}
	for i := range ol {
		if ol[i] != el[i] && !strings.HasPrefix(ol[i], "PEERS = ") {
			t.Errorf("line %d changed: %q -> %q", i+1, ol[i], el[i])
		}
	}

	// A PEERS line outside [vars], or two of them, is refused.
	for name, body := range map[string]string{
		"outside vars": "name = \"x\"\nPEERS = '{\"peer-a\":[\"<P>\"],\"peer-b\":[\"<Q>\"]}'\n[vars]\nX = \"1\"\n",
		"two lines":    "[vars]\nPEERS = '{}'\nPEERS = '{}'\n",
		"basic string": "[vars]\nPEERS = \"{\\\"peer-a\\\":[]}\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(h.dir, strings.ReplaceAll(name, " ", "-")+".toml")
			os.WriteFile(p, []byte(body), 0o600)
			h.mustFail("", "add-fingerprint.sh", "--worker-peers", p, "--peer", "peer-a", "--fingerprint", randHex(t, 32))
			if b, _ := os.ReadFile(p); string(b) != body {
				t.Fatal("file changed")
			}
		})
	}
}

// TestScriptsUnderSystemBash runs the main paths with /bin/bash, which
// on macOS is bash 3.2, so the scripts keep working with it.
func TestScriptsUnderSystemBash(t *testing.T) {
	requireTools(t, "python3", "openssl")
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("no /bin/bash")
	}
	h := newHarness(t)
	h.shell = "/bin/bash"
	p := newPKI(t)
	csr, key := writeCSR(t, h.dir, "peer-a.csr")
	certPEM, fp := p.issue(t, &key.PublicKey)
	h.respond("response.POST", apiResponse(t, certResult(certPEM, fp)))
	h.respond("response.DELETE", apiResponse(t, map[string]any{"id": certID, "status": "pending_revocation"}))
	tok := h.tokenFile()

	h.mustRun("", "issue-cert.sh", "--zone", testZone, "--csr", csr, "--token-file", tok)
	h.curlCall(1)
	h.mustRun("", "revoke-cert.sh", "--zone", testZone, "--id", certID, "--yes", "--token-file", tok)
	h.curlCall(2)
	h.mustRun("", "gen-edge-secret.sh", "--secrets-dir", filepath.Join(h.dir, "s"))
	cfg := copyExample(t, "deploy/relay.example.json", filepath.Join(h.dir, "relay.json"))
	h.mustRun("", "add-fingerprint.sh", "--relay-json", cfg, "--peer", "peer-a", "--fingerprint", fp)
	for _, s := range scripts {
		h.mustRun("", s, "--help")
	}
}
