// Package scripts tests the operator scripts in this directory. They are
// run for real, against a fake curl and a fake security on PATH that
// record their argv, environment and stdin, so the tests can check that
// the API token reaches curl only on stdin and never the real Cloudflare
// API or the real keychain.
package scripts

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	testZone = "00112233445566778899aabbccddeeff"
	apiBase  = "https://api.cloudflare.com/client/v4"
)

// scripts lists the operator scripts: every *.sh here but the shared
// helpers.
var scripts = func() []string {
	all, _ := filepath.Glob("*.sh")
	var out []string
	for _, s := range all {
		if !strings.HasPrefix(s, "_") {
			out = append(out, s)
		}
	}
	return out
}()

func scriptPath(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func requireTools(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range append([]string{"bash"}, tools...) {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found on PATH; skipping", tool)
		}
	}
}

// harness is a scratch directory with a fake curl and a fake security
// first on PATH. Each curl call n leaves argv.n, env.n, stdin.n and
// (when it sent one) body.n in rec; the response comes from
// response.n, or response.METHOD.
type harness struct {
	t     *testing.T
	dir   string
	bin   string
	rec   string
	tmp   string
	token string
	shell string // run scripts with this shell instead of their shebang
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{
		t: t, dir: dir,
		bin: filepath.Join(dir, "bin"), rec: filepath.Join(dir, "rec"), tmp: filepath.Join(dir, "tmp"),
		token: "tok_" + randHex(t, 20),
	}
	for _, d := range []string{h.bin, h.rec, h.tmp} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fakeCurl := `#!/bin/sh
rec='` + h.rec + `'
n=$(cat "$rec/count" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$rec/count"
: > "$rec/argv.$n"
for a in "$@"; do printf '%s\n' "$a" >> "$rec/argv.$n"; done
env > "$rec/env.$n"
cat > "$rec/stdin.$n"
prev=""
method=GET
for a in "$@"; do
	case "$prev" in
	--data-binary) case "$a" in @*) cp "${a#@}" "$rec/body.$n" ;; esac ;;
	-X) method=$a ;;
	esac
	prev=$a
done
if [ -f "$rec/response.$n" ]; then cat "$rec/response.$n"; else cat "$rec/response.$method" 2>/dev/null; fi
code=0
if [ -f "$rec/exit.$method" ]; then code=$(cat "$rec/exit.$method"); fi
exit "$code"
`
	fakeSecurity := `#!/bin/sh
for a in "$@"; do printf '%s\n' "$a"; done > '` + h.rec + `/security.argv'
printf '%s\n' '` + h.token + `'
`
	for name, body := range map[string]string{"curl": fakeCurl, "security": fakeSecurity} {
		if err := os.WriteFile(filepath.Join(h.bin, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

type result struct {
	stdout, stderr string
	code           int
}

func (r result) out() string { return r.stdout + r.stderr }

func (h *harness) run(stdin, script string, args ...string) result {
	h.t.Helper()
	path := scriptPath(h.t, script)
	var cmd *exec.Cmd
	if h.shell != "" {
		cmd = exec.Command(h.shell, append([]string{path}, args...)...)
	} else {
		cmd = exec.Command(path, args...)
	}
	cmd.Dir = h.dir
	cmd.Env = []string{
		"PATH=" + h.bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + h.dir,
		"TMPDIR=" + h.tmp,
		"LC_ALL=C",
	}
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			h.t.Fatalf("running %s: %v", script, err)
		}
		code = ee.ExitCode()
	}
	r := result{stdout.String(), stderr.String(), code}
	// The token is never printed, and the scripts leave no temporary
	// files behind, whatever the outcome.
	if strings.Contains(r.out(), h.token) {
		h.t.Fatalf("%s printed the API token", script)
	}
	if left, _ := os.ReadDir(h.tmp); len(left) != 0 {
		h.t.Fatalf("%s left temporary files behind: %v", script, left)
	}
	return r
}

func (h *harness) mustRun(stdin, script string, args ...string) result {
	h.t.Helper()
	r := h.run(stdin, script, args...)
	if r.code != 0 {
		h.t.Fatalf("%s %v: exit %d\nstdout:\n%s\nstderr:\n%s", script, args, r.code, r.stdout, r.stderr)
	}
	return r
}

func (h *harness) mustFail(stdin, script string, args ...string) result {
	h.t.Helper()
	r := h.run(stdin, script, args...)
	if r.code == 0 {
		h.t.Fatalf("%s %v succeeded, want failure\nstdout:\n%s", script, args, r.stdout)
	}
	return r
}

func (h *harness) file(name string) string {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.rec, name))
	if err != nil {
		h.t.Fatal(err)
	}
	return string(b)
}

func (h *harness) curlCalls() int {
	b, err := os.ReadFile(filepath.Join(h.rec, "count"))
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

func (h *harness) securityCalled() bool {
	_, err := os.Stat(filepath.Join(h.rec, "security.argv"))
	return err == nil
}

func (h *harness) respond(name, body string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.rec, name), []byte(body), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) tokenFile() string {
	h.t.Helper()
	p := filepath.Join(h.dir, "api-token")
	if err := os.WriteFile(p, []byte(h.token+"\n"), 0o600); err != nil {
		h.t.Fatal(err)
	}
	return p
}

// curlCall checks how curl call n got the token (stdin only: never in
// argv or the environment) and returns its argv, method and URL.
func (h *harness) curlCall(n int) (argv []string, method, url string) {
	h.t.Helper()
	argv = strings.Split(strings.TrimSuffix(h.file(fmt.Sprintf("argv.%d", n)), "\n"), "\n")
	if strings.Contains(strings.Join(argv, "\n"), h.token) {
		h.t.Fatalf("curl call %d: token in argv", n)
	}
	if env := h.file(fmt.Sprintf("env.%d", n)); strings.Contains(env, h.token) {
		h.t.Fatalf("curl call %d: token in the environment", n)
	}
	if got, want := h.file(fmt.Sprintf("stdin.%d", n)), "Authorization: Bearer "+h.token+"\n"; got != want {
		h.t.Fatalf("curl call %d: stdin = %q, want only the Authorization header", n, got)
	}
	if argv[0] != "-q" {
		h.t.Errorf("curl call %d: -q must come first so no curlrc applies; argv = %v", n, argv)
	}
	headerFromStdin := false
	method = "GET"
	for i, a := range argv {
		if (a == "-H" || a == "--header") && i+1 < len(argv) && argv[i+1] == "@-" {
			headerFromStdin = true
		}
		if a == "-X" && i+1 < len(argv) {
			method = argv[i+1]
		}
		if strings.HasPrefix(a, "https://") {
			url = a
		}
		if strings.HasPrefix(strings.ToLower(a), "authorization") {
			h.t.Errorf("curl call %d: an Authorization argument: %q", n, a)
		}
	}
	if !headerFromStdin {
		h.t.Errorf("curl call %d: no -H @- in argv %v", n, argv)
	}
	if !contains(argv, "--proto") || !contains(argv, "=https") {
		h.t.Errorf("curl call %d: not restricted to https: %v", n, argv)
	}
	return argv, method, url
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// --- certificates for the fake API ---

type pki struct {
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test managed CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &pki{key, cert}
}

// csr writes a CSR for a fresh key to dir/name and returns the key.
func writeCSR(t *testing.T, dir, name string) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "peer-a"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return p, key
}

// issue returns a client certificate PEM for pub and its SHA-256.
func (p *pki) issue(t *testing.T, pub any) (string, string) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "peer-a"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(14 * 24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, pub, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), hex.EncodeToString(sum[:])
}

func apiResponse(t *testing.T, result any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const certID = "3f2c9a1e-7b4d-4c1a-9e8f-0a1b2c3d4e5f"

func certResult(pemText, fp string) map[string]any {
	return map[string]any{
		"id": certID, "certificate": pemText, "fingerprint_sha256": fp,
		"expires_on": "2026-11-19T00:00:00Z", "status": "active", "validity_days": 14,
	}
}

// --- generic ---

func TestScriptsHelp(t *testing.T) {
	requireTools(t)
	if len(scripts) == 0 {
		t.Fatal("no scripts found")
	}
	h := newHarness(t)
	for _, s := range scripts {
		t.Run(s, func(t *testing.T) {
			r := h.mustRun("", s, "--help")
			if !strings.HasPrefix(r.stdout, "Usage: "+s) || !strings.Contains(r.stdout, "--dry-run") {
				t.Fatalf("help:\n%s", r.stdout)
			}
			if r := h.run("", s, "--no-such-flag"); r.code != 2 || !strings.Contains(r.stderr, "unknown argument") {
				t.Fatalf("unknown flag: exit %d, %s", r.code, r.stderr)
			}
			if fi, err := os.Stat(s); err != nil || fi.Mode()&0o111 == 0 {
				t.Fatalf("%s is not executable", s)
			}
		})
	}
	if h.curlCalls() != 0 || h.securityCalled() {
		t.Fatal("help or a usage error touched curl or the keychain")
	}
}

// TestShellcheck runs shellcheck over the scripts when it is installed.
func TestShellcheck(t *testing.T) {
	if _, err := exec.LookPath("shellcheck"); err != nil {
		t.Skip("shellcheck not installed; skipping")
	}
	out, err := exec.Command("shellcheck", append([]string{"-x", "_common.sh"}, scripts...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("shellcheck: %v\n%s", err, out)
	}
}

// TestScriptsStayGeneric: no real API token, zone or account id can sit
// in a script; the only API host is the public Cloudflare API.
func TestScriptsStayGeneric(t *testing.T) {
	hostRe := regexp.MustCompile(`https?://[A-Za-z0-9.-]+`)
	for _, s := range append([]string{"_common.sh"}, scripts...) {
		b, err := os.ReadFile(s)
		if err != nil {
			t.Fatal(err)
		}
		for _, host := range hostRe.FindAllString(string(b), -1) {
			if host != "https://api.cloudflare.com" {
				t.Errorf("%s names host %s", s, host)
			}
		}
		if m := regexp.MustCompile(`\b[0-9a-f]{32}\b`).FindString(string(b)); m != "" {
			t.Errorf("%s contains a 32-hex value (a zone or account id?): %s", s, m)
		}
	}
}

// --- issue-cert.sh ---

// dryRunBody parses the JSON body a dry run printed after the headers.
func dryRunBody(t *testing.T, out string) map[string]any {
	t.Helper()
	_, body, ok := strings.Cut(out, "Content-Type: application/json\n\n")
	if !ok {
		t.Fatalf("no request body in dry run output:\n%s", out)
	}
	body, _, _ = strings.Cut(body, "\n")
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("dry run body is not JSON: %v\n%s", err, body)
	}
	return m
}

func TestIssueCertDryRun(t *testing.T) {
	requireTools(t, "python3", "openssl")
	h := newHarness(t)
	csr, _ := writeCSR(t, h.dir, "peer-a.csr")
	csrText, _ := os.ReadFile(csr)
	r := h.mustRun("", "issue-cert.sh", "--zone", testZone, "--csr", csr, "--days", "7", "--dry-run")
	wantLine := "POST " + apiBase + "/zones/" + testZone + "/client_certificates\n"
	if !strings.Contains(r.stdout, wantLine) || !strings.Contains(r.stdout, "Authorization: Bearer [REDACTED]\n") {
		t.Fatalf("dry run output:\n%s", r.stdout)
	}
	body := dryRunBody(t, r.stdout)
	if body["csr"] != string(csrText) || body["validity_days"] != float64(7) || len(body) != 2 {
		t.Fatalf("request body = %v", body)
	}
	if h.curlCalls() != 0 || h.securityCalled() {
		t.Fatal("dry run sent a request or read the keychain")
	}
	if _, err := os.Stat(filepath.Join(h.dir, "peer-a.pem")); err == nil {
		t.Fatal("dry run wrote a certificate")
	}
	// Default validity is 14 days.
	r = h.mustRun("", "issue-cert.sh", "--zone", testZone, "--csr", csr, "--dry-run")
	if body := dryRunBody(t, r.stdout); body["validity_days"] != float64(14) {
		t.Fatalf("default validity_days = %v", body["validity_days"])
	}
}

func TestIssueCert(t *testing.T) {
	requireTools(t, "python3", "openssl")
	for _, source := range []string{"token file", "keychain"} {
		t.Run(source, func(t *testing.T) {
			h := newHarness(t)
			p := newPKI(t)
			csr, key := writeCSR(t, h.dir, "peer-a.csr")
			certPEM, fp := p.issue(t, &key.PublicKey)
			// The API's fingerprint format may differ in case or colons.
			h.respond("response.POST", apiResponse(t, certResult(certPEM, strings.ToUpper(fp))))

			args := []string{"--zone", testZone, "--csr", csr, "--days", "14"}
			if source == "token file" {
				args = append(args, "--token-file", h.tokenFile())
			}
			r := h.mustRun("", "issue-cert.sh", args...)

			if h.curlCalls() != 1 {
				t.Fatalf("%d curl calls, want 1", h.curlCalls())
			}
			argv, method, url := h.curlCall(1)
			if method != "POST" || url != apiBase+"/zones/"+testZone+"/client_certificates" {
				t.Fatalf("request = %s %s", method, url)
			}
			if !contains(argv, "Content-Type: application/json") {
				t.Errorf("no JSON content type: %v", argv)
			}
			var body map[string]any
			if err := json.Unmarshal([]byte(h.file("body.1")), &body); err != nil {
				t.Fatal(err)
			}
			csrText, _ := os.ReadFile(csr)
			if body["csr"] != string(csrText) || body["validity_days"] != float64(14) {
				t.Fatalf("request body = %v", body)
			}
			if source == "keychain" {
				if got := h.file("security.argv"); got != "find-generic-password\n-s\npostern-edge-token\n-w\n" {
					t.Fatalf("security argv = %q", got)
				}
			} else if h.securityCalled() {
				t.Fatal("--token-file still read the keychain")
			}

			written, err := os.ReadFile(filepath.Join(h.dir, "peer-a.pem"))
			if err != nil {
				t.Fatal(err)
			}
			if string(written) != certPEM {
				t.Fatal("written PEM differs from the issued certificate")
			}
			for _, want := range []string{certID, fp, "matches the API's fingerprint_sha256", "add-fingerprint.sh"} {
				if !strings.Contains(r.stdout, want) {
					t.Errorf("output lacks %q:\n%s", want, r.stdout)
				}
			}
		})
	}
}

func TestIssueCertRefusesBadResponses(t *testing.T) {
	requireTools(t, "python3", "openssl")
	p := newPKI(t)
	cases := map[string]func(h *harness, key *ecdsa.PrivateKey){
		"fingerprint mismatch": func(h *harness, key *ecdsa.PrivateKey) {
			certPEM, _ := p.issue(t, &key.PublicKey)
			h.respond("response.POST", apiResponse(t, certResult(certPEM, strings.Repeat("ab", 32))))
		},
		"no fingerprint": func(h *harness, key *ecdsa.PrivateKey) {
			certPEM, _ := p.issue(t, &key.PublicKey)
			h.respond("response.POST", apiResponse(t, certResult(certPEM, "")))
		},
		"certificate for another key": func(h *harness, _ *ecdsa.PrivateKey) {
			other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			certPEM, fp := p.issue(t, &other.PublicKey)
			h.respond("response.POST", apiResponse(t, certResult(certPEM, fp)))
		},
		"api error": func(h *harness, _ *ecdsa.PrivateKey) {
			h.respond("response.POST", `{"success":false,"errors":[{"code":1001,"message":"invalid csr"}],"result":null}`)
			h.respond("exit.POST", "22")
		},
		"not json": func(h *harness, _ *ecdsa.PrivateKey) { h.respond("response.POST", "<html>blocked</html>") },
		"no certificate": func(h *harness, _ *ecdsa.PrivateKey) {
			h.respond("response.POST", apiResponse(t, map[string]any{"id": certID}))
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			csr, key := writeCSR(t, h.dir, "peer-a.csr")
			setup(h, key)
			r := h.mustFail("", "issue-cert.sh", "--zone", testZone, "--csr", csr, "--token-file", h.tokenFile())
			if _, err := os.Stat(filepath.Join(h.dir, "peer-a.pem")); err == nil {
				t.Fatal("a certificate was written")
			}
			if name == "api error" && !strings.Contains(r.stderr, "invalid csr") {
				t.Errorf("API error not shown:\n%s", r.stderr)
			}
			if strings.Contains(name, "mismatch") || strings.Contains(name, "another key") {
				if !strings.Contains(r.stderr, certID) || !strings.Contains(r.stderr, "revoke") {
					t.Errorf("failure does not say which certificate to revoke:\n%s", r.stderr)
				}
			}
		})
	}
}

func TestIssueCertRefusesBadArguments(t *testing.T) {
	requireTools(t, "python3", "openssl")
	h := newHarness(t)
	csr, _ := writeCSR(t, h.dir, "peer-a.csr")
	notCSR := filepath.Join(h.dir, "notes.txt")
	os.WriteFile(notCSR, []byte("hello\n"), 0o644)
	existing := filepath.Join(h.dir, "existing.pem")
	os.WriteFile(existing, []byte("keep me\n"), 0o644)
	loose := filepath.Join(h.dir, "loose-token")
	os.WriteFile(loose, []byte(h.token+"\n"), 0o644)
	os.Chmod(loose, 0o644)

	for name, args := range map[string][]string{
		"no zone":           {"--csr", csr},
		"placeholder zone":  {"--zone", "<ZONE_ID>", "--csr", csr},
		"short zone":        {"--zone", "0123", "--csr", csr},
		"zone with a slash": {"--zone", testZone[:31] + "/", "--csr", csr},
		"no csr":            {"--zone", testZone},
		"missing csr":       {"--zone", testZone, "--csr", filepath.Join(h.dir, "nope.csr")},
		"not a csr":         {"--zone", testZone, "--csr", notCSR},
		"zero days":         {"--zone", testZone, "--csr", csr, "--days", "0"},
		"days not a number": {"--zone", testZone, "--csr", csr, "--days", "14d"},
		"too many days":     {"--zone", testZone, "--csr", csr, "--days", "99999"},
		"existing out":      {"--zone", testZone, "--csr", csr, "--out", existing},
		"loose token file":  {"--zone", testZone, "--csr", csr, "--token-file", loose},
		"missing value":     {"--zone", testZone, "--csr"},
	} {
		t.Run(name, func(t *testing.T) {
			r := h.mustFail("", "issue-cert.sh", args...)
			if name == "loose token file" && !strings.Contains(r.stderr, "chmod 600") {
				t.Errorf("stderr: %s", r.stderr)
			}
		})
	}
	if h.curlCalls() != 0 || h.securityCalled() {
		t.Fatal("a refused invocation sent a request or read the keychain")
	}
	if b, _ := os.ReadFile(existing); string(b) != "keep me\n" {
		t.Fatal("existing --out file was changed")
	}
}

// TestIssueCertRefusesBadToken: a token with characters that could
// inject another header line is refused before any request.
func TestIssueCertRefusesBadToken(t *testing.T) {
	requireTools(t, "python3", "openssl")
	h := newHarness(t)
	csr, _ := writeCSR(t, h.dir, "peer-a.csr")
	for name, content := range map[string]string{
		"empty":         "\n",
		"header inject": "tok_0123456789abcdef0123\tX-Other: 1\n",
		"space":         "tok_0123456789 abcdef0123\n",
		"short":         "tok_short\n",
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(h.dir, "bad-token")
			os.Remove(p)
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			r := h.mustFail("", "issue-cert.sh", "--zone", testZone, "--csr", csr, "--token-file", p)
			if !strings.Contains(r.stderr, "not shown") {
				t.Errorf("stderr: %s", r.stderr)
			}
			if v := strings.TrimSpace(content); v != "" && strings.Contains(r.out(), v) {
				t.Errorf("output echoes the token")
			}
		})
	}
	if h.curlCalls() != 0 {
		t.Fatal("a request was sent with a bad token")
	}
}
