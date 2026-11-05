package scripts

import (
	"strconv"
	"strings"
	"testing"
)

func listResponse(t *testing.T, certs []map[string]any, page, totalPages int) string {
	t.Helper()
	b := apiResponse(t, certs)
	// Add result_info by hand to keep apiResponse simple.
	return strings.TrimSuffix(b, "}") + `,"result_info":{"page":` + strconv.Itoa(page) + `,"per_page":50,"total_pages":` + strconv.Itoa(totalPages) + `}}`
}

func checkReminder(t *testing.T, out, fp string) {
	t.Helper()
	for _, want := range []string{"deploy/relay.json", "PEERS", "matches no certificate", "rather than deleting it", "--replace " + fp, "openssl rand -hex 32"} {
		if !strings.Contains(out, want) {
			t.Errorf("reminder lacks %q:\n%s", want, out)
		}
	}
}

func TestRevokeCertDryRun(t *testing.T) {
	requireTools(t, "python3")
	h := newHarness(t)
	r := h.mustRun("", "revoke-cert.sh", "--zone", testZone, "--id", certID, "--dry-run")
	if !strings.Contains(r.stdout, "DELETE "+apiBase+"/zones/"+testZone+"/client_certificates/"+certID+"\n") ||
		!strings.Contains(r.stdout, "Authorization: Bearer [REDACTED]") {
		t.Fatalf("dry run:\n%s", r.stdout)
	}
	fp := strings.Repeat("c", 64)
	r = h.mustRun("", "revoke-cert.sh", "--zone", testZone, "--fingerprint", strings.ToUpper(fp), "--dry-run")
	if !strings.Contains(r.stdout, "GET "+apiBase+"/zones/"+testZone+"/client_certificates?per_page=50&page=1\n") ||
		!strings.Contains(r.stdout, fp) || !strings.Contains(r.stdout, "DELETE ") {
		t.Fatalf("dry run:\n%s", r.stdout)
	}
	r = h.mustRun("", "revoke-cert.sh", "--zone", testZone, "--fingerprint", fp, "--lookup-only", "--dry-run")
	if strings.Contains(r.stdout, "DELETE") {
		t.Fatalf("lookup-only dry run shows a DELETE:\n%s", r.stdout)
	}
	if h.curlCalls() != 0 || h.securityCalled() {
		t.Fatal("dry run sent a request or read the keychain")
	}
}

func TestRevokeCertByID(t *testing.T) {
	requireTools(t, "python3")
	h := newHarness(t)
	fp := strings.Repeat("d", 64)
	h.respond("response.DELETE", apiResponse(t, map[string]any{"id": certID, "status": "pending_revocation", "fingerprint_sha256": fp}))
	r := h.mustRun("", "revoke-cert.sh", "--zone", testZone, "--id", certID, "--yes")
	if h.curlCalls() != 1 {
		t.Fatalf("%d curl calls", h.curlCalls())
	}
	if _, method, url := h.curlCall(1); method != "DELETE" || url != apiBase+"/zones/"+testZone+"/client_certificates/"+certID {
		t.Fatalf("request = %s %s", method, url)
	}
	if !strings.Contains(r.stdout, "pending_revocation") {
		t.Errorf("output:\n%s", r.stdout)
	}
	checkReminder(t, r.stdout, fp)
	if got := h.file("security.argv"); got != "find-generic-password\n-s\npostern-edge-token\n-w\n" {
		t.Fatalf("security argv = %q", got)
	}
}

func TestRevokeCertNeedsConfirmation(t *testing.T) {
	requireTools(t, "python3")
	h := newHarness(t)
	h.respond("response.DELETE", apiResponse(t, map[string]any{"id": certID, "status": "pending_revocation"}))
	tok := h.tokenFile()
	for _, answer := range []string{"", "y\n", "yes\n", "REVOKE\n"} {
		r := h.mustFail(answer, "revoke-cert.sh", "--zone", testZone, "--id", certID, "--token-file", tok)
		if !strings.Contains(r.stderr, "nothing revoked") {
			t.Fatalf("answer %q: %s", answer, r.stderr)
		}
	}
	if h.curlCalls() != 0 {
		t.Fatal("revoked without confirmation")
	}
	r := h.mustRun("revoke\n", "revoke-cert.sh", "--zone", testZone, "--id", certID, "--token-file", tok)
	if h.curlCalls() != 1 {
		t.Fatalf("%d curl calls after confirming", h.curlCalls())
	}
	h.curlCall(1)
	checkReminder(t, r.stdout, "<OLD_SHA256>")
}

func TestRevokeCertByFingerprint(t *testing.T) {
	requireTools(t, "python3")
	fp := strings.Repeat("e", 64)
	colons := func(s string) string {
		var parts []string
		for i := 0; i < len(s); i += 2 {
			parts = append(parts, strings.ToUpper(s[i:i+2]))
		}
		return strings.Join(parts, ":")
	}
	page1 := []map[string]any{}
	for i := 0; i < 50; i++ {
		page1 = append(page1, map[string]any{"id": "id-" + strconv.Itoa(i), "status": "active", "fingerprint_sha256": randHex(t, 32)})
	}
	page2 := []map[string]any{
		{"id": "other", "status": "active", "fingerprint_sha256": strings.Repeat("f", 64)},
		{"id": certID, "status": "active", "fingerprint_sha256": colons(fp), "expires_on": "2026-11-19T00:00:00Z"},
	}

	t.Run("lookup only", func(t *testing.T) {
		h := newHarness(t)
		h.respond("response.1", listResponse(t, page1, 1, 2))
		h.respond("response.2", listResponse(t, page2, 2, 2))
		r := h.mustRun("", "revoke-cert.sh", "--zone", testZone, "--fingerprint", fp, "--lookup-only", "--token-file", h.tokenFile())
		if h.curlCalls() != 2 {
			t.Fatalf("%d curl calls, want 2 list pages", h.curlCalls())
		}
		for n, page := range map[int]string{1: "1", 2: "2"} {
			if _, method, url := h.curlCall(n); method != "GET" || url != apiBase+"/zones/"+testZone+"/client_certificates?per_page=50&page="+page {
				t.Fatalf("call %d = %s %s", n, method, url)
			}
		}
		if !strings.Contains(r.stdout, certID) || strings.Contains(r.stdout, "Revocation requested") {
			t.Fatalf("output:\n%s", r.stdout)
		}
	})

	t.Run("revoke", func(t *testing.T) {
		h := newHarness(t)
		h.respond("response.1", listResponse(t, page2, 1, 1))
		h.respond("response.DELETE", apiResponse(t, map[string]any{"id": certID, "status": "pending_revocation"}))
		r := h.mustRun("", "revoke-cert.sh", "--zone", testZone, "--fingerprint", fp, "--yes", "--token-file", h.tokenFile())
		if h.curlCalls() != 2 {
			t.Fatalf("%d curl calls", h.curlCalls())
		}
		if _, method, url := h.curlCall(2); method != "DELETE" || url != apiBase+"/zones/"+testZone+"/client_certificates/"+certID {
			t.Fatalf("revoke request = %s %s", method, url)
		}
		checkReminder(t, r.stdout, fp)
	})

	t.Run("not found", func(t *testing.T) {
		h := newHarness(t)
		h.respond("response.1", listResponse(t, page2[:1], 1, 1))
		r := h.mustFail("", "revoke-cert.sh", "--zone", testZone, "--fingerprint", fp, "--yes", "--token-file", h.tokenFile())
		if h.curlCalls() != 1 || !strings.Contains(r.stderr, "no client certificate") {
			t.Fatalf("calls %d, stderr %s", h.curlCalls(), r.stderr)
		}
	})

	t.Run("already revoked", func(t *testing.T) {
		h := newHarness(t)
		h.respond("response.1", listResponse(t, []map[string]any{{"id": certID, "status": "revoked", "fingerprint_sha256": fp}}, 1, 1))
		r := h.mustRun("", "revoke-cert.sh", "--zone", testZone, "--fingerprint", fp, "--yes", "--token-file", h.tokenFile())
		if h.curlCalls() != 1 || !strings.Contains(r.stdout, "already revoked") {
			t.Fatalf("calls %d, output %s", h.curlCalls(), r.stdout)
		}
		checkReminder(t, r.stdout, fp)
	})

	t.Run("server ignores paging", func(t *testing.T) {
		// The same full page every time, without result_info: the
		// script must notice and stop rather than loop.
		h := newHarness(t)
		h.respond("response.GET", apiResponse(t, page1))
		h.mustFail("", "revoke-cert.sh", "--zone", testZone, "--fingerprint", fp, "--yes", "--token-file", h.tokenFile())
		if n := h.curlCalls(); n != 2 {
			t.Fatalf("%d list requests, want 2", n)
		}
	})
}

func TestRevokeCertRefusesBadArguments(t *testing.T) {
	requireTools(t, "python3")
	h := newHarness(t)
	for name, args := range map[string][]string{
		"no id":               {"--zone", testZone},
		"both":                {"--zone", testZone, "--id", certID, "--fingerprint", strings.Repeat("a", 64)},
		"id with slash":       {"--zone", testZone, "--id", "../dns_records"},
		"id with query":       {"--zone", testZone, "--id", "abc?x=1"},
		"short fingerprint":   {"--zone", testZone, "--fingerprint", "abcd"},
		"lookup-only with id": {"--zone", testZone, "--id", certID, "--lookup-only"},
		"placeholder zone":    {"--zone", "<ZONE_ID>", "--id", certID},
	} {
		t.Run(name, func(t *testing.T) { h.mustFail("", "revoke-cert.sh", append(args, "--yes")...) })
	}
	if h.curlCalls() != 0 || h.securityCalled() {
		t.Fatal("a refused invocation sent a request or read the keychain")
	}
}
