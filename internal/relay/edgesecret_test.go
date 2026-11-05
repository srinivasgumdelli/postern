package relay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// edgeReq builds a request with the given edge secret header values and
// optionally a fingerprint, so tests can send what a process that reached
// the relay without going through the edge would send.
func (f *fixture) edgeReq(method, path, body, peer string, secrets ...string) response {
	f.t.Helper()
	req, err := http.NewRequest(method, f.hs.URL+path, strings.NewReader(body))
	if err != nil {
		f.t.Fatal(err)
	}
	for _, s := range secrets {
		req.Header.Add(EdgeSecretHeader, s)
	}
	if peer != "" {
		req.Header.Set(DefaultFingerprintHeader, f.fp[peer])
	}
	return f.send(req)
}

func TestHeaderModeRequiresEdgeSecret(t *testing.T) {
	f := newFixture(t, nil)
	e, raw := f.newEnvelope("peer-b", "peer-a")
	f.mustPost("peer-b", raw)
	_, raw2 := f.newEnvelope("peer-a", "peer-b")

	endpoints := []struct {
		name, method, path, body string
		ok                       int
	}{
		{"post", http.MethodPost, "/v1/msg", string(raw2), http.StatusCreated},
		{"poll", http.MethodGet, "/v1/poll?to=peer-a&timeout=0", "", http.StatusOK},
		{"ack", http.MethodPost, "/v1/ack/" + e.ID, `{"to":"peer-a"}`, http.StatusOK},
	}
	wrong := newEdgeSecret(t)
	rejected := map[string][]string{
		"missing":             nil,
		"empty":               {""},
		"wrong":               {wrong},
		"wrong case":          {strings.ToUpper(f.edgeSecret)},
		"prefix":              {f.edgeSecret[:len(f.edgeSecret)-1]},
		"extended":            {f.edgeSecret + "0"},
		"two values, right":   {f.edgeSecret, f.edgeSecret},
		"two values, mixed":   {f.edgeSecret, wrong},
		"two values, flipped": {wrong, f.edgeSecret},
	}
	for _, ep := range endpoints {
		for name, secrets := range rejected {
			t.Run(ep.name+"/"+name, func(t *testing.T) {
				expectStatus(t, f.edgeReq(ep.method, ep.path, ep.body, "peer-a", secrets...), http.StatusUnauthorized, "no_identity")
			})
		}
	}
	// A comma-joined pair in one header line is one wrong value.
	expectStatus(t, f.edgeReq(http.MethodGet, "/v1/poll?to=peer-a&timeout=0", "", "peer-a", f.edgeSecret+", "+f.edgeSecret),
		http.StatusUnauthorized, "no_identity")

	// Nothing above changed state: peer-b's envelope is still queued for
	// peer-a and nothing new was stored.
	if n, _ := f.counts(); n != 1 {
		t.Fatalf("%d envelopes stored after rejected requests, want 1", n)
	}

	// The secret is checked before identity mapping: an unknown
	// fingerprint without the secret is 401, not 403.
	req, _ := http.NewRequest(http.MethodGet, f.hs.URL+"/v1/poll?to=peer-a&timeout=0", nil)
	req.Header.Set(DefaultFingerprintHeader, testFingerprint("stranger"))
	expectStatus(t, f.send(req), http.StatusUnauthorized, "no_identity")
	// With the secret, the same request reaches identity mapping.
	req, _ = http.NewRequest(http.MethodGet, f.hs.URL+"/v1/poll?to=peer-a&timeout=0", nil)
	req.Header.Set(EdgeSecretHeader, f.edgeSecret)
	req.Header.Set(DefaultFingerprintHeader, testFingerprint("stranger"))
	expectStatus(t, f.send(req), http.StatusForbidden, "forbidden")
	// The secret alone is not an identity.
	expectStatus(t, f.edgeReq(http.MethodGet, "/v1/poll?to=peer-a&timeout=0", "", "", f.edgeSecret), http.StatusUnauthorized, "no_identity")

	// Right secret plus fingerprint works on every endpoint.
	for _, ep := range endpoints {
		expectStatus(t, f.edgeReq(ep.method, ep.path, ep.body, "peer-a", f.edgeSecret), ep.ok, "")
	}
}

func TestHealthzNeedsNoEdgeSecret(t *testing.T) {
	f := newFixture(t, nil)
	for _, secrets := range [][]string{nil, {"wrong"}} {
		r := f.edgeReq(http.MethodGet, "/healthz", "", "", secrets...)
		if r.status != http.StatusOK || string(r.body) != "ok" {
			t.Fatalf("healthz = %d %q", r.status, r.body)
		}
	}
}

// TestMTLSModeIgnoresEdgeSecretHeader: in mtls mode the header is not an
// input at all, so a request without it (the mtls fixture's normal case)
// is authenticated, and a wrong one changes nothing.
func TestMTLSModeIgnoresEdgeSecretHeader(t *testing.T) {
	fx := newMTLSFixture(t)
	if fx.srv.cfg.edgeSecret != nil {
		t.Fatal("mtls server holds an edge secret")
	}
	cfg, err := fx.srv.ServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	hs := fx.start(t, cfg)
	a := fx.client(fx.peerA.TLS)
	for _, hdr := range []map[string]string{nil, {EdgeSecretHeader: "wrong"}} {
		if st, code, err := doReq(t, a, http.MethodGet, hs.URL+"/v1/poll?to=peer-a&timeout=0", nil, hdr); err != nil || st != http.StatusOK {
			t.Fatalf("mtls poll with edge secret header %v: %d %s %v", hdr, st, code, err)
		}
	}
}

// TestEdgeSecretRejectionLogsFixedEvent: a rejection logs one fixed event
// with a fixed reason, and no log line ever carries the secret, a wrong
// value, the digest, a fingerprint or either header's name.
func TestEdgeSecretRejectionLogsFixedEvent(t *testing.T) {
	f := newFixture(t, nil)
	wrong := newEdgeSecret(t)
	_, raw := f.newEnvelope("peer-a", "peer-b")
	f.mustPost("peer-a", raw)
	poll := "/v1/poll?to=peer-b&timeout=0"
	f.edgeReq(http.MethodGet, poll, "", "peer-b")
	f.edgeReq(http.MethodGet, poll, "", "peer-b", wrong)
	f.edgeReq(http.MethodGet, poll, "", "peer-b", f.edgeSecret, wrong)
	f.edgeReq(http.MethodGet, poll, "", "peer-b", f.edgeSecret)
	f.edgeReq(http.MethodGet, "/healthz", "", "", f.edgeSecret)

	logs := f.logs.String()
	digest := sha256.Sum256([]byte(f.edgeSecret))
	mustNotContain(t, "logs", logs,
		f.edgeSecret, f.edgeSecret[:16], wrong, wrong[:16],
		hex.EncodeToString(digest[:]), hex.EncodeToString(digest[:8]),
		f.fp["peer-a"], f.fp["peer-b"],
		EdgeSecretHeader, strings.ToLower(EdgeSecretHeader),
		DefaultFingerprintHeader, strings.ToLower(DefaultFingerprintHeader),
	)

	var reasons []string
	for _, l := range strings.Split(strings.TrimSpace(logs), "\n") {
		var ln map[string]any
		if err := json.Unmarshal([]byte(l), &ln); err != nil {
			t.Fatalf("log line is not JSON: %v", err)
		}
		if ln["msg"] != "edge secret rejected" {
			continue
		}
		for k := range ln {
			if k != "time" && k != "level" && k != "msg" && k != "reason" {
				t.Errorf("edge secret event has unexpected field %q", k)
			}
		}
		reasons = append(reasons, ln["reason"].(string))
	}
	if strings.Join(reasons, ",") != "missing,mismatch,multiple" {
		t.Fatalf("rejection reasons = %v", reasons)
	}
}

// TestHandlersDoNotSeeIdentityHeaders: once authenticate has read them,
// both identity headers are gone from the request, so no handler or
// later log statement can record them.
func TestHandlersDoNotSeeIdentityHeaders(t *testing.T) {
	f := newFixture(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/poll?to=peer-a&timeout=0", nil)
	req.Header.Set(EdgeSecretHeader, f.edgeSecret)
	req.Header.Set(DefaultFingerprintHeader, f.fp["peer-a"])
	if peer, ok := f.srv.authenticate(httptest.NewRecorder(), req); !ok || peer != "peer-a" {
		t.Fatalf("authenticate = %q %v", peer, ok)
	}
	if req.Header.Get(EdgeSecretHeader) != "" || req.Header.Get(DefaultFingerprintHeader) != "" {
		t.Fatal("identity headers still on the request after authenticate")
	}
}

// TestEdgeSecretUsesConstantTimeCompare inspects the source: the edge
// secret check must go through crypto/subtle, never ==, bytes.Equal or
// strings.Compare.
func TestEdgeSecretUsesConstantTimeCompare(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "server.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fn *ast.FuncDecl
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "edgeSecretOK" {
			fn = fd
		}
	}
	if fn == nil {
		t.Fatal("edgeSecretOK not found in server.go")
	}
	constantTime := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok {
					switch pkg.Name + "." + sel.Sel.Name {
					case "subtle.ConstantTimeCompare":
						constantTime = true
					case "bytes.Equal", "bytes.Compare", "strings.Compare", "strings.EqualFold", "bytes.EqualFold", "reflect.DeepEqual", "slices.Equal":
						t.Errorf("%s: edge secret compared with %s.%s", fset.Position(n.Pos()), pkg.Name, sel.Sel.Name)
					}
				}
			}
		case *ast.BinaryExpr:
			// A nil check, or comparing ConstantTimeCompare's int result,
			// is not comparing the secret.
			if (n.Op == token.EQL || n.Op == token.NEQ) && !isNil(n.X) && !isNil(n.Y) {
				for _, side := range []ast.Expr{n.X, n.Y} {
					if _, call := side.(*ast.CallExpr); !call && mentionsSecret(side) {
						t.Errorf("%s: edge secret compared with %s", fset.Position(n.Pos()), n.Op)
					}
				}
			}
		}
		return true
	})
	if !constantTime {
		t.Fatal("edgeSecretOK does not use subtle.ConstantTimeCompare")
	}
	// And the server must actually route header-mode requests through it.
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		if fd, ok := n.(*ast.FuncDecl); ok && fd.Name.Name == "authenticate" {
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "edgeSecretOK" {
					found = true
				}
				return true
			})
		}
		return true
	})
	if !found {
		t.Fatal("authenticate does not call edgeSecretOK")
	}
}

func isNil(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "nil"
}

func mentionsSecret(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.Ident:
			if n.Name == "digest" || n.Name == "got" || n.Name == "edgeSecret" {
				found = true
			}
		case *ast.IndexExpr:
			if id, ok := n.X.(*ast.Ident); ok && id.Name == "vals" {
				found = true
			}
		}
		return true
	})
	return found
}
