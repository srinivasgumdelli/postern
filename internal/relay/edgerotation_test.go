package relay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// rotationFixture is a header-mode relay with a next edge secret
// configured, as between the two restarts of an edge secret rotation.
func rotationFixture(t *testing.T) (*fixture, string) {
	t.Helper()
	next := newEdgeSecret(t)
	f := newFixture(t, func(c *Config) { c.EdgeSecretNextFile = writeEdgeSecret(t, next+"\n") })
	if f.srv.cfg.edgeSecretNext == nil {
		t.Fatal("next edge secret not loaded")
	}
	return f, next
}

// accessSlots returns the edge_secret_slot of every access log line, in
// order ("" when the line has none).
func accessSlots(t *testing.T, logs string) []string {
	t.Helper()
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(logs), "\n") {
		var ln map[string]any
		if err := json.Unmarshal([]byte(l), &ln); err != nil {
			t.Fatalf("log line is not JSON: %v", err)
		}
		if ln["msg"] != "request" {
			continue
		}
		v, present := ln["edge_secret_slot"]
		s, _ := v.(string)
		if present && s == "" {
			t.Fatalf("edge_secret_slot is %v", v)
		}
		out = append(out, s)
	}
	return out
}

// TestEdgeSecretRotationAcceptsEither: with a next secret configured, a
// request carrying either secret passes and anything else is refused,
// exactly as with one secret.
func TestEdgeSecretRotationAcceptsEither(t *testing.T) {
	f, next := rotationFixture(t)
	poll := "/v1/poll?to=peer-a&timeout=0"
	expectStatus(t, f.edgeReq(http.MethodGet, poll, "", "peer-a", f.edgeSecret), http.StatusOK, "")
	expectStatus(t, f.edgeReq(http.MethodGet, poll, "", "peer-a", next), http.StatusOK, "")

	wrong := newEdgeSecret(t)
	for name, secrets := range map[string][]string{
		"missing":              nil,
		"empty":                {""},
		"neither":              {wrong},
		"next prefix":          {next[:len(next)-1]},
		"next extended":        {next + "0"},
		"next wrong case":      {strings.ToUpper(next)},
		"current and next":     {f.edgeSecret, next},
		"next twice":           {next, next},
		"next and wrong":       {next, wrong},
		"joined in one header": {f.edgeSecret + ", " + next},
	} {
		t.Run(name, func(t *testing.T) {
			expectStatus(t, f.edgeReq(http.MethodGet, poll, "", "peer-a", secrets...), http.StatusUnauthorized, "no_identity")
		})
	}
	// The next secret is still only the edge's mark, not an identity.
	expectStatus(t, f.edgeReq(http.MethodGet, poll, "", "", next), http.StatusUnauthorized, "no_identity")

	// Every endpoint accepts the next secret.
	e, raw := f.newEnvelope("peer-b", "peer-a")
	expectStatus(t, f.edgeReq(http.MethodPost, "/v1/msg", string(raw), "peer-b", next), http.StatusCreated, "")
	expectStatus(t, f.edgeReq(http.MethodPost, "/v1/ack/"+e.ID, `{"to":"peer-a"}`, "peer-a", next), http.StatusOK, "")
}

// TestEdgeSecretWithoutNextRefusesOtherValues: without a next secret,
// only the current one passes. A value meant as the next secret does
// not, until the relay is restarted with it.
func TestEdgeSecretWithoutNextRefusesOtherValues(t *testing.T) {
	f := newFixture(t, nil)
	if f.srv.cfg.edgeSecretNext != nil {
		t.Fatal("next edge secret loaded without edge_secret_next_file")
	}
	poll := "/v1/poll?to=peer-a&timeout=0"
	expectStatus(t, f.edgeReq(http.MethodGet, poll, "", "peer-a", newEdgeSecret(t)), http.StatusUnauthorized, "no_identity")
	expectStatus(t, f.edgeReq(http.MethodGet, poll, "", "peer-a", f.edgeSecret), http.StatusOK, "")
	if got := strings.Join(accessSlots(t, f.logs.String()), ","); got != ",current" {
		t.Fatalf("edge_secret_slot per request = %q, want \",current\"", got)
	}
}

// TestEdgeSecretSlotLogged: the access log names the slot that matched,
// only as the fixed word "current" or "next", and never carries either
// value, a digest or part of one.
func TestEdgeSecretSlotLogged(t *testing.T) {
	f, next := rotationFixture(t)
	poll := "/v1/poll?to=peer-a&timeout=0"
	f.edgeReq(http.MethodGet, poll, "", "peer-a", f.edgeSecret)
	f.edgeReq(http.MethodGet, poll, "", "peer-a", next)
	f.edgeReq(http.MethodGet, poll, "", "peer-a", newEdgeSecret(t))
	req, _ := http.NewRequest(http.MethodGet, f.hs.URL+poll, nil)
	req.Header.Set(EdgeSecretHeader, next)
	req.Header.Set(DefaultFingerprintHeader, testFingerprint("stranger"))
	expectStatus(t, f.send(req), http.StatusForbidden, "forbidden")
	f.edgeReq(http.MethodGet, "/healthz", "", "", next)

	logs := f.logs.String()
	want := []string{"current", "next", "", "next", ""}
	if got := accessSlots(t, logs); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("edge_secret_slot per request = %q, want %q\n%s", got, want, logs)
	}
	var needles []string
	for _, s := range []string{f.edgeSecret, next} {
		d := sha256.Sum256([]byte(s))
		needles = append(needles, s, s[:16], s[len(s)-16:], hex.EncodeToString(d[:]), hex.EncodeToString(d[:8]))
	}
	mustNotContain(t, "logs", logs, needles...)
	mustNotContain(t, "logs", logs, EdgeSecretHeader, strings.ToLower(EdgeSecretHeader))
}

func headerConfigWithSecrets(t *testing.T, current, next string) string {
	t.Helper()
	return writeConfig(t, `{"identity":"header","db":"x","edge_secret_file":`+jsonString(t, current)+
		`,"edge_secret_next_file":`+jsonString(t, next)+`,
		"peers":{"peer-a":["`+fpA+`"],"peer-b":["`+fpB+`"]}}`)
}

func TestEdgeSecretNextLoading(t *testing.T) {
	cur, next := newEdgeSecret(t), newEdgeSecret(t)
	c, err := LoadConfig(headerConfigWithSecrets(t, writeEdgeSecret(t, cur+"\n"), writeEdgeSecret(t, next+"\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	if c.edgeSecret == nil || c.edgeSecret.digest != sha256.Sum256([]byte(cur)) {
		t.Fatal("current edge secret differs from its file")
	}
	if c.edgeSecretNext == nil || c.edgeSecretNext.digest != sha256.Sum256([]byte(next)) {
		t.Fatal("next edge secret differs from its file")
	}
	if got := c.EdgeSecretSlots(); got != 2 {
		t.Fatalf("EdgeSecretSlots = %d, want 2", got)
	}
	// New keeps both from an already loaded Config.
	st, err := OpenStore(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv, err := New(c, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	if srv.cfg.edgeSecretNext != c.edgeSecretNext {
		t.Fatal("New dropped or reloaded the next edge secret")
	}
	one, err := LoadConfig(headerConfigWithSecretFile(t, writeEdgeSecret(t, cur)))
	if err != nil {
		t.Fatal(err)
	}
	if one.edgeSecretNext != nil || one.EdgeSecretSlots() != 1 {
		t.Fatalf("EdgeSecretSlots = %d, want 1", one.EdgeSecretSlots())
	}
}

// TestEdgeSecretNextRejects: the next file gets the checks the current
// one gets, errors name the next field and never its content, and the
// two must hold different values.
func TestEdgeSecretNextRejects(t *testing.T) {
	cur := newEdgeSecret(t)
	curFile := writeEdgeSecret(t, cur+"\n")
	other := newEdgeSecret(t)
	cases := map[string]string{
		"empty file":        "",
		"only newline":      "\n",
		"short":             other[:MinEdgeSecretBytes-1] + "\n",
		"inner space":       other[:32] + " " + other[32:],
		"non-ascii":         other + "é",
		"angle placeholder": "<EDGE_SECRET_NEXT_FROM_OPENSSL_RAND_HEX_32>",
		"template":          "${EDGE_SECRET_NEXT}" + other,
		"changeme":          "changeme-changeme-changeme-changeme",
		"word secret":       "my-postern-edge-secret-for-the-relay-2027",
		"all zeros":         strings.Repeat("0", 64),
		"too large":         strings.Repeat(other, 100),
		"same as current":   cur + "\n",
		"same, CRLF":        cur + "\r\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadConfig(headerConfigWithSecrets(t, curFile, writeEdgeSecret(t, content)))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), "edge_secret_next_file") {
				t.Fatalf("error does not name edge_secret_next_file: %v", err)
			}
			if v := strings.TrimSpace(content); len(v) >= 8 && strings.Contains(err.Error(), v[:8]) {
				t.Fatalf("error echoes the secret file's content: %v", err)
			}
		})
	}
	for name, path := range map[string]string{"missing file": filepath.Join(t.TempDir(), "nope"), "directory": t.TempDir()} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadConfig(headerConfigWithSecrets(t, curFile, path)); err == nil || !strings.Contains(err.Error(), "edge_secret_next_file") {
				t.Fatalf("err = %v", err)
			}
		})
	}
	// A next secret does not stand in for a missing current one.
	t.Run("next without current", func(t *testing.T) {
		p := writeConfig(t, `{"identity":"header","db":"x","edge_secret_next_file":`+jsonString(t, writeEdgeSecret(t, other))+`,
			"peers":{"peer-a":["`+fpA+`"],"peer-b":["`+fpB+`"]}}`)
		if _, err := LoadConfig(p); err == nil || !strings.Contains(err.Error(), "needs edge_secret_file") {
			t.Fatalf("err = %v", err)
		}
	})
	// The current file keeps its own checks, and its errors name it.
	t.Run("bad current, good next", func(t *testing.T) {
		_, err := LoadConfig(headerConfigWithSecrets(t, writeEdgeSecret(t, "short"), writeEdgeSecret(t, other)))
		if err == nil || !strings.Contains(err.Error(), "edge_secret_file") || strings.Contains(err.Error(), "edge_secret_next_file") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestMTLSIgnoresEdgeSecretNext(t *testing.T) {
	c, err := LoadConfig(writeConfig(t, `{"identity":"mtls","db":"x","edge_secret_next_file":`+jsonString(t, writeEdgeSecret(t, "<EDGE_SECRET>"))+`,
		"tls":{"cert_file":"s.pem","key_file":"s.key","client_ca_file":"ca.pem"},
		"peers":{"peer-a":["`+fpA+`"],"peer-b":["`+fpB+`"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.edgeSecret != nil || c.edgeSecretNext != nil || c.EdgeSecretSlots() != 0 {
		t.Fatal("edge secret loaded in mtls mode")
	}
}

func TestConfigFormattingHidesEdgeSecretNext(t *testing.T) {
	cur, next := newEdgeSecret(t), newEdgeSecret(t)
	c, err := LoadConfig(headerConfigWithSecrets(t, writeEdgeSecret(t, cur), writeEdgeSecret(t, next)))
	if err != nil {
		t.Fatal(err)
	}
	j, _ := json.Marshal(c)
	for _, out := range []string{
		fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c),
		fmt.Sprint(c.edgeSecretNext), fmt.Sprintf("%#v", c.edgeSecretNext), string(j),
	} {
		for _, s := range []string{cur, next} {
			d := sha256.Sum256([]byte(s))
			mustNotContain(t, "formatted config", out, s, hex.EncodeToString(d[:]), string(d[:8]))
		}
	}
}
