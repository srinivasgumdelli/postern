package relay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "relay.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// jsonString quotes s as a JSON string (paths may hold any character).
func jsonString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// secretField returns `"edge_secret_file":"<path>",` for a fresh file
// holding a valid edge secret.
func secretField(t *testing.T) string {
	t.Helper()
	return `"edge_secret_file":` + jsonString(t, writeEdgeSecret(t, newEdgeSecret(t)+"\n")) + `,`
}

var (
	fpA = testFingerprint("peer-a")
	fpB = testFingerprint("peer-b")
	fpC = testFingerprint("peer-b-next")
)

func TestLoadConfigValid(t *testing.T) {
	upper := strings.ToUpper(fpA)
	var colon []string
	for i := 0; i < len(upper); i += 2 {
		colon = append(colon, upper[i:i+2])
	}
	p := writeConfig(t, `{
		"identity": "header",
		"db": "/data/relay.db",
		`+secretField(t)+`
		"peers": {
			"peer-a": ["`+strings.Join(colon, ":")+`"],
			"peer-b": ["`+fpB+`", "`+fpC+`"]
		}
	}`)
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8080" || c.FingerprintHeader != "X-Postern-Client-Cert-Sha256" ||
		c.PostsPerHour != 120 || c.MaxQueuedPerPeer != 1000 {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if c.Peers["peer-a"][0] != fpA {
		t.Fatalf("fingerprint not normalized: %q", c.Peers["peer-a"][0])
	}
	if len(c.Peers["peer-b"]) != 2 {
		t.Fatal("rotation overlap fingerprints lost")
	}
	if c.edgeSecret == nil {
		t.Fatal("edge secret not loaded in header mode")
	}

	p = writeConfig(t, `{"listen":":9443","identity":"mtls","db":"relay.db",
		"tls":{"cert_file":"s.pem","key_file":"s.key","client_ca_file":"ca.pem"},
		"fingerprint_header":"X-Other","posts_per_hour":5,"max_queued_per_peer":7,
		"peers":{"peer-a":["`+fpA+`"],"peer-b":["`+fpB+`"]}}`)
	c, err = LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":9443" || c.Identity != IdentityMTLS || c.TLS.ClientCAFile != "ca.pem" ||
		c.PostsPerHour != 5 || c.MaxQueuedPerPeer != 7 || c.FingerprintHeader != "X-Other" {
		t.Fatalf("explicit values lost: %+v", c)
	}
}

func TestLoadConfigRejects(t *testing.T) {
	peers := `"peers":{"peer-a":["` + fpA + `"],"peer-b":["` + fpB + `"]}`
	// Every header-mode case carries a valid edge secret, so each one is
	// rejected for the reason its name gives.
	h := `{"identity":"header",` + secretField(t)
	cases := map[string]string{
		"not json":            `identity: header`,
		"unknown field":       h + `"db":"x",` + peers + `,"debug":true}`,
		"trailing data":       h + `"db":"x",` + peers + `} {}`,
		"missing identity":    `{"db":"x",` + secretField(t) + peers + `}`,
		"bad identity":        `{"identity":"none","db":"x",` + secretField(t) + peers + `}`,
		"missing db":          h + peers + `}`,
		"mtls without tls":    `{"identity":"mtls","db":"x",` + peers + `}`,
		"mtls partial tls":    `{"identity":"mtls","db":"x","tls":{"cert_file":"a","key_file":"b"},` + peers + `}`,
		"header with tls":     h + `"db":"x","tls":{"cert_file":"a","key_file":"b","client_ca_file":"c"},` + peers + `}`,
		"one peer":            h + `"db":"x","peers":{"peer-a":["` + fpA + `"]}}`,
		"bad peer name":       h + `"db":"x","peers":{"Peer A":["` + fpA + `"],"peer-b":["` + fpB + `"]}}`,
		"no fingerprints":     h + `"db":"x","peers":{"peer-a":[],"peer-b":["` + fpB + `"]}}`,
		"short fingerprint":   h + `"db":"x","peers":{"peer-a":["abcd"],"peer-b":["` + fpB + `"]}}`,
		"non-hex fingerprint": h + `"db":"x","peers":{"peer-a":["` + strings.Repeat("z", 64) + `"],"peer-b":["` + fpB + `"]}}`,
		"placeholder":         h + `"db":"x","peers":{"peer-a":["<PEER_A_CERT_SHA256>"],"peer-b":["` + fpB + `"]}}`,
		"shared fingerprint":  h + `"db":"x","peers":{"peer-a":["` + fpA + `"],"peer-b":["` + strings.ToUpper(fpA) + `"]}}`,
		"repeated in peer":    h + `"db":"x","peers":{"peer-a":["` + fpA + `","` + fpA + `"],"peer-b":["` + fpB + `"]}}`,
		"negative posts":      h + `"db":"x","posts_per_hour":-1,` + peers + `}`,
		"negative queue":      h + `"db":"x","max_queued_per_peer":-1,` + peers + `}`,
		"bad header name":     h + `"db":"x","fingerprint_header":"X Bad: v",` + peers + `}`,
		"header no secret":    `{"identity":"header","db":"x",` + peers + `}`,
		"header empty secret": `{"identity":"header","db":"x","edge_secret_file":"",` + peers + `}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadConfig(writeConfig(t, body)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("accepted a missing file")
	}
}

func TestLoadConfigErrorsDoNotEchoFingerprints(t *testing.T) {
	bad := strings.Repeat("9", 63) + "x"
	_, err := LoadConfig(writeConfig(t, `{"identity":"header","db":"x",`+secretField(t)+`"peers":{"peer-a":["`+bad+`"],"peer-b":["`+fpB+`"]}}`))
	if err == nil || strings.Contains(err.Error(), bad) || strings.Contains(err.Error(), fpB) {
		t.Fatalf("err = %v", err)
	}
}

func headerConfigWithSecretFile(t *testing.T, path string) string {
	t.Helper()
	return writeConfig(t, `{"identity":"header","db":"x","edge_secret_file":`+jsonString(t, path)+`,
		"peers":{"peer-a":["`+fpA+`"],"peer-b":["`+fpB+`"]}}`)
}

func TestEdgeSecretLoading(t *testing.T) {
	secret := newEdgeSecret(t)
	want := sha256.Sum256([]byte(secret))
	// One trailing newline (LF or CRLF) is trimmed; nothing else is.
	for name, content := range map[string]string{
		"no newline": secret,
		"LF":         secret + "\n",
		"CRLF":       secret + "\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			c, err := LoadConfig(headerConfigWithSecretFile(t, writeEdgeSecret(t, content)))
			if err != nil {
				t.Fatal(err)
			}
			if c.edgeSecret == nil || c.edgeSecret.digest != want {
				t.Fatal("loaded edge secret differs from the file's content")
			}
		})
	}
	// Exactly the minimum length is enough.
	if _, err := LoadConfig(headerConfigWithSecretFile(t, writeEdgeSecret(t, secret[:MinEdgeSecretBytes]))); err != nil {
		t.Fatalf("minimum-length secret: %v", err)
	}
}

func TestEdgeSecretRejects(t *testing.T) {
	secret := newEdgeSecret(t)
	cases := map[string]string{
		"empty file":         "",
		"only newline":       "\n",
		"short":              secret[:MinEdgeSecretBytes-1] + "\n",
		"short with padding": secret[:MinEdgeSecretBytes-2] + "\n\n\n",
		"inner space":        secret[:32] + " " + secret[32:],
		"inner newline":      secret[:32] + "\n" + secret[32:],
		"leading space":      " " + secret,
		"tab":                secret + "\t",
		"non-ascii":          secret + "é",
		"angle placeholder":  "<EDGE_SECRET_GENERATED_WITH_OPENSSL_RAND_HEX_32>",
		"template":           "${EDGE_SECRET}" + secret,
		"braces":             "{{edge_secret}}" + secret,
		"changeme":           "changeme-changeme-changeme-changeme",
		"replace me":         "REPLACE_ME_WITH_A_RANDOM_VALUE_0123456789",
		"word secret":        "my-postern-edge-secret-for-the-relay-2026",
		"example":            "example-0123456789abcdef0123456789abcdef",
		"placeholder word":   "PLACEHOLDER0123456789abcdef0123456789abcdef",
		"xxxx":               "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0123456789",
		"all zeros":          strings.Repeat("0", 64),
		"low variety":        strings.Repeat("ab12", 16),
		"too large":          strings.Repeat(secret, 100),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadConfig(headerConfigWithSecretFile(t, writeEdgeSecret(t, content)))
			if err == nil {
				t.Fatal("accepted")
			}
			if v := strings.TrimSpace(content); len(v) >= 8 && strings.Contains(err.Error(), v[:8]) {
				t.Fatalf("error echoes the secret file's content: %v", err)
			}
		})
	}
	t.Run("missing file", func(t *testing.T) {
		if _, err := LoadConfig(headerConfigWithSecretFile(t, filepath.Join(t.TempDir(), "nope"))); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("directory", func(t *testing.T) {
		if _, err := LoadConfig(headerConfigWithSecretFile(t, t.TempDir())); err == nil {
			t.Fatal("accepted")
		}
	})
}

func TestMTLSIgnoresEdgeSecret(t *testing.T) {
	// A missing or bad edge secret file does not matter in mtls mode: it
	// is not read at all.
	for name, path := range map[string]string{
		"missing file": filepath.Join(t.TempDir(), "nope"),
		"placeholder":  writeEdgeSecret(t, "<EDGE_SECRET>"),
	} {
		t.Run(name, func(t *testing.T) {
			c, err := LoadConfig(writeConfig(t, `{"identity":"mtls","db":"x","edge_secret_file":`+jsonString(t, path)+`,
				"tls":{"cert_file":"s.pem","key_file":"s.key","client_ca_file":"ca.pem"},
				"peers":{"peer-a":["`+fpA+`"],"peer-b":["`+fpB+`"]}}`))
			if err != nil {
				t.Fatal(err)
			}
			if c.edgeSecret != nil {
				t.Fatal("edge secret loaded in mtls mode")
			}
		})
	}
}

// Printing a Config (as a test failure or a careless log line would) must
// not reveal the edge secret or its digest.
func TestConfigFormattingHidesEdgeSecret(t *testing.T) {
	secret := newEdgeSecret(t)
	c, err := LoadConfig(headerConfigWithSecretFile(t, writeEdgeSecret(t, secret)))
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256([]byte(secret))
	digestHex := hex.EncodeToString(d[:])
	j, _ := json.Marshal(c)
	for _, out := range []string{
		fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), fmt.Sprint(c.edgeSecret),
		fmt.Sprintf("%#v", c.edgeSecret), string(j),
	} {
		mustNotContain(t, "formatted config", out, secret, digestHex, string(d[:8]))
	}
}

// The example config must be structurally valid (strict JSON, known
// fields) yet refuse to load until its placeholders are replaced.
func TestExampleConfig(t *testing.T) {
	example, err := os.ReadFile(filepath.Join("..", "..", "deploy", "relay.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	secretFile := writeEdgeSecret(t, newEdgeSecret(t)+"\n")
	withSecret := strings.ReplaceAll(string(example), `"/run/secrets/edge_secret"`, jsonString(t, secretFile))
	if withSecret == string(example) {
		t.Fatal("example config does not read the edge secret from /run/secrets/edge_secret")
	}
	if _, err := LoadConfig(writeConfig(t, withSecret)); err == nil {
		t.Fatal("example config loads with placeholder fingerprints")
	}
	filled := strings.NewReplacer(
		"<PEER_A_CERT_SHA256>", fpA,
		"<PEER_B_CERT_SHA256>", fpB,
	).Replace(withSecret)
	c, err := LoadConfig(writeConfig(t, filled))
	if err != nil {
		t.Fatalf("example config with placeholders replaced: %v", err)
	}
	if c.Identity != IdentityHeader || c.DB != "/data/relay.db" || c.Listen != ":8080" || c.TLS != nil || c.edgeSecret == nil {
		t.Fatalf("example config = %+v", c)
	}
	if len(c.Peers) != 2 || c.Peers["peer-a"] == nil || c.Peers["peer-b"] == nil {
		t.Fatalf("example peers = %v", c.Peers)
	}
}
