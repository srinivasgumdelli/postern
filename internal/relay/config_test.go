package relay

import (
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
	cases := map[string]string{
		"not json":            `identity: header`,
		"unknown field":       `{"identity":"header","db":"x",` + peers + `,"debug":true}`,
		"trailing data":       `{"identity":"header","db":"x",` + peers + `} {}`,
		"missing identity":    `{"db":"x",` + peers + `}`,
		"bad identity":        `{"identity":"none","db":"x",` + peers + `}`,
		"missing db":          `{"identity":"header",` + peers + `}`,
		"mtls without tls":    `{"identity":"mtls","db":"x",` + peers + `}`,
		"mtls partial tls":    `{"identity":"mtls","db":"x","tls":{"cert_file":"a","key_file":"b"},` + peers + `}`,
		"header with tls":     `{"identity":"header","db":"x","tls":{"cert_file":"a","key_file":"b","client_ca_file":"c"},` + peers + `}`,
		"one peer":            `{"identity":"header","db":"x","peers":{"peer-a":["` + fpA + `"]}}`,
		"bad peer name":       `{"identity":"header","db":"x","peers":{"Peer A":["` + fpA + `"],"peer-b":["` + fpB + `"]}}`,
		"no fingerprints":     `{"identity":"header","db":"x","peers":{"peer-a":[],"peer-b":["` + fpB + `"]}}`,
		"short fingerprint":   `{"identity":"header","db":"x","peers":{"peer-a":["abcd"],"peer-b":["` + fpB + `"]}}`,
		"non-hex fingerprint": `{"identity":"header","db":"x","peers":{"peer-a":["` + strings.Repeat("z", 64) + `"],"peer-b":["` + fpB + `"]}}`,
		"placeholder":         `{"identity":"header","db":"x","peers":{"peer-a":["<PEER_A_CERT_SHA256>"],"peer-b":["` + fpB + `"]}}`,
		"shared fingerprint":  `{"identity":"header","db":"x","peers":{"peer-a":["` + fpA + `"],"peer-b":["` + strings.ToUpper(fpA) + `"]}}`,
		"repeated in peer":    `{"identity":"header","db":"x","peers":{"peer-a":["` + fpA + `","` + fpA + `"],"peer-b":["` + fpB + `"]}}`,
		"negative posts":      `{"identity":"header","db":"x","posts_per_hour":-1,` + peers + `}`,
		"negative queue":      `{"identity":"header","db":"x","max_queued_per_peer":-1,` + peers + `}`,
		"bad header name":     `{"identity":"header","db":"x","fingerprint_header":"X Bad: v",` + peers + `}`,
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
	_, err := LoadConfig(writeConfig(t, `{"identity":"header","db":"x","peers":{"peer-a":["`+bad+`"],"peer-b":["`+fpB+`"]}}`))
	if err == nil || strings.Contains(err.Error(), bad) || strings.Contains(err.Error(), fpB) {
		t.Fatalf("err = %v", err)
	}
}

// The example config must be structurally valid (strict JSON, known
// fields) yet refuse to load until its placeholders are replaced.
func TestExampleConfig(t *testing.T) {
	example, err := os.ReadFile(filepath.Join("..", "..", "deploy", "relay.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(writeConfig(t, string(example))); err == nil {
		t.Fatal("example config loads with placeholder fingerprints")
	}
	filled := strings.NewReplacer(
		"<PEER_A_CERT_SHA256>", fpA,
		"<PEER_B_CERT_SHA256>", fpB,
	).Replace(string(example))
	c, err := LoadConfig(writeConfig(t, filled))
	if err != nil {
		t.Fatalf("example config with placeholders replaced: %v", err)
	}
	if c.Identity != IdentityHeader || c.DB != "/data/relay.db" || c.Listen != ":8080" || c.TLS != nil {
		t.Fatalf("example config = %+v", c)
	}
	if len(c.Peers) != 2 || c.Peers["peer-a"] == nil || c.Peers["peer-b"] == nil {
		t.Fatalf("example peers = %v", c.Peers)
	}
}
