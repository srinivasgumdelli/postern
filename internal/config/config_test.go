package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"postern/internal/envelope"
	"postern/internal/secrets"
	"postern/internal/secrets/secretstest"
)

func testPeer(t *testing.T, name string) PeerConfig {
	t.Helper()
	pub, _, err := envelope.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return PeerConfig{Name: name, PublicKey: envelope.EncodeKey(pub), Fingerprint: envelope.Fingerprint(pub)}
}

func validConfig(t *testing.T) *Config {
	t.Helper()
	return &Config{
		PeerName:        "peer-a",
		RelayURL:        "https://postern.example.com",
		KeychainService: "postern",
		Sessions:        []string{"builder", "reviewer"},
		Peers:           []PeerConfig{testPeer(t, "peer-b")},
	}
}

func TestValidateAcceptsValid(t *testing.T) {
	c := validConfig(t)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.KeychainService = ""
	c.Sessions = nil
	c.Peers = nil
	c.RelayURL = "https://postern.example.com:8443/base/"
	c.RelayCAFile = "/etc/postern/relay-ca.pem"
	c.DataDir = "/var/lib/postern"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.KeychainService != DefaultKeychainService {
		t.Fatalf("keychain service default: %q", c.KeychainService)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(c *Config){
		"empty peer name":        func(c *Config) { c.PeerName = "" },
		"upper-case peer name":   func(c *Config) { c.PeerName = "Peer-A" },
		"long peer name":         func(c *Config) { c.PeerName = strings.Repeat("a", 33) },
		"empty relay url":        func(c *Config) { c.RelayURL = "" },
		"http relay":             func(c *Config) { c.RelayURL = "http://postern.example.com" },
		"ws relay":               func(c *Config) { c.RelayURL = "wss://postern.example.com" },
		"relay without host":     func(c *Config) { c.RelayURL = "https:///v1" },
		"relay port only":        func(c *Config) { c.RelayURL = "https://:443" },
		"relay opaque":           func(c *Config) { c.RelayURL = "https:postern.example.com" },
		"relay userinfo":         func(c *Config) { c.RelayURL = "https://user:" + "pw@postern.example.com" },
		"relay user only":        func(c *Config) { c.RelayURL = "https://user@postern.example.com" },
		"relay query":            func(c *Config) { c.RelayURL = "https://postern.example.com/?x=1" },
		"relay empty query":      func(c *Config) { c.RelayURL = "https://postern.example.com/?" },
		"relay fragment":         func(c *Config) { c.RelayURL = "https://postern.example.com/#f" },
		"relay empty fragment":   func(c *Config) { c.RelayURL = "https://postern.example.com/#" },
		"relay unparsable":       func(c *Config) { c.RelayURL = "https://post ern.example.com" },
		"relative ca file":       func(c *Config) { c.RelayCAFile = "ca.pem" },
		"bad keychain service":   func(c *Config) { c.KeychainService = "Postern" },
		"keychain service slash": func(c *Config) { c.KeychainService = "a/b" },
		"keychain service too long": func(c *Config) {
			c.KeychainService = strings.Repeat("a", 65)
		},
		"relative data dir":     func(c *Config) { c.DataDir = "data" },
		"bad session name":      func(c *Config) { c.Sessions = []string{"Builder"} },
		"session with space":    func(c *Config) { c.Sessions = []string{"a b"} },
		"empty session name":    func(c *Config) { c.Sessions = []string{""} },
		"duplicate session":     func(c *Config) { c.Sessions = []string{"builder", "builder"} },
		"bad peer name":         func(c *Config) { c.Peers[0].Name = "peer_b" },
		"self as peer":          func(c *Config) { c.Peers[0].Name = c.PeerName },
		"duplicate peer":        func(c *Config) { c.Peers = append(c.Peers, c.Peers[0]) },
		"peer key not base64":   func(c *Config) { c.Peers[0].PublicKey = "not base64!" },
		"peer key short":        func(c *Config) { c.Peers[0].PublicKey = "AAAA" },
		"peer key empty":        func(c *Config) { c.Peers[0].PublicKey = "" },
		"negative session rate": func(c *Config) { c.Limits.SessionPerHour = -1 },
		"negative global rate":  func(c *Config) { c.Limits.GlobalPerHour = -1 },
		"negative thread max":   func(c *Config) { c.Limits.ThreadMax = -1 },
		"negative burst":        func(c *Config) { c.Limits.ThreadBurst = -1 },
		"negative burst window": func(c *Config) { c.Limits.ThreadBurstWindowMinutes = -1 },
		"fingerprint of another key": func(c *Config) {
			c.Peers[0].Fingerprint = testPeer(t, "x").Fingerprint
		},
		"fingerprint typo": func(c *Config) {
			fp := []byte(c.Peers[0].Fingerprint)
			if fp[0] == '0' {
				fp[0] = '1'
			} else {
				fp[0] = '0'
			}
			c.Peers[0].Fingerprint = string(fp)
		},
		"fingerprint upper case": func(c *Config) {
			c.Peers[0].Fingerprint = strings.ToUpper(c.Peers[0].Fingerprint) + "X"
		},
		"fingerprint without spaces": func(c *Config) {
			c.Peers[0].Fingerprint = strings.ReplaceAll(c.Peers[0].Fingerprint, " ", "")
		},
		"fingerprint empty": func(c *Config) { c.Peers[0].Fingerprint = "" },
		"swapped peer key": func(c *Config) {
			// Key replaced, fingerprint left as the human verified it.
			c.Peers[0].PublicKey = testPeer(t, "x").PublicKey
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := validConfig(t)
			mutate(c)
			err := c.Validate()
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
}

func TestValidateErrorsDoNotEchoValues(t *testing.T) {
	c := validConfig(t)
	pw := "hunter" + "2"
	c.RelayURL = "http://user:" + pw + "@postern.example.com"
	err := c.Validate()
	if err == nil || strings.Contains(err.Error(), pw) {
		t.Fatalf("error echoes value: %v", err)
	}
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // defeat umask
		t.Fatal(err)
	}
}

func mustJSON(t *testing.T, c *Config) string {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestLoadStrictJSON(t *testing.T) {
	dir := t.TempDir()
	two := validConfig(t)
	two.Peers = append(two.Peers, testPeer(t, "peer-c")) // same keys in sibling objects are fine
	good := mustJSON(t, two)
	cases := map[string]string{
		"unknown field":     strings.Replace(good, `"peer_name"`, `"extra":1,"peer_name"`, 1),
		"unknown nested":    strings.Replace(good, `"session_per_hour"`, `"burst":1,"session_per_hour"`, 1),
		"trailing data":     good + `{}`,
		"trailing garbage":  good + `x`,
		"duplicate key":     strings.Replace(good, `"peer_name":"peer-a"`, `"peer_name":"peer-a","peer_name":"peer-c"`, 1),
		"case-folded key":   strings.Replace(good, `"relay_url"`, `"Relay_URL"`, 1),
		"duplicate by case": strings.Replace(good, `"peer_name":"peer-a"`, `"peer_name":"peer-a","PEER_NAME":"peer-c"`, 1),
		"not an object":     `[]`,
		"empty":             ``,
		"truncated":         good[:len(good)/2],
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
			writeFile(t, p, content, 0o600)
			if _, _, err := Load(p); err == nil {
				t.Fatal("Load accepted it")
			}
		})
	}

	p := filepath.Join(dir, "good.json")
	writeFile(t, p, good+"\n", 0o600)
	if _, _, err := Load(p); err != nil {
		t.Fatalf("good config with trailing newline: %v", err)
	}
}

func TestLoadRefusesWritableByOthers(t *testing.T) {
	dir := t.TempDir()
	good := mustJSON(t, validConfig(t))
	for _, mode := range []os.FileMode{0o666, 0o620, 0o602, 0o660} {
		p := filepath.Join(dir, "config.json")
		writeFile(t, p, good, mode)
		if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), "writable") {
			t.Errorf("mode %04o: got %v", mode, err)
		}
	}
	p := filepath.Join(dir, "config.json")
	writeFile(t, p, good, 0o644)
	if _, _, err := Load(p); err != nil {
		t.Errorf("mode 0644 should load: %v", err)
	}
}

func TestLoadRefusesNonRegular(t *testing.T) {
	if _, _, err := Load(t.TempDir()); err == nil {
		t.Fatal("Load accepted a directory")
	}
	if _, _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("Load accepted a missing file")
	}
}

func TestSaveModesAndRoundTrip(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "postern")
	path := filepath.Join(dir, "config.json")
	c := validConfig(t)
	c.KeychainService = ""
	c.Limits.ThreadMax = 7

	raw, err := Save(path, c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(raw), "}\n") {
		t.Fatal("saved file lacks trailing newline")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %04o, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %04o, want 0700", di.Mode().Perm())
	}
	onDisk, _ := os.ReadFile(path)
	if string(onDisk) != string(raw) {
		t.Fatal("Save returned bytes that differ from the file")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("temp files left behind: %d entries", len(entries))
	}

	got, gotRaw, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotRaw) != string(raw) {
		t.Fatal("Load raw bytes differ from Save")
	}
	if got.PeerName != c.PeerName || got.RelayURL != c.RelayURL ||
		got.KeychainService != DefaultKeychainService || got.Limits.ThreadMax != 7 ||
		len(got.Sessions) != 2 || len(got.Peers) != 1 || got.Peers[0] != c.Peers[0] {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if got.Path() != path {
		t.Fatalf("Path() = %q", got.Path())
	}
	if want := filepath.Join(dir, "inbox.db"); got.DBPath() != want {
		t.Fatalf("DBPath() = %q, want %q", got.DBPath(), want)
	}

	// Overwrite keeps 0600 and replaces content.
	got.Sessions = append(got.Sessions, "third")
	if _, err := Save(path, got); err != nil {
		t.Fatal(err)
	}
	again, _, err := Load(path)
	if err != nil || !again.HasSession("third") {
		t.Fatalf("overwrite: %v", err)
	}
}

func TestSaveRejectsInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c := validConfig(t)
	c.RelayURL = "http://postern.example.com"
	if _, err := Save(path, c); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("invalid config was written")
	}
}

func TestPinRoundTrip(t *testing.T) {
	st := secretstest.NewMemory()
	path := filepath.Join(t.TempDir(), "config.json")
	raw, err := Save(path, validConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPin(st, raw); !errors.Is(err, ErrNotPinned) {
		t.Fatalf("before pin: got %v, want ErrNotPinned", err)
	}
	if err := Pin(st, raw); err != nil {
		t.Fatal(err)
	}
	stored, err := st.Get(secrets.ConfigPin)
	if err != nil || string(stored) != Digest(raw) {
		t.Fatalf("stored pin: %q, %v", stored, err)
	}
	_, loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPin(st, loaded); err != nil {
		t.Fatalf("after pin: %v", err)
	}

	// Change one byte of the file: still valid JSON, but the pin fails.
	edited := []byte(strings.Replace(string(loaded), `"builder"`, `"builder"`+" ", 1))
	if string(edited) == string(loaded) {
		t.Fatal("edit did nothing")
	}
	if err := VerifyPin(st, edited); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("after edit: got %v, want ErrPinMismatch", err)
	}
	flipped := append([]byte(nil), loaded...)
	flipped[len(flipped)/2] ^= 1
	if err := VerifyPin(st, flipped); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("flipped byte: got %v, want ErrPinMismatch", err)
	}

	// Re-pinning accepts the new content.
	if err := Pin(st, edited); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPin(st, edited); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPin(st, loaded); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("old content after re-pin: %v", err)
	}
}

func TestDigest(t *testing.T) {
	// SHA-256 of the empty string.
	if got := Digest(nil); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatal(got)
	}
}

func TestHelpers(t *testing.T) {
	c := validConfig(t)
	if !c.HasSession("builder") || c.HasSession("other") || c.HasSession("") {
		t.Fatal("HasSession")
	}
	if p, ok := c.Peer("peer-b"); !ok || p.Name != "peer-b" {
		t.Fatal("Peer")
	}
	if _, ok := c.Peer("peer-c"); ok {
		t.Fatal("Peer unknown")
	}

	if got := c.EffectiveLimits(); got != (Limits{30, 60, 50, 10, 10}) {
		t.Fatalf("defaults: %+v", got)
	}
	c.Limits = Limits{SessionPerHour: 5, ThreadBurstWindowMinutes: 3}
	if got := c.EffectiveLimits(); got != (Limits{5, 60, 50, 10, 3}) {
		t.Fatalf("partial: %+v", got)
	}
	if c.Limits != (Limits{SessionPerHour: 5, ThreadBurstWindowMinutes: 3}) {
		t.Fatal("EffectiveLimits mutated the config")
	}

	c.DataDir = "/var/lib/postern"
	if got := c.DBPath(); got != "/var/lib/postern/inbox.db" {
		t.Fatalf("DBPath with DataDir: %q", got)
	}
	c.DataDir = ""
	t.Setenv("POSTERN_CONFIG", "/opt/postern/config.json")
	if got := c.DBPath(); got != "/opt/postern/inbox.db" {
		t.Fatalf("DBPath fallback: %q", got)
	}
}

func TestDefaultPath(t *testing.T) {
	t.Setenv("POSTERN_CONFIG", "/tmp/elsewhere/config.json")
	if p, err := DefaultPath(); err != nil || p != "/tmp/elsewhere/config.json" {
		t.Fatalf("env: %q %v", p, err)
	}
	t.Setenv("POSTERN_CONFIG", "")
	p, err := DefaultPath()
	if err != nil {
		t.Skip("no user config dir:", err)
	}
	if filepath.Base(p) != "config.json" || filepath.Base(filepath.Dir(p)) != "postern" {
		t.Fatalf("default: %q", p)
	}
}

func TestLoadSetsDataDirFromRelativePath(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.json"), mustJSON(t, validConfig(t)), 0o600)
	t.Chdir(dir)
	c, _, err := Load("config.json")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(c.DBPath()) {
		t.Fatalf("DBPath not absolute: %q", c.DBPath())
	}
}
