// Package config loads, validates, saves and pins the bridge config.
//
// The config file holds no secrets: peer public keys with their
// fingerprints, the relay URL, the session allow-list and limits. It is
// still security relevant (swapping a peer key or the relay URL would
// redirect messages), so the bridge stores the file's SHA-256 in the
// keychain (Pin) and refuses to start when the file no longer matches
// (VerifyPin) until the human reviews it and pins it again.
package config

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"postern/internal/envelope"
	"postern/internal/secrets"
)

// Default limits, used when a Limits field is zero.
const (
	DefaultSessionPerHour           = 30
	DefaultGlobalPerHour            = 60
	DefaultThreadMax                = 50
	DefaultThreadBurst              = 10
	DefaultThreadBurstWindowMinutes = 10

	// DefaultKeychainService is used when keychain_service is empty.
	DefaultKeychainService = "postern"

	// DBFile is the inbox database file name inside the data directory.
	DBFile = "inbox.db"

	// maxFileBytes bounds what Load reads. Real configs are a few KB.
	maxFileBytes = 1 << 20
)

// Errors. Callers match with errors.Is.
var (
	ErrInvalid     = errors.New("config: invalid")
	ErrNotPinned   = errors.New("config: file is not pinned; review it, then run `postern config pin`")
	ErrPinMismatch = errors.New("config: file changed since it was pinned; review it, then run `postern config pin`")
)

// Config is the bridge configuration file.
type Config struct {
	PeerName        string       `json:"peer_name"`
	RelayURL        string       `json:"relay_url"`
	RelayCAFile     string       `json:"relay_ca_file,omitempty"`
	KeychainService string       `json:"keychain_service"`
	DataDir         string       `json:"data_dir,omitempty"`
	Sessions        []string     `json:"sessions"`
	Peers           []PeerConfig `json:"peers"`
	Limits          Limits       `json:"limits"`

	// path is the absolute path the config was loaded from or saved to.
	path string
}

// PeerConfig pins one remote peer's sealing key.
type PeerConfig struct {
	Name        string `json:"name"`
	PublicKey   string `json:"public_key"`  // base64 X25519 public key
	Fingerprint string `json:"fingerprint"` // envelope.Fingerprint(PublicKey), compared out of band
}

// Limits are bridge-side send limits. Zero means the default.
type Limits struct {
	SessionPerHour           int `json:"session_per_hour"`
	GlobalPerHour            int `json:"global_per_hour"`
	ThreadMax                int `json:"thread_max"`
	ThreadBurst              int `json:"thread_burst"`
	ThreadBurstWindowMinutes int `json:"thread_burst_window_minutes"`
}

var serviceRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// DefaultPath returns $POSTERN_CONFIG if set, otherwise
// os.UserConfigDir()/postern/config.json.
func DefaultPath() (string, error) {
	if p := os.Getenv("POSTERN_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("config: %w", err)
	}
	return filepath.Join(dir, "postern", "config.json"), nil
}

// Load reads and validates the config at path. It refuses a file that
// is not a regular file or is group- or world-writable, and decodes
// strictly (see Parse). It returns the raw bytes so the caller can check
// them against the pin. DataDir defaults to the file's directory.
func Load(path string) (*Config, []byte, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, fmt.Errorf("config: %w", err)
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, nil, fmt.Errorf("config: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("config: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("config: %s is not a regular file", abs)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return nil, nil, fmt.Errorf("config: %s is writable by group or others (mode %04o); run chmod 600 on it", abs, perm)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("config: %w", err)
	}
	if len(raw) > maxFileBytes {
		return nil, nil, invalid("file larger than %d bytes", maxFileBytes)
	}
	c, err := Parse(raw)
	if err != nil {
		return nil, nil, err
	}
	c.path = abs
	return c, raw, nil
}

// Parse decodes config JSON strictly and validates it: unknown fields,
// trailing data, duplicate keys and keys that are not exactly lower case
// are all rejected.
func Parse(raw []byte) (*Config, error) {
	if err := checkKeys(raw); err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, invalid("json: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, invalid("trailing data after the JSON object")
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

type jsonFrame struct {
	object  bool
	wantKey bool
	seen    map[string]bool
}

// checkKeys walks the JSON tokens and rejects duplicate object keys and
// keys that are not exactly lower case. encoding/json matches field
// names case-insensitively and lets the last duplicate win, so without
// this a reviewer could read one value while the bridge used another.
func checkKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var stack []*jsonFrame
	valueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].wantKey = true
		}
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return invalid("json: %v", err)
		}
		if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].wantKey {
			top := stack[n-1]
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:n-1]
				valueDone()
				continue
			}
			key, _ := tok.(string)
			if key != strings.ToLower(key) {
				return invalid("json key %q is not lower case", key)
			}
			if top.seen[key] {
				return invalid("duplicate json key %q", key)
			}
			top.seen[key] = true
			top.wantKey = false
			continue
		}
		switch tok {
		case json.Delim('{'):
			stack = append(stack, &jsonFrame{object: true, wantKey: true, seen: map[string]bool{}})
		case json.Delim('['):
			stack = append(stack, &jsonFrame{})
		case json.Delim(']'), json.Delim('}'):
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			valueDone()
		default:
			valueDone()
		}
	}
}

// Validate checks every field and fills KeychainService with its
// default when empty. Error messages name the field, not its value.
func (c *Config) Validate() error {
	if c == nil {
		return invalid("nil config")
	}
	if !envelope.ValidPeerName(c.PeerName) {
		return invalid("peer_name must match ^[a-z0-9][a-z0-9-]{0,31}$")
	}
	if err := validateRelayURL(c.RelayURL); err != nil {
		return err
	}
	if c.RelayCAFile != "" && !filepath.IsAbs(c.RelayCAFile) {
		return invalid("relay_ca_file must be an absolute path")
	}
	if c.KeychainService == "" {
		c.KeychainService = DefaultKeychainService
	} else if !serviceRe.MatchString(c.KeychainService) {
		return invalid("keychain_service must match ^[a-z0-9][a-z0-9.-]{0,63}$")
	}
	// A relative data_dir would resolve against each process's working
	// directory, giving sessions on one machine different inboxes.
	if c.DataDir != "" && !filepath.IsAbs(c.DataDir) {
		return invalid("data_dir must be an absolute path")
	}

	seen := make(map[string]bool, len(c.Sessions))
	for i, s := range c.Sessions {
		if !envelope.ValidSessionName(s) {
			return invalid("sessions[%d] must match ^[a-z0-9][a-z0-9-]{0,31}$", i)
		}
		if seen[s] {
			return invalid("sessions[%d] is a duplicate", i)
		}
		seen[s] = true
	}

	peers := make(map[string]bool, len(c.Peers))
	for i, p := range c.Peers {
		if !envelope.ValidPeerName(p.Name) {
			return invalid("peers[%d].name must match ^[a-z0-9][a-z0-9-]{0,31}$", i)
		}
		if p.Name == c.PeerName {
			return invalid("peers[%d].name is this bridge's own peer_name", i)
		}
		if peers[p.Name] {
			return invalid("peers[%d].name is a duplicate", i)
		}
		peers[p.Name] = true
		key, err := envelope.DecodeKey(p.PublicKey)
		if err != nil {
			return invalid("peers[%d].public_key is not a base64 32-byte key", i)
		}
		if p.Fingerprint != envelope.Fingerprint(key) {
			return invalid("peers[%d].fingerprint does not match public_key", i)
		}
	}

	l := c.Limits
	if l.SessionPerHour < 0 || l.GlobalPerHour < 0 || l.ThreadMax < 0 ||
		l.ThreadBurst < 0 || l.ThreadBurstWindowMinutes < 0 {
		return invalid("limits must not be negative")
	}
	return nil
}

func validateRelayURL(s string) error {
	if s == "" {
		return invalid("relay_url is required")
	}
	u, err := url.Parse(s)
	if err != nil {
		return invalid("relay_url does not parse")
	}
	switch {
	case u.Scheme != "https":
		return invalid("relay_url must use https")
	case u.Opaque != "" || u.Hostname() == "":
		return invalid("relay_url must have a host")
	case u.User != nil:
		return invalid("relay_url must not contain user info")
	case u.RawQuery != "" || u.ForceQuery:
		return invalid("relay_url must not contain a query")
	case u.Fragment != "" || u.RawFragment != "" || strings.Contains(s, "#"):
		return invalid("relay_url must not contain a fragment")
	}
	return nil
}

// Save validates c and writes it to path atomically (temp file in the
// same directory, fsync, rename) with mode 0600, creating the directory
// with mode 0700 if needed. It returns the bytes written, ready to pin.
func Save(path string, c *Config) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	raw = append(raw, '\n')

	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := os.Rename(tmpName, abs); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync() // persist the rename; best effort
		d.Close()
	}
	c.path = abs
	return raw, nil
}

// Path returns the absolute path the config was loaded from or saved
// to, or "" if neither happened.
func (c *Config) Path() string { return c.path }

// Digest returns the lowercase hex SHA-256 of raw.
func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Pin stores Digest(raw) in the keychain under secrets.ConfigPin. Only
// the human runs this (`postern config pin`), after reviewing the file.
func Pin(st secrets.Store, raw []byte) error {
	if err := st.Set(secrets.ConfigPin, []byte(Digest(raw))); err != nil {
		return fmt.Errorf("config: store pin: %w", err)
	}
	return nil
}

// VerifyPin checks raw against the stored pin. It returns ErrNotPinned
// if there is no pin and ErrPinMismatch if the file changed.
func VerifyPin(st secrets.Store, raw []byte) error {
	want, err := st.Get(secrets.ConfigPin)
	if errors.Is(err, secrets.ErrNotFound) {
		return ErrNotPinned
	}
	if err != nil {
		return fmt.Errorf("config: read pin: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(Digest(raw)), want) != 1 {
		return ErrPinMismatch
	}
	return nil
}

// HasSession reports whether name is in the session allow-list.
func (c *Config) HasSession(name string) bool {
	for _, s := range c.Sessions {
		if s == name {
			return true
		}
	}
	return false
}

// Peer returns the pinned peer with the given name.
func (c *Config) Peer(name string) (PeerConfig, bool) {
	for _, p := range c.Peers {
		if p.Name == name {
			return p, true
		}
	}
	return PeerConfig{}, false
}

// DBPath returns the inbox database path: DataDir/inbox.db, where
// DataDir defaults to the directory of the config file (or of
// DefaultPath when the config was neither loaded nor saved). It returns
// "" only if no directory can be determined.
func (c *Config) DBPath() string {
	dir := c.DataDir
	if dir == "" && c.path != "" {
		dir = filepath.Dir(c.path)
	}
	if dir == "" {
		p, err := DefaultPath()
		if err != nil {
			return ""
		}
		if p, err = filepath.Abs(p); err != nil {
			return ""
		}
		dir = filepath.Dir(p)
	}
	return filepath.Join(dir, DBFile)
}

// EffectiveLimits returns Limits with zero fields replaced by defaults.
func (c *Config) EffectiveLimits() Limits {
	l := c.Limits
	def := func(v *int, d int) {
		if *v == 0 {
			*v = d
		}
	}
	def(&l.SessionPerHour, DefaultSessionPerHour)
	def(&l.GlobalPerHour, DefaultGlobalPerHour)
	def(&l.ThreadMax, DefaultThreadMax)
	def(&l.ThreadBurst, DefaultThreadBurst)
	def(&l.ThreadBurstWindowMinutes, DefaultThreadBurstWindowMinutes)
	return l
}
