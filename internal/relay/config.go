// Package relay is the Postern relay: a small HTTP service that stores
// sealed envelopes (ciphertext plus routing fields) for at most 72 hours
// and hands them to the addressed peer. It never sees plaintext.
//
// Every request under /v1 is bound to a peer by the SHA-256 fingerprint of
// that peer's client certificate. In production the edge verifies the
// certificate and forwards the fingerprint in a header; in development
// and tests the relay terminates mTLS itself.
package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"

	"postern/internal/envelope"
	"postern/internal/tlsutil"
)

// Identity modes.
const (
	// IdentityHeader trusts a fingerprint header set by the edge. Only
	// safe because the relay publishes no ports and is reachable solely
	// through the tunnel, behind an edge that verifies the client
	// certificate and overwrites the header.
	IdentityHeader = "header"
	// IdentityMTLS terminates mTLS in the relay and fingerprints the
	// verified client certificate.
	IdentityMTLS = "mtls"
)

// Defaults applied by LoadConfig and New when a field is zero.
const (
	DefaultListen            = ":8080"
	DefaultFingerprintHeader = "X-Postern-Client-Cert-Sha256"
	DefaultPostsPerHour      = 120
	DefaultMaxQueuedPerPeer  = 1000
)

const maxConfigBytes = 1 << 20

// TLSFiles names the PEM files used in mtls identity mode.
type TLSFiles struct {
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"key_file"`
	ClientCAFile string `json:"client_ca_file"`
}

// Config is the relay configuration file.
type Config struct {
	Listen            string `json:"listen"`
	DB                string `json:"db"`
	Identity          string `json:"identity"`
	FingerprintHeader string `json:"fingerprint_header"`
	// Peers maps a peer name to the SHA-256 fingerprints of the client
	// certificates allowed to act as that peer. Several fingerprints per
	// peer let an old and a new certificate overlap during rotation.
	Peers            map[string][]string `json:"peers"`
	TLS              *TLSFiles           `json:"tls,omitempty"`
	PostsPerHour     int                 `json:"posts_per_hour"`
	MaxQueuedPerPeer int                 `json:"max_queued_per_peer"`
}

// LoadConfig reads a relay configuration file strictly (unknown fields
// and trailing data are errors), applies defaults and validates it.
func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("relay config: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("relay config: %w", err)
	}
	if len(raw) > maxConfigBytes {
		return Config{}, errors.New("relay config: file too large")
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("relay config: invalid JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Config{}, errors.New("relay config: trailing data after JSON object")
	}
	c, err = c.normalized()
	if err != nil {
		return Config{}, err
	}
	if c.DB == "" {
		return Config{}, errors.New("relay config: db is required")
	}
	return c, nil
}

// normalized returns a copy of c with defaults applied and fingerprints
// normalized, or an error if c is not usable. It does not require DB,
// because New receives an already open Store.
func (c Config) normalized() (Config, error) {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.FingerprintHeader == "" {
		c.FingerprintHeader = DefaultFingerprintHeader
	}
	if c.PostsPerHour == 0 {
		c.PostsPerHour = DefaultPostsPerHour
	}
	if c.MaxQueuedPerPeer == 0 {
		c.MaxQueuedPerPeer = DefaultMaxQueuedPerPeer
	}
	if c.PostsPerHour < 0 {
		return Config{}, errors.New("relay config: posts_per_hour must be positive")
	}
	if c.MaxQueuedPerPeer < 0 {
		return Config{}, errors.New("relay config: max_queued_per_peer must be positive")
	}
	if !validHeaderName(c.FingerprintHeader) {
		return Config{}, errors.New("relay config: fingerprint_header is not a valid header name")
	}

	switch c.Identity {
	case IdentityHeader:
		if c.TLS != nil {
			return Config{}, errors.New("relay config: tls is only used with identity \"mtls\"")
		}
	case IdentityMTLS:
		if c.TLS == nil || c.TLS.CertFile == "" || c.TLS.KeyFile == "" || c.TLS.ClientCAFile == "" {
			return Config{}, errors.New("relay config: identity \"mtls\" needs tls.cert_file, tls.key_file and tls.client_ca_file")
		}
		t := *c.TLS
		c.TLS = &t
	default:
		return Config{}, errors.New("relay config: identity must be \"header\" or \"mtls\"")
	}

	if len(c.Peers) < 2 {
		return Config{}, errors.New("relay config: at least two peers are required")
	}
	owner := make(map[string]string)
	peers := make(map[string][]string, len(c.Peers))
	for _, name := range slices.Sorted(maps.Keys(c.Peers)) {
		if !envelope.ValidPeerName(name) {
			return Config{}, errors.New("relay config: invalid peer name")
		}
		fps := c.Peers[name]
		if len(fps) == 0 {
			return Config{}, fmt.Errorf("relay config: peer %s has no certificate fingerprints", name)
		}
		norm := make([]string, 0, len(fps))
		for i, fp := range fps {
			n := tlsutil.NormalizeFingerprint(fp)
			if !validFingerprint(n) {
				return Config{}, fmt.Errorf("relay config: peer %s fingerprint %d is not 64 hex characters", name, i+1)
			}
			if prev, dup := owner[n]; dup {
				if prev == name {
					return Config{}, fmt.Errorf("relay config: peer %s lists the same fingerprint twice", name)
				}
				return Config{}, fmt.Errorf("relay config: a fingerprint is listed for both %s and %s", prev, name)
			}
			owner[n] = name
			norm = append(norm, n)
		}
		peers[name] = norm
	}
	c.Peers = peers
	return c, nil
}

func validFingerprint(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// validHeaderName accepts a conservative subset of RFC 9110 tokens.
func validHeaderName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		ok := c == '-' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !ok {
			return false
		}
	}
	return true
}
