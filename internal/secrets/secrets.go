// Package secrets stores the bridge's private material: the X25519 box
// key, the mTLS client key and certificate, and the config pin.
//
// Production code uses the OS keychain only (NewKeychain). Secrets are
// never written to files or environment variables. An in-memory Store
// for tests lives in the separate secretstest package so production
// code cannot pick it up by accident.
package secrets

import (
	"errors"
	"regexp"
)

// Item names used by the bridge.
const (
	BoxPrivateKey  = "box-private-key"
	TLSPrivateKey  = "tls-private-key"
	TLSCertificate = "tls-certificate"
	ConfigPin      = "config-pin"
	InboxKey       = "inbox-key"
)

// Errors returned by Store implementations. Callers match with errors.Is.
var (
	ErrNotFound    = errors.New("secrets: item not found")
	ErrUnsupported = errors.New("secrets: no supported keychain on this platform")
	ErrInvalidName = errors.New("secrets: invalid service or item name")
)

// Store holds named secret values. Implementations copy values in and
// out, so callers may clear the slices they pass or receive.
//
// Get and Delete return ErrNotFound when the item does not exist. Set
// creates the item or replaces its value.
type Store interface {
	Get(name string) ([]byte, error)
	Set(name string, value []byte) error
	Delete(name string) error
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,127}$`)

// ValidName reports whether s is acceptable as a keychain service or
// item name: 1 to 128 characters of [a-z0-9.-], starting with a letter
// or digit.
func ValidName(s string) bool { return nameRe.MatchString(s) }
