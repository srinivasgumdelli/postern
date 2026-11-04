//go:build !darwin || !cgo

package secrets

// NewKeychain returns ErrUnsupported: v0 supports the macOS keychain
// only (built with cgo). Linux Secret Service support is planned. There
// is deliberately no file-based fallback.
func NewKeychain(service string) (Store, error) {
	if !ValidName(service) {
		return nil, ErrInvalidName
	}
	return nil, ErrUnsupported
}
