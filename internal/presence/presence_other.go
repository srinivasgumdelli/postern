//go:build !darwin || !cgo

package presence

// available reports that this build has no user-presence check.
const available = false

// confirm has no implementation here: v0 supports macOS
// LocalAuthentication only. There is deliberately no terminal fallback.
func confirm(string) error { return ErrUnsupported }
