package envelope

import (
	"regexp"

	"postern/internal/ulid"
)

var (
	nameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	threadRe = regexp.MustCompile(`^t-[0-9A-HJKMNP-TV-Z]{26}$`)
)

// ValidPeerName reports whether s is an acceptable peer name.
func ValidPeerName(s string) bool { return nameRe.MatchString(s) }

// ValidSessionName reports whether s is an acceptable session name.
func ValidSessionName(s string) bool { return nameRe.MatchString(s) }

// ValidThreadID reports whether s is a bridge-generated thread id.
func ValidThreadID(s string) bool {
	return threadRe.MatchString(s) && ulid.Valid(s[2:])
}

// NewThreadID returns a fresh thread id ("t-" + ULID). Thread ids are
// generated, never free text, so they reveal nothing to the relay.
func NewThreadID() string { return "t-" + ulid.New() }
