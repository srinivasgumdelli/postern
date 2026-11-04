// Package ulid generates and validates ULIDs: 48-bit millisecond
// timestamp plus 80 random bits, encoded as 26 Crockford base32 chars.
package ulid

import (
	"crypto/rand"
	"time"
)

const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Len is the length of an encoded ULID.
const Len = 26

// New returns a ULID for the current time.
func New() string {
	return NewAt(time.Now())
}

// NewAt returns a ULID for t with fresh randomness.
func NewAt(t time.Time) string {
	var b [16]byte
	ms := uint64(t.UnixMilli())
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	if _, err := rand.Read(b[6:]); err != nil {
		panic("ulid: crypto/rand failed: " + err.Error())
	}
	return encode(b)
}

func encode(b [16]byte) string {
	// 128 bits as 26 base32 digits; the first digit carries 3 bits.
	var out [Len]byte
	var acc uint64
	var bits uint
	pos := Len - 1
	for i := 15; i >= 0; i-- {
		acc |= uint64(b[i]) << bits
		bits += 8
		for bits >= 5 && pos >= 0 {
			out[pos] = alphabet[acc&31]
			acc >>= 5
			bits -= 5
			pos--
		}
	}
	if pos == 0 {
		out[0] = alphabet[acc&31]
	}
	return string(out[:])
}

// Valid reports whether s is a well-formed ULID in canonical upper case.
func Valid(s string) bool {
	if len(s) != Len {
		return false
	}
	// The first char may only encode 3 bits (0-7) or the value overflows.
	if s[0] < '0' || s[0] > '7' {
		return false
	}
	for i := range Len {
		if !validChar(s[i]) {
			return false
		}
	}
	return true
}

func validChar(c byte) bool {
	for i := range len(alphabet) {
		if alphabet[i] == c {
			return true
		}
	}
	return false
}
