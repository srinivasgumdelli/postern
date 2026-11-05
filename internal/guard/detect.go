package guard

import "regexp"

// ---- untrusted framing in any tool's output --------------------------------

// Postern's check_inbox output carries two kinds of marks that ordinary tool
// output does not: the delimiter line around each message's text, and the
// origin/trust tags on each message. Content that shows either is treated as
// untrusted Postern content, whichever tool brought it into the session (a
// shell running the binary directly, a file read of a saved inbox dump, a
// pipe through another program).
//
// The patterns run on a normalized copy of the raw hook input: ASCII
// lowercased, every run of backslashes dropped before the escaped character
// (so \" and \\\" read as "), \uXXXX escapes of ASCII decoded (Go's encoder
// writes < as <), and \n \r \t read as spaces. That covers the result
// as a JSON object, as a JSON string, and as a string nested in a string, to
// any depth.
var (
	delimiterRe   = regexp.MustCompile(`<<<\s*untrusted\s+postern\s+message`)
	originExtRe   = regexp.MustCompile(`"origin"\s*:\s*"external"`)
	trustUntrstRe = regexp.MustCompile(`"trust"\s*:\s*"untrusted"`)
)

// HasUntrustedFraming reports whether raw (a tool result, in any JSON
// encoding) shows Postern's untrusted framing: the message delimiter, or
// "origin":"external" together with "trust":"untrusted". An empty
// check_inbox result shows neither.
func HasUntrustedFraming(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	n := normalizeEscapes(raw)
	return delimiterRe.Match(n) || (originExtRe.Match(n) && trustUntrstRe.Match(n))
}

// normalizeEscapes returns a lowercased copy of raw with JSON string escapes
// collapsed, whatever their nesting depth. It never makes the input longer.
// The mapping is deliberately loose (a literal backslash in the text is
// dropped too): a false match only taints a session, it never untaints one.
func normalizeEscapes(raw []byte) []byte {
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); {
		c := raw[i]
		if c != '\\' {
			out = append(out, lowerASCII(c))
			i++
			continue
		}
		for i < len(raw) && raw[i] == '\\' {
			i++
		}
		if i >= len(raw) {
			break
		}
		switch e := raw[i]; e {
		case 'n', 'r', 't':
			out = append(out, ' ')
			i++
		case 'u':
			if r, ok := hex4(raw[i+1:]); ok {
				if r < 0x80 {
					out = append(out, lowerASCII(byte(r)))
				} else {
					out = append(out, '?')
				}
				i += 5
				continue
			}
			out = append(out, 'u')
			i++
		default:
			out = append(out, lowerASCII(e))
			i++
		}
	}
	return out
}

func hex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var r rune
	for _, c := range b[:4] {
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		default:
			return 0, false
		}
		r = r<<4 | rune(v)
	}
	return r, true
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
