package guard

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

// MinClaudeCodeVersion is the oldest Claude Code release the guard supports.
// Earlier releases ignore `"onFailure": "block"` on hooks and treat a
// missing, crashing or timed-out guard as a non-blocking error, so the tool
// call runs: they fail open.
const MinClaudeCodeVersion = "2.1.295"

// ErrUnknownVersion is returned by CheckClaudeCodeVersion when the version
// output cannot be parsed.
var ErrUnknownVersion = errors.New("guard: cannot tell the Claude Code version")

// ErrClaudeCodeTooOld is wrapped by the error CheckClaudeCodeVersion returns
// for a release older than MinClaudeCodeVersion.
var ErrClaudeCodeTooOld = errors.New("guard: Claude Code is too old for the guard")

// versionRe matches the first dotted version in `claude --version` output,
// for example "2.1.318 (Claude Code)".
var versionRe = regexp.MustCompile(`^\s*v?(\d{1,9})\.(\d{1,9})\.(\d{1,9})(?:[^\d.]|$)`)

// CheckClaudeCodeVersion checks the output of `claude --version` against
// MinClaudeCodeVersion. It returns nil for that release or newer, an error
// wrapping ErrClaudeCodeTooOld for an older one, and ErrUnknownVersion when
// the output does not start with a version number. A pre-release of the
// minimum version (2.1.295-beta) counts as that version.
func CheckClaudeCodeVersion(versionOutput string) error {
	have, ok := parseVersion(versionOutput)
	if !ok {
		return ErrUnknownVersion
	}
	need, _ := parseVersion(MinClaudeCodeVersion)
	for i := range have {
		if have[i] != need[i] {
			if have[i] < need[i] {
				return fmt.Errorf("%w: found %d.%d.%d, need %s or newer; older releases run the tool call when the guard fails",
					ErrClaudeCodeTooOld, have[0], have[1], have[2], MinClaudeCodeVersion)
			}
			return nil
		}
	}
	return nil
}

func parseVersion(s string) ([3]int, bool) {
	var v [3]int
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return v, false
	}
	for i := range v {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return v, false
		}
		v[i] = n
	}
	return v, true
}
