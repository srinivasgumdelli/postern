package guard

import (
	"encoding/json"
	"strings"
)

// ---- running the postern binary directly -----------------------------------

// Subcommands that must only be run by the agent client, never by the agent
// through a shell: "mcp" serves the tools (run directly, it hands inbox
// content to the shell untagged and sends without the guard's prompts), and
// "hook" is the guard itself (run directly, it can be fed fake events).
var guardedSubcommands = map[string]bool{"mcp": true, "hook": true}

// shellCommand returns the command text of a shell-like tool call: the
// "command" (or "cmd") field of the tool input, as a string or as an argv
// array joined with spaces.
func shellCommand(input json.RawMessage) (string, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(input, &fields) != nil {
		return "", false
	}
	for _, key := range []string{"command", "cmd"} {
		v, ok := fields[key]
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(v, &s) == nil {
			return s, true
		}
		var argv []string
		if json.Unmarshal(v, &argv) == nil {
			return strings.Join(argv, " "), true
		}
	}
	return "", false
}

// runsPosternDirectly reports whether a shell command line looks like it
// runs the postern binary with a guarded subcommand ("mcp" or "hook"), or
// with a subcommand computed at run time ($VAR, $(...)).
//
// This is a speed bump, not a boundary. A shell is a full programming
// language, and a session that can run arbitrary commands can always build
// the binary's name or arguments in a way no pattern sees (a copied or
// renamed binary, a script file, an encoded string). It exists so that the
// obvious route, typing or piping into `postern mcp`, stops for the human
// with an explanation. The real limit is that the bridge runs as the same OS
// user as the session (see the residual risks in docs/session-guard.md).
//
// The parse is deliberately crude and errs towards matching: quotes are
// dropped rather than honoured (so a pipeline inside `bash -c '...'` is
// split like any other), and |, ;, & and newlines start a new segment.
// Within a segment, any word that names the binary (basename "postern",
// case-insensitive, or one of the configured binary paths or their
// basenames) followed by a guarded or dynamic subcommand counts.
func runsPosternDirectly(cmd string, binaries []string) bool {
	for _, seg := range shellSegments(cmd) {
		for i := 0; i+1 < len(seg); i++ {
			if !namesPostern(seg[i], binaries) {
				continue
			}
			next := strings.ToLower(seg[i+1])
			if guardedSubcommands[next] || strings.HasPrefix(next, "$") {
				return true
			}
		}
	}
	return false
}

// namesPostern reports whether a shell word refers to the postern binary.
func namesPostern(word string, binaries []string) bool {
	base := word[strings.LastIndexByte(word, '/')+1:]
	if strings.EqualFold(base, "postern") {
		return true
	}
	for _, b := range binaries {
		if b == "" {
			continue
		}
		if word == b || strings.EqualFold(base, b[strings.LastIndexByte(b, '/')+1:]) {
			return true
		}
	}
	return false
}

// shellSegments splits a command line into segments of words. Quotes are
// removed, a backslash keeps the next character (a backslash-newline is a
// line continuation), and parentheses, braces, backticks and redirections
// only separate words.
func shellSegments(cmd string) [][]string {
	var (
		segs [][]string
		seg  []string
		word strings.Builder
	)
	endWord := func() {
		if word.Len() > 0 {
			seg = append(seg, word.String())
			word.Reset()
		}
	}
	endSeg := func() {
		endWord()
		if len(seg) > 0 {
			segs = append(segs, seg)
			seg = nil
		}
	}
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch c {
		case '\'', '"':
			// dropped
		case '\\':
			if i+1 < len(cmd) {
				i++
				if cmd[i] != '\n' {
					word.WriteByte(cmd[i])
				}
			}
		case '|', ';', '&', '\n', '\r':
			endSeg()
		case ' ', '\t', '(', ')', '{', '}', '`', '<', '>':
			endWord()
		default:
			word.WriteByte(c)
		}
	}
	endSeg()
	return segs
}
