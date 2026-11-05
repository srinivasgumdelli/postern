// Package presence asks the human at the machine to approve an action
// with the operating system's own user-presence check.
//
// On macOS this is LocalAuthentication with
// LAPolicyDeviceOwnerAuthentication: Touch ID, or the login password as
// the fallback. The dialog is drawn by the operating system, outside
// this process and outside any terminal, so a process that drives the
// command through a pseudo-terminal (script, expect, a pty library,
// tmux send-keys and capture-pane) can neither read it nor answer it,
// as it could a code printed to the terminal. Keystrokes injected into
// a terminal do not reach it.
//
// It needs a logged-in GUI session on the machine. Over SSH, in a
// headless session, or on a platform without LocalAuthentication,
// Confirm fails with ErrUnavailable or ErrUnsupported. There is
// deliberately no weaker fallback.
package presence

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Errors returned by Confirm. Callers match with errors.Is.
var (
	// ErrUnsupported means this build or platform has no user-presence
	// check (not macOS, or built without cgo).
	ErrUnsupported = errors.New("presence: no user-presence check on this platform (needs macOS, built with cgo)")
	// ErrDenied means the human cancelled, failed authentication, or did
	// not answer in time.
	ErrDenied = errors.New("presence: not approved")
	// ErrUnavailable means the check exists but cannot run now: no
	// logged-in GUI session, no Touch ID and no login password, or the
	// system refused to show the dialog.
	ErrUnavailable = errors.New("presence: user-presence check unavailable (needs a logged-in GUI session with Touch ID or a login password)")
)

// MaxReasonBytes bounds the reason shown in the system dialog.
const MaxReasonBytes = 120

// Confirm shows the system's user-presence dialog with reason, a short
// phrase such as "trust peer peer-b" that macOS shows in a sentence of
// the form "... is trying to <reason>.", and blocks until the human
// approves, refuses, or the dialog times out (two minutes). It returns
// nil only on approval.
func Confirm(reason string) error {
	r, err := cleanReason(reason)
	if err != nil {
		return err
	}
	return confirm(r)
}

// cleanReason replaces control characters and invalid UTF-8 with
// spaces, collapses whitespace and bounds the length, because
// LocalAuthentication raises an exception on an empty or invalid reason.
func cleanReason(reason string) (string, error) {
	var b strings.Builder
	for len(reason) > 0 {
		r, size := utf8.DecodeRuneInString(reason)
		reason = reason[size:]
		if r == utf8.RuneError || unicode.IsControl(r) {
			r = ' '
		}
		if b.Len()+utf8.RuneLen(r) > MaxReasonBytes {
			break
		}
		b.WriteRune(r)
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if out == "" {
		return "", errors.New("presence: empty reason")
	}
	return out, nil
}
