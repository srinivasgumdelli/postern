package presence

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestCleanReason(t *testing.T) {
	for in, want := range map[string]string{
		"trust peer peer-b":          "trust peer peer-b",
		"  pin\nconfig\x1b[2J  now ": "pin config [2J now",
		"bad \xff utf8":              "bad utf8",
	} {
		got, err := cleanReason(in)
		if err != nil || got != want {
			t.Errorf("cleanReason(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	long, err := cleanReason(strings.Repeat("é", 200))
	if err != nil || len(long) > MaxReasonBytes {
		t.Errorf("long reason: %d bytes, %v", len(long), err)
	}
}

// An empty reason is refused before any dialog is shown.
func TestConfirmRejectsEmptyReason(t *testing.T) {
	for _, r := range []string{"", "   ", "\n\t\x00"} {
		if err := Confirm(r); err == nil || errors.Is(err, ErrDenied) {
			t.Errorf("Confirm(%q) = %v, want an argument error", r, err)
		}
	}
}

func TestUnsupportedWithoutLocalAuthentication(t *testing.T) {
	if available {
		t.Skip("LocalAuthentication is available in this build")
	}
	if err := Confirm("test"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("got %v, want ErrUnsupported", err)
	}
}

// TestRealPresence shows the real system dialog, so it runs only with
// POSTERN_TEST_PRESENCE=1 and a human at the machine. Approve it with
// Touch ID or the login password.
func TestRealPresence(t *testing.T) {
	if os.Getenv("POSTERN_TEST_PRESENCE") != "1" {
		t.Skip("set POSTERN_TEST_PRESENCE=1 to show the real Touch ID / password dialog")
	}
	if err := Confirm("run the postern presence test (approve it)"); err != nil {
		t.Fatalf("approve the dialog: %v", err)
	}
}
