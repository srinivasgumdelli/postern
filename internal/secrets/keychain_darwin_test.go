//go:build darwin && cgo

package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestKeychainRoundTrip uses the real login keychain, so it runs only
// with POSTERN_TEST_KEYCHAIN=1. It uses a fresh random service name and
// removes every item it creates.
func TestKeychainRoundTrip(t *testing.T) {
	if os.Getenv("POSTERN_TEST_KEYCHAIN") != "1" {
		t.Skip("set POSTERN_TEST_KEYCHAIN=1 to run against the real keychain")
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		t.Fatal(err)
	}
	service := "postern-test-" + hex.EncodeToString(rnd[:])
	st, err := NewKeychain(service)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{BoxPrivateKey, TLSCertificate, "empty-value"}
	t.Cleanup(func() {
		for _, n := range names {
			if err := st.Delete(n); err != nil && !errors.Is(err, ErrNotFound) {
				t.Errorf("cleanup %s: %v", n, err)
			}
		}
	})

	if _, err := st.Get(BoxPrivateKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing: got %v, want ErrNotFound", err)
	}
	if err := st.Delete(BoxPrivateKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete missing: got %v, want ErrNotFound", err)
	}

	v1 := make([]byte, 32)
	if _, err := rand.Read(v1); err != nil {
		t.Fatal(err)
	}
	v1[0] = 0 // embedded NUL bytes must survive
	if err := st.Set(BoxPrivateKey, v1); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := st.Get(BoxPrivateKey)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, v1) {
		t.Fatal("Get returned a different value")
	}

	v2 := []byte("second value, longer than the first one to check resizing")
	if err := st.Set(BoxPrivateKey, v2); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	got, err = st.Get(BoxPrivateKey)
	if err != nil || !bytes.Equal(got, v2) {
		t.Fatalf("Get after overwrite: %v", err)
	}

	// Items are keyed by name within the service.
	if _, err := st.Get(TLSCertificate); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other name: got %v, want ErrNotFound", err)
	}

	if err := st.Set("empty-value", nil); err != nil {
		t.Fatalf("Set empty: %v", err)
	}
	if got, err := st.Get("empty-value"); err != nil || len(got) != 0 {
		t.Fatalf("Get empty: %v, len %d", err, len(got))
	}

	if err := st.Delete(BoxPrivateKey); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := st.Get(BoxPrivateKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after delete: got %v, want ErrNotFound", err)
	}
}

// TestKeychainACLCheck plants items the way an attacker would, with the
// security tool, and checks that CheckOwnedACL tells them apart from
// items the store created in-process. It uses the real login keychain,
// so it runs only with POSTERN_TEST_KEYCHAIN=1, under a fresh random
// service name, and removes every item it creates.
func TestKeychainACLCheck(t *testing.T) {
	if os.Getenv("POSTERN_TEST_KEYCHAIN") != "1" {
		t.Skip("set POSTERN_TEST_KEYCHAIN=1 to run against the real keychain")
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		t.Fatal(err)
	}
	service := "postern-test-" + hex.EncodeToString(rnd[:])
	st, err := NewKeychain(service)
	if err != nil {
		t.Fatal(err)
	}
	checker, ok := st.(ACLChecker)
	if !ok {
		t.Fatal("keychain store does not implement ACLChecker")
	}
	security := func(args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "/usr/bin/security", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("security %s: %v: %s", args[0], err, out)
		}
		return nil
	}
	t.Cleanup(func() {
		if err := st.Delete("owned"); err != nil && !errors.Is(err, ErrNotFound) {
			t.Errorf("cleanup owned: %v", err)
		}
		for _, a := range []string{"planted-any", "planted-named"} {
			_ = security("delete-generic-password", "-s", service, "-a", a)
		}
	})

	if err := checker.CheckOwnedACL("owned"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing item: got %v, want ErrNotFound", err)
	}
	if err := st.Set("owned", []byte("value")); err != nil {
		t.Fatal(err)
	}
	if err := checker.CheckOwnedACL("owned"); err != nil {
		t.Fatalf("item created in-process refused: %v", err)
	}

	// -A: any application may read the item without a prompt.
	if err := security("add-generic-password", "-A", "-s", service, "-a", "planted-any", "-w", "forged"); err != nil {
		t.Fatal(err)
	}
	if err := checker.CheckOwnedACL("planted-any"); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("item planted with -A: got %v, want ErrNotOwned", err)
	}

	// -T names one application. The check cannot tell this apart from an
	// item postern created (the residual risk in DESIGN.md); log it.
	if err := security("add-generic-password", "-T", "/usr/bin/true", "-s", service, "-a", "planted-named", "-w", "forged"); err != nil {
		t.Fatal(err)
	}
	t.Logf("item planted with -T: CheckOwnedACL = %v", checker.CheckOwnedACL("planted-named"))
}

func TestKeychainRejectsBadNames(t *testing.T) {
	for _, s := range []string{"", "Postern", "a b", "a/b", "a_b", "-a"} {
		if _, err := NewKeychain(s); !errors.Is(err, ErrInvalidName) {
			t.Errorf("NewKeychain(%q): got %v, want ErrInvalidName", s, err)
		}
	}
	st, err := NewKeychain("postern-test-names")
	if err != nil {
		t.Fatal(err)
	}
	// Name checks happen before any keychain call, so this is safe to
	// run without POSTERN_TEST_KEYCHAIN.
	for _, n := range []string{"", "Box", "a b", "../x"} {
		if _, err := st.Get(n); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Get(%q): got %v", n, err)
		}
		if err := st.Set(n, []byte("x")); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Set(%q): got %v", n, err)
		}
		if err := st.Delete(n); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Delete(%q): got %v", n, err)
		}
	}
}
