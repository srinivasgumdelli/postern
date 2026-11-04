//go:build darwin && cgo

package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"
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
