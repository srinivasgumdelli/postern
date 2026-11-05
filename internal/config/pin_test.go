package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"postern/internal/secrets"
	"postern/internal/secrets/secretstest"
)

// unkeyedPin is the old, forgeable pin: SHA-256 of path, NUL, contents.
// Anyone who can write a keychain item can compute it.
func unkeyedPin(t *testing.T, path string, raw []byte) []byte {
	t.Helper()
	abs, err := absPath(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	h.Write([]byte(abs))
	h.Write([]byte{0})
	h.Write(raw)
	return []byte(hex.EncodeToString(h.Sum(nil)))
}

func savedConfig(t *testing.T) (string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	raw, err := Save(path, validConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	return path, raw
}

func TestPinIsKeyedHMAC(t *testing.T) {
	st := secretstest.NewMemory()
	path, raw := savedConfig(t)
	if err := Pin(st, path, raw); err != nil {
		t.Fatal(err)
	}
	key, err := st.Get(secrets.PinKey)
	if err != nil || len(key) != 32 {
		t.Fatalf("pin key: %v, %d bytes", err, len(key))
	}
	if err := VerifyPin(st, path, raw); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	name, _ := pinName(path)
	stored, _ := st.Get(name)
	mac, _ := pinMAC(key, path, raw)
	if string(stored) != hex.EncodeToString(mac) {
		t.Fatal("stored pin is not the HMAC under the pin key")
	}
	if string(stored) == string(unkeyedPin(t, path, raw)) {
		t.Fatal("stored pin equals the unkeyed SHA-256")
	}
	// Re-pinning keeps the key.
	if err := Pin(st, path, raw); err != nil {
		t.Fatal(err)
	}
	again, _ := st.Get(secrets.PinKey)
	if hex.EncodeToString(again) != hex.EncodeToString(key) {
		t.Fatal("pin key changed on re-pin")
	}
}

// TestForgedUnkeyedPinRejected is the forgery from the review: someone
// writes the plain SHA-256 pin for a config of their choosing, at a path
// that was never pinned and over an existing pin.
func TestForgedUnkeyedPinRejected(t *testing.T) {
	st := secretstest.NewMemory()
	path, raw := savedConfig(t)
	if err := Pin(st, path, raw); err != nil {
		t.Fatal(err)
	}

	evilPath, evilRaw := savedConfig(t)
	evilName, _ := pinName(evilPath)
	if err := st.Set(evilName, unkeyedPin(t, evilPath, evilRaw)); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPin(st, evilPath, evilRaw); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("forged pin for a new path: got %v, want ErrPinMismatch", err)
	}

	name, _ := pinName(path)
	edited := append(append([]byte(nil), raw...), ' ')
	if err := st.Set(name, unkeyedPin(t, path, edited)); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPin(st, path, edited); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("forged pin over an existing one: got %v, want ErrPinMismatch", err)
	}
	// Garbage that is not even hex.
	if err := st.Set(name, []byte("not hex")); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPin(st, path, raw); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("non-hex pin: got %v, want ErrPinMismatch", err)
	}
}

func TestPinFromAnotherKeyRejected(t *testing.T) {
	a, b := secretstest.NewMemory(), secretstest.NewMemory()
	path, raw := savedConfig(t)
	if err := Pin(a, path, raw); err != nil {
		t.Fatal(err)
	}
	// b has its own pin key (from pinning some other file).
	otherPath, otherRaw := savedConfig(t)
	if err := Pin(b, otherPath, otherRaw); err != nil {
		t.Fatal(err)
	}
	name, _ := pinName(path)
	v, err := a.Get(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Set(name, v); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPin(b, path, raw); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("pin made under another key: got %v, want ErrPinMismatch", err)
	}
}

func TestMissingPinKeyMeansNotPinned(t *testing.T) {
	st := secretstest.NewMemory()
	path, raw := savedConfig(t)
	if err := Pin(st, path, raw); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(secrets.PinKey); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPin(st, path, raw); !errors.Is(err, ErrNotPinned) {
		t.Fatalf("no pin key: got %v, want ErrNotPinned", err)
	}
	// A fresh store with only a forged pin and no key: not pinned, and
	// verifying never creates a key.
	fresh := secretstest.NewMemory()
	name, _ := pinName(path)
	if err := fresh.Set(name, unkeyedPin(t, path, raw)); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPin(fresh, path, raw); !errors.Is(err, ErrNotPinned) {
		t.Fatalf("forged pin without key: got %v, want ErrNotPinned", err)
	}
	if _, err := fresh.Get(secrets.PinKey); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("VerifyPin created a pin key: %v", err)
	}
}

func TestWrongLengthPinKeyRefused(t *testing.T) {
	st := secretstest.NewMemory()
	path, raw := savedConfig(t)
	if err := st.Set(secrets.PinKey, []byte("short")); err != nil {
		t.Fatal(err)
	}
	if err := Pin(st, path, raw); err == nil {
		t.Fatal("pinned with a malformed pin key")
	}
	if err := VerifyPin(st, path, raw); err == nil || errors.Is(err, ErrNotPinned) {
		t.Fatalf("got %v, want a pin key error", err)
	}
}

// aclStore is a memory store that reports some items as not created by
// postern, the way the keychain store does for an item added with -A.
type aclStore struct {
	*secretstest.Memory
	notOwned map[string]bool
}

func (s aclStore) CheckOwnedACL(name string) error {
	if _, err := s.Get(name); err != nil {
		return err
	}
	if s.notOwned[name] {
		return fmt.Errorf("%w: %s", secrets.ErrNotOwned, name)
	}
	return nil
}

func TestPlantedItemsRefusedByACLCheck(t *testing.T) {
	path, raw := savedConfig(t)
	name, _ := pinName(path)

	// A planted pin key: refused for pinning and verifying.
	st := aclStore{secretstest.NewMemory(), map[string]bool{secrets.PinKey: true}}
	if err := st.Set(secrets.PinKey, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if err := Pin(st, path, raw); !errors.Is(err, secrets.ErrNotOwned) {
		t.Fatalf("Pin with planted key: got %v, want ErrNotOwned", err)
	}
	if _, err := st.Get(name); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatal("Pin wrote a pin under a planted key")
	}
	if err := VerifyPin(st, path, raw); !errors.Is(err, secrets.ErrNotOwned) {
		t.Fatalf("VerifyPin with planted key: got %v, want ErrNotOwned", err)
	}

	// An owned key but a planted pin item.
	st = aclStore{secretstest.NewMemory(), map[string]bool{}}
	if err := Pin(st, path, raw); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPin(st, path, raw); err != nil {
		t.Fatalf("owned items refused: %v", err)
	}
	st.notOwned[name] = true
	if err := VerifyPin(st, path, raw); !errors.Is(err, secrets.ErrNotOwned) {
		t.Fatalf("VerifyPin with planted pin item: got %v, want ErrNotOwned", err)
	}
	if err := Pin(st, path, raw); !errors.Is(err, secrets.ErrNotOwned) {
		t.Fatalf("Pin into a planted pin item: got %v, want ErrNotOwned", err)
	}
}
