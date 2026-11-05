package config

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"

	"postern/internal/secrets"
)

// pinKeyBytes is the length of the pin key.
const pinKeyBytes = 32

// pinDomain separates config pins from any other use of the pin key.
const pinDomain = "postern config pin v1\x00"

// pinName is the keychain item name for the config at path. Pins are
// bound to the file's absolute path, so pointing the bridge at another
// file (--config, $POSTERN_CONFIG) finds no pin.
func pinName(path string) (string, error) {
	abs, err := absPath(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(abs))
	return secrets.ConfigPin + "." + hex.EncodeToString(sum[:16]), nil
}

func absPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("config: resolve path: %w", err)
	}
	return filepath.Clean(abs), nil
}

// pinMAC is HMAC-SHA256, under the pin key, of a domain label, the
// file's absolute path and its contents. Without the key nobody can
// compute a pin that verifies, so a pin item written by hand (for a new
// path or edited contents) blesses nothing.
func pinMAC(key []byte, path string, raw []byte) ([]byte, error) {
	abs, err := absPath(path)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(pinDomain))
	m.Write([]byte(abs))
	m.Write([]byte{0})
	m.Write(raw)
	return m.Sum(nil), nil
}

// checkOwned refuses an item whose keychain access list shows that
// postern did not create it. Stores without access lists (the in-memory
// test store) skip the check. A missing item returns secrets.ErrNotFound.
func checkOwned(st secrets.Store, name string) error {
	c, ok := st.(secrets.ACLChecker)
	if !ok {
		return nil
	}
	err := c.CheckOwnedACL(name)
	if errors.Is(err, secrets.ErrNotOwned) {
		return fmt.Errorf("config: %w; do not trust it: delete that item from the login keychain (service %s, account %s), review the config, then run `postern config pin`",
			err, PinService, name)
	}
	return err
}

// loadPinKey returns the pin key from st (the PinService store). With
// create, a missing key is generated in-process and stored, so its
// keychain access list names the postern binary; the CLI only gets here
// after the human approved the change. Without create, a missing key
// returns secrets.ErrNotFound.
func loadPinKey(st secrets.Store, create bool) ([]byte, error) {
	if err := checkOwned(st, secrets.PinKey); err != nil && !errors.Is(err, secrets.ErrNotFound) {
		return nil, err
	}
	key, err := st.Get(secrets.PinKey)
	if errors.Is(err, secrets.ErrNotFound) {
		if !create {
			return nil, secrets.ErrNotFound
		}
		k := make([]byte, pinKeyBytes)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		err = st.Set(secrets.PinKey, k)
		clear(k)
		if err != nil {
			return nil, fmt.Errorf("config: store pin key: %w", err)
		}
		// Check and read back what is stored now, like any other item,
		// rather than trusting the bytes just generated, in case another
		// process raced this one.
		if err := checkOwned(st, secrets.PinKey); err != nil {
			return nil, err
		}
		key, err = st.Get(secrets.PinKey)
	}
	if err != nil {
		return nil, fmt.Errorf("config: read pin key: %w", err)
	}
	if len(key) != pinKeyBytes {
		clear(key)
		return nil, fmt.Errorf("config: the pin key in the keychain (service %s, account %s) has the wrong length; it was not made by postern. Delete it, review the config, then run `postern config pin`",
			PinService, secrets.PinKey)
	}
	return key, nil
}

// Pin records raw as the trusted content of the config at path. st must
// be the store for PinService. It creates the pin key on first use. Only
// the human runs this, after reviewing the file; the CLI asks for user
// presence (Touch ID or the login password) first.
func Pin(st secrets.Store, path string, raw []byte) error {
	name, err := pinName(path)
	if err != nil {
		return err
	}
	key, err := loadPinKey(st, true)
	if err != nil {
		return err
	}
	defer clear(key)
	mac, err := pinMAC(key, path, raw)
	if err != nil {
		return err
	}
	// Updating an existing item keeps its access list, so refuse to
	// write into one that postern did not create.
	if err := checkOwned(st, name); err != nil && !errors.Is(err, secrets.ErrNotFound) {
		return err
	}
	if err := st.Set(name, []byte(hex.EncodeToString(mac))); err != nil {
		return fmt.Errorf("config: store pin: %w", err)
	}
	return nil
}

// VerifyPin checks raw against the pin for path. It returns ErrNotPinned
// if there is no pin or no pin key, and ErrPinMismatch if the file
// changed or the pin was not made with this machine's pin key. Call it
// before using any value from the file.
func VerifyPin(st secrets.Store, path string, raw []byte) error {
	name, err := pinName(path)
	if err != nil {
		return err
	}
	key, err := loadPinKey(st, false)
	if errors.Is(err, secrets.ErrNotFound) {
		return ErrNotPinned
	}
	if err != nil {
		return err
	}
	defer clear(key)
	mac, err := pinMAC(key, path, raw)
	if err != nil {
		return err
	}
	switch err := checkOwned(st, name); {
	case errors.Is(err, secrets.ErrNotFound):
		return ErrNotPinned
	case err != nil:
		return err
	}
	stored, err := st.Get(name)
	if errors.Is(err, secrets.ErrNotFound) {
		return ErrNotPinned
	}
	if err != nil {
		return fmt.Errorf("config: read pin: %w", err)
	}
	want, err := hex.DecodeString(string(stored))
	if err != nil || !hmac.Equal(mac, want) {
		return ErrPinMismatch
	}
	return nil
}
