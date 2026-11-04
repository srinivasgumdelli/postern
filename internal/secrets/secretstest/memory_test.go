package secretstest

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"postern/internal/secrets"
)

func TestMemoryRoundTrip(t *testing.T) {
	m := NewMemory()
	if _, err := m.Get(secrets.BoxPrivateKey); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("Get missing: %v", err)
	}
	if err := m.Delete(secrets.BoxPrivateKey); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("Delete missing: %v", err)
	}

	in := []byte("value-one")
	if err := m.Set(secrets.BoxPrivateKey, in); err != nil {
		t.Fatal(err)
	}
	in[0] = 'X' // caller's slice is not aliased
	got, err := m.Get(secrets.BoxPrivateKey)
	if err != nil || string(got) != "value-one" {
		t.Fatalf("Get: %q, %v", got, err)
	}
	got[0] = 'Y' // returned slice is not aliased
	again, _ := m.Get(secrets.BoxPrivateKey)
	if string(again) != "value-one" {
		t.Fatalf("store aliased returned slice: %q", again)
	}

	if err := m.Set(secrets.BoxPrivateKey, []byte("value-two")); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.Get(secrets.BoxPrivateKey); !bytes.Equal(got, []byte("value-two")) {
		t.Fatalf("overwrite: %q", got)
	}
	if err := m.Delete(secrets.BoxPrivateKey); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(secrets.BoxPrivateKey); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("Get after delete: %v", err)
	}
}

func TestMemoryRejectsBadNames(t *testing.T) {
	m := NewMemory()
	for _, n := range []string{"", "Box", "a b", "a_b"} {
		if err := m.Set(n, nil); !errors.Is(err, secrets.ErrInvalidName) {
			t.Errorf("Set(%q): %v", n, err)
		}
		if _, err := m.Get(n); !errors.Is(err, secrets.ErrInvalidName) {
			t.Errorf("Get(%q): %v", n, err)
		}
		if err := m.Delete(n); !errors.Is(err, secrets.ErrInvalidName) {
			t.Errorf("Delete(%q): %v", n, err)
		}
	}
}

func TestMemoryConcurrent(t *testing.T) {
	m := NewMemory()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = m.Set(secrets.ConfigPin, []byte{byte(j)})
				_, _ = m.Get(secrets.ConfigPin)
			}
		}()
	}
	wg.Wait()
}
