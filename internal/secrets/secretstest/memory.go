// Package secretstest provides an in-memory secrets.Store.
//
// It is for tests only and must never be used in production code: the
// bridge keeps keys in the OS keychain and nowhere else.
package secretstest

import (
	"sync"

	"postern/internal/secrets"
)

// Memory is an in-memory secrets.Store for tests. It copies values in
// and out and is safe for concurrent use. It applies the same name
// rules as the keychain so tests catch names production would reject.
type Memory struct {
	mu    sync.Mutex
	items map[string][]byte
}

var _ secrets.Store = (*Memory)(nil)

// NewMemory returns an empty store. Tests only; never production.
func NewMemory() *Memory {
	return &Memory{items: make(map[string][]byte)}
}

func (m *Memory) Get(name string) ([]byte, error) {
	if !secrets.ValidName(name) {
		return nil, secrets.ErrInvalidName
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.items[name]
	if !ok {
		return nil, secrets.ErrNotFound
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

func (m *Memory) Set(name string, value []byte) error {
	if !secrets.ValidName(name) {
		return secrets.ErrInvalidName
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.items[name]; ok {
		clear(old)
	}
	v := make([]byte, len(value))
	copy(v, value)
	m.items[name] = v
	return nil
}

func (m *Memory) Delete(name string) error {
	if !secrets.ValidName(name) {
		return secrets.ErrInvalidName
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.items[name]
	if !ok {
		return secrets.ErrNotFound
	}
	clear(v)
	delete(m.items, name)
	return nil
}
