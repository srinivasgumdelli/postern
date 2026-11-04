package bridge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

// Inbox encryption at rest.
//
// The local database is readable by anything running as the same OS user,
// including agent sessions that never called check_inbox (so the session
// guard never tainted them). Subjects, bodies and session names are
// therefore sealed per row with NaCl secretbox under a key derived from
// Options.InboxKey, which lives in the OS keychain, never on disk.
//
// One blob per row: nonce (24 bytes) || secretbox(JSON {id, session,
// subject, body}). The row id is inside the box and checked on open, so a
// blob cannot be moved to another row. Outbound rows also carry a keyed
// tag of the session name (HMAC-SHA256, truncated) so that the per-session
// rate limit can be counted without decrypting anything.

const (
	nonceLen      = 24
	sessionTagLen = 16
	keyCheckID    = "key-check"
)

var errOpenRow = errors.New("bridge: stored row cannot be decrypted")

type inboxCrypto struct {
	sealKey [32]byte
	tagKey  [32]byte
}

func deriveKey(root *[32]byte, label string) [32]byte {
	m := hmac.New(sha256.New, root[:])
	m.Write([]byte(label))
	var k [32]byte
	copy(k[:], m.Sum(nil))
	return k
}

func newInboxCrypto(root *[32]byte) *inboxCrypto {
	return &inboxCrypto{
		sealKey: deriveKey(root, "postern inbox v2 seal"),
		tagKey:  deriveKey(root, "postern inbox v2 session tag"),
	}
}

func (c *inboxCrypto) wipe() {
	clear(c.sealKey[:])
	clear(c.tagKey[:])
}

type rowContent struct {
	ID      string `json:"id"`
	Session string `json:"session"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

func (c *inboxCrypto) seal(id, session, subject, body string) ([]byte, error) {
	pt, err := json.Marshal(rowContent{ID: id, Session: session, Subject: subject, Body: body})
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	var nonce [nonceLen]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	return secretbox.Seal(nonce[:], pt, &nonce, &c.sealKey), nil
}

func (c *inboxCrypto) open(id string, blob []byte) (rowContent, error) {
	if len(blob) < nonceLen+secretbox.Overhead {
		return rowContent{}, errOpenRow
	}
	var nonce [nonceLen]byte
	copy(nonce[:], blob[:nonceLen])
	pt, ok := secretbox.Open(nil, blob[nonceLen:], &nonce, &c.sealKey)
	if !ok {
		return rowContent{}, errOpenRow
	}
	defer clear(pt)
	var rc rowContent
	if err := json.Unmarshal(pt, &rc); err != nil || rc.ID != id {
		return rowContent{}, errOpenRow
	}
	return rc, nil
}

func (c *inboxCrypto) sessionTag(session string) []byte {
	m := hmac.New(sha256.New, c.tagKey[:])
	m.Write([]byte(session))
	return m.Sum(nil)[:sessionTagLen]
}
