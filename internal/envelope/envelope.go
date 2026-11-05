// Package envelope builds, seals, opens and validates Postern messages.
//
// The relay sees only the outer Envelope. Everything else, including the
// sender's session name, travels inside a NaCl box. The sealed inner
// message repeats every routing field so that Open can reject an
// envelope whose outer fields were changed in transit.
package envelope

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"

	"postern/internal/ulid"
)

// Protocol limits. These are part of the wire contract.
const (
	Version          = 1
	MaxBodyBytes     = 32 * 1024
	MaxSubjectBytes  = 256
	MaxEnvelopeBytes = 48 * 1024
	ClockSkew        = 10 * time.Minute
	Retention        = 72 * time.Hour
	NonceSize        = 24
	KeySize          = 32

	maxHeaderBytes = 8 * 1024
)

// Errors returned by this package. Callers match with errors.Is.
var (
	ErrInvalid  = errors.New("envelope: invalid")
	ErrDecrypt  = errors.New("envelope: cannot open box")
	ErrMismatch = errors.New("envelope: sealed fields do not match envelope")
	ErrTooLarge = errors.New("envelope: too large")
	ErrStale    = errors.New("envelope: timestamp outside allowed window")
)

// Envelope is what the relay stores. Only routing fields are readable.
type Envelope struct {
	V      int    `json:"v"`
	ID     string `json:"id"`
	From   string `json:"from"`
	To     string `json:"to"`
	Thread string `json:"thread"`
	TS     int64  `json:"ts"`
	Nonce  string `json:"nonce"`
	Box    string `json:"box"`
}

// Message is the plaintext a bridge seals and opens.
type Message struct {
	ID      string
	From    string
	To      string
	Thread  string
	TS      int64
	Session string
	Subject string
	Body    string
	ReplyTo string
}

// header is the JSON part of the sealed inner message. The body follows
// it as raw bytes so it is never JSON-escaped (a 32 KB body always fits
// the envelope cap).
type header struct {
	V       int    `json:"v"`
	ID      string `json:"id"`
	From    string `json:"from"`
	To      string `json:"to"`
	Thread  string `json:"thread"`
	TS      int64  `json:"ts"`
	Session string `json:"session"`
	Subject string `json:"subject"`
	ReplyTo string `json:"reply_to,omitempty"`
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Validate checks a plaintext message against the protocol limits.
func (m Message) Validate() error {
	if !ulid.Valid(m.ID) {
		return invalid("id")
	}
	if !ValidPeerName(m.From) || !ValidPeerName(m.To) {
		return invalid("peer name")
	}
	if m.From == m.To {
		return invalid("from equals to")
	}
	if !ValidThreadID(m.Thread) {
		return invalid("thread")
	}
	if m.TS <= 0 {
		return invalid("ts")
	}
	if !ValidSessionName(m.Session) {
		return invalid("session")
	}
	if m.ReplyTo != "" && !ulid.Valid(m.ReplyTo) {
		return invalid("reply_to")
	}
	if len(m.Subject) > MaxSubjectBytes {
		return fmt.Errorf("%w: subject over %d bytes", ErrTooLarge, MaxSubjectBytes)
	}
	if strings.TrimSpace(m.Subject) == "" || !utf8.ValidString(m.Subject) {
		return invalid("subject")
	}
	for _, r := range m.Subject {
		if unicode.IsControl(r) {
			return invalid("subject contains control characters")
		}
	}
	if len(m.Body) > MaxBodyBytes {
		return fmt.Errorf("%w: body over %d bytes", ErrTooLarge, MaxBodyBytes)
	}
	if m.Body == "" || !utf8.ValidString(m.Body) {
		return invalid("body")
	}
	return nil
}

// ValidateOuter checks the readable fields of an envelope. It does not
// open the box.
func (e Envelope) ValidateOuter() error {
	if e.V != Version {
		return invalid("version")
	}
	if !ulid.Valid(e.ID) {
		return invalid("id")
	}
	if !ValidPeerName(e.From) || !ValidPeerName(e.To) {
		return invalid("peer name")
	}
	if e.From == e.To {
		return invalid("from equals to")
	}
	if !ValidThreadID(e.Thread) {
		return invalid("thread")
	}
	if e.TS <= 0 {
		return invalid("ts")
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(e.Nonce)
	if err != nil || len(nonce) != NonceSize {
		return invalid("nonce")
	}
	if len(e.Box) > MaxEnvelopeBytes {
		return fmt.Errorf("%w: box", ErrTooLarge)
	}
	sealed, err := base64.StdEncoding.Strict().DecodeString(e.Box)
	if err != nil || len(sealed) < box.Overhead+4 {
		return invalid("box")
	}
	return nil
}

// envelopeKeys are the only keys an envelope object may have.
var envelopeKeys = map[string]bool{
	"v": true, "id": true, "from": true, "to": true,
	"thread": true, "ts": true, "nonce": true, "box": true,
}

// ParseEnvelope decodes one JSON envelope strictly (no unknown,
// duplicate or case-folded keys, no trailing data) and validates its
// outer fields. Every relay implementation must accept exactly the same
// envelopes: testdata/conformance holds the cases they share.
func ParseEnvelope(data []byte) (Envelope, error) {
	if len(data) > MaxEnvelopeBytes {
		return Envelope{}, ErrTooLarge
	}
	if err := checkKeys(data, envelopeKeys); err != nil {
		return Envelope{}, invalid("json")
	}
	var e Envelope
	if err := decodeStrict(data, &e); err != nil {
		return Envelope{}, invalid("json")
	}
	if err := e.ValidateOuter(); err != nil {
		return Envelope{}, err
	}
	return e, nil
}

// Seal validates m and seals it for the recipient. The returned
// envelope's readable fields are copied from m.
func Seal(m Message, recipientPub, senderPriv *[KeySize]byte) (Envelope, error) {
	if recipientPub == nil || senderPriv == nil {
		return Envelope{}, invalid("missing key")
	}
	if err := m.Validate(); err != nil {
		return Envelope{}, err
	}
	var hdr bytes.Buffer
	enc := json.NewEncoder(&hdr)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(header{
		V: Version, ID: m.ID, From: m.From, To: m.To, Thread: m.Thread, TS: m.TS,
		Session: m.Session, Subject: m.Subject, ReplyTo: m.ReplyTo,
	}); err != nil {
		return Envelope{}, invalid("header")
	}
	if hdr.Len() > maxHeaderBytes {
		return Envelope{}, fmt.Errorf("%w: header", ErrTooLarge)
	}
	inner := make([]byte, 4, 4+hdr.Len()+len(m.Body))
	binary.BigEndian.PutUint32(inner, uint32(hdr.Len()))
	inner = append(inner, hdr.Bytes()...)
	inner = append(inner, m.Body...)

	var nonce [NonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return Envelope{}, fmt.Errorf("envelope: nonce: %w", err)
	}
	sealed := box.Seal(nil, inner, &nonce, recipientPub, senderPriv)
	clear(inner)

	e := Envelope{
		V: Version, ID: m.ID, From: m.From, To: m.To, Thread: m.Thread, TS: m.TS,
		Nonce: base64.StdEncoding.EncodeToString(nonce[:]),
		Box:   base64.StdEncoding.EncodeToString(sealed),
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return Envelope{}, invalid("marshal")
	}
	if len(raw) > MaxEnvelopeBytes {
		return Envelope{}, fmt.Errorf("%w: encoded envelope over %d bytes", ErrTooLarge, MaxEnvelopeBytes)
	}
	return e, nil
}

// Open authenticates and decrypts e using the sender's pinned public key
// and the recipient's private key. It fails if the box does not open, if
// any sealed routing field differs from the envelope, or if the message
// breaks the protocol limits.
func Open(e Envelope, senderPub, recipientPriv *[KeySize]byte) (Message, error) {
	if senderPub == nil || recipientPriv == nil {
		return Message{}, invalid("missing key")
	}
	if err := e.ValidateOuter(); err != nil {
		return Message{}, err
	}
	nonceBytes, _ := base64.StdEncoding.Strict().DecodeString(e.Nonce)
	sealed, _ := base64.StdEncoding.Strict().DecodeString(e.Box)
	var nonce [NonceSize]byte
	copy(nonce[:], nonceBytes)

	inner, ok := box.Open(nil, sealed, &nonce, senderPub, recipientPriv)
	if !ok {
		return Message{}, ErrDecrypt
	}
	defer clear(inner)
	if len(inner) < 4 {
		return Message{}, invalid("inner")
	}
	hlen := binary.BigEndian.Uint32(inner[:4])
	if hlen == 0 || hlen > maxHeaderBytes || int(hlen) > len(inner)-4 {
		return Message{}, invalid("inner header length")
	}
	var h header
	if err := decodeStrict(inner[4:4+hlen], &h); err != nil {
		return Message{}, invalid("inner header")
	}
	if h.V != e.V || h.ID != e.ID || h.From != e.From || h.To != e.To ||
		h.Thread != e.Thread || h.TS != e.TS {
		return Message{}, ErrMismatch
	}
	m := Message{
		ID: h.ID, From: h.From, To: h.To, Thread: h.Thread, TS: h.TS,
		Session: h.Session, Subject: h.Subject, ReplyTo: h.ReplyTo,
		Body: string(inner[4+hlen:]),
	}
	if err := m.Validate(); err != nil {
		return Message{}, err
	}
	return m, nil
}

// CheckTime reports ErrStale if ts is more than ClockSkew in the future
// or older than maxAge.
func CheckTime(ts int64, now time.Time, maxAge time.Duration) error {
	t := time.Unix(ts, 0)
	if t.After(now.Add(ClockSkew)) {
		return fmt.Errorf("%w: in the future", ErrStale)
	}
	if t.Before(now.Add(-maxAge)) {
		return fmt.Errorf("%w: too old", ErrStale)
	}
	return nil
}

// GenerateKey returns a new X25519 key pair for sealing.
func GenerateKey() (pub, priv *[KeySize]byte, err error) {
	return box.GenerateKey(rand.Reader)
}

// PublicKey derives the X25519 public key for a private key.
func PublicKey(priv *[KeySize]byte) (*[KeySize]byte, error) {
	if priv == nil {
		return nil, invalid("missing key")
	}
	b, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, invalid("key")
	}
	var pub [KeySize]byte
	copy(pub[:], b)
	return &pub, nil
}

// EncodeKey returns the standard base64 form of a key.
func EncodeKey(k *[KeySize]byte) string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// DecodeKey parses a base64 key and checks its length.
func DecodeKey(s string) (*[KeySize]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != KeySize {
		return nil, invalid("key")
	}
	var k [KeySize]byte
	copy(k[:], b)
	clear(b)
	return &k, nil
}

// Fingerprint returns a short, human-comparable digest of a public key:
// the first 16 bytes of its SHA-256, hex, in 8 groups of 4.
func Fingerprint(pub *[KeySize]byte) string {
	sum := sha256.Sum256(pub[:])
	h := hex.EncodeToString(sum[:16])
	groups := make([]string, 0, 8)
	for i := 0; i < len(h); i += 4 {
		groups = append(groups, h[i:i+4])
	}
	return strings.Join(groups, " ")
}

// checkKeys rejects a top-level JSON object that has a key not exactly
// in allowed, or the same key twice. encoding/json alone matches keys
// case-insensitively and keeps the last of two duplicates, which parsers
// in other languages do not reproduce. Anything that is not an object is
// left to decodeStrict.
func checkKeys(data []byte, allowed map[string]bool) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil
	}
	seen := make(map[string]bool, len(allowed))
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok || !allowed[key] || seen[key] {
			return errors.New("unexpected key")
		}
		seen[key] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return err
		}
	}
	return nil
}

func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}
