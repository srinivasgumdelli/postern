package envelope

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"postern/internal/ulid"
)

type pair struct{ pub, priv *[KeySize]byte }

func newPair(t *testing.T) pair {
	t.Helper()
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return pair{pub, priv}
}

func sample() Message {
	return Message{
		ID:      ulid.New(),
		From:    "peer-a",
		To:      "peer-b",
		Thread:  NewThreadID(),
		TS:      time.Now().Unix(),
		Session: "build",
		Subject: "review request",
		Body:    "please review the change on branch x",
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	a, b := newPair(t), newPair(t)
	m := sample()
	m.ReplyTo = ulid.New()
	e, err := Seal(m, b.pub, a.priv)
	if err != nil {
		t.Fatal(err)
	}
	if e.From != m.From || e.To != m.To || e.ID != m.ID || e.Thread != m.Thread || e.TS != m.TS || e.V != Version {
		t.Fatalf("outer fields not copied: %+v", e)
	}
	raw, _ := json.Marshal(e)
	for _, secret := range []string{m.Subject, m.Body, m.Session} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("envelope JSON leaks %q", secret)
		}
	}
	got, err := Open(e, a.pub, b.priv)
	if err != nil {
		t.Fatal(err)
	}
	if got != m {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, m)
	}
}

func TestOpenWrongSenderKeyFails(t *testing.T) {
	a, b, mallory := newPair(t), newPair(t), newPair(t)
	e, err := Seal(sample(), b.pub, mallory.priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(e, a.pub, b.priv); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("got %v, want ErrDecrypt", err)
	}
}

func TestOpenWrongRecipientFails(t *testing.T) {
	a, b, c := newPair(t), newPair(t), newPair(t)
	e, err := Seal(sample(), b.pub, a.priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(e, a.pub, c.priv); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("got %v, want ErrDecrypt", err)
	}
}

func TestOpenTamperedBoxFails(t *testing.T) {
	a, b := newPair(t), newPair(t)
	e, err := Seal(sample(), b.pub, a.priv)
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := base64.StdEncoding.DecodeString(e.Box)
	for _, i := range []int{0, len(sealed) / 2, len(sealed) - 1} {
		c := append([]byte(nil), sealed...)
		c[i] ^= 0x01
		te := e
		te.Box = base64.StdEncoding.EncodeToString(c)
		if _, err := Open(te, a.pub, b.priv); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("flip at %d: got %v, want ErrDecrypt", i, err)
		}
	}
	// A different nonce also fails.
	te := e
	te.Nonce = base64.StdEncoding.EncodeToString(make([]byte, NonceSize))
	if _, err := Open(te, a.pub, b.priv); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("nonce swap: got %v, want ErrDecrypt", err)
	}
}

func TestOpenRejectsChangedRoutingFields(t *testing.T) {
	a, b := newPair(t), newPair(t)
	e, err := Seal(sample(), b.pub, a.priv)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Envelope){
		"id":     func(x *Envelope) { x.ID = ulid.New() },
		"thread": func(x *Envelope) { x.Thread = NewThreadID() },
		"ts":     func(x *Envelope) { x.TS++ },
		"from":   func(x *Envelope) { x.From = "peer-c" },
		"to":     func(x *Envelope) { x.To = "peer-c" },
	}
	for name, mutate := range cases {
		te := e
		mutate(&te)
		if _, err := Open(te, a.pub, b.priv); !errors.Is(err, ErrMismatch) {
			t.Errorf("%s changed: got %v, want ErrMismatch", name, err)
		}
	}
}

func TestSealWorstCaseBodyFitsEnvelopeCap(t *testing.T) {
	a, b := newPair(t), newPair(t)
	m := sample()
	m.Subject = strings.Repeat(`"<\>&`, MaxSubjectBytes/5)
	m.Body = strings.Repeat("\"\\<>&\n\t\x01", MaxBodyBytes/8)
	if len(m.Body) != MaxBodyBytes {
		t.Fatalf("fixture body is %d bytes", len(m.Body))
	}
	e, err := Seal(m, b.pub, a.priv)
	if err != nil {
		t.Fatalf("worst-case body rejected: %v", err)
	}
	raw, _ := json.Marshal(e)
	if len(raw) > MaxEnvelopeBytes {
		t.Fatalf("encoded envelope %d bytes > cap %d", len(raw), MaxEnvelopeBytes)
	}
	got, err := Open(e, a.pub, b.priv)
	if err != nil || got.Body != m.Body {
		t.Fatalf("worst-case round trip failed: %v", err)
	}
	if _, err := ParseEnvelope(raw); err != nil {
		t.Fatalf("ParseEnvelope: %v", err)
	}
}

func TestValidateLimits(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Message)
		want   error
	}{
		"body over cap":       {func(m *Message) { m.Body = strings.Repeat("x", MaxBodyBytes+1) }, ErrTooLarge},
		"subject over cap":    {func(m *Message) { m.Subject = strings.Repeat("x", MaxSubjectBytes+1) }, ErrTooLarge},
		"empty body":          {func(m *Message) { m.Body = "" }, ErrInvalid},
		"empty subject":       {func(m *Message) { m.Subject = "  " }, ErrInvalid},
		"subject newline":     {func(m *Message) { m.Subject = "a\nb" }, ErrInvalid},
		"subject escape":      {func(m *Message) { m.Subject = "a\x1b[2Jb" }, ErrInvalid},
		"invalid utf8 body":   {func(m *Message) { m.Body = "\xff\xfe" }, ErrInvalid},
		"bad thread":          {func(m *Message) { m.Thread = "t-4821" }, ErrInvalid},
		"free text thread":    {func(m *Message) { m.Thread = "secret project" }, ErrInvalid},
		"bad peer":            {func(m *Message) { m.To = "Peer B" }, ErrInvalid},
		"self addressed":      {func(m *Message) { m.To = m.From }, ErrInvalid},
		"bad session":         {func(m *Message) { m.Session = "../etc" }, ErrInvalid},
		"bad id":              {func(m *Message) { m.ID = "1" }, ErrInvalid},
		"bad reply_to":        {func(m *Message) { m.ReplyTo = "x" }, ErrInvalid},
		"zero ts":             {func(m *Message) { m.TS = 0 }, ErrInvalid},
		"long session":        {func(m *Message) { m.Session = strings.Repeat("a", 33) }, ErrInvalid},
		"uppercase in thread": {func(m *Message) { m.Thread = strings.ToLower(m.Thread) }, ErrInvalid},
	}
	for name, c := range cases {
		m := sample()
		c.mutate(&m)
		if err := m.Validate(); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
	if err := sample().Validate(); err != nil {
		t.Fatalf("valid sample rejected: %v", err)
	}
}

func TestSealRejectsInvalidMessage(t *testing.T) {
	a, b := newPair(t), newPair(t)
	m := sample()
	m.Body = strings.Repeat("x", MaxBodyBytes+1)
	if _, err := Seal(m, b.pub, a.priv); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
	if _, err := Seal(sample(), nil, a.priv); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil key: got %v", err)
	}
}

func TestParseEnvelopeStrict(t *testing.T) {
	a, b := newPair(t), newPair(t)
	e, err := Seal(sample(), b.pub, a.priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(e)
	if _, err := ParseEnvelope(raw); err != nil {
		t.Fatal(err)
	}
	extra := strings.Replace(string(raw), `"v":1`, `"v":1,"subject":"x"`, 1)
	if _, err := ParseEnvelope([]byte(extra)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown field: got %v", err)
	}
	if _, err := ParseEnvelope(append(raw, []byte(`{}`)...)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("trailing data: got %v", err)
	}
	if _, err := ParseEnvelope([]byte(strings.Repeat(" ", MaxEnvelopeBytes+1))); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize: got %v", err)
	}
	bad := e
	bad.V = 2
	raw, _ = json.Marshal(bad)
	if _, err := ParseEnvelope(raw); !errors.Is(err, ErrInvalid) {
		t.Fatalf("version: got %v", err)
	}
	bad = e
	bad.Nonce = base64.StdEncoding.EncodeToString(make([]byte, 12))
	raw, _ = json.Marshal(bad)
	if _, err := ParseEnvelope(raw); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short nonce: got %v", err)
	}
}

func TestCheckTime(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	ok := []time.Time{now, now.Add(-9 * time.Minute), now.Add(9 * time.Minute)}
	for _, ts := range ok {
		if err := CheckTime(ts.Unix(), now, ClockSkew); err != nil {
			t.Errorf("%v: %v", ts, err)
		}
	}
	stale := []time.Time{now.Add(-11 * time.Minute), now.Add(11 * time.Minute)}
	for _, ts := range stale {
		if err := CheckTime(ts.Unix(), now, ClockSkew); !errors.Is(err, ErrStale) {
			t.Errorf("%v: got %v, want ErrStale", ts, err)
		}
	}
	if err := CheckTime(now.Add(-71*time.Hour).Unix(), now, Retention); err != nil {
		t.Errorf("71h old within retention: %v", err)
	}
	if err := CheckTime(now.Add(-73*time.Hour).Unix(), now, Retention); !errors.Is(err, ErrStale) {
		t.Errorf("73h old: got %v", err)
	}
}

func TestKeyEncodingAndFingerprint(t *testing.T) {
	p := newPair(t)
	s := EncodeKey(p.pub)
	k, err := DecodeKey(s)
	if err != nil || *k != *p.pub {
		t.Fatalf("key round trip failed: %v", err)
	}
	if _, err := DecodeKey(base64.StdEncoding.EncodeToString(make([]byte, 31))); err == nil {
		t.Fatal("short key accepted")
	}
	fp := Fingerprint(p.pub)
	if len(fp) != 8*4+7 || strings.Count(fp, " ") != 7 {
		t.Fatalf("fingerprint format %q", fp)
	}
	if fp != Fingerprint(p.pub) {
		t.Fatal("fingerprint not deterministic")
	}
	if fp == Fingerprint(newPair(t).pub) {
		t.Fatal("different keys share a fingerprint")
	}
}

func TestThreadIDs(t *testing.T) {
	id := NewThreadID()
	if !ValidThreadID(id) {
		t.Fatalf("NewThreadID() = %q invalid", id)
	}
	for _, s := range []string{"t-4821", "x-" + ulid.New(), "t-" + ulid.New() + "0", ""} {
		if ValidThreadID(s) {
			t.Errorf("ValidThreadID(%q) = true", s)
		}
	}
}

func TestNames(t *testing.T) {
	for _, s := range []string{"peer-a", "a", "build-2", strings.Repeat("a", 32)} {
		if !ValidPeerName(s) {
			t.Errorf("ValidPeerName(%q) = false", s)
		}
	}
	for _, s := range []string{"", "-a", "Peer", "a b", "a_b", "a.b", strings.Repeat("a", 33)} {
		if ValidPeerName(s) {
			t.Errorf("ValidPeerName(%q) = true", s)
		}
	}
}
