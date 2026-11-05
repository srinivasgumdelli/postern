package conformance

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"postern/internal/envelope"
	"postern/internal/ulid"
)

// fixturePath is the shared fixture, relative to this package.
var fixturePath = filepath.Join("..", "..", "testdata", "conformance", "envelopes.json")

// Expected outcomes. "valid" means envelope.ParseEnvelope accepts the
// envelope (the relay may still answer 403, 422 or 409 for reasons that
// are not about its encoding); "invalid" is a 400 and "too_large" a 413.
const (
	expectValid    = "valid"
	expectInvalid  = "invalid"
	expectTooLarge = "too_large"
)

// Case is one fixture entry. Canonical is set for valid cases: the
// envelope re-encoded with json.Marshal, which is what a relay stores and
// hands to the recipient.
type Case struct {
	Name         string `json:"name"`
	EnvelopeJSON string `json:"envelope_json"`
	Expect       string `json:"expect"`
	Canonical    string `json:"canonical,omitempty"`
}

// fixedTS is the ts of every generated envelope (2026-11-04). Fixture
// envelopes are stale by the time anyone reads them; tests that post them
// to a relay set the relay's clock to this value.
const fixedTS = 1793824000

// field is one key and its raw JSON value, in output order.
type field struct{ key, raw string }

type doc []field

func (d doc) String() string {
	var b strings.Builder
	b.WriteByte('{')
	for i, f := range d {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(q(f.key))
		b.WriteByte(':')
		b.WriteString(f.raw)
	}
	b.WriteByte('}')
	return b.String()
}

// with returns a copy of d with key's raw value replaced.
func (d doc) with(key, raw string) doc {
	out := append(doc{}, d...)
	for i := range out {
		if out[i].key == key {
			out[i].raw = raw
			return out
		}
	}
	panic("no field " + key)
}

// without returns a copy of d without key.
func (d doc) without(key string) doc {
	var out doc
	for _, f := range d {
		if f.key != key {
			out = append(out, f)
		}
	}
	return out
}

// rekeyRaw renders d with key's name replaced by rawKey (raw JSON text).
func (d doc) rekeyRaw(key, rawKey string) string {
	s := d.String()
	return strings.Replace(s, q(key)+":", rawKey+":", 1)
}

func q(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		panic(err)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func fieldsOf(e envelope.Envelope) doc {
	return doc{
		{"v", fmt.Sprint(e.V)},
		{"id", q(e.ID)},
		{"from", q(e.From)},
		{"to", q(e.To)},
		{"thread", q(e.Thread)},
		{"ts", fmt.Sprint(e.TS)},
		{"nonce", q(e.Nonce)},
		{"box", q(e.Box)},
	}
}

type generator struct {
	t     testing.TB
	pub   map[string]*[envelope.KeySize]byte
	priv  map[string]*[envelope.KeySize]byte
	cases []Case
}

func newGenerator(t testing.TB) *generator {
	return &generator{t: t, pub: map[string]*[envelope.KeySize]byte{}, priv: map[string]*[envelope.KeySize]byte{}}
}

// keys returns a key pair for name, generated at runtime. No key is ever
// written to the fixture.
func (g *generator) keys(name string) (*[envelope.KeySize]byte, *[envelope.KeySize]byte) {
	if g.pub[name] == nil {
		pub, priv, err := envelope.GenerateKey()
		if err != nil {
			g.t.Fatal(err)
		}
		g.pub[name], g.priv[name] = pub, priv
	}
	return g.pub[name], g.priv[name]
}

// seal builds a real sealed envelope from -> to.
func (g *generator) seal(from, to string) envelope.Envelope {
	_, senderPriv := g.keys(from)
	recipientPub, _ := g.keys(to)
	at := time.Unix(fixedTS, 0)
	m := envelope.Message{
		ID:      ulid.NewAt(at),
		From:    from,
		To:      to,
		Thread:  "t-" + ulid.NewAt(at),
		TS:      fixedTS,
		Session: "main",
		Subject: "conformance",
		Body:    "a conformance test message",
	}
	e, err := envelope.Seal(m, recipientPub, senderPriv)
	if err != nil {
		g.t.Fatal(err)
	}
	return e
}

func (g *generator) add(name, raw, expect string) {
	c := Case{Name: name, EnvelopeJSON: raw, Expect: expect}
	if expect == expectValid {
		e, err := envelope.ParseEnvelope([]byte(raw))
		if err != nil {
			g.t.Fatalf("generator: case %q meant to be valid: %v", name, err)
		}
		canon, err := json.Marshal(e)
		if err != nil {
			g.t.Fatal(err)
		}
		c.Canonical = string(canon)
	}
	g.cases = append(g.cases, c)
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// sorted iterates m in key order, so the fixture's case order is stable.
func sorted(m map[string]string) iter.Seq2[string, string] {
	return func(yield func(string, string) bool) {
		for _, k := range slices.Sorted(maps.Keys(m)) {
			if !yield(k, m[k]) {
				return
			}
		}
	}
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// buildCases returns every case. The names and outcomes are fixed; the
// keys, nonces and ciphertext are fresh on every run.
func buildCases(t testing.TB) []Case {
	g := newGenerator(t)
	base := g.seal("peer-a", "peer-b")
	d := fieldsOf(base)
	canon := d.String()
	id, thread := base.ID, base.Thread
	ulidPart := thread[2:]

	// --- valid ---
	g.add("sealed peer-a to peer-b", canon, expectValid)
	g.add("sealed peer-b to peer-a", fieldsOf(g.seal("peer-b", "peer-a")).String(), expectValid)
	g.add("longest peer names", fieldsOf(g.seal(strings.Repeat("a", 32), strings.Repeat("b", 31)+"-")).String(), expectValid)
	g.add("shortest peer names", fieldsOf(g.seal("a", "0")).String(), expectValid)
	g.add("peer names with digits and hyphens", fieldsOf(g.seal("0-peer--1", "p-2-")).String(), expectValid)
	reordered := doc{d[7], d[6], d[5], d[4], d[3], d[2], d[1], d[0]}
	g.add("keys in another order", reordered.String(), expectValid)
	g.add("whitespace between tokens", " \t\r\n"+strings.ReplaceAll(strings.ReplaceAll(canon, ":", " :\n\t"), ",", " ,\r\n ")+"\n ", expectValid)
	g.add("unicode escape in a key", strings.Replace(canon, `"v":`, `"v":`, 1), expectValid)
	g.add("unicode escapes in values", d.with("id", fmt.Sprintf(`"\u%04x%s"`, id[0], id[1:])).with("thread", `"t-`+ulidPart+`"`).String(), expectValid)
	slashBox := b64(bytes.Repeat([]byte{0xff}, 21)) // "////..."
	g.add("escaped solidus in box", d.with("box", `"`+strings.ReplaceAll(slashBox, "/", `\/`)+`"`).String(), expectValid)
	g.add("shortest box (overhead plus 4 bytes)", d.with("box", q(b64(make([]byte, 20)))).String(), expectValid)
	g.add("nonce with CR LF (ignored by strict base64)", d.with("nonce", q(base.Nonce[:16]+"\r\n"+base.Nonce[16:])).String(), expectValid)
	g.add("box with LF (ignored by strict base64)", d.with("box", q(base.Box[:8]+"\n"+base.Box[8:])).String(), expectValid)
	g.add("ts of 1", d.with("ts", "1").String(), expectValid)
	g.add("ts at int64 max", d.with("ts", "9223372036854775807").String(), expectValid)
	pad := envelope.MaxEnvelopeBytes - len(canon)
	g.add("exactly the size cap", "{"+strings.Repeat(" ", pad)+canon[1:], expectValid)

	// --- too large ---
	g.add("one byte over the size cap", "{"+strings.Repeat(" ", pad+1)+canon[1:], expectTooLarge)
	g.add("box over the size cap", d.with("box", q(strings.Repeat("A", envelope.MaxEnvelopeBytes))).String(), expectTooLarge)
	g.add("oversize non-JSON", strings.Repeat("A", envelope.MaxEnvelopeBytes+1), expectTooLarge)

	// --- document structure ---
	inv := func(name, raw string) { g.add(name, raw, expectInvalid) }
	inv("empty", "")
	inv("only whitespace", " \n")
	inv("not JSON", "hello")
	inv("JSON null", "null")
	inv("JSON array", "["+canon+"]")
	inv("JSON string", q(canon))
	inv("JSON number", "1")
	inv("JSON true", "true")
	inv("empty object", "{}")
	inv("trailing object", canon+"{}")
	inv("trailing garbage", canon+"x")
	inv("trailing comma after object", canon+",")
	inv("trailing comma inside object", strings.TrimSuffix(canon, "}")+",}")
	inv("byte order mark", "\ufeff"+canon)
	inv("non-breaking space between tokens", strings.Replace(canon, ",", ",\u00a0", 1))
	inv("comment", "/* c */"+canon)
	inv("single-quoted key", strings.Replace(canon, `"v":`, `'v':`, 1))
	inv("unquoted key", strings.Replace(canon, `"v":`, `v:`, 1))
	inv("truncated", canon[:len(canon)-1])
	inv("unterminated string", canon[:len(canon)-2])
	inv("raw tab inside a string", d.with("thread", "\"t-\t"+ulidPart+"\"").String())
	inv("raw newline inside a string", d.with("id", "\""+id[:10]+"\n"+id[10:]+"\"").String())
	inv("invalid escape", d.with("id", `"\x`+id[1:]+`"`).String())
	inv("lone surrogate escape", d.with("id", `"\ud800`+id[1:]+`"`).String())
	inv("deeply nested array", strings.Repeat("[", 1000)+strings.Repeat("]", 1000))
	inv("object value", d.with("v", `{"v":1}`).String())
	inv("array value", d.with("id", "["+q(id)+"]").String())

	// --- keys ---
	inv("unknown key", strings.TrimSuffix(canon, "}")+`,"extra":1}`)
	inv("inner header key", strings.TrimSuffix(canon, "}")+`,"subject":"x"}`)
	inv("inner session key", strings.TrimSuffix(canon, "}")+`,"session":"main"}`)
	inv("duplicate key with the same value", strings.TrimSuffix(canon, "}")+`,"v":1}`)
	inv("duplicate id, different value", strings.TrimSuffix(canon, "}")+`,"id":`+q(ulid.NewAt(time.Unix(fixedTS, 0)))+`}`)
	inv("duplicate key via escape", strings.TrimSuffix(canon, "}")+`,"box":`+q(base.Box)+`}`)
	inv("upper-case key ID", d.rekeyRaw("id", `"ID"`))
	inv("upper-case key V", d.rekeyRaw("v", `"V"`))
	inv("mixed-case key From", d.rekeyRaw("from", `"From"`))
	inv("key with trailing space", d.rekeyRaw("box", `"box "`))
	inv("empty key", strings.TrimSuffix(canon, "}")+`,"":1}`)
	for _, f := range d {
		inv("missing "+f.key, d.without(f.key).String())
		inv("null "+f.key, d.with(f.key, "null").String())
	}

	// --- v ---
	for name, raw := range sorted(map[string]string{
		"v 2": "2", "v 0": "0", "v -1": "-1", "v as string": `"1"`, "v 1.0": "1.0",
		"v 1e0": "1e0", "v 1E0": "1E0", "v true": "true", "v with leading zero": "01",
		"v with plus sign": "+1", "v 1.5": "1.5",
	}) {
		inv(name, d.with("v", raw).String())
	}

	// --- id ---
	for name, val := range sorted(map[string]string{
		"id lower case":           strings.ToLower(id),
		"id 25 characters":        id[:25],
		"id 27 characters":        id + "0",
		"id first character 8":    "8" + id[1:],
		"id with I":               id[:25] + "I",
		"id with L":               id[:25] + "L",
		"id with O":               id[:25] + "O",
		"id with U":               id[:25] + "U",
		"id with trailing LF":     id + "\n",
		"id with leading space":   " " + id[1:],
		"id empty":                "",
		"id is the thread id":     thread,
		"id with non-ASCII digit": id[:25] + "\u0661",
	}) {
		inv(name, d.with("id", q(val)).String())
	}
	inv("id as number", d.with("id", "12345678901234567890123456").String())

	// --- from / to ---
	for name, val := range sorted(map[string]string{
		"upper case":        "Peer-a",
		"leading hyphen":    "-peer",
		"33 characters":     strings.Repeat("a", 33),
		"empty":             "",
		"non-ASCII letter":  "p\u00e9er",
		"space":             "peer a",
		"underscore":        "peer_a",
		"dot":               "peer.a",
		"trailing LF":       "peer-a\n",
		"fullwidth letters": "\uff50\uff45\uff45\uff52",
	}) {
		inv("from "+name, d.with("from", q(val)).String())
		inv("to "+name, d.with("to", q(val)).String())
	}
	inv("from as number", d.with("from", "1").String())
	inv("to equals from", d.with("to", q(base.From)).String())

	// --- thread ---
	for name, val := range sorted(map[string]string{
		"thread without prefix":        ulidPart,
		"thread with x- prefix":        "x-" + ulidPart,
		"thread with T- prefix":        "T-" + ulidPart,
		"thread lower case":            "t-" + strings.ToLower(ulidPart),
		"thread first character 8":     "t-8" + ulidPart[1:],
		"thread too short":             thread[:len(thread)-1],
		"thread too long":              thread + "0",
		"thread with L":                thread[:len(thread)-1] + "L",
		"thread with trailing LF":      thread + "\n",
		"thread free text":             "t-free text",
		"thread empty":                 "",
		"thread prefix only":           "t-",
		"thread with double prefix":    "t-t-" + ulidPart[2:],
		"thread with non-ASCII prefix": "\u0442-" + ulidPart,
	}) {
		inv(name, d.with("thread", q(val)).String())
	}

	// --- ts ---
	for name, raw := range sorted(map[string]string{
		"ts 0": "0", "ts -1": "-1", "ts -0": "-0", "ts 1.5": "1.5", "ts 1e9": "1e9",
		"ts as string": q(fmt.Sprint(fixedTS)), "ts over int64": "9223372036854775808",
		"ts far over int64": "1e400", "ts with leading zero": "0" + fmt.Sprint(fixedTS),
		"ts true": "true", "ts with fraction zero": fmt.Sprint(fixedTS) + ".0",
		"ts min int64": "-9223372036854775808",
	}) {
		inv(name, d.with("ts", raw).String())
	}

	// --- nonce ---
	n24 := randomBytes(24)
	for name, val := range sorted(map[string]string{
		"nonce empty":                  "",
		"nonce 23 bytes":               b64(n24[:23]),
		"nonce 25 bytes":               b64(append(append([]byte{}, n24...), 0)),
		"nonce 12 bytes":               b64(n24[:12]),
		"nonce URL-safe alphabet":      "-" + base.Nonce[1:],
		"nonce URL-safe underscore":    "_" + base.Nonce[1:],
		"nonce with space":             base.Nonce[:16] + " " + base.Nonce[16:],
		"nonce with tab":               base.Nonce[:16] + "\t" + base.Nonce[16:],
		"nonce with invalid character": "!" + base.Nonce[1:],
		"nonce raw (not base64)":       string(bytes.Repeat([]byte("n"), 24)),
		"nonce with padding inside":    base.Nonce[:16] + "=" + base.Nonce[17:],
	}) {
		inv(name, d.with("nonce", q(val)).String())
	}
	inv("nonce as number", d.with("nonce", "123").String())

	zero20 := b64(make([]byte, 20)) // 27 'A' and one '='
	for name, val := range sorted(map[string]string{
		"box empty":                   "",
		"box 19 bytes":                b64(make([]byte, 19)),
		"box non-zero padding bits":   zero20[:26] + "B=",
		"box missing padding":         strings.TrimRight(zero20, "="),
		"box extra padding":           zero20 + "=",
		"box URL-safe alphabet":       "-" + base.Box[1:],
		"box with space":              base.Box[:8] + " " + base.Box[8:],
		"box with invalid character":  base.Box[:8] + "!" + base.Box[9:],
		"box with padding inside":     "AAA=" + zero20,
		"box not base64":              "!!!",
		"box length not a multiple 4": base.Box + "A",
	}) {
		inv(name, d.with("box", q(val)).String())
	}
	inv("box as number", d.with("box", "1").String())
	return g.cases
}

func readFixture(t *testing.T) []Case {
	t.Helper()
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture (regenerate with POSTERN_WRITE_CONFORMANCE=1): %v", err)
	}
	var cases []Case
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cases); err != nil {
		t.Fatal(err)
	}
	return cases
}

// TestWriteConformance regenerates the fixture. It is skipped unless
// POSTERN_WRITE_CONFORMANCE=1.
func TestWriteConformance(t *testing.T) {
	if os.Getenv("POSTERN_WRITE_CONFORMANCE") != "1" {
		t.Skip("set POSTERN_WRITE_CONFORMANCE=1 to regenerate the fixture")
	}
	cases := buildCases(t)
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cases); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(fixturePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixturePath, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d cases to %s", len(cases), fixturePath)
}

// TestFixtureMatchesGenerator fails when the committed fixture no longer
// has the generator's cases (names and outcomes), so neither can drift.
func TestFixtureMatchesGenerator(t *testing.T) {
	want := buildCases(t)
	got := readFixture(t)
	if len(got) != len(want) {
		t.Fatalf("fixture has %d cases, generator %d: regenerate with POSTERN_WRITE_CONFORMANCE=1", len(got), len(want))
	}
	names := map[string]bool{}
	for i := range want {
		if got[i].Name != want[i].Name || got[i].Expect != want[i].Expect {
			t.Fatalf("case %d: fixture %q/%s, generator %q/%s: regenerate", i, got[i].Name, got[i].Expect, want[i].Name, want[i].Expect)
		}
		if names[got[i].Name] {
			t.Fatalf("duplicate case name %q", got[i].Name)
		}
		names[got[i].Name] = true
	}
}

// TestFixtureAgainstParseEnvelope runs every committed case through the
// Go relay's parser.
func TestFixtureAgainstParseEnvelope(t *testing.T) {
	cases := readFixture(t)
	counts := map[string]int{}
	for _, c := range cases {
		counts[c.Expect]++
		t.Run(c.Name, func(t *testing.T) {
			e, err := envelope.ParseEnvelope([]byte(c.EnvelopeJSON))
			switch c.Expect {
			case expectValid:
				if err != nil {
					t.Fatalf("want valid, got %v", err)
				}
				canon, _ := json.Marshal(e)
				if string(canon) != c.Canonical {
					t.Fatalf("canonical form differs:\n got %s\nwant %s", canon, c.Canonical)
				}
			case expectTooLarge:
				if !errors.Is(err, envelope.ErrTooLarge) {
					t.Fatalf("want too_large, got %v", err)
				}
			case expectInvalid:
				if !errors.Is(err, envelope.ErrInvalid) || errors.Is(err, envelope.ErrTooLarge) {
					t.Fatalf("want invalid, got %v", err)
				}
				if c.Canonical != "" {
					t.Fatal("invalid case has a canonical form")
				}
			default:
				t.Fatalf("unknown expectation %q", c.Expect)
			}
		})
	}
	if counts[expectValid] == 0 || counts[expectInvalid] == 0 || counts[expectTooLarge] == 0 {
		t.Fatalf("fixture lacks a category: %v", counts)
	}
}
