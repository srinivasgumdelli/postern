package relay

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"postern/internal/envelope"
)

// TestRelayStoresNoPlaintext seals a real message whose subject, body and
// session carry marker strings, posts it, and checks that none of them
// appear in the database file, its WAL or its shared-memory file, while
// the store is open and again after it is closed and checkpointed.
func TestRelayStoresNoPlaintext(t *testing.T) {
	f := newFixture(t, nil)
	const (
		subjectMarker = "SUBJECTMARKER-q7Zr41"
		bodyMarker    = "BODYMARKER-p0Xw93"
		sessionMarker = "sessmarker-k5v2"
	)
	m := f.msg("peer-a", "peer-b")
	m.Subject = "review " + subjectMarker
	m.Body = strings.Repeat("line with "+bodyMarker+"\n", 50)
	m.Session = sessionMarker
	e, raw := f.sealMsg(m)
	f.mustPost("peer-a", raw)

	markers := []string{subjectMarker, bodyMarker, sessionMarker}
	// Also check the base64 forms, in case anything re-encoded the text.
	for _, s := range []string{subjectMarker, bodyMarker, sessionMarker} {
		markers = append(markers, base64.StdEncoding.EncodeToString([]byte(s))[:16])
	}

	readAll := func() []byte {
		var all []byte
		for _, suffix := range []string{"", "-wal", "-shm"} {
			b, err := os.ReadFile(f.dbPath + suffix)
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			all = append(all, b...)
		}
		return all
	}
	open := readAll()
	if !bytes.Contains(open, []byte(e.ID)) {
		t.Fatal("sanity: envelope id not found in database files; reading the wrong files?")
	}
	if !bytes.Contains(open, []byte(e.Box[:64])) {
		t.Fatal("sanity: ciphertext not found in database files")
	}
	if _, err := os.Stat(f.dbPath + "-wal"); err != nil {
		t.Fatalf("expected a WAL file: %v", err)
	}
	mustNotContain(t, "database files (open)", string(open), markers...)

	// Deliver and ack it too: nothing on that path writes plaintext either.
	p := f.poll("peer-b", "peer-b", 0, 0)
	if len(p.envelopes) != 1 {
		t.Fatalf("poll returned %d envelopes", len(p.envelopes))
	}
	expectStatus(t, f.ack("peer-b", e.ID, "peer-b"), http.StatusOK, "")

	f.hs.Close()
	if err := f.st.Close(); err != nil {
		t.Fatal(err)
	}
	mustNotContain(t, "database files (closed)", string(readAll()), markers...)
	mustNotContain(t, "logs", f.logs.String(), markers...)
}

// TestAccessLogHasNoQueryStringOrContent checks the access log carries
// method, route, status, bytes, duration and peer, and never the query
// string, envelope content, identity header value or remote address.
func TestAccessLogHasNoQueryStringOrContent(t *testing.T) {
	f := newFixture(t, nil)
	e, raw := f.newEnvelope("peer-a", "peer-b")
	f.mustPost("peer-a", raw)
	const queryMarker = "querymarker-zz81"
	r := f.do(http.MethodGet, "/v1/poll?to=peer-b&after=0&timeout=0&x="+queryMarker, "peer-b", nil)
	expectStatus(t, r, http.StatusOK, "")
	expectStatus(t, f.ack("peer-b", e.ID, "peer-b"), http.StatusOK, "")
	expectStatus(t, f.do(http.MethodGet, "/v1/poll?to=peer-b&timeout=0", "", nil), http.StatusUnauthorized, "no_identity")
	f.do(http.MethodGet, "/healthz", "", nil)

	logs := f.logs.String()
	mustNotContain(t, "access log", logs,
		queryMarker, "after=", "timeout=", "?to=",
		e.Box[:32], e.Nonce,
		f.fp["peer-a"], f.fp["peer-b"],
		strings.TrimPrefix(f.hs.URL, "http://"), "127.0.0.1", "remote",
	)

	type line struct {
		Msg        string `json:"msg"`
		Method     string `json:"method"`
		Route      string `json:"route"`
		Status     int    `json:"status"`
		Bytes      *int64 `json:"bytes"`
		DurationMS *int64 `json:"duration_ms"`
		Peer       string `json:"peer"`
	}
	var got []line
	for _, l := range strings.Split(strings.TrimSpace(logs), "\n") {
		var ln line
		if err := json.Unmarshal([]byte(l), &ln); err != nil {
			t.Fatalf("log line is not JSON: %v", err)
		}
		if ln.Msg == "request" {
			got = append(got, ln)
		}
	}
	want := []line{
		{Method: "POST", Route: "POST /v1/msg", Status: 201, Peer: "peer-a"},
		{Method: "GET", Route: "GET /v1/poll", Status: 200, Peer: "peer-b"},
		{Method: "POST", Route: "POST /v1/ack/{id}", Status: 200, Peer: "peer-b"},
		{Method: "GET", Route: "GET /v1/poll", Status: 401, Peer: ""},
		{Method: "GET", Route: "GET /healthz", Status: 200, Peer: ""},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d access log lines, want %d:\n%s", len(got), len(want), logs)
	}
	for i, w := range want {
		g := got[i]
		if g.Method != w.Method || g.Route != w.Route || g.Status != w.Status || g.Peer != w.Peer {
			t.Errorf("line %d = %+v, want %+v", i, g, w)
		}
		if g.Bytes == nil || *g.Bytes <= 0 || g.DurationMS == nil {
			t.Errorf("line %d missing bytes or duration_ms", i)
		}
	}
	if *got[1].Bytes < int64(len(raw)) {
		t.Errorf("poll bytes = %d, want at least the envelope size %d", *got[1].Bytes, len(raw))
	}
}

func TestPostedEnvelopeIsReturnedUnchanged(t *testing.T) {
	// The relay re-encodes accepted envelopes; for anything produced by
	// envelope.Seal + json.Marshal that must be byte-identical.
	f := newFixture(t, nil)
	_, raw := f.newEnvelope("peer-a", "peer-b")
	var indented bytes.Buffer
	if err := json.Indent(&indented, raw, "", "  "); err != nil {
		t.Fatal(err)
	}
	f.mustPost("peer-a", indented.Bytes())
	p := f.poll("peer-b", "peer-b", 0, 0)
	if len(p.envelopes) != 1 || !bytes.Equal(p.envelopes[0], raw) {
		t.Fatalf("got %s\nwant %s", p.envelopes, raw)
	}
	if _, err := envelope.ParseEnvelope(p.envelopes[0]); err != nil {
		t.Fatal(err)
	}
}
