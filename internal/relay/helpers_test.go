package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"postern/internal/envelope"
	"postern/internal/ulid"
)

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type keyPair struct{ pub, priv *[envelope.KeySize]byte }

// fixture is a header-mode relay behind an httptest server, with a
// controllable clock and real sealing keys for peer-a and peer-b.
type fixture struct {
	t      *testing.T
	srv    *Server
	st     *Store
	hs     *httptest.Server
	dbPath string
	logs   *syncBuffer
	fp     map[string]string
	keys   map[string]keyPair
	// edgeSecret is what the edge's transform rule would set on every
	// request it forwards.
	edgeSecret string

	clockMu sync.Mutex
	now     time.Time
}

func testFingerprint(name string) string {
	sum := sha256.Sum256([]byte("postern test certificate " + name))
	return hex.EncodeToString(sum[:])
}

// newEdgeSecret returns a fresh random edge secret, as
// `openssl rand -hex 32` would.
func newEdgeSecret(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// writeEdgeSecret writes content to a fresh file and returns its path.
func writeEdgeSecret(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "edge-secret")
	if err := os.WriteFile(p, []byte(content), 0o400); err != nil {
		t.Fatal(err)
	}
	return p
}

// baseConfig is a header-mode config whose edge secret file holds secret
// (with a trailing newline, as `openssl rand -hex 32 > file` writes it).
func baseConfig(t *testing.T, secret string) Config {
	t.Helper()
	return Config{
		Identity:       IdentityHeader,
		EdgeSecretFile: writeEdgeSecret(t, secret+"\n"),
		Peers: map[string][]string{
			"peer-a": {testFingerprint("peer-a")},
			"peer-b": {testFingerprint("peer-b")},
		},
	}
}

func newFixture(t *testing.T, mutate func(*Config)) *fixture {
	t.Helper()
	secret := newEdgeSecret(t)
	cfg := baseConfig(t, secret)
	if mutate != nil {
		mutate(&cfg)
	}
	dbPath := filepath.Join(t.TempDir(), "relay", "relay.db")
	st, err := OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	logs := &syncBuffer{}
	srv, err := New(cfg, st, slog.New(slog.NewJSONHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		t: t, srv: srv, st: st, dbPath: dbPath, logs: logs, edgeSecret: secret,
		fp:   map[string]string{"peer-a": testFingerprint("peer-a"), "peer-b": testFingerprint("peer-b")},
		keys: map[string]keyPair{},
		now:  time.Now().Truncate(time.Second),
	}
	for _, p := range []string{"peer-a", "peer-b"} {
		pub, priv, err := envelope.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		f.keys[p] = keyPair{pub, priv}
	}
	srv.SetNow(f.clock)
	f.hs = httptest.NewServer(srv.Handler())
	t.Cleanup(f.hs.Close)
	return f
}

func (f *fixture) clock() time.Time {
	f.clockMu.Lock()
	defer f.clockMu.Unlock()
	return f.now
}

func (f *fixture) advance(d time.Duration) {
	f.clockMu.Lock()
	defer f.clockMu.Unlock()
	f.now = f.now.Add(d)
}

// sealMsg seals a real message from -> to with the given id and ts.
func (f *fixture) sealMsg(m envelope.Message) (envelope.Envelope, []byte) {
	f.t.Helper()
	e, err := envelope.Seal(m, f.keys[m.To].pub, f.keys[m.From].priv)
	if err != nil {
		f.t.Fatal(err)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		f.t.Fatal(err)
	}
	return e, raw
}

func (f *fixture) msg(from, to string) envelope.Message {
	return envelope.Message{
		ID: ulid.New(), From: from, To: to, Thread: envelope.NewThreadID(),
		TS: f.clock().Unix(), Session: "build", Subject: "status", Body: "all green",
	}
}

func (f *fixture) newEnvelope(from, to string) (envelope.Envelope, []byte) {
	f.t.Helper()
	return f.sealMsg(f.msg(from, to))
}

type response struct {
	status int
	body   []byte
	header http.Header
}

func (r response) errorCode() string {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(r.body, &e)
	return e.Error
}

// do sends a request as the edge would forward it from peer: always with
// the edge secret, and with peer's fingerprint ("" sends no fingerprint).
func (f *fixture) do(method, path, peer string, body []byte) response {
	f.t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, f.hs.URL+path, rd)
	if err != nil {
		f.t.Fatal(err)
	}
	req.Header.Set(EdgeSecretHeader, f.edgeSecret)
	if peer != "" {
		req.Header.Set(DefaultFingerprintHeader, f.fp[peer])
	}
	return f.send(req)
}

func (f *fixture) send(req *http.Request) response {
	f.t.Helper()
	resp, err := f.hs.Client().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		f.t.Fatal(err)
	}
	return response{status: resp.StatusCode, body: b, header: resp.Header}
}

func (f *fixture) post(peer string, raw []byte) response {
	f.t.Helper()
	return f.do(http.MethodPost, "/v1/msg", peer, raw)
}

func (f *fixture) mustPost(peer string, raw []byte) {
	f.t.Helper()
	if r := f.post(peer, raw); r.status != http.StatusCreated {
		f.t.Fatalf("post: status %d body %s", r.status, r.body)
	}
}

type pollResult struct {
	status    int
	code      string
	envelopes []json.RawMessage
	cursor    int64
}

func (f *fixture) poll(peer, to string, after int64, timeout int) pollResult {
	f.t.Helper()
	r := f.do(http.MethodGet, fmt.Sprintf("/v1/poll?to=%s&after=%d&timeout=%d", to, after, timeout), peer, nil)
	pr := pollResult{status: r.status, code: r.errorCode()}
	if r.status == http.StatusOK {
		var body struct {
			Envelopes []json.RawMessage `json:"envelopes"`
			Cursor    *int64            `json:"cursor"`
		}
		if err := json.Unmarshal(r.body, &body); err != nil {
			f.t.Fatalf("poll body: %v", err)
		}
		if body.Envelopes == nil || body.Cursor == nil {
			f.t.Fatalf("poll body missing envelopes or cursor: %s", r.body)
		}
		pr.envelopes, pr.cursor = body.Envelopes, *body.Cursor
	}
	return pr
}

func (f *fixture) ack(peer, id, to string) response {
	f.t.Helper()
	return f.do(http.MethodPost, "/v1/ack/"+id, peer, []byte(`{"to":"`+to+`"}`))
}

func (f *fixture) counts() (envelopes, ids int64) {
	f.t.Helper()
	ctx := context.Background()
	if err := f.st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM envelopes`).Scan(&envelopes); err != nil {
		f.t.Fatal(err)
	}
	if err := f.st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM seen_ids`).Scan(&ids); err != nil {
		f.t.Fatal(err)
	}
	return envelopes, ids
}

func expectStatus(t *testing.T, r response, status int, code string) {
	t.Helper()
	if r.status != status {
		t.Fatalf("status = %d, want %d (body %s)", r.status, status, r.body)
	}
	if code != "" && r.errorCode() != code {
		t.Fatalf("error = %q, want %q", r.errorCode(), code)
	}
}

func envelopeID(t *testing.T, raw []byte) string {
	t.Helper()
	var e envelope.Envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	return e.ID
}

func mustNotContain(t *testing.T, where, haystack string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if n != "" && strings.Contains(haystack, n) {
			t.Errorf("%s contains %q", where, n)
		}
	}
}
