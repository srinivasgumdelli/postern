package bridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"postern/internal/envelope"
	"postern/internal/tlsutil"
	"postern/internal/tlsutil/tlstest"
)

// Markers that must never appear in logs. Every test subject and body
// contains plainMarker, every test session name starts with
// sessionMarker, and the fake scanner trips on secretMarker.
const (
	plainMarker   = "PLAINTEXT-MARKER"
	sessionMarker = "sess-qx"
	secretMarker  = "FAKE-SECRET-VALUE"
)

// testLogs collects the logs of every bridge opened by these tests.
// TestMain checks them for content after all tests ran.
var testLogs syncBuffer

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func testLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func forbiddenInLogs(logs string) []string {
	var found []string
	for _, s := range []string{plainMarker, sessionMarker, secretMarker, "BEGIN", "PRIVATE KEY"} {
		if strings.Contains(logs, s) {
			found = append(found, s)
		}
	}
	return found
}

func TestMain(m *testing.M) {
	code := m.Run()
	if bad := forbiddenInLogs(testLogs.String()); len(bad) > 0 {
		fmt.Fprintf(os.Stderr, "bridge logs contain content markers %q\n", bad)
		code = 1
	}
	os.Exit(code)
}

// testScanner stands in for the real secret scanner: it blocks anything
// containing secretMarker and names the rule and line, never the match.
func testScanner(subject, body string) error {
	if strings.Contains(subject, secretMarker) {
		return errors.New("test-secret rule matched in subject")
	}
	for i, line := range strings.Split(body, "\n") {
		if strings.Contains(line, secretMarker) {
			return fmt.Errorf("test-secret rule matched on body line %d", i+1)
		}
	}
	return nil
}

// testClock runs in real time plus a manual offset, so tests can jump
// ahead while timers and long polls still behave.
type testClock struct {
	mu     sync.Mutex
	offset time.Duration
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.offset)
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.offset += d
}

// fakeRelay implements the relay API over mTLS: identity binding by
// client certificate fingerprint, the ±10 minute ts window (422), id
// dedup (409), long poll, and ack. Switches simulate outages and errors.
type fakeRelay struct {
	t     testing.TB
	srv   *httptest.Server
	clock *testClock

	mu        sync.Mutex
	idents    map[string]string // cert fingerprint -> peer
	seq       int64
	boxes     map[string][]storedEnv
	seen      map[string]bool
	acked     map[string]bool
	posts     []envelope.Envelope // every post that reached the store logic
	requests  int
	offline   bool
	postCode  int    // forced status for posts (0 = normal)
	storeFail bool   // store the post, then answer 503 (lost response)
	redirect  string // answer posts with 307 to this URL
	ackCode   int    // forced status for acks (0 = normal)
	revoked   map[string]bool
	notify    chan struct{}
	stop      chan struct{}
	stopOnce  sync.Once
}

type storedEnv struct {
	seq int64
	id  string
	raw json.RawMessage
}

func newFakeRelay(t testing.TB, ca *tlstest.CA, clock *testClock, hosts ...string) *fakeRelay {
	t.Helper()
	f := &fakeRelay{
		t:       t,
		clock:   clock,
		idents:  map[string]string{},
		boxes:   map[string][]storedEnv{},
		seen:    map[string]bool{},
		acked:   map[string]bool{},
		revoked: map[string]bool{},
		notify:  make(chan struct{}),
		stop:    make(chan struct{}),
	}
	f.srv = httptest.NewUnstartedServer(f)
	f.srv.EnableHTTP2 = true
	f.srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{ca.ServerCert(t, hosts...)},
		ClientCAs:    ca.Pool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0) // expected handshake failures
	f.srv.StartTLS()
	t.Cleanup(f.Close)
	return f
}

func (f *fakeRelay) Close() {
	f.stopOnce.Do(func() { close(f.stop) })
	f.srv.Close()
}

func (f *fakeRelay) URL() string { return f.srv.URL }

func (f *fakeRelay) bind(fingerprint, peer string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.idents[tlsutil.NormalizeFingerprint(fingerprint)] = peer
}

// revoke makes the edge refuse a certificate with 403, as after a
// revocation.
func (f *fakeRelay) revoke(fingerprint string, v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked[tlsutil.NormalizeFingerprint(fingerprint)] = v
}

func (f *fakeRelay) setOffline(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.offline = v
}

func (f *fakeRelay) setPostCode(code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.postCode = code
}

func (f *fakeRelay) setStoreFail(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.storeFail = v
}

func (f *fakeRelay) setAckCode(code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ackCode = code
}

func (f *fakeRelay) setRedirect(u string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.redirect = u
}

func (f *fakeRelay) acceptedPosts() []envelope.Envelope {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]envelope.Envelope(nil), f.posts...)
}

func (f *fakeRelay) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

func (f *fakeRelay) isAcked(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.acked[id]
}

func (f *fakeRelay) pending(mailbox string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.boxes[mailbox])
}

// inject puts an envelope straight into a mailbox, bypassing identity,
// time and dedup checks: it simulates a hostile or buggy relay.
func (f *fakeRelay) inject(mailbox string, e envelope.Envelope) {
	raw, err := json.Marshal(e)
	if err != nil {
		f.t.Fatal(err)
	}
	f.injectRaw(mailbox, e.ID, raw)
}

func (f *fakeRelay) injectRaw(mailbox, id string, raw []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.storeLocked(mailbox, id, raw)
}

func (f *fakeRelay) storeLocked(mailbox, id string, raw []byte) {
	f.seq++
	f.boxes[mailbox] = append(f.boxes[mailbox], storedEnv{seq: f.seq, id: id, raw: append(json.RawMessage(nil), raw...)})
	close(f.notify)
	f.notify = make(chan struct{})
}

func (f *fakeRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests++
	offline := f.offline
	f.mu.Unlock()
	if offline {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
		return
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		f.mu.Lock()
		rev := f.revoked[tlsutil.Fingerprint(r.TLS.PeerCertificates[0].Raw)]
		f.mu.Unlock()
		if rev {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "revoked"})
			return
		}
	}
	peer := f.identity(r)
	if peer == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no_identity"})
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/msg":
		f.handlePost(w, r, peer)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/poll":
		f.handlePoll(w, r, peer)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/ack/"):
		f.handleAck(w, r, peer)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
	}
}

func (f *fakeRelay) identity(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	fp := tlsutil.Fingerprint(r.TLS.PeerCertificates[0].Raw)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.idents[fp]
}

func (f *fakeRelay) handlePost(w http.ResponseWriter, r *http.Request, peer string) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, envelope.MaxEnvelopeBytes+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid"})
		return
	}
	if len(raw) > envelope.MaxEnvelopeBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "too_large"})
		return
	}
	e, err := envelope.ParseEnvelope(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid"})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.redirect != "" {
		w.Header().Set("Location", f.redirect)
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	}
	if e.From != peer {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	now := f.clock.Now().Unix()
	if d := e.TS - now; d > int64(envelope.ClockSkew/time.Second) || -d > int64(envelope.ClockSkew/time.Second) {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "stale"})
		return
	}
	f.posts = append(f.posts, e)
	if f.postCode != 0 {
		writeJSON(w, f.postCode, map[string]string{"error": "forced"})
		return
	}
	if f.seen[e.ID] {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "duplicate"})
		return
	}
	f.seen[e.ID] = true
	f.storeLocked(e.To, e.ID, raw)
	if f.storeFail {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": e.ID})
}

func (f *fakeRelay) handlePoll(w http.ResponseWriter, r *http.Request, peer string) {
	q := r.URL.Query()
	to := q.Get("to")
	if to != peer {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	after, err := strconv.ParseInt(q.Get("after"), 10, 64)
	if err != nil || after < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid"})
		return
	}
	secs, err := strconv.Atoi(q.Get("timeout"))
	if err != nil || secs < 0 || secs > 25 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid"})
		return
	}
	deadline := time.NewTimer(time.Duration(secs) * time.Second)
	defer deadline.Stop()
	for {
		f.mu.Lock()
		var envs []json.RawMessage
		cursor := after
		for _, s := range f.boxes[to] {
			if s.seq > after && len(envs) < 50 {
				envs = append(envs, s.raw)
				cursor = s.seq
			}
		}
		wake := f.notify
		f.mu.Unlock()
		if len(envs) > 0 {
			writeJSON(w, http.StatusOK, map[string]any{"envelopes": envs, "cursor": cursor})
			return
		}
		select {
		case <-wake:
		case <-deadline.C:
			writeJSON(w, http.StatusOK, map[string]any{"envelopes": []json.RawMessage{}, "cursor": cursor})
			return
		case <-r.Context().Done():
			return
		case <-f.stop:
			return
		}
	}
}

func (f *fakeRelay) handleAck(w http.ResponseWriter, r *http.Request, peer string) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/ack/")
	var body struct {
		To string `json:"to"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid"})
		return
	}
	if body.To != peer {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ackCode != 0 {
		writeJSON(w, f.ackCode, map[string]string{"error": "forced"})
		return
	}
	box := f.boxes[body.To]
	for i, s := range box {
		if s.id == id {
			f.boxes[body.To] = append(box[:i:i], box[i+1:]...)
			f.acked[id] = true
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// identity is one test peer: box keys and a client certificate.
type identity struct {
	name      string
	pub, priv *[32]byte
	cert      tlstest.ClientCert
	inboxKey  *[32]byte
}

// world is a CA, a clock, a fake relay and two peers bound to it.
type world struct {
	t     *testing.T
	ca    *tlstest.CA
	clock *testClock
	relay *fakeRelay
	a, b  identity
}

func newIdentity(t *testing.T, ca *tlstest.CA, name string) identity {
	t.Helper()
	pub, priv, err := envelope.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return identity{name: name, pub: pub, priv: priv, cert: ca.ClientCert(t, name), inboxKey: &k}
}

func newWorld(t *testing.T) *world {
	t.Helper()
	ca := tlstest.NewCA(t)
	clock := &testClock{}
	w := &world{t: t, ca: ca, clock: clock}
	w.a = newIdentity(t, ca, "peer-a")
	w.b = newIdentity(t, ca, "peer-b")
	w.relay = newFakeRelay(t, ca, clock)
	w.relay.bind(w.a.cert.Fingerprint, w.a.name)
	w.relay.bind(w.b.cert.Fingerprint, w.b.name)
	return w
}

// options returns Options for self talking to the given peers through the
// world's relay, with a fresh database unless dbPath is set.
func (w *world) options(self identity, dbPath string, peers ...identity) Options {
	w.t.Helper()
	if dbPath == "" {
		dbPath = filepath.Join(w.t.TempDir(), "data", self.name+".db")
	}
	var ps []Peer
	for _, p := range peers {
		ps = append(ps, Peer{Name: p.name, PublicKey: p.pub})
	}
	return Options{
		Scanner:     testScanner,
		Self:        self.name,
		BoxPrivate:  self.priv,
		InboxKey:    self.inboxKey,
		Peers:       ps,
		RelayURL:    w.relay.URL(),
		ClientCert:  self.cert.TLS,
		RootCAs:     w.ca.Pool(),
		DBPath:      dbPath,
		Logger:      testLogger(&testLogs),
		Now:         w.clock.Now,
		PollTimeout: time.Millisecond, // relay answers at once when empty
	}
}

func (w *world) open(opts Options) *Bridge {
	w.t.Helper()
	b, err := Open(opts)
	if err != nil {
		w.t.Fatalf("Open: %v", err)
	}
	w.t.Cleanup(func() { b.Close() })
	return b
}

// pair opens bridges for peer-a and peer-b that know each other.
func (w *world) pair() (*Bridge, *Bridge) {
	w.t.Helper()
	a := w.open(w.options(w.a, "", w.b))
	b := w.open(w.options(w.b, "", w.a))
	return a, b
}

// sealFrom seals a message from one identity to another, for injection.
func sealFrom(t *testing.T, from identity, toName string, toPub *[32]byte, ts time.Time, mod func(*envelope.Message)) envelope.Envelope {
	t.Helper()
	m := envelope.Message{
		ID: newID(), From: from.name, To: toName, Thread: envelope.NewThreadID(), TS: ts.Unix(),
		Session: sessionMarker + "9", Subject: plainMarker + " injected subject", Body: plainMarker + " injected body",
	}
	if mod != nil {
		mod(&m)
	}
	e, err := envelope.Seal(m, toPub, from.priv)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func ctxT(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}
