package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"postern/internal/envelope"
	"postern/internal/tlsutil"
	"postern/internal/ulid"
)

const (
	maxPollTimeout    = 25 * time.Second
	maxPollBatch      = 50
	maxAckBodyBytes   = 1024
	maxPollersPerPeer = 16
	healthTimeout     = 2 * time.Second
)

// Server is the relay HTTP service.
type Server struct {
	cfg      Config
	st       *Store
	log      *slog.Logger
	peerByFP map[string]string
	notify   *notifier
	posts    *windowLimiter
	pollers  *concurrencyLimiter
	postMu   sync.Mutex // serializes the dedup / limit / insert sequence
	now      atomic.Pointer[func() time.Time]
	handler  http.Handler
}

// New builds a relay server. cfg is validated and defaults are applied;
// st must be open. A nil logger discards logs.
func New(cfg Config, st *Store, log *slog.Logger) (*Server, error) {
	if st == nil {
		return nil, errors.New("relay: nil store")
	}
	c, err := cfg.normalized()
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Server{
		cfg:      c,
		st:       st,
		log:      log,
		peerByFP: make(map[string]string),
		notify:   newNotifier(),
		posts:    newWindowLimiter(c.PostsPerHour, time.Hour),
		pollers:  newConcurrencyLimiter(maxPollersPerPeer),
	}
	for name, fps := range c.Peers {
		for _, fp := range fps {
			s.peerByFP[fp] = name
		}
	}
	s.SetNow(nil)
	s.handler = s.routes()
	return s, nil
}

// Handler returns the relay's HTTP handler, including the access log.
func (s *Server) Handler() http.Handler { return s.handler }

// SetNow replaces the clock used for timestamps, the replay window,
// rate limits and expiry. nil restores time.Now. Tests only.
func (s *Server) SetNow(now func() time.Time) {
	if now == nil {
		now = time.Now
	}
	s.now.Store(&now)
}

func (s *Server) clock() time.Time { return (*s.now.Load())() }

// ServerTLSConfig returns the TLS configuration for mtls identity mode:
// the relay's own certificate, and a client certificate is required and
// verified against ClientCAFile. Identity still comes from the verified
// peer certificate on each request, so any equivalent tls.Config works.
func (s *Server) ServerTLSConfig() (*tls.Config, error) {
	if s.cfg.Identity != IdentityMTLS || s.cfg.TLS == nil {
		return nil, errors.New("relay: ServerTLSConfig needs identity \"mtls\"")
	}
	cert, err := tls.LoadX509KeyPair(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
	if err != nil {
		return nil, errors.New("relay: cannot load server certificate and key")
	}
	caPEM, err := os.ReadFile(s.cfg.TLS.ClientCAFile)
	if err != nil {
		return nil, errors.New("relay: cannot read client CA file")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("relay: client CA file has no certificates")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		Certificates: []tls.Certificate{cert},
	}, nil
}

// RunExpiry deletes envelopes and seen ids older than envelope.Retention,
// once immediately and then every interval, until ctx is done.
func (s *Server) RunExpiry(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = time.Minute
	}
	s.expire(ctx)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.expire(ctx)
		}
	}
}

func (s *Server) expire(ctx context.Context) {
	cutoff := s.clock().Add(-envelope.Retention).Unix()
	n, m, err := s.st.expire(ctx, cutoff)
	if err != nil {
		if ctx.Err() == nil {
			s.log.Error("expiry failed", "err", err)
		}
		return
	}
	if n > 0 || m > 0 {
		s.log.Info("expired", "envelopes", n, "ids", m)
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/msg", s.handlePost)
	mux.HandleFunc("GET /v1/poll", s.handlePoll)
	mux.HandleFunc("POST /v1/ack/{id}", s.handleAck)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	// Known paths with the wrong method get a JSON 405; anything else a
	// JSON 404. Neither echoes the request.
	mux.Handle("/v1/msg", methodNotAllowed("POST"))
	mux.Handle("/v1/poll", methodNotAllowed("GET, HEAD"))
	mux.Handle("/v1/ack/{id}", methodNotAllowed("POST"))
	mux.Handle("/healthz", methodNotAllowed("GET, HEAD"))
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not_found")
	})
	return s.accessLog(cleanPathOnly(mux))
}

func methodNotAllowed(allow string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Allow", allow)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
	})
}

// cleanPathOnly answers 404 for non-canonical paths instead of letting
// ServeMux redirect, because the redirect would echo the path back.
func cleanPathOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if p == "" || p[0] != '/' || path.Clean(p) != p {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- identity ---

type ctxKey struct{}

// reqInfo carries the authenticated peer from the handler back to the
// access log.
type reqInfo struct{ peer string }

// authenticate maps the request's client-certificate fingerprint to a
// configured peer. It writes 401 when the request carries no identity
// and 403 when the fingerprint belongs to no peer.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (string, bool) {
	fp, present := s.fingerprint(r)
	if !present {
		writeError(w, http.StatusUnauthorized, "no_identity")
		return "", false
	}
	peer, ok := s.peerByFP[fp]
	if !ok {
		writeError(w, http.StatusForbidden, "forbidden")
		return "", false
	}
	if info, _ := r.Context().Value(ctxKey{}).(*reqInfo); info != nil {
		info.peer = peer
	}
	return peer, true
}

// fingerprint returns the normalized SHA-256 fingerprint of the client
// certificate behind r. present is false when the request carries no
// identity at all. A present but unusable identity (for example two
// header values) returns a value that matches no peer.
func (s *Server) fingerprint(r *http.Request) (fp string, present bool) {
	if s.cfg.Identity == IdentityMTLS {
		// Only a certificate that the TLS layer verified against the
		// client CA counts. Headers are ignored entirely in this mode.
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
			return "", false
		}
		return tlsutil.Fingerprint(r.TLS.PeerCertificates[0].Raw), true
	}
	// Header mode. The edge verifies the client certificate and a
	// transform rule SETS this header from the verified certificate's
	// fingerprint, overwriting anything the client sent. Trusting it is
	// safe ONLY because the relay publishes no ports and is reachable
	// solely through the tunnel (cloudflared on an internal Compose
	// network). Never expose the relay any other way in this mode.
	vals := r.Header.Values(s.cfg.FingerprintHeader)
	switch len(vals) {
	case 0:
		return "", false
	case 1:
		v := tlsutil.NormalizeFingerprint(vals[0])
		if v == "" {
			return "", false
		}
		return v, true
	default:
		return "", true
	}
}

// --- handlers ---

func (s *Server) handlePost(w http.ResponseWriter, r *http.Request) {
	peer, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, envelope.MaxEnvelopeBytes)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	e, err := envelope.ParseEnvelope(data)
	if err != nil {
		if errors.Is(err, envelope.ErrTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	if e.From != peer {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if _, known := s.cfg.Peers[e.To]; !known {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	now := s.clock()
	if err := envelope.CheckTime(e.TS, now, envelope.ClockSkew); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "stale")
		return
	}
	// Re-encode rather than store the request bytes: for an envelope
	// built with envelope.Seal and json.Marshal the result is identical,
	// and it guarantees the stored JSON says exactly what the routing
	// columns say (no duplicate or case-folded keys reach the recipient).
	raw, err := json.Marshal(e)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}

	ctx := r.Context()
	s.postMu.Lock()
	defer s.postMu.Unlock()
	dup, err := s.st.seen(ctx, e.ID)
	if err != nil {
		s.internalError(w, "seen", err)
		return
	}
	if dup {
		writeError(w, http.StatusConflict, "duplicate")
		return
	}
	if !s.posts.allow(peer, now) {
		writeError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	_, err = s.st.insert(ctx, e, raw, now.Unix(), s.cfg.MaxQueuedPerPeer)
	switch {
	case errors.Is(err, errDuplicate):
		writeError(w, http.StatusConflict, "duplicate")
		return
	case errors.Is(err, errQueueFull):
		writeError(w, http.StatusTooManyRequests, "queue_full")
		return
	case err != nil:
		s.internalError(w, "insert", err)
		return
	}
	s.notify.notify(e.To)
	writeJSON(w, http.StatusCreated, map[string]string{"id": e.ID})
}

type pollResponse struct {
	Envelopes []json.RawMessage `json:"envelopes"`
	Cursor    int64             `json:"cursor"`
}

func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request) {
	peer, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	if q.Get("to") != peer {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	var after int64
	if v := q.Get("after"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		}
		after = n
	}
	timeout := maxPollTimeout
	if v := q.Get("timeout"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid")
			return
		}
		timeout = time.Duration(min(max(n, 0), int64(maxPollTimeout/time.Second))) * time.Second
	}
	if !s.pollers.acquire(peer) {
		writeError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	defer s.pollers.release(peer)

	ctx := r.Context()
	var expired <-chan time.Time
	if timeout > 0 {
		t := time.NewTimer(timeout)
		defer t.Stop()
		expired = t.C
	}
	for {
		// Take the wake channel before querying so an envelope committed
		// after the query cannot be missed.
		wake := s.notify.wait(peer)
		notBefore := s.clock().Add(-envelope.Retention).Unix()
		envs, err := s.st.pending(ctx, peer, after, notBefore, maxPollBatch)
		if err != nil {
			if ctx.Err() != nil {
				writePoll(w, nil, after)
				return
			}
			s.internalError(w, "pending", err)
			return
		}
		if len(envs) > 0 || expired == nil {
			writePoll(w, envs, after)
			return
		}
		select {
		case <-wake:
		case <-expired:
			writePoll(w, nil, after)
			return
		case <-ctx.Done():
			// Client went away or the server is shutting down.
			writePoll(w, nil, after)
			return
		}
	}
}

func writePoll(w http.ResponseWriter, envs []storedEnvelope, after int64) {
	resp := pollResponse{Envelopes: make([]json.RawMessage, 0, len(envs)), Cursor: after}
	for _, e := range envs {
		resp.Envelopes = append(resp.Envelopes, json.RawMessage(e.Raw))
		resp.Cursor = max(resp.Cursor, e.Seq)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAck(w http.ResponseWriter, r *http.Request) {
	peer, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAckBodyBytes)
	var req struct {
		To string `json:"to"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	if _, err := dec.Token(); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	if req.To != peer {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	id := r.PathValue("id")
	if !ulid.Valid(id) {
		writeError(w, http.StatusBadRequest, "invalid")
		return
	}
	deleted, err := s.st.ack(r.Context(), id, peer)
	if err != nil {
		s.internalError(w, "ack", err)
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), healthTimeout)
	defer cancel()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err := s.st.ping(ctx); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "unavailable")
		return
	}
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "ok")
}

func (s *Server) internalError(w http.ResponseWriter, op string, err error) {
	// Store errors carry SQL text and constraint names, never values:
	// every statement uses placeholders.
	s.log.Error("store error", "op", op, "err", err)
	writeError(w, http.StatusInternalServerError, "internal")
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		status = http.StatusInternalServerError
		buf.Reset()
		buf.WriteString(`{"error":"internal"}` + "\n")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

// --- access log ---

// accessLog writes one JSON line per request with method, route pattern,
// status, response bytes, duration and peer. It never logs the query
// string, request body, headers or remote address.
func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		info := &reqInfo{}
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, info))
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		s.log.LogAttrs(context.Background(), slog.LevelInfo, "request",
			slog.String("method", logMethod(r.Method)),
			slog.String("route", r.Pattern),
			slog.Int("status", sw.status),
			slog.Int64("bytes", sw.bytes),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()),
			slog.String("peer", info.peer),
		)
	})
}

func logMethod(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions, http.MethodConnect, http.MethodTrace:
		return m
	}
	return "OTHER"
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
