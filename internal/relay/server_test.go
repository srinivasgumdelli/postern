package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"postern/internal/envelope"
	"postern/internal/ulid"
)

func TestHealthzNeedsNoIdentity(t *testing.T) {
	f := newFixture(t, nil)
	r := f.do(http.MethodGet, "/healthz", "", nil)
	if r.status != http.StatusOK || string(r.body) != "ok" {
		t.Fatalf("healthz = %d %q", r.status, r.body)
	}
}

func TestUnknownRouteAndWrongMethod(t *testing.T) {
	f := newFixture(t, nil)
	expectStatus(t, f.do(http.MethodGet, "/nope", "peer-a", nil), http.StatusNotFound, "not_found")
	expectStatus(t, f.do(http.MethodGet, "/v1/msg/", "peer-a", nil), http.StatusNotFound, "not_found")
	expectStatus(t, f.do(http.MethodGet, "/v1/msg", "peer-a", nil), http.StatusMethodNotAllowed, "method_not_allowed")
	expectStatus(t, f.do(http.MethodPost, "/v1/poll", "peer-a", nil), http.StatusMethodNotAllowed, "method_not_allowed")
	expectStatus(t, f.do(http.MethodGet, "/v1/ack/"+ulid.New(), "peer-a", nil), http.StatusMethodNotAllowed, "method_not_allowed")
	expectStatus(t, f.do(http.MethodPost, "/healthz", "", nil), http.StatusMethodNotAllowed, "method_not_allowed")

	// A non-canonical path is a plain 404, not a redirect that echoes it.
	req, _ := http.NewRequest(http.MethodGet, f.hs.URL+"/v1//poll", nil)
	r := f.send(req)
	expectStatus(t, r, http.StatusNotFound, "not_found")
	if r.header.Get("Location") != "" {
		t.Fatalf("redirected to %q", r.header.Get("Location"))
	}
}

func TestErrorsNeverEchoInput(t *testing.T) {
	f := newFixture(t, nil)
	marker := "echomarker7731"
	checks := []response{
		f.do(http.MethodGet, "/"+marker, "peer-a", nil),
		f.do(http.MethodPost, "/v1/msg", "peer-a", []byte(`{"`+marker+`":1}`)),
		f.do(http.MethodGet, "/v1/poll?to="+marker, "peer-a", nil),
		f.do(http.MethodGet, "/v1/poll?to=peer-a&after="+marker, "peer-a", nil),
		f.do(http.MethodPost, "/v1/ack/"+marker, "peer-a", []byte(`{"to":"peer-a"}`)),
		f.do(http.MethodPost, "/v1/ack/"+ulid.New(), "peer-a", []byte(`{"to":"`+marker+`"}`)),
	}
	for i, r := range checks {
		if r.status < 400 {
			t.Fatalf("check %d: status %d", i, r.status)
		}
		mustNotContain(t, "error body", string(r.body), marker)
		for k, v := range r.header {
			mustNotContain(t, "header "+k, strings.Join(v, ","), marker)
		}
	}
}

func TestPostPollAckRoundTrip(t *testing.T) {
	f := newFixture(t, nil)
	e, raw := f.newEnvelope("peer-a", "peer-b")
	r := f.post("peer-a", raw)
	expectStatus(t, r, http.StatusCreated, "")
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(r.body, &created); err != nil || created.ID != e.ID {
		t.Fatalf("created = %s", r.body)
	}

	// The sender's own mailbox is empty.
	if p := f.poll("peer-a", "peer-a", 0, 0); len(p.envelopes) != 0 {
		t.Fatalf("sender mailbox has %d envelopes", len(p.envelopes))
	}

	p := f.poll("peer-b", "peer-b", 0, 0)
	if p.status != http.StatusOK || len(p.envelopes) != 1 {
		t.Fatalf("poll = %+v", p)
	}
	if !bytes.Equal(p.envelopes[0], raw) {
		t.Fatalf("envelope changed in transit:\n got %s\nwant %s", p.envelopes[0], raw)
	}
	got, err := envelope.ParseEnvelope(p.envelopes[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := envelope.Open(got, f.keys["peer-a"].pub, f.keys["peer-b"].priv); err != nil {
		t.Fatalf("recipient cannot open relayed envelope: %v", err)
	}
	if p.cursor <= 0 {
		t.Fatalf("cursor = %d", p.cursor)
	}
	// Cursor excludes what was already returned.
	if again := f.poll("peer-b", "peer-b", p.cursor, 0); len(again.envelopes) != 0 || again.cursor != p.cursor {
		t.Fatalf("poll after cursor = %+v", again)
	}

	expectStatus(t, f.ack("peer-b", e.ID, "peer-b"), http.StatusOK, "")
	if after := f.poll("peer-b", "peer-b", 0, 0); len(after.envelopes) != 0 {
		t.Fatalf("acked envelope still delivered")
	}
	expectStatus(t, f.ack("peer-b", e.ID, "peer-b"), http.StatusNotFound, "not_found")
}

func TestLongPollWakesOnNewMessage(t *testing.T) {
	f := newFixture(t, nil)
	type result struct {
		p       pollResult
		elapsed time.Duration
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		p := f.poll("peer-b", "peer-b", 0, 20)
		done <- result{p, time.Since(start)}
	}()
	time.Sleep(300 * time.Millisecond) // let the poller start waiting
	select {
	case r := <-done:
		t.Fatalf("poll returned before any message: %+v", r.p)
	default:
	}
	_, raw := f.newEnvelope("peer-a", "peer-b")
	f.mustPost("peer-a", raw)

	select {
	case r := <-done:
		if len(r.p.envelopes) != 1 {
			t.Fatalf("woken poll returned %d envelopes", len(r.p.envelopes))
		}
		if r.elapsed > 5*time.Second {
			t.Fatalf("poll took %v; should wake well before the 20s timeout", r.elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("long-poll did not wake on new message")
	}
}

func TestLongPollIgnoresOtherPeersMessages(t *testing.T) {
	f := newFixture(t, nil)
	done := make(chan pollResult, 1)
	go func() { done <- f.poll("peer-b", "peer-b", 0, 1) }()
	time.Sleep(100 * time.Millisecond)
	_, raw := f.newEnvelope("peer-b", "peer-a") // for peer-a, not peer-b
	f.mustPost("peer-b", raw)
	if p := <-done; len(p.envelopes) != 0 {
		t.Fatalf("peer-b received peer-a's envelope")
	}
}

func TestLongPollTimeoutReturnsEmptyCursorUnchanged(t *testing.T) {
	f := newFixture(t, nil)
	start := time.Now()
	p := f.poll("peer-b", "peer-b", 42, 1)
	elapsed := time.Since(start)
	if p.status != http.StatusOK || len(p.envelopes) != 0 || p.cursor != 42 {
		t.Fatalf("poll = %+v", p)
	}
	if elapsed < 900*time.Millisecond || elapsed > 5*time.Second {
		t.Fatalf("timeout poll took %v, want about 1s", elapsed)
	}

	// timeout=0 (and negative, clamped to 0) returns at once.
	start = time.Now()
	for _, q := range []string{"timeout=0", "timeout=-5"} {
		r := f.do(http.MethodGet, "/v1/poll?to=peer-b&"+q, "peer-b", nil)
		expectStatus(t, r, http.StatusOK, "")
		if !strings.Contains(string(r.body), `"cursor":0`) || !strings.Contains(string(r.body), `"envelopes":[]`) {
			t.Fatalf("empty poll body = %s", r.body)
		}
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout=0 poll waited")
	}
}

func TestPollBadParams(t *testing.T) {
	f := newFixture(t, nil)
	for _, q := range []string{"after=-1", "after=x", "after=1.5", "timeout=abc", "timeout=1e3"} {
		expectStatus(t, f.do(http.MethodGet, "/v1/poll?to=peer-b&"+q, "peer-b", nil), http.StatusBadRequest, "invalid")
	}
}

func TestPollReturnsAtMost50InSeqOrder(t *testing.T) {
	f := newFixture(t, nil)
	var ids []string
	for range 60 {
		e, raw := f.newEnvelope("peer-a", "peer-b")
		f.mustPost("peer-a", raw)
		ids = append(ids, e.ID)
	}
	first := f.poll("peer-b", "peer-b", 0, 0)
	if len(first.envelopes) != maxPollBatch {
		t.Fatalf("first poll returned %d, want %d", len(first.envelopes), maxPollBatch)
	}
	second := f.poll("peer-b", "peer-b", first.cursor, 0)
	if len(second.envelopes) != 10 || second.cursor <= first.cursor {
		t.Fatalf("second poll = %d envelopes, cursor %d (first %d)", len(second.envelopes), second.cursor, first.cursor)
	}
	all := append(first.envelopes, second.envelopes...)
	for i, raw := range all {
		if got := envelopeID(t, raw); got != ids[i] {
			t.Fatalf("envelope %d out of order", i)
		}
	}
}

func TestDuplicateIDRejectedIncludingAfterAck(t *testing.T) {
	f := newFixture(t, nil)
	m := f.msg("peer-a", "peer-b")
	e, raw := f.sealMsg(m)
	f.mustPost("peer-a", raw)
	expectStatus(t, f.post("peer-a", raw), http.StatusConflict, "duplicate")

	// A reseal with a fresh ts but the same id is still a duplicate.
	f.advance(time.Minute)
	m.TS = f.clock().Unix()
	_, resealed := f.sealMsg(m)
	expectStatus(t, f.post("peer-a", resealed), http.StatusConflict, "duplicate")

	expectStatus(t, f.ack("peer-b", e.ID, "peer-b"), http.StatusOK, "")
	expectStatus(t, f.post("peer-a", raw), http.StatusConflict, "duplicate")
	expectStatus(t, f.post("peer-a", resealed), http.StatusConflict, "duplicate")
	if p := f.poll("peer-b", "peer-b", 0, 0); len(p.envelopes) != 0 {
		t.Fatal("replayed envelope was delivered after ack")
	}
}

func TestOversizeEnvelope413(t *testing.T) {
	f := newFixture(t, nil)
	big := bytes.Repeat([]byte("A"), envelope.MaxEnvelopeBytes+1)
	expectStatus(t, f.post("peer-a", big), http.StatusRequestEntityTooLarge, "too_large")

	// A well-formed envelope whose box pushes it over the cap.
	e, _ := f.newEnvelope("peer-a", "peer-b")
	e.Box = strings.Repeat("A", envelope.MaxEnvelopeBytes)
	raw, _ := json.Marshal(e)
	expectStatus(t, f.post("peer-a", raw), http.StatusRequestEntityTooLarge, "too_large")

	if n, _ := f.counts(); n != 0 {
		t.Fatalf("%d envelopes stored", n)
	}
}

func TestInvalidEnvelope400(t *testing.T) {
	f := newFixture(t, nil)
	e, _ := f.newEnvelope("peer-a", "peer-b")
	mod := func(fn func(*envelope.Envelope)) []byte {
		c := e
		fn(&c)
		b, _ := json.Marshal(c)
		return b
	}
	good, _ := json.Marshal(e)
	cases := map[string][]byte{
		"not json":       []byte("hello"),
		"empty":          {},
		"unknown field":  append(bytes.TrimSuffix(good, []byte("}")), []byte(`,"extra":1}`)...),
		"trailing data":  append(append([]byte{}, good...), []byte(`{}`)...),
		"wrong version":  mod(func(c *envelope.Envelope) { c.V = 2 }),
		"bad id":         mod(func(c *envelope.Envelope) { c.ID = "nope" }),
		"bad thread":     mod(func(c *envelope.Envelope) { c.Thread = "free text" }),
		"bad nonce":      mod(func(c *envelope.Envelope) { c.Nonce = "AAAA" }),
		"unknown peer":   mod(func(c *envelope.Envelope) { c.To = "peer-c" }),
		"to self":        mod(func(c *envelope.Envelope) { c.To = "peer-a" }),
		"bad peer name":  mod(func(c *envelope.Envelope) { c.To = "Peer B" }),
		"missing ts":     mod(func(c *envelope.Envelope) { c.TS = 0 }),
		"box not base64": mod(func(c *envelope.Envelope) { c.Box = "!!!" }),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			expectStatus(t, f.post("peer-a", body), http.StatusBadRequest, "invalid")
		})
	}
	if n, _ := f.counts(); n != 0 {
		t.Fatalf("%d envelopes stored", n)
	}
}

func TestStaleTimestamp422(t *testing.T) {
	f := newFixture(t, nil)
	now := f.clock()
	for name, ts := range map[string]time.Time{
		"too old":       now.Add(-envelope.ClockSkew - time.Minute),
		"in the future": now.Add(envelope.ClockSkew + time.Minute),
	} {
		t.Run(name, func(t *testing.T) {
			m := f.msg("peer-a", "peer-b")
			m.TS = ts.Unix()
			_, raw := f.sealMsg(m)
			expectStatus(t, f.post("peer-a", raw), http.StatusUnprocessableEntity, "stale")
		})
	}
	for name, ts := range map[string]time.Time{
		"just old enough":   now.Add(-envelope.ClockSkew + time.Minute),
		"just early enough": now.Add(envelope.ClockSkew - time.Minute),
	} {
		t.Run(name, func(t *testing.T) {
			m := f.msg("peer-a", "peer-b")
			m.TS = ts.Unix()
			_, raw := f.sealMsg(m)
			expectStatus(t, f.post("peer-a", raw), http.StatusCreated, "")
		})
	}
	// A stale envelope does not burn its id.
	m := f.msg("peer-a", "peer-b")
	m.TS = now.Add(-time.Hour).Unix()
	_, raw := f.sealMsg(m)
	expectStatus(t, f.post("peer-a", raw), http.StatusUnprocessableEntity, "stale")
	m.TS = now.Unix()
	_, raw = f.sealMsg(m)
	expectStatus(t, f.post("peer-a", raw), http.StatusCreated, "")
}

func TestExpiryDeletesOldEnvelopesAndSeenIDs(t *testing.T) {
	f := newFixture(t, nil)
	old := f.msg("peer-a", "peer-b")
	_, oldRaw := f.sealMsg(old)
	f.mustPost("peer-a", oldRaw)
	acked := f.msg("peer-a", "peer-b")
	_, ackedRaw := f.sealMsg(acked)
	f.mustPost("peer-a", ackedRaw)
	expectStatus(t, f.ack("peer-b", acked.ID, "peer-b"), http.StatusOK, "")

	f.advance(envelope.Retention - time.Hour)
	fresh := f.msg("peer-a", "peer-b")
	_, freshRaw := f.sealMsg(fresh)
	f.mustPost("peer-a", freshRaw)

	if n, ids := f.counts(); n != 2 || ids != 3 {
		t.Fatalf("before expiry: %d envelopes, %d ids", n, ids)
	}
	f.advance(2 * time.Hour) // first two are now past retention
	// Even before the expiry job runs, nothing past retention is served.
	p := f.poll("peer-b", "peer-b", 0, 0)
	if len(p.envelopes) != 1 || envelopeID(t, p.envelopes[0]) != fresh.ID {
		t.Fatalf("poll served expired envelopes: %d", len(p.envelopes))
	}

	f.srv.expire(context.Background())
	if n, ids := f.counts(); n != 1 || ids != 1 {
		t.Fatalf("after expiry: %d envelopes, %d ids; want 1, 1", n, ids)
	}
	// Expired ids are forgotten: a reseal with a fresh ts is accepted.
	old.TS = f.clock().Unix()
	_, again := f.sealMsg(old)
	expectStatus(t, f.post("peer-a", again), http.StatusCreated, "")
	// The fresh one is still remembered.
	fresh.TS = f.clock().Unix()
	_, freshAgain := f.sealMsg(fresh)
	expectStatus(t, f.post("peer-a", freshAgain), http.StatusConflict, "duplicate")
}

func TestRunExpiryRunsAndStopsOnCancel(t *testing.T) {
	f := newFixture(t, nil)
	_, raw := f.newEnvelope("peer-a", "peer-b")
	f.mustPost("peer-a", raw)
	f.advance(envelope.Retention + time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.srv.RunExpiry(ctx, 10*time.Millisecond); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if n, ids := f.counts(); n == 0 && ids == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("RunExpiry did not expire old rows")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunExpiry did not return after cancel")
	}
}

func TestPostWithForeignFrom403(t *testing.T) {
	f := newFixture(t, nil)
	_, raw := f.newEnvelope("peer-b", "peer-a") // claims to be from peer-b
	expectStatus(t, f.post("peer-a", raw), http.StatusForbidden, "forbidden")
	if n, ids := f.counts(); n != 0 || ids != 0 {
		t.Fatalf("forged envelope stored (%d, %d)", n, ids)
	}
}

func TestPollAndAckOfAnotherPeersMailbox403(t *testing.T) {
	f := newFixture(t, nil)
	e, raw := f.newEnvelope("peer-a", "peer-b")
	f.mustPost("peer-a", raw)

	expectStatus(t, f.do(http.MethodGet, "/v1/poll?to=peer-b&timeout=0", "peer-a", nil), http.StatusForbidden, "forbidden")
	expectStatus(t, f.do(http.MethodGet, "/v1/poll?timeout=0", "peer-a", nil), http.StatusForbidden, "forbidden")
	expectStatus(t, f.ack("peer-a", e.ID, "peer-b"), http.StatusForbidden, "forbidden")
	// Acking another peer's envelope through one's own mailbox finds nothing.
	expectStatus(t, f.ack("peer-a", e.ID, "peer-a"), http.StatusNotFound, "not_found")

	if p := f.poll("peer-b", "peer-b", 0, 0); len(p.envelopes) != 1 {
		t.Fatal("envelope was removed by the wrong peer")
	}
}

func TestAckRequestValidation(t *testing.T) {
	f := newFixture(t, nil)
	e, raw := f.newEnvelope("peer-a", "peer-b")
	f.mustPost("peer-a", raw)
	path := "/v1/ack/" + e.ID
	for name, body := range map[string]string{
		"empty":         ``,
		"not json":      `to=peer-b`,
		"unknown field": `{"to":"peer-b","id":"x"}`,
		"trailing":      `{"to":"peer-b"}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			expectStatus(t, f.do(http.MethodPost, path, "peer-b", []byte(body)), http.StatusBadRequest, "invalid")
		})
	}
	expectStatus(t, f.do(http.MethodPost, path, "peer-b", bytes.Repeat([]byte(" "), 2*maxAckBodyBytes)), http.StatusRequestEntityTooLarge, "too_large")
	expectStatus(t, f.ack("peer-b", "not-a-ulid", "peer-b"), http.StatusBadRequest, "invalid")
	expectStatus(t, f.ack("peer-b", strings.ToLower(e.ID), "peer-b"), http.StatusBadRequest, "invalid")
	expectStatus(t, f.ack("peer-b", e.ID, "peer-b"), http.StatusOK, "")
}

func TestHeaderModeIdentity(t *testing.T) {
	f := newFixture(t, nil)
	e, raw := f.newEnvelope("peer-a", "peer-b")
	endpoints := []struct{ method, path, body string }{
		{http.MethodPost, "/v1/msg", string(raw)},
		{http.MethodGet, "/v1/poll?to=peer-a&timeout=0", ""},
		{http.MethodPost, "/v1/ack/" + e.ID, `{"to":"peer-a"}`},
	}
	send := func(method, path, body string, values ...string) response {
		req, _ := http.NewRequest(method, f.hs.URL+path, strings.NewReader(body))
		for _, v := range values {
			req.Header.Add(DefaultFingerprintHeader, v)
		}
		return f.send(req)
	}
	unknown := testFingerprint("stranger")
	for _, ep := range endpoints {
		expectStatus(t, send(ep.method, ep.path, ep.body), http.StatusUnauthorized, "no_identity")
		expectStatus(t, send(ep.method, ep.path, ep.body, ""), http.StatusUnauthorized, "no_identity")
		expectStatus(t, send(ep.method, ep.path, ep.body, unknown), http.StatusForbidden, "forbidden")
		expectStatus(t, send(ep.method, ep.path, ep.body, "not-a-fingerprint"), http.StatusForbidden, "forbidden")
		// Two values are ambiguous, even if one is valid.
		expectStatus(t, send(ep.method, ep.path, ep.body, f.fp["peer-a"], unknown), http.StatusForbidden, "forbidden")
	}
	// Edge formats (upper case, colon separated) normalize to the same peer.
	fp := strings.ToUpper(f.fp["peer-a"])
	var colon []string
	for i := 0; i < len(fp); i += 2 {
		colon = append(colon, fp[i:i+2])
	}
	expectStatus(t, send(http.MethodPost, "/v1/msg", string(raw), strings.Join(colon, ":")), http.StatusCreated, "")
	if n, _ := f.counts(); n != 1 {
		t.Fatalf("%d envelopes stored, want 1", n)
	}
}

func TestRateLimitPerSender429(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.PostsPerHour = 3 })
	for range 3 {
		_, raw := f.newEnvelope("peer-a", "peer-b")
		f.mustPost("peer-a", raw)
	}
	_, raw := f.newEnvelope("peer-a", "peer-b")
	expectStatus(t, f.post("peer-a", raw), http.StatusTooManyRequests, "rate_limited")

	// Other senders are unaffected.
	_, other := f.newEnvelope("peer-b", "peer-a")
	f.mustPost("peer-b", other)

	// A rejected post does not burn its id; it goes through once the
	// window has moved on (resealed with a fresh ts, as a bridge would).
	f.advance(time.Hour + time.Second)
	m := f.msg("peer-a", "peer-b")
	m.ID = envelopeID(t, raw)
	_, raw = f.sealMsg(m)
	f.mustPost("peer-a", raw)
}

func TestQueueCap429(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.MaxQueuedPerPeer = 2 })
	var first string
	for i := range 2 {
		e, raw := f.newEnvelope("peer-a", "peer-b")
		f.mustPost("peer-a", raw)
		if i == 0 {
			first = e.ID
		}
	}
	_, raw := f.newEnvelope("peer-a", "peer-b")
	expectStatus(t, f.post("peer-a", raw), http.StatusTooManyRequests, "queue_full")
	// peer-a's own queue is separate.
	_, toA := f.newEnvelope("peer-b", "peer-a")
	f.mustPost("peer-b", toA)
	// Acking frees a slot.
	expectStatus(t, f.ack("peer-b", first, "peer-b"), http.StatusOK, "")
	f.mustPost("peer-a", raw)
}

func TestPollerConcurrencyCap(t *testing.T) {
	f := newFixture(t, nil)
	f.srv.pollers = newConcurrencyLimiter(1)
	done := make(chan pollResult, 1)
	go func() { done <- f.poll("peer-b", "peer-b", 0, 20) }()
	deadline := time.Now().Add(5 * time.Second)
	for f.srv.pollers.inUse("peer-b") != 1 {
		if time.Now().After(deadline) {
			t.Fatal("long poll never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	expectStatus(t, f.do(http.MethodGet, "/v1/poll?to=peer-b&timeout=0", "peer-b", nil), http.StatusTooManyRequests, "rate_limited")
	// peer-a is unaffected.
	expectStatus(t, f.do(http.MethodGet, "/v1/poll?to=peer-a&timeout=0", "peer-a", nil), http.StatusOK, "")
	_, raw := f.newEnvelope("peer-a", "peer-b")
	f.mustPost("peer-a", raw)
	if p := <-done; len(p.envelopes) != 1 {
		t.Fatalf("long poll got %d envelopes", len(p.envelopes))
	}
	// The slot is released after the poll returns.
	expectStatus(t, f.do(http.MethodGet, "/v1/poll?to=peer-b&timeout=0", "peer-b", nil), http.StatusOK, "")
}

func TestConcurrentPostsSameIDStoreOnce(t *testing.T) {
	f := newFixture(t, nil)
	_, raw := f.newEnvelope("peer-a", "peer-b")
	var wg sync.WaitGroup
	statuses := make(chan int, 8)
	for range 8 {
		wg.Go(func() { statuses <- f.post("peer-a", raw).status })
	}
	wg.Wait()
	close(statuses)
	created := 0
	for s := range statuses {
		switch s {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
		default:
			t.Fatalf("unexpected status %d", s)
		}
	}
	if created != 1 {
		t.Fatalf("%d posts created, want 1", created)
	}
}

func TestNewRejectsBadInput(t *testing.T) {
	st, err := OpenStore(t.TempDir() + "/relay.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := New(baseConfig(), nil, nil); err == nil {
		t.Fatal("New accepted a nil store")
	}
	bad := baseConfig()
	bad.Identity = "none"
	if _, err := New(bad, st, nil); err == nil {
		t.Fatal("New accepted an invalid identity mode")
	}
	s, err := New(baseConfig(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.Listen != DefaultListen || s.cfg.FingerprintHeader != DefaultFingerprintHeader ||
		s.cfg.PostsPerHour != DefaultPostsPerHour || s.cfg.MaxQueuedPerPeer != DefaultMaxQueuedPerPeer {
		t.Fatalf("defaults not applied: %+v", s.cfg)
	}
	if _, err := s.ServerTLSConfig(); err == nil {
		t.Fatal("ServerTLSConfig worked in header mode")
	}
}
