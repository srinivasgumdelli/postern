package bridge

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"postern/internal/audit"
	"postern/internal/envelope"
)

// withAudit gives o a real audit log in a fresh directory.
func withAudit(t *testing.T, o Options) (Options, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit", "audit.jsonl")
	l, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	o.Audit = l
	return o, path
}

// auditEntries returns every entry of the log at path after checking
// that its chain verifies.
func auditEntries(t *testing.T, path string) []audit.Entry {
	t.Helper()
	if _, err := audit.Verify(path); err != nil {
		t.Fatalf("audit chain: %v", err)
	}
	es, err := audit.Tail(path, 100000)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

func eventNames(es []audit.Entry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Event)
	}
	return out
}

func only(t *testing.T, es []audit.Entry, event string) audit.Entry {
	t.Helper()
	var found []audit.Entry
	for _, e := range es {
		if e.Event == event {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d %s events, want 1; events: %v", len(found), event, eventNames(es))
	}
	return found[0]
}

// assertNoContent checks the raw audit file for content markers.
func assertNoContent(t *testing.T, path string, markers ...string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range append([]string{plainMarker, secretMarker, "BEGIN", "PRIVATE KEY", "Re: "}, markers...) {
		if bytes.Contains(raw, []byte(m)) {
			t.Fatalf("audit log contains %q", m)
		}
	}
}

// TestAuditSendReceiveBlocked: a send, its receipt, a blocked send and a
// reply each leave one metadata-only event on the right machine.
func TestAuditSendReceiveBlocked(t *testing.T) {
	w := newWorld(t)
	oa, pathA := withAudit(t, w.options(w.a, "", w.b))
	ob, pathB := withAudit(t, w.options(w.b, "", w.a))
	a, b := w.open(oa), w.open(ob)
	ctx := ctxT(t)

	subject, body := msg("audit", "body line\nsecond line")
	res := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	_, err := a.Send(ctx, sess1, SendRequest{
		To: "peer-b", Subject: plainMarker + " leak", Body: "fine\nkey = " + secretMarker, Thread: res.Thread,
	})
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("blocked send err = %v", err)
	}
	pollAll(t, b)
	reply, err := b.Reply(ctx, "review", res.Thread, plainMarker+" reply body")
	if err != nil {
		t.Fatal(err)
	}
	pollAll(t, a)

	ea := auditEntries(t, pathA)
	s := only(t, ea, audit.EventSent)
	if s.Actor != audit.ActorBridge || s.Peer != "peer-b" || s.Session != sess1 || s.Thread != res.Thread ||
		s.ID != res.ID || s.SizeBytes != int64(len(body)) || s.Status != 201 {
		t.Fatalf("sent event = %+v", s)
	}
	bl := only(t, ea, audit.EventBlockedByScanner)
	if bl.Reason != "rule=test-secret,line=2" || bl.Peer != "peer-b" || bl.Session != sess1 || bl.Thread != res.Thread || bl.ID != "" {
		t.Fatalf("blocked event = %+v", bl)
	}
	r := only(t, ea, audit.EventReceived)
	if r.ID != reply.ID || r.Peer != "peer-b" || r.Thread != res.Thread || r.Session != "" {
		t.Fatalf("received event on A = %+v", r)
	}

	eb := auditEntries(t, pathB)
	r = only(t, eb, audit.EventReceived)
	if r.ID != res.ID || r.Peer != "peer-a" || r.Thread != res.Thread || r.SizeBytes != int64(len(body)) {
		t.Fatalf("received event on B = %+v", r)
	}
	// The sending session's name is the other machine's content.
	if r.Session != "" {
		t.Fatalf("received event records the remote session %q", r.Session)
	}
	if s := only(t, eb, audit.EventSent); s.ID != reply.ID || s.Session != "review" {
		t.Fatalf("reply event = %+v", s)
	}
	assertNoContent(t, pathA)
	// B's log must not name A's session (sess1 starts with sessionMarker).
	assertNoContent(t, pathB, sessionMarker)
}

func TestAuditQueuedDeliveredRejected(t *testing.T) {
	w := newWorld(t)
	oa, path := withAudit(t, w.options(w.a, "", w.b))
	a := w.open(oa)
	ctx := ctxT(t)
	subject, body := msg("queue", "queue")

	w.relay.setOffline(true)
	q := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	if q.Status != StatusQueued {
		t.Fatalf("status = %s", q.Status)
	}
	// Retries during the outage are not audited.
	if _, err := a.FlushOutbox(ctx); err != nil {
		t.Fatal(err)
	}
	w.relay.setOffline(false)
	if n, err := a.FlushOutbox(ctx); err != nil || n != 1 {
		t.Fatalf("FlushOutbox = %d, %v", n, err)
	}
	w.relay.setPostCode(400)
	if _, err := a.Send(ctx, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body}); !errors.Is(err, ErrRejected) {
		t.Fatalf("send on 400 err = %v", err)
	}

	es := auditEntries(t, path)
	if got := strings.Join(eventNames(es), ","); got != "queued,delivered,rejected" {
		t.Fatalf("events = %s", got)
	}
	if es[0].ID != q.ID || es[0].Reason == "" || es[1].ID != q.ID || es[1].Status != 201 || es[1].Session != sess1 {
		t.Fatalf("queued/delivered = %+v / %+v", es[0], es[1])
	}
	if es[2].Status != 400 || es[2].Reason != "rejected" {
		t.Fatalf("rejected = %+v", es[2])
	}
	assertNoContent(t, path)
}

func TestAuditOutboxExpiry(t *testing.T) {
	w := newWorld(t)
	oa, path := withAudit(t, w.options(w.a, "", w.b))
	a := w.open(oa)
	subject, body := msg("expire", "expire")
	w.relay.setOffline(true)
	q := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	w.clock.Advance(envelope.Retention + time.Hour)
	if _, err := a.FlushOutbox(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	e := only(t, auditEntries(t, path), audit.EventRejected)
	if e.ID != q.ID || e.Reason != "expired" || e.Peer != "peer-b" {
		t.Fatalf("expiry event = %+v", e)
	}
}

func TestAuditLimitsAndTrip(t *testing.T) {
	w := newWorld(t)
	oa, path := withAudit(t, w.options(w.a, "", w.b))
	oa.Limits = Limits{SessionPerHour: 100, GlobalPerHour: 100, ThreadMax: 2, ThreadBurst: 100}
	a := w.open(oa)
	ctx := ctxT(t)
	subject, body := msg("limit", "limit")

	first := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	req := SendRequest{To: "peer-b", Subject: subject, Body: body, Thread: first.Thread}
	mustSend(t, a, sess1, req)
	if _, err := a.Send(ctx, sess1, req); !errors.Is(err, ErrThreadTripped) {
		t.Fatalf("third send err = %v", err)
	}
	// Refused again on the paused thread: no second trip event.
	if _, err := a.Send(ctx, sess1, req); !errors.Is(err, ErrThreadTripped) {
		t.Fatalf("fourth send err = %v", err)
	}
	tr := only(t, auditEntries(t, path), audit.EventThreadTripped)
	if tr.Thread != first.Thread || tr.Reason != "cap" || tr.Peer != "peer-b" || tr.Session != sess1 {
		t.Fatalf("trip event = %+v", tr)
	}

	ob, pathB := withAudit(t, w.options(w.b, "", w.a))
	ob.Limits = Limits{SessionPerHour: 1, GlobalPerHour: 100}
	b := w.open(ob)
	mustSend(t, b, "review", SendRequest{To: "peer-a", Subject: subject, Body: body})
	if _, err := b.Send(ctx, "review", SendRequest{To: "peer-a", Subject: subject, Body: body}); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("second send err = %v", err)
	}
	rl := only(t, auditEntries(t, pathB), audit.EventRateLimited)
	if rl.Reason != "session" || rl.Session != "review" || rl.Peer != "peer-a" {
		t.Fatalf("rate limit event = %+v", rl)
	}
	assertNoContent(t, path)
	assertNoContent(t, pathB)
}

func TestAuditDropped(t *testing.T) {
	w := newWorld(t)
	ob, path := withAudit(t, w.options(w.b, "", w.a))
	b := w.open(ob)
	c := newIdentity(t, w.ca, "peer-c")
	now := w.clock.Now()

	wrong := sealFrom(t, w.a, "peer-c", w.b.pub, now, nil)
	stranger := sealFrom(t, c, "peer-b", w.b.pub, now, nil)
	good := sealFrom(t, w.a, "peer-b", w.b.pub, now, nil)
	for _, e := range []envelope.Envelope{wrong, stranger, good} {
		w.relay.inject("peer-b", e)
	}
	if n := pollAll(t, b); n != 1 {
		t.Fatalf("stored %d, want 1", n)
	}
	es := auditEntries(t, path)
	want := map[string]audit.Entry{
		wrong.ID:    {Event: audit.EventDropped, Peer: "peer-a", Reason: "wrong_recipient"},
		stranger.ID: {Event: audit.EventDropped, Peer: "", Reason: "unknown_sender"},
		good.ID:     {Event: audit.EventReceived, Peer: "peer-a"},
	}
	if len(es) != len(want) {
		t.Fatalf("events = %v", eventNames(es))
	}
	for _, e := range es {
		wnt, ok := want[e.ID]
		if !ok || e.Event != wnt.Event || e.Peer != wnt.Peer || e.Reason != wnt.Reason {
			t.Fatalf("event %+v, want %+v", e, wnt)
		}
	}
	// The injected messages carry plainMarker and a session starting
	// with sessionMarker; neither may reach the log.
	assertNoContent(t, path, sessionMarker)
}

func TestAuditRelayStatus(t *testing.T) {
	w := newWorld(t)
	oa, path := withAudit(t, w.options(w.a, "", w.b))
	a := w.open(oa)
	ctx := ctxT(t)

	w.relay.setOffline(true)
	_, _ = a.PollOnce(ctx)
	w.clock.Advance(90 * time.Second)
	_, _ = a.PollOnce(ctx)
	w.clock.Advance(60 * time.Second)
	_, _ = a.PollOnce(ctx) // unreachable now
	w.clock.Advance(60 * time.Second)
	_, _ = a.PollOnce(ctx) // still unreachable: no second event
	w.relay.setOffline(false)
	if _, err := a.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	w.relay.revoke(w.a.cert.Fingerprint, true)
	_, _ = a.PollOnce(ctx)
	_, _ = a.PollOnce(ctx) // still refused: no second event
	w.relay.revoke(w.a.cert.Fingerprint, false)
	if _, err := a.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := a.PollOnce(ctx); err != nil { // healthy: nothing to record
		t.Fatal(err)
	}

	es := auditEntries(t, path)
	got := strings.Join(eventNames(es), ",")
	if got != "relay_unreachable,relay_recovered,relay_auth_failed,relay_recovered" {
		t.Fatalf("events = %s", got)
	}
	if es[0].Reason == "" || es[2].Status != 403 || es[3].Status != 200 {
		t.Fatalf("events = %+v", es)
	}
}

type failingAuditor struct{ calls int }

func (f *failingAuditor) Record(context.Context, audit.Event) error {
	f.calls++
	return errors.New("disk full")
}

// TestAuditFailureDoesNotBlock: the audit log is evidence; a failing
// write is logged and messaging carries on.
func TestAuditFailureDoesNotBlock(t *testing.T) {
	w := newWorld(t)
	fa := &failingAuditor{}
	oa := w.options(w.a, "", w.b)
	oa.Audit = fa
	a := w.open(oa)
	subject, body := msg("fail", "fail")
	if r := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body}); r.Status != StatusSent {
		t.Fatalf("status = %s", r.Status)
	}
	if fa.calls != 1 {
		t.Fatalf("auditor called %d times, want 1", fa.calls)
	}
}
