package bridge

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"postern/internal/envelope"
	"postern/internal/ulid"
)

const (
	sess1 = sessionMarker + "1"
	sess2 = sessionMarker + "2"
)

func newID() string { return ulid.New() }

func msg(subject, body string) (string, string) {
	return plainMarker + " " + subject, plainMarker + " " + body
}

func countRows(t *testing.T, b *Bridge, where string, args ...any) int {
	t.Helper()
	var n int
	q := `SELECT COUNT(*) FROM messages`
	if where != "" {
		q += ` WHERE ` + where
	}
	if err := b.db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// storedContent opens a stored row's sealed content.
func storedContent(t *testing.T, b *Bridge, id string) rowContent {
	t.Helper()
	var blob []byte
	if err := b.db.QueryRow(`SELECT sealed FROM messages WHERE id = ?`, id).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	rc, err := b.crypt.open(id, blob)
	if err != nil {
		t.Fatal(err)
	}
	return rc
}

func rowState(t *testing.T, b *Bridge, id string) string {
	t.Helper()
	var s string
	if err := b.db.QueryRow(`SELECT state FROM messages WHERE id = ?`, id).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func mustSend(t *testing.T, b *Bridge, session string, req SendRequest) SendResult {
	t.Helper()
	res, err := b.Send(ctxT(t), session, req)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	return res
}

func pollAll(t *testing.T, b *Bridge) int {
	t.Helper()
	n, err := b.PollOnce(ctxT(t))
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	return n
}

func TestOpenValidation(t *testing.T) {
	w := newWorld(t)
	cases := map[string]func(*Options){
		"nil scanner":     func(o *Options) { o.Scanner = nil },
		"http relay":      func(o *Options) { o.RelayURL = strings.Replace(o.RelayURL, "https://", "http://", 1) },
		"relay with user": func(o *Options) { o.RelayURL = "https://user:pw@127.0.0.1:1" },
		"relay query":     func(o *Options) { o.RelayURL = o.RelayURL + "/?x=1" },
		"no client cert":  func(o *Options) { o.ClientCert.Certificate = nil },
		"bad self":        func(o *Options) { o.Self = "Peer A" },
		"peer is self":    func(o *Options) { o.Peers = append(o.Peers, Peer{Name: o.Self, PublicKey: o.Peers[0].PublicKey}) },
		"duplicate peer":  func(o *Options) { o.Peers = append(o.Peers, o.Peers[0]) },
		"no peer key":     func(o *Options) { o.Peers[0].PublicKey = nil },
		"no peers":        func(o *Options) { o.Peers = nil },
		"no box key":      func(o *Options) { o.BoxPrivate = nil },
		"no inbox key":    func(o *Options) { o.InboxKey = nil },
		"no db path":      func(o *Options) { o.DBPath = "" },
		"negative limit":  func(o *Options) { o.Limits.ThreadMax = -1 },
		"negative poll":   func(o *Options) { o.PollTimeout = -time.Second },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			o := w.options(w.a, "", w.b)
			mod(&o)
			b, err := Open(o)
			if err == nil {
				b.Close()
				t.Fatal("Open succeeded")
			}
		})
	}
}

func TestDatabasePermissions(t *testing.T) {
	w := newWorld(t)
	dir := filepath.Join(t.TempDir(), "nested", "postern")
	path := filepath.Join(dir, "inbox.db")
	b := w.open(w.options(w.a, path, w.b))
	subject, body := msg("perm", "perm")
	mustSend(t, b, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})

	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %v, %v; want 0700", fi.Mode().Perm(), err)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		fi, err := os.Stat(p)
		if err != nil {
			if p == path {
				t.Fatal(err)
			}
			continue
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v; want 0600", filepath.Base(p), fi.Mode().Perm())
		}
	}
	var mode string
	if err := b.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || !strings.EqualFold(mode, "wal") {
		t.Fatalf("journal_mode = %q, %v; want wal", mode, err)
	}
}

func TestScannerBlocksSendAndReply(t *testing.T) {
	w := newWorld(t)
	a, b := w.pair()
	ctx := ctxT(t)

	_, err := a.Send(ctx, sess1, SendRequest{
		To: "peer-b", Subject: plainMarker + " config", Body: "line one\nkey = " + secretMarker + "\n",
	})
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("Send err = %v; want ErrBlocked", err)
	}
	if !strings.Contains(err.Error(), "test-secret rule matched on body line 2") {
		t.Fatalf("error does not carry the scanner text: %v", err)
	}
	if strings.Contains(err.Error(), secretMarker) {
		t.Fatal("error echoes the secret")
	}
	_, err = a.Send(ctx, sess1, SendRequest{To: "peer-b", Subject: secretMarker, Body: plainMarker})
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("Send with secret subject err = %v; want ErrBlocked", err)
	}
	if n := countRows(t, a, ""); n != 0 {
		t.Fatalf("blocked send stored %d rows", n)
	}
	if n := w.relay.requestCount(); n != 0 {
		t.Fatalf("blocked send reached the relay (%d requests)", n)
	}

	// Reply: B gets a real message (so the thread exists), then tries to
	// reply with a secret.
	subject, body := msg("question", "question")
	sent := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	pollAll(t, b)
	before := w.relay.requestCount()
	_, err = b.Reply(ctx, sess2, sent.Thread, "here it is: "+secretMarker)
	if !errors.Is(err, ErrBlocked) || !strings.Contains(err.Error(), "test-secret rule matched on body line 1") {
		t.Fatalf("Reply err = %v; want ErrBlocked with scanner text", err)
	}
	if n := countRows(t, b, `direction = 'out'`); n != 0 {
		t.Fatalf("blocked reply stored %d rows", n)
	}
	if n := w.relay.requestCount(); n != before {
		t.Fatalf("blocked reply reached the relay")
	}
}

func TestSendPollAckRoundTrip(t *testing.T) {
	w := newWorld(t)
	a, b := w.pair()
	ctx := ctxT(t)
	subject, body := msg("hello", "body with <tags> & \"quotes\"\nand lines")

	res := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	if res.Status != StatusSent || !ulid.Valid(res.ID) || !envelope.ValidThreadID(res.Thread) {
		t.Fatalf("Send result = %+v", res)
	}
	if got := rowState(t, a, res.ID); got != "sent" {
		t.Fatalf("outbound state = %q; want sent", got)
	}

	if n := pollAll(t, b); n != 1 {
		t.Fatalf("PollOnce stored %d; want 1", n)
	}
	if !w.relay.isAcked(res.ID) || w.relay.pending("peer-b") != 0 {
		t.Fatal("message not acked at the relay")
	}
	msgs, err := b.CheckInbox(ctx, InboxQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("inbox has %d messages; want 1", len(msgs))
	}
	m := msgs[0]
	if m.ID != res.ID || m.Thread != res.Thread || m.FromPeer != "peer-a" || m.FromSession != sess1 ||
		m.Subject != subject || m.Body != body || m.Read {
		t.Fatalf("inbox message = %+v", m)
	}
	if d := w.clock.Now().Sub(m.ReceivedAt); d < 0 || d > time.Minute {
		t.Fatalf("ReceivedAt off by %v", d)
	}
	// The sender's own outbox never shows up in its inbox.
	if msgs, _ := a.CheckInbox(ctx, InboxQuery{IncludeRead: true}); len(msgs) != 0 {
		t.Fatalf("sender inbox has %d messages", len(msgs))
	}

	n, err := b.MarkRead(ctx, []string{m.ID})
	if err != nil || n != 1 {
		t.Fatalf("MarkRead = %d, %v; want 1", n, err)
	}
	if n, _ := b.MarkRead(ctx, []string{m.ID}); n != 0 {
		t.Fatalf("second MarkRead changed %d", n)
	}
	if msgs, _ := b.CheckInbox(ctx, InboxQuery{}); len(msgs) != 0 {
		t.Fatal("read message still listed as unread")
	}
	msgs, _ = b.CheckInbox(ctx, InboxQuery{IncludeRead: true})
	if len(msgs) != 1 || !msgs[0].Read {
		t.Fatalf("IncludeRead = %+v", msgs)
	}
	// MarkRead ignores outbound ids.
	if n, _ := a.MarkRead(ctx, []string{res.ID}); n != 0 {
		t.Fatalf("MarkRead changed an outbound row")
	}
	if _, err := b.MarkRead(ctx, []string{"not-an-id"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("MarkRead bad id err = %v", err)
	}
}

func TestSendValidation(t *testing.T) {
	w := newWorld(t)
	c := newIdentity(t, w.ca, "peer-c")
	w.relay.bind(c.cert.Fingerprint, c.name)
	a := w.open(w.options(w.a, "", w.b, c))
	ctx := ctxT(t)
	subject, body := msg("s", "b")

	check := func(name string, err, want error) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Fatalf("%s: err = %v; want %v", name, err, want)
		}
		if strings.Contains(err.Error(), plainMarker) {
			t.Fatalf("%s: error echoes content: %v", name, err)
		}
	}
	_, err := a.Send(ctx, "Bad Session", SendRequest{To: "peer-b", Subject: subject, Body: body})
	check("session", err, ErrInvalid)
	_, err = a.Send(ctx, sess1, SendRequest{To: "peer-z", Subject: subject, Body: body})
	check("unknown peer", err, ErrUnknownPeer)
	_, err = a.Send(ctx, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body, Thread: "t-free-text"})
	check("thread", err, ErrInvalid)
	_, err = a.Send(ctx, sess1, SendRequest{To: "peer-b", Subject: subject, Body: strings.Repeat(plainMarker, envelope.MaxBodyBytes/len(plainMarker)+1)})
	check("big body", err, ErrInvalid)
	if !strings.Contains(err.Error(), "body over 32768 bytes") {
		t.Fatalf("big body message = %v", err)
	}
	_, err = a.Send(ctx, sess1, SendRequest{To: "peer-b", Subject: strings.Repeat("x", envelope.MaxSubjectBytes+1), Body: body})
	check("big subject", err, ErrInvalid)
	_, err = a.Send(ctx, sess1, SendRequest{To: "peer-b", Subject: plainMarker + "\x1b[31m", Body: body})
	check("control subject", err, ErrInvalid)
	_, err = a.Send(ctx, sess1, SendRequest{To: "peer-b", Subject: " ", Body: body})
	check("empty subject", err, ErrInvalid)
	_, err = a.Send(ctx, sess1, SendRequest{To: "peer-b", Subject: subject, Body: ""})
	check("empty body", err, ErrInvalid)
	if n := countRows(t, a, ""); n != 0 {
		t.Fatalf("invalid sends stored %d rows", n)
	}

	// A body of exactly the cap, full of characters JSON would escape,
	// still fits.
	full := strings.Repeat("\"\\<>\n", envelope.MaxBodyBytes/5)
	full += strings.Repeat("x", envelope.MaxBodyBytes-len(full))
	if res := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: full}); res.Status != StatusSent {
		t.Fatalf("full body status = %s", res.Status)
	}

	// A thread belongs to one peer.
	res := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	_, err = a.Send(ctx, sess1, SendRequest{To: "peer-c", Subject: subject, Body: body, Thread: res.Thread})
	check("thread of another peer", err, ErrInvalid)
	// An explicit, new, valid thread id is accepted.
	tid := envelope.NewThreadID()
	if res := mustSend(t, a, sess1, SendRequest{To: "peer-c", Subject: subject, Body: body, Thread: tid}); res.Thread != tid {
		t.Fatalf("thread = %s; want %s", res.Thread, tid)
	}
}

func TestReply(t *testing.T) {
	w := newWorld(t)
	a, b := w.pair()
	ctx := ctxT(t)
	subject, body := msg("plan", "first")

	first := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	pollAll(t, b)
	rep, err := b.Reply(ctx, sess2, first.Thread, plainMarker+" reply one")
	if err != nil || rep.Status != StatusSent || rep.Thread != first.Thread {
		t.Fatalf("Reply = %+v, %v", rep, err)
	}
	var replyTo, to string
	if err := b.db.QueryRow(`SELECT reply_to, peer FROM messages WHERE id = ?`, rep.ID).Scan(&replyTo, &to); err != nil {
		t.Fatal(err)
	}
	if replyTo != first.ID || to != "peer-a" {
		t.Fatalf("reply_to = %s, peer = %s; want %s, peer-a", replyTo, to, first.ID)
	}

	pollAll(t, a)
	msgs, err := a.CheckInbox(ctx, InboxQuery{Thread: first.Thread})
	if err != nil || len(msgs) != 1 {
		t.Fatalf("A inbox = %v, %v", msgs, err)
	}
	if msgs[0].Subject != "Re: "+subject || msgs[0].FromSession != sess2 || msgs[0].FromPeer != "peer-b" {
		t.Fatalf("reply as received = %+v", msgs[0])
	}
	// reply_to travelled inside the box.
	if err := a.db.QueryRow(`SELECT reply_to FROM messages WHERE id = ?`, rep.ID).Scan(&replyTo); err != nil || replyTo != first.ID {
		t.Fatalf("received reply_to = %s, %v", replyTo, err)
	}

	// A replies back: subject is not doubled, reply_to is B's reply.
	rep2, err := a.Reply(ctx, sess1, first.Thread, plainMarker+" reply two")
	if err != nil {
		t.Fatal(err)
	}
	pollAll(t, b)
	msgs, _ = b.CheckInbox(ctx, InboxQuery{Thread: first.Thread, IncludeRead: true})
	if len(msgs) != 2 || msgs[1].ID != rep2.ID || msgs[1].Subject != "Re: "+subject {
		t.Fatalf("B thread = %+v", msgs)
	}
	if err := b.db.QueryRow(`SELECT reply_to FROM messages WHERE id = ?`, rep2.ID).Scan(&replyTo); err != nil || replyTo != rep.ID {
		t.Fatalf("second reply_to = %s, %v; want %s", replyTo, err, rep.ID)
	}

	// A first subject that already starts with "Re: " is not doubled.
	re := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: "Re: " + subject, Body: body})
	pollAll(t, b)
	r3, err := b.Reply(ctx, sess2, re.Thread, plainMarker+" r3")
	if err != nil {
		t.Fatal(err)
	}
	pollAll(t, a)
	msgs, _ = a.CheckInbox(ctx, InboxQuery{Thread: re.Thread})
	if len(msgs) != 1 || msgs[0].ID != r3.ID || msgs[0].Subject != "Re: "+subject {
		t.Fatalf("Re: thread = %+v", msgs)
	}

	// Long multibyte subject: truncated on a rune boundary.
	long := plainMarker + strings.Repeat("é", 200) // 16 + 400 bytes > 256
	long = truncateUTF8(long, envelope.MaxSubjectBytes)
	lt := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: long, Body: body})
	pollAll(t, b)
	lr, err := b.Reply(ctx, sess2, lt.Thread, plainMarker+" long")
	if err != nil {
		t.Fatal(err)
	}
	subj := storedContent(t, b, lr.ID).Subject
	if len(subj) > envelope.MaxSubjectBytes || !utf8.ValidString(subj) || !strings.HasPrefix(subj, "Re: "+plainMarker) {
		t.Fatalf("long reply subject: %d bytes, valid=%v", len(subj), utf8.ValidString(subj))
	}

	// Unknown and invalid threads.
	if _, err := b.Reply(ctx, sess2, envelope.NewThreadID(), plainMarker); !errors.Is(err, ErrUnknownThread) {
		t.Fatalf("unknown thread err = %v", err)
	}
	if _, err := b.Reply(ctx, sess2, "t-nope", plainMarker); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid thread err = %v", err)
	}
	if _, err := b.Reply(ctx, "Bad", first.Thread, plainMarker); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid session err = %v", err)
	}
}

func TestRateLimits(t *testing.T) {
	w := newWorld(t)
	o := w.options(w.a, "", w.b)
	o.Limits = Limits{SessionPerHour: 3, GlobalPerHour: 5}
	a := w.open(o)
	ctx := ctxT(t)
	subject, body := msg("rate", "rate")
	req := SendRequest{To: "peer-b", Subject: subject, Body: body}

	for i := 0; i < 3; i++ {
		mustSend(t, a, sess1, req)
	}
	if _, err := a.Send(ctx, sess1, req); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("4th send by one session err = %v; want ErrRateLimited", err)
	}
	mustSend(t, a, sess2, req)
	mustSend(t, a, sess2, req)
	_, err := a.Send(ctx, sess2, req)
	if !errors.Is(err, ErrRateLimited) || !strings.Contains(err.Error(), "machine") {
		t.Fatalf("6th send overall err = %v; want global ErrRateLimited", err)
	}
	if n := countRows(t, a, `direction = 'out'`); n != 5 {
		t.Fatalf("stored %d outbound; want 5", n)
	}
	w.clock.Advance(61 * time.Minute)
	mustSend(t, a, sess1, req)
}

func TestThreadCapTripAndReset(t *testing.T) {
	w := newWorld(t)
	oa := w.options(w.a, "", w.b)
	oa.Limits = Limits{ThreadMax: 4, ThreadBurst: 100}
	a := w.open(oa)
	b := w.open(w.options(w.b, "", w.a))
	ctx := ctxT(t)
	subject, body := msg("cap", "cap")

	first := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	req := SendRequest{To: "peer-b", Subject: subject, Body: body, Thread: first.Thread}
	mustSend(t, a, sess1, req)
	// An inbound message counts toward the cap too.
	pollAll(t, b)
	if _, err := b.Reply(ctx, sess2, first.Thread, plainMarker+" reply"); err != nil {
		t.Fatal(err)
	}
	pollAll(t, a)
	mustSend(t, a, sess1, req) // 4th message in the thread

	_, err := a.Send(ctx, sess1, req)
	if !errors.Is(err, ErrThreadTripped) {
		t.Fatalf("5th message err = %v; want ErrThreadTripped", err)
	}
	if !strings.Contains(err.Error(), "postern thread reset "+first.Thread) || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("trip message = %v", err)
	}
	var reason string
	if err := a.db.QueryRow(`SELECT trip_reason FROM threads WHERE thread = ?`, first.Thread).Scan(&reason); err != nil || reason != "cap" {
		t.Fatalf("trip_reason = %q, %v", reason, err)
	}
	if _, err := a.Reply(ctx, sess1, first.Thread, plainMarker+" more"); !errors.Is(err, ErrThreadTripped) {
		t.Fatalf("reply on tripped thread err = %v", err)
	}
	// Other threads are unaffected.
	mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})

	if err := ResetThread(ctx, a.dbPathForTest(t), first.Thread); err != nil {
		t.Fatalf("ResetThread: %v", err)
	}
	for i := 0; i < 4; i++ {
		mustSend(t, a, sess1, req)
	}
	if _, err := a.Send(ctx, sess1, req); !errors.Is(err, ErrThreadTripped) {
		t.Fatalf("after reset, 5th message err = %v; want ErrThreadTripped", err)
	}

	if err := ResetThread(ctx, a.dbPathForTest(t), envelope.NewThreadID()); !errors.Is(err, ErrUnknownThread) {
		t.Fatalf("reset unknown thread err = %v", err)
	}
	if err := ResetThread(ctx, a.dbPathForTest(t), "t-bad"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("reset invalid thread err = %v", err)
	}
	if err := ResetThread(ctx, filepath.Join(t.TempDir(), "missing.db"), first.Thread); !errors.Is(err, ErrUnknownThread) {
		t.Fatalf("reset with no database err = %v", err)
	}
}

func TestThreadBurstTripAndReset(t *testing.T) {
	w := newWorld(t)
	o := w.options(w.a, "", w.b)
	o.Limits = Limits{ThreadMax: 100, ThreadBurst: 3, ThreadBurstWindow: 10 * time.Minute}
	a := w.open(o)
	ctx := ctxT(t)
	subject, body := msg("burst", "burst")

	first := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	req := SendRequest{To: "peer-b", Subject: subject, Body: body, Thread: first.Thread}
	mustSend(t, a, sess1, req)
	mustSend(t, a, sess1, req)
	// The window slides: after it passes, three more fit.
	w.clock.Advance(11 * time.Minute)
	for i := 0; i < 3; i++ {
		mustSend(t, a, sess1, req)
	}
	_, err := a.Send(ctx, sess1, req)
	if !errors.Is(err, ErrThreadTripped) || !strings.Contains(err.Error(), "burst") {
		t.Fatalf("burst err = %v; want ErrThreadTripped (burst)", err)
	}
	// Tripped stays tripped after the window passes.
	w.clock.Advance(11 * time.Minute)
	if _, err := a.Send(ctx, sess1, req); !errors.Is(err, ErrThreadTripped) {
		t.Fatalf("tripped thread err = %v", err)
	}
	if err := ResetThread(ctx, a.dbPathForTest(t), first.Thread); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		mustSend(t, a, sess1, req)
	}
	if _, err := a.Send(ctx, sess1, req); !errors.Is(err, ErrThreadTripped) {
		t.Fatalf("after reset, burst err = %v", err)
	}
}

func TestCheckInboxQueries(t *testing.T) {
	w := newWorld(t)
	oa := w.options(w.a, "", w.b)
	oa.Limits = Limits{ThreadBurst: 100}
	a := w.open(oa)
	b := w.open(w.options(w.b, "", w.a))
	ctx := ctxT(t)
	subject, body := msg("q", "q")

	t1 := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	var ids []string
	ids = append(ids, t1.ID)
	for i := 0; i < 4; i++ {
		r := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body, Thread: t1.Thread})
		ids = append(ids, r.ID)
	}
	t2 := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	ids = append(ids, t2.ID)
	if n := pollAll(t, b); n != 6 {
		t.Fatalf("stored %d; want 6", n)
	}

	all, err := b.CheckInbox(ctx, InboxQuery{})
	if err != nil || len(all) != 6 {
		t.Fatalf("all = %d, %v", len(all), err)
	}
	for i, m := range all {
		if m.ID != ids[i] {
			t.Fatalf("order: got %s at %d; want %s", m.ID, i, ids[i])
		}
	}
	page, _ := b.CheckInbox(ctx, InboxQuery{Limit: 2})
	if len(page) != 2 || page[0].ID != ids[0] {
		t.Fatalf("limit page = %v", page)
	}
	next, _ := b.CheckInbox(ctx, InboxQuery{SinceID: page[1].ID, Limit: 2})
	if len(next) != 2 || next[0].ID != ids[2] || next[1].ID != ids[3] {
		t.Fatalf("since page = %v", next)
	}
	th, _ := b.CheckInbox(ctx, InboxQuery{Thread: t2.Thread})
	if len(th) != 1 || th[0].ID != t2.ID {
		t.Fatalf("thread filter = %v", th)
	}
	if _, err := b.CheckInbox(ctx, InboxQuery{SinceID: newID()}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown since_id err = %v", err)
	}
	if _, err := b.CheckInbox(ctx, InboxQuery{SinceID: "nope"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad since_id err = %v", err)
	}
	if _, err := b.CheckInbox(ctx, InboxQuery{Thread: "t-x"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad thread err = %v", err)
	}
	if _, err := b.CheckInbox(ctx, InboxQuery{Limit: -1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("negative limit err = %v", err)
	}
	if n, err := b.MarkRead(ctx, ids[:3]); err != nil || n != 3 {
		t.Fatalf("MarkRead = %d, %v", n, err)
	}
	unread, _ := b.CheckInbox(ctx, InboxQuery{})
	if len(unread) != 3 || unread[0].ID != ids[3] {
		t.Fatalf("unread = %v", unread)
	}
	withRead, _ := b.CheckInbox(ctx, InboxQuery{IncludeRead: true, Limit: 1000})
	if len(withRead) != 6 {
		t.Fatalf("include read = %d", len(withRead))
	}
}

func TestDefaultLimitsAndCaps(t *testing.T) {
	l, err := Limits{}.withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	want := Limits{SessionPerHour: 30, GlobalPerHour: 60, ThreadMax: 50, ThreadBurst: 10, ThreadBurstWindow: 10 * time.Minute}
	if l != want {
		t.Fatalf("defaults = %+v", l)
	}
	w := newWorld(t)
	o := w.options(w.a, "", w.b)
	o.PollTimeout = 0
	b := w.open(o)
	if b.client.pollTimeout != 25*time.Second {
		t.Fatalf("default poll timeout = %v", b.client.pollTimeout)
	}
	o = w.options(w.a, "", w.b)
	o.PollTimeout = time.Hour
	b = w.open(o)
	if b.client.pollSeconds() != 25 {
		t.Fatalf("capped poll timeout = %v", b.client.pollTimeout)
	}
}

func TestRunDeliversAndReceivesAndStops(t *testing.T) {
	w := newWorld(t)
	oa := w.options(w.a, "", w.b)
	ob := w.options(w.b, "", w.a)
	oa.PollTimeout, ob.PollTimeout = 2*time.Second, 2*time.Second
	a, b := w.open(oa), w.open(ob)
	subject, body := msg("run", "run")

	// Queued while the relay is down; Run's outbox loop delivers it.
	w.relay.setOffline(true)
	q := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	if q.Status != StatusQueued {
		t.Fatalf("status = %s; want queued", q.Status)
	}
	w.relay.setOffline(false)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 2)
	go func() { done <- a.Run(ctx) }()
	go func() { done <- b.Run(ctx) }()

	ictx := ctxT(t)
	waitFor(t, 20*time.Second, "B to receive the queued message", func() bool {
		msgs, err := b.CheckInbox(ictx, InboxQuery{})
		return err == nil && len(msgs) == 1 && msgs[0].ID == q.ID
	})
	rep, err := b.Reply(ictx, sess2, q.Thread, plainMarker+" pong")
	if err != nil || rep.Status != StatusSent {
		t.Fatalf("Reply = %+v, %v", rep, err)
	}
	waitFor(t, 20*time.Second, "A to receive the reply", func() bool {
		msgs, err := a.CheckInbox(ictx, InboxQuery{})
		return err == nil && len(msgs) == 1 && msgs[0].ID == rep.ID
	})

	cancel()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Run returned %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("Run did not stop after cancel")
		}
	}
}

func TestCloseStopsRun(t *testing.T) {
	w := newWorld(t)
	o := w.options(w.a, "", w.b)
	o.PollTimeout = 5 * time.Second
	b, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- b.Run(context.Background()) }()
	time.Sleep(100 * time.Millisecond)
	closed := make(chan error, 1)
	go func() { closed <- b.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop on Close")
	}
	if err := <-closed; err != nil {
		t.Fatalf("Close = %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
}

// TestLogsContainNoContent runs every path that logs (send, deliver,
// queue, poll, drop, reject, block, rate limit, trip) with a private log
// buffer and checks that no subject, body or session string appears.
// TestMain does the same check over all tests' logs.
func TestLogsContainNoContent(t *testing.T) {
	var logs syncBuffer
	w := newWorld(t)
	oa := w.options(w.a, "", w.b)
	ob := w.options(w.b, "", w.a)
	oa.Logger, ob.Logger = testLogger(&logs), testLogger(&logs)
	oa.Limits = Limits{SessionPerHour: 3, ThreadMax: 3}
	a, b := w.open(oa), w.open(ob)
	ctx := ctxT(t)
	subject, body := msg("log subject", "log body")

	r := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	pollAll(t, b)
	if _, err := b.Reply(ctx, sess2, r.Thread, plainMarker+" reply body"); err != nil {
		t.Fatal(err)
	}
	pollAll(t, a)
	_, _ = a.Send(ctx, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body, Thread: r.Thread})
	_, _ = a.Send(ctx, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body, Thread: r.Thread}) // trips
	_, _ = a.Send(ctx, sess1, SendRequest{To: "peer-b", Subject: subject, Body: secretMarker})           // blocked
	w.relay.setOffline(true)
	_, _ = a.Send(ctx, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body}) // queued
	_, _ = b.PollOnce(ctx)                                                             // poll fails
	w.relay.setOffline(false)
	_, _ = a.FlushOutbox(ctx)
	_, _ = a.Send(ctx, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body}) // rate limited
	w.relay.setPostCode(422)
	_, _ = a.Send(ctx, sess2, SendRequest{To: "peer-b", Subject: subject, Body: body}) // rejected
	w.relay.setPostCode(0)
	bad := sealFrom(t, w.a, "peer-b", w.b.pub, w.clock.Now(), nil)
	bad.Thread = envelope.NewThreadID()
	w.relay.inject("peer-b", bad) // dropped (mismatch)
	_, _ = b.PollOnce(ctx)

	out := logs.String()
	if out == "" {
		t.Fatal("no logs captured")
	}
	if bad := forbiddenInLogs(out); len(bad) > 0 {
		t.Fatalf("logs contain %q:\n%s", bad, out)
	}
	for _, want := range []string{"outbound delivered", "outbound deferred", "outbound rejected", "inbound stored",
		"inbound dropped", "thread breaker tripped", "outbound rate limited", "blocked by scanner", "poll failed"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected a %q log line", want)
		}
	}
}

// dbPathForTest returns the database file path the bridge opened.
func (b *Bridge) dbPathForTest(t *testing.T) string {
	t.Helper()
	var seq int
	var name, file string
	if err := b.db.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &file); err != nil {
		t.Fatal(err)
	}
	return file
}
