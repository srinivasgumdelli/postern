package bridge

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"postern/internal/envelope"
)

func TestInvalidEnvelopesDroppedAndAcked(t *testing.T) {
	w := newWorld(t)
	c := newIdentity(t, w.ca, "peer-c") // not configured on B
	_, b := w.pair()
	otherPub, _, err := envelope.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := w.clock.Now()

	cases := map[string]func() envelope.Envelope{
		"tampered box": func() envelope.Envelope {
			e := sealFrom(t, w.a, "peer-b", w.b.pub, now, nil)
			raw, _ := base64.StdEncoding.DecodeString(e.Box)
			raw[len(raw)/2] ^= 0x01
			e.Box = base64.StdEncoding.EncodeToString(raw)
			return e
		},
		"sealed to another key": func() envelope.Envelope {
			return sealFrom(t, w.a, "peer-b", otherPub, now, nil)
		},
		"unknown sender": func() envelope.Envelope {
			return sealFrom(t, c, "peer-b", w.b.pub, now, nil)
		},
		"outer thread changed": func() envelope.Envelope {
			e := sealFrom(t, w.a, "peer-b", w.b.pub, now, nil)
			e.Thread = envelope.NewThreadID()
			return e
		},
		"outer ts changed": func() envelope.Envelope {
			e := sealFrom(t, w.a, "peer-b", w.b.pub, now, nil)
			e.TS++
			return e
		},
		"relabelled sender": func() envelope.Envelope {
			// Sealed by an unpinned key but labelled as peer-a.
			e := sealFrom(t, c, "peer-b", w.b.pub, now, nil)
			e.From = "peer-a"
			return e
		},
		"addressed to someone else": func() envelope.Envelope {
			return sealFrom(t, w.a, "peer-c", w.b.pub, now, nil)
		},
		"stale": func() envelope.Envelope {
			return sealFrom(t, w.a, "peer-b", w.b.pub, now.Add(-envelope.Retention-time.Hour), nil)
		},
		"from the future": func() envelope.Envelope {
			return sealFrom(t, w.a, "peer-b", w.b.pub, now.Add(time.Hour), nil)
		},
		"bad outer version": func() envelope.Envelope {
			e := sealFrom(t, w.a, "peer-b", w.b.pub, now, nil)
			e.V = 2
			return e
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			e := mk()
			w.relay.inject("peer-b", e)
			n, err := b.PollOnce(ctxT(t))
			if err != nil {
				t.Fatalf("PollOnce: %v", err)
			}
			if n != 0 {
				t.Fatalf("stored %d; want 0", n)
			}
			if !w.relay.isAcked(e.ID) {
				t.Fatal("dropped envelope was not acked")
			}
			if got := countRows(t, b, ""); got != 0 {
				t.Fatalf("inbox has %d rows", got)
			}
		})
	}

	// Garbage that still carries an id is acked; garbage without one is
	// skipped without blocking the rest of the batch.
	id := newID()
	w.relay.injectRaw("peer-b", id, []byte(fmt.Sprintf(`{"id":%q,"v":"x"}`, id)))
	w.relay.injectRaw("peer-b", "", []byte(`{"nonsense":true}`))
	good := sealFrom(t, w.a, "peer-b", w.b.pub, now, nil)
	w.relay.inject("peer-b", good)
	if n := pollAll(t, b); n != 1 {
		t.Fatalf("stored %d; want 1 (the good one)", n)
	}
	if !w.relay.isAcked(id) || !w.relay.isAcked(good.ID) {
		t.Fatal("parseable ids not acked")
	}
}

func TestInboundCannotJoinAnotherPeersThread(t *testing.T) {
	w := newWorld(t)
	c := newIdentity(t, w.ca, "peer-c")
	w.relay.bind(c.cert.Fingerprint, c.name)
	b := w.open(w.options(w.b, "", w.a, c))
	a := w.open(w.options(w.a, "", w.b))
	subject, body := msg("t", "t")
	r := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})
	pollAll(t, b)

	hijack := sealFrom(t, c, "peer-b", w.b.pub, w.clock.Now(), func(m *envelope.Message) { m.Thread = r.Thread })
	w.relay.inject("peer-b", hijack)
	if n := pollAll(t, b); n != 0 {
		t.Fatalf("hijack stored %d", n)
	}
	if !w.relay.isAcked(hijack.ID) {
		t.Fatal("hijack not acked")
	}
	msgs, _ := b.CheckInbox(ctxT(t), InboxQuery{Thread: r.Thread, IncludeRead: true})
	if len(msgs) != 1 || msgs[0].FromPeer != "peer-a" {
		t.Fatalf("thread = %+v", msgs)
	}
}

func TestDuplicateDeliveryStoredOnce(t *testing.T) {
	w := newWorld(t)
	_, b := w.pair()
	e := sealFrom(t, w.a, "peer-b", w.b.pub, w.clock.Now(), nil)
	w.relay.inject("peer-b", e)
	w.relay.inject("peer-b", e) // same envelope twice in one batch
	if n := pollAll(t, b); n != 1 {
		t.Fatalf("first poll stored %d; want 1", n)
	}
	w.relay.inject("peer-b", e) // and again later
	if n := pollAll(t, b); n != 0 {
		t.Fatalf("redelivery stored %d; want 0", n)
	}
	if n := countRows(t, b, ""); n != 1 {
		t.Fatalf("inbox rows = %d; want 1", n)
	}
	if w.relay.pending("peer-b") != 0 {
		t.Fatal("duplicates left at the relay")
	}
}

func TestPollRetriesWhenAckFails(t *testing.T) {
	w := newWorld(t)
	a, b := w.pair()
	subject, body := msg("c", "c")
	r := mustSend(t, a, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body})

	w.relay.setAckCode(503)
	n, err := b.PollOnce(ctxT(t))
	if err == nil || n != 1 {
		t.Fatalf("PollOnce with failing ack = %d, %v; want 1 stored and an error", n, err)
	}
	if w.relay.isAcked(r.ID) {
		t.Fatal("acked despite failure")
	}
	// The cursor did not move, so the next poll sees it again, does not
	// store it twice, and acks it.
	w.relay.setAckCode(0)
	if n := pollAll(t, b); n != 0 {
		t.Fatalf("retry stored %d; want 0", n)
	}
	if !w.relay.isAcked(r.ID) || w.relay.pending("peer-b") != 0 {
		t.Fatal("not acked on retry")
	}
	if got := countRows(t, b, ""); got != 1 {
		t.Fatalf("rows = %d; want 1", got)
	}
}

func TestPollErrorsOnRelayFailure(t *testing.T) {
	w := newWorld(t)
	_, b := w.pair()
	w.relay.setOffline(true)
	if _, err := b.PollOnce(ctxT(t)); err == nil {
		t.Fatal("PollOnce succeeded against an offline relay")
	}
	w.relay.setOffline(false)
	if _, err := b.PollOnce(ctxT(t)); err != nil {
		t.Fatalf("PollOnce after recovery: %v", err)
	}
}

// TestTwoBridgesShareInboxNoDuplicates: two processes on one machine
// (same identity, same database file) poll the same mailbox at once
// while also sending and marking read. Every message is stored exactly
// once and no SQLITE_BUSY reaches a caller.
func TestTwoBridgesShareInboxNoDuplicates(t *testing.T) {
	const n = 40
	w := newWorld(t)
	oa := w.options(w.a, "", w.b)
	oa.Limits = Limits{SessionPerHour: 1000, GlobalPerHour: 1000}
	a := w.open(oa)
	shared := w.options(w.b, "", w.a).DBPath
	ob := w.options(w.b, shared, w.a)
	ob.Limits = Limits{SessionPerHour: 1000, GlobalPerHour: 1000}
	b1 := w.open(ob)
	b2 := w.open(ob)
	ctx := ctxT(t)
	subject, body := msg("shared", "shared")

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		errs     []error
		stored   int
		sendDone = make(chan struct{})
	)
	fail := func(err error) {
		mu.Lock()
		errs = append(errs, err)
		mu.Unlock()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(sendDone)
		for i := 0; i < n; i++ {
			if _, err := a.Send(ctx, sess1, SendRequest{To: "peer-b", Subject: subject, Body: body}); err != nil {
				fail(err)
				return
			}
		}
	}()
	for i, bb := range []*Bridge{b1, b2} {
		session := fmt.Sprintf("%s%d", sessionMarker, 10+i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			sends := 0
			for {
				k, err := bb.PollOnce(ctx)
				if err != nil {
					fail(err)
					return
				}
				mu.Lock()
				stored += k
				mu.Unlock()
				if sends < 5 {
					if _, err := bb.Send(ctx, session, SendRequest{To: "peer-a", Subject: subject, Body: body}); err != nil {
						fail(err)
						return
					}
					sends++
				}
				msgs, err := bb.CheckInbox(ctx, InboxQuery{Limit: 5})
				if err != nil {
					fail(err)
					return
				}
				var ids []string
				for _, m := range msgs {
					ids = append(ids, m.ID)
				}
				if _, err := bb.MarkRead(ctx, ids); err != nil {
					fail(err)
					return
				}
				select {
				case <-sendDone:
					if sends == 5 && w.relay.pending("peer-b") == 0 {
						return
					}
				default:
				}
			}
		}()
	}
	wg.Wait()
	for _, err := range errs {
		t.Errorf("concurrent error: %v", err)
	}
	if t.Failed() {
		return
	}
	if got := countRows(t, b1, `direction = 'in'`); got != n {
		t.Fatalf("inbox rows = %d; want %d", got, n)
	}
	var distinct int
	if err := b1.db.QueryRow(`SELECT COUNT(DISTINCT id) FROM messages WHERE direction = 'in'`).Scan(&distinct); err != nil || distinct != n {
		t.Fatalf("distinct = %d, %v", distinct, err)
	}
	if stored != n {
		t.Fatalf("PollOnce reported %d new rows in total; want %d", stored, n)
	}
	if got := countRows(t, b1, `direction = 'out'`); got != 10 {
		t.Fatalf("outbound rows = %d; want 10", got)
	}
}

func TestPollResponseShape(t *testing.T) {
	// The bridge tolerates extra fields in envelopes from the relay.
	w := newWorld(t)
	_, b := w.pair()
	e := sealFrom(t, w.a, "peer-b", w.b.pub, w.clock.Now(), nil)
	raw, _ := json.Marshal(e)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	m["received_at"] = 123
	raw, _ = json.Marshal(m)
	w.relay.injectRaw("peer-b", e.ID, raw)
	if n := pollAll(t, b); n != 1 {
		t.Fatalf("stored %d; want 1", n)
	}
}
