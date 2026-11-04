// Package bridge is the per-machine core of Postern: the local inbox and
// outbox (SQLite), the relay client, the poller, the outbox retry loop and
// the outbound limits.
//
// There is no daemon. Every agent session that uses Postern runs its own
// process, which calls Open and then Run. Several such processes on one
// machine share one SQLite file and poll the same relay mailbox, so every
// state change is safe across processes: WAL mode, a busy timeout, BEGIN
// IMMEDIATE for every check-then-insert, INSERT OR IGNORE for inbound
// dedup, leases on outbox rows and idempotent acks.
//
// Logging: the logger only ever sees ids, threads, peer names, status
// codes, counts and short reason codes. Subjects, bodies, session names,
// keys and certificates are never logged.
//
// Errors: errors returned by the public methods are safe to show to an
// agent. They never contain subject or body text, file paths or SQL.
// Internal failures are reported as "internal error" and logged without
// content.
package bridge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"postern/internal/envelope"
	"postern/internal/ulid"
)

// Status values reported in SendResult.Status.
const (
	StatusSent   = "sent"
	StatusQueued = "queued"
)

// Errors returned by the bridge. Callers match with errors.Is. The error
// text that wraps them is safe to show to an agent.
var (
	ErrInvalid       = errors.New("invalid request")
	ErrUnknownPeer   = errors.New("unknown peer")
	ErrUnknownThread = errors.New("unknown thread")
	ErrRateLimited   = errors.New("rate limit reached")
	ErrThreadTripped = errors.New("thread paused by its circuit breaker")
	ErrBlocked       = errors.New("message blocked by the secret scanner")
	ErrRejected      = errors.New("relay rejected the message")

	errInternal = errors.New("internal error")
)

const (
	defaultPollTimeout = 25 * time.Second
	maxPollTimeout     = 25 * time.Second

	// sendAttemptTimeout bounds one delivery attempt (seal + POST).
	sendAttemptTimeout = 10 * time.Second
	// ackTimeout bounds one ack request.
	ackTimeout = 10 * time.Second
	// leaseDuration is how long a process owns an outbox row while it
	// attempts delivery. It is longer than sendAttemptTimeout so two
	// processes do not post the same row at once; if a process dies
	// mid-attempt another one takes over once the lease expires.
	leaseDuration = time.Minute
	// recordTimeout bounds the store update after an attempt. The update
	// runs even if the caller's context was cancelled.
	recordTimeout = 15 * time.Second
)

// Options configure a Bridge.
type Options struct {
	// Scanner checks every outgoing subject and body before anything is
	// stored or sent. A non-nil error blocks the message; its text (which
	// names a rule and a line, never the match) is returned to the agent
	// wrapped in ErrBlocked. Required: Open fails if nil.
	Scanner func(subject, body string) error
	// Self is this machine's peer name.
	Self string
	// BoxPrivate is this machine's X25519 private key.
	BoxPrivate *[32]byte
	// Peers are the pinned remote peers.
	Peers []Peer
	// InboxKey encrypts subjects, bodies and session names in the local
	// database (NaCl secretbox, keys derived from it). Required: Open
	// fails if nil. It must come from the OS keychain, never a file.
	InboxKey *[32]byte
	// RelayURL is the relay base URL. It must be https.
	RelayURL string
	// ClientCert is the mTLS client certificate presented to the edge.
	ClientCert tls.Certificate
	// ReloadClientCert is optional. After a 401/403 from the relay (for
	// example after the edge revoked or rotated the certificate) it is
	// called at most once a minute; if it returns a different certificate
	// the bridge switches to it for new connections.
	ReloadClientCert func() (tls.Certificate, error)
	// RootCAs verifies the relay's server certificate. nil = system roots.
	RootCAs *x509.CertPool
	// DBPath is the shared SQLite inbox/outbox file.
	DBPath string
	// Limits are the outbound limits; zero fields take defaults.
	Limits Limits
	// Logger receives metadata-only logs. nil discards.
	Logger *slog.Logger
	// Now is the clock. nil = time.Now.
	Now func() time.Time
	// PollTimeout is the long-poll timeout sent to the relay. Zero means
	// 25s; values above 25s are capped (the relay maximum).
	PollTimeout time.Duration
}

// Peer is a pinned remote peer.
type Peer struct {
	Name      string
	PublicKey *[32]byte
}

// SendRequest is an outgoing message from a session.
type SendRequest struct {
	To      string
	Subject string
	Body    string
	Thread  string // empty starts a new thread
}

// SendResult reports what happened to an outgoing message. Status is
// StatusSent when the relay accepted it, StatusQueued when it is stored in
// the outbox and will be retried.
type SendResult struct {
	ID     string
	Thread string
	Status string
}

// InboxQuery selects inbound messages.
type InboxQuery struct {
	SinceID     string // only messages that arrived after this one
	Limit       int    // default 20, max 100
	Thread      string // only this thread
	IncludeRead bool   // false = unread only
}

// InboxMessage is an inbound message as stored locally. Its content came
// from another machine and is untrusted.
type InboxMessage struct {
	ID          string
	Thread      string
	FromPeer    string
	FromSession string
	Subject     string
	Body        string
	ReceivedAt  time.Time
	Read        bool
}

// Bridge is one process's handle on the shared inbox/outbox and the relay.
type Bridge struct {
	self      string
	priv      *[32]byte
	peers     map[string]*[32]byte
	peerNames []string
	scanner   func(subject, body string) error
	limits    Limits
	log       *slog.Logger
	nowFn     func() time.Time
	db        *sql.DB
	client    *relayClient
	crypt     *inboxCrypto
	reload    func() (tls.Certificate, error)

	onceMu     sync.Mutex
	onceLogged map[string]struct{}

	statusMu      sync.Mutex
	authFailed    bool
	pollFailSince time.Time
	lastReload    time.Time

	mu       sync.Mutex
	cursor   int64
	cursorAt time.Time

	kick chan struct{}

	// runMu orders Run's closed check and runWG.Add against Close, so a
	// Run that starts while Close is in progress either sees the bridge
	// closed or is waited for.
	runMu     sync.Mutex
	isClosed  bool
	runWG     sync.WaitGroup
	closeOnce sync.Once
	closed    chan struct{}
}

// Open validates opts, opens (creating if needed) the shared database and
// prepares the relay client. It does not contact the relay.
func Open(opts Options) (*Bridge, error) {
	if opts.Scanner == nil {
		return nil, errors.New("bridge: a secret scanner is required")
	}
	if !envelope.ValidPeerName(opts.Self) {
		return nil, errors.New("bridge: self peer name is not valid")
	}
	if opts.BoxPrivate == nil {
		return nil, errors.New("bridge: box private key is required")
	}
	if opts.InboxKey == nil {
		return nil, errors.New("bridge: inbox key is required")
	}
	if len(opts.Peers) == 0 {
		return nil, errors.New("bridge: at least one peer is required")
	}
	peers := make(map[string]*[32]byte, len(opts.Peers))
	names := make([]string, 0, len(opts.Peers))
	for _, p := range opts.Peers {
		if !envelope.ValidPeerName(p.Name) {
			return nil, errors.New("bridge: peer name is not valid")
		}
		if p.Name == opts.Self {
			return nil, errors.New("bridge: a peer cannot have this machine's own name")
		}
		if p.PublicKey == nil {
			return nil, fmt.Errorf("bridge: peer %s has no public key", p.Name)
		}
		if _, dup := peers[p.Name]; dup {
			return nil, fmt.Errorf("bridge: peer %s is listed twice", p.Name)
		}
		peers[p.Name] = p.PublicKey
		names = append(names, p.Name)
	}
	sort.Strings(names)
	base, err := parseRelayURL(opts.RelayURL)
	if err != nil {
		return nil, err
	}
	if len(opts.ClientCert.Certificate) == 0 || opts.ClientCert.PrivateKey == nil {
		return nil, errors.New("bridge: client certificate is required")
	}
	if opts.DBPath == "" {
		return nil, errors.New("bridge: database path is required")
	}
	lim, err := opts.Limits.withDefaults()
	if err != nil {
		return nil, err
	}
	pt := opts.PollTimeout
	switch {
	case pt < 0:
		return nil, errors.New("bridge: poll timeout must not be negative")
	case pt == 0:
		pt = defaultPollTimeout
	case pt > maxPollTimeout:
		pt = maxPollTimeout
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	db, err := openDB(opts.DBPath, true)
	if err != nil {
		log.Error("open database failed", "err", safeFSError(err))
		return nil, fmt.Errorf("bridge: cannot open database: %s", safeFSError(err))
	}
	crypt := newInboxCrypto(opts.InboxKey)
	kctx, kcancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = checkInboxKey(kctx, db, crypt)
	kcancel()
	if err != nil {
		db.Close()
		crypt.wipe()
		if errors.Is(err, errWrongKey) {
			log.Error("open database failed", "err", err.Error())
			return nil, fmt.Errorf("bridge: %w", err)
		}
		log.Error("open database failed", "err", "key check")
		return nil, errors.New("bridge: cannot open database: database error")
	}
	b := &Bridge{
		self:      opts.Self,
		priv:      opts.BoxPrivate,
		peers:     peers,
		peerNames: names,
		scanner:   opts.Scanner,
		limits:    lim,
		log:       log,
		nowFn:     now,
		db:        db,
		client:    newRelayClient(base, opts.ClientCert, opts.RootCAs, pt),
		crypt:     crypt,
		reload:    opts.ReloadClientCert,
		kick:      make(chan struct{}, 1),

		onceLogged: map[string]struct{}{},
		closed:     make(chan struct{}),
	}
	b.log.Info("bridge opened", "peer", b.self, "peers", len(peers))
	return b, nil
}

// Close stops Run (if running), waits for it and closes the database.
// It is safe to call more than once.
func (b *Bridge) Close() error {
	var err error
	b.closeOnce.Do(func() {
		b.runMu.Lock()
		b.isClosed = true
		close(b.closed)
		b.runMu.Unlock()
		b.runWG.Wait()
		b.client.closeIdle()
		err = b.db.Close()
		b.crypt.wipe()
		b.log.Info("bridge closed")
	})
	return err
}

// Run polls the relay and retries the outbox until ctx is done or the
// bridge is closed. It returns nil on a clean stop.
func (b *Bridge) Run(ctx context.Context) error {
	b.runMu.Lock()
	if b.isClosed {
		b.runMu.Unlock()
		return errors.New("bridge: closed")
	}
	b.runWG.Add(1)
	b.runMu.Unlock()
	defer b.runWG.Done()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-b.closed:
			cancel()
		case <-ctx.Done():
		}
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); b.pollLoop(ctx) }()
	go func() { defer wg.Done(); b.outboxLoop(ctx) }()
	b.log.Info("bridge running")
	wg.Wait()
	b.log.Info("bridge stopped")
	return nil
}

func (b *Bridge) now() time.Time { return b.nowFn() }

// logOnce reports whether key has not been logged before in this process
// (bounded: the set is cleared when it gets large).
func (b *Bridge) logOnce(key string) bool {
	b.onceMu.Lock()
	defer b.onceMu.Unlock()
	if _, ok := b.onceLogged[key]; ok {
		return false
	}
	if len(b.onceLogged) >= 4096 {
		clear(b.onceLogged)
	}
	b.onceLogged[key] = struct{}{}
	return true
}

// logUnreadable logs (once per id) a stored row that does not decrypt.
func (b *Bridge) logUnreadable(id string) {
	if b.logOnce("unreadable:" + id) {
		b.log.Error("stored row cannot be decrypted; skipped", "id", id)
	}
}

// Send scans, validates, limits and stores an outgoing message, then
// tries to deliver it once. Transient delivery failures leave it queued.
func (b *Bridge) Send(ctx context.Context, session string, req SendRequest) (SendResult, error) {
	if !envelope.ValidSessionName(session) {
		return SendResult{}, errInvalidSession
	}
	if _, ok := b.peers[req.To]; !ok {
		return SendResult{}, b.unknownPeerErr()
	}
	if err := b.scan(req.Subject, req.Body); err != nil {
		return SendResult{}, err
	}
	thread := req.Thread
	if thread == "" {
		thread = envelope.NewThreadID()
	} else if !envelope.ValidThreadID(thread) {
		return SendResult{}, fmt.Errorf("%w: thread is not a valid thread id (omit it to start a new thread)", ErrInvalid)
	}
	if err := validateContent(req.Subject, req.Body); err != nil {
		return SendResult{}, err
	}
	return b.submit(ctx, outgoing{
		session: session, peer: req.To, thread: thread,
		subject: req.Subject, body: req.Body,
	})
}

// Reply sends body on an existing thread to that thread's peer. The
// subject is "Re: " plus the thread's first subject, and reply_to is the
// latest inbound message in the thread.
func (b *Bridge) Reply(ctx context.Context, session, thread, body string) (SendResult, error) {
	if !envelope.ValidSessionName(session) {
		return SendResult{}, errInvalidSession
	}
	if !envelope.ValidThreadID(thread) {
		return SendResult{}, fmt.Errorf("%w: thread is not a valid thread id", ErrInvalid)
	}
	ti, found, err := b.threadInfo(ctx, thread)
	if err != nil {
		return SendResult{}, err
	}
	if !found {
		return SendResult{}, fmt.Errorf("%w: no local thread with that id", ErrUnknownThread)
	}
	if _, ok := b.peers[ti.peer]; !ok {
		return SendResult{}, b.unknownPeerErr()
	}
	subject := replySubject(ti.firstSubject)
	if err := b.scan(subject, body); err != nil {
		return SendResult{}, err
	}
	if err := validateContent(subject, body); err != nil {
		return SendResult{}, err
	}
	return b.submit(ctx, outgoing{
		session: session, peer: ti.peer, thread: thread,
		subject: subject, body: body, replyTo: ti.lastInbound,
	})
}

var errInvalidSession = fmt.Errorf("%w: session name is not valid", ErrInvalid)

func (b *Bridge) unknownPeerErr() error {
	return fmt.Errorf("%w: configured peers: %s", ErrUnknownPeer, strings.Join(b.peerNames, ", "))
}

// scan runs the secret scanner. The scanner's error text names a rule and
// a line, never the match, so it is passed to the agent; it is not logged.
func (b *Bridge) scan(subject, body string) error {
	if err := b.scanner(subject, body); err != nil {
		b.log.Warn("outgoing message blocked by scanner")
		return fmt.Errorf("%w: %w", ErrBlocked, err)
	}
	return nil
}

type outgoing struct {
	session, peer, thread, subject, body, replyTo string
}

// submit stores an outgoing message (after the limit checks) and makes
// one bounded delivery attempt.
func (b *Bridge) submit(ctx context.Context, o outgoing) (SendResult, error) {
	now := b.now()
	m := envelope.Message{
		ID: ulid.New(), From: b.self, To: o.peer, Thread: o.thread, TS: now.Unix(),
		Session: o.session, Subject: o.subject, Body: o.body, ReplyTo: o.replyTo,
	}
	// A trial seal proves the message is valid and fits the envelope cap
	// before anything is stored.
	if _, err := envelope.Seal(m, b.peers[o.peer], b.priv); err != nil {
		if errors.Is(err, envelope.ErrTooLarge) {
			return SendResult{}, fmt.Errorf("%w: message too large for one envelope", ErrInvalid)
		}
		return SendResult{}, fmt.Errorf("%w: message is not valid", ErrInvalid)
	}
	if err := b.insertOutbound(ctx, o, m, now); err != nil {
		return SendResult{}, err
	}
	b.log.Info("outbound stored", "id", m.ID, "thread", m.Thread, "peer", m.To)

	r := outRow{
		id: m.ID, peer: o.peer, thread: o.thread, session: o.session,
		subject: o.subject, body: o.body, replyTo: o.replyTo, createdAt: now,
	}
	actx, cancel := context.WithTimeout(ctx, sendAttemptTimeout)
	res := b.attempt(actx, r)
	cancel()
	b.record(ctx, r, res)
	switch res.outcome {
	case outDelivered:
		b.kickOutbox()
		return SendResult{ID: m.ID, Thread: m.Thread, Status: StatusSent}, nil
	case outPermanent:
		if res.status != 0 {
			return SendResult{}, fmt.Errorf("%w: message %s (relay status %d)", ErrRejected, m.ID, res.status)
		}
		return SendResult{}, fmt.Errorf("%w: message %s", ErrRejected, m.ID)
	default:
		return SendResult{ID: m.ID, Thread: m.Thread, Status: StatusQueued}, nil
	}
}

// insertOutbound runs the breaker, thread cap, burst and rate checks and
// inserts the pending row, all in one immediate transaction so that
// concurrent processes cannot both pass a check that only one should.
func (b *Bridge) insertOutbound(ctx context.Context, o outgoing, m envelope.Message, now time.Time) error {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return b.internal(ctx, "begin outbound", err)
	}
	defer tx.Rollback()

	th, found, err := getThread(ctx, tx, o.thread)
	if err != nil {
		return b.internal(ctx, "load thread", err)
	}
	if found {
		if th.peer != o.peer {
			return fmt.Errorf("%w: that thread belongs to another peer", ErrInvalid)
		}
		if th.tripped {
			return trippedErr(o.thread, th.tripReason)
		}
		reason, err := threadLimitReason(ctx, tx, b.limits, o.thread, th.resetSeq, now)
		if err != nil {
			return b.internal(ctx, "thread limits", err)
		}
		if reason != "" {
			if err := tripThread(ctx, tx, o.thread, reason, now); err != nil {
				return b.internal(ctx, "trip thread", err)
			}
			if err := tx.Commit(); err != nil {
				return b.internal(ctx, "commit trip", err)
			}
			b.log.Warn("thread breaker tripped", "thread", o.thread, "peer", o.peer, "reason", reason)
			return trippedErr(o.thread, reason)
		}
	}
	tag := b.crypt.sessionTag(o.session)
	scope, err := rateLimitScope(ctx, tx, b.limits, tag, now)
	if err != nil {
		return b.internal(ctx, "rate limits", err)
	}
	switch scope {
	case "session":
		b.log.Warn("outbound rate limited", "scope", scope)
		return fmt.Errorf("%w: this session may send %d messages per hour; try again later", ErrRateLimited, b.limits.SessionPerHour)
	case "global":
		b.log.Warn("outbound rate limited", "scope", scope)
		return fmt.Errorf("%w: this machine may send %d messages per hour; try again later", ErrRateLimited, b.limits.GlobalPerHour)
	}
	if !found {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO threads (thread, peer, created_at) VALUES (?, ?, ?)`,
			o.thread, o.peer, now.UnixMilli()); err != nil {
			return b.internal(ctx, "insert thread", err)
		}
	}
	sealed, err := b.crypt.seal(m.ID, o.session, o.subject, o.body)
	if err != nil {
		return b.internal(ctx, "seal outbound", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO messages (id, direction, peer, session_tag, thread, sealed, reply_to,
			created_at, ts, state, attempts, next_attempt_at, lease_until)
		VALUES (?, 'out', ?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?)`,
		m.ID, o.peer, tag, o.thread, sealed, nullable(o.replyTo),
		now.UnixMilli(), m.TS, now.UnixMilli(), now.Add(leaseDuration).UnixMilli()); err != nil {
		return b.internal(ctx, "insert outbound", err)
	}
	if err := tx.Commit(); err != nil {
		return b.internal(ctx, "commit outbound", err)
	}
	return nil
}

func trippedErr(thread, reason string) error {
	switch reason {
	case "cap", "burst":
	default:
		reason = "limit"
	}
	return fmt.Errorf("%w (%s): thread %s is paused; a human must run `postern thread reset %s` to resume it",
		ErrThreadTripped, reason, thread, thread)
}

// internal logs a store failure (no content) and returns a generic error.
// Context cancellation is passed through as is.
func (b *Bridge) internal(ctx context.Context, op string, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	b.log.Error("store error", "op", op, "err", err.Error())
	return errInternal
}

// validateContent checks subject and body against the protocol limits and
// returns an error that is safe to show (it never echoes the content).
func validateContent(subject, body string) error {
	switch {
	case strings.TrimSpace(subject) == "":
		return fmt.Errorf("%w: subject is required", ErrInvalid)
	case len(subject) > envelope.MaxSubjectBytes:
		return fmt.Errorf("%w: subject over %d bytes", ErrInvalid, envelope.MaxSubjectBytes)
	case !utf8.ValidString(subject):
		return fmt.Errorf("%w: subject is not valid UTF-8", ErrInvalid)
	case strings.IndexFunc(subject, unicode.IsControl) >= 0:
		return fmt.Errorf("%w: subject contains control characters", ErrInvalid)
	case body == "":
		return fmt.Errorf("%w: body is required", ErrInvalid)
	case len(body) > envelope.MaxBodyBytes:
		return fmt.Errorf("%w: body over %d bytes", ErrInvalid, envelope.MaxBodyBytes)
	case !utf8.ValidString(body):
		return fmt.Errorf("%w: body is not valid UTF-8", ErrInvalid)
	}
	return nil
}

// replySubject derives a reply subject from a thread's first subject.
func replySubject(first string) string {
	s := first
	if !strings.HasPrefix(s, "Re: ") {
		s = "Re: " + s
	}
	return truncateUTF8(s, envelope.MaxSubjectBytes)
}

// truncateUTF8 cuts s to at most n bytes on a rune boundary.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// safeFSError describes a filesystem or database error without a path.
func safeFSError(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Op + ": " + pe.Err.Error()
	}
	if errors.Is(err, errNotRegular) || errors.Is(err, errSchemaTooNew) || errors.Is(err, errSchemaV1) {
		return err.Error()
	}
	return "database error"
}
