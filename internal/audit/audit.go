// Package audit is the bridge's local audit log: an append-only JSONL
// file per machine that records what happened (a message sent, queued,
// received or dropped; a trust change made with the CLI), never what was
// said.
//
// Metadata only. An Event has no field that could carry a subject, body,
// key, certificate, query string or file path, and Record checks every
// field it does have against a strict pattern (peer and session names,
// thread ids, message ids, short reason codes). A value that does not
// match is written as "!invalid", so a caller bug cannot smuggle content
// into the file.
//
// Several processes share one log (every `postern mcp` session process
// and the CLI), so Record holds an exclusive lock on a lock file next to
// the log while it reads the last line, appends one line with a single
// write to an O_APPEND file, and rotates.
//
// Tamper evidence, not prevention. Every line carries seq (one more than
// the line before) and prev (the hex SHA-256 of the previous line's
// bytes, without its newline). Editing, removing or reordering a line
// breaks the chain at the line after it, which Verify reports. Anything
// running as the same OS user can still rewrite the whole file and
// recompute the chain, and cutting lines off the end (or editing only
// the last line) leaves a valid chain; compare the last hash Verify
// prints with a copy kept elsewhere to catch that.
//
// Rotation: when the active file reaches MaxBytes (10 MiB), it is renamed
// to audit-YYYYMMDD-HHMMSS.jsonl (UTC) and a new file starts whose first
// line links to the old file's last line. At most Keep (10) rotated files
// are kept; the oldest kept file's first line is then the start of the
// chain that can be checked.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"postern/internal/envelope"
	"postern/internal/ulid"
)

// Actors.
const (
	ActorBridge = "bridge"
	ActorCLI    = "cli"
)

// Bridge events.
const (
	EventSent             = "sent"               // accepted by the relay on the first attempt
	EventQueued           = "queued"             // stored; the first attempt did not reach the relay
	EventDelivered        = "delivered"          // a queued message accepted by the relay on a retry
	EventRejected         = "rejected"           // the relay refused it, or the bridge gave up (reason)
	EventBlockedByScanner = "blocked_by_scanner" // reason: rule=NAME,line=N
	EventRateLimited      = "rate_limited"       // reason: session or global
	EventThreadTripped    = "thread_tripped"     // reason: cap or burst
	EventReceived         = "received"           // an inbound message stored
	EventDropped          = "dropped"            // an inbound envelope dropped (reason code)
	EventRelayAuthFailed  = "relay_auth_failed"  // the edge or relay answered 401/403
	EventRelayUnreachable = "relay_unreachable"  // polls failing for over 2 minutes
	EventRelayRecovered   = "relay_recovered"    // the relay answered normally again
)

// CLI trust-change events, recorded after the change succeeded.
const (
	EventInit          = "init"
	EventPeerAdd       = "peer_add"
	EventPeerRemove    = "peer_remove"
	EventSessionAdd    = "session_add"
	EventSessionRemove = "session_remove"
	EventConfigPin     = "config_pin"
	EventCertImport    = "cert_import"
	EventCertRotate    = "cert_rotate"
	EventThreadReset   = "thread_reset"
	EventGuardInstall  = "guard_install"
)

// eventActor maps every allowed event to the actor that may record it.
var eventActor = map[string]string{
	EventSent: ActorBridge, EventQueued: ActorBridge, EventDelivered: ActorBridge,
	EventRejected: ActorBridge, EventBlockedByScanner: ActorBridge, EventRateLimited: ActorBridge,
	EventThreadTripped: ActorBridge, EventReceived: ActorBridge, EventDropped: ActorBridge,
	EventRelayAuthFailed: ActorBridge, EventRelayUnreachable: ActorBridge, EventRelayRecovered: ActorBridge,

	EventInit: ActorCLI, EventPeerAdd: ActorCLI, EventPeerRemove: ActorCLI,
	EventSessionAdd: ActorCLI, EventSessionRemove: ActorCLI, EventConfigPin: ActorCLI,
	EventCertImport: ActorCLI, EventCertRotate: ActorCLI, EventThreadReset: ActorCLI,
	EventGuardInstall: ActorCLI,
}

// Events returns every allowed event name.
func Events() []string {
	out := make([]string, 0, len(eventActor))
	for e := range eventActor {
		out = append(out, e)
	}
	return out
}

// ActorOf returns the actor that records event, or "" if it is unknown.
func ActorOf(event string) string { return eventActor[event] }

// Invalid replaces a field value that does not match its pattern. It is
// not a valid peer, session, thread, id or reason, so it cannot be
// mistaken for one.
const Invalid = "!invalid"

// GenesisPrev is the prev of the first line ever written.
var GenesisPrev = strings.Repeat("0", 64)

// Event is what a caller records. Record adds ts, seq and prev.
//
// Session is a local session name (from this machine's config), never the
// sending session of an inbound message: that name is chosen by the other
// machine and travels sealed, so it is content.
type Event struct {
	Event     string // one of the Event* constants
	Actor     string // ActorBridge or ActorCLI
	Peer      string // peer name
	Session   string // local session name
	Thread    string // thread id (t-ULID)
	ID        string // message id (ULID)
	SizeBytes int64  // body size in bytes
	Status    int    // HTTP status from the relay, if any
	Reason    string // short code, [a-z0-9_.:=,-], at most 64 bytes
}

// Entry is one line of the log.
type Entry struct {
	TS        string `json:"ts"`
	Seq       uint64 `json:"seq"`
	Event     string `json:"event"`
	Actor     string `json:"actor"`
	Peer      string `json:"peer,omitempty"`
	Session   string `json:"session,omitempty"`
	Thread    string `json:"thread,omitempty"`
	ID        string `json:"id,omitempty"`
	SizeBytes int64  `json:"size_bytes,omitempty"`
	Status    int    `json:"status,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Prev      string `json:"prev"`
}

var (
	reasonRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:=,-]{0,63}$`)
	hashRe   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// sanitize returns e with every field that does not match its pattern
// replaced by Invalid (or zero for numbers). Unknown events and actors
// are errors: they are programming mistakes, not data.
func sanitize(e Event) (Event, error) {
	want, ok := eventActor[e.Event]
	if !ok {
		return Event{}, errors.New("audit: unknown event")
	}
	if e.Actor != want {
		return Event{}, errors.New("audit: event recorded by the wrong actor")
	}
	check := func(v *string, valid func(string) bool) {
		if *v != "" && !valid(*v) {
			*v = Invalid
		}
	}
	check(&e.Peer, envelope.ValidPeerName)
	check(&e.Session, envelope.ValidSessionName)
	check(&e.Thread, envelope.ValidThreadID)
	check(&e.ID, ulid.Valid)
	check(&e.Reason, reasonRe.MatchString)
	if e.SizeBytes < 0 || e.SizeBytes > 1<<30 {
		e.SizeBytes = 0
	}
	if e.Status < 0 || e.Status > 999 {
		e.Status = 0
	}
	return e, nil
}

// sanitizeEntry applies the same patterns to an entry read back from the
// file, so Tail never prints text that Record would not have written.
func sanitizeEntry(en Entry) Entry {
	e, err := sanitize(Event{
		Event: en.Event, Actor: en.Actor, Peer: en.Peer, Session: en.Session, Thread: en.Thread,
		ID: en.ID, SizeBytes: en.SizeBytes, Status: en.Status, Reason: en.Reason,
	})
	if err != nil {
		e = Event{Event: Invalid, Actor: Invalid}
	}
	out := Entry{
		TS: en.TS, Seq: en.Seq, Event: e.Event, Actor: e.Actor, Peer: e.Peer, Session: e.Session,
		Thread: e.Thread, ID: e.ID, SizeBytes: e.SizeBytes, Status: e.Status, Reason: e.Reason, Prev: en.Prev,
	}
	if _, err := time.Parse(time.RFC3339, out.TS); err != nil {
		out.TS = Invalid
	}
	if !hashRe.MatchString(out.Prev) {
		out.Prev = Invalid
	}
	return out
}

// hashLine is the prev value for the line after line (no newline).
func hashLine(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}

// Defaults for Options.
const (
	DefaultMaxBytes = 10 << 20
	DefaultKeep     = 10

	// lockTimeout bounds how long Record waits for another process's
	// append when the caller's context has no deadline.
	lockTimeout = 10 * time.Second
	// tailChunk is how much of the end of the file Record reads to find
	// the last line; it doubles up to maxLine.
	tailChunk = 4 << 10
	maxLine   = 1 << 20
)

// Options tune a Log. Zero fields take defaults.
type Options struct {
	MaxBytes int64            // rotate when the active file reaches this size
	Keep     int              // rotated files to keep
	Now      func() time.Time // clock; nil = time.Now
}

// Log appends events to one audit file. It is safe for concurrent use,
// and several Logs (in one process or many) may share a file.
type Log struct {
	path     string
	dir      string
	maxBytes int64
	keep     int
	now      func() time.Time

	mu     sync.Mutex
	lock   *os.File
	closed bool
}

// Open opens (creating if needed) the audit log at path with default
// options. The directory is created with mode 0700 and the file with
// 0600; an existing directory or file that group or others can access
// is refused.
func Open(path string) (*Log, error) { return OpenWith(path, Options{}) }

// OpenWith is Open with options.
func OpenWith(path string, opts Options) (*Log, error) {
	if path == "" {
		return nil, errors.New("audit: path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, errors.New("audit: cannot resolve the log path")
	}
	l := &Log{
		path: abs, dir: filepath.Dir(abs),
		maxBytes: opts.MaxBytes, keep: opts.Keep, now: opts.Now,
	}
	if l.maxBytes <= 0 {
		l.maxBytes = DefaultMaxBytes
	}
	if l.keep <= 0 {
		l.keep = DefaultKeep
	}
	if l.now == nil {
		l.now = time.Now
	}
	if err := os.MkdirAll(l.dir, 0o700); err != nil {
		return nil, fsErr("create directory", err)
	}
	if err := checkDir(l.dir); err != nil {
		return nil, err
	}
	lock, err := openPrivate(filepath.Join(l.dir, lockName), os.O_RDWR|os.O_CREATE)
	if err != nil {
		return nil, err
	}
	l.lock = lock
	// Refuse a log file that already has loose permissions or is not a
	// regular file now, rather than at the first event.
	if f, err := openPrivate(l.path, os.O_RDONLY); err == nil {
		f.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		lock.Close()
		return nil, err
	}
	return l, nil
}

// Path returns the active log file path.
func (l *Log) Path() string { return l.path }

// Close releases the lock file. Record fails after Close.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return l.lock.Close()
}

// Record appends one event. ctx bounds the wait for the lock (10s when
// it has no deadline). Errors never contain paths or field values.
func (l *Log) Record(ctx context.Context, e Event) error {
	e, err := sanitize(e)
	if err != nil {
		return err
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, lockTimeout)
		defer cancel()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("audit: log is closed")
	}
	if err := lockFile(ctx, l.lock); err != nil {
		return err
	}
	defer unlockFile(l.lock)
	return l.appendLocked(e)
}

// appendLocked runs with the cross-process lock held.
func (l *Log) appendLocked(e Event) error {
	tail, err := l.lastLine()
	if err != nil {
		return err
	}
	if tail.size >= l.maxBytes {
		if err := l.rotate(); err != nil {
			return err
		}
		tail.size, tail.torn = 0, false
	}
	en := Entry{
		TS: l.now().UTC().Format(time.RFC3339), Seq: tail.nextSeq,
		Event: e.Event, Actor: e.Actor, Peer: e.Peer, Session: e.Session, Thread: e.Thread,
		ID: e.ID, SizeBytes: e.SizeBytes, Status: e.Status, Reason: e.Reason,
		Prev: tail.hash,
	}
	line, err := json.Marshal(en)
	if err != nil {
		return errors.New("audit: encode event")
	}
	buf := make([]byte, 0, len(line)+2)
	if tail.torn {
		// The last write was cut short (crash or full disk). End that
		// fragment so this line stands alone; Verify reports the fragment.
		buf = append(buf, '\n')
	}
	buf = append(buf, line...)
	buf = append(buf, '\n')

	f, err := openPrivate(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(buf); err != nil {
		return fsErr("append", err)
	}
	if err := f.Sync(); err != nil {
		return fsErr("sync", err)
	}
	return nil
}

type tailInfo struct {
	size    int64  // size of the active file (0 if missing)
	torn    bool   // the active file does not end with a newline
	hash    string // prev for the next line
	nextSeq uint64 // seq for the next line
}

// lastLine finds the line the next one chains to: the last line of the
// active file, or of the newest rotated file when the active one is
// empty or missing (just after a rotation).
func (l *Log) lastLine() (tailInfo, error) {
	ti := tailInfo{hash: GenesisPrev, nextSeq: 1}
	size, last, torn, before, err := readLast(l.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return ti, err
	}
	ti.size, ti.torn = size, torn
	if last == nil {
		files, err := rotatedFiles(l.dir)
		if err != nil {
			return ti, err
		}
		if len(files) == 0 {
			return ti, nil
		}
		_, last, _, before, err = readLast(files[len(files)-1].path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return ti, err
		}
		if last == nil {
			return ti, nil
		}
	}
	ti.hash = hashLine(last)
	ti.nextSeq = nextSeq(last, before)
	return ti, nil
}

// nextSeq is one more than last's seq. If last does not parse (a torn or
// edited line), it counts on from the nearest earlier line that does, as
// if every unparseable line had taken a seq.
func nextSeq(last []byte, before [][]byte) uint64 {
	if s, ok := lineSeq(last); ok {
		return s + 1
	}
	skipped := uint64(1)
	for i := len(before) - 1; i >= 0; i-- {
		if s, ok := lineSeq(before[i]); ok {
			return s + skipped + 1
		}
		skipped++
	}
	return skipped + 1
}

func lineSeq(line []byte) (uint64, bool) {
	var probe struct {
		Seq *uint64 `json:"seq"`
	}
	if json.Unmarshal(line, &probe) != nil || probe.Seq == nil || *probe.Seq == 0 {
		return 0, false
	}
	return *probe.Seq, true
}

// readLast returns the file size, its last line (without newline; nil if
// the file is empty), whether the file lacks a final newline, and the
// lines before the last one within the chunk read.
func readLast(path string) (size int64, last []byte, torn bool, before [][]byte, err error) {
	f, err := openPrivate(path, os.O_RDONLY)
	if err != nil {
		return 0, nil, false, nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, nil, false, nil, fsErr("stat", err)
	}
	size = fi.Size()
	if size == 0 {
		return 0, nil, false, nil, nil
	}
	for chunk := int64(tailChunk); ; chunk *= 2 {
		start := max(size-chunk, 0)
		buf := make([]byte, size-start)
		if _, err := f.ReadAt(buf, start); err != nil {
			return 0, nil, false, nil, fsErr("read", err)
		}
		torn = buf[len(buf)-1] != '\n'
		body := buf
		if !torn {
			body = buf[:len(buf)-1]
		}
		i := lastIndexByte(body, '\n')
		if i < 0 && start > 0 {
			if chunk >= maxLine {
				return 0, nil, false, nil, errors.New("audit: last line is too long")
			}
			continue
		}
		last = body[i+1:]
		if i > 0 {
			lines := splitLines(body[:i])
			if start > 0 && len(lines) > 0 {
				lines = lines[1:] // the first one may be cut
			}
			before = lines
		}
		return size, last, torn, before, nil
	}
}

func lastIndexByte(b []byte, c byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		i := 0
		for i < len(b) && b[i] != '\n' {
			i++
		}
		out = append(out, b[:i])
		if i == len(b) {
			break
		}
		b = b[i+1:]
	}
	return out
}

// rotate renames the active file to a timestamped name and removes the
// oldest rotated files beyond Keep.
func (l *Log) rotate() error {
	stamp := l.now().UTC().Format("20060102-150405")
	name := filepath.Join(l.dir, rotatedPrefix+stamp+".jsonl")
	for n := 2; ; n++ {
		if _, err := os.Lstat(name); errors.Is(err, os.ErrNotExist) {
			break
		}
		name = filepath.Join(l.dir, rotatedPrefix+stamp+"-"+strconv.Itoa(n)+".jsonl")
	}
	if err := os.Rename(l.path, name); err != nil {
		return fsErr("rotate", err)
	}
	files, err := rotatedFiles(l.dir)
	if err != nil {
		return err
	}
	for len(files) > l.keep {
		if err := os.Remove(files[0].path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fsErr("remove old file", err)
		}
		files = files[1:]
	}
	syncDir(l.dir)
	return nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync() // best effort: persist the rename
		d.Close()
	}
}

const (
	lockName      = "audit.lock"
	rotatedPrefix = "audit-"
)

// checkDir refuses a log directory that is a symlink, not a directory,
// or open to group or others.
func checkDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fsErr("stat directory", err)
	}
	if !fi.IsDir() {
		return errors.New("audit: log directory is not a directory")
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("audit: log directory is accessible by group or others (mode %04o); run chmod 700 on it", perm)
	}
	return nil
}

// openPrivate opens a file inside the log directory without following a
// symlink, and refuses anything that is not a regular file with no group
// or other permissions. New files get mode 0600.
func openPrivate(path string, flag int) (*os.File, error) {
	f, err := os.OpenFile(path, flag|oNoFollow, 0o600)
	if err != nil {
		return nil, fsErr("open", err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fsErr("stat", err)
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("audit: log file is not a regular file")
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		f.Close()
		return nil, fmt.Errorf("audit: log file is accessible by group or others (mode %04o); run chmod 600 on it", perm)
	}
	return f, nil
}

// fsErr describes a filesystem error without its path. It keeps the
// underlying error for errors.Is (os.ErrNotExist).
func fsErr(op string, err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return &opError{op: op, err: pe.Err}
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		return &opError{op: op, err: le.Err}
	}
	return &opError{op: op, err: err}
}

type opError struct {
	op  string
	err error
}

func (e *opError) Error() string { return "audit: " + e.op + ": " + e.err.Error() }
func (e *opError) Unwrap() error { return e.err }
