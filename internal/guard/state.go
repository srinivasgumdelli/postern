package guard

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Marker states.
//
// "pending" and "tainted" both mean "untrusted Postern content may be in this
// session's context" and gate tool calls the same way. "pending" is set
// before check_inbox runs; "tainted" once a non-empty (or unverifiable)
// result has been seen.
//
// "cleared" records that the human cleared the guard; "clean" records that
// the session's transcript was scanned up to an offset and showed no
// check_inbox call. Both are untainted. They exist so that the lazy
// transcript scan in PreToolUse neither re-taints a cleared session nor
// rescans a long transcript on every call. Any other state is treated as
// tainted.
const (
	statePending = "pending"
	stateTainted = "tainted"
	stateCleared = "cleared"
	stateClean   = "clean"
)

// The transcript scan counts a JSONL line as a check_inbox call only when
// it holds a structural tool_use block naming an MCP check_inbox tool:
// unescaped "type":"tool_use" and "name":"mcp__<server>__check_inbox"
// (whitespace allowed around the colon). Tool names that appear as text,
// such as Claude Code's deferred-tool listings or a tool result quoting a
// name, sit inside JSON string values where every quote is escaped (\"),
// so they do not match. A quote preceded by a backslash is never counted.
var (
	toolUseTypeRe = regexp.MustCompile(`(?:^|[^\\])"type"\s*:\s*"tool_use"`)
	inboxNameRe   = regexp.MustCompile(`(?:^|[^\\])"name"\s*:\s*"mcp__[^"\\]*__check_inbox"`)
)

// maxScanLine bounds the bytes of one transcript line held for the exact
// match. Longer lines are judged by streaming flags instead: any line that
// contains both "tool_use" and "__check_inbox" anywhere counts (fail
// closed).
var maxScanLine = 1 << 20

const (
	maxMarkerBytes  = 4096
	lockPoll        = 5 * time.Millisecond
	staleLockAge    = 15 * time.Second
	maxTranscriptSz = 1 << 30 // 1 GiB; larger transcripts are treated as tainted
)

// lockWait bounds how long a hook waits for another hook process holding
// the same session's lock (a variable so tests can shorten it).
var lockWait = 3 * time.Second

var errLockTimeout = errors.New("timed out waiting for the marker lock")

// marker is the on-disk taint record for one Claude Code session. It never
// holds message content, subjects, senders or the session id itself.
type marker struct {
	State string `json:"state"`
	Since int64  `json:"since"`
	// Pending counts check_inbox calls whose result the guard has not seen
	// yet. A marker is only dropped when every one of them came back empty.
	Pending int `json:"pending,omitempty"`

	// For "clean" markers: how many bytes of the transcript have been
	// scanned, and a hash of the transcript path they belong to.
	Scanned    int64  `json:"scanned,omitempty"`
	Transcript string `json:"transcript,omitempty"`

	// corrupt is set by load when the file could not be parsed; update then
	// rewrites it as a clean "tainted" record.
	corrupt bool
}

func (m marker) gated() bool { return m.State == statePending || m.State == stateTainted }

func (m marker) known() bool {
	switch m.State {
	case statePending, stateTainted, stateCleared, stateClean:
		return true
	}
	return false
}

// store keeps one marker file per session under dir.
type store struct {
	dir string
	now func() time.Time
}

func newStore(dir string, now func() time.Time) *store {
	if now == nil {
		now = time.Now
	}
	return &store{dir: dir, now: now}
}

func sessionKey(sessionID string) string {
	sum := sha256.Sum256([]byte(sessionID))
	return hex.EncodeToString(sum[:])
}

func (s *store) path(sessionID string) string {
	return filepath.Join(s.dir, sessionKey(sessionID)+".json")
}

func (s *store) lockPath(sessionID string) string {
	return filepath.Join(s.dir, sessionKey(sessionID)+".lock")
}

// ensureDir creates the state directory with mode 0700 (and tightens it if
// it already exists with wider permissions).
func (s *store) ensureDir() error {
	if s.dir == "" {
		return errors.New("no state directory configured")
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Stat(s.dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("state path is not a directory")
	}
	if fi.Mode().Perm() != 0o700 {
		if err := os.Chmod(s.dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// load returns the session's marker. exists is false only when there is no
// marker file. A marker file that cannot be parsed, or that names an unknown
// state, is reported as tainted (fail closed), not as an error. Any read
// error other than "does not exist" is returned.
func (s *store) load(sessionID string) (m marker, exists bool, err error) {
	f, err := os.Open(s.path(sessionID))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return marker{}, false, nil
		}
		return marker{}, false, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxMarkerBytes+1))
	if err != nil {
		return marker{}, false, err
	}
	if len(raw) > maxMarkerBytes || json.Unmarshal(raw, &m) != nil || !m.known() {
		return marker{State: stateTainted, Since: s.now().Unix(), corrupt: true}, true, nil
	}
	if m.State == statePending && m.Pending < 1 {
		m.Pending = 1
	}
	return m, true, nil
}

// save writes the marker atomically (temp file + rename) with mode 0600.
func (s *store) save(sessionID string, m marker) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	if m.State != statePending {
		m.Pending = 0
	}
	if m.State != stateClean {
		m.Scanned, m.Transcript = 0, ""
	}
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path(sessionID), append(data, '\n'), 0o600)
}

// remove deletes the session's marker; a missing marker is not an error.
func (s *store) remove(sessionID string) error {
	err := os.Remove(s.path(sessionID))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// update runs fn on the current marker while holding the session's lock, so
// that concurrent hook processes (parallel tool calls) cannot lose an
// update. fn returns the new marker and whether it should be kept; keep ==
// false removes the marker.
func (s *store) update(sessionID string, fn func(m marker, exists bool) (next marker, keep bool, changed bool)) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	unlock, err := s.lock(sessionID)
	if err != nil {
		return err
	}
	defer unlock()
	cur, exists, err := s.load(sessionID)
	if err != nil {
		return err
	}
	next, keep, changed := fn(cur, exists)
	if !changed && !cur.corrupt {
		return nil
	}
	if !keep {
		return s.remove(sessionID)
	}
	return s.save(sessionID, next)
}

// lock takes a per-session lock file created with O_EXCL. It uses wall-clock
// time (not s.now) so that tests with a frozen clock still time out.
func (s *store) lock(sessionID string) (func(), error) {
	p := s.lockPath(sessionID)
	deadline := time.Now().Add(lockWait)
	for {
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			return func() { os.Remove(p) }, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		// A hook process holds the lock for milliseconds. One that is much
		// older was left by a process that died; break it.
		if fi, serr := os.Stat(p); serr == nil && time.Since(fi.ModTime()) > staleLockAge {
			os.Remove(p)
			continue
		}
		if time.Now().After(deadline) {
			return nil, errLockTimeout
		}
		time.Sleep(lockPoll)
	}
}

// writeFileAtomic writes data to a temp file in the target directory and
// renames it into place, so readers never see a partial file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()
	if err = tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func expandHome(path string) (string, error) {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

// pathKey identifies a transcript path in a "clean" marker without storing
// the path itself.
func pathKey(path string) string {
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:8])
}

// transcriptMentions reports whether the transcript shows a check_inbox
// tool call. It returns an error if the file cannot be read in full; callers
// treat an error as "may contain one". The transcript is scanned, never
// stored.
func transcriptMentions(path string) (bool, error) {
	if path == "" {
		return false, errors.New("no transcript path")
	}
	found, _, err := scanTranscript(path, "", 0)
	return found, err
}

// scanTranscript reports whether any line of the transcript from byte
// offset from onwards is a check_inbox tool call, ignoring lines that
// contain exclude (the current call's tool_use_id, when not empty). from
// must be a line boundary previously returned as end; it is ignored if the
// file is now shorter. end is the offset just past the last complete line
// read, so a line still being written is scanned again next time. A missing
// file returns an error wrapping fs.ErrNotExist. Memory use is bounded
// regardless of line length.
func scanTranscript(path, exclude string, from int64) (found bool, end int64, err error) {
	path, err = expandHome(path)
	if err != nil {
		return false, 0, err
	}
	f, err := os.Open(path)
	if err != nil {
		return false, 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return false, 0, err
	}
	if !fi.Mode().IsRegular() {
		return false, 0, errors.New("transcript is not a regular file")
	}
	if from > fi.Size() || from < 0 {
		from = 0 // shrank or was replaced: scan it all again
	}
	if _, err := f.Seek(from, io.SeekStart); err != nil {
		return false, 0, err
	}
	found, n, err := scanLines(f, []byte(exclude), maxTranscriptSz)
	return found, from + n, err
}

// substrFlag tracks whether a needle occurs in a stream fed in pieces.
type substrFlag struct {
	needle []byte
	tail   []byte
	seen   bool
}

func (f *substrFlag) feed(seg []byte) {
	if f.seen || len(f.needle) == 0 {
		return
	}
	w := append(append([]byte{}, f.tail...), seg...)
	if bytes.Contains(w, f.needle) {
		f.seen = true
		return
	}
	keep := len(f.needle) - 1
	if len(w) > keep {
		w = w[len(w)-keep:]
	}
	f.tail = append(f.tail[:0], w...)
}

func (f *substrFlag) reset() { f.tail, f.seen = f.tail[:0], false }

// scanLines streams r line by line and reports whether some line is a
// check_inbox tool call (see toolUseTypeRe) that does not contain exclude,
// and how many bytes up to and including the last newline were consumed.
// Reading more than limit bytes is an error.
func scanLines(r io.Reader, exclude []byte, limit int64) (found bool, complete int64, err error) {
	var (
		total    int64
		line     []byte
		overflow bool
		toolUse  = &substrFlag{needle: []byte("tool_use")}
		inbox    = &substrFlag{needle: []byte("__check_inbox")}
		excl     = &substrFlag{needle: exclude}
		chunk    = make([]byte, 64*1024)
	)
	feed := func(seg []byte) {
		toolUse.feed(seg)
		inbox.feed(seg)
		excl.feed(seg)
		if !overflow {
			if len(line)+len(seg) > maxScanLine {
				overflow, line = true, line[:0]
			} else {
				line = append(line, seg...)
			}
		}
	}
	endLine := func() bool {
		var hit bool
		switch {
		case excl.seen:
			hit = false
		case overflow:
			hit = toolUse.seen && inbox.seen
		default:
			hit = toolUseTypeRe.Match(line) && inboxNameRe.Match(line)
		}
		line, overflow = line[:0], false
		toolUse.reset()
		inbox.reset()
		excl.reset()
		return hit
	}
	for {
		n, rerr := r.Read(chunk)
		data := chunk[:n]
		for len(data) > 0 {
			nl := bytes.IndexByte(data, '\n')
			if nl < 0 {
				feed(data)
				total += int64(len(data))
				break
			}
			feed(data[:nl])
			total += int64(nl + 1)
			if endLine() {
				return true, total, nil
			}
			complete = total
			data = data[nl+1:]
		}
		if total > limit {
			return false, complete, errors.New("transcript too large to scan")
		}
		if rerr == io.EOF {
			// A final line without a newline may still be being written;
			// it counts now but is rescanned next time.
			return endLine(), complete, nil
		}
		if rerr != nil {
			return false, complete, rerr
		}
	}
}
