package guard

import (
	"bufio"
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
	"strings"
	"time"
)

// Marker states. Both mean "untrusted Postern content may be in this
// session's context" and gate tool calls the same way. "pending" is set
// before check_inbox runs; "tainted" once a non-empty (or unverifiable)
// result has been seen.
const (
	statePending = "pending"
	stateTainted = "tainted"
)

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

	// corrupt is set by load when the file could not be parsed; update then
	// rewrites it as a clean "tainted" record.
	corrupt bool
}

func (m marker) gated() bool { return m.State == statePending || m.State == stateTainted }

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
	if len(raw) > maxMarkerBytes || json.Unmarshal(raw, &m) != nil || !m.gated() {
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

// transcriptMentions reports whether the transcript file contains needle.
// It returns an error if the file cannot be read in full; callers treat an
// error as "may contain it". The transcript is scanned, never stored.
func transcriptMentions(path, needle string) (bool, error) {
	if path == "" {
		return false, errors.New("no transcript path")
	}
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return false, err
		}
		path = filepath.Join(home, path[2:])
	}
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	return readerContains(f, []byte(needle), maxTranscriptSz)
}

// readerContains streams r looking for needle without loading it all into
// memory. Reading more than limit bytes is an error.
func readerContains(r io.Reader, needle []byte, limit int64) (bool, error) {
	if len(needle) == 0 {
		return true, nil
	}
	br := bufio.NewReaderSize(r, 64*1024)
	buf := make([]byte, 0, 64*1024+len(needle))
	chunk := make([]byte, 64*1024)
	var total int64
	for {
		n, err := br.Read(chunk)
		if n > 0 {
			total += int64(n)
			if total > limit {
				return false, errors.New("transcript too large to scan")
			}
			buf = append(buf, chunk[:n]...)
			if bytes.Contains(buf, needle) {
				return true, nil
			}
			// Keep only the tail that could start a match spanning chunks.
			if keep := len(needle) - 1; len(buf) > keep {
				buf = append(buf[:0], buf[len(buf)-keep:]...)
			}
		}
		if err == io.EOF {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
}
