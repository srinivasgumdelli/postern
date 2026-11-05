package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// logFile is one file of the chain.
type logFile struct {
	path     string
	firstSeq uint64 // 0 if the first line does not parse
}

// rotatedFiles lists the rotated files in dir, oldest first. Files are
// ordered by the seq of their first line (names only break ties), so a
// clock that went backwards does not reorder the chain.
func rotatedFiles(dir string) ([]logFile, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fsErr("list directory", err)
	}
	var out []logFile
	for _, de := range ents {
		name := de.Name()
		if !strings.HasPrefix(name, rotatedPrefix) || !strings.HasSuffix(name, ".jsonl") || !de.Type().IsRegular() {
			continue
		}
		p := filepath.Join(dir, name)
		seq, err := firstSeq(p)
		if err != nil {
			return nil, err
		}
		out = append(out, logFile{path: p, firstSeq: seq})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].firstSeq != out[j].firstSeq {
			return out[i].firstSeq < out[j].firstSeq
		}
		return out[i].path < out[j].path
	})
	return out, nil
}

func firstSeq(path string) (uint64, error) {
	f, err := openPrivate(path, os.O_RDONLY)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	line, err := bufio.NewReaderSize(f, 4096).ReadSlice('\n')
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return 0, fsErr("read", err)
	}
	s, _ := lineSeq(bytes.TrimSuffix(line, []byte("\n")))
	return s, nil
}

// chainFiles returns every file of the log at path in chain order: the
// rotated files, oldest first, then the active file if it exists.
func chainFiles(path string) ([]logFile, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, errors.New("audit: cannot resolve the log path")
	}
	files, err := rotatedFiles(filepath.Dir(abs))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(abs); err == nil {
		files = append(files, logFile{path: abs})
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fsErr("stat", err)
	}
	return files, nil
}

// eachLine calls fn for every line of path (without its newline),
// including a final line that has no newline.
func eachLine(path string, fn func(n int, line []byte) error) error {
	f, err := openPrivate(path, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64<<10)
	for n := 1; ; n++ {
		line, err := r.ReadBytes('\n')
		if len(line) > maxLine {
			return fmt.Errorf("audit: %s line %d is too long", filepath.Base(path), n)
		}
		if len(line) > 0 {
			if ferr := fn(n, bytes.TrimSuffix(line, []byte("\n"))); ferr != nil {
				return ferr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fsErr("read", err)
		}
	}
}

// parseStrict decodes one line, refusing unknown fields, trailing data,
// unknown events, mismatched actors and malformed seq, ts or prev.
func parseStrict(line []byte) (Entry, error) {
	var en Entry
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&en); err != nil {
		return Entry{}, errors.New("line is not a valid audit entry")
	}
	if dec.More() {
		return Entry{}, errors.New("line has trailing data")
	}
	if en.Seq == 0 {
		return Entry{}, errors.New("line has no seq")
	}
	if !hashRe.MatchString(en.Prev) {
		return Entry{}, errors.New("line has no valid prev")
	}
	if _, err := time.Parse(time.RFC3339, en.TS); err != nil {
		return Entry{}, errors.New("line has no valid ts")
	}
	if want, ok := eventActor[en.Event]; !ok || en.Actor != want {
		return Entry{}, errors.New("line has an unknown event or actor")
	}
	return en, nil
}

// BreakError reports the first place the chain does not hold.
type BreakError struct {
	File   string // base name of the file
	Line   int    // line number in that file
	Seq    uint64 // seq of the offending line, or the seq expected there if it does not parse
	Reason string
}

func (e *BreakError) Error() string {
	return fmt.Sprintf("audit chain broken at seq %d (%s line %d): %s", e.Seq, e.File, e.Line, e.Reason)
}

// Summary describes a log that verified.
type Summary struct {
	Files    []string // base names, in chain order
	Events   int
	FirstSeq uint64
	LastSeq  uint64
	LastHash string // SHA-256 of the last line; keep a copy elsewhere to detect truncation
	// Anchored is true when the chain starts at seq 1 with the genesis
	// prev. It is false once the oldest rotated files have been removed:
	// the first kept line is then trusted as the start.
	Anchored bool
	// HashSeq is the seq of the entry whose hash VerifyHash was given.
	HashSeq uint64
}

// Verify checks the chain across the rotated files and the active file
// of the log at path. It returns a *BreakError for the first line that
// does not parse, does not carry the next seq, or whose prev is not the
// hash of the line before it (including across a rotation). An empty or
// missing log verifies with zero events.
func Verify(path string) (Summary, error) { return verify(path, "") }

// ErrHashNotFound means VerifyHash's hash is the hash of no line in the
// log: the entry it was taken from has been cut, rewritten or rotated
// away.
var ErrHashNotFound = errors.New("audit: that hash is not the hash of any entry in the log")

// VerifyHash is Verify, and also checks that hash (a LastHash noted
// earlier) is the hash of one of the entries; Summary.HashSeq names it.
// Since a same-user process can rewrite the whole log, a hash kept
// somewhere else is what shows that the entries up to it are unchanged.
func VerifyHash(path, hash string) (Summary, error) {
	if !hashRe.MatchString(hash) {
		return Summary{}, errors.New("audit: hash must be 64 lowercase hex characters")
	}
	s, err := verify(path, hash)
	if err == nil && s.HashSeq == 0 {
		return s, ErrHashNotFound
	}
	return s, err
}

func verify(path, hash string) (Summary, error) {
	var s Summary
	files, err := chainFiles(path)
	if err != nil {
		return s, err
	}
	var (
		prevHash  string
		expectSeq uint64
	)
	for _, lf := range files {
		name := filepath.Base(lf.path)
		s.Files = append(s.Files, name)
		err := eachLine(lf.path, func(n int, line []byte) error {
			brk := func(seq uint64, reason string) error {
				return &BreakError{File: name, Line: n, Seq: seq, Reason: reason}
			}
			en, err := parseStrict(line)
			if err != nil {
				return brk(expectSeq, err.Error())
			}
			if expectSeq == 0 {
				// The first line kept. Seq 1 must start from genesis;
				// anything later had its predecessors rotated away.
				if en.Seq == 1 {
					if en.Prev != GenesisPrev {
						return brk(en.Seq, "the first entry does not start from the genesis prev")
					}
					s.Anchored = true
				}
				s.FirstSeq = en.Seq
			} else {
				if en.Seq != expectSeq {
					return brk(en.Seq, fmt.Sprintf("seq %d follows seq %d (an entry was removed, added or reordered)", en.Seq, expectSeq-1))
				}
				if en.Prev != prevHash {
					return brk(en.Seq, fmt.Sprintf("prev does not match the hash of seq %d (an entry was edited, removed or reordered)", expectSeq-1))
				}
			}
			prevHash = hashLine(line)
			if hash != "" && prevHash == hash {
				s.HashSeq = en.Seq
			}
			expectSeq = en.Seq + 1
			s.LastSeq = en.Seq
			s.Events++
			return nil
		})
		if err != nil {
			return s, err
		}
	}
	s.LastHash = prevHash
	return s, nil
}

// Tail returns the last n entries of the log at path, oldest first,
// reading back through rotated files as needed. Every field is checked
// against the patterns Record uses and replaced by Invalid if it does not
// match, so the output never carries free text, even from an edited file.
// A line that does not parse is returned with Event and Actor Invalid.
func Tail(path string, n int) ([]Entry, error) {
	if n <= 0 {
		return nil, nil
	}
	files, err := chainFiles(path)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for i := len(files) - 1; i >= 0 && len(out) < n; i-- {
		var lines []Entry
		err := eachLine(files[i].path, func(_ int, line []byte) error {
			lines = append(lines, readEntry(line))
			return nil
		})
		if err != nil {
			return nil, err
		}
		if extra := len(out) + len(lines) - n; extra > 0 {
			lines = lines[extra:]
		}
		out = append(lines, out...)
	}
	return out, nil
}

func readEntry(line []byte) Entry {
	var en Entry
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if dec.Decode(&en) != nil {
		return Entry{TS: Invalid, Event: Invalid, Actor: Invalid, Prev: Invalid}
	}
	return sanitizeEntry(en)
}
