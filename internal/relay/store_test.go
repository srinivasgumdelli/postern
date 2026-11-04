package relay

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"postern/internal/envelope"
	"postern/internal/ulid"
)

func testEnvelope(to string) (envelope.Envelope, []byte) {
	from := "peer-a"
	if to == "peer-a" {
		from = "peer-b"
	}
	e := envelope.Envelope{
		V: envelope.Version, ID: ulid.New(), From: from, To: to,
		Thread: envelope.NewThreadID(), TS: time.Now().Unix(),
		Nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Box: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	raw, _ := json.Marshal(e)
	return e, raw
}

func TestOpenStoreCreatesPrivateFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	dir := filepath.Join(t.TempDir(), "state", "relay")
	path := filepath.Join(dir, "relay.db")
	st, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	e, raw := testEnvelope("peer-b")
	if _, err := st.insert(context.Background(), e, raw, time.Now().Unix(), 10); err != nil {
		t.Fatal(err)
	}
	check := func(p string, want os.FileMode) {
		t.Helper()
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s mode = %o, want %o", filepath.Base(p), got, want)
		}
	}
	check(dir, 0o700)
	check(path, 0o600)
	check(path+"-wal", 0o600)
	check(path+"-shm", 0o600)
}

func TestOpenStoreTightensExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	path := filepath.Join(t.TempDir(), "relay.db")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", fi.Mode().Perm())
	}
}

func TestStoreSeqNeverReused(t *testing.T) {
	// Cursors rely on seq only growing, even after the newest row is
	// acked and the store reopened.
	path := filepath.Join(t.TempDir(), "relay.db")
	ctx := context.Background()
	st, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	e1, raw1 := testEnvelope("peer-b")
	seq1, err := st.insert(ctx, e1, raw1, time.Now().Unix(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := st.ack(ctx, e1.ID, "peer-b"); err != nil || !ok {
		t.Fatalf("ack: %v %v", ok, err)
	}
	st.Close()
	st, err = OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	e2, raw2 := testEnvelope("peer-b")
	seq2, err := st.insert(ctx, e2, raw2, time.Now().Unix(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if seq2 <= seq1 {
		t.Fatalf("seq reused: %d then %d", seq1, seq2)
	}
	// The acked id is still remembered across the reopen.
	if dup, err := st.seen(ctx, e1.ID); err != nil || !dup {
		t.Fatalf("acked id forgotten: %v %v", dup, err)
	}
	if _, err := st.insert(ctx, e1, raw1, time.Now().Unix(), 10); err != errDuplicate {
		t.Fatalf("re-insert of acked id: %v", err)
	}
}

func TestStoreQueueLimitAndExpire(t *testing.T) {
	ctx := context.Background()
	st, err := OpenStore(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for i := range 2 {
		e, raw := testEnvelope("peer-b")
		if _, err := st.insert(ctx, e, raw, int64(100+i), 2); err != nil {
			t.Fatal(err)
		}
	}
	e, raw := testEnvelope("peer-b")
	if _, err := st.insert(ctx, e, raw, 102, 2); err != errQueueFull {
		t.Fatalf("third insert: %v", err)
	}
	if seen, _ := st.seen(ctx, e.ID); seen {
		t.Fatal("rejected envelope's id was recorded")
	}
	n, ids, err := st.expire(ctx, 101)
	if err != nil || n != 1 || ids != 1 {
		t.Fatalf("expire = %d %d %v", n, ids, err)
	}
	got, err := st.pending(ctx, "peer-b", 0, 0, 50)
	if err != nil || len(got) != 1 {
		t.Fatalf("pending = %d %v", len(got), err)
	}
}

func TestOpenStoreErrors(t *testing.T) {
	if _, err := OpenStore(""); err == nil {
		t.Fatal("accepted empty path")
	}
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(filepath.Join(blocker, "relay.db")); err == nil {
		t.Fatal("opened a store under a regular file")
	}
}
