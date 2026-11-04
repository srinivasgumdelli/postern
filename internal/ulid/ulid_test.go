package ulid

import (
	"sort"
	"strings"
	"testing"
	"time"
)

func TestNewIsValidAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := New()
		if !Valid(id) {
			t.Fatalf("New() = %q, not valid", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}

func TestTimeOrdering(t *testing.T) {
	base := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	var ids []string
	for i := 0; i < 50; i++ {
		ids = append(ids, NewAt(base.Add(time.Duration(i)*time.Millisecond)))
	}
	if !sort.StringsAreSorted(ids) {
		t.Fatal("ids for increasing times are not lexically sorted")
	}
}

func TestKnownEncoding(t *testing.T) {
	// Zero time and zero entropy encode to all zeros.
	var b [16]byte
	if got := encode(b); got != strings.Repeat("0", Len) {
		t.Fatalf("encode(zero) = %q", got)
	}
	for i := range b {
		b[i] = 0xff
	}
	if got := encode(b); got != "7"+strings.Repeat("Z", Len-1) {
		t.Fatalf("encode(max) = %q", got)
	}
}

func TestValidRejects(t *testing.T) {
	for _, s := range []string{
		"",
		"01JC9Z",
		"8ZZZZZZZZZZZZZZZZZZZZZZZZZ", // overflows 128 bits
		"01jc9zzzzzzzzzzzzzzzzzzzzz", // lower case
		"01JC9ZZZZZZZZZZZZZZZZZZZZI", // I not in alphabet
		"01JC9ZZZZZZZZZZZZZZZZZZZZU", // U not in alphabet
		"01JC9ZZZZZZZZZZZZZZZZZZZZZ0",
	} {
		if Valid(s) {
			t.Errorf("Valid(%q) = true", s)
		}
	}
}
