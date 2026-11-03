package pkload

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestDeriveRefusesBeforeAnyDecode: Derive compares the raw file's SHA-256
// with the raw pin before any decoder sees a byte (F2). A flipped byte inside
// a point, which gnark's checked decoder would itself reject, must stop at the
// digest with no decoder call, and nothing is written.
func TestDeriveRefusesBeforeAnyDecode(t *testing.T) {
	s := newSetup(t)
	raw, err := os.ReadFile(s.raw)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(at int) []byte { b := bytes.Clone(raw); b[at] ^= 0x01; return b }
	for _, c := range []struct {
		name  string
		b     []byte
		stage Stage
	}{
		{"flipped byte in a point", flip(len(raw) / 2), StageDigest},
		{"flipped byte near the end", flip(len(raw) - 3), StageDigest},
		{"truncated", raw[:len(raw)-1], StageSize},
		{"appended", append(bytes.Clone(raw), 0), StageSize},
	} {
		p := filepath.Join(s.dir, "raw.bad")
		out := filepath.Join(s.dir, "from-bad.image")
		if err := os.WriteFile(p, c.b, 0o600); err != nil {
			t.Fatal(err)
		}
		refused(t, "derive: "+c.name, c.stage, func() error { _, err := Derive(p, s.rawPin, out, FormatImage); return err })
		if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("derive: %s: an image was written", c.name)
		}
		os.Remove(p)
	}
	// Positive control: the unmodified file derives, and its decode is counted,
	// so the counter would have seen a decode before the refusals above.
	before := decodeCalls.Load()
	if _, err := Derive(s.raw, s.rawPin, filepath.Join(s.dir, "good.image"), FormatImage); err != nil {
		t.Fatal(err)
	}
	if decodeCalls.Load() == before {
		t.Fatal("Derive's checked decode is not counted; the no-decode assertions above prove nothing")
	}
}
