package devprove

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestLiveReviewCorpusAuthentication(t *testing.T) {
	t.Skip("requires protected action witnesses; not shipped")
	defer protectedPanic(t)
	c := liveFixture(t)
	c.Entries[0].Name = ReferenceEntry
	c.Entries[0].Note = "SYNTHETIC_PRIVATE_TEXT_MARKER"
	path := liveFile(t, liveJSON(t, c))
	a, src, err := ActionTarget(path).Assignment()
	if err != ErrCorpusSource || a != nil || src != nil {
		protectedFatal(t, "renamed live request acquired corpus provenance")
	}
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		protectedFatal(t, "read fixture")
	}
	// An exact copy is authenticated by content, not by where the caller put it.
	if err := os.WriteFile(path, raw, 0600); err != nil {
		protectedFatal(t, "copy fixture")
	}
	a, src, err = ActionTarget(path).Assignment()
	if err != nil || a == nil || src.Kind != "committed-corpus" || src.Corpus != actionCorpusFile {
		protectedFatal(t, "genuine committed corpus refused")
	}
	b, _ := json.Marshal(src)
	if strings.Contains(string(b), path) || strings.Contains(string(b), "SYNTHETIC_PRIVATE_TEXT_MARKER") {
		protectedFatal(t, "caller metadata in corpus provenance")
	}
	// A one-byte, semantically irrelevant edit still loses committed provenance.
	if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
		protectedFatal(t, "mutate fixture")
	}
	if _, _, err := ActionTarget(path).Assignment(); err != ErrCorpusSource {
		protectedFatal(t, "edited corpus accepted")
	}
}

// Raw file-object and replacement admission is exercised by the owning
// bridge/construction suites; no unguarded private-file reader remains.

// R3: decoder-only retained-memory controls. Guarded path substitution and
// inode replacement belong to the real bridge/construction suites. These
// bytes could not be admitted through a genuine unchanged construction.
func TestMIG01R3DecoderRetainsImmutableAssignment(t *testing.T) {
	t.Skip("requires protected action witnesses; not shipped")
	defer protectedPanic(t)
	raw := liveJSON(t, liveFixture(t))
	a, _, err := liveAssignment(raw)
	if err != nil {
		protectedFatal(t, "decoder unit positive refused")
	}
	held, _ := json.Marshal(a)
	changed := liveFixture(t)
	changed.Entries[0].Witness.Outputs[0].ValueSats = "1"
	fresh, _, err := liveAssignment(liveJSON(t, changed))
	if err != nil {
		protectedFatal(t, "changed decoder unit positive refused")
	}
	different, _ := json.Marshal(fresh)
	if bytes.Equal(different, held) {
		protectedFatal(t, "snapshot detector failed its firing control")
	}
	for _, invalid := range [][]byte{[]byte("{"), nil} {
		if _, _, err := liveAssignment(invalid); err != ErrRequestMalformed {
			protectedFatal(t, "malformed decoder unit accepted")
		}
	}
	raw[0] = 0
	after, _ := json.Marshal(a)
	if !bytes.Equal(after, held) {
		protectedFatal(t, "held assignment changed after original bytes mutated")
	}
}
