package verifier_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/verifier"
)

// ENG-443 (REV-198 H2): the report names the exact transcript bytes it
// accepted. The report is read as its JSON, the form a release gate archives,
// so this test also runs against a verifier whose report lacks the field.

// reportJSON verifies c and returns the report as decoded JSON.
func reportJSON(t *testing.T, c ceremony) map[string]any {
	t.Helper()
	rep, err := verifier.Verify(c.inputs())
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func without(m map[string]any, key string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if k != key {
			out[k] = v
		}
	}
	return out
}

func TestReportNamesTheExactTranscript(t *testing.T) {
	c := base(t)
	path := filepath.Join(c.dir, transcript.TranscriptFile)
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	first := reportJSON(t, c)
	if first["transcriptSha256"] != transcript.Digest(orig) {
		t.Fatalf("transcriptSha256 %v, the file hashes to %s", first["transcriptSha256"], transcript.Digest(orig))
	}

	// Phase1.Source is neither checked nor reported: the edited transcript is
	// VALID with a report equal in every other field, so only the new field
	// tells the two transcripts apart.
	tr := c.load(t)
	tr.Phase1.Source += " (edited)"
	c.save(t, tr)
	edited, _ := os.ReadFile(path)
	second := reportJSON(t, c)
	if second["transcriptSha256"] != transcript.Digest(edited) || second["transcriptSha256"] == first["transcriptSha256"] {
		t.Fatalf("edited source: transcriptSha256 %v, first %v", second["transcriptSha256"], first["transcriptSha256"])
	}
	if !reflect.DeepEqual(without(first, "transcriptSha256"), without(second, "transcriptSha256")) {
		t.Fatal("the unreported edit changed another report field; the test no longer isolates it")
	}

	// The same transcript in other bytes (compact JSON) is another file.
	var compact bytes.Buffer
	if err := json.Compact(&compact, orig); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, compact.Bytes(), 0o644)
	third := reportJSON(t, c)
	if third["transcriptSha256"] != transcript.Digest(compact.Bytes()) || third["transcriptSha256"] == first["transcriptSha256"] {
		t.Fatalf("compact bytes: transcriptSha256 %v", third["transcriptSha256"])
	}

	// REV-198's case: an edited root challenge is refused, and its bytes do
	// not hash to the transcriptSha256 of the report the original earned, so
	// that archived report cannot be attached to it.
	os.WriteFile(path, orig, 0o644)
	tr = c.load(t)
	flip := map[byte]string{'0': "1"}[tr.Phase2.RootChallenge[0]]
	if flip == "" {
		flip = "0"
	}
	tr.Phase2.RootChallenge = flip + tr.Phase2.RootChallenge[1:]
	c.save(t, tr)
	rootEdited, _ := os.ReadFile(path)
	if _, err := verifier.Verify(c.inputs()); failure.CodeOf(err) != failure.RootMismatch {
		t.Fatalf("edited root challenge: %v", err)
	}
	if transcript.Digest(rootEdited) == first["transcriptSha256"] {
		t.Fatal("the edited transcript hashes to the archived report's transcriptSha256")
	}
}
