package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/internal/fixture"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/rerun"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

// --expect-r1cs-sha256 refuses a transcript for another circuit (exit 1,
// R1CS_UNEXPECTED); with the right digest the report says the circuit is
// anchored, and without the flag it says it is not.
func TestExpectR1CSFlag(t *testing.T) {
	root := t.TempDir()
	r1csPath, r := fixture.R1CS(t, root, "cubic", 5)
	ptauPath, pin := fixture.Ptau(t, root, fixture.Power(r))
	out := filepath.Join(root, "ceremony")
	s, err := rerun.Run(rerun.Options{
		PtauPath: ptauPath, PtauPin: pin, PtauSource: "toy fixture (INSECURE)",
		R1CSPath: r1csPath, CircuitLabel: "cubic", OutDir: out, CeremonyID: "cli-r1cs-anchor",
		Contributions: 1, Beacon: fixture.Beacon,
	})
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"--transcript", filepath.Join(out, transcript.TranscriptFile), "--ptau", ptauPath, "--r1cs", r1csPath,
		"--expect-phase1-pin", pin.String(), "--expect-beacon", fixture.Beacon.Value}
	runWith := func(extra ...string) (int, string) {
		var o, e bytes.Buffer
		code := run(append(append([]string(nil), args...), extra...), &o, &e)
		return code, o.String() + e.String()
	}
	if code, text := runWith(); code != 0 || !strings.Contains(text, "circuit anchor: NONE") {
		t.Fatalf("no flag: exit %d\n%s", code, text)
	}
	if code, text := runWith("--expect-r1cs-sha256", s.Report.R1CSSHA256); code != 0 || !strings.Contains(text, "circuit anchor: r1cs sha256 equals") {
		t.Fatalf("matching flag: exit %d\n%s", code, text)
	}
	code, text := runWith("--expect-r1cs-sha256", s.Report.R1CSSHA256, "--json")
	var rep struct {
		Anchors struct{ R1CS bool } `json:"anchors"`
	}
	if code != 0 || json.Unmarshal([]byte(text[:strings.LastIndex(text, "}")+1]), &rep) != nil || !rep.Anchors.R1CS {
		t.Fatalf("matching flag, JSON: exit %d\n%s", code, text)
	}
	if code, text := runWith("--expect-r1cs-sha256", strings.Repeat("0", 64)); code != 1 || !strings.Contains(text, "R1CS_UNEXPECTED") {
		t.Fatalf("other digest: exit %d\n%s", code, text)
	}
}
