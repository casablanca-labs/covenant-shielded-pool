package rerun_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/internal/fixture"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/rerun"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/testcircuits"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/verifier"
)

// phasedOptions starts from an action-shaped test circuit, the kind the
// phased runs are measured on.
func phasedOptions(t *testing.T) rerun.Options {
	t.Helper()
	dir := t.TempDir()
	ref := testcircuits.Shape{
		NbConstraints: 1000, NbInternal: 1246, NbSecret: 5, NbPublic: 3,
		L:             testcircuits.TermCount{One: 1612, MinusOne: 438, Two: 12, Other: 549, OtherWords: [4]int64{547, 1, 0, 1}},
		R:             testcircuits.TermCount{One: 1009, Other: 23, OtherWords: [4]int64{23}},
		O:             testcircuits.TermCount{Zero: 17, One: 998, MinusOne: 2, Other: 94, OtherWords: [4]int64{94}},
		NbCommitments: 1, NbCommitted: 589,
	}
	r, err := testcircuits.Shaped(ref, 700, 1)
	if err != nil {
		t.Fatal(err)
	}
	r1csPath := filepath.Join(dir, "shaped.r1cs")
	if err := testcircuits.WriteR1CS(r1csPath, r); err != nil {
		t.Fatal(err)
	}
	ptauPath, pin := fixture.Ptau(t, dir, fixture.Power(r))
	return rerun.Options{
		PtauPath: ptauPath, PtauPin: pin, PtauSource: "toy fixture (INSECURE)",
		R1CSPath: r1csPath, CircuitLabel: "shaped-700",
		OutDir: filepath.Join(dir, "ceremony"), WorkDir: filepath.Join(dir, "work"),
		CeremonyID: "phased", Contributions: 2, Beacon: fixture.Beacon,
	}
}

// Each phase as its own step, passing everything on disk, then the
// standalone verifier anchored: VALID, with the automated contributors in
// order.
func TestPhasesRunAsSeparateSteps(t *testing.T) {
	o := phasedOptions(t)
	if _, err := rerun.Init(o); err != nil {
		t.Fatal(err)
	}
	for i := range o.Contributions {
		s, err := rerun.Contribute(o)
		if err != nil {
			t.Fatal(err)
		}
		if s.Contribution == nil || s.Contribution.Index != i+1 {
			t.Fatalf("contribution %d: %+v", i+1, s.Contribution)
		}
	}
	if _, err := rerun.Seal(o); err != nil {
		t.Fatal(err)
	}
	rep, err := verifier.Verify(verifier.Inputs{
		TranscriptPath: filepath.Join(o.OutDir, transcript.TranscriptFile), PtauPath: o.PtauPath, R1CSPath: o.R1CSPath,
		ExpectedPhase1Pin: &o.PtauPin, ExpectedBeacon: o.Beacon.Value,
	})
	if err != nil || !rep.Authoritative() || rep.Provenance != transcript.SimulatedSingleParty {
		t.Fatalf("report %+v, err %v", rep, err)
	}
	for i, c := range rep.Contributions {
		if c.Contributor.ID != []string{"automated-01", "automated-02"}[i] || c.Contributor.Kind != transcript.KindAutomatedLocal {
			t.Fatalf("contribution %d by %+v", i+1, c.Contributor)
		}
	}
	// A sealed ceremony takes no further contribution or seal.
	_, err = rerun.Contribute(o)
	wantCode(t, err, failure.CeremonySealed)
	_, err = rerun.Seal(o)
	wantCode(t, err, failure.CeremonySealed)
}

// Seal refuses a phase-1 pin other than the transcript's and a number of
// contributions other than the expected one, before it reads the phase-1
// file.
func TestSealRefusesOtherPinAndCount(t *testing.T) {
	o := phasedOptions(t)
	if _, err := rerun.Init(o); err != nil {
		t.Fatal(err)
	}
	if _, err := rerun.Contribute(o); err != nil {
		t.Fatal(err)
	}
	other := o
	other.PtauPin = ptau.Pin{Algorithm: ptau.AlgSHA256, Digest: "0000000000000000000000000000000000000000000000000000000000000000"}
	_, err := rerun.Seal(other)
	wantCode(t, err, failure.Phase1PinUnexpected)

	_, err = rerun.Seal(o) // expects 2, the transcript holds 1
	wantCode(t, err, failure.ContributionSequence)

	o.Contributions = 1
	if _, err := rerun.Seal(o); err != nil {
		t.Fatal(err)
	}
}

func TestInitRefusesMissingOrUsedWorkDirectory(t *testing.T) {
	o := phasedOptions(t)
	noWork := o
	noWork.WorkDir = ""
	_, err := rerun.Init(noWork)
	wantCode(t, err, failure.WorkMismatch)

	if err := os.MkdirAll(o.WorkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(o.WorkDir, "left-over"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = rerun.Init(o)
	wantCode(t, err, failure.OutputExists)
	if _, err := os.Stat(o.OutDir); !os.IsNotExist(err) {
		t.Fatal("a refused init created the ceremony directory")
	}
}

// The one-command run leaves only the ceremony directory: its work
// directory is removed once the ceremony verifies.
func TestRunRemovesItsWorkDirectory(t *testing.T) {
	o := phasedOptions(t)
	o.WorkDir = ""
	s, err := rerun.Run(o)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Report.Authoritative() {
		t.Fatalf("report %+v", s.Report)
	}
	if _, err := os.Stat(o.OutDir + ".work"); !os.IsNotExist(err) {
		t.Fatalf("work directory left behind: %v", err)
	}
}
