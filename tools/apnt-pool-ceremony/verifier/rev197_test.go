package verifier_test

// REV-197's end-to-end counterexample (R-401, /private/tmp/rev197.2ELkM8/fixed),
// made a committed negative by IMPL-28. The reviewer's
// TestRev197NonrandomMaskLikeWireReachesValid asserted VALID for a ceremony
// whose only commitment covers an ordinary secret input y with y·1 = y; this
// test asserts the refusal instead, from rerun and from the verifier alone.

import (
	"path/filepath"
	"testing"

	"github.com/consensys/gnark/constraint"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/internal/fixture"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/rerun"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/verifier"
)

func TestRev197NonrandomMaskLikeWireIsRefused(t *testing.T) {
	r := fixture.UnmaskedR1CS()
	info := r.CommitmentInfo.(constraint.Groth16Commitments)
	info[0].PrivateCommitted[0] = 2 // y is a secret input constrained y*1=y, no Randomize hint
	root := t.TempDir()
	r1csPath := writeR1CS(t, root, r)
	ptauPath, pin := fixture.Ptau(t, root, 2)
	out := filepath.Join(root, "ceremony")
	o := rerun.Options{
		PtauPath: ptauPath, PtauPin: pin, PtauSource: "toy fixture (INSECURE)",
		R1CSPath: r1csPath, CircuitLabel: "fake-mask", OutDir: out, WorkDir: filepath.Join(root, "work"),
		CeremonyID: "rev197-fake-mask", Contributions: 1, Beacon: fixture.Beacon,
	}
	s, err := rerun.Run(o)
	if failure.CodeOf(err) != failure.CommitmentMaskNotRandomized || (s != nil && s.Report != nil) {
		t.Fatalf("rerun: verdict %s, err %v; want %s", summaryVerdict(s), err, failure.CommitmentMaskNotRandomized)
	}
	// rerun.Run stops at its verifier; the sealed ceremony is on disk.
	rep, err := verifier.Verify(verifier.Inputs{
		TranscriptPath: filepath.Join(out, transcript.TranscriptFile), PtauPath: ptauPath,
		R1CSPath: r1csPath, ExpectedPhase1Pin: &pin, ExpectedBeacon: fixture.Beacon.Value,
	})
	if rep != nil || failure.CodeOf(err) != failure.CommitmentMaskNotRandomized {
		t.Fatalf("verifier: verdict %s, err %v; want %s", verdictOf(rep), err, failure.CommitmentMaskNotRandomized)
	}
}
