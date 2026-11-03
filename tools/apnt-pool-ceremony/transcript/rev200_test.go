package transcript_test

// REV-200's probes (R-410, archive REV-200-…-evidence/tests/rev200_angles_test.go),
// made committed controls by IMPL-31. Each isolates one condition of the
// Randomize call-shape test or the hint-name record.

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/internal/fixture"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

// rev200ConstHint is a no-input, one-output hint that is not Randomize (a
// constant), registered only in this test binary.
func rev200ConstHint(_ *big.Int, _ []*big.Int, out []*big.Int) error {
	out[0].SetUint64(5)
	return nil
}

func init() { solver.RegisterHint(rev200ConstHint) }

// Only the id tells this call from gnark's Randomize call. In the second
// circuit a genuine Randomize call elsewhere makes the hint-name record
// present, so nothing but the id condition refuses the mask.
func TestRev200NoInputForeignHintRefused(t *testing.T) {
	alone := fixture.MaskFromHintR1CS(solver.GetHintID(rev200ConstHint))
	withRandomize := fixture.MaskFromHintR1CS(solver.GetHintID(rev200ConstHint))
	if _, err := withRandomize.AddSolverHint(solver.GetRegisteredHint(transcript.RandomizeHintID), transcript.RandomizeHintID, nil, 1); err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]*cs.R1CS{"alone": alone, "beside a Randomize call": withRandomize} {
		_, err := transcript.LocateCommitmentMasks(r)
		if failure.CodeOf(err) != failure.CommitmentMaskNotRandomized {
			t.Fatalf("no-input constant hint, %s: %v", name, err)
		}
	}
}

// Only the output count tells this call from gnark's Randomize call.
func TestRev200TwoOutputRandomizeRefused(t *testing.T) {
	r := fixture.MaskFromHintR1CS(transcript.RandomizeHintID)
	var hm constraint.HintMapping
	for i, pi := range r.Instructions {
		bh, ok := r.Blueprints[pi.BlueprintID].(constraint.BlueprintHint)
		if !ok {
			continue
		}
		bh.DecompressHint(&hm, pi.Unpack(&r.System))
		var cd []uint32
		hm.OutputRange.End = hm.OutputRange.Start + 2
		bh.CompressHint(hm, &cd)
		r.Instructions[i].StartCallData = uint64(len(r.CallData))
		r.CallData = append(r.CallData, cd...)
	}
	_, err := transcript.LocateCommitmentMasks(r)
	if failure.CodeOf(err) != failure.CommitmentMaskNotRandomized {
		t.Fatalf("two-output Randomize: %v", err)
	}
}

// A mask's R1CS must record the Randomize id under gnark's name.
func TestRev200MissingNameRecordRefused(t *testing.T) {
	r := fixture.MaskFromHintR1CS(transcript.RandomizeHintID)
	delete(r.MHintsDependencies, transcript.RandomizeHintID)
	m, err := transcript.LocateCommitmentMasks(r)
	if failure.CodeOf(err) != failure.CommitmentMaskNotRandomized {
		t.Fatalf("name record absent: masks %+v, err %v", m, err)
	}
}
