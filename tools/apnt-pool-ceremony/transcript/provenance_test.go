package transcript_test

import (
	"hash/fnv"
	"testing"

	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/internal/fixture"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

// The Randomize hint id is pinned to gnark v0.16.3 (TestToolRecordMatchesGoMod
// pins the version): it is FNV-32a of the name, gnark's solver registers
// Randomize under it, and gnark's own Commit, compiled here, calls it with no
// input for the mask it appends, and records the name in the R1CS.
func TestRandomizeHintIDIsPinned(t *testing.T) {
	h := fnv.New32a()
	h.Write([]byte(transcript.RandomizeHintName))
	if solver.HintID(h.Sum32()) != transcript.RandomizeHintID {
		t.Fatalf("FNV-32a(%q) = %#x, pinned %#x", transcript.RandomizeHintName, h.Sum32(), uint32(transcript.RandomizeHintID))
	}
	fn := solver.GetRegisteredHint(transcript.RandomizeHintID)
	if fn == nil || solver.GetHintName(fn) != transcript.RandomizeHintName || solver.GetHintID(fn) != transcript.RandomizeHintID {
		t.Fatal("gnark's solver does not register Randomize under the pinned id")
	}

	r := compile(t, "committed", 3)
	committed := r.CommitmentInfo.(constraint.Groth16Commitments)[0].PrivateCommitted
	mask := committed[len(committed)-1]
	var found int
	var hm constraint.HintMapping
	for _, pi := range r.Instructions {
		bp, ok := r.Blueprints[pi.BlueprintID].(constraint.BlueprintHint)
		if !ok {
			continue
		}
		bp.DecompressHint(&hm, pi.Unpack(&r.System))
		if int(hm.OutputRange.Start) <= mask && mask < int(hm.OutputRange.End) {
			found++
			if hm.HintID != transcript.RandomizeHintID || len(hm.Inputs) != 0 || hm.OutputRange.End != hm.OutputRange.Start+1 {
				t.Fatalf("gnark's Commit set the mask with hint %#x, %d inputs, outputs [%d, %d)", uint32(hm.HintID), len(hm.Inputs), hm.OutputRange.Start, hm.OutputRange.End)
			}
		}
	}
	if found != 1 {
		t.Fatalf("%d hint instructions set the mask", found)
	}
	if r.MHintsDependencies[transcript.RandomizeHintID] != transcript.RandomizeHintName {
		t.Fatalf("the R1CS names the id %q", r.MHintsDependencies[transcript.RandomizeHintID])
	}
}

// A mask-shaped committed wire counts as a mask only as the sole output of
// one Randomize hint instruction with no input. The positive control is the
// same circuit with a proper Randomize mask.
func TestLocateCommitmentMasksRequiresRandomizeProvenance(t *testing.T) {
	m, err := transcript.LocateCommitmentMasks(fixture.MaskFromHintR1CS(transcript.RandomizeHintID))
	if err != nil || len(m.Positions) != 1 || len(m.Positions[0]) != 1 || m.Positions[0][0] != 0 {
		t.Fatalf("Randomize mask: %+v, %v", m, err)
	}
	for name, r := range map[string]*cs.R1CS{
		"output of another hint":       fixture.MaskFromHintR1CS(solver.GetHintID(solver.InvZeroHint), 1),
		"Randomize with an input":      fixture.MaskFromHintR1CS(transcript.RandomizeHintID, 1),
		"set by a second hint too":     secondHintOnMask(t, fixture.MaskFromHintR1CS(transcript.RandomizeHintID)),
		"id recorded under a new name": renamedRandomize(fixture.MaskFromHintR1CS(transcript.RandomizeHintID)),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := transcript.LocateCommitmentMasks(r)
			wantCode(t, err, failure.CommitmentMaskNotRandomized)
		})
	}
}

// secondHintOnMask appends, below gnark's builder (whose instruction tree
// refuses it), a second hint instruction whose output is the mask wire.
func secondHintOnMask(t *testing.T, r *cs.R1CS) *cs.R1CS {
	t.Helper()
	mask := r.CommitmentInfo.(constraint.Groth16Commitments)[0].PrivateCommitted[0]
	for id, bp := range r.Blueprints {
		if bh, ok := bp.(constraint.BlueprintHint); ok {
			var calldata []uint32
			bh.CompressHint(constraint.HintMapping{
				HintID:      solver.GetHintID(solver.InvZeroHint),
				Inputs:      []constraint.LinearExpression{{{CID: constraint.CoeffIdOne, VID: 1}}},
				OutputRange: struct{ Start, End uint32 }{uint32(mask), uint32(mask) + 1},
			}, &calldata)
			r.Instructions = append(r.Instructions, constraint.PackedInstruction{
				BlueprintID: constraint.BlueprintID(id), ConstraintOffset: uint32(r.GetNbConstraints()), StartCallData: uint64(len(r.CallData)),
			})
			r.CallData = append(r.CallData, calldata...)
			return r
		}
	}
	t.Fatal("no hint blueprint")
	return nil
}

func renamedRandomize(r *cs.R1CS) *cs.R1CS {
	r.MHintsDependencies[transcript.RandomizeHintID] = "example.com/not.Randomize"
	return r
}
