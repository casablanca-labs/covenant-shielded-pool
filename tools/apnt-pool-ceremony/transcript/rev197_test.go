package transcript_test

// REV-197's counterexamples (R-401, /private/tmp/rev197.2ELkM8/fixed), made
// committed controls by IMPL-28. The reviewer's
// TestRev197PatternCanMatchNonrandomWire asserted that the locator accepted
// an ordinary secret input with the mask's constraint shape; this negative
// asserts the refusal instead. The two other reviewer tests are kept as
// written: they passed before the fix and must still pass.

import (
	"testing"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/pedersen"
	bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/internal/fixture"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

// y is a secret input constrained y·1 = y, not a Randomize hint output.
func TestRev197NonrandomMaskLikeWireIsNotAMask(t *testing.T) {
	r := fixture.UnmaskedR1CS()
	info := r.CommitmentInfo.(constraint.Groth16Commitments)
	info[0].PrivateCommitted[0] = 2
	m, err := transcript.LocateCommitmentMasks(r)
	if failure.CodeOf(err) != failure.CommitmentMaskNotRandomized {
		t.Fatalf("locator returned %+v, %v; want %s", m, err, failure.CommitmentMaskNotRandomized)
	}
}

func TestRev197RejectsSecondZeroMask(t *testing.T) {
	_, _, g1, _ := curve.Generators()
	m := &transcript.CommitmentMasks{NbCommitted: []int{1, 1}, Positions: [][]int{{0}, {0}}}
	pk := &bn254.ProvingKey{CommitmentKeys: []pedersen.ProvingKey{
		{Basis: []curve.G1Affine{g1}}, {Basis: []curve.G1Affine{{}}},
	}}
	if code := failure.CodeOf(m.Check(pk)); code != failure.CommitmentMaskZero {
		t.Fatalf("second mask: got %s, want %s", code, failure.CommitmentMaskZero)
	}
}

func TestRev197RejectsCrossCommitmentWire(t *testing.T) {
	r := fixture.MaskCancelledR1CS()
	cw := r.AddInternalVariable()
	info := r.CommitmentInfo.(constraint.Groth16Commitments)
	r.CommitmentInfo = append(info, constraint.Groth16Commitment{
		PrivateCommitted: []int{info[0].PrivateCommitted[0]}, CommitmentIndex: cw,
	})
	if code := failure.CodeOf(func() error { _, err := transcript.LocateCommitmentMasks(r); return err }()); code != failure.CommitmentMaskMissing {
		t.Fatalf("shared wire: got %s, want %s", code, failure.CommitmentMaskMissing)
	}
}
