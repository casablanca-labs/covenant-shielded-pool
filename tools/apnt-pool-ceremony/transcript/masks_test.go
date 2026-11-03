package transcript_test

import (
	"math/big"
	"math/bits"
	"testing"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/internal/fixture"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/testcircuits"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

func bigU(v uint64) *big.Int { return new(big.Int).SetUint64(v) }

func frU(v uint64) fr.Element {
	var e fr.Element
	e.SetUint64(v)
	return e
}

// sealed runs gnark's phase 2 on r and commons, as the ceremony does (one
// contribution, then the beacon), and returns the proving key.
func sealed(t *testing.T, r *cs.R1CS, commons *mpcsetup.SrsCommons) *groth16bn254.ProvingKey {
	t.Helper()
	p, _, evals, err := transcript.InitialState(r, commons, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	p.Contribute()
	pk, _ := p.Seal(transcript.SealCommons(commons), evals, []byte("a thirty-two byte test beacon!!!"))
	return pk.(*groth16bn254.ProvingKey)
}

func commonsFor(r *cs.R1CS, tau, alpha, beta fr.Element) *mpcsetup.SrsCommons {
	return ptau.ToyCommonsFr(uint32(bits.TrailingZeros64(transcript.DomainSize(r))), tau, alpha, beta)
}

func compile(t *testing.T, name string, size int) *cs.R1CS {
	t.Helper()
	r, err := testcircuits.Compile(name, size)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// gnark's Commit: in the committed test circuit, which commits to X[0..7],
// the mask is found once, as the ninth and last committed wire. Circuits
// without a commitment have no mask to find. The action-shaped test
// circuit's mask constraint is found too.
func TestLocateCommitmentMasksOfTestCircuits(t *testing.T) {
	for _, size := range []int{3, 40} {
		m, err := transcript.LocateCommitmentMasks(compile(t, "committed", size))
		if err != nil {
			t.Fatal(err)
		}
		if len(m.Positions) != 1 || len(m.Positions[0]) != 1 || m.Positions[0][0] != 8 || m.NbCommitted[0] != 9 {
			t.Fatalf("committed-%d: %+v, want the mask at position 8 of 9", size, m)
		}
	}
	for _, name := range []string{"cubic", "chain"} {
		m, err := transcript.LocateCommitmentMasks(compile(t, name, 5))
		if err != nil || len(m.Positions) != 0 {
			t.Fatalf("%s: %+v, %v", name, m, err)
		}
	}
	ref := testcircuits.Shape{
		NbConstraints: 1000, NbInternal: 1246, NbSecret: 5, NbPublic: 3,
		L:             testcircuits.TermCount{One: 1612, MinusOne: 438, Two: 12, Other: 549, OtherWords: [4]int64{547, 1, 0, 1}},
		R:             testcircuits.TermCount{One: 1009, Other: 23, OtherWords: [4]int64{23}},
		O:             testcircuits.TermCount{Zero: 17, One: 998, MinusOne: 2, Other: 94, OtherWords: [4]int64{94}},
		NbCommitments: 2, NbCommitted: 589,
	}
	shaped, err := testcircuits.Shaped(ref, 700, 1)
	if err != nil {
		t.Fatal(err)
	}
	m, err := transcript.LocateCommitmentMasks(shaped)
	if err != nil {
		t.Fatal(err)
	}
	for k := range m.Positions {
		if len(m.Positions[k]) != 1 {
			t.Fatalf("shaped commitment %d: masks %v", k, m.Positions[k])
		}
	}
	// The hand-built fixture: x and m are both Randomize outputs with the
	// mask's constraint.
	m, err = transcript.LocateCommitmentMasks(fixture.MaskCancelledR1CS())
	if err != nil || len(m.Positions) != 1 || len(m.Positions[0]) != 2 || m.Positions[0][0] != 0 || m.Positions[0][1] != 1 {
		t.Fatalf("mask-cancelled fixture: %+v, %v", m, err)
	}
}

// A commitment with no committed wire w constrained by w·1 = w is refused:
// no mask, no hiding, and a change to gnark's Commit fails closed.
func TestLocateCommitmentMasksRefusesAnUnmaskedCommitment(t *testing.T) {
	_, err := transcript.LocateCommitmentMasks(fixture.UnmaskedR1CS())
	wantCode(t, err, failure.CommitmentMaskMissing)
}

// A commitment layout the basis order cannot be read from is refused.
func TestLocateCommitmentMasksRefusesAnUnreadableLayout(t *testing.T) {
	for name, edit := range map[string]func(c *constraint.Groth16Commitment){
		"unsorted": func(c *constraint.Groth16Commitment) {
			c.PrivateCommitted[0], c.PrivateCommitted[1] = c.PrivateCommitted[1], c.PrivateCommitted[0]
		},
		"public wire committed":     func(c *constraint.Groth16Commitment) { c.PrivateCommitted[0] = 0 },
		"commitment wire committed": func(c *constraint.Groth16Commitment) { c.PrivateCommitted[0] = c.CommitmentIndex },
	} {
		r := fixture.MaskCancelledR1CS()
		info := r.CommitmentInfo.(constraint.Groth16Commitments)
		edit(&info[0])
		_, err := transcript.LocateCommitmentMasks(r)
		if failure.CodeOf(err) != failure.CommitmentMaskMissing {
			t.Fatalf("%s: got %v", name, err)
		}
	}
}

// The check on real sealed keys of the committed circuit: an honest phase 1
// passes; β = −1 and τ a root of unity other than ω^(mask constraint) each
// leave the mask's basis element O and are refused, which is ARCH-238's
// construction. An O at the mask position is refused whatever made it, and
// an O at another committed position is not this check's concern.
func TestCheckRefusesAZeroMaskBasisElement(t *testing.T) {
	r := compile(t, "committed", 3)
	m, err := transcript.LocateCommitmentMasks(r)
	if err != nil {
		t.Fatal(err)
	}
	mask := m.Positions[0][0]

	honest := sealed(t, r, commonsFor(r, frU(fixture.ToyTau), frU(fixture.ToyAlpha), frU(fixture.ToyBeta)))
	if err := m.Check(honest); err != nil {
		t.Fatalf("honest key: %v", err)
	}

	var minusOne fr.Element
	minusOne.SetOne()
	minusOne.Neg(&minusOne)
	betaKey := sealed(t, r, commonsFor(r, frU(fixture.ToyTau), frU(fixture.ToyAlpha), minusOne))
	if !betaKey.CommitmentKeys[0].Basis[mask].IsInfinity() {
		t.Fatal("β = −1: the mask's basis element is not O")
	}
	wantCode(t, m.Check(betaKey), failure.CommitmentMaskZero)

	// τ = ωʲ with j not the mask constraint's index k: Lₖ(τ) = 0.
	k := maskConstraintIndex(t, r)
	n := transcript.DomainSize(r)
	var tau fr.Element
	tau.Exp(fft.NewDomain(n).Generator, bigU(uint64((k+1)%int(n))))
	tauKey := sealed(t, r, commonsFor(r, tau, frU(fixture.ToyAlpha), frU(fixture.ToyBeta)))
	wantCode(t, m.Check(tauKey), failure.CommitmentMaskZero)

	zeroed := sealed(t, r, commonsFor(r, frU(fixture.ToyTau), frU(fixture.ToyAlpha), frU(fixture.ToyBeta)))
	zeroed.CommitmentKeys[0].Basis[mask] = curve.G1Affine{}
	wantCode(t, m.Check(zeroed), failure.CommitmentMaskZero)

	other := sealed(t, r, commonsFor(r, frU(fixture.ToyTau), frU(fixture.ToyAlpha), frU(fixture.ToyBeta)))
	other.CommitmentKeys[0].Basis[mask-1] = curve.G1Affine{}
	if err := m.Check(other); err != nil {
		t.Fatalf("an O at a non-mask position: %v", err)
	}
}

// A key whose commitment keys do not have the circuit's shape is refused:
// the mask positions say nothing about it.
func TestCheckRefusesAKeyOfAnotherShape(t *testing.T) {
	r := compile(t, "committed", 3)
	m, err := transcript.LocateCommitmentMasks(r)
	if err != nil {
		t.Fatal(err)
	}
	pk := sealed(t, r, commonsFor(r, frU(fixture.ToyTau), frU(fixture.ToyAlpha), frU(fixture.ToyBeta)))
	short := *pk
	short.CommitmentKeys = append(short.CommitmentKeys[:0:0], pk.CommitmentKeys[0])
	short.CommitmentKeys[0].Basis = pk.CommitmentKeys[0].Basis[:len(pk.CommitmentKeys[0].Basis)-1]
	wantCode(t, m.Check(&short), failure.CommitmentMaskMissing)
	none := *pk
	none.CommitmentKeys = nil
	wantCode(t, m.Check(&none), failure.CommitmentMaskMissing)
	var notBN254 groth16.ProvingKey
	wantCode(t, m.Check(notBN254), failure.CommitmentMaskMissing)
}

// maskConstraintIndex returns the index of the committed circuit's mask
// constraint, found independently of LocateCommitmentMasks: the constraint
// whose L and O are the last committed wire alone.
func maskConstraintIndex(t *testing.T, r *cs.R1CS) int {
	t.Helper()
	committed := r.CommitmentInfo.(constraint.Groth16Commitments)[0].PrivateCommitted
	w := committed[len(committed)-1]
	i, found := 0, -1
	it := r.GetR1CIterator()
	for c := it.Next(); c != nil; c = it.Next() {
		if len(c.L) == 1 && len(c.O) == 1 && c.L[0].WireID() == w && c.O[0].WireID() == w {
			found = i
		}
		i++
	}
	if found < 0 {
		t.Fatal("no mask constraint")
	}
	return found
}
