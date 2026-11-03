package fixture

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

// Hand-built R1CS files for negative controls of the BSB22 mask check. Each
// has three constraints (domain 4), one commitment and no witness solver.
// Nobody proves with them.

// handR1CS starts an R1CS with the constant-one wire 0, the given secret
// wires (1, 2, …) and one internal wire for the commitment, and returns the
// generic R1C blueprint and a term builder.
func handR1CS(secrets ...string) (r *cs.R1CS, commitWire int, bid constraint.BlueprintID, term func(c fr.Element, wire int) constraint.Term) {
	r = cs.NewR1CS(3)
	r.AddPublicVariable("1")
	for _, s := range secrets {
		r.AddSecretVariable(s)
	}
	commitWire = r.AddInternalVariable()
	bid = r.AddBlueprint(&constraint.BlueprintGenericR1C{})
	term = func(c fr.Element, wire int) constraint.Term { return r.MakeTerm(r.FromInterface(c), wire) }
	return r, commitWire, bid, term
}

func r1c(l, rr, o constraint.Term) constraint.R1C {
	return constraint.R1C{L: constraint.LinearExpression{l}, R: constraint.LinearExpression{rr}, O: constraint.LinearExpression{o}}
}

// hintWire adds a hint instruction with the given id, the given input wires
// and one output wire, as gnark's Commit adds its Randomize call, and returns
// the output wire. fn is the function gnark registers under id.
func hintWire(r *cs.R1CS, id solver.HintID, inputs ...int) int {
	fn := solver.GetRegisteredHint(id)
	if fn == nil {
		panic("no hint registered under the id")
	}
	var in []constraint.LinearExpression
	var o fr.Element
	o.SetOne()
	for _, w := range inputs {
		in = append(in, constraint.LinearExpression{r.MakeTerm(r.FromInterface(o), w)})
	}
	out, err := r.AddSolverHint(fn, id, in, 1)
	if err != nil {
		panic(err)
	}
	return out[0]
}

// MaskCancelledR1CS commits to two wires, x (3) and m (4), each the output
// of gnark's Randomize hint with no input and each with the constraint
// w·1 = w, as gnark's Commit makes its mask; y (1) is a secret input:
//
//	0: x·1 = x      1: y·1 = k·x      2: m·1 = m
//
// Wire x's basis element is (β+1)·L₀(τ) + k·L₁(τ) (γ = 1), and k is chosen
// to cancel it on the toy phase 1 (ToyTau, ToyBeta): k = −(β+1)·L₀(τ)/L₁(τ).
// So a key sealed on that phase 1, whose τ and β are not degenerate, has an O
// basis element at a mask position (committed position 0). m is an ordinary
// mask whose basis element is not O. The same circuit sealed on any other
// phase 1 has x's element non-zero unless that τ and β cancel it too.
func MaskCancelledR1CS() *cs.R1CS {
	r, cw, bid, term := handR1CS("y")
	const one, y = 0, 1
	x := hintWire(r, transcript.RandomizeHintID)
	m := hintWire(r, transcript.RandomizeHintID)
	var o fr.Element
	o.SetOne()
	r.AddR1C(r1c(term(o, x), term(o, one), term(o, x)), bid)
	r.AddR1C(r1c(term(o, y), term(o, one), term(CancellingCoefficient(4, ToyTau, ToyBeta), x)), bid)
	r.AddR1C(r1c(term(o, m), term(o, one), term(o, m)), bid)
	if err := r.AddCommitment(constraint.Groth16Commitment{PublicAndCommitmentCommitted: []int{}, PrivateCommitted: []int{x, m}, CommitmentIndex: cw}); err != nil {
		panic(err)
	}
	return r
}

// CancellingCoefficient returns k = −(β+1)·L₀(τ)/L₁(τ) for the Lagrange
// basis of gnark's FFT domain of size n, where constraint i is evaluated at
// ωⁱ: Lᵢ(τ) = (ωⁱ/n)·(τⁿ − 1)/(τ − ωⁱ), so L₀(τ)/L₁(τ) = (τ − ω)/(ω·(τ − 1)).
func CancellingCoefficient(n uint64, tau, beta uint64) fr.Element {
	var t, b, w, num, den, k fr.Element
	t.SetUint64(tau)
	b.SetUint64(beta)
	w = fft.NewDomain(n).Generator
	num.Sub(&t, &w)
	var one fr.Element
	one.SetOne()
	den.Sub(&t, &one)
	den.Mul(&den, &w)
	k.Div(&num, &den)
	b.Add(&b, &one)
	k.Mul(&k, &b)
	k.Neg(&k)
	return k
}

// MaskFromHintR1CS commits to one wire h, with the constraint h·1 = h, where
// h is the output of the hint registered under id, called on the given input
// wires (the secret input x is wire 1, y wire 2): the mask's constraint shape
// on a wire of any provenance.
//
//	0: x·x = y      1: h·1 = h      2: y·1 = y
func MaskFromHintR1CS(id solver.HintID, inputs ...int) *cs.R1CS {
	r, cw, bid, term := handR1CS("x", "y")
	const one, x, y = 0, 1, 2
	h := hintWire(r, id, inputs...)
	var o fr.Element
	o.SetOne()
	r.AddR1C(r1c(term(o, x), term(o, x), term(o, y)), bid)
	r.AddR1C(r1c(term(o, h), term(o, one), term(o, h)), bid)
	r.AddR1C(r1c(term(o, y), term(o, one), term(o, y)), bid)
	if err := r.AddCommitment(constraint.Groth16Commitment{PublicAndCommitmentCommitted: []int{}, PrivateCommitted: []int{h}, CommitmentIndex: cw}); err != nil {
		panic(err)
	}
	return r
}

// MaskReadEarlyR1CS is MaskFromHintR1CS with gnark's Randomize, plus a hint
// (InvZero) added before the Randomize call that takes the mask wire, not
// yet created, as its input. gnark's builder puts both hints in level 0, so
// the solver can run the reader before Randomize has set the mask. Its
// schedule is the one gnark derives from its instructions.
func MaskReadEarlyR1CS() *cs.R1CS {
	r, cw, bid, term := handR1CS("x", "y")
	const one, x, y = 0, 1, 2
	const mask = 5 // after the commitment wire (3) and the reader's output (4)
	hintWire(r, solver.GetHintID(solver.InvZeroHint), mask)
	if h := hintWire(r, transcript.RandomizeHintID); h != mask {
		panic("unexpected mask wire")
	}
	var o fr.Element
	o.SetOne()
	r.AddR1C(r1c(term(o, x), term(o, x), term(o, y)), bid)
	r.AddR1C(r1c(term(o, mask), term(o, one), term(o, mask)), bid)
	r.AddR1C(r1c(term(o, y), term(o, one), term(o, y)), bid)
	if err := r.AddCommitment(constraint.Groth16Commitment{PublicAndCommitmentCommitted: []int{}, PrivateCommitted: []int{mask}, CommitmentIndex: cw}); err != nil {
		panic(err)
	}
	return r
}

// MaskSetEarlyR1CS is MaskFromHintR1CS with gnark's Randomize, plus an R1C
// x·1 = mask added before the Randomize call, when the mask wire does not yet
// exist. gnark's builder then skips the wire; its solver would solve the mask
// from x in level 0 and then panic when Randomize sets it again.
func MaskSetEarlyR1CS() *cs.R1CS {
	r, cw, bid, term := handR1CS("x", "y")
	const one, x, y = 0, 1, 2
	const mask = 4 // after the commitment wire (3)
	var o fr.Element
	o.SetOne()
	r.AddR1C(r1c(term(o, x), term(o, one), term(o, mask)), bid)
	if h := hintWire(r, transcript.RandomizeHintID); h != mask {
		panic("unexpected mask wire")
	}
	r.AddR1C(r1c(term(o, mask), term(o, one), term(o, mask)), bid)
	r.AddR1C(r1c(term(o, x), term(o, x), term(o, y)), bid)
	if err := r.AddCommitment(constraint.Groth16Commitment{PublicAndCommitmentCommitted: []int{}, PrivateCommitted: []int{mask}, CommitmentIndex: cw}); err != nil {
		panic(err)
	}
	return r
}

// UnmaskedR1CS commits to one secret wire x and has no committed wire with
// a constraint w·1 = w (y has one but is not committed):
//
//	0: x·x = y      1: y·1 = y      2: x·1 = 2·x
func UnmaskedR1CS() *cs.R1CS {
	r, cw, bid, term := handR1CS("x", "y")
	const one, x, y = 0, 1, 2
	var o, two fr.Element
	o.SetOne()
	two.SetUint64(2)
	r.AddR1C(r1c(term(o, x), term(o, x), term(o, y)), bid)
	r.AddR1C(r1c(term(o, y), term(o, one), term(o, y)), bid)
	r.AddR1C(r1c(term(o, x), term(o, one), term(two, x)), bid)
	if err := r.AddCommitment(constraint.Groth16Commitment{PublicAndCommitmentCommitted: []int{}, PrivateCommitted: []int{x}, CommitmentIndex: cw}); err != nil {
		panic(err)
	}
	return r
}
