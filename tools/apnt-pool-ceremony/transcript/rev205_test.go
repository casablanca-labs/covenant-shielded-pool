package transcript_test

// REV-205's probes (R-414, archive REV-205-…-evidence/tests/rev205_lookup_test.go),
// made committed negatives by IMPL-32. Each is built with gnark's own builder
// (AddInstruction), so its Levels are gnark's and the schedule replay alone
// cannot refuse it.

import (
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

// rev205Witness is x = 3, y = 9 for the probes' x·x = y.
func rev205Witness(t *testing.T) witness.Witness {
	t.Helper()
	wit, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan any, 2)
	ch <- big.NewInt(3)
	ch <- big.NewInt(9)
	close(ch)
	if err := wit.Fill(0, 2, ch); err != nil {
		t.Fatal(err)
	}
	return wit
}

// The boundary of "every other instruction whose walk touches the mask".
// gnark's lookup blueprint walks each table entry only in the first query
// that covers it; later queries reuse its cached level. So a query can read
// the mask through its table without walking it:
//
//	H0: u = InvZero(x)                  level 0
//	Q1: lookup(index 0·u) over [w]      level 1 (depends on u); walks w, unset
//	Q2: lookup(index 0·ONE) over [w]    level 0 (cached walk; w not touched)
//	R : w = Randomize()                 level 0
//	w·1 = w, x·x = y, x·1 = cw
//
// Level 0 runs H0, Q2, R in that order, so Q2 reads w before R sets it. The
// blueprint also caches entry values on the first query it executes, so Q1,
// though walked after Randomize, reads the same stale 0 (REV-205 measured
// both). The verifier accepts the file, as the README says. The negative is on
// the mask: the stale reads change the queries' outputs, never the mask, which
// Randomize still draws.
func TestRev205LookupReadBeforeRandomizeLeavesTheMaskRandom(t *testing.T) {
	r := cs.NewR1CS(4)
	r.AddPublicVariable("1")
	x := r.AddSecretVariable("x")
	y := r.AddSecretVariable("y")
	cw := r.AddInternalVariable()
	var one fr.Element
	one.SetOne()
	c1 := r.FromInterface(one)
	term := func(w int) constraint.Term { return r.MakeTerm(c1, w) }

	inv := solver.GetRegisteredHint(solver.GetHintID(solver.InvZeroHint))
	u, err := r.AddSolverHint(inv, solver.GetHintID(solver.InvZeroHint), []constraint.LinearExpression{{term(x)}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	next := func() int { a, b, c := r.GetNbVariables(); return a + b + c }
	w := next() + 2 // after Q1's and Q2's outputs
	lk := &constraint.BlueprintLookupHint[constraint.U64]{}
	constraint.Term{CID: constraint.CoeffIdOne, VID: uint32(w)}.Compress(&lk.EntriesCalldata)
	lid := r.AddBlueprint(lk)
	query := func(in constraint.Term) int {
		cd := []uint32{0, 1, 1}
		in.Compress(&cd)
		cd[0] = uint32(len(cd))
		return int(r.AddInstruction(lid, cd)[0])
	}
	o1 := query(constraint.Term{CID: constraint.CoeffIdZero, VID: uint32(u[0])})
	iQ1 := len(r.Instructions) - 1
	o2 := query(constraint.Term{CID: constraint.CoeffIdZero, VID: 0})
	iQ2 := len(r.Instructions) - 1
	out, err := r.AddSolverHint(solver.GetRegisteredHint(transcript.RandomizeHintID), transcript.RandomizeHintID, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	iR := len(r.Instructions) - 1
	if out[0] != w {
		t.Fatalf("mask wire %d, predicted %d", out[0], w)
	}
	bid := r.AddBlueprint(&constraint.BlueprintGenericR1C{})
	r1c := func(l, rr, o int) constraint.R1C {
		return constraint.R1C{L: constraint.LinearExpression{term(l)}, R: constraint.LinearExpression{term(rr)}, O: constraint.LinearExpression{term(o)}}
	}
	r.AddR1C(r1c(w, 0, w), bid)
	r.AddR1C(r1c(x, x, y), bid)
	r.AddR1C(r1c(x, 0, cw), bid)
	if err := r.AddCommitment(constraint.Groth16Commitment{PublicAndCommitmentCommitted: []int{}, PrivateCommitted: []int{w}, CommitmentIndex: cw}); err != nil {
		t.Fatal(err)
	}
	levelOf := func(i int) int {
		for l, lv := range r.Levels {
			for _, j := range lv {
				if int(j) == i {
					return l
				}
			}
		}
		return -1
	}
	// The construction must exercise the case: Q2 shares Randomize's level
	// and precedes it, Q1 is later.
	if lq2, lr, lq1 := levelOf(iQ2), levelOf(iR), levelOf(iQ1); lq2 != lr || iQ2 >= iR || lq1 <= lr {
		t.Fatalf("levels %v: Q2 at %d, Randomize at %d, Q1 at %d; the probe no longer reads the mask before Randomize", r.Levels, lq2, lr, lq1)
	}

	if _, err := transcript.LocateCommitmentMasks(r); err != nil {
		t.Fatalf("the verifier refuses the lookup probe (%v); the README's statement of the rule no longer describes it", err)
	}
	sol, err := r.Solve(rev205Witness(t))
	if err != nil {
		t.Fatalf("solve: %v", err)
	}
	W := sol.(*cs.R1CSSolution).W
	if W[w].IsZero() {
		t.Fatal("the mask is zero: Randomize did not draw it")
	}
	if !W[o2].IsZero() || !W[o1].IsZero() {
		t.Fatalf("Q2 read %s and Q1 read %s: the stale reads the README describes did not happen", W[o2].String(), W[o1].String())
	}
}

// A second setter the replay alone would accept: gnark's sparse Mul
// blueprint, which an R1CS file can decode, writes its XC unconditionally
// while its walk treats an already-set XC as an input. Placed after Randomize
// with XC = mask. IMPL-32 refuses any sparse blueprint (R1CS_SCHEDULE_INVALID);
// before it, only gnark's solver panic stopped this file. The same circuit
// without the sparse Mul is accepted, so the refusal is the blueprint's.
func TestRev205SparseMulSecondSetterRefused(t *testing.T) {
	build := func(sparse bool) *cs.R1CS {
		r := cs.NewR1CS(3)
		r.AddPublicVariable("1")
		x := r.AddSecretVariable("x")
		y := r.AddSecretVariable("y")
		cw := r.AddInternalVariable()
		var one fr.Element
		one.SetOne()
		c1 := r.FromInterface(one)
		term := func(w int) constraint.Term { return r.MakeTerm(c1, w) }
		out, err := r.AddSolverHint(solver.GetRegisteredHint(transcript.RandomizeHintID), transcript.RandomizeHintID, nil, 1)
		if err != nil {
			t.Fatal(err)
		}
		w := out[0]
		if sparse {
			mul := r.AddBlueprint(&constraint.BlueprintSparseR1CMul[constraint.U64]{})
			r.AddInstruction(mul, []uint32{uint32(x), 0, uint32(w), constraint.CoeffIdOne}) // mask := x·1
		}
		bid := r.AddBlueprint(&constraint.BlueprintGenericR1C{})
		r1c := func(l, rr, o int) constraint.R1C {
			return constraint.R1C{L: constraint.LinearExpression{term(l)}, R: constraint.LinearExpression{term(rr)}, O: constraint.LinearExpression{term(o)}}
		}
		r.AddR1C(r1c(w, 0, w), bid)
		r.AddR1C(r1c(x, x, y), bid)
		r.AddR1C(r1c(x, 0, cw), bid)
		if err := r.AddCommitment(constraint.Groth16Commitment{PublicAndCommitmentCommitted: []int{}, PrivateCommitted: []int{w}, CommitmentIndex: cw}); err != nil {
			t.Fatal(err)
		}
		return r
	}

	if _, err := transcript.LocateCommitmentMasks(build(false)); err != nil {
		t.Fatalf("positive control refused: %v", err)
	}
	r := build(true)
	_, err := transcript.LocateCommitmentMasks(r)
	if failure.CodeOf(err) != failure.R1CSScheduleInvalid || !strings.Contains(err.Error(), "sparse") {
		t.Fatalf("a sparse Mul second setter of the mask: %v, want %s naming the sparse blueprint", err, failure.R1CSScheduleInvalid)
	}

	// gnark's solver, the backstop before IMPL-32, still panics on it.
	defer func() {
		if p := recover(); p == nil {
			t.Fatal("gnark's solver did not panic on the second setter")
		}
	}()
	_, err = r.Solve(rev205Witness(t))
	t.Fatalf("solve returned %v without a panic", err)
}
