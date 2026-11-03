package poolaction

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	csbn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
)

// xorProbeCircuit is a gadget-level probe, not the action circuit: Z is
// Xor(X, Y) with the same gnark uints gadget SHA-256 and the packet's pad
// xors use in the action circuit.
type xorProbeCircuit struct {
	X, Y frontend.Variable
	Z    frontend.Variable `gnark:",public"`
}

func (c *xorProbeCircuit) Define(api frontend.API) error {
	b, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	z := b.Xor(b.ValueOf(c.X), b.ValueOf(c.Y))
	api.AssertIsEqual(b.ValueUnchecked(z), c.Z)
	return nil
}

// TestUintsXorResultAliasRegression is the regression for item 8 of gnark
// advisory GHSA-3mvx-pp85-pm65 (ENG-370): the log-derivative lookup behind
// uints.Xor constrains only the packed key x + 2^8·y + 2^16·z, so without a
// range check on z a prover can answer Xor(1, 0) with z = 1/256, whose key is
// 257, the table row of Xor(1, 1) = 0. gnark v0.16.2+ range-checks every
// result. On this gadget circuit the forged public Z = 1/256 must be refused
// by a constraint: with gnark's DecomposeHint by the range check's
// recomposition, and with an exact DecomposeHint and a tolerant countHint (the
// stronger adversary) by the log-derivative argument over the range table.
func TestUintsXorResultAliasRegression(t *testing.T) {
	defer protectedPanic(t)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &xorProbeCircuit{})
	if err != nil {
		protectedFatal(t, err)
	}
	r := ccs.(*csbn254.R1CS)
	h := newHintHarness(t, r)
	if !h.has(hintXor) {
		protectedFatal(t, "the probe does not call xorHint")
	}
	inv256 := new(big.Int).ModInverse(big.NewInt(256), nativeQ)
	assign := func(z *big.Int) frontend.Circuit {
		return &xorProbeCircuit{X: 1, Y: 0, Z: z}
	}
	alias := func(forged *int64) solver.Hint {
		return forgeAfter(mustHonest(t, hintXor), everyCall, forged, byteOpMutate(byteAlias, xorOp))
	}
	passThrough := func(forged *int64) solver.Hint {
		return forgeAfter(mustHonest(t, hintXor), everyCall, forged, func(_, _ []*big.Int) error { return nil })
	}
	// the alias of Xor(1, 0) is exactly the advisory's 1/256
	var probe [2]*big.Int
	probe[0], probe[1] = big.NewInt(1), big.NewInt(0)
	out := []*big.Int{big.NewInt(1)}
	if err := byteOpMutate(byteAlias, xorOp)(probe[:], out); err != nil || out[0].Cmp(inv256) != 0 {
		protectedFatal(t, "alias of Xor(1,0) is %v, want 1/256", out[0])
	}

	type tc struct {
		name   string
		z      *big.Int
		adv    func(*int64) adversary
		expect string
		forges bool // the override changes the xor call's answer
	}
	cases := []tc{
		{"honest Z = 1", big.NewInt(1), func(*int64) adversary { return adversary{} }, gotSatisfied, false},
		{"forged Z = 1/256, honest hints", inv256, func(*int64) adversary { return adversary{} }, gotConstraint, false},
		{"pass-through xorHint, honest Z", big.NewInt(1), func(f *int64) adversary {
			return adversary{hints: map[string]solver.Hint{hintXor: passThrough(f)}, layer: true}
		}, gotSatisfied, false},
		{"alias z' = 1/256, gnark's DecomposeHint and countHint", inv256, func(f *int64) adversary {
			return adversary{hints: map[string]solver.Hint{hintXor: alias(f)}}
		}, gotConstraint, true},
		{"alias z' = 1/256, exact DecomposeHint, tolerant countHint", inv256, func(f *int64) adversary {
			return adversary{hints: map[string]solver.Hint{hintXor: alias(f)}, layer: true}
		}, gotConstraint, true},
	}
	protectedLog(t, "probe circuit: %d constraints", r.GetNbConstraints())
	for _, c := range cases {
		var forged int64
		v, fired, unm, _, _ := h.solve(assign(c.z), c.adv(&forged))
		protectedLog(t, "%-58s %-22s cid=%-3d xor calls=%d forgedCalls=%d unmatched=%d %s", c.name, v.Got, v.CID, fired[hintXor], forged, unm, clip(v.Message, 100))
		if v.Got != c.expect {
			protectedError(t, "%s: expected %s, got %s: %s", c.name, c.expect, v.Got, v.Message)
		}
		if _, overridden := fired[hintXor]; overridden && fired[hintXor] != 1 {
			protectedError(t, "%s: firing control: xorHint override ran on %d calls, want 1", c.name, fired[hintXor])
		}
		if want := map[bool]int64{true: 1, false: 0}[c.forges]; forged != want {
			protectedError(t, "%s: %d xor calls forged, want %d", c.name, forged, want)
		}
	}
}

func mustHonest(t testing.TB, name string) solver.Hint {
	t.Helper()
	f, err := honestHint(name)
	if err != nil {
		protectedFatal(t, err)
	}
	return f
}
