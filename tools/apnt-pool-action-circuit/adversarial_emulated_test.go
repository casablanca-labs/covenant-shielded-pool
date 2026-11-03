package poolaction

import (
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	csbn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
)

// hintByName returns the registered gnark hint with this fully qualified name.
func hintByName(t testing.TB, hints []solver.Hint, name string) solver.Hint {
	t.Helper()
	for _, h := range hints {
		if solver.GetHintName(h) == name {
			return h
		}
	}
	protectedFatal(t, "hint %s not found", name)
	return nil
}

const mulHintName = "github.com/consensys/gnark/std/math/emulated.mulHint"

// mulProbeCircuit is a gadget-level probe, not the action circuit: Z = X·Y in
// secp256k1's base field, with the same gnark emulated field the action
// circuit uses.
type mulProbeCircuit struct {
	X, Y emulated.Element[Fp]
	Z    emulated.Element[Fp] `gnark:",public"`
}

func (c *mulProbeCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[Fp](api)
	if err != nil {
		return err
	}
	f.AssertIsEqual(f.Mul(&c.X, &c.Y), &c.Z)
	return nil
}

func limbsOf(v *big.Int, nbLimbs int, nbBits uint) ([]*big.Int, error) {
	if v.Sign() < 0 || v.BitLen() > nbLimbs*int(nbBits) {
		return nil, fmt.Errorf("%d-bit value does not fit %d limbs of %d bits", v.BitLen(), nbLimbs, nbBits)
	}
	out := make([]*big.Int, nbLimbs)
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), nbBits), big.NewInt(1))
	rest := new(big.Int).Set(v)
	for i := range out {
		out[i] = new(big.Int).And(rest, mask)
		rest.Rsh(rest, nbBits)
	}
	return out, nil
}

func recompose(l []*big.Int, nbBits uint) *big.Int {
	acc := new(big.Int)
	for i := len(l) - 1; i >= 0; i-- {
		acc.Lsh(acc, nbBits)
		acc.Add(acc, l[i])
	}
	return acc
}

func convolve(a, b []*big.Int) []*big.Int {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	out := make([]*big.Int, len(a)+len(b)-1)
	for i := range out {
		out[i] = new(big.Int)
	}
	for i := range a {
		for j := range b {
			out[i+j].Add(out[i+j], new(big.Int).Mul(a[i], b[j]))
		}
	}
	return out
}

// mulHintLayout splits a mulHint call into its parts (see emulated.mulHint).
type mulHintLayout struct {
	nbBits                uint
	p, a, b               []*big.Int
	quo, rem, carry       []*big.Int // output slices, aliased
	nbQuo, nbRem, nbCarry int
}

func parseMulHint(inputs, outputs []*big.Int) mulHintLayout {
	nbBits := uint(inputs[0].Uint64())
	nbLimbs := int(inputs[1].Int64())
	nbA := int(inputs[2].Int64())
	nbQuo := int(inputs[3].Int64())
	ptr := 4
	l := mulHintLayout{nbBits: nbBits, nbQuo: nbQuo, nbRem: nbLimbs}
	l.p = inputs[ptr : ptr+nbLimbs]
	ptr += nbLimbs
	l.a = inputs[ptr : ptr+nbA]
	ptr += nbA
	l.b = inputs[ptr:]
	l.quo = outputs[:nbQuo]
	l.rem = outputs[nbQuo : nbQuo+nbLimbs]
	l.carry = outputs[nbQuo+nbLimbs:]
	l.nbCarry = len(l.carry)
	return l
}

// carriesModQ recomputes the carry limbs so that
// a(X)·b(X) = r(X) + k(X)·p(X) + (2^w − X)·c(X) holds coefficient by
// coefficient in the native field F_q. It returns the residual of the top
// coefficient, zero exactly when (a·b − r − k·p) ≡ 0 (mod q).
func carriesModQ(q *big.Int, l mulHintLayout, rem, quo []*big.Int) *big.Int {
	lhs := convolve(l.a, l.b)
	rhs := convolve(quo, l.p)
	for i := range rem {
		if i < len(rhs) {
			rhs[i] = new(big.Int).Add(rhs[i], rem[i])
		} else {
			rhs = append(rhs, new(big.Int).Set(rem[i]))
		}
	}
	coef := func(v []*big.Int, i int) *big.Int {
		if i < len(v) {
			return v[i]
		}
		return new(big.Int)
	}
	invW := new(big.Int).ModInverse(new(big.Int).Lsh(big.NewInt(1), l.nbBits), q)
	carry := new(big.Int)
	for i := 0; i < l.nbCarry; i++ {
		d := new(big.Int).Sub(coef(lhs, i), coef(rhs, i))
		d.Add(d, carry)
		carry = d.Mul(d, invW).Mod(d, q)
		l.carry[i].Set(carry)
	}
	// top coefficient: lhs_n − rhs_n + c_{n−1} must vanish.
	top := new(big.Int).Sub(coef(lhs, l.nbCarry), coef(rhs, l.nbCarry))
	top.Add(top, carry).Mod(top, q)
	return top
}

// carryWrapMode is what a mulHint override does on the product call.
type carryWrapMode int

const (
	honestPassThrough   carryWrapMode = iota // gnark's own outputs, unchanged
	remPlusQ                                 // r' = r + q, honest carries
	remPlusQCarriesModQ                      // r' = r + q, carries recomputed in F_q
)

// TestEmulatedMulCarryWrapProbe is the regression for ENG-324's finding
// (R-333), item 1 of gnark advisory GHSA-3mvx-pp85-pm65 (unconstrained carry
// in emulated-field deferred checks, fixed in gnark v0.16.2). On a small
// gadget circuit, not the action circuit, a mulHint override returns
// r' = r + q (a different value mod p), keeps the quotient and recomputes the
// carries in F_q. gnark v0.15.0's solver accepted it. This test fails unless
// a constraint refuses it; the controls show the override fires and that an
// override returning gnark's own outputs is still satisfied.
func TestEmulatedMulCarryWrapProbe(t *testing.T) {
	defer protectedPanic(t)
	q := ecc.BN254.ScalarField()
	p := emulated.Secp256k1Fp{}.Modulus()
	ccs, err := frontend.Compile(q, r1cs.NewBuilder, &mulProbeCircuit{})
	if err != nil {
		protectedFatal(t, err)
	}
	mulHint := hintByName(t, emulated.GetHints(), mulHintName)
	x, y := big.NewInt(2), big.NewInt(3)
	honestZ := new(big.Int).Mul(x, y)
	forgedZ := new(big.Int).Add(honestZ, q)
	forgedZ.Mod(forgedZ, p)
	assign := func(z *big.Int) frontend.Circuit {
		return &mulProbeCircuit{X: emulated.ValueOf[Fp](x), Y: emulated.ValueOf[Fp](y), Z: emulated.ValueOf[Fp](z)}
	}
	solve := func(z *big.Int, opts ...solver.Option) error {
		w, err := frontend.NewWitness(assign(z), q)
		if err != nil {
			protectedFatal(t, err)
		}
		return ccs.IsSolved(w, opts...)
	}
	// override: on the product call (b is Y, not the one-limb constant 1),
	// apply mode and count the call.
	override := func(mode carryWrapMode, calls *int32) solver.Option {
		return solver.OverrideHint(solver.GetHintID(mulHint), func(field *big.Int, inputs, outputs []*big.Int) error {
			if err := mulHint(field, inputs, outputs); err != nil {
				return err
			}
			l := parseMulHint(inputs, outputs)
			if len(l.b) == 1 {
				return nil // checkZero's call
			}
			atomic.AddInt32(calls, 1)
			if mode == honestPassThrough {
				return nil
			}
			r := recompose(l.rem, l.nbBits)
			r.Add(r, q)
			rl, err := limbsOf(r, l.nbRem, l.nbBits)
			if err != nil {
				return err
			}
			for i := range rl {
				l.rem[i].Set(rl[i])
			}
			if mode == remPlusQ {
				return nil
			}
			if top := carriesModQ(field, l, l.rem, l.quo); top.Sign() != 0 {
				return fmt.Errorf("top coefficient residual %s", top)
			}
			return nil
		})
	}
	// constraintRefusal: refused by an R1C, not by a hint error.
	constraintRefusal := func(err error) bool {
		var u *csbn254.UnsatisfiedConstraintError
		return errors.As(err, &u)
	}

	if err := solve(honestZ); err != nil {
		protectedFatal(t, "control: honest Z refused: %v", err)
	}
	if err := solve(forgedZ); !constraintRefusal(err) {
		protectedFatal(t, "control: Z = xy + q with honest hints not refused by a constraint: %v", err)
	}
	var c0, c1, c2 int32
	errPass := solve(honestZ, override(honestPassThrough, &c0))
	errKeep := solve(forgedZ, override(remPlusQ, &c1))
	errWrap := solve(forgedZ, override(remPlusQCarriesModQ, &c2))
	protectedLog(t, "pass-through, honest Z:  calls=%d err=%v", c0, errPass)
	protectedLog(t, "r'=r+q, honest carries: calls=%d err=%v", c1, errKeep)
	protectedLog(t, "r'=r+q, carries mod q:  calls=%d err=%v", c2, errWrap)
	if c0 != 1 || c1 != 1 || c2 != 1 {
		protectedFatal(t, "firing control: product-call overrides fired %d, %d, %d times, want 1 each", c0, c1, c2)
	}
	if errPass != nil {
		protectedFatal(t, "firing control: pass-through override with honest Z refused: %v", errPass)
	}
	if !constraintRefusal(errKeep) {
		protectedFatal(t, "control: r' = r + q with honest carries not refused by a constraint: %v", errKeep)
	}
	if errWrap == nil {
		protectedFatal(t, "SATISFIED: Z ≡ X·Y + q (mod p) accepted by gnark's emulated Mul with carries recomputed mod q (GHSA-3mvx-pp85-pm65 item 1)")
	}
	if !constraintRefusal(errWrap) {
		protectedFatal(t, "r' = r + q with carries mod q refused, but not by a constraint: %v", errWrap)
	}
}
