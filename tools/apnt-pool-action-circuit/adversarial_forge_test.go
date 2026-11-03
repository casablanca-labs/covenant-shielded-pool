package poolaction

import (
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/bitslice"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/rangecheck"
)

// honestHint returns gnark's own hint function with this name.
func honestHint(name string) (solver.Hint, error) {
	lists := [][]solver.Hint{
		sw_emulated.GetHints(), emulated.GetHints(), uints.GetHints(), bitslice.GetHints(), bits.GetHints(),
		{solver.InvZeroHint, rangecheck.DecomposeHint},
	}
	for _, l := range lists {
		for _, h := range l {
			if solver.GetHintName(h) == name {
				return h, nil
			}
		}
	}
	return nil, fmt.Errorf("no honest hint %s", name)
}

func mulHintFn() solver.Hint {
	h, err := honestHint(mulHintName)
	if err != nil {
		panic(err)
	}
	return h
}

// callSet selects hint calls by their index in solve order.
func callSet(ks ...int64) func(int64) bool {
	set := map[int64]bool{}
	for _, k := range ks {
		set[k] = true
	}
	return func(k int64) bool { return set[k] }
}

func everyCall(int64) bool { return true }

// differs reports whether any output differs from the honest one, mod q.
func differs(honest, out []*big.Int) bool {
	for i := range out {
		if modQ(out[i]).Cmp(modQ(honest[i])) != 0 {
			return true
		}
	}
	return false
}

func snapshot(out []*big.Int) []*big.Int {
	c := make([]*big.Int, len(out))
	for i := range out {
		c[i] = new(big.Int).Set(out[i])
	}
	return c
}

// forgeAfter runs the honest hint, then mutate on the calls target selects.
// forged counts the calls whose outputs the mutation actually changed.
func forgeAfter(honest solver.Hint, target func(int64) bool, forged *int64, mutate func(in, out []*big.Int) error) solver.Hint {
	var calls int64
	return func(m *big.Int, in, out []*big.Int) error {
		if err := honest(m, in, out); err != nil {
			return err
		}
		if k := atomic.AddInt64(&calls, 1) - 1; target(k) {
			before := snapshot(out)
			if err := mutate(in, out); err != nil {
				return err
			}
			if differs(before, out) {
				atomic.AddInt64(forged, 1)
			}
		}
		return nil
	}
}

// forgeInstead answers the calls target selects with forge, the others
// honestly. forged counts the calls whose answer differs from the honest one.
func forgeInstead(honest solver.Hint, target func(int64) bool, forged *int64, forge solver.Hint) solver.Hint {
	var calls int64
	return func(m *big.Int, in, out []*big.Int) error {
		if k := atomic.AddInt64(&calls, 1) - 1; target(k) {
			if err := honest(m, in, out); err != nil {
				return err
			}
			before := snapshot(out)
			if err := forge(m, in, out); err != nil {
				return err
			}
			if differs(before, out) {
				atomic.AddInt64(forged, 1)
			}
			return nil
		}
		return honest(m, in, out)
	}
}

// ---- ScalarMulBase: the comb recoding ----

type recodeForgery int

const (
	recodeB0Flip      recodeForgery = iota // parity bit flipped, digits kept
	recodePlusOne                          // a consistent recoding of s + 1
	recodeNegated                          // a consistent recoding of n − s (rk's y flips)
	recodeNonBoolean                       // digits 0,1 → 2,0 at one place: 2c + b0 kept
	recodeAlternative                      // 2c + b0 = s + 2^n − n: the same scalar mod n
)

// recodeHint answers combRecodeHint with the chosen recoding. The circuit
// pins 2c + b0 ≡ s + 2^n (mod n) and asserts every digit boolean; the honest
// recoding has 2c + b0 = s + 2^n over the integers.
func recodeHint(kind recodeForgery) solver.Hint {
	return func(_ *big.Int, in, out []*big.Int) error {
		return emulated.UnwrapHintWithNativeOutput(in, out, func(n *big.Int, ein, nout []*big.Int) error {
			digits := len(nout) - 1
			s := new(big.Int).Mod(ein[0], n)
			twoN := new(big.Int).Lsh(big.NewInt(1), uint(digits))
			set := func(v *big.Int) { // v = 2c + b0
				nout[0].SetUint64(uint64(v.Bit(0)))
				for i := 0; i < digits; i++ {
					nout[1+i].SetUint64(uint64(v.Bit(i + 1)))
				}
			}
			switch kind {
			case recodeB0Flip:
				set(new(big.Int).Add(s, twoN))
				nout[0].SetUint64(1 - nout[0].Uint64())
			case recodePlusOne:
				s1 := new(big.Int).Add(s, big.NewInt(1))
				set(s1.Mod(s1, n).Add(s1, twoN))
			case recodeNegated:
				sn := new(big.Int).Sub(n, s)
				set(sn.Mod(sn, n).Add(sn, twoN))
			case recodeNonBoolean:
				set(new(big.Int).Add(s, twoN))
				for i := 1; i < digits; i++ {
					if nout[i].Sign() == 0 && nout[i+1].Sign() != 0 {
						nout[i].SetUint64(2)
						nout[i+1].SetUint64(0)
						return nil
					}
				}
				return errors.New("no 0,1 digit pair")
			case recodeAlternative:
				v := new(big.Int).Add(s, twoN)
				set(v.Sub(v, n))
			}
			return nil
		})
	}
}

// ---- slopes: the comb chain and the unified addition ----

type slopeForgery int

const (
	slopePlusOne slopeForgery = iota // λ + 1
	slopeNegated                     // −λ
	slopeOther                       // the chain: the chord to −T; unified: the tangent at p
	slopePlusQ                       // λ ± q: another value mod p, for a carries-mod-q forgery
)

func forgedSlope(kind slopeForgery, p, lam, other *big.Int) (*big.Int, error) {
	switch kind {
	case slopePlusOne:
		v := new(big.Int).Add(lam, big.NewInt(1))
		return v.Mod(v, p), nil
	case slopeNegated:
		v := new(big.Int).Neg(lam)
		return v.Mod(v, p), nil
	case slopeOther:
		return other, nil
	case slopePlusQ:
		v := new(big.Int).Add(lam, nativeQ)
		if v.BitLen() <= 256 {
			return v, nil
		}
		v.Sub(lam, nativeQ)
		if v.Sign() < 0 {
			return nil, errors.New("neither λ + q nor λ − q is a 256-bit value")
		}
		return v, nil
	}
	return nil, errors.New("unknown slope forgery")
}

func modInv(v, p *big.Int) (*big.Int, error) {
	d := new(big.Int).Mod(v, p)
	if d.Sign() == 0 {
		return nil, errors.New("zero denominator")
	}
	return d.ModInverse(d, p), nil
}

// combLambdaHint answers combChainLambdaHint with a forged slope. Inputs
// λprev, x, xTprev, yTprev, xT, yT; the accumulator's y is implicit,
// y = λprev·(xTprev − x) − yTprev, and the honest slope is (yT − y)/(xT − x).
func combLambdaHint(kind slopeForgery) solver.Hint {
	return func(_ *big.Int, in, out []*big.Int) error {
		return emulated.UnwrapHint(in, out, func(p *big.Int, ein, eout []*big.Int) error {
			lamPrev, x, xTPrev, yTPrev, xT, yT := ein[0], ein[1], ein[2], ein[3], ein[4], ein[5]
			y := new(big.Int).Sub(xTPrev, x)
			y.Mul(y, lamPrev).Sub(y, yTPrev).Mod(y, p)
			inv, err := modInv(new(big.Int).Sub(xT, x), p)
			if err != nil {
				return err
			}
			lam := new(big.Int).Sub(yT, y)
			lam.Mul(lam, inv).Mod(lam, p)
			other := new(big.Int).Neg(yT)
			other.Sub(other, y).Mul(other, inv).Mod(other, p)
			v, err := forgedSlope(kind, p, lam, other)
			if err != nil {
				return err
			}
			eout[0].Set(v)
			return nil
		})
	}
}

// unifiedSlopeForge answers unifiedSlopeHint with a forged slope for a
// chord call (x1 ≠ x2) and honestly otherwise. Inputs x1, y1, x2, y2.
func unifiedSlopeForge(kind slopeForgery, honest solver.Hint) solver.Hint {
	return func(m *big.Int, in, out []*big.Int) error {
		if err := honest(m, in, out); err != nil {
			return err
		}
		return emulated.UnwrapHint(in, out, func(p *big.Int, ein, eout []*big.Int) error {
			x1, y1, x2, y2 := ein[0], ein[1], ein[2], ein[3]
			var lam, other *big.Int
			if new(big.Int).Sub(x2, x1).Mod(new(big.Int).Sub(x2, x1), p).Sign() == 0 {
				// doubling: the honest slope is the tangent; the other is the
				// chord's value 0 (a dummy denominator would make it 0)
				inv, err := modInv(new(big.Int).Lsh(y1, 1), p)
				if err != nil {
					return err
				}
				lam = new(big.Int).Mul(x1, x1)
				lam.Mul(lam, big.NewInt(3)).Mul(lam, inv).Mod(lam, p)
				other = new(big.Int)
			} else {
				inv, err := modInv(new(big.Int).Sub(x2, x1), p)
				if err != nil {
					return err
				}
				lam = new(big.Int).Sub(y2, y1)
				lam.Mul(lam, inv).Mod(lam, p)
				tinv, err := modInv(new(big.Int).Lsh(y1, 1), p)
				if err != nil {
					return err
				}
				other = new(big.Int).Mul(x1, x1)
				other.Mul(other, big.NewInt(3)).Mul(other, tinv).Mod(other, p)
			}
			v, err := forgedSlope(kind, p, lam, other)
			if err != nil {
				return err
			}
			eout[0].Set(v)
			return nil
		})
	}
}

// ---- api.IsZero ----

type invZeroForgery int

const (
	invZeroClaimsZero   invZeroForgery = iota // a ≠ 0: return 0, so IsZero would read 1
	invZeroWrongInverse                       // a ≠ 0: return 2/a
	invZeroFreeWitness                        // a = 0: return 1 (the output stays 1 whatever this is)
)

// invZeroHint answers InvZeroHint. target selects, by index among calls
// with a ≠ 0 (a = 0 for the free-witness mode), which calls are forged.
func invZeroHint(kind invZeroForgery, target func(int64) bool, forged, eligible *int64) solver.Hint {
	return func(q *big.Int, in, out []*big.Int) error {
		if err := solver.InvZeroHint(q, in, out); err != nil {
			return err
		}
		a := modQ(in[0])
		if (kind == invZeroFreeWitness) != (a.Sign() == 0) {
			return nil
		}
		k := atomic.AddInt64(eligible, 1) - 1
		if !target(k) {
			return nil
		}
		atomic.AddInt64(forged, 1)
		switch kind {
		case invZeroClaimsZero:
			out[0].SetUint64(0)
		case invZeroWrongInverse:
			out[0].Lsh(out[0], 1)
		case invZeroFreeWitness:
			out[0].SetUint64(1)
		}
		return nil
	}
}

// ---- uints byte operations (advisory item 8) ----

type byteForgery int

const (
	byteFlip  byteForgery = iota // z ⊕ 1: a byte, and a key not in the table
	byteAlias                    // z' with x + 2^8·y + 2^16·z' = another table row's key
)

// byteOpMutate forges a xorHint/andHint output. The table row for (x, y) is
// x + 2^8·y + 2^16·f(x, y). The alias takes the row of (x, y ± 1) and solves
// for z' in F_q: z' = f(x, y ± 1) ± 2^{-8}, the advisory's Xor(1,0) = 1/256.
func byteOpMutate(kind byteForgery, op func(x, y uint64) uint64) func(in, out []*big.Int) error {
	return func(in, out []*big.Int) error {
		x, y := in[0].Uint64(), in[1].Uint64()
		switch kind {
		case byteFlip:
			out[0].SetUint64(out[0].Uint64() ^ 1)
		case byteAlias:
			y2 := y + 1
			if y == 255 {
				y2 = y - 1
			}
			key := new(big.Int).SetUint64(x + 256*y2 + 65536*op(x, y2))
			key.Sub(key, new(big.Int).SetUint64(x+256*y))
			key.Mul(key, new(big.Int).ModInverse(big.NewInt(65536), nativeQ))
			out[0].Set(modQ(key))
		}
		return nil
	}
}

func xorOp(x, y uint64) uint64 { return x ^ y }
func andOp(x, y uint64) uint64 { return x & y }

// ---- bitslice.Partition, uints toBytes, bits.ToBinary ----

// partitionShift moves 2^split from lower into upper: v = lower + 2^split·upper
// still holds, lower is negative.
func partitionShift(in, out []*big.Int) error {
	split := uint(in[0].Uint64())
	out[0].Add(out[0], big.NewInt(1))
	out[1].Sub(out[1], new(big.Int).Lsh(big.NewInt(1), split))
	out[1].Set(modQ(out[1]))
	return nil
}

// toBytesCarry moves 256 from byte 1 into byte 0: the value recomposes, byte
// 0 is not a byte.
func toBytesCarry(_, out []*big.Int) error {
	if len(out) < 2 {
		return errors.New("one-byte value")
	}
	out[0].Add(out[0], big.NewInt(256))
	out[1].Set(modQ(new(big.Int).Sub(out[1], big.NewInt(1))))
	return nil
}

// nBitsFlip flips bit 0: the recomposition no longer holds.
func nBitsFlip(_, out []*big.Int) error {
	out[0].SetUint64(out[0].Uint64() ^ 1)
	return nil
}

// nBitsNonBoolean turns bits 0,1 at one place into 2,0: the recomposition
// holds, one "bit" is 2.
func nBitsNonBoolean(_, out []*big.Int) error {
	for i := 0; i+1 < len(out); i++ {
		if out[i].Sign() == 0 && out[i+1].Sign() != 0 {
			out[i].SetUint64(2)
			out[i+1].SetUint64(0)
			return nil
		}
	}
	return errors.New("no 0,1 bit pair")
}

// ---- rangecheck.DecomposeHint ----

type decomposeForgery int

const (
	decomposeAlias   decomposeForgery = iota // l0 + 2^k, l1 − 1: same value, l0 outside the table
	decomposePlusOne                         // l0 + 1: the recomposition no longer holds
)

// decomposeForge is the exact DecomposeHint, with the calls target selects
// (by index among calls with at least two limbs, for the alias) forged.
func decomposeForge(kind decomposeForgery, target func(int64) bool, forged *int64) solver.Hint {
	var multi int64
	return func(_ *big.Int, in, out []*big.Int) error {
		if err := decomposeLimbs(decomposeExact, in, out); err != nil {
			return err
		}
		if kind == decomposeAlias && len(out) < 2 {
			return nil
		}
		if !target(atomic.AddInt64(&multi, 1) - 1) {
			return nil
		}
		atomic.AddInt64(forged, 1)
		k := uint(in[1].Uint64())
		switch kind {
		case decomposeAlias:
			out[0].Add(out[0], new(big.Int).Lsh(big.NewInt(1), k))
			out[1].Set(modQ(new(big.Int).Sub(out[1], big.NewInt(1))))
		case decomposePlusOne:
			out[0].Add(out[0], big.NewInt(1))
		}
		return nil
	}
}

// ---- logderivarg countHint ----

// countShift is the tolerant countHint with, on the calls target selects,
// one multiplicity moved from a used table row to the next row: the sum of
// multiplicities is kept, the rows they name are not.
func countShift(target func(int64) bool, forged, unmatched *int64) solver.Hint {
	inner := tolerantCount(unmatched)
	var calls int64
	return func(m *big.Int, in, out []*big.Int) error {
		if err := inner(m, in, out); err != nil {
			return err
		}
		if !target(atomic.AddInt64(&calls, 1) - 1) {
			return nil
		}
		for i := range out {
			if out[i].Sign() != 0 {
				j := (i + 1) % len(out)
				out[i].Sub(out[i], big.NewInt(1))
				out[j].Add(out[j], big.NewInt(1))
				atomic.AddInt64(forged, 1)
				return nil
			}
		}
		return errors.New("no used table row")
	}
}
