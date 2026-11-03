package poolaction

import (
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"

	"github.com/consensys/gnark/constraint/solver"
)

// Adversarial versions of gnark v0.16.3's emulated-arithmetic hints. The
// deferred check of a multiplication or a multivariate evaluation is the
// polynomial identity
//
//	L(X) = R(X) + s·K(X)·P(X) + (2^t − X)·C(X)
//
// at one committed random point, over F_q; a·b (or the evaluated polynomial)
// is L, the remainder R, the quotient K with sign s, the carries C. With the
// carries free, the identity holds for any R, K whose integer residue
// L(2^t) − R(2^t) − s·K(2^t)·P(2^t) is 0 mod q, not 0: advisory
// GHSA-3mvx-pp85-pm65 item 1. gnark v0.16.2+ range-checks the low carries (a
// CRT certificate). The "wrap" modes below build exactly that coordinated
// forgery: a value ≢ the honest one mod p, with carries recomputed mod q.

// polyMvCall is one polyMvHint call, parsed as polyMvHint parses it.
type polyMvCall struct {
	nbBits                         uint
	nbLimbs, nbQuo, nbRem, nbCarry int
	signs                          []int
	terms                          [][]int
	coeffs                         []*big.Int
	p                              *big.Int
	pLimbs                         []*big.Int
	varLimbs                       [][]*big.Int
	vars                           []*big.Int
	quoOut, remOut, carryOut       []*big.Int
	kNegOut                        *big.Int
	lhsFull                        *big.Int   // the evaluated polynomial over the integers
	lhsCoef                        []*big.Int // its limb coefficients (signed)
}

func parsePolyMv(inputs, outputs []*big.Int) (*polyMvCall, error) {
	if len(inputs) < 8 {
		return nil, errors.New("not enough inputs")
	}
	c := &polyMvCall{
		nbBits:  uint(inputs[0].Int64()),
		nbLimbs: int(inputs[1].Int64()),
		nbQuo:   int(inputs[4].Int64()),
		nbRem:   int(inputs[5].Int64()),
		nbCarry: int(inputs[6].Int64()),
	}
	nbTerms, nbVars := int(inputs[2].Int64()), int(inputs[3].Int64())
	if len(outputs) != c.nbQuo+c.nbRem+c.nbCarry+1 {
		return nil, errors.New("output length mismatch")
	}
	c.quoOut = outputs[:c.nbQuo]
	c.remOut = outputs[c.nbQuo : c.nbQuo+c.nbRem]
	c.carryOut = outputs[c.nbQuo+c.nbRem : c.nbQuo+c.nbRem+c.nbCarry]
	c.kNegOut = outputs[c.nbQuo+c.nbRem+c.nbCarry]
	ptr := 7
	c.signs = make([]int, nbTerms)
	for i := range c.signs {
		c.signs[i] = int(inputs[ptr].Int64())
		ptr++
	}
	c.terms = make([][]int, nbTerms)
	for i := range c.terms {
		c.terms[i] = make([]int, nbVars)
		for j := range c.terms[i] {
			c.terms[i][j] = int(inputs[ptr].Int64())
			ptr++
		}
	}
	c.coeffs = make([]*big.Int, nbTerms)
	for i := range c.coeffs {
		c.coeffs[i] = inputs[ptr]
		ptr++
	}
	c.pLimbs = inputs[ptr : ptr+c.nbLimbs]
	ptr += c.nbLimbs
	c.p = recompose(c.pLimbs, c.nbBits)
	c.varLimbs = make([][]*big.Int, nbVars)
	c.vars = make([]*big.Int, nbVars)
	for i := range c.varLimbs {
		n := int(inputs[ptr].Int64())
		ptr++
		c.varLimbs[i] = inputs[ptr : ptr+n]
		ptr += n
		c.vars[i] = recompose(c.varLimbs[i], c.nbBits)
	}
	if ptr != len(inputs) {
		return nil, errors.New("inputs not exhausted")
	}
	c.lhsFull = new(big.Int)
	for i, term := range c.terms {
		v := new(big.Int).Set(c.coeffs[i])
		poly := []*big.Int{new(big.Int).Set(c.coeffs[i])}
		for j, pow := range term {
			for k := 0; k < pow; k++ {
				v.Mul(v, c.vars[j])
				poly = convolve(poly, c.varLimbs[j])
			}
		}
		for len(c.lhsCoef) < len(poly) {
			c.lhsCoef = append(c.lhsCoef, new(big.Int))
		}
		if c.signs[i] != 0 {
			c.lhsFull.Sub(c.lhsFull, v)
			for k := range poly {
				c.lhsCoef[k].Sub(c.lhsCoef[k], poly[k])
			}
		} else {
			c.lhsFull.Add(c.lhsFull, v)
			for k := range poly {
				c.lhsCoef[k].Add(c.lhsCoef[k], poly[k])
			}
		}
	}
	return c, nil
}

// residualCoefficients returns L − R − s·K·P, coefficient by coefficient.
func (c *polyMvCall) residualCoefficients(rem, quo []*big.Int, neg bool) []*big.Int {
	kp := convolve(quo, c.pLimbs)
	n := max(len(c.lhsCoef), len(kp), len(rem))
	d := make([]*big.Int, n)
	for i := range d {
		d[i] = new(big.Int)
		if i < len(c.lhsCoef) {
			d[i].Add(d[i], c.lhsCoef[i])
		}
		if i < len(rem) {
			d[i].Sub(d[i], rem[i])
		}
		if i < len(kp) {
			if neg {
				d[i].Add(d[i], kp[i])
			} else {
				d[i].Sub(d[i], kp[i])
			}
		}
	}
	return d
}

// integerCarries sets the carries as polyMvHint does: floor division of the
// running residual by 2^t. They are the honest carries when the identity
// holds over the integers, and some integers when it does not.
func integerCarries(d []*big.Int, nbBits uint, out []*big.Int) {
	carry := new(big.Int)
	for i := range out {
		if i < len(d) {
			carry.Add(carry, d[i])
		}
		carry.Rsh(carry, nbBits)
		out[i].Set(carry)
	}
}

// carriesModQCoef sets the carries so that every coefficient of
// d(X) = (2^t − X)·C(X) holds in F_q, and returns the residual of the
// coefficients the carries cannot absorb: zero exactly when d(2^t) ≡ 0 mod q
// and d fits the carry count.
func carriesModQCoef(d []*big.Int, nbBits uint, out []*big.Int) *big.Int {
	invW := new(big.Int).ModInverse(new(big.Int).Lsh(big.NewInt(1), nbBits), nativeQ)
	carry := new(big.Int)
	for i := range out {
		v := new(big.Int).Add(carry, coefAt(d, i))
		carry = modQ(v.Mul(v, invW))
		out[i].Set(carry)
	}
	res := new(big.Int)
	for i := len(out); i < len(d); i++ {
		v := new(big.Int).Set(coefAt(d, i))
		if i == len(out) {
			v.Add(v, carry)
		}
		if modQ(v).Sign() != 0 {
			res.Add(res, big.NewInt(1))
		}
	}
	if len(d) <= len(out) {
		// the top coefficient of d is below the carry count: −c_{n−1} must vanish
		if carry.Sign() != 0 {
			res.Add(res, big.NewInt(1))
		}
	}
	return res
}

func coefAt(v []*big.Int, i int) *big.Int {
	if i < len(v) {
		return v[i]
	}
	return new(big.Int)
}

// polyMvMode is what the adversarial polyMvHint does.
type polyMvMode int

const (
	// polyMvTolerant computes as polyMvHint does, but an asserted-zero call
	// whose value is not 0 mod p returns a quotient and integer carries
	// instead of failing the solve; the deferred check then decides.
	polyMvTolerant polyMvMode = iota
	// polyMvWrapInexact is polyMvTolerant, except that an asserted-zero call
	// whose value is not 0 mod p gets K ≡ L/p (mod q) and carries mod q:
	// the item-1 forgery against whatever made the value wrong.
	polyMvWrapInexact
	// polyMvEvalRemPlusOne returns r + 1 from a targeted Eval call (honest
	// quotient and integer carries).
	polyMvEvalRemPlusOne
	// polyMvEvalRemWrap returns r ± q from a targeted Eval call, keeps the
	// quotient and recomputes the carries mod q.
	polyMvEvalRemWrap
)

// polyMvStats counts what an adversarial polyMvHint did.
type polyMvStats struct {
	// wrapped counts forgeries whose quotient fits its limbs; wideQuotient
	// those whose K ≡ L/p (mod q) does not, answered with an over-wide top
	// limb (the identity then holds mod q and the quotient's range check is
	// what stands in the way)
	evalCalls, assertCalls, inexact, wrapped, wideQuotient, wrapImpossible, forged int64
	// also counts wraps, when set (to share one forged-output counter)
	alsoWrapped *int64
}

// polyMvAdversary returns an adversarial polyMvHint. target selects Eval
// calls (by their index among Eval calls, in solve order) for the forging
// modes; nil selects none.
func polyMvAdversary(mode polyMvMode, target func(evalCall int64) bool) solver.Hint {
	return polyMvAdversaryStats(mode, target, &polyMvStats{})
}

func polyMvAdversaryStats(mode polyMvMode, target func(evalCall int64) bool, st *polyMvStats) solver.Hint {
	return func(_ *big.Int, inputs, outputs []*big.Int) error {
		c, err := parsePolyMv(inputs, outputs)
		if err != nil {
			return err
		}
		quo, rem := new(big.Int), new(big.Int)
		quo.DivMod(c.lhsFull, c.p, rem)
		neg := quo.Sign() < 0
		absQuo := new(big.Int).Abs(quo)
		quoLimbs := make([]*big.Int, c.nbQuo)
		for i := range quoLimbs {
			quoLimbs[i] = new(big.Int)
		}
		if err := limbsInto(absQuo, c.nbBits, quoLimbs); err != nil {
			return fmt.Errorf("quotient: %w", err)
		}
		remLimbs := make([]*big.Int, c.nbRem)
		for i := range remLimbs {
			remLimbs[i] = new(big.Int)
		}
		isEval := c.nbRem > 0
		var evalIdx int64 = -1
		if isEval {
			evalIdx = atomic.AddInt64(&st.evalCalls, 1) - 1
			if err := limbsInto(rem, c.nbBits, remLimbs); err != nil {
				return fmt.Errorf("remainder: %w", err)
			}
		} else {
			atomic.AddInt64(&st.assertCalls, 1)
			if rem.Sign() != 0 {
				atomic.AddInt64(&st.inexact, 1)
			}
		}
		write := func(q []*big.Int, r []*big.Int, kNeg bool) {
			for i := range c.quoOut {
				c.quoOut[i].Set(q[i])
			}
			for i := range c.remOut {
				c.remOut[i].Set(r[i])
			}
			if kNeg {
				c.kNegOut.SetInt64(1)
			} else {
				c.kNegOut.SetInt64(0)
			}
		}
		honest := func() error {
			write(quoLimbs, remLimbs, neg)
			integerCarries(c.residualCoefficients(remLimbs, quoLimbs, neg), c.nbBits, c.carryOut)
			return nil
		}
		switch {
		case !isEval && rem.Sign() != 0 && mode == polyMvWrapInexact:
			// K ≡ L·p^{-1} (mod q), non-negative; it must fit the quotient limbs
			k := modQ(new(big.Int).Mul(c.lhsFull, new(big.Int).ModInverse(c.p, nativeQ)))
			kLimbs := make([]*big.Int, c.nbQuo)
			for i := range kLimbs {
				kLimbs[i] = new(big.Int)
			}
			wide := false
			if err := limbsInto(k, c.nbBits, kLimbs); err != nil {
				if !limbsWide(k, c.nbBits, kLimbs) {
					atomic.AddInt64(&st.wrapImpossible, 1)
					return honest()
				}
				wide = true
			}
			write(kLimbs, remLimbs, false)
			if res := carriesModQCoef(c.residualCoefficients(remLimbs, kLimbs, false), c.nbBits, c.carryOut); res.Sign() != 0 {
				atomic.AddInt64(&st.wrapImpossible, 1)
				return honest()
			}
			if wide {
				atomic.AddInt64(&st.wideQuotient, 1)
			} else {
				atomic.AddInt64(&st.wrapped, 1)
			}
			if st.alsoWrapped != nil {
				atomic.AddInt64(st.alsoWrapped, 1)
			}
			return nil
		case isEval && target != nil && target(evalIdx) && mode == polyMvEvalRemPlusOne:
			atomic.AddInt64(&st.forged, 1)
			r1 := new(big.Int).Add(rem, big.NewInt(1))
			if err := limbsInto(r1, c.nbBits, remLimbs); err != nil {
				return err
			}
			write(quoLimbs, remLimbs, neg)
			integerCarries(c.residualCoefficients(remLimbs, quoLimbs, neg), c.nbBits, c.carryOut)
			return nil
		case isEval && target != nil && target(evalIdx) && mode == polyMvEvalRemWrap:
			atomic.AddInt64(&st.forged, 1)
			rq := new(big.Int).Add(rem, nativeQ)
			if limbsInto(rq, c.nbBits, remLimbs) != nil {
				rq.Sub(rem, nativeQ)
				if rq.Sign() < 0 || limbsInto(rq, c.nbBits, remLimbs) != nil {
					return errors.New("neither r + q nor r − q fits the remainder limbs")
				}
			}
			write(quoLimbs, remLimbs, neg)
			if res := carriesModQCoef(c.residualCoefficients(remLimbs, quoLimbs, neg), c.nbBits, c.carryOut); res.Sign() != 0 {
				return fmt.Errorf("wrapped remainder leaves residual %s", res)
			}
			return nil
		}
		return honest()
	}
}

// limbsWide writes v into out as nbBits-bit limbs except the top one, which
// takes all the remaining bits (wider than nbBits when v does not fit). It
// fails only when out is empty or v is negative.
func limbsWide(v *big.Int, nbBits uint, out []*big.Int) bool {
	if len(out) == 0 || v.Sign() < 0 {
		return false
	}
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), nbBits), big.NewInt(1))
	rest := new(big.Int).Set(v)
	for i := range out {
		if i == len(out)-1 {
			out[i].Set(rest)
			break
		}
		out[i].And(rest, mask)
		rest.Rsh(rest, nbBits)
	}
	return true
}

// limbsInto writes v's nbBits-bit limbs into out, or fails when v is
// negative or does not fit.
func limbsInto(v *big.Int, nbBits uint, out []*big.Int) error {
	l, err := limbsOf(v, len(out), nbBits)
	if err != nil {
		return err
	}
	for i := range out {
		out[i].Set(l[i])
	}
	return nil
}

// mulMode is what the adversarial mulHint does on a targeted call.
type mulMode int

const (
	mulRemPlusOne mulMode = iota // r + 1, honest carries
	mulCarryWrap                 // r ± q, quotient kept, carries mod q (R-333's forgery)
	// mulWrapInexact targets checkZero calls (a·1 = 0 + k·p): when a is not
	// 0 mod p, it answers K ≡ a/p (mod q) with carries mod q, the item-1
	// forgery against whatever made a non-zero.
	mulWrapInexact
)

// mulStats counts what an adversarial mulHint did.
type mulStats struct {
	forged, inexact, wideQuotient, wrapImpossible int64
}

// mulAdversary wraps gnark's mulHint. target selects calls by their index
// in solve order among all mulHint calls; the caller restricts it to calls
// whose remainder is used (mulRemainderUsed).
func mulAdversary(mode mulMode, target func(call int64) bool, forged *int64) solver.Hint {
	return mulAdversaryStats(mode, target, &mulStats{}, forged)
}

func mulAdversaryStats(mode mulMode, target func(call int64) bool, st *mulStats, forged *int64) solver.Hint {
	var calls int64
	mulHint := mulHintFn()
	return func(field *big.Int, inputs, outputs []*big.Int) error {
		if err := mulHint(field, inputs, outputs); err != nil {
			return err
		}
		l := parseMulHint(inputs, outputs)
		idx := atomic.AddInt64(&calls, 1) - 1
		if !target(idx) {
			return nil
		}
		if mode == mulWrapInexact {
			ab := new(big.Int).Mul(recompose(l.a, l.nbBits), recompose(l.b, l.nbBits))
			p := recompose(l.p, l.nbBits)
			if new(big.Int).Mod(ab, p).Sign() == 0 {
				return nil
			}
			atomic.AddInt64(&st.inexact, 1)
			k := modQ(ab.Mul(ab, new(big.Int).ModInverse(p, nativeQ)))
			quo := make([]*big.Int, len(l.quo))
			carry := make([]*big.Int, len(l.carry))
			zero := make([]*big.Int, len(l.rem))
			for i := range quo {
				quo[i] = new(big.Int)
			}
			for i := range carry {
				carry[i] = new(big.Int)
			}
			for i := range zero {
				zero[i] = new(big.Int)
			}
			wide := false
			if limbsInto(k, l.nbBits, quo) != nil {
				if !limbsWide(k, l.nbBits, quo) {
					atomic.AddInt64(&st.wrapImpossible, 1)
					return nil
				}
				wide = true
			}
			trial := l
			trial.carry = carry
			if top := carriesModQ(nativeQ, trial, zero, quo); top.Sign() != 0 {
				atomic.AddInt64(&st.wrapImpossible, 1)
				return nil
			}
			for i := range quo {
				l.quo[i].Set(quo[i])
			}
			for i := range carry {
				l.carry[i].Set(carry[i])
			}
			if wide {
				atomic.AddInt64(&st.wideQuotient, 1)
			}
			atomic.AddInt64(forged, 1)
			atomic.AddInt64(&st.forged, 1)
			return nil
		}
		atomic.AddInt64(forged, 1)
		atomic.AddInt64(&st.forged, 1)
		r := recompose(l.rem, l.nbBits)
		switch mode {
		case mulRemPlusOne:
			r.Add(r, big.NewInt(1))
			return limbsInto(r, l.nbBits, l.rem)
		case mulCarryWrap:
			rq := new(big.Int).Add(r, nativeQ)
			if limbsInto(rq, l.nbBits, l.rem) != nil {
				rq.Sub(r, nativeQ)
				if rq.Sign() < 0 || limbsInto(rq, l.nbBits, l.rem) != nil {
					return errors.New("neither r + q nor r − q fits the remainder limbs")
				}
			}
			if top := carriesModQ(nativeQ, l, l.rem, l.quo); top.Sign() != 0 {
				return fmt.Errorf("top coefficient residual %s", top)
			}
		}
		return nil
	}
}
