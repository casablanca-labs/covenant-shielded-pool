package testcircuits

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
)

// TermCount counts the terms of one side (L, R or O) of every constraint by
// the coefficient class that decides what phase 2 does with them.
// Phase2.Initialize adds one point for a unit coefficient (One, MinusOne),
// two for Two, and does one scalar multiplication for any other
// coefficient; it skips Zero. OtherWords splits Other by the 64-bit words of
// the smaller of c and r−c, which is what the scalar multiplication's GLV
// loop runs over: index 0 is one word, index 3 four.
type TermCount struct {
	Zero       int64    `json:"zero"`
	One        int64    `json:"one"`
	MinusOne   int64    `json:"minusOne"`
	Two        int64    `json:"two"`
	Other      int64    `json:"other"`
	OtherWords [4]int64 `json:"otherWords"`
}

// Total is every term on the side.
func (c TermCount) Total() int64 { return c.Zero + c.One + c.MinusOne + c.Two + c.Other }

func (c *TermCount) add(t constraint.Term, words []int) {
	switch t.CoeffID() {
	case constraint.CoeffIdZero:
		c.Zero++
	case constraint.CoeffIdOne:
		c.One++
	case constraint.CoeffIdMinusOne:
		c.MinusOne++
	case constraint.CoeffIdTwo:
		c.Two++
	default:
		c.Other++
		c.OtherWords[words[t.CoeffID()]-1]++
	}
}

// coeffWords returns, per coefficient id, the 64-bit words of the smaller
// of c and r−c (at least one).
func coeffWords(r *cs.R1CS) []int {
	words := make([]int, len(r.Coefficients))
	var v, neg big.Int
	mod := fr.Modulus()
	for i := range r.Coefficients {
		r.Coefficients[i].BigInt(&v)
		neg.Sub(mod, &v)
		n := min(v.BitLen(), neg.BitLen())
		words[i] = max(1, (n+63)/64)
	}
	return words
}

// Shape is what phase 2's cost depends on in an R1CS, beyond its domain:
// wires, terms per side by coefficient class, and commitment bases. It
// describes the circuit only; nothing in it is secret.
type Shape struct {
	NbConstraints int       `json:"nbConstraints"`
	NbInternal    int       `json:"nbInternal"`
	NbSecret      int       `json:"nbSecret"`
	NbPublic      int       `json:"nbPublic"`
	NbWires       int       `json:"nbWires"`
	L             TermCount `json:"l"`
	R             TermCount `json:"r"`
	O             TermCount `json:"o"`
	MaxTerms      int       `json:"maxTermsPerSide"`
	NbCommitments int       `json:"nbCommitments"`
	// NbCommitted is the number of private committed wires, the commitment
	// bases phase 2 carries (SigmaCKK) and a contribution scales.
	NbCommitted int `json:"nbCommitted"`
}

// ShapeOf walks every constraint of r.
func ShapeOf(r *cs.R1CS) Shape {
	internal, secret, public := r.GetNbVariables()
	s := Shape{
		NbConstraints: r.GetNbConstraints(),
		NbInternal:    internal, NbSecret: secret, NbPublic: public,
		NbWires: internal + secret + public,
	}
	words := coeffWords(r)
	it := r.GetR1CIterator()
	for c := it.Next(); c != nil; c = it.Next() {
		for _, side := range []struct {
			le constraint.LinearExpression
			n  *TermCount
		}{{c.L, &s.L}, {c.R, &s.R}, {c.O, &s.O}} {
			s.MaxTerms = max(s.MaxTerms, len(side.le))
			for _, t := range side.le {
				side.n.add(t, words)
			}
		}
	}
	commitments := r.CommitmentInfo.(constraint.Groth16Commitments)
	s.NbCommitments = len(commitments)
	for _, c := range commitments {
		s.NbCommitted += len(c.PrivateCommitted)
	}
	return s
}
