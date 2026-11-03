// Package testcircuits holds small circuits for exercising the ceremony
// tooling. None of them is the pool action circuit, and nothing here may be
// used to set up a circuit that guards value.
package testcircuits

import (
	"bytes"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Cubic proves knowledge of x with x³ + x + K = y. Changing K is the smallest
// possible circuit change: same shape, different R1CS coefficients.
type Cubic struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
	K int               `gnark:"-"`
}

func (c *Cubic) Define(api frontend.API) error {
	x3 := api.Mul(c.X, c.X, c.X)
	api.AssertIsEqual(c.Y, api.Add(x3, c.X, c.K))
	return nil
}

// Chain proves y = x^(2^Rounds), one constraint per round; it scales the
// circuit to a chosen domain size.
type Chain struct {
	X      frontend.Variable
	Y      frontend.Variable `gnark:",public"`
	Rounds int               `gnark:"-"`
}

func (c *Chain) Define(api frontend.API) error {
	v := c.X
	for i := 0; i < c.Rounds; i++ {
		v = api.Mul(v, v)
	}
	api.AssertIsEqual(v, c.Y)
	return nil
}

// Committed uses gnark's commitment API, so its ceremony exercises the σ
// update proofs and commitment bases the pool action circuit also has.
type Committed struct {
	X      [8]frontend.Variable
	Y      frontend.Variable `gnark:",public"`
	Rounds int               `gnark:"-"`
}

func (c *Committed) Define(api frontend.API) error {
	committer, ok := api.(frontend.Committer)
	if !ok {
		return fmt.Errorf("builder does not support commitments")
	}
	r, err := committer.Commit(c.X[:]...)
	if err != nil {
		return err
	}
	// y = Σ xᵢ, and a random linear combination keyed by the commitment
	// ties the committed values into the proof.
	sum := frontend.Variable(0)
	acc := frontend.Variable(0)
	for i := range c.X {
		sum = api.Add(sum, c.X[i])
		acc = api.Add(api.Mul(acc, r), c.X[i])
	}
	api.AssertIsDifferent(acc, 0)
	v := sum
	for i := 0; i < c.Rounds; i++ {
		v = api.Mul(v, v)
	}
	api.AssertIsEqual(sum, c.Y)
	api.AssertIsDifferent(v, 0)
	return nil
}

// ByName returns a test circuit and a satisfying assignment.
func ByName(name string, size int) (frontend.Circuit, frontend.Circuit, error) {
	switch name {
	case "cubic":
		k := size
		if k == 0 {
			k = 5
		}
		y := 27 + 3 + k
		return &Cubic{K: k}, &Cubic{X: 3, Y: y, K: k}, nil
	case "chain":
		var x, y fr.Element
		x.SetUint64(3)
		y.Set(&x)
		for i := 0; i < size; i++ {
			y.Square(&y)
		}
		var yb big.Int
		y.BigInt(&yb)
		return &Chain{Rounds: size}, &Chain{X: 3, Y: &yb, Rounds: size}, nil
	case "committed":
		a := &Committed{Rounds: size}
		sum := 0
		for i := range a.X {
			a.X[i] = i + 2
			sum += i + 2
		}
		a.Y = sum
		return &Committed{Rounds: size}, a, nil
	}
	return nil, nil, fmt.Errorf("unknown test circuit %q (cubic, chain, committed)", name)
}

// Compile compiles a named test circuit to a bn254 R1CS.
func Compile(name string, size int) (*cs.R1CS, error) {
	c, _, err := ByName(name, size)
	if err != nil {
		return nil, err
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
	if err != nil {
		return nil, err
	}
	return ccs.(*cs.R1CS), nil
}

// WriteR1CS writes r1cs in gnark's serialization.
func WriteR1CS(path string, r *cs.R1CS) error {
	var b bytes.Buffer
	if _, err := r.WriteTo(&b); err != nil {
		return err
	}
	return os.WriteFile(path, b.Bytes(), 0o644)
}
