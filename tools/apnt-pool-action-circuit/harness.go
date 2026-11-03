package poolaction

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Compile compiles the circuit to BN254 R1CS with the given clauses ablated
// (none for production). Compile only: no Setup, no proving key.
func Compile(ablated ...Clause) (constraint.ConstraintSystem, error) {
	c := NewActionCircuit()
	if len(ablated) > 0 {
		c.ablated = make(map[Clause]bool, len(ablated))
		for _, cl := range ablated {
			c.ablated[cl] = true
		}
	}
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
}

// Release drops the caller's last reference before the next compile; one
// constraint system is held at a time.
func Release() {
	runtime.GC()
	debug.FreeOSMemory()
}

// Solve runs gnark's R1CS solver on a full assignment. nil means the
// constraint system is satisfied for the solver's hint outputs. A solver
// panic (for example a lookup index outside its table) is returned as an
// error and marked as such.
func Solve(ccs constraint.ConstraintSystem, assignment *ActionCircuit) (err error) {
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("witness: %w", err)
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("solver panic: %v", r)
		}
	}()
	return ccs.IsSolved(w)
}
