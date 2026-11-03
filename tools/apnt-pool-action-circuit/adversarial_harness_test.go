package poolaction

import (
	"fmt"
	"sort"
	"testing"

	"github.com/consensys/gnark/constraint"
	csbn254 "github.com/consensys/gnark/constraint/bn254"
)

// hintInventory is every solver-assigned output the compiled system has: the
// generic hints by id, and the other blueprints whose Solve writes wires.
type hintInventory struct {
	Hints      []hintCount      `json:"hints"`
	Blueprints []blueprintCount `json:"solverBlueprints"`
	R1Cs       int              `json:"r1cs"`
}

type hintCount struct {
	ID           uint32 `json:"id"`
	Name         string `json:"name"`
	Instructions int    `json:"instructions"`
	Outputs      int    `json:"outputs"`
}

type blueprintCount struct {
	Type         string `json:"type"`
	Instructions int    `json:"instructions"`
	Outputs      int    `json:"outputs"`
}

func asR1CS(t *testing.T, ccs constraint.ConstraintSystem) *csbn254.R1CS {
	t.Helper()
	r, ok := ccs.(*csbn254.R1CS)
	if !ok {
		protectedFatal(t, "constraint system is %T, not a BN254 R1CS", ccs)
	}
	return r
}

func inventory(r *csbn254.R1CS) hintInventory {
	hints := map[uint32]*hintCount{}
	bps := map[string]*blueprintCount{}
	var inv hintInventory
	var hm constraint.HintMapping
	for _, pi := range r.Instructions {
		bp := r.Blueprints[pi.BlueprintID]
		if bh, ok := bp.(constraint.BlueprintHint); ok {
			bh.DecompressHint(&hm, pi.Unpack(&r.System))
			id := uint32(hm.HintID)
			if hints[id] == nil {
				hints[id] = &hintCount{ID: id, Name: r.MHintsDependencies[hm.HintID]}
			}
			hints[id].Instructions++
			hints[id].Outputs += int(hm.OutputRange.End - hm.OutputRange.Start)
			continue
		}
		if _, ok := bp.(constraint.BlueprintR1C); ok {
			inv.R1Cs++
			continue
		}
		name := fmt.Sprintf("%T", bp)
		if bps[name] == nil {
			bps[name] = &blueprintCount{Type: name}
		}
		bps[name].Instructions++
		bps[name].Outputs += bp.NbOutputs(pi.Unpack(&r.System))
	}
	for _, h := range hints {
		inv.Hints = append(inv.Hints, *h)
	}
	sort.Slice(inv.Hints, func(i, j int) bool { return inv.Hints[i].Name < inv.Hints[j].Name })
	for _, b := range bps {
		inv.Blueprints = append(inv.Blueprints, *b)
	}
	sort.Slice(inv.Blueprints, func(i, j int) bool { return inv.Blueprints[i].Type < inv.Blueprints[j].Type })
	return inv
}

func TestAdversarialInventoryProbe(t *testing.T) {
	defer protectedPanic(t)
	ccs, err := Compile()
	if err != nil {
		protectedFatal(t, err)
	}
	r := asR1CS(t, ccs)
	inv := inventory(r)
	for _, h := range inv.Hints {
		protectedLog(t, "hint %10d %-75s instr=%8d outputs=%9d", h.ID, h.Name, h.Instructions, h.Outputs)
	}
	for _, b := range inv.Blueprints {
		protectedLog(t, "blueprint %-60s instr=%8d outputs=%9d", b.Type, b.Instructions, b.Outputs)
	}
	protectedLog(t, "r1cs=%d constraints=%d commitments=%d", inv.R1Cs, r.GetNbConstraints(), len(r.CommitmentInfo.(constraint.Groth16Commitments)))
	for i, c := range r.CommitmentInfo.(constraint.Groth16Commitments) {
		protectedLog(t, "commitment %d: wire %d, private committed %d, public/commitment committed %d", i, c.CommitmentIndex, len(c.PrivateCommitted), len(c.PublicAndCommitmentCommitted))
	}
}
