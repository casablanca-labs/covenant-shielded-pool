package transcript

import (
	"fmt"
	"slices"

	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
)

// gnark v0.16.3's Randomize hint (internal/hints), the source of every
// commitment mask: Commit calls NewHint(hints.Randomize, 1) with no input.
// A hint's id is the FNV-32a hash of its name (solver.GetHintID), and gnark's
// solver registers Randomize under it in its own init, so its solver, with
// the default registry, calls Randomize (crypto/rand) for an instruction with
// this id when its schedule runs that instruction (see checkSchedule).
// TestRandomizeHintIDIsPinned fails if either value changes.
const (
	RandomizeHintName               = "github.com/consensys/gnark/internal/hints.Randomize"
	RandomizeHintID   solver.HintID = 0x69c66a53
)

// CommitmentMasks says where the random mask of each BSB22 commitment of an
// R1CS sits in a proving key's commitment basis.
//
// gnark v0.16.3's Commit (frontend/cs/r1cs/api.go) appends a mask drawn from
// crypto/rand to the committed values and adds the constraint mask·1 = mask,
// so that the mask reaches the commitment. The mask is the commitment's only
// randomness. Its basis element is (β+1)·Lₖ(τ)/γ; if that is O, a proof's
// commitment is a fixed function of the committed private values (ARCH-238).
type CommitmentMasks struct {
	// NbCommitted is, per commitment, the number of committed private wires:
	// the length of the key's Basis.
	NbCommitted []int `json:"nbCommitted"`
	// Positions lists, per commitment, the positions in the key's Basis of
	// the committed wires w constrained by w·1 = w.
	Positions [][]int `json:"positions"`
}

// LocateCommitmentMasks finds every commitment's mask by the rule of
// ARCH-238's crscheck (crscheck/layout.go, lane/pool-crs-coverage b613957a),
// not by an index guess: a committed private wire w with a constraint whose
// L is {w: 1}, R is {wire 0 (the constant one): 1} and O is {w: 1}. A wire's
// position is its rank among its commitment's committed wires, the order
// gnark's Phase2.Initialize builds the basis in (ascending wire id).
//
// The constraint shape alone says nothing about where w comes from (REV-197),
// so every such wire must also be the sole output of exactly one hint
// instruction of the R1CS, and that instruction must be the Randomize hint
// (RandomizeHintID) with no input and one output, the call gnark's Commit
// makes, with the R1CS's hint-name record for the id present and naming it.
// An instruction list says nothing about what the solver runs (REV-200), so
// checkSchedule also requires the R1CS's Levels to be the schedule gnark's
// builder derives from its instructions, and each mask's Randomize
// instruction to run in a level strictly before every other instruction whose
// walk references the mask. (A walk is not every read: a lookup query can read
// the mask through its table without walking it, REV-205.) For a
// circuit that passes, gnark v0.16.3's solver with its default registry sets
// each mask with crypto/rand or does not complete [R, source]; that reading of
// gnark is not a certificate for an untrusted circuit file, whose control is
// the caller's R1CS anchor (verifier.Inputs.ExpectedR1CSSHA256).
//
// It refuses (COMMITMENT_MASK_MISSING) a commitment for which no such wire
// exists and committed wires that are not laid out as that order assumes,
// (COMMITMENT_MASK_NOT_RANDOMIZED) a mask-shaped committed wire without that
// provenance or that order, and (R1CS_SCHEDULE_INVALID) a schedule that is not
// the builder's.
func LocateCommitmentMasks(r1cs *cs.R1CS) (m *CommitmentMasks, err error) {
	defer func() {
		if p := recover(); p != nil {
			m, err = nil, failure.New(failure.CommitmentMaskMissing, "reading the R1CS's instructions panicked: %v", p)
		}
	}()
	if fn := solver.GetRegisteredHint(RandomizeHintID); fn == nil || solver.GetHintName(fn) != RandomizeHintName {
		return nil, failure.New(failure.CommitmentMaskNotRandomized, "this build's gnark does not register %s under id %#x", RandomizeHintName, uint32(RandomizeHintID))
	}
	info, ok := r1cs.CommitmentInfo.(constraint.Groth16Commitments)
	if !ok {
		return nil, failure.New(failure.CommitmentMaskMissing, "the R1CS's commitment info is not Groth16's")
	}
	nbInternal, nbSecret, nbPublic := r1cs.GetNbVariables()
	nbWires := nbInternal + nbSecret + nbPublic

	// commitOf[j] is the commitment wire j is committed to, or −1.
	commitOf := make([]int32, nbWires)
	for j := range commitOf {
		commitOf[j] = -1
	}
	isCommitmentWire := make(map[int]bool, len(info))
	for _, j := range info.CommitmentIndexes() {
		if j < nbPublic || j >= nbWires || isCommitmentWire[j] {
			return nil, failure.New(failure.CommitmentMaskMissing, "commitment wire %d is out of place", j)
		}
		isCommitmentWire[j] = true
	}
	committed := info.GetPrivateCommitted()
	m = &CommitmentMasks{NbCommitted: make([]int, len(info)), Positions: make([][]int, len(info))}
	for k, pc := range committed {
		if !slices.IsSorted(pc) {
			return nil, failure.New(failure.CommitmentMaskMissing, "commitment %d's committed wires are not sorted", k)
		}
		for _, j := range pc {
			if j < nbPublic || j >= nbWires || isCommitmentWire[j] || commitOf[j] != -1 {
				return nil, failure.New(failure.CommitmentMaskMissing, "committed wire %d of commitment %d is out of place", j, k)
			}
			commitOf[j] = int32(k)
		}
		m.NbCommitted[k] = len(pc)
	}

	shaped := map[int]bool{} // committed wires with the mask's constraint
	it := r1cs.GetR1CIterator()
	for c := it.Next(); c != nil; c = it.Next() {
		if len(c.L) != 1 || len(c.R) != 1 || len(c.O) != 1 {
			continue
		}
		l, r, o := c.L[0], c.R[0], c.O[0]
		if l.WireID() != o.WireID() || r.WireID() != 0 ||
			l.CoeffID() != constraint.CoeffIdOne || r.CoeffID() != constraint.CoeffIdOne || o.CoeffID() != constraint.CoeffIdOne {
			continue
		}
		j := l.WireID()
		if j < 0 || j >= nbWires || commitOf[j] == -1 {
			continue
		}
		k := commitOf[j]
		p, _ := slices.BinarySearch(committed[k], j)
		m.Positions[k] = append(m.Positions[k], p)
		shaped[j] = true
	}
	why, randomizeOf := maskProvenance(r1cs, shaped)
	for k := range m.Positions {
		slices.Sort(m.Positions[k])
		m.Positions[k] = slices.Compact(m.Positions[k])
		if len(m.Positions[k]) == 0 {
			return nil, failure.New(failure.CommitmentMaskMissing, "commitment %d: no committed wire w has a constraint w·1 = w, so no mask was found", k)
		}
		for _, p := range m.Positions[k] {
			if w := committed[k][p]; why[w] != "" {
				return nil, failure.New(failure.CommitmentMaskNotRandomized, "commitment %d: committed wire %d (position %d) has the mask's constraint w·1 = w but %s", k, w, p, why[w])
			}
		}
	}
	name, recorded := r1cs.MHintsDependencies[RandomizeHintID]
	if (recorded || len(randomizeOf) > 0) && name != RandomizeHintName {
		return nil, failure.New(failure.CommitmentMaskNotRandomized, "the R1CS records hint id %#x as %q (recorded %v), not %s", uint32(RandomizeHintID), name, recorded, RandomizeHintName)
	}
	if err := checkSchedule(r1cs, randomizeOf); err != nil {
		return nil, err
	}
	return m, nil
}

// maskProvenance returns, for each wire of want that is not the sole output
// of exactly one Randomize hint instruction with no input, why not; and, for
// each wire that is, the index of that instruction.
func maskProvenance(r1cs *cs.R1CS, want map[int]bool) (map[int]string, map[int]int) {
	setBy := make(map[int]int, len(want))
	randomized := make(map[int]int, len(want))
	var hm constraint.HintMapping
	for i, pi := range r1cs.Instructions {
		if int(pi.BlueprintID) >= len(r1cs.Blueprints) {
			panic(fmt.Sprintf("instruction blueprint %d of %d", pi.BlueprintID, len(r1cs.Blueprints)))
		}
		bp, ok := r1cs.Blueprints[pi.BlueprintID].(constraint.BlueprintHint)
		if !ok {
			continue
		}
		bp.DecompressHint(&hm, pi.Unpack(&r1cs.System))
		for w := range want {
			if uint64(w) < uint64(hm.OutputRange.Start) || uint64(w) >= uint64(hm.OutputRange.End) {
				continue
			}
			setBy[w]++
			if hm.HintID == RandomizeHintID && len(hm.Inputs) == 0 && hm.OutputRange.End == hm.OutputRange.Start+1 {
				randomized[w] = i
			}
		}
	}
	why := make(map[int]string, len(want))
	for w := range want {
		_, isRandomize := randomized[w]
		switch {
		case setBy[w] == 0:
			why[w] = "no hint sets it"
		case setBy[w] > 1:
			why[w] = fmt.Sprintf("%d hint instructions set it", setBy[w])
		case !isRandomize:
			why[w] = "the hint that sets it is not gnark's Randomize with no input and one output"
		}
	}
	for w := range why {
		delete(randomized, w)
	}
	return why, randomized
}

// Check refuses (COMMITMENT_MASK_ZERO) a proving key whose basis element at a
// mask position is the point at infinity: that commitment would not hide the
// committed private values. It refuses (COMMITMENT_MASK_MISSING) a key whose
// commitment keys do not have the circuit's shape, since the mask positions
// then say nothing about it.
func (m *CommitmentMasks) Check(pk groth16.ProvingKey) error {
	key, ok := pk.(*groth16bn254.ProvingKey)
	if !ok {
		return failure.New(failure.CommitmentMaskMissing, "not a BN254 Groth16 proving key")
	}
	if len(key.CommitmentKeys) != len(m.Positions) {
		return failure.New(failure.CommitmentMaskMissing, "the key has %d commitment keys, the circuit %d commitments", len(key.CommitmentKeys), len(m.Positions))
	}
	for k, ck := range key.CommitmentKeys {
		if len(ck.Basis) != m.NbCommitted[k] {
			return failure.New(failure.CommitmentMaskMissing, "commitment %d: the key's basis has %d elements, the circuit commits %d wires", k, len(ck.Basis), m.NbCommitted[k])
		}
		for _, p := range m.Positions[k] {
			if ck.Basis[p].IsInfinity() {
				return failure.New(failure.CommitmentMaskZero, "commitment %d: the random mask's basis element (committed position %d of %d) is O, so the commitment is a fixed function of the committed private values", k, p, len(ck.Basis))
			}
		}
	}
	return nil
}
