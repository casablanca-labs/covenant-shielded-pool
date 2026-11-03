package crscheck

import (
	"fmt"
	"slices"
	"strings"

	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
)

// The mask's origin (ENG-447; REV-198 H2, REV-200 H1). A committed wire with
// the constraint w·1 = w is gnark's random mask only if gnark's prover
// actually draws it at random. gnark v0.16.3's Commit (frontend/cs/r1cs
// api.go) makes the mask the one output of a call to internal/hints.Randomize
// with no input, which fills it from crypto/rand. The prover's solver runs the
// instructions its R1CS lists in Levels, level by level, and nothing else
// (constraint/bn254/solver.go run()); Levels are read from the file
// unchecked (constraint/marshal.go). So the shape of a constraint, or a
// Randomize instruction in the instruction list, says nothing unless the
// schedule the prover runs is the one gnark would derive and every other
// instruction whose walk touches the mask runs in a strictly later level than
// the Randomize call.
//
// This file checks exactly that, from the R1CS alone, written from gnark's
// source and not from the ceremony tooling (which checks the same criterion
// in its own code):
//
//   - CheckSchedule: replaying gnark's System.AddInstruction level
//     assignment (constraint/core.go) over the file's instructions, with this
//     package's own instruction tree and each blueprint's
//     UpdateInstructionTree on fresh blueprint state, gives exactly the
//     file's Levels. A wire set by two instructions fails the replay.
//   - CheckMaskOrigin, per commitment: each mask-shaped committed wire is set
//     by exactly one instruction of the replay, a hint call with
//     RandomizeHintID, no input and that wire as its only output; the R1CS
//     records RandomizeHintName under that id; this build's gnark registers
//     that function under that id; and every other instruction whose walk
//     touches the wire runs in a strictly later level.
//
// With both, gnark v0.16.3's solver with its default hint registry either
// fills each mask from crypto/rand in a level before every other instruction
// whose walk touches it, or produces no proof (it refuses to set a wire
// twice). A walk is what an instruction's UpdateInstructionTree reports, and
// that is not every read: gnark's lookup blueprint walks each table entry only
// in the first query that covers it, so a later query can read the mask
// through its table in Randomize's level, before Randomize runs, and read it
// unset, and gnark then serves that cached value to every later query over
// the table (REV-205, REV-206 W2). That changes the queries' outputs, not the
// mask. It does not cover a prover that overrides the Randomize hint
// (solver.OverrideHint) or runs another gnark.

// RandomizeHintName and RandomizeHintID identify the hint gnark v0.16.3's
// Commit calls for the mask. The id is the FNV-32a hash of the name
// (solver.GetHintID); TestRandomizeHintIsPinned ties both to gnark.
const (
	RandomizeHintName               = "github.com/consensys/gnark/internal/hints.Randomize"
	RandomizeHintID   solver.HintID = 0x69c66a53
)

// Check names of the R1CS's schedule and the masks' origin.
const (
	CheckSchedule   = "R1CS_SCHEDULE"              // Levels equal gnark's schedule of the instructions
	CheckMaskOrigin = "COMMITMENT_MASK_RANDOMIZED" // each mask is a no-input Randomize output; every other walk that touches it is in a later level
)

// scheduleTree is the replay's instruction tree (constraint.InstructionTree):
// a level per internal wire, as gnark's System keeps it, plus the instruction
// that set each wire and, for watched wires, every instruction that touched
// them.
type scheduleTree struct {
	offset  uint32 // the first internal wire
	level   []constraint.Level
	setter  []int32
	watched []bool
	touched map[uint32][]int32
	cur     int32
	fault   string
}

func (t *scheduleTree) internal(w uint32) (int, bool) {
	if w < t.offset || w-t.offset >= uint32(len(t.level)) {
		return 0, false
	}
	return int(w - t.offset), true
}

func (t *scheduleTree) touch(i int, w uint32) {
	if t.watched[i] {
		if s := t.touched[w]; len(s) == 0 || s[len(s)-1] != t.cur {
			t.touched[w] = append(s, t.cur)
		}
	}
}

func (t *scheduleTree) HasWire(w uint32) bool {
	i, ok := t.internal(w)
	if ok {
		t.touch(i, w)
	}
	return ok
}

func (t *scheduleTree) GetWireLevel(w uint32) constraint.Level {
	i, ok := t.internal(w)
	if !ok {
		if t.fault == "" {
			t.fault = fmt.Sprintf("instruction %d reads the level of wire %d, which is not internal", t.cur, w)
		}
		return constraint.LevelUnset
	}
	t.touch(i, w)
	return t.level[i]
}

func (t *scheduleTree) InsertWire(w uint32, l constraint.Level) {
	i, ok := t.internal(w)
	switch {
	case !ok:
		if t.fault == "" {
			t.fault = fmt.Sprintf("instruction %d sets wire %d, which is not internal", t.cur, w)
		}
		return
	case l < 0:
		if t.fault == "" {
			t.fault = fmt.Sprintf("instruction %d sets wire %d at level %d", t.cur, w, l)
		}
		return
	case t.level[i] != constraint.LevelUnset:
		if t.fault == "" {
			t.fault = fmt.Sprintf("wire %d is set by instructions %d and %d", w, t.setter[i], t.cur)
		}
		return
	}
	t.touch(i, w)
	t.level[i], t.setter[i] = l, t.cur
}

// freshBlueprints returns blueprints with the file's data and no walk state.
// gnark's lookup blueprint caches its walk over the table in unexported
// fields; the builder walked from an empty cache, so the replay must too. A
// blueprint type this replay does not know is refused.
func freshBlueprints(bs []constraint.Blueprint) ([]constraint.Blueprint, error) {
	out := make([]constraint.Blueprint, len(bs))
	for i, b := range bs {
		switch b := b.(type) {
		case *constraint.BlueprintGenericR1C:
			out[i] = &constraint.BlueprintGenericR1C{}
		case *constraint.BlueprintGenericHint:
			out[i] = &constraint.BlueprintGenericHint{}
		case *constraint.BlueprintBatchInverse[constraint.U64]:
			out[i] = &constraint.BlueprintBatchInverse[constraint.U64]{}
		case *constraint.BlueprintLookupHint[constraint.U64]:
			out[i] = &constraint.BlueprintLookupHint[constraint.U64]{EntriesCalldata: b.EntriesCalldata}
		default:
			return nil, fmt.Errorf("blueprint %d has type %T, which the schedule replay does not know", i, b)
		}
	}
	return out, nil
}

// schedule is the replay's result.
type schedule struct {
	levels  [][]uint32 // as gnark's AddInstruction would build them
	level   []int32    // the level each instruction is placed in
	tree    *scheduleTree
	problem string // why the replay or the comparison failed; "" if Levels match
}

// replaySchedule replays gnark v0.16.3's AddInstruction over r's instructions
// and compares the result with r.Levels. Wires in watch are recorded as they
// are touched.
func replaySchedule(r *cs.R1CS, watch []uint32) (s *schedule) {
	s = &schedule{}
	defer func() {
		if e := recover(); e != nil {
			s.problem = fmt.Sprintf("the instructions cannot be replayed: %v", e)
		}
	}()
	nbInternal := r.NbInternalVariables
	t := &scheduleTree{
		offset:  uint32(r.GetNbPublicVariables() + r.GetNbSecretVariables()),
		level:   make([]constraint.Level, nbInternal),
		setter:  make([]int32, nbInternal),
		watched: make([]bool, nbInternal),
		touched: map[uint32][]int32{},
	}
	for i := range t.level {
		t.level[i], t.setter[i] = constraint.LevelUnset, -1
	}
	for _, w := range watch {
		if i, ok := t.internal(w); ok {
			t.watched[i] = true
		}
	}
	s.tree = t
	bps, err := freshBlueprints(r.Blueprints)
	if err != nil {
		s.problem = err.Error()
		return s
	}
	s.level = make([]int32, len(r.Instructions))
	for i, pi := range r.Instructions {
		if int(pi.BlueprintID) >= len(bps) {
			s.problem = fmt.Sprintf("instruction %d names blueprint %d of %d", i, pi.BlueprintID, len(bps))
			return s
		}
		t.cur = int32(i)
		l := bps[pi.BlueprintID].UpdateInstructionTree(pi.Unpack(&r.System), t)
		if t.fault != "" {
			s.problem = t.fault
			return s
		}
		// As AddInstruction: a level past the last opens a new one.
		if l < 0 {
			s.problem = fmt.Sprintf("instruction %d has level %d", i, l)
			return s
		}
		if int(l) >= len(s.levels) {
			s.levels = append(s.levels, []uint32{uint32(i)})
			s.level[i] = int32(len(s.levels) - 1)
		} else {
			s.levels[l] = append(s.levels[l], uint32(i))
			s.level[i] = int32(l)
		}
	}
	if len(r.Levels) != len(s.levels) {
		s.problem = fmt.Sprintf("the file has %d levels, gnark's schedule of its instructions has %d", len(r.Levels), len(s.levels))
		return s
	}
	for k := range s.levels {
		if !slices.Equal(r.Levels[k], s.levels[k]) {
			s.problem = fmt.Sprintf("level %d differs from gnark's schedule of the instructions (%d instructions in the file, %d in the schedule)", k, len(r.Levels[k]), len(s.levels[k]))
			return s
		}
	}
	return s
}

// randomizeRegistered reports whether this build's gnark registers the
// function named RandomizeHintName under RandomizeHintID.
func randomizeRegistered() bool {
	fn := solver.GetRegisteredHint(RandomizeHintID)
	return fn != nil && solver.GetHintName(fn) == RandomizeHintName && solver.GetHintID(fn) == RandomizeHintID
}

// maskOrigin is one mask wire's origin in the replay: "" if it is the sole
// output of a no-input Randomize call run before every other instruction
// whose walk touches it, else why not.
func maskOrigin(r *cs.R1CS, s *schedule, w uint32) (reason string) {
	defer func() {
		if e := recover(); e != nil {
			reason = fmt.Sprintf("wire %d: its setter cannot be read: %v", w, e)
		}
	}()
	i, ok := s.tree.internal(w)
	if !ok {
		return fmt.Sprintf("wire %d is an input, not the output of an instruction", w)
	}
	set := s.tree.setter[i]
	if set < 0 {
		return fmt.Sprintf("wire %d is set by no instruction", w)
	}
	pi := r.Instructions[set]
	bp, ok := r.Blueprints[pi.BlueprintID].(constraint.BlueprintHint)
	if !ok {
		return fmt.Sprintf("wire %d is set by instruction %d, a %T, not a hint", w, set, r.Blueprints[pi.BlueprintID])
	}
	var h constraint.HintMapping
	bp.DecompressHint(&h, pi.Unpack(&r.System))
	switch {
	case h.HintID != RandomizeHintID:
		return fmt.Sprintf("wire %d is set by instruction %d, a call to hint %#x, not Randomize (%#x)", w, set, uint32(h.HintID), uint32(RandomizeHintID))
	case len(h.Inputs) != 0:
		return fmt.Sprintf("wire %d is set by instruction %d, a Randomize call with %d inputs", w, set, len(h.Inputs))
	case h.OutputRange.Start != w || h.OutputRange.End != w+1:
		return fmt.Sprintf("wire %d is set by instruction %d, a Randomize call with outputs [%d, %d), not only the mask", w, set, h.OutputRange.Start, h.OutputRange.End)
	}
	for _, o := range s.tree.touched[w] {
		if o != set && s.level[o] <= s.level[set] {
			return fmt.Sprintf("wire %d: instruction %d touches it in level %d, not after its Randomize call (instruction %d, level %d)", w, o, s.level[o], set, s.level[set])
		}
	}
	return ""
}

// originResults checks the schedule and each commitment's masks, whose
// positions in committed[k] are masks[k].
func originResults(r *cs.R1CS, committed [][]int32, masks [][]int) []Result {
	var watch []uint32
	for k := range masks {
		for _, p := range masks[k] {
			watch = append(watch, uint32(committed[k][p]))
		}
	}
	s := replaySchedule(r, watch)
	out := []Result{{Name: CheckSchedule, ZK: true, Pass: s.problem == ""}}
	if s.problem != "" {
		out[0].Detail = s.problem
	}
	record, recorded := r.MHintsDependencies[RandomizeHintID]
	registered := randomizeRegistered()
	for k := range masks {
		res := Result{Name: CheckMaskOrigin, ZK: true, Detail: fmt.Sprintf("commitment %d", k)}
		var bad []string
		switch {
		case len(masks[k]) == 0:
			bad = append(bad, "no committed wire w with a constraint w·1 = w")
		case s.problem != "":
			bad = append(bad, "the schedule is not gnark's, so no mask's origin can be established")
		default:
			if !recorded || record != RandomizeHintName {
				bad = append(bad, fmt.Sprintf("the R1CS records %q under the Randomize id (present: %v), want %q", record, recorded, RandomizeHintName))
			}
			if !registered {
				bad = append(bad, "this build's gnark does not register Randomize under its id")
			}
			for _, p := range masks[k] {
				if why := maskOrigin(r, s, uint32(committed[k][p])); why != "" {
					bad = append(bad, fmt.Sprintf("committed position %d: %s", p, why))
				}
			}
		}
		if len(bad) == 0 {
			res.Pass = true
			res.Detail = fmt.Sprintf("commitment %d: each mask (committed position(s) %v) is the sole output of a no-input Randomize call, and every other instruction whose walk touches it runs in a strictly later level", k, masks[k])
		} else {
			res.Detail = fmt.Sprintf("commitment %d: %s", k, strings.Join(bad, "; "))
		}
		out = append(out, res)
	}
	return out
}
