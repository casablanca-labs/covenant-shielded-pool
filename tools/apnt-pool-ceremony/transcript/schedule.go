package transcript

import (
	"fmt"
	"reflect"
	"slices"

	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
)

// gnark v0.16.3's solver runs only the instructions an R1CS's Levels list,
// level by level (constraint/bn254/solver.go run()), and Levels are read from
// the file as they are (constraint/marshal.go). gnark's builder writes Levels
// in one place, System.AddInstruction (constraint/core.go), from each
// blueprint's UpdateInstructionTree. So the schedule of an R1CS gnark built is
// exactly what replaying AddInstruction over its instructions yields, and
// checkSchedule requires that (REV-200).

// scheduleTree is constraint.System's instruction tree (instruction_tree.go)
// on fresh state, with every internal wire present from the start. It also
// records, for the watched wires, the instructions that reference them.
type scheduleTree struct {
	offset  uint32             // the first internal wire
	levels  []constraint.Level // per internal wire
	watch   map[int]bool
	touched map[int][]int // watched wire -> instructions that referenced it
	cur     int           // the instruction being replayed
}

func (t *scheduleTree) note(w uint32) {
	if t.watch[int(w)] {
		if s := t.touched[int(w)]; len(s) == 0 || s[len(s)-1] != t.cur {
			t.touched[int(w)] = append(s, t.cur)
		}
	}
}

func (t *scheduleTree) HasWire(w uint32) bool {
	t.note(w)
	return w >= t.offset && w-t.offset < uint32(len(t.levels))
}

func (t *scheduleTree) GetWireLevel(w uint32) constraint.Level {
	t.note(w)
	return t.levels[w-t.offset]
}

func (t *scheduleTree) InsertWire(w uint32, level constraint.Level) {
	t.note(w)
	if w < t.offset {
		panic(fmt.Sprintf("an instruction sets input wire %d", w))
	}
	if t.levels[w-t.offset] != constraint.LevelUnset {
		panic(fmt.Sprintf("wire %d is set by two instructions", w))
	}
	t.levels[w-t.offset] = level
}

// freshBlueprint returns a copy of b with its exported fields, the ones an
// R1CS file carries, and every unexported field zero: the state a blueprint
// has when decoded, and when gnark's builder creates it. The lookup
// blueprint's UpdateInstructionTree caches progress in unexported fields, so
// replaying on the R1CS's own blueprints would depend on, and change, what an
// earlier walk left there.
func freshBlueprint(b constraint.Blueprint) constraint.Blueprint {
	v := reflect.ValueOf(b)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		return b
	}
	fresh := reflect.New(v.Elem().Type())
	for i := 0; i < v.Elem().NumField(); i++ {
		if f := fresh.Elem().Field(i); f.CanSet() {
			f.Set(v.Elem().Field(i))
		}
	}
	return fresh.Interface().(constraint.Blueprint)
}

// replaySchedule replays System.AddInstruction's level assignment over the
// instructions of r, in order, and returns the Levels it yields, each
// instruction's position in them, and, for each watched wire, the
// instructions whose blueprint walk referenced it. A panic, such as a wire
// set by two instructions, is returned as an error, and so is a sparse
// (PLONK) blueprint: an R1CS file can carry one (constraint/marshal.go),
// gnark's R1CS builder never emits one, and a sparse Mul or Add writes its
// output unconditionally while its walk treats an already-set output as an
// input, so the replay could not see it set a wire twice (REV-205, IMPL-32).
func replaySchedule(r *cs.R1CS, watch map[int]bool) (levels [][]uint32, at []int, touched map[int][]int, err error) {
	defer func() {
		if p := recover(); p != nil {
			levels, at, touched, err = nil, nil, nil, fmt.Errorf("%v", p)
		}
	}()
	nbInternal, nbSecret, nbPublic := r.GetNbVariables()
	tree := &scheduleTree{
		offset: uint32(nbPublic + nbSecret), levels: make([]constraint.Level, nbInternal),
		watch: watch, touched: map[int][]int{},
	}
	for i := range tree.levels {
		tree.levels[i] = constraint.LevelUnset
	}
	bps := make([]constraint.Blueprint, len(r.Blueprints))
	for i, b := range r.Blueprints {
		if _, sparse := b.(constraint.BlueprintSparseR1C); sparse {
			return nil, nil, nil, fmt.Errorf("blueprint %d is a %T, a sparse (PLONK) blueprint gnark's R1CS builder never emits", i, b)
		}
		bps[i] = freshBlueprint(b)
	}
	at = make([]int, len(r.Instructions))
	for i, pi := range r.Instructions {
		if int(pi.BlueprintID) >= len(bps) {
			return nil, nil, nil, fmt.Errorf("instruction %d names blueprint %d of %d", i, pi.BlueprintID, len(bps))
		}
		tree.cur = i
		level := bps[pi.BlueprintID].UpdateInstructionTree(pi.Unpack(&r.System), tree)
		// AddInstruction's own placement: "we can't skip levels".
		if int(level) >= len(levels) {
			levels = append(levels, []uint32{uint32(i)})
			at[i] = len(levels) - 1
		} else {
			levels[level] = append(levels[level], uint32(i))
			at[i] = int(level)
		}
	}
	return levels, at, tree.touched, nil
}

// checkSchedule refuses (R1CS_SCHEDULE_INVALID) an R1CS whose Levels are not
// the schedule gnark v0.16.3's builder derives from its instructions, so that
// the solver runs every instruction exactly once in dependency order, or
// that carries a sparse blueprint; and (COMMITMENT_MASK_NOT_RANDOMIZED) a
// mask whose Randomize instruction is not in a level strictly before every
// other instruction whose walk references the mask wire. randomizeOf maps
// each mask wire to its Randomize instruction.
func checkSchedule(r *cs.R1CS, randomizeOf map[int]int) error {
	watch := make(map[int]bool, len(randomizeOf))
	for w := range randomizeOf {
		watch[w] = true
	}
	levels, at, touched, err := replaySchedule(r, watch)
	if err != nil {
		return failure.New(failure.R1CSScheduleInvalid, "replaying the R1CS's instructions as gnark's builder does fails: %v", err)
	}
	if len(levels) != len(r.Levels) {
		return failure.New(failure.R1CSScheduleInvalid, "the R1CS schedules %d levels, its instructions give %d", len(r.Levels), len(levels))
	}
	for l := range levels {
		if !slices.Equal(levels[l], r.Levels[l]) {
			return failure.New(failure.R1CSScheduleInvalid, "level %d of the R1CS's schedule is not the one its instructions give", l)
		}
	}
	for w, h := range randomizeOf {
		for _, i := range touched[w] {
			if i != h && at[i] <= at[h] {
				return failure.New(failure.CommitmentMaskNotRandomized, "instruction %d (level %d) references mask wire %d, not after its Randomize instruction %d (level %d)", i, at[i], w, h, at[h])
			}
		}
	}
	return nil
}
