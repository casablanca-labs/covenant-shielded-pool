package transcript_test

import (
	"os"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/lookup/logderivlookup"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/internal/fixture"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

// IMPL-31 (REV-200): gnark's solver runs only the R1CS's Levels, so the mask
// check requires Levels to be the schedule gnark's builder derives from the
// instructions, and each mask's Randomize call to run in a level strictly
// before every other instruction whose walk touches the mask.

// Edits of a built circuit's Levels are refused: an instruction dropped, one
// scheduled twice, one moved to a later level. The unedited circuit passes.
func TestScheduleRefusesEditedLevels(t *testing.T) {
	build := func() *cs.R1CS { return fixture.MaskFromHintR1CS(transcript.RandomizeHintID) }
	if _, err := transcript.LocateCommitmentMasks(build()); err != nil {
		t.Fatalf("unedited: %v", err)
	}
	for name, edit := range map[string]func(r *cs.R1CS){
		"an instruction dropped": func(r *cs.R1CS) { r.Levels[0] = r.Levels[0][1:] },
		"an instruction scheduled twice": func(r *cs.R1CS) {
			r.Levels = append(r.Levels, []uint32{r.Levels[0][0]})
		},
		"an instruction moved to a later level": func(r *cs.R1CS) {
			last := len(r.Levels) - 1
			r.Levels[last] = append(r.Levels[last], r.Levels[0][0])
			r.Levels[0] = slices.Clone(r.Levels[0][1:])
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := build()
			edit(r)
			_, err := transcript.LocateCommitmentMasks(r)
			wantCode(t, err, failure.R1CSScheduleInvalid)
		})
	}
}

// A second setter of the mask, placed before the Randomize call, is refused:
// replaying gnark's builder sets the wire twice.
func TestScheduleRefusesASecondSetter(t *testing.T) {
	_, err := transcript.LocateCommitmentMasks(fixture.MaskSetEarlyR1CS())
	wantCode(t, err, failure.R1CSScheduleInvalid)
}

// A reader of the mask in the Randomize call's own level is refused: the
// solver could run it before the mask is set.
func TestScheduleRefusesAMaskReadBeforeItIsRandomized(t *testing.T) {
	_, err := transcript.LocateCommitmentMasks(fixture.MaskReadEarlyR1CS())
	wantCode(t, err, failure.CommitmentMaskNotRandomized)
}

type lookupCircuit struct {
	Entries [3]frontend.Variable
	Queries [2]frontend.Variable
	Results [2]frontend.Variable `gnark:",public"`
}

// A query before a deep entry is inserted, and one after: each lookup
// instruction depends on the entries the table had when it was added.
func (c *lookupCircuit) Define(api frontend.API) error {
	table := logderivlookup.New(api)
	table.Insert(c.Entries[0])
	table.Insert(c.Entries[1])
	early := table.Lookup(c.Queries[0])[0]
	table.Insert(api.Mul(api.Mul(c.Entries[2], c.Entries[2]), c.Entries[2]))
	late := table.Lookup(c.Queries[1])[0]
	api.AssertIsEqual(early, c.Results[0])
	api.AssertIsEqual(late, c.Results[1])
	return nil
}

// gnark's lookup blueprint caches its walk in unexported fields. The replay
// walks fresh copies, so a compiled circuit whose lookups are interleaved with
// inserts (its blueprint holding the builder's final cache) is accepted, twice
// on one object, and again after a round trip through its file.
func TestScheduleOfALookupCircuit(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &lookupCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	r := ccs.(*cs.R1CS)
	for i := range 2 {
		if _, err := transcript.LocateCommitmentMasks(r); err != nil {
			t.Fatalf("call %d on the compiled circuit: %v", i+1, err)
		}
	}
	path := t.TempDir() + "/lookup.r1cs"
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.WriteTo(f); err != nil {
		t.Fatal(err)
	}
	f.Close()
	back, _, err := transcript.ReadR1CS(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transcript.LocateCommitmentMasks(back); err != nil {
		t.Fatalf("read back: %v", err)
	}
}
