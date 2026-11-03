package transcript

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark/constraint"
)

// On a real R1CS (APNT_CEREMONY_R1CS, e.g. the 5.1c action circuit): the
// mask check, schedule included, accepts it, and the file's Levels are the
// schedule its instructions give. Read-only; no key, no proof.
func TestRealR1CSSchedule(t *testing.T) {
	path := os.Getenv("APNT_CEREMONY_R1CS")
	if path == "" {
		t.Skip("APNT_CEREMONY_R1CS not set: real-R1CS schedule check not exercised")
	}
	t0 := time.Now()
	r, sha, err := ReadR1CS(path)
	if err != nil {
		t.Fatal(err)
	}
	read := time.Since(t0)
	t0 = time.Now()
	m, err := LocateCommitmentMasks(r)
	if err != nil {
		t.Fatal(err)
	}
	locate := time.Since(t0)
	committed := r.CommitmentInfo.(constraint.Groth16Commitments)
	watch := map[int]bool{}
	for k, ps := range m.Positions {
		for _, p := range ps {
			watch[committed[k].PrivateCommitted[p]] = true
		}
	}
	levels, at, touched, err := replaySchedule(r, watch)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("r1cs %s: read %.2f s, LocateCommitmentMasks (provenance and schedule) %.2f s", sha, read.Seconds(), locate.Seconds())
	t.Logf("%d instructions, %d levels (file %d), masks %+v", len(r.Instructions), len(levels), len(r.Levels), m)
	_, randomizeOf := maskProvenance(r, watch)
	for w, h := range randomizeOf {
		minOther := -1
		for _, i := range touched[w] {
			if i != h && (minOther < 0 || at[i] < minOther) {
				minOther = at[i]
			}
		}
		t.Logf("mask wire %d: Randomize instruction %d at level %d; %d instructions reference it, the earliest other at level %d", w, h, at[h], len(touched[w]), minOther)
	}
	types := map[string]int{}
	for _, pi := range r.Instructions {
		types[typeName(r.Blueprints[pi.BlueprintID])]++
	}
	t.Logf("instructions by blueprint: %v", types)
}

func typeName(b constraint.Blueprint) string {
	return fmt.Sprintf("%T", b)
}
