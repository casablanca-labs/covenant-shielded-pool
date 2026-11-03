package crscheck

// The masks' origin and the schedule (origin.go): REV-197's shaped secret,
// REV-200's Levels bypass, and one negative per condition, each with a
// positive control. Toy circuits only; the hand-built ones are never proved.

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/lookup/logderivlookup"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/internal/fixture"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/testcircuits"
)

// originOf locates r's mask-shaped wires as Prepare does and returns the
// origin results: the schedule's, then one per commitment.
func originOf(t testing.TB, r *cs.R1CS) []Result {
	t.Helper()
	l, err := newLayout(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.accumulate(r, powers(frU(3), l.nbWires)); err != nil {
		t.Fatal(err)
	}
	return originResults(r, l.committed, l.masks)
}

// wantOrigin requires the schedule check to pass or fail as given and every
// commitment's origin check to pass or fail as given, with detail naming why.
func wantOrigin(t testing.TB, name string, res []Result, schedule, origin bool, why string) {
	t.Helper()
	if len(res) < 2 || res[0].Name != CheckSchedule {
		t.Fatalf("%s: results %+v", name, res)
	}
	if res[0].Pass != schedule {
		t.Errorf("%s: %s pass=%v, want %v (%s)", name, CheckSchedule, res[0].Pass, schedule, res[0].Detail)
	}
	for _, r := range res[1:] {
		if r.Name != CheckMaskOrigin || !r.ZK {
			t.Fatalf("%s: result %+v", name, r)
		}
		if r.Pass != origin {
			t.Errorf("%s: %s pass=%v, want %v (%s)", name, CheckMaskOrigin, r.Pass, origin, r.Detail)
		}
	}
	all := ""
	for _, r := range res {
		all += r.Detail + "\n"
	}
	if why != "" && !strings.Contains(all, why) {
		t.Errorf("%s: no detail says %q:\n%s", name, why, all)
	}
	t.Logf("%s: %s", name, strings.ReplaceAll(strings.TrimSpace(all), "\n", " | "))
}

// The id is the FNV-32a of the name, gnark registers Randomize under it, and
// gnark's own Commit sets the mask with it (the committed test circuit's
// origin passes).
func TestRandomizeHintIsPinned(t *testing.T) {
	h := fnv.New32a()
	h.Write([]byte(RandomizeHintName))
	if solver.HintID(h.Sum32()) != RandomizeHintID {
		t.Fatalf("FNV-32a(%q) = %#x, pinned %#x", RandomizeHintName, h.Sum32(), uint32(RandomizeHintID))
	}
	fn := solver.GetRegisteredHint(RandomizeHintID)
	if fn == nil || solver.GetHintName(fn) != RandomizeHintName || solver.GetHintID(fn) != RandomizeHintID {
		t.Fatal("gnark does not register Randomize under the pinned id")
	}
	if !randomizeRegistered() {
		t.Fatal("randomizeRegistered is false")
	}
	r, err := testcircuits.Compile("committed", 3)
	if err != nil {
		t.Fatal(err)
	}
	if r.MHintsDependencies[RandomizeHintID] != RandomizeHintName {
		t.Fatalf("gnark's Commit records %q", r.MHintsDependencies[RandomizeHintID])
	}
	wantOrigin(t, "gnark's committed circuit", originOf(t, r), true, true, "sole output of a no-input Randomize call")
}

// hand starts an R1CS like the ceremony fixtures': the one-wire, secrets x
// (1) and y (2), one internal commitment wire (3) and the generic R1C
// blueprint. A mask built by addHint(RandomizeHintID) with no input and one
// output is honest.
type hand struct {
	r   *cs.R1CS
	cw  int
	bid constraint.BlueprintID
}

func newHand() *hand {
	r := cs.NewR1CS(3)
	r.AddPublicVariable("1")
	r.AddSecretVariable("x")
	r.AddSecretVariable("y")
	cw := r.AddInternalVariable()
	return &hand{r: r, cw: cw, bid: r.AddBlueprint(&constraint.BlueprintGenericR1C{})}
}

func (h *hand) term(c uint64, w int) constraint.Term {
	return h.r.MakeTerm(h.r.FromInterface(frU(c)), w)
}

func (h *hand) r1c(l, rr, o constraint.Term) {
	h.r.AddR1C(constraint.R1C{L: constraint.LinearExpression{l}, R: constraint.LinearExpression{rr}, O: constraint.LinearExpression{o}}, h.bid)
}

func (h *hand) hint(id solver.HintID, nbOut int, inputs ...int) []int {
	fn := solver.GetRegisteredHint(id)
	var in []constraint.LinearExpression
	for _, w := range inputs {
		in = append(in, constraint.LinearExpression{h.term(1, w)})
	}
	out, err := h.r.AddSolverHint(fn, id, in, nbOut)
	if err != nil {
		panic(err)
	}
	return out
}

// commit commits to wire m with m·1 = m and adds x·x = y.
func (h *hand) commit(m int) *cs.R1CS {
	h.r1c(h.term(1, 1), h.term(1, 1), h.term(1, 2))
	h.r1c(h.term(1, m), h.term(1, 0), h.term(1, m))
	if err := h.r.AddCommitment(constraint.Groth16Commitment{PublicAndCommitmentCommitted: []int{}, PrivateCommitted: []int{m}, CommitmentIndex: h.cw}); err != nil {
		panic(err)
	}
	return h.r
}

var invZeroID = solver.GetHintID(solver.InvZeroHint)

// Each condition, with a hand-built R1CS; the first is the positive control.
func TestMaskOriginConditions(t *testing.T) {
	h := newHand()
	wantOrigin(t, "honest: a no-input Randomize output", originOf(t, h.commit(h.hint(RandomizeHintID, 1)[0])), true, true, "")

	// REV-197: an ordinary secret input with the mask's constraint shape.
	r := fixture.UnmaskedR1CS()
	r.CommitmentInfo.(constraint.Groth16Commitments)[0].PrivateCommitted[0] = 2
	wantOrigin(t, "REV-197: a secret input y with y·1 = y", originOf(t, r), true, false, "is an input")

	h = newHand()
	wantOrigin(t, "another hint's output (InvZero)", originOf(t, h.commit(h.hint(invZeroID, 1, 1)[0])), true, false, "not Randomize")

	// A no-input foreign hint beside a genuine Randomize call elsewhere, so
	// the name record is present and only the id condition refuses it.
	h = newHand()
	h.hint(RandomizeHintID, 1)
	foreign := h.hint(invZeroID, 1)[0]
	wantOrigin(t, "a no-input foreign hint beside a Randomize call", originOf(t, h.commit(foreign)), true, false, "not Randomize")

	h = newHand()
	wantOrigin(t, "Randomize called with an input", originOf(t, h.commit(h.hint(RandomizeHintID, 1, 1)[0])), true, false, "with 1 inputs")

	h = newHand()
	wantOrigin(t, "Randomize with two outputs", originOf(t, h.commit(h.hint(RandomizeHintID, 2)[0])), true, false, "not only the mask")

	h = newHand()
	r = h.commit(h.hint(RandomizeHintID, 1)[0])
	delete(r.MHintsDependencies, RandomizeHintID)
	wantOrigin(t, "no name record", originOf(t, r), true, false, "present: false")

	h = newHand()
	r = h.commit(h.hint(RandomizeHintID, 1)[0])
	r.MHintsDependencies[RandomizeHintID] = "example.com/fork.Randomize"
	wantOrigin(t, "another name recorded", originOf(t, r), true, false, "example.com/fork.Randomize")

	// Hand-built with the ceremony's fixtures: a reader scheduled with
	// Randomize in level 0, and an R1C that sets the mask first.
	wantOrigin(t, "a reader in Randomize's level", originOf(t, fixture.MaskReadEarlyR1CS()), true, false, "not after its Randomize call")
	wantOrigin(t, "an R1C setting the mask before Randomize", originOf(t, fixture.MaskSetEarlyR1CS()), false, false, "is set by instructions")

	h = newHand()
	r = h.commit(h.hint(RandomizeHintID, 1)[0])
	r.Levels[0] = append(r.Levels[0], r.Levels[0][0])
	wantOrigin(t, "an instruction scheduled twice", originOf(t, r), false, false, "differs from gnark's schedule")

	h = newHand()
	m := h.r.AddInternalVariable()
	h.r1c(h.term(1, 1), h.term(1, 0), h.term(1, m)) // x·1 = m sets m
	wantOrigin(t, "an R1C sets the mask, no hint at all", originOf(t, h.commit(m)), true, false, "not a hint")

	h = newHand()
	r = h.commit(h.hint(RandomizeHintID, 1)[0])
	r.Levels = append(r.Levels, []uint32{0})
	wantOrigin(t, "an extra level", originOf(t, r), false, false, "levels, gnark's schedule of its instructions has")

	h = newHand()
	r = h.commit(h.hint(RandomizeHintID, 1)[0])
	r.Blueprints = append(r.Blueprints, &constraint.BlueprintSparseR1CAdd[constraint.U64]{})
	wantOrigin(t, "a blueprint the replay does not know", originOf(t, r), false, false, "does not know")

	h = newHand()
	r = h.commit(h.hint(RandomizeHintID, 1)[0])
	r.CommitmentInfo.(constraint.Groth16Commitments)[0].PrivateCommitted[0] = 1
	wantOrigin(t, "no mask-shaped committed wire", originOf(t, r), true, false, "no committed wire w with a constraint w·1 = w")
}

// rev200Circuit is REV-200's: a commitment to x, and x·x = y.
type rev200Circuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *rev200Circuit) Define(api frontend.API) error {
	cm, err := api.(frontend.Committer).Commit(c.X)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(cm, 0)
	api.AssertIsEqual(api.Mul(c.X, c.X), c.Y)
	return nil
}

func rev200Compile(t testing.TB) *cs.R1CS {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &rev200Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	return ccs.(*cs.R1CS)
}

// rev200Tamper is REV-200's construction, written here from its description:
// append the R1C x·1 = mask (x the secret input), schedule it first, and
// either drop the mask's Randomize instruction from Levels (the solver never
// runs it) or keep it after the new setter.
func rev200Tamper(t testing.TB, r *cs.R1CS, dropHint bool) {
	t.Helper()
	mask := r.CommitmentInfo.(constraint.Groth16Commitments)[0].PrivateCommitted
	m := mask[len(mask)-1]
	hintIdx := -1
	for i, pi := range r.Instructions {
		if bp, ok := r.Blueprints[pi.BlueprintID].(constraint.BlueprintHint); ok {
			var hm constraint.HintMapping
			bp.DecompressHint(&hm, pi.Unpack(&r.System))
			if int(hm.OutputRange.Start) <= m && m < int(hm.OutputRange.End) {
				if hm.HintID != RandomizeHintID || hintIdx >= 0 {
					t.Fatal("the mask is not set by exactly one Randomize call")
				}
				hintIdx = i
			}
		}
	}
	if hintIdx < 0 {
		t.Fatal("no Randomize call sets the mask")
	}
	bid := ^constraint.BlueprintID(0)
	for i, bp := range r.Blueprints {
		if _, ok := bp.(*constraint.BlueprintGenericR1C); ok {
			bid = constraint.BlueprintID(i)
		}
	}
	one := r.FromInterface(frU(1))
	x := len(r.Public)
	r.AddR1C(constraint.R1C{
		L: constraint.LinearExpression{r.MakeTerm(one, x)},
		R: constraint.LinearExpression{r.MakeTerm(one, 0)},
		O: constraint.LinearExpression{r.MakeTerm(one, m)},
	}, bid)
	added := uint32(len(r.Instructions) - 1)
	levels := [][]uint32{{added}}
	for _, l := range r.Levels {
		l = slices.DeleteFunc(slices.Clone(l), func(i uint32) bool { return i == added || (dropHint && i == uint32(hintIdx)) })
		if len(l) > 0 {
			levels = append(levels, l)
		}
	}
	r.Levels = levels
}

// fromFile writes r and reads it back, as the prover and the gate get it.
func fromFile(t testing.TB, r *cs.R1CS) *cs.R1CS {
	t.Helper()
	var b bytes.Buffer
	if _, err := r.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	back := &cs.R1CS{}
	if _, err := back.ReadFrom(bytes.NewReader(b.Bytes())); err != nil {
		t.Fatal(err)
	}
	return back
}

// commitmentsOf proves the REV-200 circuit twice for x = 7 with gnark's
// default prover and returns the two BSB22 commitments, each proof verified.
func commitmentsOf(t testing.TB, r *cs.R1CS, c ceremony) (string, string, error) {
	t.Helper()
	pk, vk := loadKeys(t, c.dir)
	w, err := frontend.NewWitness(&rev200Circuit{X: 7, Y: 49}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := w.Public()
	var out [2]string
	for i := range out {
		// gnark's solver panics, rather than returning an error, on a wire
		// set twice.
		proof, err := func() (p groth16.Proof, err error) {
			defer func() {
				if e := recover(); e != nil {
					err = fmt.Errorf("prover panicked: %v", e)
				}
			}()
			return groth16.Prove(r, pk, w)
		}()
		if err != nil {
			return "", "", err
		}
		if err := groth16.Verify(proof, vk, pub); err != nil {
			t.Fatalf("proof %d does not verify: %v", i, err)
		}
		b := proof.(*groth16bn254.Proof).Commitments[0].Bytes()
		out[i] = string(b[:])
	}
	return out[0], out[1], nil
}

// REV-200's Levels bypass, end to end on toy keys sealed directly: the
// tampered circuit really makes a deterministic commitment (the attack is
// real), its keys are otherwise well formed, and the checker refuses it on
// R1CS_SCHEDULE. The honest circuit's commitments differ and it passes.
func TestLevelsBypassIsRefused(t *testing.T) {
	honest := fromFile(t, rev200Compile(t))
	good := sealR1CS(t, t.TempDir(), honest, frU(fixture.ToyTau), frU(fixture.ToyAlpha), frU(fixture.ToyBeta), "rev200", 0)
	a, b, err := commitmentsOf(t, honest, good)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("honest circuit: two proofs of one witness carry the same commitment")
	}
	pk, vk := loadKeys(t, good.dir)
	if rep := check(t, plan(t, good), pk, vk); rep.Verdict != VerdictWellFormed || len(failedNames(rep)) != 0 {
		t.Fatalf("honest circuit: %v", failedNames(rep))
	}

	for _, drop := range []bool{true, false} {
		r := rev200Compile(t)
		rev200Tamper(t, r, drop)
		r = fromFile(t, r)
		bad := sealR1CS(t, t.TempDir(), r, frU(fixture.ToyTau), frU(fixture.ToyAlpha), frU(fixture.ToyBeta), "rev200", 0)
		a, b, err := commitmentsOf(t, r, bad)
		switch {
		case drop && (err != nil || a != b):
			t.Fatalf("Randomize dropped from Levels: err %v, commitments equal %v; the attack did not reproduce", err, a == b)
		case !drop && err == nil:
			t.Fatal("R1C setter scheduled before Randomize: the prover did not refuse the double set")
		}
		pk, vk := loadKeys(t, bad.dir)
		rep := check(t, plan(t, bad), pk, vk)
		f := failedNames(rep)
		if rep.Verdict != VerdictMalformed || !slices.Contains(f, CheckSchedule) || !slices.Contains(f, CheckMaskOrigin) {
			t.Fatalf("dropHint=%v: verdict %s, failed %v", drop, rep.Verdict, f)
		}
		// Every other check passes: only the schedule and origin see it.
		for _, n := range f {
			if n != CheckSchedule && n != CheckMaskOrigin {
				t.Errorf("dropHint=%v: %s also failed", drop, n)
			}
		}
		t.Logf("dropHint=%v: prove err %v, commitments equal %v; failed %v", drop, err, err == nil && a == b, f)
	}
}

// The 5.1c action R1CS, when present, passes both checks. Skipped without
// the file (CRSCHECK_REAL_R1CS names it); it takes about 3 GiB.
func TestRealR1CSOrigin(t *testing.T) {
	path := os.Getenv("CRSCHECK_REAL_R1CS")
	if path == "" {
		t.Skip("CRSCHECK_REAL_R1CS not set")
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := &cs.R1CS{}
	if _, err := r.ReadFrom(f); err != nil {
		t.Fatal(err)
	}
	wantOrigin(t, "5.1c", originOf(t, r), true, true, "")
}

// pick never loops (ENG-447): with every index avoided it returns -1, and a
// key whose commitment commits only its mask gets no basis or σ control
// rather than a control loop that never ends.
func TestPickNeverLoops(t *testing.T) {
	for _, c := range []struct {
		n     int
		avoid []int
		want  int
	}{
		{0, nil, -1}, {1, []int{0}, -1}, {3, []int{0, 1, 2}, -1},
		{5, nil, 2}, {5, []int{2}, 3}, {5, []int{2, 3, 4}, 0}, {1, nil, 0},
	} {
		if got := pick(c.n, c.avoid); got != c.want {
			t.Errorf("pick(%d, %v) = %d, want %d", c.n, c.avoid, got, c.want)
		}
	}
	r := fixture.MaskFromHintR1CS(RandomizeHintID)
	c := sealR1CS(t, t.TempDir(), r, frU(fixture.ToyTau), frU(fixture.ToyAlpha), frU(fixture.ToyBeta), "mask-only", 0)
	pk, _ := loadKeys(t, c.dir)
	p := plan(t, c)
	if len(p.Masks[0]) != 1 || len(pk.CommitmentKeys[0].Basis) != 1 {
		t.Fatalf("masks %v, basis %d: want the mask as the only committed wire", p.Masks, len(pk.CommitmentKeys[0].Basis))
	}
	cl, err := p.Controls(pk)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, ctl := range cl {
		names = append(names, ctl.Name)
	}
	if slices.Contains(names, "commitment-basis-perturbed") || slices.Contains(names, "commitment-sigma-perturbed") || !slices.Contains(names, "commitment-mask-zeroed") {
		t.Fatalf("controls %v", names)
	}
}

// lookupCircuit interleaves table inserts with lookups, so gnark's lookup
// blueprint walks its table in steps while the circuit is built; the log-
// derivative argument commits (a mask of its own).
type lookupCircuit struct {
	X, Y frontend.Variable
	Z    frontend.Variable `gnark:",public"`
}

func (c *lookupCircuit) Define(api frontend.API) error {
	tb := logderivlookup.New(api)
	tb.Insert(5)
	tb.Insert(7)
	a := tb.Lookup(c.X)[0]
	b := api.Mul(a, a)
	tb.Insert(b)
	d := tb.Lookup(c.Y)[0]
	api.AssertIsEqual(api.Add(a, d), c.Z)
	return nil
}

// A compiled circuit with lookups passes the schedule replay both as built
// (its lookup blueprint still carries the builder's walk cache, which the
// replay must not reuse) and as read from a file.
func TestLookupScheduleReplays(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &lookupCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	r := ccs.(*cs.R1CS)
	lookups := 0
	for _, bp := range r.Blueprints {
		if _, ok := bp.(*constraint.BlueprintLookupHint[constraint.U64]); ok {
			lookups++
		}
	}
	if lookups == 0 {
		t.Fatal("the circuit has no lookup blueprint")
	}
	wantOrigin(t, "lookups, as built", originOf(t, r), true, true, "")
	wantOrigin(t, "lookups, from a file", originOf(t, fromFile(t, r)), true, true, "")
}
