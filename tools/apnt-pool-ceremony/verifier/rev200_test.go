package verifier_test

// REV-200's counterexample (R-410, archive REV-200-…-evidence/tests/rev200_levels_test.go),
// made committed negatives by IMPL-31. gnark v0.16.3's solver runs only the
// instructions an R1CS's Levels list, which the file supplies. The reviewer
// compiled a circuit with gnark's Commit, appended the R1C x·1 = mask, and
// rewrote Levels to run it first: with the Randomize call dropped from Levels
// the ceremony was VALID and two proofs of one witness carried the same
// commitment; with it kept after the new setter the ceremony was VALID and the
// prover panicked. Both are now refused. The positive control proves the
// honest circuit twice and requires two different commitments.

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/internal/fixture"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/rerun"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/verifier"
)

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

func rev200Compile(t *testing.T) *cs.R1CS {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &rev200Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	return ccs.(*cs.R1CS)
}

// rev200Tamper is the reviewer's edit: it appends the R1C x·1 = mask (x the
// secret input) and rewrites Levels to run it first. dropHint also removes the
// mask's Randomize instruction from Levels.
func rev200Tamper(t *testing.T, r *cs.R1CS, dropHint bool) {
	t.Helper()
	pc := r.CommitmentInfo.(constraint.Groth16Commitments)[0].PrivateCommitted
	mask := pc[len(pc)-1] // gnark's Commit appends the mask last
	hintIdx := -1
	var hm constraint.HintMapping
	for i, pi := range r.Instructions {
		if bp, ok := r.Blueprints[pi.BlueprintID].(constraint.BlueprintHint); ok {
			bp.DecompressHint(&hm, pi.Unpack(&r.System))
			if int(hm.OutputRange.Start) <= mask && mask < int(hm.OutputRange.End) {
				hintIdx = i
			}
		}
	}
	if hintIdx < 0 {
		t.Fatal("no hint sets the mask")
	}
	x := len(r.Public) // the first secret wire
	bid := constraint.BlueprintID(len(r.Blueprints))
	for i, bp := range r.Blueprints {
		if _, ok := bp.(*constraint.BlueprintGenericR1C); ok {
			bid = constraint.BlueprintID(i)
		}
	}
	if int(bid) == len(r.Blueprints) {
		t.Fatal("no generic R1C blueprint")
	}
	var one fr.Element
	one.SetOne()
	c1 := r.FromInterface(one)
	r.AddR1C(constraint.R1C{
		L: constraint.LinearExpression{r.MakeTerm(c1, x)},
		R: constraint.LinearExpression{r.MakeTerm(c1, 0)},
		O: constraint.LinearExpression{r.MakeTerm(c1, mask)},
	}, bid)
	newIdx := uint32(len(r.Instructions) - 1)
	levels := [][]uint32{{newIdx}}
	for _, l := range r.Levels {
		l = slices.DeleteFunc(slices.Clone(l), func(i uint32) bool { return i == newIdx || (dropHint && i == uint32(hintIdx)) })
		if len(l) > 0 {
			levels = append(levels, l)
		}
	}
	r.Levels = levels
}

// rev200Ceremony runs the simulated ceremony (with its verifier) on r.
func rev200Ceremony(t *testing.T, r *cs.R1CS) (dir string, s *rerun.Summary, err error) {
	t.Helper()
	root := t.TempDir()
	r1csPath := writeR1CS(t, root, r)
	ptauPath, pin := fixture.Ptau(t, root, fixture.Power(r)+1)
	dir = filepath.Join(root, "ceremony")
	s, err = rerun.Run(rerun.Options{
		PtauPath: ptauPath, PtauPin: pin, PtauSource: "toy fixture (INSECURE)",
		R1CSPath: r1csPath, CircuitLabel: "rev200", OutDir: dir, WorkDir: filepath.Join(root, "work"),
		CeremonyID: "rev200-levels", Contributions: 1, Beacon: fixture.Beacon,
	})
	return dir, s, err
}

func TestRev200RandomizeOutsideLevelsIsRefused(t *testing.T) {
	r := rev200Compile(t)
	rev200Tamper(t, r, true)
	if _, err := transcript.LocateCommitmentMasks(r); failure.CodeOf(err) != failure.R1CSScheduleInvalid {
		t.Fatalf("locator: %v; want %s", err, failure.R1CSScheduleInvalid)
	}
	if _, s, err := rev200Ceremony(t, r); failure.CodeOf(err) != failure.R1CSScheduleInvalid {
		t.Fatalf("rerun: verdict %s, err %v; want %s", summaryVerdict(s), err, failure.R1CSScheduleInvalid)
	}
}

func TestRev200SetterScheduledFirstIsRefused(t *testing.T) {
	r := rev200Compile(t)
	rev200Tamper(t, r, false)
	if _, err := transcript.LocateCommitmentMasks(r); failure.CodeOf(err) != failure.R1CSScheduleInvalid {
		t.Fatalf("locator: %v; want %s", err, failure.R1CSScheduleInvalid)
	}
	if _, s, err := rev200Ceremony(t, r); failure.CodeOf(err) != failure.R1CSScheduleInvalid {
		t.Fatalf("rerun: verdict %s, err %v; want %s", summaryVerdict(s), err, failure.R1CSScheduleInvalid)
	}
}

// Positive control: the honest circuit's ceremony is VALID, and two proofs of
// one witness (gnark's default prover, the R1CS read back from its file)
// verify and carry different BSB22 commitments.
func TestRev200HonestMaskIsFreshPerProof(t *testing.T) {
	r := rev200Compile(t)
	dir, s, err := rev200Ceremony(t, r)
	if err != nil || s.Report == nil || s.Report.Verdict != verifier.VerdictValid {
		t.Fatalf("rerun: verdict %s, err %v", summaryVerdict(s), err)
	}
	fromFile, _, err := transcript.ReadR1CS(filepath.Join(filepath.Dir(dir), "circuit.r1cs"))
	if err != nil {
		t.Fatal(err)
	}
	pk, vk := &groth16bn254.ProvingKey{}, &groth16bn254.VerifyingKey{}
	pkb, _ := os.ReadFile(filepath.Join(dir, transcript.ProvingKeyFile))
	vkb, _ := os.ReadFile(filepath.Join(dir, transcript.VerifyingKeyFile))
	if _, err := pk.ReadFrom(bytes.NewReader(pkb)); err != nil {
		t.Fatal(err)
	}
	if _, err := vk.ReadFrom(bytes.NewReader(vkb)); err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(&rev200Circuit{X: 7, Y: 49}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := w.Public()
	var commitments [2][64]byte
	for i := range commitments {
		proof, err := groth16.Prove(fromFile, pk, w)
		if err != nil {
			t.Fatal(err)
		}
		if err := groth16.Verify(proof, vk, pub); err != nil {
			t.Fatalf("proof %d does not verify: %v", i, err)
		}
		commitments[i] = proof.(*groth16bn254.Proof).Commitments[0].RawBytes()
	}
	if commitments[0] == commitments[1] {
		t.Fatal("two proofs of one witness carry the same commitment")
	}
}
