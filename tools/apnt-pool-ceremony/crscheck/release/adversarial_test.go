package release

// Keys the project's ceremony refuses (a degenerate phase 1, a mask that is
// not random, a doctored schedule), given a consistent record that says
// VALID: what a ceremony and verifier without those refusals, or sharing a
// defect, would publish. The gate's own checks are then all that stands
// between such a key and RELEASE-OK. INSECURE toy phase 1 only.

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/crscheck"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/internal/fixture"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/testcircuits"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/verifier"
)

// forge seals keys for r on a toy phase 1 with gnark's mpcsetup directly and
// writes a complete record for them: a sealed transcript, its key metadata,
// and a VALID, doubly anchored verifier report from a verified build naming
// the transcript's digest, every field written out here from the
// transcript. It returns complete gate inputs with the true digests.
func forge(t testing.TB, r *cs.R1CS, label string, tau, alpha, beta fr.Element) Inputs {
	t.Helper()
	dir := t.TempDir()
	r1csPath := filepath.Join(dir, label+".r1cs")
	if err := testcircuits.WriteR1CS(r1csPath, r); err != nil {
		t.Fatal(err)
	}
	power := fixture.Power(r)
	ptauPath := filepath.Join(dir, "toy.ptau")
	f, err := os.Create(ptauPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := ptau.Write(f, toyCommons(power, tau, alpha, beta)); err != nil {
		t.Fatal(err)
	}
	f.Close()
	commons := toyCommons(power, tau, alpha, beta)
	var p mpcsetup.Phase2
	evals := p.Initialize(r, commons)
	p.Contribute()
	pk, vk := p.Seal(commons, &evals, []byte("forged record"))
	var pb, vb bytes.Buffer
	if _, err := pk.(*groth16bn254.ProvingKey).WriteRawTo(&pb); err != nil {
		t.Fatal(err)
	}
	if _, err := vk.WriteTo(&vb); err != nil {
		t.Fatal(err)
	}
	pkPath, vkPath := filepath.Join(dir, transcript.ProvingKeyFile), filepath.Join(dir, transcript.VerifyingKeyFile)
	os.WriteFile(pkPath, pb.Bytes(), 0o644)
	os.WriteFile(vkPath, vb.Bytes(), 0o644)

	pin := fixture.PinOf(t, ptauPath)
	nbInternal, nbSecret, nbPublic := r.GetNbVariables()
	hex := func(c string) string { return strings.Repeat(c, 64) }
	tr := transcript.Transcript{
		Format: transcript.Format, Status: transcript.StatusSealed, CeremonyID: "forged-" + label,
		Provenance: transcript.SimulatedSingleParty, ZeroValueOnly: true, Notice: transcript.SimulatedNotice,
		Tool: transcript.CurrentTool,
		Phase1: transcript.Phase1{Source: "toy fixture (INSECURE)", File: "toy.ptau", FileSize: int64(len(mustRead(t, ptauPath))),
			Pin: pin, Power: power, DomainSize: uint64(crscheck.Domain(r)), CommonsSHA256: hex("c")},
		Circuit: transcript.Circuit{Label: label, R1CSSHA256: sha(t, r1csPath), NbConstraints: r.GetNbConstraints(),
			NbPublic: nbPublic, NbSecret: nbSecret, NbInternal: nbInternal,
			NbCommitments: len(r.CommitmentInfo.(constraint.Groth16Commitments))},
		Phase2: transcript.Phase2Record{RootChallenge: hex("a"), InitialStateSHA256: hex("b"), StateLength: 1,
			Contributions: []transcript.Contribution{{Index: 1, File: "phase2-0001.bin", StateSHA256: hex("d"), Challenge: hex("b"),
				Contributor: transcript.Contributor{ID: "automated-01", Kind: transcript.KindAutomatedLocal}}}},
		Beacon: &fixture.Beacon,
		Keys: &transcript.Keys{
			ProvingKey:   transcript.KeyFile{File: transcript.ProvingKeyFile, SHA256: digest(pb.Bytes()), Encoding: transcript.ProvingKeyEncoding},
			VerifyingKey: transcript.KeyFile{File: transcript.VerifyingKeyFile, SHA256: digest(vb.Bytes()), Encoding: transcript.VerifyingKeyEncoding},
			Metadata:     transcript.KeyMetadataFile,
		},
	}
	trPath, metaPath := filepath.Join(dir, transcript.TranscriptFile), filepath.Join(dir, transcript.KeyMetadataFile)
	if err := transcript.WriteJSON(trPath, &tr); err != nil {
		t.Fatal(err)
	}
	meta := transcript.MetadataFor(&tr)
	if err := transcript.WriteJSON(metaPath, &meta); err != nil {
		t.Fatal(err)
	}
	rep := verifier.Report{
		Verdict: verifier.VerdictValid, Anchors: verifier.Anchors{Phase1Pin: true, Beacon: true},
		Provenance: tr.Provenance, ZeroValueOnly: tr.ZeroValueOnly, Notice: tr.Notice, CeremonyID: tr.CeremonyID,
		CircuitLabel: label, R1CSSHA256: tr.Circuit.R1CSSHA256, NbConstraints: tr.Circuit.NbConstraints,
		Phase1Pin: pin, Phase1CommonsSHA256: tr.Phase1.CommonsSHA256, DomainSize: tr.Phase1.DomainSize,
		Contributions: []verifier.ReportContribution{{Index: 1, StateSHA256: hex("d"), Contributor: tr.Phase2.Contributions[0].Contributor}},
		Beacon:        fixture.Beacon, ProvingKeySHA256: tr.Keys.ProvingKey.SHA256, VerifyingKeySHA256: tr.Keys.VerifyingKey.SHA256,
		TranscriptSHA256: sha(t, trPath), VerifierBuild: verifiedBuild(),
	}
	repPath := filepath.Join(dir, "verify.stdout")
	return Inputs{
		ProvingKey: pkPath, VerifyingKey: vkPath, R1CS: r1csPath, Ptau: ptauPath,
		Transcript: trPath, KeyMetadata: metaPath, CeremonyReport: repPath,
		ProvingKeySHA256: tr.Keys.ProvingKey.SHA256, VerifyingKeySHA256: tr.Keys.VerifyingKey.SHA256,
		R1CSSHA256: tr.Circuit.R1CSSHA256, PtauSHA256: pin.Digest, CeremonyReportSHA256: writeVerifierReport(t, repPath, &rep),
	}
}

func mustRead(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func toy() (tau, alpha, beta fr.Element) {
	return frU(fixture.ToyTau), frU(fixture.ToyAlpha), frU(fixture.ToyBeta)
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

// rev200Bypass compiles REV-200's circuit, appends the R1C x·1 = mask,
// schedules it first and drops the mask's Randomize instruction from Levels.
// gnark's prover on it makes verifying proofs whose commitment is the same
// for one witness (crscheck's TestLevelsBypassIsRefused shows it).
func rev200Bypass(t testing.TB) *cs.R1CS {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &rev200Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	r := ccs.(*cs.R1CS)
	pc := r.CommitmentInfo.(constraint.Groth16Commitments)[0].PrivateCommitted
	m := pc[len(pc)-1]
	hintIdx := -1
	for i, pi := range r.Instructions {
		if bp, ok := r.Blueprints[pi.BlueprintID].(constraint.BlueprintHint); ok {
			var hm constraint.HintMapping
			bp.DecompressHint(&hm, pi.Unpack(&r.System))
			if int(hm.OutputRange.Start) <= m && m < int(hm.OutputRange.End) && hm.HintID == crscheck.RandomizeHintID {
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
		l = slices.DeleteFunc(slices.Clone(l), func(i uint32) bool { return i == added || i == uint32(hintIdx) })
		if len(l) > 0 {
			levels = append(levels, l)
		}
	}
	r.Levels = levels
	return r
}

// shapedSecretR1CS is REV-197's attack with room for the controls: secret
// inputs x (1), y (2) and z (3), a commitment to x and y, and
//
//	0: x·x = y      1: y·1 = y      2: z·z = x
//
// y has the mask's constraint shape but is an ordinary secret input, not a
// Randomize output: the commitment has no randomness. z is a private wire
// outside the commitment, so the key has a K element for the controls.
// (REV-198's exact construction, a commitment to y alone, leaves no
// committed wire but the mask candidate; see TestPickNeverLoops.)
func shapedSecretR1CS() *cs.R1CS {
	r := cs.NewR1CS(3)
	r.AddPublicVariable("1")
	for _, n := range []string{"x", "y", "z"} {
		r.AddSecretVariable(n)
	}
	cw := r.AddInternalVariable()
	bid := r.AddBlueprint(&constraint.BlueprintGenericR1C{})
	one := r.FromInterface(frU(1))
	term := func(w int) constraint.LinearExpression { return constraint.LinearExpression{r.MakeTerm(one, w)} }
	r.AddR1C(constraint.R1C{L: term(1), R: term(1), O: term(2)}, bid)
	r.AddR1C(constraint.R1C{L: term(2), R: term(0), O: term(2)}, bid)
	r.AddR1C(constraint.R1C{L: term(3), R: term(3), O: term(1)}, bid)
	if err := r.AddCommitment(constraint.Groth16Commitment{PublicAndCommitmentCommitted: []int{}, PrivateCommitted: []int{1, 2}, CommitmentIndex: cw}); err != nil {
		panic(err)
	}
	return r
}

// REV-198 H2 and REV-200 H1 at the release level. Each record is otherwise
// consistent (transcript, key metadata, a VALID report from a verified
// build naming the transcript), and each key is otherwise well formed; only
// the mask's origin or the schedule refuses it. The positive control is the
// same forged record for an honest compiled circuit, which is released.
func TestNonRandomMasksAreRefused(t *testing.T) {
	tau, alpha, beta := toy()
	honest, err := testcircuits.Compile("committed", 3)
	if err != nil {
		t.Fatal(err)
	}
	if rep := Run(forge(t, honest, "committed", tau, alpha, beta)); rep.Statement.Verdict != VerdictReleaseOK {
		t.Fatalf("honest circuit with a forged record: %+v", rep.Statement.Refusals)
	}

	rev198 := fixture.UnmaskedR1CS() // REV-198's exact construction: a commitment to y alone
	rev198.CommitmentInfo.(constraint.Groth16Commitments)[0].PrivateCommitted[0] = 2
	for _, c := range []struct {
		name   string
		r      *cs.R1CS
		checks []string
	}{
		{"REV-198's exact case: a commitment to y alone, y·1 = y", rev198, []string{crscheck.CheckMaskOrigin}},
		{"REV-197/REV-198: a secret input shaped like a mask, beside x", shapedSecretR1CS(), []string{crscheck.CheckMaskOrigin}},
		{"REV-200: Randomize left out of Levels, the mask set from x", rev200Bypass(t), []string{crscheck.CheckSchedule, crscheck.CheckMaskOrigin}},
	} {
		rep := Run(forge(t, c.r, "adversarial", tau, alpha, beta))
		wantRefused(t, c.name, rep, CodeMalformed)
		var failed []string
		for _, r := range rep.Statement.Checks {
			if !r.Pass {
				failed = append(failed, r.Name)
			}
		}
		if !reflect.DeepEqual(failed, c.checks) {
			t.Errorf("%s: failed checks %v, want exactly %v", c.name, failed, c.checks)
		}
	}
}

// unverifiedBuild, one field at a time; the clean record passes.
func TestUnverifiedBuildFields(t *testing.T) {
	if why := unverifiedBuild(verifiedBuild()); why != "" {
		t.Fatalf("a verified build refused: %s", why)
	}
	for _, c := range []struct {
		name string
		edit func(*verifier.Build)
		says string
	}{
		{"status unverified", func(b *verifier.Build) { b.Status = verifier.BuildUnverified }, "status"},
		{"a reason given", func(b *verifier.Build) { b.Reason = "x" }, "reason"},
		{"another module", func(b *verifier.Build) { b.Module = "example.com/fork" }, "module"},
		{"no revision", func(b *verifier.Build) { b.VCSRevision = "" }, "vcsRevision"},
		{"a short revision", func(b *verifier.Build) { b.VCSRevision = "54e0a074" }, "vcsRevision"},
		{"a modified tree", func(b *verifier.Build) { b.VCSModified = "true" }, "vcsModified"},
		{"vcs.modified not recorded", func(b *verifier.Build) { b.VCSModified = "" }, "vcsModified"},
		{"another gnark", func(b *verifier.Build) { b.Gnark = "v0.16.4" }, "gnark"},
		{"another gnark-crypto", func(b *verifier.Build) { b.GnarkCrypto = "v0.21.1" }, "gnark-crypto"},
		{"the zero value (an output without the field)", func(b *verifier.Build) { *b = verifier.Build{} }, "status"},
	} {
		b := verifiedBuild()
		c.edit(&b)
		if why := unverifiedBuild(b); why == "" || !strings.Contains(why, c.says) {
			t.Errorf("%s: %q", c.name, why)
		}
	}
}

// pinnedExit is the public contract of the refusal codes and exit statuses,
// written as literals, independent of Codes and ExitOf (REV-198 H3).
var pinnedExit = map[string]int{
	"CHECKER_BUILD_UNVERIFIED":        10,
	"TRANSCRIPT_INVALID":              11,
	"KEY_METADATA_MISMATCH":           12,
	"CEREMONY_REPORT_DIGEST_MISMATCH": 13,
	"CEREMONY_NOT_VALID":              14,
	"CEREMONY_REPORT_MISMATCH":        15,
	"GNARK_VERSION_MISMATCH":          16,
	"R1CS_DIGEST_MISMATCH":            17,
	"PTAU_PIN_MISMATCH":               18,
	"VK_DIGEST_MISMATCH":              19,
	"PK_DIGEST_MISMATCH":              20,
	"INPUT_UNREADABLE":                21,
	"CRS_MALFORMED":                   22,
	"CHECK_INCOMPLETE":                23,
	"ANCILLARY_CHECK_FAILED":          24,
	"NEGATIVE_CONTROL_NOT_FIRED":      25,
	"CEREMONY_REPORT_UNBOUND":         26,
	"CEREMONY_VERIFIER_UNVERIFIED":    27,
}

// Every constant spells its literal, has its literal status, and Codes lists
// exactly the pinned codes in the pinned order (by status).
func TestCodeExitLiteralsArePinned(t *testing.T) {
	for _, c := range []struct {
		code    Code
		literal string
	}{
		{CodeCheckerBuild, "CHECKER_BUILD_UNVERIFIED"},
		{CodeTranscript, "TRANSCRIPT_INVALID"},
		{CodeKeyMetadata, "KEY_METADATA_MISMATCH"},
		{CodeReportDigest, "CEREMONY_REPORT_DIGEST_MISMATCH"},
		{CodeCeremonyNotValid, "CEREMONY_NOT_VALID"},
		{CodeReportMismatch, "CEREMONY_REPORT_MISMATCH"},
		{CodeGnarkVersion, "GNARK_VERSION_MISMATCH"},
		{CodeR1CSDigest, "R1CS_DIGEST_MISMATCH"},
		{CodePtauPin, "PTAU_PIN_MISMATCH"},
		{CodeVKDigest, "VK_DIGEST_MISMATCH"},
		{CodePKDigest, "PK_DIGEST_MISMATCH"},
		{CodeUnreadable, "INPUT_UNREADABLE"},
		{CodeMalformed, "CRS_MALFORMED"},
		{CodeIncomplete, "CHECK_INCOMPLETE"},
		{CodeAncillary, "ANCILLARY_CHECK_FAILED"},
		{CodeControl, "NEGATIVE_CONTROL_NOT_FIRED"},
		{CodeReportUnbound, "CEREMONY_REPORT_UNBOUND"},
		{CodeVerifierUnverified, "CEREMONY_VERIFIER_UNVERIFIED"},
	} {
		if string(c.code) != c.literal {
			t.Errorf("constant spells %q, pinned %q", c.code, c.literal)
		}
		if got := ExitOf(Code(c.literal)); got != pinnedExit[c.literal] {
			t.Errorf("%s exits %d, pinned %d", c.literal, got, pinnedExit[c.literal])
		}
	}
	if len(Codes) != len(pinnedExit) {
		t.Fatalf("%d codes, %d pinned", len(Codes), len(pinnedExit))
	}
	for i, e := range Codes {
		if want, ok := pinnedExit[string(e.Code)]; !ok || e.Exit != want || e.Exit != 10+i {
			t.Errorf("Codes[%d] = %s %d, pinned %d at status %d", i, e.Code, e.Exit, want, 10+i)
		}
	}
}
