package release

// Toy ceremonies only: every key here is made by the project's own simulated
// ceremony (rerun) on INSECURE toy phase-1 files whose τ, α, β are public
// constants. Run under the machine-wide prover lock.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
	"time"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/crscheck"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/internal/fixture"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/rerun"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/testcircuits"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/verifier"
)

// cleanRecords is build info whose records are what go build records for the
// gate at an unmodified revision: this module, the pinned gnark versions
// among unrelated modules, a revision and vcs.modified=false.
func cleanRecords() *debug.BuildInfo {
	return &debug.BuildInfo{
		Path: MainModule + "/crscheck/cmd/apnt-pool-crscheck",
		Main: debug.Module{Path: MainModule, Version: "(devel)"},
		Deps: []*debug.Module{
			{Path: "github.com/bits-and-blooms/bitset", Version: "v1.24.6"},
			{Path: gnarkModule, Version: crscheck.GnarkVersion},
			{Path: gnarkCryptoModule, Version: crscheck.GnarkCryptoVersion},
			{Path: "golang.org/x/sys", Version: "v0.47.0"},
		},
		Settings: []debug.BuildSetting{
			{Key: "vcs", Value: "git"},
			{Key: "vcs.revision", Value: strings.Repeat("0123456789", 4)},
			{Key: "vcs.time", Value: "2026-09-25T00:00:00Z"},
			{Key: "vcs.modified", Value: "false"},
		},
	}
}

// TestMain gives this package's tests a record source: a go test binary lists
// no dependencies and records no revision, so the real source refuses every
// run in it (see the command's TestGoTestBinaryIsRefused).
func TestMain(m *testing.M) {
	readBuildInfo = func() (*debug.BuildInfo, bool) { return cleanRecords(), true }
	os.Exit(m.Run())
}

func frU(v uint64) fr.Element {
	var e fr.Element
	e.SetUint64(v)
	return e
}

// toyCommons is ptau.ToyCommons with field-element scalars, so a test can
// choose β = −1 or τ = ω. INSECURE by construction.
func toyCommons(power uint32, tau, alpha, beta fr.Element) *mpcsetup.SrsCommons {
	n := 1 << power
	pows := make([]fr.Element, 2*n-1)
	pows[0].SetOne()
	for i := 1; i < len(pows); i++ {
		pows[i].Mul(&pows[i-1], &tau)
	}
	ap, bp := make([]fr.Element, n), make([]fr.Element, n)
	for i := 0; i < n; i++ {
		ap[i].Mul(&pows[i], &alpha)
		bp[i].Mul(&pows[i], &beta)
	}
	_, _, g1, g2 := curve.Generators()
	var c mpcsetup.SrsCommons
	c.G1.Tau = curve.BatchScalarMultiplicationG1(&g1, pows)
	c.G2.Tau = curve.BatchScalarMultiplicationG2(&g2, pows[:n])
	c.G1.AlphaTau = curve.BatchScalarMultiplicationG1(&g1, ap)
	c.G1.BetaTau = curve.BatchScalarMultiplicationG1(&g1, bp)
	c.G2.Beta = curve.BatchScalarMultiplicationG2(&g2, []fr.Element{beta})[0]
	return &c
}

func sha(t testing.TB, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return digest(b)
}

// writeVerifierReport writes rep the way apnt-pool-ceremony-verify --json does.
func writeVerifierReport(t testing.TB, path string, rep any) string {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return digest(buf.Bytes())
}

// runToy runs the project's simulated ceremony (init, two contributions,
// seal, then its standalone verifier anchored to the pin and beacon) on a toy
// phase-1 file, archives the verifier's report as the CLI prints it, and
// returns complete gate inputs whose out-of-band digests are the true ones.
func runToy(t testing.TB, name string, size int, tau, alpha, beta fr.Element) Inputs {
	t.Helper()
	dir := t.TempDir()
	r1csPath, r := fixture.R1CS(t, dir, name, size)
	ptauPath := filepath.Join(dir, "toy.ptau")
	f, err := os.Create(ptauPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := ptau.Write(f, toyCommons(fixture.Power(r), tau, alpha, beta)); err != nil {
		t.Fatal(err)
	}
	f.Close()
	pin := fixture.PinOf(t, ptauPath)
	out := filepath.Join(dir, "ceremony")
	s, err := rerun.Run(rerun.Options{
		PtauPath: ptauPath, PtauPin: pin, PtauSource: "toy fixture (INSECURE)",
		R1CSPath: r1csPath, CircuitLabel: name, OutDir: out, CeremonyID: "crs-release-" + name,
		Contributions: 2, Beacon: fixture.Beacon,
	})
	if err != nil {
		t.Fatalf("ceremony: %v", err)
	}
	if !s.Report.Authoritative() {
		t.Fatalf("ceremony verdict %s", s.Report.Verdict)
	}
	if s.Report.TranscriptSHA256 != sha(t, filepath.Join(out, transcript.TranscriptFile)) {
		t.Fatal("the verifier's report does not name the transcript it read")
	}
	// A go test binary's verifier build is unverified (no dependency records,
	// no VCS revision); the archived output of a clean-clone verifier build
	// records a verified one, which the fixture substitutes here.
	s.Report.VerifierBuild = verifiedBuild()
	reportPath := filepath.Join(dir, "verify.stdout")
	reportSHA := writeVerifierReport(t, reportPath, s.Report)
	pkPath, vkPath := filepath.Join(out, transcript.ProvingKeyFile), filepath.Join(out, transcript.VerifyingKeyFile)
	return Inputs{
		ProvingKey: pkPath, VerifyingKey: vkPath, R1CS: r1csPath, Ptau: ptauPath,
		Transcript: filepath.Join(out, transcript.TranscriptFile), KeyMetadata: filepath.Join(out, transcript.KeyMetadataFile),
		CeremonyReport:   reportPath,
		ProvingKeySHA256: sha(t, pkPath), VerifyingKeySHA256: sha(t, vkPath), R1CSSHA256: sha(t, r1csPath),
		PtauSHA256: pin.Digest, CeremonyReportSHA256: reportSHA,
	}
}

// verifiedBuild is the verifier build a clean clone of this module records
// (ENG-443): status verified, a revision, vcs.modified false, crscheck's
// gnark.
func verifiedBuild() verifier.Build {
	return verifier.Build{Status: verifier.BuildVerified, Module: MainModule, VCSRevision: strings.Repeat("0123456789abcdef", 2) + "01234567",
		VCSModified: "false", Gnark: crscheck.GnarkVersion, GnarkCrypto: crscheck.GnarkCryptoVersion}
}

// rebind makes the verifier's report name the transcript as it now is, as a
// verifier that read the edited transcript would, and re-pins the report.
func rebind(t testing.TB, in *Inputs) {
	t.Helper()
	var rep verifier.Report
	b, _ := os.ReadFile(in.CeremonyReport)
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	rep.TranscriptSHA256 = sha(t, in.Transcript)
	in.CeremonyReportSHA256 = writeVerifierReport(t, in.CeremonyReport, &rep)
}

func honestToy(t testing.TB) Inputs {
	return runToy(t, "committed", 3, frU(fixture.ToyTau), frU(fixture.ToyAlpha), frU(fixture.ToyBeta))
}

// copyRecord copies the small ceremony records (transcript, key metadata,
// verifier report) and both keys into a fresh directory, so a case can edit
// them without touching the original ceremony.
func copyRecord(t testing.TB, in Inputs) Inputs {
	t.Helper()
	dir := t.TempDir()
	cp := func(src, name string) string {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(dir, name)
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return dst
	}
	in.Transcript = cp(in.Transcript, transcript.TranscriptFile)
	in.KeyMetadata = cp(in.KeyMetadata, transcript.KeyMetadataFile)
	in.CeremonyReport = cp(in.CeremonyReport, "verify.stdout")
	in.ProvingKey = cp(in.ProvingKey, transcript.ProvingKeyFile)
	in.VerifyingKey = cp(in.VerifyingKey, transcript.VerifyingKeyFile)
	return in
}

func editJSON[T any](t testing.TB, path string, edit func(*T)) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	edit(&v)
	if err := transcript.WriteJSON(path, &v); err != nil {
		t.Fatal(err)
	}
}

// reissue models ceremony tooling and a verifier that share a defect: it
// applies mutate to the sealed keys, rewrites the key files, and rewrites the
// transcript, the key metadata, the verifier's VALID report and the
// out-of-band digests so that every record agrees on the new keys.
func reissue(t testing.TB, in Inputs, mutate func(pk *groth16bn254.ProvingKey, vk *groth16bn254.VerifyingKey)) Inputs {
	t.Helper()
	in = copyRecord(t, in)
	pk, vk := &groth16bn254.ProvingKey{}, &groth16bn254.VerifyingKey{}
	pkb, _ := os.ReadFile(in.ProvingKey)
	vkb, _ := os.ReadFile(in.VerifyingKey)
	if _, err := pk.ReadFrom(bytes.NewReader(pkb)); err != nil {
		t.Fatal(err)
	}
	if _, err := vk.ReadFrom(bytes.NewReader(vkb)); err != nil {
		t.Fatal(err)
	}
	mutate(pk, vk)
	var pb, vb bytes.Buffer
	if _, err := pk.WriteRawTo(&pb); err != nil {
		t.Fatal(err)
	}
	if _, err := vk.WriteTo(&vb); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in.ProvingKey, pb.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in.VerifyingKey, vb.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	in.ProvingKeySHA256, in.VerifyingKeySHA256 = digest(pb.Bytes()), digest(vb.Bytes())
	editJSON(t, in.Transcript, func(tr *transcript.Transcript) {
		tr.Keys.ProvingKey.SHA256, tr.Keys.VerifyingKey.SHA256 = in.ProvingKeySHA256, in.VerifyingKeySHA256
	})
	tr, err := transcript.Load(in.Transcript)
	if err != nil {
		t.Fatal(err)
	}
	meta := transcript.MetadataFor(tr)
	if err := transcript.WriteJSON(in.KeyMetadata, &meta); err != nil {
		t.Fatal(err)
	}
	var rep verifier.Report
	b, _ := os.ReadFile(in.CeremonyReport)
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	rep.ProvingKeySHA256, rep.VerifyingKeySHA256 = in.ProvingKeySHA256, in.VerifyingKeySHA256
	rep.TranscriptSHA256 = sha(t, in.Transcript)
	in.CeremonyReportSHA256 = writeVerifierReport(t, in.CeremonyReport, &rep)
	return in
}

// rerecord edits the ceremony's record consistently, as a ceremony whose
// own tooling wrote it would: the transcript by editT, the verifier's report
// by editR and naming the edited transcript (its digest re-pinned), and
// keys.meta.json regenerated from the edited transcript by the module's own
// transcript.MetadataFor. Only the edit itself can then be refused.
func rerecord(t testing.TB, in *Inputs, editT func(*transcript.Transcript), editR func(*verifier.Report)) {
	t.Helper()
	editJSON(t, in.Transcript, editT)
	var tr transcript.Transcript
	b, _ := os.ReadFile(in.Transcript)
	if err := json.Unmarshal(b, &tr); err != nil {
		t.Fatal(err)
	}
	meta := transcript.MetadataFor(&tr)
	if err := transcript.WriteJSON(in.KeyMetadata, &meta); err != nil {
		t.Fatal(err)
	}
	var rep verifier.Report
	b, _ = os.ReadFile(in.CeremonyReport)
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	editR(&rep)
	rep.TranscriptSHA256 = sha(t, in.Transcript)
	in.CeremonyReportSHA256 = writeVerifierReport(t, in.CeremonyReport, &rep)
}

func codes(rep *Report) []Code { return rep.Codes() }

func wantRefused(t testing.TB, name string, rep *Report, want ...Code) {
	t.Helper()
	t.Logf("%s: exit %d, %+v", name, rep.ExitStatus(), rep.Statement.Refusals)
	if got := codes(rep); !reflect.DeepEqual(got, want) {
		t.Errorf("%s: refusals %v, want exactly %v; details %+v", name, got, want, rep.Statement.Refusals)
		return
	}
	if rep.Statement.Verdict != VerdictRefused {
		t.Errorf("%s: verdict %s", name, rep.Statement.Verdict)
	}
	if got, w := rep.ExitStatus(), pinnedExit[string(want[0])]; got != w || got == 0 {
		t.Errorf("%s: exit %d, want %d (pinned)", name, got, w)
	}
	if _, err := Decode(mustEncode(t, rep)); err != nil {
		t.Errorf("%s: the refused report does not decode: %v", name, err)
	}
}

func mustEncode(t testing.TB, rep *Report) []byte {
	t.Helper()
	b, err := rep.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Positive control: an honest toy ceremony is released. Every check passes,
// every control fires, the report file decodes with its statement digest,
// its sidecar names its SHA-256, a second run gives the same statement, and
// the weights were drawn after the inputs were bound.
func TestHonestCeremonyIsReleased(t *testing.T) {
	in := honestToy(t)
	rep := Run(in)
	st := rep.Statement
	if st.Verdict != VerdictReleaseOK || rep.ExitStatus() != 0 || len(st.Refusals) != 0 {
		t.Fatalf("verdict %s, exit %d, refusals %+v", st.Verdict, rep.ExitStatus(), st.Refusals)
	}
	if st.PrivacyOnlyVerdict != crscheck.VerdictWellFormed {
		t.Fatalf("privacy-only verdict %s", st.PrivacyOnlyVerdict)
	}
	for _, r := range st.Checks {
		if !r.Pass {
			t.Fatalf("%s failed", r.Name)
		}
	}
	if len(st.Checks) != len(baseChecks)+len(commitmentChecks) {
		t.Fatalf("%d checks, want %d", len(st.Checks), len(baseChecks)+len(commitmentChecks))
	}
	if len(st.Controls) != 14 {
		t.Fatalf("%d controls, want 14", len(st.Controls))
	}
	for _, c := range st.Controls {
		if !c.Fired {
			t.Fatalf("control %s did not fire: %v", c.Name, c.Failed)
		}
	}
	if st.RestoredKey == nil || st.RestoredKey.Verdict != crscheck.VerdictWellFormed || len(st.RestoredKey.Failed) != 0 {
		t.Fatalf("restored key %+v", st.RestoredKey)
	}
	for name, f := range map[string]File{"r1cs": st.Files.R1CS, "ptau": st.Files.Ptau, "pk": st.Files.ProvingKey, "vk": st.Files.VerifyingKey} {
		if f.SHA256 == "" || f.SHA256 != f.Expected || f.SHA256 != f.Transcript || f.Bytes == 0 {
			t.Fatalf("%s: %+v", name, f)
		}
	}
	if st.Files.CeremonyReport.SHA256 != in.CeremonyReportSHA256 || st.Ceremony.VerifierVerdict != verifier.VerdictValid ||
		!st.Ceremony.Anchors.Phase1Pin || !st.Ceremony.Anchors.Beacon || st.Checker.VCSModified != "false" {
		t.Fatalf("ceremony %+v, checker %+v", st.Ceremony, st.Checker)
	}
	bound, _ := time.Parse(time.RFC3339Nano, rep.Run.InputsBoundUTC)
	drawn, _ := time.Parse(time.RFC3339Nano, rep.Run.WeightsDrawnFromUTC)
	if bound.IsZero() || drawn.Before(bound) {
		t.Fatalf("weights drawn at %s, inputs bound at %s", rep.Run.WeightsDrawnFromUTC, rep.Run.InputsBoundUTC)
	}

	path := filepath.Join(t.TempDir(), "crs-release-report.json")
	sum, err := rep.Write(path)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if digest(b) != sum {
		t.Fatal("Write returned another digest than the file's")
	}
	side, _ := os.ReadFile(path + ".sha256")
	if string(side) != sum+"  crs-release-report.json\n" {
		t.Fatalf("sidecar %q", side)
	}
	back, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if back.StatementSHA256 != rep.StatementSHA256 || !reflect.DeepEqual(back.Statement, rep.Statement) {
		t.Fatal("the written statement does not round-trip")
	}
	// A tampered statement no longer matches its digest.
	if _, err := Decode(bytes.Replace(b, []byte(`"verdict": "RELEASE-OK"`), []byte(`"verdict": "RELEASE-OKAY"`), 1)); err == nil {
		t.Fatal("a tampered statement decoded")
	}

	again := Run(in)
	if again.StatementSHA256 != rep.StatementSHA256 {
		t.Fatalf("statement not reproducible: %s then %s", rep.StatementSHA256, again.StatementSHA256)
	}
}

// REV-195 H3: a vk.K element off by g₁ in a ceremony whose tooling and
// verifier agree on it. crscheck's privacy-only verdict stays WELL-FORMED;
// the release is refused on the ancillary VK_K.
func TestAncillaryFailureRefusesRelease(t *testing.T) {
	in := reissue(t, honestToy(t), func(_ *groth16bn254.ProvingKey, vk *groth16bn254.VerifyingKey) {
		_, _, g1, _ := curve.Generators()
		vk.G1.K[0].Add(&vk.G1.K[0], &g1)
	})
	rep := Run(in)
	wantRefused(t, "vk.K[0] += g1", rep, CodeAncillary)
	if rep.Statement.PrivacyOnlyVerdict != crscheck.VerdictWellFormed {
		t.Fatalf("privacy-only verdict %s, want WELL-FORMED (the point of H3)", rep.Statement.PrivacyOnlyVerdict)
	}
	if d := rep.Statement.Refusals[0].Detail; !strings.Contains(d, crscheck.CheckVKK) {
		t.Fatalf("detail %q does not name VK_K", d)
	}
	// Positive control of the helper: an identity reissue is released.
	if rep := Run(reissue(t, honestToy(t), func(*groth16bn254.ProvingKey, *groth16bn254.VerifyingKey) {})); rep.Statement.Verdict != VerdictReleaseOK {
		t.Fatalf("identity reissue refused: %+v", rep.Statement.Refusals)
	}
	// And the other two ancillary checks.
	for _, c := range []struct {
		name   string
		mutate func(*groth16bn254.ProvingKey, *groth16bn254.VerifyingKey)
		check  string
	}{
		{"vk [α]₁ += g₁", func(_ *groth16bn254.ProvingKey, vk *groth16bn254.VerifyingKey) {
			_, _, g1, _ := curve.Generators()
			vk.G1.Alpha.Add(&vk.G1.Alpha, &g1)
		}, crscheck.CheckVKMatch},
	} {
		rep := Run(reissue(t, honestToy(t), c.mutate))
		wantRefused(t, c.name, rep, CodeAncillary)
		if !strings.Contains(rep.Statement.Refusals[0].Detail, c.check) {
			t.Errorf("%s: detail %q", c.name, rep.Statement.Refusals[0].Detail)
		}
	}
}

// The degenerate trapdoors ARCH-238 found. The project's ceremony has refused
// them at phase-1 import since ENG-440; a ceremony and verifier without that
// refusal certify them (forge), and the gate refuses the key on a
// zero-knowledge check.
func TestDegenerateTrapdoorsAreRefused(t *testing.T) {
	var minusOne fr.Element
	minusOne.SetOne()
	minusOne.Neg(&minusOne)
	r, err := testcircuits.Compile("committed", 3)
	if err != nil {
		t.Fatal(err)
	}
	omega := fft.NewDomain(uint64(crscheck.Domain(r))).Generator
	for _, c := range []struct {
		name             string
		tau, alpha, beta fr.Element
		check            string
	}{
		{"β = −1", frU(fixture.ToyTau), frU(fixture.ToyAlpha), minusOne, crscheck.CheckCommitMask},
		{"τ = ω", omega, frU(fixture.ToyAlpha), frU(fixture.ToyBeta), crscheck.CheckTauDomain},
	} {
		r, err := testcircuits.Compile("committed", 3)
		if err != nil {
			t.Fatal(err)
		}
		rep := Run(forge(t, r, "committed", c.tau, c.alpha, c.beta))
		wantRefused(t, c.name, rep, CodeMalformed)
		if rep.Statement.PrivacyOnlyVerdict != crscheck.VerdictMalformed || !strings.Contains(rep.Statement.Refusals[0].Detail, c.check) {
			t.Errorf("%s: privacy-only %s, detail %q", c.name, rep.Statement.PrivacyOnlyVerdict, rep.Statement.Refusals[0].Detail)
		}
		if rep.Statement.Controls != nil {
			t.Errorf("%s: controls ran on a refused key", c.name)
		}
	}
}

// Each refusal of the ceremony record, the out-of-band digests and the input
// files, one case at a time on copies of one honest ceremony's records.
func TestRecordRefusals(t *testing.T) {
	good := honestToy(t)
	other := runToy(t, "committed", 3, frU(fixture.ToyTau), frU(fixture.ToyAlpha), frU(fixture.ToyBeta))
	otherCircuit := runToy(t, "cubic", 5, frU(fixture.ToyTau), frU(fixture.ToyAlpha), frU(fixture.ToyBeta))
	if good.ProvingKeySHA256 == other.ProvingKeySHA256 {
		t.Fatal("two ceremonies gave the same key")
	}
	flip := func(s string) string {
		b := []byte(s)
		if b[0] == '0' {
			b[0] = '1'
		} else {
			b[0] = '0'
		}
		return string(b)
	}
	editReport := func(t testing.TB, in *Inputs, edit func(r *verifier.Report)) {
		var rep verifier.Report
		b, _ := os.ReadFile(in.CeremonyReport)
		if err := json.Unmarshal(b, &rep); err != nil {
			t.Fatal(err)
		}
		edit(&rep)
		in.CeremonyReportSHA256 = writeVerifierReport(t, in.CeremonyReport, &rep)
	}
	for _, c := range []struct {
		name string
		edit func(t testing.TB, in *Inputs)
		want []Code
	}{
		{"the gate's build is from a modified tree", func(t testing.TB, in *Inputs) {
			readBuildInfo = func() (*debug.BuildInfo, bool) {
				bi := cleanRecords()
				bi.Settings[3].Value = "true"
				return bi, true
			}
		}, []Code{CodeCheckerBuild}},
		{"the transcript is not sealed", func(t testing.TB, in *Inputs) {
			editJSON(t, in.Transcript, func(tr *transcript.Transcript) { tr.Status, tr.Keys, tr.Beacon = transcript.StatusOpen, nil, nil })
			rebind(t, in)
		}, []Code{CodeTranscript}},
		{"the transcript is unreadable", func(t testing.TB, in *Inputs) { in.Transcript += ".missing" }, []Code{CodeTranscript, CodeReportUnbound}},
		{"the transcript carries an unknown field", func(t testing.TB, in *Inputs) {
			b, _ := os.ReadFile(in.Transcript)
			os.WriteFile(in.Transcript, bytes.Replace(b, []byte(`"status"`), []byte(`"extra": 1, "status"`), 1), 0o644)
			rebind(t, in)
		}, []Code{CodeTranscript}},
		{"the transcript names another key encoding", func(t testing.TB, in *Inputs) {
			editJSON(t, in.Transcript, func(tr *transcript.Transcript) { tr.Keys.ProvingKey.Encoding = "gnark-v0.16.3-groth16-bn254-WriteTo" })
			rebind(t, in)
		}, []Code{CodeTranscript}},
		{"the transcript's keys come from another gnark", func(t testing.TB, in *Inputs) {
			editJSON(t, in.Transcript, func(tr *transcript.Transcript) { tr.Tool.Gnark = "v0.16.4" })
			rebind(t, in)
		}, []Code{CodeGnarkVersion}},
		// REV-198 H2: an edit to a field the verifier's output does not
		// report (the root challenge; the verifier itself refuses it). Only
		// the transcript digest ties the output to the bytes.
		{"REV-198: the transcript's root challenge edited", func(t testing.TB, in *Inputs) {
			editJSON(t, in.Transcript, func(tr *transcript.Transcript) { tr.Phase2.RootChallenge = strings.Repeat("ab", 32) })
		}, []Code{CodeReportUnbound}},
		{"the verifier output names another transcript", func(t testing.TB, in *Inputs) {
			editReport(t, in, func(r *verifier.Report) { r.TranscriptSHA256 = flip(r.TranscriptSHA256) })
		}, []Code{CodeReportUnbound}},
		{"the verifier output names no transcript (before ENG-443)", func(t testing.TB, in *Inputs) {
			editReport(t, in, func(r *verifier.Report) { r.TranscriptSHA256 = "" })
		}, []Code{CodeReportUnbound}},
		{"the verifier output comes from this go test binary's build (unverified)", func(t testing.TB, in *Inputs) {
			editReport(t, in, func(r *verifier.Report) { r.VerifierBuild = verifier.ThisBuild() })
		}, []Code{CodeVerifierUnverified}},
		{"the verifier output from a verified-looking build on a modified tree", func(t testing.TB, in *Inputs) {
			editReport(t, in, func(r *verifier.Report) { r.VerifierBuild.VCSModified = "true" })
		}, []Code{CodeVerifierUnverified}},
		{"an archived output with neither field, like 5.1c's", func(t testing.TB, in *Inputs) {
			b, _ := os.ReadFile(in.CeremonyReport)
			var m map[string]json.RawMessage
			if err := json.Unmarshal(b, &m); err != nil {
				t.Fatal(err)
			}
			delete(m, "transcriptSha256")
			delete(m, "verifierBuild")
			in.CeremonyReportSHA256 = writeVerifierReport(t, in.CeremonyReport, m)
		}, []Code{CodeReportUnbound, CodeVerifierUnverified}},
		{"the key metadata disagrees with the transcript", func(t testing.TB, in *Inputs) {
			editJSON(t, in.KeyMetadata, func(m *transcript.KeyMetadata) { m.Contributions++ })
		}, []Code{CodeKeyMetadata}},
		{"the key metadata is missing", func(t testing.TB, in *Inputs) { in.KeyMetadata += ".missing" }, []Code{CodeKeyMetadata}},
		{"the verifier output is not the one named", func(t testing.TB, in *Inputs) { in.CeremonyReportSHA256 = flip(in.CeremonyReportSHA256) },
			[]Code{CodeReportDigest}},
		{"the verifier output is CONSISTENT-UNANCHORED", func(t testing.TB, in *Inputs) {
			editReport(t, in, func(r *verifier.Report) { r.Verdict, r.Anchors.Beacon = verifier.VerdictUnanchored, false })
		}, []Code{CodeCeremonyNotValid}},
		{"the verifier output says VALID without the beacon anchor", func(t testing.TB, in *Inputs) {
			editReport(t, in, func(r *verifier.Report) { r.Anchors.Beacon = false })
		}, []Code{CodeCeremonyNotValid}},
		{"the verifier output is a REFUSED output", func(t testing.TB, in *Inputs) {
			in.CeremonyReportSHA256 = writeVerifierReport(t, in.CeremonyReport, map[string]string{"verdict": "REFUSED", "code": "SEALED_KEY_MISMATCH", "detail": "x"})
		}, []Code{CodeCeremonyNotValid}},
		{"the verifier output is missing", func(t testing.TB, in *Inputs) { in.CeremonyReport += ".missing" }, []Code{CodeCeremonyNotValid}},
		{"the verifier output is another ceremony's", func(t testing.TB, in *Inputs) {
			in.CeremonyReport, in.CeremonyReportSHA256 = other.CeremonyReport, other.CeremonyReportSHA256
		}, []Code{CodeReportMismatch, CodeReportUnbound}},
		{"the verifier output names another proving key", func(t testing.TB, in *Inputs) {
			editReport(t, in, func(r *verifier.Report) { r.ProvingKeySHA256 = other.ProvingKeySHA256 })
		}, []Code{CodeReportMismatch}},
		{"out-of-band R1CS digest differs from the transcript's", func(t testing.TB, in *Inputs) { in.R1CSSHA256 = flip(in.R1CSSHA256) },
			[]Code{CodeR1CSDigest}},
		{"out-of-band phase-1 pin differs from the transcript's", func(t testing.TB, in *Inputs) { in.PtauSHA256 = flip(in.PtauSHA256) },
			[]Code{CodePtauPin}},
		{"out-of-band verifying key digest differs from the transcript's", func(t testing.TB, in *Inputs) {
			in.VerifyingKeySHA256 = flip(in.VerifyingKeySHA256)
		}, []Code{CodeVKDigest}},
		{"out-of-band proving key digest differs from the transcript's", func(t testing.TB, in *Inputs) {
			in.ProvingKeySHA256 = flip(in.ProvingKeySHA256)
		}, []Code{CodePKDigest}},
		{"the R1CS file is another circuit's", func(t testing.TB, in *Inputs) { in.R1CS = otherCircuit.R1CS }, []Code{CodeR1CSDigest}},
		{"the phase-1 file has a flipped byte", func(t testing.TB, in *Inputs) {
			b, _ := os.ReadFile(in.Ptau)
			b[len(b)/2] ^= 1
			in.Ptau = filepath.Join(t.TempDir(), "flipped.ptau")
			os.WriteFile(in.Ptau, b, 0o644)
		}, []Code{CodePtauPin}},
		{"the verifying key file is another ceremony's", func(t testing.TB, in *Inputs) { in.VerifyingKey = other.VerifyingKey },
			[]Code{CodeVKDigest}},
		{"the proving key file is another ceremony's", func(t testing.TB, in *Inputs) { in.ProvingKey = other.ProvingKey },
			[]Code{CodePKDigest}},
		{"a digest is missing", func(t testing.TB, in *Inputs) { in.CeremonyReportSHA256 = "" }, []Code{CodeUnreadable}},
		// A consistent record (transcript, key metadata, verifier report)
		// that names another file than the operator's digest, which the file
		// itself matches: only the comparison with the transcript sees it.
		{"the record names another R1CS than the operator's", func(t testing.TB, in *Inputs) {
			rerecord(t, in, func(tr *transcript.Transcript) { tr.Circuit.R1CSSHA256 = otherCircuit.R1CSSHA256 },
				func(r *verifier.Report) { r.R1CSSHA256 = otherCircuit.R1CSSHA256 })
		}, []Code{CodeR1CSDigest}},
		{"the record pins another phase-1 file than the operator's", func(t testing.TB, in *Inputs) {
			rerecord(t, in, func(tr *transcript.Transcript) { tr.Phase1.Pin.Digest = otherCircuit.R1CSSHA256 },
				func(r *verifier.Report) { r.Phase1Pin.Digest = otherCircuit.R1CSSHA256 })
		}, []Code{CodePtauPin}},
		{"the record names another verifying key than the operator's", func(t testing.TB, in *Inputs) {
			rerecord(t, in, func(tr *transcript.Transcript) { tr.Keys.VerifyingKey.SHA256 = other.VerifyingKeySHA256 },
				func(r *verifier.Report) { r.VerifyingKeySHA256 = other.VerifyingKeySHA256 })
		}, []Code{CodeVKDigest}},
		{"the record names another proving key than the operator's", func(t testing.TB, in *Inputs) {
			rerecord(t, in, func(tr *transcript.Transcript) { tr.Keys.ProvingKey.SHA256 = other.ProvingKeySHA256 },
				func(r *verifier.Report) { r.ProvingKeySHA256 = other.ProvingKeySHA256 })
		}, []Code{CodePKDigest}},
		{"the transcript is open but carries keys", func(t testing.TB, in *Inputs) {
			rerecord(t, in, func(tr *transcript.Transcript) { tr.Status = transcript.StatusOpen }, func(*verifier.Report) {})
		}, []Code{CodeTranscript}},
		{"the transcript is mislabelled (a simulated ceremony not zero-value-only)", func(t testing.TB, in *Inputs) {
			rerecord(t, in, func(tr *transcript.Transcript) { tr.ZeroValueOnly = false }, func(r *verifier.Report) { r.ZeroValueOnly = false })
		}, []Code{CodeTranscript}},
		{"the transcript is for another curve", func(t testing.TB, in *Inputs) {
			rerecord(t, in, func(tr *transcript.Transcript) { tr.Tool.Curve = "bls12-381" }, func(*verifier.Report) {})
		}, []Code{CodeTranscript}},
		// Positive control of rerecord: an empty edit is released.
		{"rerecord with no edit", func(t testing.TB, in *Inputs) {
			rerecord(t, in, func(*transcript.Transcript) {}, func(*verifier.Report) {})
		}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			defer func() { readBuildInfo = func() (*debug.BuildInfo, bool) { return cleanRecords(), true } }()
			in := copyRecord(t, good)
			c.edit(t, &in)
			rep := Run(in)
			if c.want == nil {
				if rep.Statement.Verdict != VerdictReleaseOK || rep.ExitStatus() != 0 {
					t.Fatalf("refused: %+v", rep.Statement.Refusals)
				}
				return
			}
			wantRefused(t, c.name, rep, c.want...)
			if len(rep.Statement.Checks) != 0 {
				t.Errorf("the key was checked although the record was refused")
			}
		})
	}
}

// The key files as named by a consistent record, but not decodable: the
// gate refuses them as unreadable before any check.
func TestUndecodableKeysAreRefused(t *testing.T) {
	good := honestToy(t)
	for _, c := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{"proving key truncated", func(b []byte) []byte { return b[:len(b)-1] }},
		{"proving key with a trailing byte", func(b []byte) []byte { return append(b, 0) }},
	} {
		in := copyRecord(t, good)
		b, _ := os.ReadFile(in.ProvingKey)
		b = c.edit(b)
		os.WriteFile(in.ProvingKey, b, 0o644)
		in.ProvingKeySHA256 = digest(b)
		editJSON(t, in.Transcript, func(tr *transcript.Transcript) { tr.Keys.ProvingKey.SHA256 = in.ProvingKeySHA256 })
		tr, err := transcript.Load(in.Transcript)
		if err != nil {
			t.Fatal(err)
		}
		meta := transcript.MetadataFor(tr)
		transcript.WriteJSON(in.KeyMetadata, &meta)
		var rep verifier.Report
		rb, _ := os.ReadFile(in.CeremonyReport)
		json.Unmarshal(rb, &rep)
		rep.ProvingKeySHA256 = in.ProvingKeySHA256
		rep.TranscriptSHA256 = sha(t, in.Transcript)
		in.CeremonyReportSHA256 = writeVerifierReport(t, in.CeremonyReport, &rep)
		wantRefused(t, c.name, Run(in), CodeUnreadable)
	}
}

// readPinned on constructed decoders: a file that changes between the digest
// pass and the decoding pass, a decoder that stops early, and a decoder that
// misreports how much it read are each refused; an honest decoder is not.
func TestReadPinnedBranches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.bin")
	a := bytes.Repeat([]byte("a"), 1000)
	for _, c := range []struct {
		name   string
		decode func(io.Reader) (int64, error)
		want   []Code
	}{
		{"honest", func(r io.Reader) (int64, error) { b, err := io.ReadAll(r); return int64(len(b)), err }, nil},
		{"the file changes after the digest pass", func(r io.Reader) (int64, error) {
			if err := os.WriteFile(path, bytes.Repeat([]byte("b"), 1000), 0o644); err != nil {
				return 0, err
			}
			b, err := io.ReadAll(r)
			return int64(len(b)), err
		}, []Code{CodePKDigest}},
		{"the decoder stops one byte early", func(r io.Reader) (int64, error) {
			n, err := io.CopyN(io.Discard, r, 999)
			return n, err
		}, []Code{CodeUnreadable}},
		{"the decoder reads all but reports one byte less", func(r io.Reader) (int64, error) {
			b, err := io.ReadAll(r)
			return int64(len(b)) - 1, err
		}, []Code{CodeUnreadable}},
		{"the decoder reads one byte less but reports all", func(r io.Reader) (int64, error) {
			n, err := io.CopyN(io.Discard, r, 999)
			return n + 1, err
		}, []Code{CodeUnreadable}},
		{"the decoder fails", func(io.Reader) (int64, error) { return 0, errors.New("bad point") }, []Code{CodeUnreadable}},
	} {
		if err := os.WriteFile(path, a, 0o644); err != nil {
			t.Fatal(err)
		}
		g := &gate{rep: &Report{Run: RunInfo{StageSeconds: map[string]float64{}}}}
		g.st = &g.rep.Statement
		var rec File
		ok := g.readPinned("stage", path, digest(a), &rec, CodePKDigest, c.decode)
		var got []Code
		for _, r := range g.st.Refusals {
			got = append(got, r.Code)
		}
		if !reflect.DeepEqual(got, c.want) || ok != (c.want == nil) {
			t.Errorf("%s: ok %v, refusals %v, want %v", c.name, ok, g.st.Refusals, c.want)
		}
		if rec.SHA256 != digest(a) || rec.Bytes != 1000 {
			t.Errorf("%s: record %+v", c.name, rec)
		}
	}
}

// judgeChecks and judgeControls, branch by branch, on constructed outcomes.
func TestJudgeBranches(t *testing.T) {
	all := func(k int) *crscheck.Report {
		r := &crscheck.Report{Verdict: crscheck.VerdictWellFormed}
		for _, n := range baseChecks {
			zk := n != crscheck.CheckVKK && n != crscheck.CheckVKMatch && n != crscheck.CheckPhase1
			r.Results = append(r.Results, crscheck.Result{Name: n, ZK: zk, Pass: true})
		}
		for range k {
			for _, n := range commitmentChecks {
				r.Results = append(r.Results, crscheck.Result{Name: n, ZK: true, Pass: true})
			}
		}
		return r
	}
	codesOf := func(rs []Refusal) []Code {
		var c []Code
		for _, r := range rs {
			c = append(c, r.Code)
		}
		return c
	}
	if r := judgeChecks(all(1), 1); len(r) != 0 {
		t.Fatalf("all passing refused: %+v", r)
	}
	fail := func(k int, name string) *crscheck.Report {
		r := all(k)
		for i := range r.Results {
			if r.Results[i].Name == name {
				r.Results[i].Pass = false
				if r.Results[i].ZK {
					r.Verdict = crscheck.VerdictMalformed
				}
			}
		}
		return r
	}
	drop := func(k int, name string) *crscheck.Report {
		r := all(k)
		r.Results = slices.DeleteFunc(r.Results, func(x crscheck.Result) bool { return x.Name == name })
		return r
	}
	for _, c := range []struct {
		name string
		rep  *crscheck.Report
		k    int
		want []Code
	}{
		{"a ZK check failed", fail(1, crscheck.CheckZQuery), 1, []Code{CodeMalformed}},
		{"VK_K failed", fail(1, crscheck.CheckVKK), 1, []Code{CodeAncillary}},
		{"PHASE1_ALPHA_BETA failed", fail(1, crscheck.CheckPhase1), 1, []Code{CodeAncillary}},
		{"verdict MALFORMED with every result passing", func() *crscheck.Report { r := all(1); r.Verdict = crscheck.VerdictMalformed; return r }(), 1, []Code{CodeMalformed}},
		{"VK_K missing", drop(1, crscheck.CheckVKK), 1, []Code{CodeIncomplete}},
		{"the mask check missing", drop(1, crscheck.CheckCommitMask), 1, []Code{CodeIncomplete}},
		{"one commitment's checks for two commitments", all(1), 2, []Code{CodeIncomplete}},
		{"KEY_SHAPE failed (the checker stops)", func() *crscheck.Report {
			return &crscheck.Report{Verdict: crscheck.VerdictMalformed, Results: []crscheck.Result{{Name: crscheck.CheckShape, ZK: true}}}
		}(), 1, []Code{CodeMalformed}},
	} {
		if got := codesOf(judgeChecks(c.rep, c.k)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}

	var controls []ControlOutcome
	for _, n := range append(slices.Clone(controlTargets), commitmentChecks...) {
		controls = append(controls, ControlOutcome{Name: n, MustFail: []string{n}, Fired: true})
	}
	ok := &Restored{Verdict: crscheck.VerdictWellFormed, Failed: []string{}}
	if r := judgeControls(controls, ok, 1); len(r) != 0 {
		t.Fatalf("all fired refused: %+v", r)
	}
	notFired := slices.Clone(controls)
	notFired[3].Fired = false
	untargeted := slices.DeleteFunc(slices.Clone(controls), func(c ControlOutcome) bool { return c.Name == crscheck.CheckVKK })
	for _, c := range []struct {
		name     string
		controls []ControlOutcome
		restored *Restored
		k        int
		want     []Code
	}{
		{"a control did not fire", notFired, ok, 1, []Code{CodeControl}},
		{"no control targets VK_K", untargeted, ok, 1, []Code{CodeControl}},
		{"no controls at all", nil, ok, 0, []Code{CodeControl}},
		{"the restored key fails", controls, &Restored{Verdict: crscheck.VerdictWellFormed, Failed: []string{crscheck.CheckVKK}}, 1, []Code{CodeControl}},
		{"the restored key was not checked", controls, nil, 1, []Code{CodeControl}},
	} {
		if got := codesOf(judgeControls(c.controls, c.restored, c.k)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// checkerOf, every branch, on constructed records.
func TestCheckerBuildFailsClosed(t *testing.T) {
	with := func(edit func(*debug.BuildInfo)) *debug.BuildInfo { bi := cleanRecords(); edit(bi); return bi }
	set := func(path string, f func(*debug.Module)) func(*debug.BuildInfo) {
		return func(bi *debug.BuildInfo) {
			for _, d := range bi.Deps {
				if d.Path == path {
					f(d)
				}
			}
		}
	}
	setting := func(key, v string) func(*debug.BuildInfo) {
		return func(bi *debug.BuildInfo) {
			for i := range bi.Settings {
				if bi.Settings[i].Key == key {
					bi.Settings[i].Value = v
				}
			}
		}
	}
	errs := []error{ErrNoBuildInfo, ErrMainModule, ErrModuleMissing, ErrModuleReplaced, ErrModuleVersion, ErrNoRevision, ErrModified}
	for _, c := range []struct {
		name string
		bi   *debug.BuildInfo
		ok   bool
		want error
	}{
		{"no build info", nil, false, ErrNoBuildInfo},
		{"build info reported absent", cleanRecords(), false, ErrNoBuildInfo},
		{"another main module", with(func(bi *debug.BuildInfo) { bi.Main.Path = "example.com/fork" }), true, ErrMainModule},
		{"no dependency records (a go test binary)", with(func(bi *debug.BuildInfo) { bi.Deps = nil }), true, ErrModuleMissing},
		{"gnark replaced", with(set(gnarkModule, func(d *debug.Module) { d.Replace = &debug.Module{Path: "../gnark"} })), true, ErrModuleReplaced},
		{"gnark-crypto another version", with(set(gnarkCryptoModule, func(d *debug.Module) { d.Version = "v0.21.1" })), true, ErrModuleVersion},
		{"gnark recorded twice", with(func(bi *debug.BuildInfo) {
			bi.Deps = append(bi.Deps, &debug.Module{Path: gnarkModule, Version: "v0.15.0"})
		}), true, ErrModuleVersion},
		{"no revision", with(setting("vcs.revision", "")), true, ErrNoRevision},
		{"a short revision", with(setting("vcs.revision", "b613957a")), true, ErrNoRevision},
		{"modified tree", with(setting("vcs.modified", "true")), true, ErrModified},
		{"vcs.modified not recorded", with(func(bi *debug.BuildInfo) { bi.Settings = bi.Settings[:3] }), true, ErrModified},
	} {
		_, err := checkerOf(c.bi, c.ok)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
			continue
		}
		for _, other := range errs {
			if other != c.want && errors.Is(err, other) {
				t.Errorf("%s: also matches %v", c.name, other)
			}
		}
	}
	c, err := checkerOf(cleanRecords(), true)
	if err != nil || c.Gnark != crscheck.GnarkVersion || c.GnarkCrypto != crscheck.GnarkCryptoVersion || c.Module != MainModule {
		t.Fatalf("clean records refused or misread: %+v %v", c, err)
	}
}

// requiredVersions returns every version go.mod requires for module mod
// (matched exactly: gnark is a prefix of gnark-crypto) and every replace
// directive naming it.
func requiredVersions(gomod []byte, mod string) (versions, replaces []string) {
	for _, line := range strings.Split(string(gomod), "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if strings.HasPrefix(line, "replace ") || strings.Contains(line, "=>") {
			if f := strings.Fields(strings.TrimPrefix(line, "replace ")); len(f) > 0 && f[0] == mod {
				replaces = append(replaces, line)
			}
			continue
		}
		f := strings.Fields(strings.TrimPrefix(line, "require "))
		if len(f) == 2 && f[0] == mod {
			versions = append(versions, f[1])
		}
	}
	return versions, replaces
}

// The versions crscheck is written against are the ones go.mod requires,
// unreplaced, and the ones this module's ceremonies record; MainModule is
// go.mod's module.
func TestVersionsMatchGoMod(t *testing.T) {
	raw, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	for mod, want := range map[string]string{gnarkModule: crscheck.GnarkVersion, gnarkCryptoModule: crscheck.GnarkCryptoVersion} {
		if v, r := requiredVersions(raw, mod); !reflect.DeepEqual(v, []string{want}) || len(r) != 0 {
			t.Errorf("%s: go.mod requires %v (replaces %v), crscheck is written against %s", mod, v, r, want)
		}
	}
	if !bytes.HasPrefix(raw, []byte("module "+MainModule+"\n")) {
		t.Errorf("go.mod's module is not %s", MainModule)
	}
	if transcript.CurrentTool.Gnark != crscheck.GnarkVersion || transcript.CurrentTool.GnarkCrypto != crscheck.GnarkCryptoVersion {
		t.Errorf("the ceremony records %+v", transcript.CurrentTool)
	}
}

// Every code has its own exit status, none reserved.
func TestExitStatusesAreStable(t *testing.T) {
	seen := map[int]Code{}
	for _, e := range Codes {
		if e.Exit == 0 || e.Exit == 1 || e.Exit == 2 || e.Exit == 75 || e.Exit > 125 {
			t.Errorf("%s: reserved status %d", e.Code, e.Exit)
		}
		if prev, ok := seen[e.Exit]; ok {
			t.Errorf("%s and %s share status %d", e.Code, prev, e.Exit)
		}
		seen[e.Exit] = e.Code
	}
	if len(Codes) != 18 {
		t.Errorf("%d codes", len(Codes))
	}
	if ExitOf("NOT_A_CODE") != 1 {
		t.Error("an unknown code does not exit 1")
	}
}
