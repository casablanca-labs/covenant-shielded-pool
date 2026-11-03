// Package release is the once-per-ceremony CRS release gate (ENG-441, run
// R-399; fix round ENG-447; reviewed by REV-206, PASS). It issues one
// verdict, RELEASE-OK, for a sealed
// Groth16 proving key and verifying key, and a report that ships with the
// ceremony's transcript.
//
// RELEASE-OK needs all of:
//
//   - the gate's own build is identified (checkerOf): built from this module
//     at a recorded, unmodified VCS revision, linking unreplaced gnark and
//     gnark-crypto at the versions crscheck was written against;
//   - the transcript is sealed, correctly labelled, for BN254 Groth16 on that
//     gnark, and keys.meta.json is exactly what it implies;
//   - the ceremony verifier's output is the file the operator names by
//     SHA-256, is VALID with both anchors, describes this transcript field
//     for field, names by transcriptSha256 exactly the transcript bytes the
//     gate parsed, and records a clean, stamped build of this module on
//     crscheck's gnark (the verifier binary's self-report, not
//     authenticated; the revision is recorded for audit, not compared with a
//     reviewed commit);
//   - the operator's out-of-band SHA-256 of the R1CS, the phase-1 file, the
//     proving key and the verifying key equal the transcript's, and each file
//     read hashes to it before it is parsed;
//   - every crscheck check passes, the zero-knowledge checks (the
//     privacy-only verdict WELL-FORMED, which includes each mask's origin in
//     a no-input Randomize call, every other instruction whose walk touches
//     the mask running in a strictly later level, and the R1CS's schedule)
//     and the ancillary
//     ones (VK_K, VK_MATCHES_PK, PHASE1_ALPHA_BETA) alike, and none is
//     missing;
//   - every negative control fires on this key, one targets each check, and
//     the restored key passes every check again.
//
// The privacy-only verdict is recorded for information and is never release
// authority (REV-195 H3). The gate does not re-run the ceremony verifier: it
// binds the release to one archived VALID output by digest and by content.
//
// The package reads the ceremony's records with the transcript and verifier
// packages' own types. The key check itself is package crscheck, which
// imports neither gnark's mpcsetup nor any package of this module.
package release

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"time"

	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/crscheck"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/verifier"
)

const (
	Format           = "apnt-pool-crs-release/v1"
	VerdictReleaseOK = "RELEASE-OK"
	VerdictRefused   = "RELEASE-REFUSED"

	Notice = "CRS RELEASE GATE (ENG-441, ENG-447). RELEASE-OK means: the ceremony verifier's archived VALID output, which " +
		"records a clean, stamped build of this module (the verifier binary's self-report, not authenticated; the revision " +
		"is recorded for audit, not compared with a reviewed commit) and names these exact transcript bytes, the transcript, " +
		"the key metadata and the operator's out-of-band digests all name these exact files; each commitment mask is gnark's " +
		"no-input Randomize output under the R1CS's own schedule, and every other instruction whose walk touches the mask " +
		"runs in a strictly later level; every crscheck " +
		"check passed on them, the zero-knowledge checks and the ancillary ones alike; and every negative control fired on " +
		"this key. It concerns the prover's zero knowledge under this key and the key's consistency with its ceremony. It is " +
		"not proof verification or chain validation, it did not re-run the ceremony verifier, and it says nothing about " +
		"soundness against whoever holds the setup trapdoor. privacyOnlyVerdict is informational and never release authority."

	WeightSource = "crypto/rand (gnark-crypto fr.Element.SetRandom), drawn inside crscheck.Prepare after every input digest " +
		"was bound to the transcript and the out-of-band digests; never written out. The negative controls reuse the clean " +
		"check's weights; each malformation is fixed without reference to them."
)

// Inputs are the gate's files and the SHA-256 digests their operator already
// trusts out of band (the ceremony's published record, a wallet's pin).
// Every field but Log is mandatory.
type Inputs struct {
	ProvingKey, VerifyingKey, R1CS, Ptau    string
	Transcript, KeyMetadata, CeremonyReport string

	ProvingKeySHA256, VerifyingKeySHA256, R1CSSHA256, PtauSHA256, CeremonyReportSHA256 string

	Log io.Writer // progress lines; may be nil
}

var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Validate requires every path and every digest, as lowercase hex.
func (in *Inputs) Validate() error {
	var bad []string
	for _, f := range []struct{ name, v string }{
		{"proving key", in.ProvingKey}, {"verifying key", in.VerifyingKey}, {"R1CS", in.R1CS}, {"phase-1 file", in.Ptau},
		{"transcript", in.Transcript}, {"key metadata", in.KeyMetadata}, {"ceremony verifier report", in.CeremonyReport},
	} {
		if f.v == "" {
			bad = append(bad, f.name+" path missing")
		}
	}
	for _, d := range []struct{ name, v string }{
		{"proving key", in.ProvingKeySHA256}, {"verifying key", in.VerifyingKeySHA256}, {"R1CS", in.R1CSSHA256},
		{"phase-1 file", in.PtauSHA256}, {"ceremony verifier report", in.CeremonyReportSHA256},
	} {
		if !hexDigest.MatchString(d.v) {
			bad = append(bad, d.name+" SHA-256 missing or not 64 lowercase hex characters")
		}
	}
	if len(bad) > 0 {
		return errors.New("inputs incomplete: " + strings.Join(bad, "; "))
	}
	return nil
}

// Refusal is one reason the gate refused.
type Refusal struct {
	Code   Code   `json:"code"`
	Detail string `json:"detail"`
}

// File records one input: what it hashed to when read, and the digests it
// was required to equal.
type File struct {
	SHA256     string `json:"sha256,omitempty"`     // measured; empty if not read
	Bytes      int64  `json:"bytes,omitempty"`      // measured
	Expected   string `json:"expected,omitempty"`   // the operator's out-of-band digest
	Transcript string `json:"transcript,omitempty"` // the digest the transcript names
}

// Files are the gate's inputs.
type Files struct {
	R1CS           File `json:"r1cs"`
	Ptau           File `json:"ptau"`
	ProvingKey     File `json:"provingKey"`
	VerifyingKey   File `json:"verifyingKey"`
	Transcript     File `json:"transcript"`
	KeyMetadata    File `json:"keyMetadata"`
	CeremonyReport File `json:"ceremonyReport"`
}

// Ceremony is what the transcript and the verifier's output say about the
// ceremony.
type Ceremony struct {
	ID              string           `json:"ceremonyId,omitempty"`
	Provenance      string           `json:"provenance,omitempty"`
	ZeroValueOnly   bool             `json:"zeroValueOnly"`
	Notice          string           `json:"notice,omitempty"`
	VerifierVerdict string           `json:"verifierVerdict,omitempty"`
	Anchors         verifier.Anchors `json:"verifierAnchors"`
	// What the verifier's output names: the transcript's SHA-256 and the
	// verifier build (ENG-443).
	TranscriptSHA256 string         `json:"verifierTranscriptSha256,omitempty"`
	VerifierBuild    verifier.Build `json:"verifierBuild"`
}

// Circuit is the checked R1CS and key shape.
type Circuit struct {
	NbConstraints    int            `json:"nbConstraints"`
	NbWires          int            `json:"nbWires"`
	NbPublic         int            `json:"nbPublic"`
	Domain           int            `json:"domain"`
	NbCommitted      []int          `json:"nbCommittedPerCommitment"`
	MaskPositions    [][]int        `json:"maskPositions"`
	KeyVectorLengths map[string]int `json:"keyVectorLengths,omitempty"`
}

// ControlOutcome is one negative control's result.
type ControlOutcome struct {
	Name     string   `json:"name"`
	Change   string   `json:"change"`
	MustFail []string `json:"mustFail"`
	Fired    bool     `json:"fired"`
	Failed   []string `json:"failed"`
}

// Restored is the re-check of the key after every control was undone.
type Restored struct {
	Verdict string   `json:"verdict"`
	Failed  []string `json:"failed"`
}

// Statement is the deterministic part of the report: for the same inputs and
// the same checker revision, every run that completes gives the same
// statement, so anyone who re-runs the gate can compare statementSha256.
type Statement struct {
	Format             string            `json:"format"`
	Notice             string            `json:"notice"`
	Verdict            string            `json:"verdict"`
	Refusals           []Refusal         `json:"refusals"`
	PrivacyOnlyVerdict string            `json:"privacyOnlyVerdict,omitempty"`
	Ceremony           Ceremony          `json:"ceremony"`
	Files              Files             `json:"files"`
	Checker            Checker           `json:"checker"`
	WeightSource       string            `json:"weightSource"`
	Circuit            *Circuit          `json:"circuit,omitempty"`
	Checks             []crscheck.Result `json:"checks"`
	Controls           []ControlOutcome  `json:"controls"`
	RestoredKey        *Restored         `json:"restoredKey,omitempty"`
}

// Binary is the running gate binary.
type Binary struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// RunInfo is what varies between runs of the same statement: times, paths
// and the machine.
type RunInfo struct {
	StartedUTC          string             `json:"startedUtc"`
	InputsBoundUTC      string             `json:"inputsBoundUtc,omitempty"`
	WeightsDrawnFromUTC string             `json:"weightsDrawnFromUtc,omitempty"`
	WeightsDrawnByUTC   string             `json:"weightsDrawnByUtc,omitempty"`
	FinishedUTC         string             `json:"finishedUtc"`
	Paths               map[string]string  `json:"paths"`
	StageSeconds        map[string]float64 `json:"stageSeconds"`
	PlanSeconds         map[string]float64 `json:"planSeconds,omitempty"`
	CheckSeconds        map[string]float64 `json:"checkSeconds,omitempty"`
	GoHeapSysMaxBytes   uint64             `json:"goHeapSysMaxBytes"`
	GOMAXPROCS          int                `json:"gomaxprocs"`
	GoVersion           string             `json:"goVersion"`
	Platform            string             `json:"platform"`
	Binary              Binary             `json:"binary"`
	BuildPath           string             `json:"buildPath,omitempty"`
	VCSTime             string             `json:"vcsTime,omitempty"`
}

// Report is the release report: the statement, its SHA-256, and the run.
type Report struct {
	Statement       Statement `json:"statement"`
	StatementSHA256 string    `json:"statementSha256"`
	Run             RunInfo   `json:"run"`
}

// StatementDigest is the SHA-256 of the statement's compact encoding/json
// form (struct field order).
func StatementDigest(st *Statement) (string, error) {
	b, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}

// ExitStatus is the process exit status for the report: 0 only for
// RELEASE-OK with no refusal, else the first refusal's (1 if a refused
// report names none).
func (r *Report) ExitStatus() int {
	if len(r.Statement.Refusals) == 0 {
		if r.Statement.Verdict == VerdictReleaseOK {
			return 0
		}
		return 1
	}
	return ExitOf(r.Statement.Refusals[0].Code)
}

// Codes lists the report's refusal codes in order.
func (r *Report) Codes() []Code {
	var c []Code
	for _, x := range r.Statement.Refusals {
		c = append(c, x.Code)
	}
	return c
}

// Encode is the report file's bytes: indented JSON and a newline.
func (r *Report) Encode() ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Write writes the report to path and its SHA-256 to path + ".sha256", in
// shasum's format, and returns the digest.
func (r *Report) Write(path string) (string, error) {
	b, err := r.Encode()
	if err != nil {
		return "", err
	}
	sum := digest(b)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(path+".sha256", []byte(sum+"  "+filepath.Base(path)+"\n"), 0o644); err != nil {
		return "", err
	}
	return sum, nil
}

// Decode reads a report strictly and requires its statementSha256 to be the
// statement's digest. It does not re-check anything the statement claims.
func Decode(b []byte) (*Report, error) {
	var r Report
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after the report")
	}
	d, err := StatementDigest(&r.Statement)
	if err != nil {
		return nil, err
	}
	if d != r.StatementSHA256 {
		return nil, fmt.Errorf("statementSha256 %s, but the statement hashes to %s", r.StatementSHA256, d)
	}
	return &r, nil
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func utcNow() string { return time.Now().UTC().Format(time.RFC3339Nano) }

type gate struct {
	in      Inputs
	rep     *Report
	st      *Statement
	heapMax uint64
}

// Run runs the gate once and returns its report; it never returns nil. Every
// problem it finds is a refusal in the report; a refused run stops before
// the next expensive step.
func Run(in Inputs) *Report {
	g := &gate{in: in, rep: &Report{Statement: Statement{Format: Format, Notice: Notice, Verdict: VerdictRefused, WeightSource: WeightSource}}}
	g.st = &g.rep.Statement
	r := &g.rep.Run
	r.StartedUTC = utcNow()
	r.Paths = map[string]string{
		"provingKey": in.ProvingKey, "verifyingKey": in.VerifyingKey, "r1cs": in.R1CS, "ptau": in.Ptau,
		"transcript": in.Transcript, "keyMetadata": in.KeyMetadata, "ceremonyReport": in.CeremonyReport,
	}
	r.StageSeconds = map[string]float64{}
	r.GOMAXPROCS, r.GoVersion, r.Platform = runtime.GOMAXPROCS(0), runtime.Version(), runtime.GOOS+"/"+runtime.GOARCH
	if exe, err := os.Executable(); err == nil {
		r.Binary.Path = exe
		if b, err := os.ReadFile(exe); err == nil {
			r.Binary.SHA256 = digest(b)
		}
	}
	g.run()
	g.finish()
	return g.rep
}

func (g *gate) refuse(c Code, format string, a ...any) {
	g.st.Refusals = append(g.st.Refusals, Refusal{Code: c, Detail: fmt.Sprintf(format, a...)})
}

func (g *gate) refused() bool { return len(g.st.Refusals) > 0 }

func (g *gate) logf(format string, a ...any) {
	if g.in.Log != nil {
		fmt.Fprintf(g.in.Log, "crs-release: "+format+"\n", a...)
	}
}

func (g *gate) noteHeap() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	g.heapMax = max(g.heapMax, m.HeapSys)
}

func (g *gate) free() {
	g.noteHeap()
	runtime.GC()
	debug.FreeOSMemory()
}

// stage times f under name.
func (g *gate) stage(name string, f func()) {
	t := time.Now()
	f()
	g.rep.Run.StageSeconds[name] += time.Since(t).Seconds()
	g.noteHeap()
	g.logf("%s %.1f s", name, time.Since(t).Seconds())
}

func (g *gate) finish() {
	st := g.st
	sort.SliceStable(st.Refusals, func(i, j int) bool {
		a, b := st.Refusals[i], st.Refusals[j]
		if rank(a.Code) != rank(b.Code) {
			return rank(a.Code) < rank(b.Code)
		}
		return a.Detail < b.Detail
	})
	if st.Refusals == nil {
		st.Refusals = []Refusal{}
		st.Verdict = VerdictReleaseOK
	} else {
		st.Verdict = VerdictRefused
	}
	g.noteHeap()
	g.rep.Run.GoHeapSysMaxBytes = g.heapMax
	g.rep.Run.FinishedUTC = utcNow()
	d, err := StatementDigest(st)
	if err != nil {
		// Unreachable for these types; a report without a digest fails Decode.
		d = ""
	}
	g.rep.StatementSHA256 = d
}

func (g *gate) run() {
	in, st := g.in, g.st
	if err := in.Validate(); err != nil {
		g.refuse(CodeUnreadable, "%v", err)
		return
	}

	// 1. The gate's own build.
	bi, ok := readBuildInfo()
	var err error
	if st.Checker, err = checkerOf(bi, ok); err != nil {
		g.refuse(CodeCheckerBuild, "%v", err)
	}
	if ok && bi != nil {
		g.rep.Run.BuildPath, g.rep.Run.VCSTime = bi.Path, setting(bi, "vcs.time")
	}

	// 2. The ceremony's record, all small files, checked before anything
	// large is read or any weight is drawn.
	t := g.transcript()
	g.keyMetadata(t)
	g.ceremonyReport(t)
	g.expectedDigests(t)
	if g.refused() {
		return
	}
	g.rep.Run.InputsBoundUTC = utcNow()

	// 3. R1CS, phase 1 and the plan (the weights are drawn here); both are
	// dropped before the keys are read.
	r1cs := &cs.R1CS{}
	if !g.readPinned("readR1CS", in.R1CS, in.R1CSSHA256, &st.Files.R1CS, CodeR1CSDigest, r1cs.ReadFrom) {
		return
	}
	nbInternal, nbSecret, nbPublic := r1cs.GetNbVariables()
	n := crscheck.Domain(r1cs)
	st.Circuit = &Circuit{NbConstraints: r1cs.GetNbConstraints(), NbWires: nbInternal + nbSecret + nbPublic, NbPublic: nbPublic, Domain: n}
	var srs *crscheck.SRS
	g.stage("readPtau", func() { srs, err = crscheck.ReadPtau(in.Ptau, in.PtauSHA256, n) })
	if err != nil {
		if errors.Is(err, crscheck.ErrDigestMismatch) {
			g.refuse(CodePtauPin, "the phase-1 file: %v", err)
		} else {
			g.refuse(CodeUnreadable, "the phase-1 file: %v", err)
		}
		return
	}
	st.Files.Ptau.SHA256 = srs.FileSHA256
	if fi, err := os.Stat(in.Ptau); err == nil {
		st.Files.Ptau.Bytes = fi.Size()
	}
	var plan *crscheck.Plan
	g.rep.Run.WeightsDrawnFromUTC = utcNow()
	g.stage("prepare", func() { plan, err = crscheck.Prepare(r1cs, srs, crscheck.Options{}) })
	g.rep.Run.WeightsDrawnByUTC = utcNow()
	if err != nil {
		g.refuse(CodeUnreadable, "preparing the check: %v", err)
		return
	}
	g.rep.Run.PlanSeconds = plan.Seconds
	st.Circuit.NbCommitted, st.Circuit.MaskPositions = plan.NbCommitted, plan.Masks
	r1cs, srs = nil, nil
	g.free()

	// 4. The keys, with gnark's checked decoders (curve and subgroup checks
	// on every point), each hashed before it is parsed.
	pk, vk := &groth16bn254.ProvingKey{}, &groth16bn254.VerifyingKey{}
	if !g.readPinned("readVerifyingKey", in.VerifyingKey, in.VerifyingKeySHA256, &st.Files.VerifyingKey, CodeVKDigest, vk.ReadFrom) {
		return
	}
	if !g.readPinned("readProvingKey", in.ProvingKey, in.ProvingKeySHA256, &st.Files.ProvingKey, CodePKDigest, pk.ReadFrom) {
		return
	}
	kl := map[string]int{"A": len(pk.G1.A), "B1": len(pk.G1.B), "B2": len(pk.G2.B), "K": len(pk.G1.K), "Z": len(pk.G1.Z),
		"nbInfinityA": int(pk.NbInfinityA), "nbInfinityB": int(pk.NbInfinityB), "vkK": len(vk.G1.K), "commitments": len(pk.CommitmentKeys)}
	for k, ck := range pk.CommitmentKeys {
		kl[fmt.Sprintf("basis%d", k)] = len(ck.Basis)
	}
	st.Circuit.KeyVectorLengths = kl

	// 5. The clean check, the negative controls, the restored key.
	var clean *crscheck.Report
	g.stage("checkKey", func() { clean, err = plan.CheckKey(pk, vk) })
	if err != nil {
		g.refuse(CodeUnreadable, "checking the key: %v", err)
		return
	}
	st.Checks, st.PrivacyOnlyVerdict, g.rep.Run.CheckSeconds = clean.Results, clean.Verdict, clean.Seconds
	if r := judgeChecks(clean, len(plan.NbCommitted)); len(r) > 0 {
		// Refused on the key itself; the controls would add nothing.
		st.Refusals = append(st.Refusals, r...)
		return
	}

	controls, err := plan.Controls(pk)
	if err != nil {
		g.refuse(CodeControl, "the negative controls could not be made: %v", err)
	}
	for _, c := range controls {
		var rep *crscheck.Report
		g.stage("control:"+c.Name, func() {
			undo := c.Apply(pk, vk)
			defer undo()
			rep, err = plan.CheckKey(pk, vk)
		})
		if err != nil {
			g.refuse(CodeUnreadable, "checking the key under control %s: %v", c.Name, err)
			return
		}
		fired, why := c.Fired(rep)
		g.logf("control %s fired=%v (%s)", c.Name, fired, why)
		st.Controls = append(st.Controls, ControlOutcome{Name: c.Name, Change: c.Change, MustFail: c.MustFail, Fired: fired, Failed: failedNames(rep)})
	}
	var restored *crscheck.Report
	g.stage("checkRestoredKey", func() { restored, err = plan.CheckKey(pk, vk) })
	if err != nil {
		g.refuse(CodeUnreadable, "re-checking the restored key: %v", err)
		return
	}
	st.RestoredKey = &Restored{Verdict: restored.Verdict, Failed: failedNames(restored)}
	st.Refusals = append(st.Refusals, judgeControls(st.Controls, st.RestoredKey, len(plan.NbCommitted))...)
}

func failedNames(rep *crscheck.Report) []string {
	f := []string{}
	for _, r := range rep.Results {
		if !r.Pass && !slices.Contains(f, r.Name) {
			f = append(f, r.Name)
		}
	}
	return f
}

// Required checks: each base check once, each commitment check once per
// commitment.
var (
	baseChecks = []string{
		crscheck.CheckSRSPowers, crscheck.CheckTauDomain, crscheck.CheckSchedule, crscheck.CheckShape, crscheck.CheckDomain, crscheck.CheckNonZero,
		crscheck.CheckBeta, crscheck.CheckDelta, crscheck.CheckAQuery, crscheck.CheckBQueryG1, crscheck.CheckBQueryG2,
		crscheck.CheckKQuery, crscheck.CheckZQuery, crscheck.CheckVKK, crscheck.CheckVKMatch, crscheck.CheckPhase1,
	}
	commitmentChecks = []string{crscheck.CheckCommitBase, crscheck.CheckCommitSig, crscheck.CheckCommitMask, crscheck.CheckMaskOrigin}
	// Every check a negative control must target; the commitment ones only
	// when the circuit has a commitment. SRS_POWERS, TAU_NOT_IN_DOMAIN,
	// KEY_SHAPE and DELTA_G1_G2, and the R1CS's R1CS_SCHEDULE and
	// COMMITMENT_MASK_RANDOMIZED, have toy negatives in crscheck's and this
	// package's tests instead: the phase-1 file, the R1CS and the key's shape
	// are fixed by digest here.
	controlTargets = []string{
		crscheck.CheckNonZero, crscheck.CheckZQuery, crscheck.CheckKQuery, crscheck.CheckAQuery, crscheck.CheckBQueryG1,
		crscheck.CheckBQueryG2, crscheck.CheckBeta, crscheck.CheckDomain, crscheck.CheckVKK, crscheck.CheckVKMatch, crscheck.CheckPhase1,
	}
)

// judgeChecks decides the refusals of the clean check from its results
// alone: every zero-knowledge check and every ancillary check must pass, and
// every required check must be present.
func judgeChecks(clean *crscheck.Report, nbCommitments int) []Refusal {
	var out []Refusal
	refuse := func(c Code, format string, a ...any) { out = append(out, Refusal{c, fmt.Sprintf(format, a...)}) }
	count := map[string]int{}
	var failedZK, failedOther []string
	shapeFailed := false
	for _, r := range clean.Results {
		count[r.Name]++
		if r.Pass {
			continue
		}
		if r.Name == crscheck.CheckShape {
			shapeFailed = true
		}
		if r.ZK {
			failedZK = append(failedZK, r.Name)
		} else {
			failedOther = append(failedOther, r.Name)
		}
	}
	if len(failedZK) > 0 || clean.Verdict != crscheck.VerdictWellFormed {
		refuse(CodeMalformed, "privacy-only verdict %s; failed zero-knowledge checks %v", clean.Verdict, failedZK)
	}
	// KEY_SHAPE stops the checker before the equations, by design.
	if !shapeFailed {
		var missing []string
		for _, n := range baseChecks {
			if count[n] < 1 {
				missing = append(missing, n)
			}
		}
		for _, n := range commitmentChecks {
			if count[n] < nbCommitments {
				missing = append(missing, fmt.Sprintf("%s (%d of %d)", n, count[n], nbCommitments))
			}
		}
		if len(missing) > 0 {
			refuse(CodeIncomplete, "missing from the checker's results: %s", strings.Join(missing, ", "))
		}
	}
	if len(failedOther) > 0 {
		refuse(CodeAncillary, "failed ancillary checks %v (the privacy-only verdict does not include them)", failedOther)
	}
	return out
}

// judgeControls decides the refusals of the negative controls, run on a key
// whose clean check passed: every control fired, one targets each required
// check, and the restored key passes every check again.
func judgeControls(controls []ControlOutcome, restored *Restored, nbCommitments int) []Refusal {
	var out []Refusal
	refuse := func(c Code, format string, a ...any) { out = append(out, Refusal{c, fmt.Sprintf(format, a...)}) }
	targets := slices.Clone(controlTargets)
	if nbCommitments > 0 {
		targets = append(targets, crscheck.CheckCommitBase, crscheck.CheckCommitSig, crscheck.CheckCommitMask)
	}
	targeted := map[string]bool{}
	var notFired []string
	for _, c := range controls {
		for _, m := range c.MustFail {
			targeted[m] = true
		}
		if !c.Fired {
			notFired = append(notFired, c.Name)
		}
	}
	var untargeted []string
	for _, n := range targets {
		if !targeted[n] {
			untargeted = append(untargeted, n)
		}
	}
	if len(notFired) > 0 {
		refuse(CodeControl, "negative controls that did not fire: %v", notFired)
	}
	if len(untargeted) > 0 {
		refuse(CodeControl, "no negative control targets %v", untargeted)
	}
	if restored == nil || restored.Verdict != crscheck.VerdictWellFormed || len(restored.Failed) > 0 {
		refuse(CodeControl, "the key restored after the controls does not pass every check again: %+v", restored)
	}
	return out
}

// transcript reads and checks the transcript. It returns nil when the
// transcript is unusable for the checks that depend on it.
func (g *gate) transcript() *transcript.Transcript {
	rec := &g.st.Files.Transcript
	b, err := os.ReadFile(g.in.Transcript)
	if err != nil {
		g.refuse(CodeTranscript, "reading the transcript: %v", err)
		return nil
	}
	rec.SHA256, rec.Bytes = digest(b), int64(len(b))
	var t transcript.Transcript
	if err := transcript.DecodeStrict(b, &t, failure.TranscriptFormat, "transcript"); err != nil {
		g.refuse(CodeTranscript, "%v", err)
		return nil
	}
	if t.Format != transcript.Format {
		g.refuse(CodeTranscript, "format %q, want %q", t.Format, transcript.Format)
		return nil
	}
	if t.Status != transcript.StatusSealed || t.Keys == nil || t.Beacon == nil {
		g.refuse(CodeTranscript, "the transcript is not sealed (status %q)", t.Status)
		return nil
	}
	if err := t.CheckLabels(); err != nil {
		g.refuse(CodeTranscript, "%v", err)
	}
	if t.Tool.Curve != "bn254" || t.Tool.Backend != "groth16" {
		g.refuse(CodeTranscript, "tool %s/%s; the check is for bn254/groth16", t.Tool.Curve, t.Tool.Backend)
	}
	if t.Keys.ProvingKey.Encoding != transcript.ProvingKeyEncoding || t.Keys.VerifyingKey.Encoding != transcript.VerifyingKeyEncoding {
		g.refuse(CodeTranscript, "key encodings %q, %q", t.Keys.ProvingKey.Encoding, t.Keys.VerifyingKey.Encoding)
	}
	if t.Tool.Gnark != crscheck.GnarkVersion || t.Tool.GnarkCrypto != crscheck.GnarkCryptoVersion {
		g.refuse(CodeGnarkVersion, "the transcript's keys come from gnark %s / gnark-crypto %s; crscheck is written against %s / %s",
			t.Tool.Gnark, t.Tool.GnarkCrypto, crscheck.GnarkVersion, crscheck.GnarkCryptoVersion)
	}
	c := &g.st.Ceremony
	c.ID, c.Provenance, c.ZeroValueOnly, c.Notice = t.CeremonyID, string(t.Provenance), t.ZeroValueOnly, t.Notice
	f := &g.st.Files
	f.R1CS.Transcript, f.Ptau.Transcript = t.Circuit.R1CSSHA256, t.Phase1.Pin.Digest
	f.ProvingKey.Transcript, f.VerifyingKey.Transcript = t.Keys.ProvingKey.SHA256, t.Keys.VerifyingKey.SHA256
	return &t
}

// fieldDiff names the top-level JSON fields in which a and b differ.
func fieldDiff(a, b any) []string {
	var ma, mb map[string]json.RawMessage
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	if errA != nil || errB != nil || json.Unmarshal(ja, &ma) != nil || json.Unmarshal(jb, &mb) != nil {
		return []string{"(unencodable)"}
	}
	var d []string
	for k, v := range ma {
		if w, ok := mb[k]; !ok || !bytes.Equal(v, w) {
			d = append(d, k)
		}
	}
	for k := range mb {
		if _, ok := ma[k]; !ok {
			d = append(d, k)
		}
	}
	sort.Strings(d)
	return d
}

func (g *gate) keyMetadata(t *transcript.Transcript) {
	rec := &g.st.Files.KeyMetadata
	b, err := os.ReadFile(g.in.KeyMetadata)
	if err != nil {
		g.refuse(CodeKeyMetadata, "reading the key metadata: %v", err)
		return
	}
	rec.SHA256, rec.Bytes = digest(b), int64(len(b))
	var m transcript.KeyMetadata
	if err := transcript.DecodeStrict(b, &m, failure.KeyMetadataMalformed, "key metadata"); err != nil {
		g.refuse(CodeKeyMetadata, "%v", err)
		return
	}
	if t == nil {
		return
	}
	if want := transcript.MetadataFor(t); m != want {
		g.refuse(CodeKeyMetadata, "the key metadata differs from what the transcript implies in %v", fieldDiff(m, want))
	}
}

// reportFor is the verifier output a VALID, doubly anchored verification of t
// produces (verifier.Verify).
func reportFor(t *transcript.Transcript) verifier.Report {
	r := verifier.Report{
		Verdict: verifier.VerdictValid, Anchors: verifier.Anchors{Phase1Pin: true, Beacon: true},
		Provenance: t.Provenance, ZeroValueOnly: t.ZeroValueOnly, Notice: t.Notice, CeremonyID: t.CeremonyID,
		CircuitLabel: t.Circuit.Label, R1CSSHA256: t.Circuit.R1CSSHA256, NbConstraints: t.Circuit.NbConstraints,
		Phase1Pin: t.Phase1.Pin, Phase1CommonsSHA256: t.Phase1.CommonsSHA256, DomainSize: t.Phase1.DomainSize,
		Beacon: *t.Beacon, ProvingKeySHA256: t.Keys.ProvingKey.SHA256, VerifyingKeySHA256: t.Keys.VerifyingKey.SHA256,
	}
	for _, c := range t.Phase2.Contributions {
		r.Contributions = append(r.Contributions, verifier.ReportContribution{Index: c.Index, StateSHA256: c.StateSHA256, Contributor: c.Contributor})
	}
	return r
}

// ceremonyReport binds the release to the ceremony verifier's archived
// output: the file the operator names by digest, VALID with both anchors,
// about this transcript.
func (g *gate) ceremonyReport(t *transcript.Transcript) {
	rec := &g.st.Files.CeremonyReport
	rec.Expected = g.in.CeremonyReportSHA256
	b, err := os.ReadFile(g.in.CeremonyReport)
	if err != nil {
		g.refuse(CodeCeremonyNotValid, "reading the ceremony verifier's output: %v", err)
		return
	}
	rec.SHA256, rec.Bytes = digest(b), int64(len(b))
	if rec.SHA256 != rec.Expected {
		g.refuse(CodeReportDigest, "the ceremony verifier's output hashes to %s, want %s", rec.SHA256, rec.Expected)
		return
	}
	var rep verifier.Report
	if err := transcript.DecodeStrict(b, &rep, failure.TranscriptFormat, "ceremony verifier report"); err != nil {
		g.refuse(CodeCeremonyNotValid, "not a verifier report (a REFUSED output is not one): %v", err)
		return
	}
	c := &g.st.Ceremony
	c.VerifierVerdict, c.Anchors, c.TranscriptSHA256, c.VerifierBuild = rep.Verdict, rep.Anchors, rep.TranscriptSHA256, rep.VerifierBuild
	if !rep.Authoritative() {
		g.refuse(CodeCeremonyNotValid, "the verifier's verdict is %q with anchors %+v; only VALID with both anchors is authoritative", rep.Verdict, rep.Anchors)
	}
	// The exact transcript (REV-198 H2): the output must name the bytes the
	// gate hashed and parsed, not only agree on the fields it reports.
	if parsed := g.st.Files.Transcript.SHA256; rep.TranscriptSHA256 == "" || rep.TranscriptSHA256 != parsed {
		if rep.TranscriptSHA256 == "" {
			g.refuse(CodeReportUnbound, "the verifier's output names no transcript SHA-256; an output from before ENG-443 cannot be bound to one transcript")
		} else {
			g.refuse(CodeReportUnbound, "the verifier's output names transcript %s; the transcript the gate parsed hashes to %q", rep.TranscriptSHA256, parsed)
		}
	}
	if why := unverifiedBuild(rep.VerifierBuild); why != "" {
		g.refuse(CodeVerifierUnverified, "the verifier's output does not record a clean, stamped build of this module: %s", why)
	}
	if t == nil {
		return
	}
	want := reportFor(t)
	// Judged above.
	want.Verdict, want.Anchors, want.TranscriptSHA256, want.VerifierBuild = rep.Verdict, rep.Anchors, rep.TranscriptSHA256, rep.VerifierBuild
	if d := fieldDiff(rep, want); len(d) > 0 {
		g.refuse(CodeReportMismatch, "the verifier's output differs from the transcript in %v", d)
	}
}

// unverifiedBuild says why b is not the verifier binary's unauthenticated
// self-report of a clean, stamped build of this module, or "" if it is. It
// re-checks every field rather than trusting b.Status alone: status verified
// with no reason, this module, a clean 40- or 64-hex revision recorded for
// audit rather than compared with a reviewed commit, and the gnark versions
// crscheck is written against.
func unverifiedBuild(b verifier.Build) string {
	var bad []string
	if b.Status != verifier.BuildVerified || b.Reason != "" {
		bad = append(bad, fmt.Sprintf("status %q (reason %q)", b.Status, b.Reason))
	}
	if b.Module != MainModule {
		bad = append(bad, fmt.Sprintf("module %q", b.Module))
	}
	if !vcsRevision.MatchString(b.VCSRevision) {
		bad = append(bad, fmt.Sprintf("vcsRevision %q", b.VCSRevision))
	}
	if b.VCSModified != "false" {
		bad = append(bad, fmt.Sprintf("vcsModified %q", b.VCSModified))
	}
	if b.Gnark != crscheck.GnarkVersion || b.GnarkCrypto != crscheck.GnarkCryptoVersion {
		bad = append(bad, fmt.Sprintf("gnark %q / gnark-crypto %q", b.Gnark, b.GnarkCrypto))
	}
	return strings.Join(bad, "; ")
}

// expectedDigests requires each out-of-band digest to equal the transcript's.
func (g *gate) expectedDigests(t *transcript.Transcript) {
	f, in := &g.st.Files, g.in
	f.R1CS.Expected, f.Ptau.Expected, f.ProvingKey.Expected, f.VerifyingKey.Expected = in.R1CSSHA256, in.PtauSHA256, in.ProvingKeySHA256, in.VerifyingKeySHA256
	if t == nil {
		return
	}
	if in.R1CSSHA256 != t.Circuit.R1CSSHA256 {
		g.refuse(CodeR1CSDigest, "out-of-band R1CS SHA-256 %s, the transcript names %s", in.R1CSSHA256, t.Circuit.R1CSSHA256)
	}
	if t.Phase1.Pin.Algorithm != "sha256" || in.PtauSHA256 != t.Phase1.Pin.Digest {
		g.refuse(CodePtauPin, "out-of-band phase-1 SHA-256 %s, the transcript pins %s", in.PtauSHA256, t.Phase1.Pin)
	}
	if in.VerifyingKeySHA256 != t.Keys.VerifyingKey.SHA256 {
		g.refuse(CodeVKDigest, "out-of-band verifying key SHA-256 %s, the transcript names %s", in.VerifyingKeySHA256, t.Keys.VerifyingKey.SHA256)
	}
	if in.ProvingKeySHA256 != t.Keys.ProvingKey.SHA256 {
		g.refuse(CodePKDigest, "out-of-band proving key SHA-256 %s, the transcript names %s", in.ProvingKeySHA256, t.Keys.ProvingKey.SHA256)
	}
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, bufio.NewReaderSize(f, 1<<22))
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// readPinned hashes path and refuses it with code unless it hashes to want;
// only then decodes it, hashing again as it reads, and requires the decoder
// to have consumed exactly the file (by its own count and by the reader's)
// and the same digest.
func (g *gate) readPinned(stage, path, want string, rec *File, code Code, decode func(io.Reader) (int64, error)) bool {
	ok := false
	g.stage(stage, func() {
		first, n, err := hashFile(path)
		if err != nil {
			g.refuse(CodeUnreadable, "%s: %v", path, err)
			return
		}
		rec.SHA256, rec.Bytes = first, n
		if first != want {
			g.refuse(code, "%s hashes to %s, want %s", filepath.Base(path), first, want)
			return
		}
		f, err := os.Open(path)
		if err != nil {
			g.refuse(CodeUnreadable, "%s: %v", path, err)
			return
		}
		defer f.Close()
		h := sha256.New()
		br := bufio.NewReaderSize(io.TeeReader(f, h), 1<<22)
		used, err := decode(br)
		if err != nil {
			g.refuse(CodeUnreadable, "decoding %s: %v", filepath.Base(path), err)
			return
		}
		if _, err := br.ReadByte(); err != io.EOF || used != n {
			g.refuse(CodeUnreadable, "%s: the decoder used %d of %d bytes", filepath.Base(path), used, n)
			return
		}
		if second := hex.EncodeToString(h.Sum(nil)); second != first {
			g.refuse(code, "%s changed between the digest pass and the decoding pass", filepath.Base(path))
			return
		}
		ok = true
	})
	return ok
}
