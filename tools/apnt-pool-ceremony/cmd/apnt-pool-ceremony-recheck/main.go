// Command apnt-pool-ceremony-recheck evaluates, on a ceremony sealed and
// verified before ENG-440, only the checks ENG-440 added to the ceremony
// verifier:
//
//   - the phase-1 non-degeneracy checks (t(τ) ≠ 0 on the circuit's domain,
//     β ≠ −1), run as part of the pinned phase-1 import, ptau.ImportFile,
//     which is the code the verifier runs;
//   - the BSB22 mask check: the commitment masks located in the R1CS by
//     transcript.LocateCommitmentMasks, and CommitmentMasks.Check on the
//     published proving key.
//
// It is not a ceremony verification. It does not replay phase 2, re-seal, or
// compare the key with a re-derivation; apnt-pool-ceremony-verify does that.
// Its inputs are anchored to the transcript's own record and to three values
// the caller trusts out of band: the phase-1 pin, the circuit's R1CS SHA-256
// (from the proof-system record) and the proving key's SHA-256. It reads its
// inputs and writes only its report, a JSON object on stdout.
//
// Exit status: 0 PASS, 1 refused (the stable failure code is in the report),
// 2 usage error.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

// Scope is carried in every report.
const Scope = "ENG-440 recheck only: the phase-1 import with its non-degeneracy checks (t(τ) ≠ 0, β ≠ −1), " +
	"the location of each BSB22 commitment's Randomize-hint mask, and the mask basis check on the published " +
	"proving key; not a ceremony verification (no phase-2 replay, no re-seal, no comparison with a re-derived key)"

// Report is the command's output.
type Report struct {
	Scope               string                      `json:"scope"`
	Verdict             string                      `json:"verdict"` // PASS or REFUSED
	Code                failure.Code                `json:"code,omitempty"`
	Detail              string                      `json:"detail,omitempty"`
	CeremonyID          string                      `json:"ceremonyId,omitempty"`
	Provenance          transcript.Provenance       `json:"provenance,omitempty"`
	ZeroValueOnly       bool                        `json:"zeroValueOnly"`
	R1CSSHA256          string                      `json:"r1csSha256,omitempty"`
	DomainSize          uint64                      `json:"domainSize,omitempty"`
	Phase1Pin           *ptau.Pin                   `json:"phase1Pin,omitempty"`
	Phase1CommonsSHA256 string                      `json:"phase1CommonsSha256,omitempty"`
	ProvingKeySHA256    string                      `json:"provingKeySha256,omitempty"`
	Checks              []Check                     `json:"checks"`
	Masks               *transcript.CommitmentMasks `json:"masks,omitempty"`
	Seconds             map[string]float64          `json:"seconds"`
}

// Check is one passed step.
type Check struct {
	Name   string `json:"name"`
	Detail string `json:"detail"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("apnt-pool-ceremony-recheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tpath := fs.String("transcript", "", "the sealed ceremony's transcript.json")
	ptauPath := fs.String("ptau", "", "the phase-1 .ptau file")
	r1csPath := fs.String("r1cs", "", "the circuit's R1CS")
	expPin := fs.String("expect-phase1-pin", "", "the phase-1 pin trusted out of band, ALG:HEX")
	expPK := fs.String("expect-proving-key-sha256", "", "the proving key's SHA-256 trusted out of band, hex")
	expR1CS := fs.String("expect-r1cs-sha256", "", "the circuit's R1CS SHA-256 from the proof-system record, hex")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *tpath == "" || *ptauPath == "" || *r1csPath == "" || *expPin == "" || *expPK == "" || *expR1CS == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: apnt-pool-ceremony-recheck --transcript F --ptau F --r1cs F --expect-phase1-pin ALG:HEX --expect-r1cs-sha256 HEX --expect-proving-key-sha256 HEX")
		return 2
	}
	pin, err := ptau.ParsePin(*expPin)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	rep := &Report{Scope: Scope, Seconds: map[string]float64{}}
	err = recheck(rep, *tpath, *ptauPath, *r1csPath, pin, *expR1CS, *expPK)
	status := 0
	if err != nil {
		rep.Verdict, rep.Code, rep.Detail, status = "REFUSED", failure.CodeOf(err), err.Error(), 1
		fmt.Fprintf(stderr, "REFUSED %s\n", err)
	} else {
		rep.Verdict = "PASS"
		fmt.Fprintf(stderr, "PASS: %d checks\n", len(rep.Checks))
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	stdout.Write(append(b, '\n'))
	return status
}

func recheck(rep *Report, tpath, ptauPath, r1csPath string, pin ptau.Pin, expR1CS, expPK string) error {
	lap := func(name string, since time.Time) { rep.Seconds[name] = time.Since(since).Seconds() }
	pass := func(name, format string, args ...any) {
		rep.Checks = append(rep.Checks, Check{Name: name, Detail: fmt.Sprintf(format, args...)})
	}

	t, err := transcript.Load(tpath)
	if err != nil {
		return err
	}
	if t.Status != transcript.StatusSealed || t.Keys == nil {
		return failure.New(failure.TranscriptFormat, "transcript is not sealed")
	}
	rep.CeremonyID, rep.Provenance, rep.ZeroValueOnly = t.CeremonyID, t.Provenance, t.ZeroValueOnly
	if pin != t.Phase1.Pin {
		return failure.New(failure.Phase1PinUnexpected, "transcript pins phase 1 to %s, expected %s", t.Phase1.Pin, pin)
	}
	if expR1CS != t.Circuit.R1CSSHA256 {
		return failure.New(failure.R1CSUnexpected, "transcript is for R1CS %s, expected %s", t.Circuit.R1CSSHA256, expR1CS)
	}
	if expPK != t.Keys.ProvingKey.SHA256 {
		return failure.New(failure.KeyFileDigestMismatch, "transcript records proving key %s, expected %s", t.Keys.ProvingKey.SHA256, expPK)
	}
	rep.Phase1Pin, rep.ProvingKeySHA256 = &t.Phase1.Pin, t.Keys.ProvingKey.SHA256
	pass("ANCHORS", "the transcript's phase-1 pin, R1CS digest and proving-key digest equal the expected values")

	t0 := time.Now()
	r1cs, r1csSHA, err := transcript.ReadR1CS(r1csPath)
	if err != nil {
		return err
	}
	if r1csSHA != t.Circuit.R1CSSHA256 {
		return failure.New(failure.R1CSDigestMismatch, "R1CS digest %s, transcript is for %s", r1csSHA, t.Circuit.R1CSSHA256)
	}
	domain := transcript.DomainSize(r1cs)
	if domain != t.Phase1.DomainSize {
		return failure.New(failure.Phase1DomainMismatch, "transcript domain %d, circuit needs %d", t.Phase1.DomainSize, domain)
	}
	rep.R1CSSHA256, rep.DomainSize = r1csSHA, domain
	lap("readR1cs", t0)

	t0 = time.Now()
	masks, err := transcript.LocateCommitmentMasks(r1cs)
	if err != nil {
		return err
	}
	rep.Masks = masks
	pass("COMMITMENT_MASKS_LOCATED", "%d commitment(s); mask positions %v of %v committed wires, each the sole output of gnark's Randomize hint (id %#x) with no input", len(masks.Positions), masks.Positions, masks.NbCommitted, uint32(transcript.RandomizeHintID))
	lap("locateMasks", t0)

	t0 = time.Now()
	commons, info, err := ptau.ImportFile(ptauPath, t.Phase1.Pin, domain)
	if err != nil {
		return err
	}
	if info.CommonsSHA256 != t.Phase1.CommonsSHA256 {
		return failure.New(failure.Phase1CommonsMismatch, "phase-1 parameters digest %s, transcript records %s", info.CommonsSHA256, t.Phase1.CommonsSHA256)
	}
	rep.Phase1CommonsSHA256 = info.CommonsSHA256
	pass("PHASE1_IMPORT", "pinned import accepted at domain %d (whole-file digest twice, every point, common ratio, β, and the non-degeneracy checks)", domain)
	// The import above already ran it; run it again on the imported
	// parameters so the report names it.
	if err := ptau.CheckNonDegenerate(commons); err != nil {
		return err
	}
	pass("PHASE1_NON_DEGENERATE", "[τ^%d]₁ ≠ [τ⁰]₁ (t(τ) ≠ 0) and [β]₁ ≠ −[1]₁ (β ≠ −1)", domain)
	lap("phase1Import", t0)

	t0 = time.Now()
	name := t.Keys.ProvingKey.File
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return failure.New(failure.TranscriptFormat, "proving key file name %q is not a plain name", name)
	}
	pkPath := filepath.Join(filepath.Dir(tpath), name)
	pk, err := readProvingKey(pkPath, t.Keys.ProvingKey.SHA256)
	if err != nil {
		return err
	}
	pass("PROVING_KEY_READ", "%s: SHA-256 equals the record on the pass that decoded it (gnark's checked decoder)", t.Keys.ProvingKey.File)
	lap("readProvingKey", t0)

	t0 = time.Now()
	if err := masks.Check(pk); err != nil {
		return err
	}
	for k, ps := range masks.Positions {
		for _, p := range ps {
			pass("COMMITMENT_MASK_NONZERO", "commitment %d: the basis element at mask position %d of %d is not O", k, p, masks.NbCommitted[k])
		}
	}
	lap("checkMasks", t0)
	return nil
}

// readProvingKey hashes the key file and refuses a digest other than want
// before decoding it, then decodes it while hashing it again and refuses
// unless that digest also matches and the decoder consumed the whole file.
func readProvingKey(path, want string) (*groth16bn254.ProvingKey, error) {
	got, err := transcript.DigestFile(path)
	if err != nil {
		return nil, failure.Wrap(failure.KeyFileDigestMismatch, err, "reading %s", path)
	}
	if got != want {
		return nil, failure.New(failure.KeyFileDigestMismatch, "%s has SHA-256 %s, the record %s", path, got, want)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, failure.Wrap(failure.IO, err, "opening %s", path)
	}
	defer f.Close()
	h := sha256.New()
	br := bufio.NewReaderSize(io.TeeReader(f, h), 1<<20)
	pk := &groth16bn254.ProvingKey{}
	if _, err := pk.ReadFrom(br); err != nil {
		return nil, failure.Wrap(failure.IO, err, "decoding %s", path)
	}
	rest, err := io.Copy(io.Discard, br)
	if err != nil {
		return nil, failure.Wrap(failure.IO, err, "reading %s", path)
	}
	if rest != 0 {
		return nil, failure.New(failure.KeyFileDigestMismatch, "%s has %d bytes after the key", path, rest)
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		return nil, failure.New(failure.KeyFileDigestMismatch, "%s changed between the digest pass and the decoding pass", path)
	}
	return pk, nil
}
