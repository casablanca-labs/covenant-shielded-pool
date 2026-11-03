// Package verifier re-verifies a sealed ceremony transcript from its public
// inputs alone: the pinned Powers of Tau file, the R1CS, the contribution
// files and the beacon. It re-derives every phase-2 step and the sealed keys
// and compares them with what was published. It does not import the
// coordinator or the contributor, and trusts nothing either wrote except as a
// claim to check. It does share the ptau importer and the transcript
// derivations (root, initial state, shape guard, decoding) with the
// coordinator, and both use gnark's phase-2 implementation, so a defect there
// is common to both. Beyond the replay it refuses a degenerate phase 1 (τ a
// root of unity of the domain, β = −1; at import), a BSB22 commitment whose
// mask is not the sole output of gnark's Randomize hint (before import), and
// a re-derived key whose mask basis element is O (after sealing), which a
// faithful replay alone would accept (ENG-440 after ARCH-238, IMPL-28 after
// REV-197).
package verifier

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

// Inputs names what to verify. The expectations are out-of-band values the
// verifier's operator already trusts, such as the published digest of the
// Perpetual Powers of Tau file or a pre-announced block hash; when set, the
// transcript must agree with them. The phase-1 pin and the beacon must both be
// set for a VALID verdict.
//
// ExpectedR1CSSHA256 is the circuit's R1CS digest from the proof-system
// record (the action circuit's manifest), hex. When set, the transcript must
// be for that circuit, and Anchors.R1CS reports it. When unset, the R1CS is
// checked only against the transcript's own record, so a VALID verdict says
// nothing about which circuit the keys are for; the mask checks then vouch
// only for whatever circuit the transcript names. A release gate sets it.
type Inputs struct {
	TranscriptPath     string
	PtauPath           string
	R1CSPath           string
	ExpectedPhase1Pin  *ptau.Pin
	ExpectedBeacon     string
	ExpectedR1CSSHA256 string
}

// ReportContribution lets a contributor find its own contribution.
type ReportContribution struct {
	Index       int                    `json:"index"`
	StateSHA256 string                 `json:"stateSha256"`
	Contributor transcript.Contributor `json:"contributor"`
}

// Verdicts of an accepted transcript.
//
// VerdictValid is the only authoritative verdict: the transcript is
// consistent end to end and agrees with both out-of-band anchors, the phase-1
// pin and the beacon, that the caller supplied.
//
// VerdictUnanchored means the same checks passed but at least one anchor was
// not supplied, so the transcript was checked only against the pin and beacon
// it names itself. Anyone can make a self-consistent transcript on a phase-1
// file and beacon of their choosing; this verdict does not say the ceremony
// used the ones the caller trusts. It deliberately does not contain the
// string "VALID".
const (
	VerdictValid      = "VALID"
	VerdictUnanchored = "CONSISTENT-UNANCHORED"
)

// Anchors records which out-of-band expectations the verdict rests on.
// R1CS does not enter the verdict (see Inputs.ExpectedR1CSSHA256).
type Anchors struct {
	Phase1Pin bool `json:"phase1Pin"`
	Beacon    bool `json:"beacon"`
	R1CS      bool `json:"r1cs"`
}

// Report is the verifier's verdict on a transcript it accepted.
type Report struct {
	Verdict             string                `json:"verdict"`
	Anchors             Anchors               `json:"anchors"`
	Provenance          transcript.Provenance `json:"provenance"`
	ZeroValueOnly       bool                  `json:"zeroValueOnly"`
	Notice              string                `json:"notice"`
	CeremonyID          string                `json:"ceremonyId"`
	CircuitLabel        string                `json:"circuitLabel"`
	R1CSSHA256          string                `json:"r1csSha256"`
	NbConstraints       int                   `json:"nbConstraints"`
	Phase1Pin           ptau.Pin              `json:"phase1Pin"`
	Phase1CommonsSHA256 string                `json:"phase1CommonsSha256"`
	DomainSize          uint64                `json:"domainSize"`
	Contributions       []ReportContribution  `json:"contributions"`
	Beacon              transcript.Beacon     `json:"beacon"`
	ProvingKeySHA256    string                `json:"provingKeySha256"`
	VerifyingKeySHA256  string                `json:"verifyingKeySha256"`
	// TranscriptSHA256 is the SHA-256 of exactly the transcript bytes the
	// verifier read and accepted, so the report names one file, not every
	// transcript that agrees on the fields above (REV-198).
	TranscriptSHA256 string `json:"transcriptSha256"`
	// VerifierBuild is the build that produced the report (see Build).
	VerifierBuild Build `json:"verifierBuild"`
}

// Authoritative reports whether the verdict is VALID, that is, anchored to
// both out-of-band expectations.
func (r *Report) Authoritative() bool {
	return r.Verdict == VerdictValid && r.Anchors.Phase1Pin && r.Anchors.Beacon
}

// MultiParty reports whether the verified transcript is permissionless
// multi-party. It is derived from the verified provenance only.
func (r *Report) MultiParty() bool {
	return r.Provenance == transcript.PermissionlessMultiParty
}

func plainName(name string) error {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return failure.New(failure.TranscriptFormat, "file name %q is not a plain name", name)
	}
	return nil
}

func checkStructure(t *transcript.Transcript) error {
	if t.Status != transcript.StatusSealed || t.Beacon == nil || t.Keys == nil {
		return failure.New(failure.TranscriptFormat, "transcript is not sealed")
	}
	if t.Tool != transcript.CurrentTool {
		return failure.New(failure.TranscriptFormat, "transcript was made by %+v, this verifier is %+v", t.Tool, transcript.CurrentTool)
	}
	if t.Keys.ProvingKey.Encoding != transcript.ProvingKeyEncoding || t.Keys.VerifyingKey.Encoding != transcript.VerifyingKeyEncoding {
		return failure.New(failure.TranscriptFormat, "unknown key encoding")
	}
	for _, n := range []string{t.Keys.ProvingKey.File, t.Keys.VerifyingKey.File, t.Keys.Metadata} {
		if err := plainName(n); err != nil {
			return err
		}
	}
	if len(t.Phase2.Contributions) == 0 {
		return failure.New(failure.CeremonyNoContributions, "transcript has no contribution")
	}
	for i, c := range t.Phase2.Contributions {
		if c.Index != i+1 {
			return failure.New(failure.TranscriptSequence, "contribution at position %d has index %d", i+1, c.Index)
		}
		if err := plainName(c.File); err != nil {
			return err
		}
	}
	return nil
}

// Verify checks a sealed transcript end to end and returns its report, or the
// first refusal.
func Verify(in Inputs) (*Report, error) {
	t, transcriptSHA, err := transcript.LoadDigest(in.TranscriptPath)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(in.TranscriptPath)
	if err := checkStructure(t); err != nil {
		return nil, err
	}
	if err := t.CheckLabels(); err != nil {
		return nil, err
	}

	// Circuit.
	if in.ExpectedR1CSSHA256 != "" && in.ExpectedR1CSSHA256 != t.Circuit.R1CSSHA256 {
		return nil, failure.New(failure.R1CSUnexpected, "transcript is for R1CS %s, expected %s", t.Circuit.R1CSSHA256, in.ExpectedR1CSSHA256)
	}
	r1cs, r1csSHA, err := transcript.ReadR1CS(in.R1CSPath)
	if err != nil {
		return nil, err
	}
	if r1csSHA != t.Circuit.R1CSSHA256 {
		return nil, failure.New(failure.R1CSDigestMismatch, "R1CS digest %s, transcript is for %s", r1csSHA, t.Circuit.R1CSSHA256)
	}
	if got := transcript.DescribeCircuit(t.Circuit.Label, r1cs, r1csSHA); got != t.Circuit {
		return nil, failure.New(failure.R1CSShapeMismatch, "R1CS shape %+v, transcript records %+v", got, t.Circuit)
	}
	// Where each commitment's random mask sits in the key, located while the
	// R1CS is held; the re-derived key is checked against it after sealing.
	masks, err := transcript.LocateCommitmentMasks(r1cs)
	if err != nil {
		return nil, err
	}

	// Phase 1.
	if in.ExpectedPhase1Pin != nil && *in.ExpectedPhase1Pin != t.Phase1.Pin {
		return nil, failure.New(failure.Phase1PinUnexpected, "transcript pins phase 1 to %s, expected %s", t.Phase1.Pin, *in.ExpectedPhase1Pin)
	}
	domain := transcript.DomainSize(r1cs)
	if t.Phase1.DomainSize != domain {
		return nil, failure.New(failure.Phase1DomainMismatch, "transcript domain %d, circuit needs %d", t.Phase1.DomainSize, domain)
	}
	commons, info, err := ptau.ImportFile(in.PtauPath, t.Phase1.Pin, domain)
	if err != nil {
		return nil, err
	}
	if info.Power != t.Phase1.Power || info.FileSize != t.Phase1.FileSize {
		return nil, failure.New(failure.Phase1DomainMismatch, "phase-1 file is power %d, %d bytes; transcript records power %d, %d bytes", info.Power, info.FileSize, t.Phase1.Power, t.Phase1.FileSize)
	}
	if info.CommonsSHA256 != t.Phase1.CommonsSHA256 {
		return nil, failure.New(failure.Phase1CommonsMismatch, "phase-1 parameters digest %s, transcript records %s", info.CommonsSHA256, t.Phase1.CommonsSHA256)
	}

	// Phase-2 root, recomputed from the verifier's own digests.
	root, err := transcript.RootChallenge(t.CeremonyID, t.Provenance, info.CommonsSHA256, r1csSHA)
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(root) != t.Phase2.RootChallenge {
		return nil, failure.New(failure.RootMismatch, "root challenge does not match the transcript")
	}
	prev, prevBytes, evals, err := transcript.InitialState(r1cs, commons, root)
	if err != nil {
		return nil, err
	}
	prevSHA := transcript.Digest(prevBytes)
	if prevSHA != t.Phase2.InitialStateSHA256 || int64(len(prevBytes)) != t.Phase2.StateLength {
		return nil, failure.New(failure.InitialMismatch, "initial phase-2 state does not match the transcript")
	}
	// From here on only [α]₁, [β]₁ and [β]₂ of phase 1 are needed; the R1CS
	// and the τ vectors are no longer referenced and can be freed.
	sealCommons := transcript.SealCommons(commons)

	// The contribution chain.
	for _, rec := range t.Phase2.Contributions {
		state, err := os.ReadFile(filepath.Join(dir, rec.File))
		if errors.Is(err, fs.ErrNotExist) {
			return nil, failure.New(failure.ContributionMissing, "contribution %d file %s is missing", rec.Index, rec.File)
		} else if err != nil {
			return nil, failure.Wrap(failure.IO, err, "reading contribution %d", rec.Index)
		}
		if transcript.Digest(state) != rec.StateSHA256 {
			return nil, failure.New(failure.ContributionFileDigest, "contribution %d file does not match its recorded digest", rec.Index)
		}
		if rec.Challenge != prevSHA {
			return nil, failure.New(failure.ContributionChainBroken, "contribution %d records challenge %s, the previous state is %s", rec.Index, rec.Challenge, prevSHA)
		}
		if err := transcript.CheckShape(prev, prevBytes, state); err != nil {
			return nil, err
		}
		next, err := transcript.DecodeState(state)
		if err != nil {
			return nil, err
		}
		prevRaw, _ := hex.DecodeString(prevSHA)
		if !bytes.Equal(next.Challenge, prevRaw) {
			return nil, failure.New(failure.ContributionChainBroken, "contribution %d was not made on the previous state", rec.Index)
		}
		if err := prev.Verify(next); err != nil {
			return nil, failure.Wrap(failure.ContributionInvalid, err, "contribution %d does not verify", rec.Index)
		}
		prev, prevBytes, prevSHA = next, state, rec.StateSHA256
	}

	// Seal with the recorded beacon and compare the keys.
	if in.ExpectedBeacon != "" && in.ExpectedBeacon != t.Beacon.Value {
		return nil, failure.New(failure.BeaconUnexpected, "transcript beacon %s, expected %s", t.Beacon.Value, in.ExpectedBeacon)
	}
	beacon, err := transcript.DecodeBeacon(*t.Beacon)
	if err != nil {
		return nil, err
	}
	pk, vk := prev.Seal(sealCommons, evals, beacon)
	// A key the honest re-derivation yields can still have a mask basis
	// element of O; its commitments would not hide (ARCH-238).
	if err := masks.Check(pk); err != nil {
		return nil, err
	}
	// The re-derived keys are hashed as they are serialized, and the key
	// files as they are read, so neither is held as one buffer.
	pkSHA, err := transcript.DigestWriterTo(pk.WriteRawTo)
	if err != nil {
		return nil, failure.Wrap(failure.IO, err, "serializing proving key")
	}
	vkSHA, err := transcript.DigestWriterTo(vk.WriteTo)
	if err != nil {
		return nil, failure.Wrap(failure.IO, err, "serializing verifying key")
	}
	if pkSHA != t.Keys.ProvingKey.SHA256 || vkSHA != t.Keys.VerifyingKey.SHA256 {
		return nil, failure.New(failure.SealedKeyMismatch, "re-derived keys do not match the published digests")
	}
	for file, derived := range map[string]string{t.Keys.ProvingKey.File: pkSHA, t.Keys.VerifyingKey.File: vkSHA} {
		got, err := transcript.DigestFile(filepath.Join(dir, file))
		if err != nil {
			return nil, failure.Wrap(failure.KeyFileDigestMismatch, err, "reading %s", file)
		}
		if got != derived {
			return nil, failure.New(failure.KeyFileDigestMismatch, "%s does not match the re-derived key", file)
		}
	}
	meta, err := transcript.LoadKeyMetadata(filepath.Join(dir, t.Keys.Metadata))
	if err != nil {
		return nil, err
	}
	if *meta != transcript.MetadataFor(t) {
		return nil, failure.New(failure.KeyMetadataMismatch, "key metadata disagrees with the transcript")
	}

	anchors := Anchors{Phase1Pin: in.ExpectedPhase1Pin != nil, Beacon: in.ExpectedBeacon != "", R1CS: in.ExpectedR1CSSHA256 != ""}
	verdict := VerdictUnanchored
	if anchors.Phase1Pin && anchors.Beacon {
		verdict = VerdictValid
	}
	rep := &Report{
		Verdict:             verdict,
		Anchors:             anchors,
		Provenance:          t.Provenance,
		ZeroValueOnly:       t.ZeroValueOnly,
		Notice:              t.Notice,
		CeremonyID:          t.CeremonyID,
		CircuitLabel:        t.Circuit.Label,
		R1CSSHA256:          r1csSHA,
		NbConstraints:       t.Circuit.NbConstraints,
		Phase1Pin:           t.Phase1.Pin,
		Phase1CommonsSHA256: info.CommonsSHA256,
		DomainSize:          domain,
		Beacon:              *t.Beacon,
		ProvingKeySHA256:    pkSHA,
		VerifyingKeySHA256:  vkSHA,
		TranscriptSHA256:    transcriptSHA,
		VerifierBuild:       ThisBuild(),
	}
	for _, c := range t.Phase2.Contributions {
		rep.Contributions = append(rep.Contributions, ReportContribution{Index: c.Index, StateSHA256: c.StateSHA256, Contributor: c.Contributor})
	}
	return rep, nil
}
