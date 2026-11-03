// Package coordinator runs a phase-2 ceremony as a sequential queue: it hands
// the latest verified state to one contributor at a time, verifies what comes
// back, and refuses anything that does not verify. It cannot forge a
// contribution; it can only stall or censor, which is a liveness matter.
package coordinator

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	cs "github.com/consensys/gnark/constraint/bn254"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

// Config starts a ceremony.
type Config struct {
	Dir          string
	CeremonyID   string
	Provenance   transcript.Provenance
	Phase1       transcript.Phase1 // CommonsSHA256 and DomainSize are filled in
	Commons      *mpcsetup.SrsCommons
	R1CS         *cs.R1CS
	R1CSSHA256   string
	CircuitLabel string
	// Work, when set, receives the initial state and the evaluations so that
	// later phases can run as separate processes (see Open). It must be new
	// or empty, and not Dir.
	Work string
}

// Coordinator holds the latest verified state of one ceremony.
type Coordinator struct {
	dir          string
	t            transcript.Transcript
	commons      *mpcsetup.SrsCommons
	evals        *mpcsetup.Phase2Evaluations
	current      *mpcsetup.Phase2
	currentBytes []byte
	currentSHA   string
	sealed       bool
}

// New initializes phase 2 for the R1CS and writes an open transcript. It
// refuses a directory that already holds anything, so a re-run never
// overwrites an earlier ceremony.
func New(cfg Config) (*Coordinator, error) {
	prov, err := transcript.ParseProvenance(string(cfg.Provenance))
	if err != nil {
		return nil, err
	}
	if entries, err := os.ReadDir(cfg.Dir); err == nil && len(entries) > 0 {
		return nil, failure.New(failure.OutputExists, "%s is not empty", cfg.Dir)
	}
	if cfg.Work != "" {
		if filepath.Clean(cfg.Work) == filepath.Clean(cfg.Dir) {
			return nil, failure.New(failure.OutputExists, "the work directory must not be the ceremony directory")
		}
		if entries, err := os.ReadDir(cfg.Work); err == nil && len(entries) > 0 {
			return nil, failure.New(failure.OutputExists, "%s is not empty", cfg.Work)
		}
	}
	if err := os.MkdirAll(cfg.Dir, 0o755); err != nil {
		return nil, failure.Wrap(failure.IO, err, "creating %s", cfg.Dir)
	}
	domain := transcript.DomainSize(cfg.R1CS)
	if uint64(len(cfg.Commons.G2.Tau)) != domain {
		return nil, failure.New(failure.Phase1DomainMismatch, "phase-1 parameters are for domain %d, the circuit needs %d", len(cfg.Commons.G2.Tau), domain)
	}
	commonsSHA, err := ptau.CommonsDigest(cfg.Commons)
	if err != nil {
		return nil, err
	}
	if cfg.Phase1.CommonsSHA256 != "" && cfg.Phase1.CommonsSHA256 != commonsSHA {
		return nil, failure.New(failure.Phase1CommonsMismatch, "phase-1 parameters do not match the import record")
	}
	cfg.Phase1.CommonsSHA256 = commonsSHA
	cfg.Phase1.DomainSize = domain

	root, err := transcript.RootChallenge(cfg.CeremonyID, prov, commonsSHA, cfg.R1CSSHA256)
	if err != nil {
		return nil, err
	}
	state, stateBytes, evals, err := transcript.InitialState(cfg.R1CS, cfg.Commons, root)
	if err != nil {
		return nil, err
	}
	c := &Coordinator{
		dir:     cfg.Dir,
		commons: cfg.Commons,
		evals:   evals,
		current: state, currentBytes: stateBytes, currentSHA: transcript.Digest(stateBytes),
		t: transcript.Transcript{
			Format:        transcript.Format,
			Status:        transcript.StatusOpen,
			CeremonyID:    cfg.CeremonyID,
			Provenance:    prov,
			ZeroValueOnly: prov.ZeroValueOnly(),
			Notice:        prov.Notice(),
			Tool:          transcript.CurrentTool,
			Phase1:        cfg.Phase1,
			Circuit:       transcript.DescribeCircuit(cfg.CircuitLabel, cfg.R1CS, cfg.R1CSSHA256),
			Phase2: transcript.Phase2Record{
				RootChallenge:      hex.EncodeToString(root),
				InitialStateSHA256: transcript.Digest(stateBytes),
				StateLength:        int64(len(stateBytes)),
				Contributions:      []transcript.Contribution{},
			},
		},
	}
	if err := c.save(); err != nil {
		return nil, err
	}
	if cfg.Work != "" {
		if err := c.saveWork(cfg.Work, cfg.R1CSSHA256); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *Coordinator) save() error {
	return transcript.WriteJSON(filepath.Join(c.dir, transcript.TranscriptFile), &c.t)
}

// Transcript returns a copy of the current transcript.
func (c *Coordinator) Transcript() transcript.Transcript {
	t := c.t
	t.Phase2.Contributions = append([]transcript.Contribution(nil), c.t.Phase2.Contributions...)
	return t
}

// Challenge returns the message the next contributor answers.
func (c *Coordinator) Challenge() ([]byte, error) {
	if c.sealed {
		return nil, failure.New(failure.CeremonySealed, "ceremony is sealed")
	}
	return transcript.EncodeMessage(transcript.MessageHeader{
		Type:        transcript.MessageChallenge,
		Format:      transcript.Format,
		CeremonyID:  c.t.CeremonyID,
		Provenance:  c.t.Provenance,
		Index:       len(c.t.Phase2.Contributions) + 1,
		StateSHA256: c.currentSHA,
		StateLength: int64(len(c.currentBytes)),
	}, c.currentBytes)
}

// Submit verifies a contribution message against the latest state and, only
// if every check passes, records it. A refused message changes nothing.
func (c *Coordinator) Submit(msg []byte) (*transcript.Contribution, error) {
	if c.sealed {
		return nil, failure.New(failure.CeremonySealed, "ceremony is sealed")
	}
	h, state, err := transcript.DecodeMessage(msg)
	if err != nil {
		return nil, err
	}
	if h.Type != transcript.MessageContribution {
		return nil, failure.New(failure.MessageMalformed, "message type %q, want %q", h.Type, transcript.MessageContribution)
	}
	if h.CeremonyID != c.t.CeremonyID || h.Provenance != c.t.Provenance {
		return nil, failure.New(failure.MessageWrongCeremony, "message is for ceremony %q (%s)", h.CeremonyID, h.Provenance)
	}
	index := len(c.t.Phase2.Contributions) + 1
	if h.Index != index {
		return nil, failure.New(failure.ContributionSequence, "contribution index %d, expected %d", h.Index, index)
	}
	if h.PreviousStateSHA256 != c.currentSHA {
		return nil, failure.New(failure.ContributionStale, "contribution was built on state %s, the latest is %s", h.PreviousStateSHA256, c.currentSHA)
	}
	if h.Contributor == nil {
		return nil, failure.New(failure.MessageMalformed, "contribution names no contributor")
	}
	if err := transcript.CheckContributor(c.t.Provenance, *h.Contributor); err != nil {
		return nil, err
	}
	if err := transcript.CheckShape(c.current, c.currentBytes, state); err != nil {
		return nil, err
	}
	next, err := transcript.DecodeState(state)
	if err != nil {
		return nil, err
	}
	prevDigest, _ := hex.DecodeString(c.currentSHA)
	if !bytes.Equal(next.Challenge, prevDigest) {
		return nil, failure.New(failure.ContributionChainBroken, "contribution's challenge is not the latest state's digest")
	}
	if err := c.current.Verify(next); err != nil {
		return nil, failure.Wrap(failure.ContributionInvalid, err, "contribution %d does not verify", index)
	}

	rec := transcript.Contribution{
		Index:       index,
		File:        fmt.Sprintf("phase2-%04d.bin", index),
		StateSHA256: h.StateSHA256,
		Challenge:   c.currentSHA,
		Contributor: *h.Contributor,
	}
	if err := os.WriteFile(filepath.Join(c.dir, rec.File), state, 0o644); err != nil {
		return nil, failure.Wrap(failure.IO, err, "writing %s", rec.File)
	}
	c.t.Phase2.Contributions = append(c.t.Phase2.Contributions, rec)
	c.current, c.currentBytes, c.currentSHA = next, state, h.StateSHA256
	return &rec, c.save()
}

// Seal applies the public beacon to the latest state, writes the proving and
// verifying keys and their provenance metadata, and closes the transcript.
func (c *Coordinator) Seal(beacon transcript.Beacon) (*transcript.Transcript, error) {
	if c.sealed {
		return nil, failure.New(failure.CeremonySealed, "ceremony is sealed")
	}
	if len(c.t.Phase2.Contributions) == 0 {
		return nil, failure.New(failure.CeremonyNoContributions, "no contribution to seal")
	}
	value, err := transcript.DecodeBeacon(beacon)
	if err != nil {
		return nil, err
	}
	if c.commons == nil || c.evals == nil {
		return nil, failure.New(failure.WorkMismatch, "the ceremony was opened without the phase-1 parameters sealing needs")
	}
	// Only [α]₁, [β]₁ and [β]₂ are kept; dropping c.commons lets the τ
	// vectors be freed before sealing allocates the proving key.
	commons := transcript.SealCommons(c.commons)
	c.commons = nil
	pk, vk := c.current.Seal(commons, c.evals, value)
	c.sealed = true

	// Each key is streamed to its file while it is hashed, so the proving key
	// (about 2.8 GB raw at 2^23) is never also held as one buffer.
	pkRef, err := writeHashed(c.dir, transcript.ProvingKeyFile, func(w io.Writer) error { _, err := pk.WriteRawTo(w); return err })
	if err != nil {
		return nil, err
	}
	vkRef, err := writeHashed(c.dir, transcript.VerifyingKeyFile, func(w io.Writer) error { _, err := vk.WriteTo(w); return err })
	if err != nil {
		return nil, err
	}
	c.t.Status = transcript.StatusSealed
	c.t.Beacon = &beacon
	c.t.Keys = &transcript.Keys{
		ProvingKey:   transcript.KeyFile{File: transcript.ProvingKeyFile, SHA256: pkRef.SHA256, Encoding: transcript.ProvingKeyEncoding},
		VerifyingKey: transcript.KeyFile{File: transcript.VerifyingKeyFile, SHA256: vkRef.SHA256, Encoding: transcript.VerifyingKeyEncoding},
		Metadata:     transcript.KeyMetadataFile,
	}
	meta := transcript.MetadataFor(&c.t)
	if err := transcript.WriteJSON(filepath.Join(c.dir, transcript.KeyMetadataFile), &meta); err != nil {
		return nil, err
	}
	if err := c.save(); err != nil {
		return nil, err
	}
	t := c.Transcript()
	return &t, nil
}

// Contributor answers challenge messages. Local automated contributors and
// remote contributors reached over any transport implement it alike.
type Contributor interface {
	ID() string
	Contribute(challenge []byte) ([]byte, error)
}

// Refusal records a contributor whose answer was not accepted.
type Refusal struct {
	ContributorID string       `json:"contributorId"`
	Index         int          `json:"index"`
	Code          failure.Code `json:"code"`
	Detail        string       `json:"detail"`
}

// RunQueue serves the contributors strictly in order. A contributor whose
// answer fails is recorded as refused and the next one gets the same state.
func (c *Coordinator) RunQueue(contributors []Contributor) ([]transcript.Contribution, []Refusal, error) {
	var accepted []transcript.Contribution
	var refused []Refusal
	for _, who := range contributors {
		challenge, err := c.Challenge()
		if err != nil {
			return accepted, refused, err
		}
		index := len(c.t.Phase2.Contributions) + 1
		answer, err := who.Contribute(challenge)
		if err == nil {
			var rec *transcript.Contribution
			if rec, err = c.Submit(answer); err == nil {
				accepted = append(accepted, *rec)
				continue
			}
		}
		code := failure.CodeOf(err)
		if code == "" {
			code = failure.IO
		}
		refused = append(refused, Refusal{ContributorID: who.ID(), Index: index, Code: code, Detail: err.Error()})
	}
	return accepted, refused, nil
}
