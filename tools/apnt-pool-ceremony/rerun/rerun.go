// Package rerun is the one-command simulated ceremony: import the pinned
// phase-1 file, run phase 2 for an R1CS with the project's own automated
// contributors, seal with the beacon, and re-verify the result with the
// standalone verifier, anchored to the pin and beacon it was given. That
// verifier imports no coordinator package and replays the ceremony from its
// public inputs, but it is not an independent implementation: it shares the
// ptau importer, the transcript derivations and gnark's mpcsetup with the
// coordinator, so a defect there is common to both. It can only produce
// simulated-single-party transcripts: the provenance is fixed here, not a
// parameter.
//
// The ceremony runs in phases that pass their results on disk: Init (phase-1
// import and gnark's Phase2.Initialize), one Contribute per automated
// contribution, and Seal. Run performs them in one process; each can also run
// as its own process (the CLI's --phase), so that no process holds more than
// its own step needs, followed by the standalone verifier as a separate
// process. Between phases the coordinator's state lives in a work directory
// (coordinator.Open), which the verifier never reads.
package rerun

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/contributor"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/coordinator"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/verifier"
)

// Provenance is the only provenance a re-run produces.
const Provenance = transcript.SimulatedSingleParty

// DefaultContributions is the default number of automated contributions.
const DefaultContributions = 3

// Phases that can run as separate processes.
const (
	PhaseInit       = "init"
	PhaseContribute = "contribute"
	PhaseSeal       = "seal"
)

// Options configure one re-run or one phase of it.
type Options struct {
	PtauPath     string
	PtauPin      ptau.Pin
	PtauSource   string
	R1CSPath     string
	CircuitLabel string
	OutDir       string
	// WorkDir holds the coordinator's state between phases. Run uses
	// OutDir + ".work" when it is empty and removes it once the ceremony
	// verifies.
	WorkDir    string
	CeremonyID string
	// Contributions is the number of automated contributions Run makes. Seal
	// refuses unless the transcript holds exactly this many; 0 skips that
	// check.
	Contributions int
	Beacon        transcript.Beacon
}

// Summary is what a re-run or a phase did and how long each stage took.
type Summary struct {
	Phase          string                   `json:"phase,omitempty"`
	TranscriptPath string                   `json:"transcriptPath"`
	Report         *verifier.Report         `json:"report"`
	Refusals       []coordinator.Refusal    `json:"refusals"`
	Seconds        map[string]float64       `json:"seconds"`
	Phase1         *ptau.Info               `json:"phase1"`
	Circuit        transcript.Circuit       `json:"circuit"`
	Contribution   *transcript.Contribution `json:"contribution,omitempty"`
}

func newSummary(phase, out string) (*Summary, func(string, time.Time)) {
	s := &Summary{Phase: phase, TranscriptPath: filepath.Join(out, transcript.TranscriptFile), Seconds: map[string]float64{}}
	return s, func(name string, since time.Time) { s.Seconds[name] += time.Since(since).Seconds() }
}

// Init imports the pinned phase-1 file for the R1CS's domain, runs gnark's
// Phase2.Initialize, and writes the open transcript to OutDir and the
// initial state and evaluations to WorkDir. Both must be new or empty.
func Init(o Options) (*Summary, error) {
	if o.WorkDir == "" {
		return nil, failure.New(failure.WorkMismatch, "a work directory is required")
	}
	s, lap := newSummary(PhaseInit, o.OutDir)
	t0 := time.Now()
	r1cs, r1csSHA, err := transcript.ReadR1CS(o.R1CSPath)
	if err != nil {
		return nil, err
	}
	lap("readR1cs", t0)

	t0 = time.Now()
	commons, info, err := ptau.ImportFile(o.PtauPath, o.PtauPin, transcript.DomainSize(r1cs))
	if err != nil {
		return nil, err
	}
	s.Phase1 = info
	lap("phase1Import", t0)

	t0 = time.Now()
	c, err := coordinator.New(coordinator.Config{
		Dir:        o.OutDir,
		Work:       o.WorkDir,
		CeremonyID: o.CeremonyID,
		Provenance: Provenance,
		Phase1: transcript.Phase1{
			Source:        o.PtauSource,
			File:          filepath.Base(o.PtauPath),
			FileSize:      info.FileSize,
			Pin:           o.PtauPin,
			Power:         info.Power,
			CommonsSHA256: info.CommonsSHA256,
		},
		Commons:      commons,
		R1CS:         r1cs,
		R1CSSHA256:   r1csSHA,
		CircuitLabel: o.CircuitLabel,
	})
	if err != nil {
		return nil, err
	}
	s.Circuit = c.Transcript().Circuit
	lap("phase2Initialize", t0)
	return s, nil
}

// Contribute adds one automated contribution to the open ceremony in OutDir,
// resuming from WorkDir. Its contributor id is automated-NN, NN the index.
func Contribute(o Options) (*Summary, error) {
	s, lap := newSummary(PhaseContribute, o.OutDir)
	t0 := time.Now()
	c, err := coordinator.Open(coordinator.OpenConfig{Dir: o.OutDir, Work: o.WorkDir})
	if err != nil {
		return nil, err
	}
	lap("open", t0)
	s.Circuit = c.Transcript().Circuit

	t0 = time.Now()
	index := len(c.Transcript().Phase2.Contributions) + 1
	accepted, refused, err := c.RunQueue([]coordinator.Contributor{contributor.NewAutomated(fmt.Sprintf("automated-%02d", index))})
	s.Refusals = refused
	if err != nil {
		return s, err
	}
	if len(accepted) != 1 {
		return s, failure.New(failure.ContributionInvalid, "automated contribution %d was not accepted", index)
	}
	s.Contribution = &accepted[0]
	lap("contribute", t0)
	return s, nil
}

// Seal re-imports the pinned phase-1 file, checks it against the
// transcript's record, seals the ceremony in OutDir with the beacon and
// writes the keys. It refuses a pin other than the transcript's, and, when
// Contributions is set, any other number of contributions.
func Seal(o Options) (*Summary, error) {
	if _, err := transcript.DecodeBeacon(o.Beacon); err != nil {
		return nil, err
	}
	s, lap := newSummary(PhaseSeal, o.OutDir)
	t, err := transcript.Load(s.TranscriptPath)
	if err != nil {
		return nil, err
	}
	if o.PtauPin != t.Phase1.Pin {
		return nil, failure.New(failure.Phase1PinUnexpected, "transcript pins phase 1 to %s, sealing was given %s", t.Phase1.Pin, o.PtauPin)
	}
	if n := len(t.Phase2.Contributions); o.Contributions > 0 && n != o.Contributions {
		return nil, failure.New(failure.ContributionSequence, "transcript holds %d contributions, sealing expects %d", n, o.Contributions)
	}

	t0 := time.Now()
	commons, info, err := ptau.ImportFile(o.PtauPath, o.PtauPin, t.Phase1.DomainSize)
	if err != nil {
		return nil, err
	}
	s.Phase1 = info
	lap("phase1Import", t0)

	t0 = time.Now()
	c, err := coordinator.Open(coordinator.OpenConfig{Dir: o.OutDir, Work: o.WorkDir, Commons: commons})
	if err != nil {
		return nil, err
	}
	s.Circuit = c.Transcript().Circuit
	lap("open", t0)

	t0 = time.Now()
	if _, err := c.Seal(o.Beacon); err != nil {
		return nil, err
	}
	lap("seal", t0)
	return s, nil
}

// Run performs the whole simulated ceremony in one process: Init, the
// automated contributions, Seal, and the standalone verifier's replay
// anchored to the pin and beacon it was given.
func Run(o Options) (*Summary, error) {
	if o.Contributions < 1 {
		return nil, failure.New(failure.CeremonyNoContributions, "at least one contribution is required")
	}
	if _, err := transcript.DecodeBeacon(o.Beacon); err != nil {
		return nil, err
	}
	if o.WorkDir == "" {
		o.WorkDir = filepath.Clean(o.OutDir) + ".work"
	}
	start := time.Now()
	s, err := Init(o)
	if err != nil {
		return nil, err
	}
	s.Phase = ""
	for range o.Contributions {
		t0 := time.Now()
		cs, err := Contribute(o)
		if cs != nil {
			s.Refusals = append(s.Refusals, cs.Refusals...)
		}
		if err != nil {
			return s, err
		}
		s.Seconds["phase2Contributions"] += time.Since(t0).Seconds()
	}

	t0 := time.Now()
	ss, err := Seal(o)
	if err != nil {
		return s, err
	}
	s.Seconds["sealPhase1Import"] = ss.Seconds["phase1Import"]
	s.Seconds["seal"] = time.Since(t0).Seconds() - ss.Seconds["phase1Import"]

	t0 = time.Now()
	s.Report, err = verifier.Verify(verifier.Inputs{
		TranscriptPath:    s.TranscriptPath,
		PtauPath:          o.PtauPath,
		R1CSPath:          o.R1CSPath,
		ExpectedPhase1Pin: &o.PtauPin,
		ExpectedBeacon:    o.Beacon.Value,
	})
	if err != nil {
		return s, err
	}
	s.Seconds["independentVerify"] = time.Since(t0).Seconds()
	// Everything in the work directory was written by this run (Init refuses
	// a non-empty one) and the verified transcript does not use it.
	if err := os.RemoveAll(o.WorkDir); err != nil {
		return s, failure.Wrap(failure.IO, err, "removing %s", o.WorkDir)
	}
	s.Seconds["total"] = time.Since(start).Seconds()
	return s, nil
}
