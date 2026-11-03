package coordinator

import (
	"bytes"
	"encoding/json"
	"math/bits"
	"os"
	"path/filepath"
	"testing"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/contributor"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/internal/fixture"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/verifier"
)

func wantWorkCode(t *testing.T, err error, code failure.Code) {
	t.Helper()
	if got := failure.CodeOf(err); got != code {
		t.Fatalf("got %v (code %q), want code %q", err, got, code)
	}
}

// phased is a ceremony started with a work directory, as rerun's init phase
// starts one.
type phased struct {
	dir, work, ptauPath, r1csPath string
	pin                           ptau.Pin
	commons                       *mpcsetup.SrsCommons
}

func startPhased(t *testing.T) *phased {
	t.Helper()
	root := t.TempDir()
	r1csPath, r := fixture.R1CS(t, root, "committed", 3)
	ptauPath, pin := fixture.Ptau(t, root, fixture.Power(r))
	commons, info, err := ptau.ImportFile(ptauPath, pin, transcript.DomainSize(r))
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := transcript.ReadR1CS(r1csPath)
	if err != nil {
		t.Fatal(err)
	}
	p := &phased{dir: filepath.Join(root, "ceremony"), work: filepath.Join(root, "work"), ptauPath: ptauPath, r1csPath: r1csPath, pin: pin, commons: commons}
	if _, err := New(Config{
		Dir: p.dir, Work: p.work, CeremonyID: "phased", Provenance: transcript.SimulatedSingleParty,
		Phase1:  transcript.Phase1{Source: "toy", File: filepath.Base(ptauPath), FileSize: info.FileSize, Pin: pin, Power: info.Power, CommonsSHA256: info.CommonsSHA256},
		Commons: commons, R1CS: r, R1CSSHA256: digest, CircuitLabel: "committed-3",
	}); err != nil {
		t.Fatal(err)
	}
	return p
}

// contributeOnce resumes the ceremony and adds one automated contribution,
// as rerun's contribute phase does in its own process.
func (p *phased) contributeOnce(t *testing.T, id string) {
	t.Helper()
	c, err := Open(OpenConfig{Dir: p.dir, Work: p.work})
	if err != nil {
		t.Fatal(err)
	}
	if acc, ref, err := c.RunQueue([]Contributor{contributor.NewAutomated(id)}); err != nil || len(acc) != 1 || len(ref) != 0 {
		t.Fatalf("accepted %v, refused %v, err %v", acc, ref, err)
	}
}

func (p *phased) verify(t *testing.T) (*verifier.Report, error) {
	t.Helper()
	return verifier.Verify(verifier.Inputs{
		TranscriptPath: filepath.Join(p.dir, transcript.TranscriptFile), PtauPath: p.ptauPath, R1CSPath: p.r1csPath,
		ExpectedPhase1Pin: &p.pin, ExpectedBeacon: fixture.Beacon.Value,
	})
}

// Every phase resumes from disk in a fresh coordinator, and the result
// verifies anchored.
func TestWorkResumesEachPhase(t *testing.T) {
	p := startPhased(t)
	p.contributeOnce(t, "automated-01")
	p.contributeOnce(t, "automated-02")

	// Without the phase-1 parameters a resumed ceremony cannot seal.
	c, err := Open(OpenConfig{Dir: p.dir, Work: p.work})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Seal(fixture.Beacon)
	wantWorkCode(t, err, failure.WorkMismatch)

	c, err = Open(OpenConfig{Dir: p.dir, Work: p.work, Commons: p.commons})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Seal(fixture.Beacon); err != nil {
		t.Fatal(err)
	}
	rep, err := p.verify(t)
	if err != nil || !rep.Authoritative() || len(rep.Contributions) != 2 {
		t.Fatalf("report %+v, err %v", rep, err)
	}
	_, err = Open(OpenConfig{Dir: p.dir, Work: p.work})
	wantWorkCode(t, err, failure.CeremonySealed)
}

func flipLastByte(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 1
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func editWork(t *testing.T, p *phased, edit func(*WorkRecord)) {
	t.Helper()
	path := filepath.Join(p.work, WorkFile)
	var w WorkRecord
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &w); err != nil {
		t.Fatal(err)
	}
	edit(&w)
	if err := transcript.WriteJSON(path, &w); err != nil {
		t.Fatal(err)
	}
}

// A damaged, missing or foreign work file stops the ceremony with
// WORK_MISMATCH; phase-1 parameters other than the transcript's stop sealing.
func TestOpenRefusesDamagedWork(t *testing.T) {
	for _, c := range []struct {
		name       string
		contribute bool
		damage     func(t *testing.T, p *phased)
		seal       bool
		want       failure.Code
	}{
		{"initial state flipped", false, func(t *testing.T, p *phased) { flipLastByte(t, filepath.Join(p.work, InitialStateFile)) }, false, failure.WorkMismatch},
		{"latest contribution flipped", true, func(t *testing.T, p *phased) { flipLastByte(t, filepath.Join(p.dir, "phase2-0001.bin")) }, false, failure.WorkMismatch},
		{"work record missing", false, func(t *testing.T, p *phased) { os.Remove(filepath.Join(p.work, WorkFile)) }, false, failure.WorkMismatch},
		{"work record of another ceremony", false, func(t *testing.T, p *phased) { editWork(t, p, func(w *WorkRecord) { w.CeremonyID = "other" }) }, false, failure.WorkMismatch},
		{"work record with another root", false, func(t *testing.T, p *phased) {
			editWork(t, p, func(w *WorkRecord) { w.RootChallenge = w.InitialState.SHA256 })
		}, false, failure.WorkMismatch},
		{"work record with an unknown field", false, func(t *testing.T, p *phased) {
			path := filepath.Join(p.work, WorkFile)
			b, _ := os.ReadFile(path)
			os.WriteFile(path, bytes.Replace(b, []byte("{"), []byte(`{"extra": 1,`), 1), 0o644)
		}, false, failure.WorkMismatch},
		{"evaluations flipped", false, func(t *testing.T, p *phased) { flipLastByte(t, filepath.Join(p.work, EvaluationsFile)) }, true, failure.WorkMismatch},
		{"evaluations missing", false, func(t *testing.T, p *phased) { os.Remove(filepath.Join(p.work, EvaluationsFile)) }, true, failure.WorkMismatch},
		// Raw points decode without an on-curve check (the file is the
		// coordinator's own), so a flipped coordinate bit still decodes:
		// only the digest stops it.
		{"evaluations point coordinate flipped, still decodes", false, func(t *testing.T, p *phased) {
			path := filepath.Join(p.work, EvaluationsFile)
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			e, err := readEvaluations(bytes.NewReader(b))
			if err != nil {
				t.Fatal(err)
			}
			j := 0
			for j < len(e.G1.A) && e.G1.A[j].IsInfinity() {
				j++
			}
			off := len(evaluationsMagic) + 4 + j*curve.SizeOfG1AffineUncompressed + 31 // last byte of X
			b[off] ^= 1
			if _, err := readEvaluations(bytes.NewReader(b)); err != nil {
				t.Fatalf("the damaged file no longer decodes, so it cannot isolate the digest check: %v", err)
			}
			os.WriteFile(path, b, 0o644)
		}, true, failure.WorkMismatch},
		{"evaluations with a trailing byte, digest updated", false, func(t *testing.T, p *phased) {
			path := filepath.Join(p.work, EvaluationsFile)
			b, _ := os.ReadFile(path)
			b = append(b, 0)
			os.WriteFile(path, b, 0o644)
			editWork(t, p, func(w *WorkRecord) { w.Evaluations.SHA256, w.Evaluations.Length = transcript.Digest(b), int64(len(b)) })
		}, true, failure.WorkMismatch},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := startPhased(t)
			if c.contribute {
				p.contributeOnce(t, "automated-01")
			}
			c.damage(t, p)
			cfg := OpenConfig{Dir: p.dir, Work: p.work}
			if c.seal {
				cfg.Commons = p.commons
			}
			_, err := Open(cfg)
			wantWorkCode(t, err, c.want)
		})
	}
}

func TestOpenForSealRefusesOtherPhase1(t *testing.T) {
	p := startPhased(t)
	p.contributeOnce(t, "automated-01")
	// The same domain and α, β, but another τ.
	power := uint32(bits.TrailingZeros(uint(len(p.commons.G2.Tau))))
	other := ptau.ToyCommons(power, fixture.ToyTau+1, fixture.ToyAlpha, fixture.ToyBeta)
	_, err := Open(OpenConfig{Dir: p.dir, Work: p.work, Commons: other})
	wantWorkCode(t, err, failure.Phase1CommonsMismatch)
}

// The work files are not trusted by the verifier: evaluations edited and
// re-bound to the work record are accepted by the coordinator, which then
// seals keys the verifier refuses.
func TestEditedEvaluationsAreCaughtByTheVerifier(t *testing.T) {
	p := startPhased(t)
	p.contributeOnce(t, "automated-01")
	path := filepath.Join(p.work, EvaluationsFile)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	e, err := readEvaluations(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	_, _, g1, _ := curve.Generators()
	moved := false
	for i := range e.G1.A {
		if !e.G1.A[i].IsInfinity() {
			e.G1.A[i].Add(&e.G1.A[i], &g1)
			moved = true
			break
		}
	}
	if !moved {
		t.Fatal("no finite A point to move")
	}
	var b bytes.Buffer
	if err := writeEvaluations(&b, e); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	editWork(t, p, func(w *WorkRecord) {
		w.Evaluations.SHA256, w.Evaluations.Length = transcript.Digest(b.Bytes()), int64(b.Len())
	})
	c, err := Open(OpenConfig{Dir: p.dir, Work: p.work, Commons: p.commons})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Seal(fixture.Beacon); err != nil {
		t.Fatal(err)
	}
	_, err = p.verify(t)
	wantWorkCode(t, err, failure.SealedKeyMismatch)
}

func TestEvaluationsRoundTrip(t *testing.T) {
	p := startPhased(t)
	r, _, err := transcript.ReadR1CS(p.r1csPath)
	if err != nil {
		t.Fatal(err)
	}
	var probe mpcsetup.Phase2
	want := probe.Initialize(r, p.commons)
	var a, b bytes.Buffer
	if err := writeEvaluations(&a, &want); err != nil {
		t.Fatal(err)
	}
	got, err := readEvaluations(bytes.NewReader(a.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeEvaluations(&b, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) || len(got.G1.CKK) != len(want.G1.CKK) || len(got.G1.CKK) == 0 {
		t.Fatal("evaluations do not round-trip")
	}
	stored, err := os.ReadFile(filepath.Join(p.work, EvaluationsFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, a.Bytes()) {
		t.Fatal("the work directory's evaluations are not gnark's Initialize output")
	}
}

// New checks the work directory before it writes anything, so a refused
// start leaves the ceremony directory empty.
func TestNewRefusesUsedWorkDirectory(t *testing.T) {
	p := startPhased(t)
	root := filepath.Dir(p.dir)
	r, digest, err := transcript.ReadR1CS(p.r1csPath)
	if err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(root, "fresh")
	for _, work := range []string{p.work, fresh} {
		_, err = New(Config{
			Dir: fresh, Work: work, CeremonyID: "again", Provenance: transcript.SimulatedSingleParty,
			Phase1:  transcript.Phase1{Source: "toy", Pin: p.pin},
			Commons: p.commons, R1CS: r, R1CSSHA256: digest, CircuitLabel: "x",
		})
		wantWorkCode(t, err, failure.OutputExists)
		if entries, _ := os.ReadDir(fresh); len(entries) != 0 {
			t.Fatalf("a refused start wrote %d entries", len(entries))
		}
	}
}
