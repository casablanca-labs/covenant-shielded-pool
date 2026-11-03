package verifier_test

import (
	"bytes"
	"math/bits"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	cs "github.com/consensys/gnark/constraint/bn254"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/contributor"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/coordinator"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/internal/fixture"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/rerun"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/testcircuits"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/verifier"
)

// ENG-440 negative controls (ARCH-238). Before ENG-440 the verifier returned
// VALID for each of these ceremonies.

func frU(v uint64) fr.Element {
	var e fr.Element
	e.SetUint64(v)
	return e
}

func frMinusOne() fr.Element {
	var e fr.Element
	e.SetOne()
	e.Neg(&e)
	return e
}

// writePtau writes commons as a .ptau file and returns its path and pin.
func writePtau(t *testing.T, dir string, commons *mpcsetup.SrsCommons) (string, ptau.Pin) {
	t.Helper()
	path := filepath.Join(dir, "phase1.ptau")
	var b bytes.Buffer
	if err := ptau.Write(&b, commons); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path, fixture.PinOf(t, path)
}

// writeR1CS writes a hand-built R1CS and returns its path.
func writeR1CS(t *testing.T, dir string, r *cs.R1CS) string {
	t.Helper()
	path := filepath.Join(dir, "circuit.r1cs")
	if err := testcircuits.WriteR1CS(path, r); err != nil {
		t.Fatal(err)
	}
	return path
}

// bypassCeremony runs a sealed ceremony through the coordinator on phase-1
// parameters that never passed the importer, as a coordinator without the
// phase-1 checks would, and writes the same parameters as the .ptau file the
// verifier is given. It is how a degenerate phase 1 reaches the verifier now
// that the importer, which rerun's init and seal phases call, refuses it.
func bypassCeremony(t *testing.T, name string, size int, commons *mpcsetup.SrsCommons) ceremony {
	t.Helper()
	root := t.TempDir()
	r1csPath, r := fixture.R1CS(t, root, name, size)
	if uint64(len(commons.G2.Tau)) != transcript.DomainSize(r) {
		t.Fatalf("parameters for domain %d, the circuit needs %d", len(commons.G2.Tau), transcript.DomainSize(r))
	}
	ptauPath, pin := writePtau(t, root, commons)
	st, err := os.Stat(ptauPath)
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := transcript.ReadR1CS(r1csPath)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "ceremony")
	co, err := coordinator.New(coordinator.Config{
		Dir: out, CeremonyID: "degenerate-" + name, Provenance: transcript.SimulatedSingleParty,
		Phase1: transcript.Phase1{
			Source: "toy fixture (INSECURE, degenerate)", File: filepath.Base(ptauPath), FileSize: st.Size(), Pin: pin,
			Power: uint32(bits.TrailingZeros(uint(len(commons.G2.Tau)))),
		},
		Commons: commons, R1CS: r, R1CSSHA256: digest, CircuitLabel: name,
	})
	if err != nil {
		t.Fatal(err)
	}
	accepted, refused, err := co.RunQueue([]coordinator.Contributor{contributor.NewAutomated("automated-01"), contributor.NewAutomated("automated-02")})
	if err != nil || len(accepted) != 2 || len(refused) != 0 {
		t.Fatalf("contributions: %d accepted, refused %+v, %v", len(accepted), refused, err)
	}
	if _, err := co.Seal(fixture.Beacon); err != nil {
		t.Fatal(err)
	}
	return ceremony{dir: out, ptau: ptauPath, r1cs: r1csPath, pin: pin, name: name, size: size}
}

// A phase 1 with τ a root of unity of the domain, or with β = −1, passes
// every point, ratio and β check and every phase-2 check. The verifier
// refuses it at the phase-1 import; so does rerun, before phase 2 starts.
func TestRefusesDegeneratePhase1(t *testing.T) {
	r, err := testcircuits.Compile("committed", 3)
	if err != nil {
		t.Fatal(err)
	}
	power := fixture.Power(r)
	omega := fft.NewDomain(uint64(1) << power).Generator
	for _, tc := range []struct {
		name             string
		tau, alpha, beta fr.Element
		want             failure.Code
	}{
		{"τ = ω", omega, frU(fixture.ToyAlpha), frU(fixture.ToyBeta), failure.Phase1TauInDomain},
		{"β = −1", frU(fixture.ToyTau), frU(fixture.ToyAlpha), frMinusOne(), failure.Phase1BetaMinusOne},
	} {
		commons := ptau.ToyCommonsFr(power, tc.tau, tc.alpha, tc.beta)
		t.Run(tc.name+"/verifier", func(t *testing.T) {
			c := bypassCeremony(t, "committed", 3, commons)
			rep, err := verifier.Verify(c.inputs())
			if rep != nil || failure.CodeOf(err) != tc.want {
				t.Fatalf("verifier verdict %s, err %v; want %s", verdictOf(rep), err, tc.want)
			}
		})
		t.Run(tc.name+"/rerun", func(t *testing.T) {
			root := t.TempDir()
			r1csPath, _ := fixture.R1CS(t, root, "committed", 3)
			ptauPath, pin := writePtau(t, root, commons)
			s, err := rerun.Run(rerun.Options{
				PtauPath: ptauPath, PtauPin: pin, PtauSource: "toy fixture (INSECURE, degenerate)",
				R1CSPath: r1csPath, CircuitLabel: "committed", OutDir: filepath.Join(root, "ceremony"),
				CeremonyID: "degenerate-rerun", Contributions: 2, Beacon: fixture.Beacon,
			})
			if failure.CodeOf(err) != tc.want || (s != nil && s.Report != nil) {
				t.Fatalf("rerun verdict %s, err %v; want %s", summaryVerdict(s), err, tc.want)
			}
		})
	}
}

func verdictOf(rep *verifier.Report) string {
	if rep == nil {
		return "none"
	}
	return rep.Verdict
}

func summaryVerdict(s *rerun.Summary) string {
	if s == nil {
		return "none"
	}
	return verdictOf(s.Report)
}

// A committed wire with the mask's constraint w·1 = w whose basis element is
// O on a phase 1 that is not degenerate (fixture.MaskCancelledR1CS: another
// constraint cancels it at the toy τ and β). The phase-1 checks pass, the
// ceremony seals, the sealed key holds O at that mask position, and the
// verifier refuses the re-derived key after sealing. The same circuit on
// another τ is VALID: the check refuses only an O.
func TestRefusesZeroMaskBasisAfterSealing(t *testing.T) {
	dir := t.TempDir()
	r1csPath := writeR1CS(t, dir, fixture.MaskCancelledR1CS())
	for _, tc := range []struct {
		name string
		tau  uint64
		want failure.Code
	}{
		{"cancelling τ", fixture.ToyTau, failure.CommitmentMaskZero},
		{"another τ", 17, ""},
	} {
		t.Run(tc.name, func(t *testing.T) { zeroMaskCase(t, r1csPath, tc.tau, tc.want) })
	}
}

func zeroMaskCase(t *testing.T, r1csPath string, tau uint64, want failure.Code) {
	t.Helper()
	root := t.TempDir()
	ptauPath, pin := fixture.PtauWith(t, root, 3, tau, fixture.ToyAlpha, fixture.ToyBeta)
	o := rerun.Options{
		PtauPath: ptauPath, PtauPin: pin, PtauSource: "toy fixture (INSECURE)",
		R1CSPath: r1csPath, CircuitLabel: "mask-cancelled", OutDir: filepath.Join(root, "ceremony"),
		WorkDir: filepath.Join(root, "work"), CeremonyID: "mask-cancelled", Contributions: 2, Beacon: fixture.Beacon,
	}
	if _, err := rerun.Init(o); err != nil {
		t.Fatalf("init: %v", err)
	}
	for range o.Contributions {
		if _, err := rerun.Contribute(o); err != nil {
			t.Fatalf("contribute: %v", err)
		}
	}
	if _, err := rerun.Seal(o); err != nil {
		t.Fatalf("seal: %v", err)
	}
	pk := &groth16bn254.ProvingKey{}
	b, err := os.ReadFile(filepath.Join(o.OutDir, transcript.ProvingKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pk.ReadFrom(bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	basis := pk.CommitmentKeys[0].Basis
	if basis[0].IsInfinity() != (want != "") || basis[1].IsInfinity() {
		t.Fatalf("basis[0] O %v, basis[1] O %v", basis[0].IsInfinity(), basis[1].IsInfinity())
	}
	rep, err := verifier.Verify(verifier.Inputs{
		TranscriptPath: filepath.Join(o.OutDir, transcript.TranscriptFile), PtauPath: ptauPath, R1CSPath: r1csPath,
		ExpectedPhase1Pin: &pin, ExpectedBeacon: fixture.Beacon.Value,
	})
	if want == "" {
		if err != nil || rep.Verdict != verifier.VerdictValid {
			t.Fatalf("verifier verdict %s, err %v; want VALID", verdictOf(rep), err)
		}
		return
	}
	if rep != nil || failure.CodeOf(err) != want {
		t.Fatalf("verifier verdict %s, err %v; want %s", verdictOf(rep), err, want)
	}
}

// A commitment with no committed wire w constrained by w·1 = w has no mask
// to check, so the verifier refuses it before the phase-1 import.
func TestRefusesCommitmentWithoutMask(t *testing.T) {
	root := t.TempDir()
	r1csPath := writeR1CS(t, root, fixture.UnmaskedR1CS())
	ptauPath, pin := fixture.Ptau(t, root, 3)
	s, err := rerun.Run(rerun.Options{
		PtauPath: ptauPath, PtauPin: pin, PtauSource: "toy fixture (INSECURE)",
		R1CSPath: r1csPath, CircuitLabel: "unmasked", OutDir: filepath.Join(root, "ceremony"),
		CeremonyID: "unmasked", Contributions: 2, Beacon: fixture.Beacon,
	})
	if failure.CodeOf(err) != failure.CommitmentMaskMissing || (s != nil && s.Report != nil) {
		t.Fatalf("rerun verdict %s, err %v; want %s", summaryVerdict(s), err, failure.CommitmentMaskMissing)
	}
}
