package rerun_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/internal/fixture"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/rerun"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/testcircuits"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/verifier"
)

func wantCode(t *testing.T, err error, code failure.Code) {
	t.Helper()
	if got := failure.CodeOf(err); got != code {
		t.Fatalf("got %v (code %q), want code %q", err, got, code)
	}
}

// After an R1CS change, one call redoes phase 2 and yields new keys and a new
// transcript; the old transcript is refused for the new R1CS.
func TestOneCommandRerunAfterR1CSChange(t *testing.T) {
	dir := t.TempDir()
	// cubic K=5 then K=6: same shape, different coefficients.
	v1, r1 := fixture.R1CS(t, dir, "cubic", 5)
	v2, _ := fixture.R1CS(t, dir, "cubic", 6)
	ptauPath, pin := fixture.Ptau(t, dir, fixture.Power(r1))
	run := func(r1csPath, out string) *rerun.Summary {
		s, err := rerun.Run(rerun.Options{
			PtauPath: ptauPath, PtauPin: pin, PtauSource: "toy fixture (INSECURE)",
			R1CSPath: r1csPath, CircuitLabel: filepath.Base(r1csPath),
			OutDir: out, CeremonyID: "rerun-" + filepath.Base(out), Contributions: 2,
			Beacon: fixture.Beacon,
		})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	s1 := run(v1, filepath.Join(dir, "v1"))
	s2 := run(v2, filepath.Join(dir, "v2"))
	for _, s := range []*rerun.Summary{s1, s2} {
		if s.Report.Verdict != "VALID" || s.Report.Provenance != transcript.SimulatedSingleParty || len(s.Refusals) != 0 {
			t.Fatalf("summary %+v", s)
		}
	}
	if s1.Report.R1CSSHA256 == s2.Report.R1CSSHA256 || s1.Report.VerifyingKeySHA256 == s2.Report.VerifyingKeySHA256 {
		t.Fatal("an R1CS change did not produce new keys")
	}
	_, err := verifier.Verify(verifier.Inputs{TranscriptPath: s1.TranscriptPath, PtauPath: ptauPath, R1CSPath: v2})
	wantCode(t, err, failure.R1CSDigestMismatch)

	// A re-run never overwrites an earlier ceremony.
	_, err = rerun.Run(rerun.Options{
		PtauPath: ptauPath, PtauPin: pin, PtauSource: "toy", R1CSPath: v2, CircuitLabel: "x",
		OutDir: filepath.Join(dir, "v1"), CeremonyID: "again", Contributions: 1, Beacon: fixture.Beacon,
	})
	wantCode(t, err, failure.OutputExists)
	if _, err := os.Stat(filepath.Join(dir, "v1", transcript.TranscriptFile)); err != nil {
		t.Fatal(err)
	}
}

func TestRerunIsAlwaysSimulated(t *testing.T) {
	if rerun.Provenance != transcript.SimulatedSingleParty {
		t.Fatal("the one-command re-run must only produce simulated-single-party transcripts")
	}
}

func TestRerunRefusesBadInputs(t *testing.T) {
	dir := t.TempDir()
	r1csPath, r := fixture.R1CS(t, dir, "chain", 20)
	ptauPath, pin := fixture.Ptau(t, dir, fixture.Power(r)-1) // too small for the circuit
	opts := rerun.Options{
		PtauPath: ptauPath, PtauPin: pin, PtauSource: "toy", R1CSPath: r1csPath, CircuitLabel: "chain",
		OutDir: filepath.Join(dir, "out"), CeremonyID: "bad", Contributions: 1, Beacon: fixture.Beacon,
	}
	_, err := rerun.Run(opts)
	wantCode(t, err, failure.Phase1DomainTooLarge)

	opts.Contributions = 0
	_, err = rerun.Run(opts)
	wantCode(t, err, failure.CeremonyNoContributions)

	opts.Contributions, opts.Beacon = 1, transcript.Beacon{Value: "00", Source: "short"}
	_, err = rerun.Run(opts)
	wantCode(t, err, failure.BeaconInvalid)
}

// TestRerunOnRealPerpetualPowersOfTau runs the whole simulated ceremony on a
// real Perpetual Powers of Tau prepared file and proves with the sealed keys:
//
//	APNT_CEREMONY_PPOT=/path/ppot_0080_08.ptau APNT_CEREMONY_PPOT_PIN=sha256:<hex> go test ./rerun
func TestRerunOnRealPerpetualPowersOfTau(t *testing.T) {
	path, pinText := os.Getenv("APNT_CEREMONY_PPOT"), os.Getenv("APNT_CEREMONY_PPOT_PIN")
	if path == "" || pinText == "" {
		t.Skip("APNT_CEREMONY_PPOT and APNT_CEREMONY_PPOT_PIN not set: real-file ceremony not exercised")
	}
	pin, err := ptau.ParsePin(pinText)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// committed with 100 rounds fits a 256 domain and carries a commitment.
	r1csPath, r := fixture.R1CS(t, dir, "committed", 100)
	s, err := rerun.Run(rerun.Options{
		PtauPath: path, PtauPin: pin, PtauSource: filepath.Base(path) + " (PSE Perpetual Powers of Tau, contribution 0080, prepared)",
		R1CSPath: r1csPath, CircuitLabel: "committed-100",
		OutDir: filepath.Join(dir, "ceremony"), CeremonyID: "real-ppot-test", Contributions: 3,
		Beacon: fixture.Beacon,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("constraints %d, domain %d, commitments %d, vk %s", s.Circuit.NbConstraints, s.Report.DomainSize, s.Circuit.NbCommitments, s.Report.VerifyingKeySHA256)

	pk, vk := &groth16bn254.ProvingKey{}, &groth16bn254.VerifyingKey{}
	pkb, _ := os.ReadFile(filepath.Join(dir, "ceremony", transcript.ProvingKeyFile))
	vkb, _ := os.ReadFile(filepath.Join(dir, "ceremony", transcript.VerifyingKeyFile))
	if _, err := pk.UnsafeReadFrom(bytes.NewReader(pkb)); err != nil {
		t.Fatal(err)
	}
	if _, err := vk.ReadFrom(bytes.NewReader(vkb)); err != nil {
		t.Fatal(err)
	}
	_, assignment, _ := testcircuits.ByName("committed", 100)
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := w.Public()
	proof, err := groth16.Prove(r, pk, w)
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatalf("proof under real-phase-1 ceremony keys does not verify: %v", err)
	}
}
