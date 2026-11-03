package crscheck

// RESEARCH PROTOTYPE, NOT REVIEWED. Toy ceremonies only: every key here is
// made by the project's own simulated ceremony (rerun) on INSECURE toy
// phase-1 files whose τ, α, β are public constants.

import (
	"bytes"
	"go/build"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/internal/fixture"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/rerun"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/testcircuits"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/verifier"
)

func bigOfFr(e fr.Element) *big.Int {
	b := new(big.Int)
	e.BigInt(b)
	return b
}

func frU(v uint64) fr.Element {
	var e fr.Element
	e.SetUint64(v)
	return e
}

// toyCommons is ptau.ToyCommons with field-element scalars, so a test can
// choose values such as β = −1 or τ = ω. INSECURE by construction.
func toyCommons(power uint32, tau, alpha, beta fr.Element) *mpcsetup.SrsCommons {
	n := 1 << power
	pows := powers(tau, 2*n-1)
	ap := make([]fr.Element, n)
	bp := make([]fr.Element, n)
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

func srsFromCommons(c *mpcsetup.SrsCommons, n int) *SRS {
	return &SRS{N: n, TauG1: append([]curve.G1Affine(nil), c.G1.Tau[:2*n-1]...), Tau2: c.G2.Tau[1],
		Alpha1: c.G1.AlphaTau[0], Beta1: c.G1.BetaTau[0], Beta2: c.G2.Beta}
}

type ceremony struct {
	dir, ptauPath string
	pin           ptau.Pin
	r1cs          *cs.R1CS
	name          string
	size          int
	verdict       string
}

// runCeremony runs the project's simulated ceremony (init, two
// contributions, seal, then its standalone verifier anchored to the pin and
// beacon) on a toy phase-1 file with the given scalars.
func runCeremony(t testing.TB, name string, size int, tau, alpha, beta fr.Element) ceremony {
	t.Helper()
	c, err := runCeremonyErr(t, name, size, tau, alpha, beta)
	if err != nil {
		t.Fatalf("ceremony: %v", err)
	}
	return c
}

// runCeremonyErr is runCeremony returning the ceremony's refusal.
func runCeremonyErr(t testing.TB, name string, size int, tau, alpha, beta fr.Element) (ceremony, error) {
	t.Helper()
	dir := t.TempDir()
	r1csPath, r := fixture.R1CS(t, dir, name, size)
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
	pin := fixture.PinOf(t, ptauPath)
	out := filepath.Join(dir, "ceremony")
	s, err := rerun.Run(rerun.Options{
		PtauPath: ptauPath, PtauPin: pin, PtauSource: "toy fixture (INSECURE)",
		R1CSPath: r1csPath, CircuitLabel: name, OutDir: out, CeremonyID: "crscheck-" + name,
		Contributions: 2, Beacon: fixture.Beacon,
	})
	if err != nil {
		return ceremony{}, err
	}
	return ceremony{dir: out, ptauPath: ptauPath, pin: pin, r1cs: r, name: name, size: size, verdict: s.Report.Verdict}, nil
}

// sealDirect seals keys for a test circuit on a toy phase 1 with gnark's own
// mpcsetup (Initialize, one contribution, Seal), bypassing the project's
// ceremony and its phase-1 refusals: a ceremony without them seals the same
// keys. The phase-1 file is written for the plan; the keys go to dir.
func sealDirect(t testing.TB, name string, size int, tau, alpha, beta fr.Element) ceremony {
	t.Helper()
	dir := t.TempDir()
	_, r := fixture.R1CS(t, dir, name, size)
	return sealR1CS(t, dir, r, tau, alpha, beta, name, size)
}

// sealR1CS is sealDirect for a given R1CS.
func sealR1CS(t testing.TB, dir string, r *cs.R1CS, tau, alpha, beta fr.Element, name string, size int) ceremony {
	t.Helper()
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
	pk, vk := p.Seal(commons, &evals, []byte("crscheck direct seal"))
	out := filepath.Join(dir, "keys")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	var pb, vb bytes.Buffer
	if _, err := pk.(*groth16bn254.ProvingKey).WriteRawTo(&pb); err != nil {
		t.Fatal(err)
	}
	if _, err := vk.WriteTo(&vb); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(out, transcript.ProvingKeyFile), pb.Bytes(), 0o644)
	os.WriteFile(filepath.Join(out, transcript.VerifyingKeyFile), vb.Bytes(), 0o644)
	return ceremony{dir: out, ptauPath: ptauPath, pin: fixture.PinOf(t, ptauPath), r1cs: r, name: name, size: size}
}

func honest(t testing.TB, name string, size int) ceremony {
	return runCeremony(t, name, size, frU(fixture.ToyTau), frU(fixture.ToyAlpha), frU(fixture.ToyBeta))
}

// loadKeys reads the sealed keys with gnark's checked decoders.
func loadKeys(t testing.TB, dir string) (*groth16bn254.ProvingKey, *groth16bn254.VerifyingKey) {
	t.Helper()
	pk, vk := &groth16bn254.ProvingKey{}, &groth16bn254.VerifyingKey{}
	pkb, err := os.ReadFile(filepath.Join(dir, transcript.ProvingKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	vkb, err := os.ReadFile(filepath.Join(dir, transcript.VerifyingKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pk.ReadFrom(bytes.NewReader(pkb)); err != nil {
		t.Fatal(err)
	}
	if _, err := vk.ReadFrom(bytes.NewReader(vkb)); err != nil {
		t.Fatal(err)
	}
	return pk, vk
}

func plan(t testing.TB, c ceremony) *Plan {
	t.Helper()
	n := 1 << fixture.Power(c.r1cs)
	srs, err := ReadPtau(c.ptauPath, c.pin.Digest, n)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Prepare(c.r1cs, srs, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func check(t testing.TB, p *Plan, pk *groth16bn254.ProvingKey, vk *groth16bn254.VerifyingKey) *Report {
	t.Helper()
	rep, err := p.CheckKey(pk, vk)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func failedNames(rep *Report) []string {
	var f []string
	for _, r := range rep.Results {
		if !r.Pass {
			f = append(f, r.Name)
		}
	}
	return f
}

// Positive control: keys from an honest simulated ceremony pass every check,
// including the ones that do not decide the verdict.
func TestHonestCeremonyKeysAreWellFormed(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
	}{{"committed", 3}, {"cubic", 5}, {"chain", 40}} {
		c := honest(t, tc.name, tc.size)
		if c.verdict != verifier.VerdictValid {
			t.Fatalf("%s: ceremony verdict %s", tc.name, c.verdict)
		}
		pk, vk := loadKeys(t, c.dir)
		rep := check(t, plan(t, c), pk, vk)
		if rep.Verdict != VerdictWellFormed || len(failedNames(rep)) != 0 {
			t.Fatalf("%s: verdict %s, failed %v, results %+v", tc.name, rep.Verdict, failedNames(rep), rep.Results)
		}
	}
}

// Every negative control fires with fresh weights, and undoing it restores
// a key that passes every check again, the ancillary ones included (so the
// controls do not leak into each other).
func TestNegativeControlsFire(t *testing.T) {
	c := honest(t, "committed", 3)
	pk, vk := loadKeys(t, c.dir)
	p := plan(t, c)
	if len(p.Masks) != 1 || len(p.Masks[0]) != 1 {
		t.Fatalf("masks %v, want exactly one per commitment", p.Masks)
	}
	controls, err := p.Controls(pk)
	if err != nil {
		t.Fatal(err)
	}
	if len(controls) < 14 {
		t.Fatalf("only %d controls", len(controls))
	}
	var ancillary int
	for _, ctl := range controls {
		for _, m := range ctl.MustFail {
			if m == CheckVKK || m == CheckVKMatch || m == CheckPhase1 {
				ancillary++
			}
		}
	}
	if ancillary != 3 {
		t.Fatalf("%d controls on VK_K, VK_MATCHES_PK and PHASE1_ALPHA_BETA, want 3", ancillary)
	}
	for _, ctl := range controls {
		undo := ctl.Apply(pk, vk)
		rep := check(t, plan(t, c), pk, vk) // fresh weights per control
		fired, why := ctl.Fired(rep)
		if !fired {
			t.Errorf("%s did not fire: %s", ctl.Name, why)
		}
		undo()
		if rep := check(t, p, pk, vk); rep.Verdict != VerdictWellFormed || len(failedNames(rep)) != 0 {
			t.Fatalf("after undoing %s the key fails %v", ctl.Name, failedNames(rep))
		}
	}
}

// The check binds the key to the phase-1 file: an honest key checked against
// another phase 1's powers fails the query checks.
func TestKeyFromAnotherPhase1Fails(t *testing.T) {
	c := honest(t, "committed", 3)
	other := runCeremony(t, "committed", 3, frU(17), frU(fixture.ToyAlpha), frU(fixture.ToyBeta))
	pk, vk := loadKeys(t, other.dir)
	rep := check(t, plan(t, c), pk, vk)
	f := strings.Join(failedNames(rep), " ")
	for _, want := range []string{CheckAQuery, CheckBQueryG1, CheckKQuery, CheckZQuery, CheckCommitBase} {
		if !strings.Contains(f, want) {
			t.Errorf("%s did not fail; failed: %s", want, f)
		}
	}
}

// proveCommitted returns the proof's BSB22 commitment for the toy committed
// circuit, proving with gnark's own prover.
func proveCommitted(t testing.TB, c ceremony, pk *groth16bn254.ProvingKey, vk *groth16bn254.VerifyingKey) curve.G1Affine {
	t.Helper()
	_, assignment, err := testcircuits.ByName("committed", c.size)
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(c.r1cs, pk, w)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := w.Public()
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatalf("proof does not verify: %v", err)
	}
	return proof.(*groth16bn254.Proof).Commitments[0]
}

// guessedCommitment is what an adversary holding the key computes from a
// guessed witness when the mask contributes nothing: Σᵢ xᵢ·Basis[i] over the
// committed inputs X[0..7] = 2..9 (testcircuits.ByName).
func guessedCommitment(t testing.TB, p *Plan, pk *groth16bn254.ProvingKey) curve.G1Affine {
	t.Helper()
	committed := p.l.committed[0]
	if len(committed) != 9 || p.Masks[0][0] != 8 {
		t.Fatalf("committed wires %v, mask %v: want X[0..7] then the mask", committed, p.Masks[0])
	}
	var sum curve.G1Affine
	for i := 0; i < 8; i++ {
		if int(committed[i]) != p.l.nbPublic+i {
			t.Fatalf("committed wire %d is %d, want %d", i, committed[i], p.l.nbPublic+i)
		}
		var term curve.G1Affine
		term.ScalarMultiplication(&pk.CommitmentKeys[0].Basis[i], bigOfFr(frU(uint64(i+2))))
		sum.Add(&sum, &term)
	}
	return sum
}

// With β = −1 every structural check passes, but the mask's basis element
// (β+1)·L_k(τ)/γ is O: the commitment in every proof is Σ xᵢ·Basisᵢ,
// identical across proofs and computable by anyone who holds the key and
// guesses the witness. The checker's COMMITMENT_MASK_NONZERO is the only
// check that catches it. ARCH-238 found the ceremony verifier VALID on this
// phase 1; since ENG-440 the project's ceremony refuses it at import, so the
// key is sealed here with gnark's mpcsetup directly, as a ceremony without
// that refusal seals it.
func TestBetaMinusOneKeyLeaksCommittedValues(t *testing.T) {
	var minusOne fr.Element
	minusOne.SetOne()
	minusOne.Neg(&minusOne)
	if _, err := runCeremonyErr(t, "committed", 3, frU(fixture.ToyTau), frU(fixture.ToyAlpha), minusOne); err == nil {
		t.Fatal("the project's ceremony accepted β = −1")
	}
	bad := sealDirect(t, "committed", 3, frU(fixture.ToyTau), frU(fixture.ToyAlpha), minusOne)
	pk, vk := loadKeys(t, bad.dir)
	p := plan(t, bad)
	rep := check(t, p, pk, vk)
	if f := failedNames(rep); rep.Verdict != VerdictMalformed || len(f) != 1 || f[0] != CheckCommitMask {
		t.Fatalf("verdict %s, failed %v; want only %s", rep.Verdict, f, CheckCommitMask)
	}
	d1, d2 := proveCommitted(t, bad, pk, vk), proveCommitted(t, bad, pk, vk)
	guess := guessedCommitment(t, p, pk)
	if !d1.Equal(&d2) || !d1.Equal(&guess) {
		t.Fatal("β = −1: the commitment is not the deterministic Σ xᵢ·Basisᵢ")
	}

	// The honest control: the same circuit and witness, β = 13.
	good := sealDirect(t, "committed", 3, frU(fixture.ToyTau), frU(fixture.ToyAlpha), frU(fixture.ToyBeta))
	gpk, gvk := loadKeys(t, good.dir)
	gp := plan(t, good)
	if rep := check(t, gp, gpk, gvk); rep.Verdict != VerdictWellFormed {
		t.Fatalf("honest key: %v", rep.Failed)
	}
	h1, h2 := proveCommitted(t, good, gpk, gvk), proveCommitted(t, good, gpk, gvk)
	hg := guessedCommitment(t, gp, gpk)
	if h1.Equal(&h2) || h1.Equal(&hg) || h2.Equal(&hg) {
		t.Fatal("honest key: the commitment repeated or matched the guess")
	}
}

// With τ = ω, a root of unity of the FFT domain, t(τ) = 0: every point is
// valid and the powers are geometric, and every Z element of the sealed key
// is O. The checker fails TAU_NOT_IN_DOMAIN (Fuchsbauer's check 2,
// "Z(τ) ≠ 0"). ARCH-238 found the ceremony VALID on this phase 1; since
// ENG-440 it refuses it at import, so the key is sealed directly.
func TestTauInDomainKeyIsRefused(t *testing.T) {
	r, err := testcircuits.Compile("committed", 3)
	if err != nil {
		t.Fatal(err)
	}
	n := 1 << fixture.Power(r)
	omega := fft.NewDomain(uint64(n)).Generator
	if _, err := runCeremonyErr(t, "committed", 3, omega, frU(fixture.ToyAlpha), frU(fixture.ToyBeta)); err == nil {
		t.Fatal("the project's ceremony accepted τ = ω")
	}
	bad := sealDirect(t, "committed", 3, omega, frU(fixture.ToyAlpha), frU(fixture.ToyBeta))
	pk, vk := loadKeys(t, bad.dir)
	for i := range pk.G1.Z {
		if !pk.G1.Z[i].IsInfinity() {
			t.Fatalf("Z[%d] is not O", i)
		}
	}
	rep := check(t, plan(t, bad), pk, vk)
	if !strings.Contains(strings.Join(failedNames(rep), " "), CheckTauDomain) || rep.Verdict != VerdictMalformed {
		t.Fatalf("verdict %s, failed %v", rep.Verdict, failedNames(rep))
	}
}

// The light .ptau reader returns what the ceremony's importer returns.
func TestReadPtauMatchesImporter(t *testing.T) {
	c := honest(t, "committed", 3)
	n := 1 << fixture.Power(c.r1cs)
	srs, err := ReadPtau(c.ptauPath, c.pin.Digest, n)
	if err != nil {
		t.Fatal(err)
	}
	commons, _, err := ptau.ImportFile(c.ptauPath, c.pin, uint64(n))
	if err != nil {
		t.Fatal(err)
	}
	want := srsFromCommons(commons, n)
	if len(srs.TauG1) != len(want.TauG1) {
		t.Fatal("length")
	}
	for i := range want.TauG1 {
		if !srs.TauG1[i].Equal(&want.TauG1[i]) {
			t.Fatalf("[τ^%d]₁ differs", i)
		}
	}
	if !srs.Tau2.Equal(&want.Tau2) || !srs.Alpha1.Equal(&want.Alpha1) || !srs.Beta1.Equal(&want.Beta1) || !srs.Beta2.Equal(&want.Beta2) {
		t.Fatal("[τ]₂, α or β differs")
	}
	if srs.FileSHA256 != c.pin.Digest {
		t.Fatal("digest")
	}
	// Wrong pin, and a flipped byte, are refused before parsing.
	if _, err := ReadPtau(c.ptauPath, strings.Repeat("0", 64), n); err == nil {
		t.Fatal("wrong pin accepted")
	}
	b, _ := os.ReadFile(c.ptauPath)
	b[len(b)/2] ^= 1
	flipped := filepath.Join(t.TempDir(), "flipped.ptau")
	os.WriteFile(flipped, b, 0o644)
	if _, err := ReadPtau(flipped, c.pin.Digest, n); err == nil {
		t.Fatal("flipped byte accepted")
	}
}

// SRS_POWERS fires on a non-geometric phase 1 and on a [τ]₂ from another τ.
func TestSRSPowersSelfCheckFires(t *testing.T) {
	c := honest(t, "committed", 3)
	n := 1 << fixture.Power(c.r1cs)
	for _, mut := range []struct {
		name string
		f    func(s *SRS)
	}{
		{"one power perturbed", func(s *SRS) {
			_, _, g1, _ := curve.Generators()
			s.TauG1[n+1].Add(&s.TauG1[n+1], &g1)
		}},
		{"[τ]₂ of another τ", func(s *SRS) {
			_, _, _, g2 := curve.Generators()
			s.Tau2.Add(&s.Tau2, &g2)
		}},
	} {
		srs, err := ReadPtau(c.ptauPath, c.pin.Digest, n)
		if err != nil {
			t.Fatal(err)
		}
		mut.f(srs)
		p, err := Prepare(c.r1cs, srs, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if p.results[0].Name != CheckSRSPowers || p.results[0].Pass {
			t.Errorf("%s: SRS_POWERS passed", mut.name)
		}
	}
}

// gnark-crypto's MSM over vectors that contain O agrees with a naive sum
// (Z and commitment bases can legitimately contain O).
func TestMSMWithInfinity(t *testing.T) {
	_, _, g1, _ := curve.Generators()
	pts := make([]curve.G1Affine, 300)
	sc := make([]fr.Element, len(pts))
	var naive curve.G1Affine
	for i := range pts {
		if i%3 != 0 {
			pts[i].ScalarMultiplication(&g1, bigOfFr(frU(uint64(i*i+1))))
		}
		sc[i] = frU(uint64(7*i + 3))
		var term curve.G1Affine
		term.ScalarMultiplication(&pts[i], bigOfFr(sc[i]))
		naive.Add(&naive, &term)
	}
	got, err := msmG1(pts, sc)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(&naive) {
		t.Fatal("MSM with O points disagrees with the naive sum")
	}
}

// The checker shares no code with the ceremony: it imports neither gnark's
// mpcsetup nor any package of this module.
func TestCheckerIsIndependentOfTheCeremony(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range pkg.Imports {
		if strings.Contains(imp, "mpcsetup") || strings.Contains(imp, "bch-cloak/tools") {
			t.Errorf("crscheck imports %s", imp)
		}
	}
}

// What a malicious commitment key lets the key's maker learn: with
// BasisExpSigma = λ·Basis except one position t, where it is λ·Basis[t] + g₁,
// the proof's knowledge proof minus λ times its commitment is [x_t]₁, the
// mask cancelled, so a small committed value falls to a search. gnark's
// prover emits the proof; only verification under the ceremony's vk fails,
// which is what a wallet that verifies before release (ENG-435 F3) relies on.
func TestMaliciousCommitmentKeyRevealsACommittedValue(t *testing.T) {
	c := honest(t, "committed", 3)
	pk, vk := loadKeys(t, c.dir)
	p := plan(t, c)
	const target = 3 // X[3] = 5 in testcircuits.ByName
	lambda := frU(987654321)
	_, _, g1, _ := curve.Generators()
	ck := &pk.CommitmentKeys[0]
	for j := range ck.Basis {
		ck.BasisExpSigma[j].ScalarMultiplication(&ck.Basis[j], bigOfFr(lambda))
	}
	ck.BasisExpSigma[target].Add(&ck.BasisExpSigma[target], &g1)
	if rep := check(t, p, pk, vk); !strings.Contains(strings.Join(rep.Failed, " "), CheckCommitSig) {
		t.Fatalf("checker did not flag the key: %v", rep.Failed)
	}

	_, assignment, _ := testcircuits.ByName("committed", c.size)
	w, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	proof, err := groth16.Prove(c.r1cs, pk, w)
	if err != nil {
		t.Fatalf("gnark refused to prove: %v", err)
	}
	pr := proof.(*groth16bn254.Proof)
	var leak, ld curve.G1Affine
	ld.ScalarMultiplication(&pr.Commitments[0], bigOfFr(lambda))
	leak.Sub(&pr.CommitmentPok, &ld)
	recovered := -1
	var acc curve.G1Affine
	for v := 0; v < 1<<16; v++ {
		if acc.Equal(&leak) {
			recovered = v
			break
		}
		acc.Add(&acc, &g1)
	}
	if recovered != target+2 {
		t.Fatalf("recovered %d, want X[%d] = %d", recovered, target, target+2)
	}
	pub, _ := w.Public()
	if err := groth16.Verify(proof, vk, pub); err == nil {
		t.Fatal("the leaking proof verifies under the ceremony's vk")
	}
}
