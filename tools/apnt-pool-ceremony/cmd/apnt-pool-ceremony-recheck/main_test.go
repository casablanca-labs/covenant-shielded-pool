package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/internal/fixture"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/rerun"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/testcircuits"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

// ceremony is a sealed toy ceremony and the recheck's inputs for it.
type ceremony struct {
	dir, ptau, r1cs string
	pin             ptau.Pin
	r1csSHA, pk     string
}

func (c ceremony) recheck(t *testing.T) (int, Report) {
	t.Helper()
	var out, errOut bytes.Buffer
	status := run([]string{
		"--transcript", filepath.Join(c.dir, transcript.TranscriptFile), "--ptau", c.ptau, "--r1cs", c.r1cs,
		"--expect-phase1-pin", c.pin.String(), "--expect-r1cs-sha256", c.r1csSHA, "--expect-proving-key-sha256", c.pk,
	}, &out, &errOut)
	var rep Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("report does not decode: %v\n%s\n%s", err, out.String(), errOut.String())
	}
	return status, rep
}

// sealedCeremony runs init, the contributions and seal, without the
// standalone verifier, so a circuit the verifier refuses still yields keys.
func sealedCeremony(t *testing.T, r *cs.R1CS, ptauPower uint32) ceremony {
	t.Helper()
	root := t.TempDir()
	r1csPath := filepath.Join(root, "circuit.r1cs")
	if err := testcircuits.WriteR1CS(r1csPath, r); err != nil {
		t.Fatal(err)
	}
	ptauPath, pin := fixture.Ptau(t, root, ptauPower)
	o := rerun.Options{
		PtauPath: ptauPath, PtauPin: pin, PtauSource: "toy fixture (INSECURE)",
		R1CSPath: r1csPath, CircuitLabel: "recheck", OutDir: filepath.Join(root, "ceremony"),
		WorkDir: filepath.Join(root, "work"), CeremonyID: "recheck", Contributions: 1, Beacon: fixture.Beacon,
	}
	if _, err := rerun.Init(o); err != nil {
		t.Fatal(err)
	}
	if _, err := rerun.Contribute(o); err != nil {
		t.Fatal(err)
	}
	if _, err := rerun.Seal(o); err != nil {
		t.Fatal(err)
	}
	tr, err := transcript.Load(filepath.Join(o.OutDir, transcript.TranscriptFile))
	if err != nil {
		t.Fatal(err)
	}
	return ceremony{dir: o.OutDir, ptau: ptauPath, r1cs: r1csPath, pin: pin, r1csSHA: tr.Circuit.R1CSSHA256, pk: tr.Keys.ProvingKey.SHA256}
}

func committed(t *testing.T) ceremony {
	t.Helper()
	r, err := testcircuits.Compile("committed", 3)
	if err != nil {
		t.Fatal(err)
	}
	return sealedCeremony(t, r, fixture.Power(r)+1)
}

func wantRefused(t *testing.T, name string, status int, rep Report, code failure.Code) {
	t.Helper()
	if status != 1 || rep.Verdict != "REFUSED" || rep.Code != code {
		t.Fatalf("%s: exit %d, verdict %s, code %s (%s); want exit 1, %s", name, status, rep.Verdict, rep.Code, rep.Detail, code)
	}
}

// Positive control: an honest toy ceremony passes, and the report locates
// the committed circuit's mask at position 8 of 9.
func TestRecheckPassesAnHonestCeremony(t *testing.T) {
	status, rep := committed(t).recheck(t)
	if status != 0 || rep.Verdict != "PASS" {
		t.Fatalf("exit %d, %+v", status, rep)
	}
	if rep.Masks == nil || len(rep.Masks.Positions) != 1 || len(rep.Masks.Positions[0]) != 1 || rep.Masks.Positions[0][0] != 8 || rep.Masks.NbCommitted[0] != 9 {
		t.Fatalf("masks %+v", rep.Masks)
	}
	names := map[string]bool{}
	for _, c := range rep.Checks {
		names[c.Name] = true
	}
	for _, want := range []string{"ANCHORS", "COMMITMENT_MASKS_LOCATED", "PHASE1_IMPORT", "PHASE1_NON_DEGENERATE", "PROVING_KEY_READ", "COMMITMENT_MASK_NONZERO"} {
		if !names[want] {
			t.Fatalf("report lacks %s: %+v", want, rep.Checks)
		}
	}
}

// The phase-1 checks fire through the recheck: the ceremony's record is
// pointed at a degenerate phase-1 file of the circuit's domain.
func TestRecheckRefusesADegeneratePhase1(t *testing.T) {
	var minusOne fr.Element
	minusOne.SetOne()
	minusOne.Neg(&minusOne)
	for _, tc := range []struct {
		name string
		tau  func(n uint64) fr.Element
		beta fr.Element
		want failure.Code
	}{
		{"τ = ω", func(n uint64) fr.Element { return fft.NewDomain(n).Generator }, fr.NewElement(fixture.ToyBeta), failure.Phase1TauInDomain},
		{"β = −1", func(uint64) fr.Element { return fr.NewElement(fixture.ToyTau) }, minusOne, failure.Phase1BetaMinusOne},
	} {
		c := committed(t)
		tr, err := transcript.Load(filepath.Join(c.dir, transcript.TranscriptFile))
		if err != nil {
			t.Fatal(err)
		}
		power := uint32(0)
		for 1<<power < tr.Phase1.DomainSize {
			power++
		}
		commons := ptau.ToyCommonsFr(power, tc.tau(tr.Phase1.DomainSize), fr.NewElement(fixture.ToyAlpha), tc.beta)
		var b bytes.Buffer
		if err := ptau.Write(&b, commons); err != nil {
			t.Fatal(err)
		}
		c.ptau = filepath.Join(t.TempDir(), "degenerate.ptau")
		if err := os.WriteFile(c.ptau, b.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		c.pin = fixture.PinOf(t, c.ptau)
		tr.Phase1.Pin, tr.Phase1.FileSize, tr.Phase1.Power = c.pin, int64(b.Len()), power
		if tr.Phase1.CommonsSHA256, err = ptau.CommonsDigest(commons); err != nil {
			t.Fatal(err)
		}
		if err := transcript.WriteJSON(filepath.Join(c.dir, transcript.TranscriptFile), tr); err != nil {
			t.Fatal(err)
		}
		status, rep := c.recheck(t)
		wantRefused(t, tc.name, status, rep, tc.want)
	}
}

// The mask check fires through the recheck on the key file: the published
// key with its mask's basis element set to O (and the record updated to its
// digest), and a sealed key whose mask position is O by cancellation.
func TestRecheckRefusesAZeroMaskBasisElement(t *testing.T) {
	c := committed(t)
	pkPath := filepath.Join(c.dir, transcript.ProvingKeyFile)
	b, err := os.ReadFile(pkPath)
	if err != nil {
		t.Fatal(err)
	}
	pk := &groth16bn254.ProvingKey{}
	if _, err := pk.ReadFrom(bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	pk.CommitmentKeys[0].Basis[8] = curve.G1Affine{}
	var zeroed bytes.Buffer
	if _, err := pk.WriteRawTo(&zeroed); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pkPath, zeroed.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	tr, err := transcript.Load(filepath.Join(c.dir, transcript.TranscriptFile))
	if err != nil {
		t.Fatal(err)
	}
	c.pk = transcript.Digest(zeroed.Bytes())
	tr.Keys.ProvingKey.SHA256 = c.pk
	if err := transcript.WriteJSON(filepath.Join(c.dir, transcript.TranscriptFile), tr); err != nil {
		t.Fatal(err)
	}
	status, rep := c.recheck(t)
	wantRefused(t, "mask zeroed", status, rep, failure.CommitmentMaskZero)

	cancelled := sealedCeremony(t, fixture.MaskCancelledR1CS(), 3)
	status, rep = cancelled.recheck(t)
	wantRefused(t, "mask cancelled", status, rep, failure.CommitmentMaskZero)
}

// A commitment without a mask, a mask-shaped wire without Randomize
// provenance (REV-197's circuit), and inputs that do not match the anchors or
// the record, are refused.
func TestRecheckRefusesUnanchoredOrUnmaskedInputs(t *testing.T) {
	status, rep := sealedCeremony(t, fixture.UnmaskedR1CS(), 3).recheck(t)
	wantRefused(t, "unmasked", status, rep, failure.CommitmentMaskMissing)

	nonrandom := fixture.UnmaskedR1CS()
	nonrandom.CommitmentInfo.(constraint.Groth16Commitments)[0].PrivateCommitted[0] = 2
	status, rep = sealedCeremony(t, nonrandom, 3).recheck(t)
	wantRefused(t, "mask-shaped secret input", status, rep, failure.CommitmentMaskNotRandomized)

	c := committed(t)
	wrongPin := c
	wrongPin.pin.Digest = "00" + c.pin.Digest[2:]
	status, rep = wrongPin.recheck(t)
	wantRefused(t, "other phase-1 pin", status, rep, failure.Phase1PinUnexpected)

	wrongR1CS := c
	wrongR1CS.r1csSHA = "00" + c.r1csSHA[2:]
	status, rep = wrongR1CS.recheck(t)
	wantRefused(t, "other R1CS digest", status, rep, failure.R1CSUnexpected)

	wrongPK := c
	wrongPK.pk = "00" + c.pk[2:]
	status, rep = wrongPK.recheck(t)
	wantRefused(t, "other proving-key digest", status, rep, failure.KeyFileDigestMismatch)

	pkPath := filepath.Join(c.dir, transcript.ProvingKeyFile)
	b, err := os.ReadFile(pkPath)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 1
	if err := os.WriteFile(pkPath, b, 0o644); err != nil {
		t.Fatal(err)
	}
	status, rep = c.recheck(t)
	wantRefused(t, "key file edited", status, rep, failure.KeyFileDigestMismatch)
}
