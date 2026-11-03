package verifier_test

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"

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

func wantCode(t *testing.T, err error, code failure.Code) {
	t.Helper()
	if got := failure.CodeOf(err); got != code {
		t.Fatalf("got %v (code %q), want code %q", err, got, code)
	}
}

// ceremony is one sealed simulated ceremony on disk.
type ceremony struct {
	dir, ptau, r1cs string
	pin             ptau.Pin
	name            string
	size            int
}

func (c ceremony) inputs() verifier.Inputs {
	return verifier.Inputs{
		TranscriptPath:    filepath.Join(c.dir, transcript.TranscriptFile),
		PtauPath:          c.ptau,
		R1CSPath:          c.r1cs,
		ExpectedPhase1Pin: &c.pin,
		ExpectedBeacon:    fixture.Beacon.Value,
	}
}

func runCeremony(t *testing.T, name string, size, contributions int) ceremony {
	t.Helper()
	root := t.TempDir()
	r1csPath, r := fixture.R1CS(t, root, name, size)
	ptauPath, pin := fixture.Ptau(t, root, fixture.Power(r)+1) // a larger file, truncated on import
	out := filepath.Join(root, "ceremony")
	if _, err := rerun.Run(rerun.Options{
		PtauPath: ptauPath, PtauPin: pin, PtauSource: "toy fixture (INSECURE)",
		R1CSPath: r1csPath, CircuitLabel: name,
		OutDir: out, CeremonyID: "test-" + name, Contributions: contributions,
		Beacon: fixture.Beacon,
	}); err != nil {
		t.Fatal(err)
	}
	return ceremony{dir: out, ptau: ptauPath, r1cs: r1csPath, pin: pin, name: name, size: size}
}

// copyOf copies the ceremony directory so a negative test can tamper with it.
func (c ceremony) copyOf(t *testing.T) ceremony {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "ceremony")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(c.dir)
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(c.dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dst, e.Name()), b, 0o644)
	}
	c.dir = dst
	return c
}

func (c ceremony) load(t *testing.T) *transcript.Transcript {
	t.Helper()
	tr, err := transcript.Load(filepath.Join(c.dir, transcript.TranscriptFile))
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func (c ceremony) save(t *testing.T, tr *transcript.Transcript) {
	t.Helper()
	if err := transcript.WriteJSON(filepath.Join(c.dir, transcript.TranscriptFile), tr); err != nil {
		t.Fatal(err)
	}
}

var shared ceremony

func base(t *testing.T) ceremony {
	t.Helper()
	if shared.dir == "" {
		// Built once per test binary; tests tamper only with copies.
		dir, err := os.MkdirTemp("", "apnt-pool-ceremony-verifier-*")
		if err != nil {
			t.Fatal(err)
		}
		r1csPath, r := fixture.R1CS(t, dir, "committed", 3)
		ptauPath, pin := fixture.Ptau(t, dir, fixture.Power(r)+1)
		out := filepath.Join(dir, "ceremony")
		if _, err := rerun.Run(rerun.Options{
			PtauPath: ptauPath, PtauPin: pin, PtauSource: "toy fixture (INSECURE)",
			R1CSPath: r1csPath, CircuitLabel: "committed",
			OutDir: out, CeremonyID: "test-committed", Contributions: 3,
			Beacon: fixture.Beacon,
		}); err != nil {
			t.Fatal(err)
		}
		shared = ceremony{dir: out, ptau: ptauPath, r1cs: r1csPath, pin: pin, name: "committed", size: 3}
	}
	return shared.copyOf(t)
}

func TestMain(m *testing.M) {
	code := m.Run()
	if shared.dir != "" {
		os.RemoveAll(filepath.Dir(shared.dir))
	}
	os.Exit(code)
}

func TestVerifiesSimulatedCeremony(t *testing.T) {
	c := base(t)
	rep, err := verifier.Verify(c.inputs())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != "VALID" || rep.Provenance != transcript.SimulatedSingleParty || !rep.ZeroValueOnly || rep.MultiParty() || rep.Notice != transcript.SimulatedNotice {
		t.Fatalf("report %+v", rep)
	}
	if len(rep.Contributions) != 3 {
		t.Fatalf("%d contributions", len(rep.Contributions))
	}
	meta, err := transcript.LoadKeyMetadata(filepath.Join(c.dir, transcript.KeyMetadataFile))
	if err != nil || meta.Provenance != transcript.SimulatedSingleParty || !meta.ZeroValueOnly || meta.Notice != transcript.SimulatedNotice {
		t.Fatalf("key metadata %+v %v", meta, err)
	}
}

// VALID is authoritative only with both out-of-band anchors. With either
// missing, the same transcript is reported CONSISTENT-UNANCHORED, a verdict
// no check for "VALID" can match.
func TestValidRequiresBothAnchors(t *testing.T) {
	c := base(t)
	for _, k := range []struct {
		name        string
		pin, beacon bool
	}{
		{"both anchors", true, true},
		{"phase-1 pin only", true, false},
		{"beacon only", false, true},
		{"no anchor", false, false},
	} {
		in := c.inputs()
		if !k.pin {
			in.ExpectedPhase1Pin = nil
		}
		if !k.beacon {
			in.ExpectedBeacon = ""
		}
		rep, err := verifier.Verify(in)
		if err != nil {
			t.Fatalf("%s: %v", k.name, err)
		}
		if rep.Anchors != (verifier.Anchors{Phase1Pin: k.pin, Beacon: k.beacon}) {
			t.Fatalf("%s: anchors %+v", k.name, rep.Anchors)
		}
		anchored := k.pin && k.beacon
		if rep.Authoritative() != anchored {
			t.Fatalf("%s: authoritative %v", k.name, rep.Authoritative())
		}
		if anchored {
			if rep.Verdict != verifier.VerdictValid {
				t.Fatalf("%s: verdict %q", k.name, rep.Verdict)
			}
			continue
		}
		if rep.Verdict != verifier.VerdictUnanchored || strings.Contains(rep.Verdict, "VALID") {
			t.Fatalf("%s: verdict %q", k.name, rep.Verdict)
		}
	}
}

// The sealed keys are real Groth16 keys: a proof made with the proving key
// verifies under the verifying key, and not under another ceremony's.
func TestSealedKeysProveAndVerify(t *testing.T) {
	c := base(t)
	other := runCeremony(t, "committed", 3, 1)
	for _, cc := range []ceremony{c, other} {
		if _, err := verifier.Verify(cc.inputs()); err != nil {
			t.Fatal(err)
		}
	}
	ccs, err := testcircuits.Compile("committed", 3)
	if err != nil {
		t.Fatal(err)
	}
	_, assignment, _ := testcircuits.ByName("committed", 3)
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := w.Public()

	readKeys := func(dir string) (groth16.ProvingKey, groth16.VerifyingKey) {
		pk, vk := &groth16bn254.ProvingKey{}, &groth16bn254.VerifyingKey{}
		pkb, _ := os.ReadFile(filepath.Join(dir, transcript.ProvingKeyFile))
		vkb, _ := os.ReadFile(filepath.Join(dir, transcript.VerifyingKeyFile))
		if _, err := pk.UnsafeReadFrom(bytes.NewReader(pkb)); err != nil {
			t.Fatal(err)
		}
		if _, err := vk.ReadFrom(bytes.NewReader(vkb)); err != nil {
			t.Fatal(err)
		}
		return pk, vk
	}
	pk, vk := readKeys(c.dir)
	_, otherVK := readKeys(other.dir)

	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatalf("proof does not verify under its own ceremony's key: %v", err)
	}
	if err := groth16.Verify(proof, otherVK, pub); err == nil {
		t.Fatal("proof verifies under another ceremony's key")
	}
}

func TestRefusesTamperedContribution(t *testing.T) {
	// Byte flip: the file no longer matches its recorded digest.
	c := base(t)
	f := filepath.Join(c.dir, "phase2-0002.bin")
	b, _ := os.ReadFile(f)
	b[len(b)/2] ^= 1
	os.WriteFile(f, b, 0o644)
	_, err := verifier.Verify(c.inputs())
	wantCode(t, err, failure.ContributionFileDigest)

	// A valid point replaced by another valid point, with the transcript
	// digest updated to match: only the update proof check can refuse it.
	c = base(t)
	f = filepath.Join(c.dir, "phase2-0002.bin")
	b, _ = os.ReadFile(f)
	p, err := transcript.DecodeState(b)
	if err != nil {
		t.Fatal(err)
	}
	_, _, g1, _ := curve.Generators()
	p.Parameters.G1.PKK[0].Add(&p.Parameters.G1.PKK[0], &g1)
	nb, _ := transcript.StateBytes(p)
	os.WriteFile(f, nb, 0o644)
	tr := c.load(t)
	tr.Phase2.Contributions[1].StateSHA256 = transcript.Digest(nb)
	c.save(t, tr)
	_, err = verifier.Verify(c.inputs())
	wantCode(t, err, failure.ContributionInvalid)
}

func TestRefusesSkippedStep(t *testing.T) {
	// Contribution 2 dropped, indices left as they were.
	c := base(t)
	tr := c.load(t)
	tr.Phase2.Contributions = append(tr.Phase2.Contributions[:1], tr.Phase2.Contributions[2])
	c.save(t, tr)
	_, err := verifier.Verify(c.inputs())
	wantCode(t, err, failure.TranscriptSequence)

	// Dropped and renumbered: contribution 3 now follows contribution 1.
	c = base(t)
	tr = c.load(t)
	tr.Phase2.Contributions = append(tr.Phase2.Contributions[:1], tr.Phase2.Contributions[2])
	tr.Phase2.Contributions[1].Index = 2
	c.save(t, tr)
	_, err = verifier.Verify(c.inputs())
	wantCode(t, err, failure.ContributionChainBroken)

	// And with the recorded challenge forged to point at contribution 1: the
	// challenge inside contribution 3's state still names contribution 2.
	tr.Phase2.Contributions[1].Challenge = tr.Phase2.Contributions[0].StateSHA256
	c.save(t, tr)
	_, err = verifier.Verify(c.inputs())
	wantCode(t, err, failure.ContributionChainBroken)

	// A missing contribution file.
	c = base(t)
	os.Remove(filepath.Join(c.dir, "phase2-0003.bin"))
	_, err = verifier.Verify(c.inputs())
	wantCode(t, err, failure.ContributionMissing)
}

// The recorded challenge is checked in its own right: with every state
// intact, a transcript whose challenge record names the wrong state is
// refused rather than carried as unchecked decoration.
func TestRefusesEditedChallengeRecord(t *testing.T) {
	c := base(t)
	tr := c.load(t)
	tr.Phase2.Contributions[1].Challenge = strings.Repeat("0", 64)
	c.save(t, tr)
	_, err := verifier.Verify(c.inputs())
	wantCode(t, err, failure.ContributionChainBroken)
}

func TestRefusesWrongBeacon(t *testing.T) {
	// The transcript names another beacon than the one the keys were sealed with.
	c := base(t)
	tr := c.load(t)
	tr.Beacon.Value = strings.Repeat("ab", 32)
	c.save(t, tr)
	in := c.inputs()
	in.ExpectedBeacon = ""
	_, err := verifier.Verify(in)
	wantCode(t, err, failure.SealedKeyMismatch)

	// The operator expects a different public beacon.
	c = base(t)
	in = c.inputs()
	in.ExpectedBeacon = strings.Repeat("cd", 32)
	_, err = verifier.Verify(in)
	wantCode(t, err, failure.BeaconUnexpected)

	// A beacon too short to be a block hash.
	c = base(t)
	tr = c.load(t)
	tr.Beacon.Value = "0011"
	c.save(t, tr)
	in = c.inputs()
	in.ExpectedBeacon = ""
	_, err = verifier.Verify(in)
	wantCode(t, err, failure.BeaconInvalid)
}

func TestRefusesPhase1Mismatch(t *testing.T) {
	// The phase-1 file changed on disk.
	c := base(t)
	b, _ := os.ReadFile(c.ptau)
	b[len(b)-1] ^= 1
	tampered := filepath.Join(t.TempDir(), "tampered.ptau")
	os.WriteFile(tampered, b, 0o644)
	in := c.inputs()
	in.PtauPath = tampered
	_, err := verifier.Verify(in)
	wantCode(t, err, failure.Phase1HashMismatch)

	// The transcript pins a different file than the operator trusts.
	c = base(t)
	in = c.inputs()
	other := ptau.Pin{Algorithm: ptau.AlgSHA256, Digest: strings.Repeat("0", 64)}
	in.ExpectedPhase1Pin = &other
	_, err = verifier.Verify(in)
	wantCode(t, err, failure.Phase1PinUnexpected)

	// Another valid powers-of-tau file, with the transcript re-pinned to it.
	c = base(t)
	_, r := fixture.R1CS(t, t.TempDir(), c.name, c.size)
	otherPath, otherPin := fixture.PtauWith(t, t.TempDir(), fixture.Power(r)+1, 17, 19, 23)
	tr := c.load(t)
	tr.Phase1.Pin = otherPin
	st, _ := os.Stat(otherPath)
	tr.Phase1.FileSize = st.Size()
	c.save(t, tr)
	in = c.inputs()
	in.PtauPath, in.ExpectedPhase1Pin = otherPath, &otherPin
	_, err = verifier.Verify(in)
	wantCode(t, err, failure.Phase1CommonsMismatch)
}

func TestRefusesDifferentR1CS(t *testing.T) {
	// Verified against another circuit's R1CS.
	c := base(t)
	otherPath, other := fixture.R1CS(t, t.TempDir(), c.name, c.size+1)
	in := c.inputs()
	in.R1CSPath = otherPath
	_, err := verifier.Verify(in)
	wantCode(t, err, failure.R1CSDigestMismatch)

	// The transcript rewritten to describe the other R1CS, consistently:
	// digest, shape, root and initial state all recomputed. The contributions
	// were made on the original circuit's chain and cannot be moved.
	_, digest, _ := transcript.ReadR1CS(otherPath)
	tr := c.load(t)
	tr.Circuit = transcript.DescribeCircuit(tr.Circuit.Label, other, digest)
	commons, info, err := ptau.ImportFile(c.ptau, c.pin, transcript.DomainSize(other))
	if err != nil {
		t.Fatal(err)
	}
	tr.Phase1.DomainSize, tr.Phase1.CommonsSHA256 = info.DomainSize, info.CommonsSHA256
	root, _ := transcript.RootChallenge(tr.CeremonyID, tr.Provenance, info.CommonsSHA256, digest)
	_, initial, _, err := transcript.InitialState(other, commons, root)
	if err != nil {
		t.Fatal(err)
	}
	tr.Phase2.RootChallenge = hex.EncodeToString(root)
	tr.Phase2.InitialStateSHA256, tr.Phase2.StateLength = transcript.Digest(initial), int64(len(initial))
	tr.Phase2.Contributions[0].Challenge = tr.Phase2.InitialStateSHA256
	c.save(t, tr)
	_, err = verifier.Verify(in)
	if code := failure.CodeOf(err); code != failure.ContributionChainBroken && code != failure.ContributionShape {
		t.Fatalf("got %v, want the contribution chain refused", err)
	}
}

func TestRefusesTamperedKeysAndMetadata(t *testing.T) {
	c := base(t)
	f := filepath.Join(c.dir, transcript.VerifyingKeyFile)
	b, _ := os.ReadFile(f)
	b[len(b)-1] ^= 1
	os.WriteFile(f, b, 0o644)
	_, err := verifier.Verify(c.inputs())
	wantCode(t, err, failure.KeyFileDigestMismatch)

	c = base(t)
	meta, _ := transcript.LoadKeyMetadata(filepath.Join(c.dir, transcript.KeyMetadataFile))
	meta.Provenance, meta.ZeroValueOnly, meta.Notice = transcript.PermissionlessMultiParty, false, transcript.MultiPartyNotice
	transcript.WriteJSON(filepath.Join(c.dir, transcript.KeyMetadataFile), meta)
	_, err = verifier.Verify(c.inputs())
	wantCode(t, err, failure.KeyMetadataMismatch)

	// A second JSON value after the unchanged metadata object (REV-148 H3).
	c = base(t)
	mf := filepath.Join(c.dir, transcript.KeyMetadataFile)
	b, _ = os.ReadFile(mf)
	os.WriteFile(mf, append(b, "{}\n"...), 0o644)
	_, err = verifier.Verify(c.inputs())
	wantCode(t, err, failure.KeyMetadataMalformed)
}

// TestSimulatedNeverReportedMultiParty walks every step an editor could take
// to relabel a simulated transcript as permissionless multi-party, making it
// more self-consistent at each step. Every step is refused, and the only
// report these contributions can ever produce says simulated.
func TestSimulatedNeverReportedMultiParty(t *testing.T) {
	c := base(t)
	rep, err := verifier.Verify(c.inputs())
	if err != nil || rep.MultiParty() || rep.Provenance != transcript.SimulatedSingleParty {
		t.Fatalf("baseline: %+v %v", rep, err)
	}
	steps := []struct {
		name string
		edit func(tr *transcript.Transcript)
		want failure.Code
	}{
		{"label only", func(tr *transcript.Transcript) {
			tr.Provenance = transcript.PermissionlessMultiParty
		}, failure.ProvenanceConflict},
		{"label, zero-value flag and notice", func(tr *transcript.Transcript) {
			tr.ZeroValueOnly, tr.Notice = false, transcript.MultiPartyNotice
		}, failure.ProvenanceConflict},
		{"contributors relabelled remote", func(tr *transcript.Transcript) {
			for i := range tr.Phase2.Contributions {
				tr.Phase2.Contributions[i].Contributor.Kind = transcript.KindRemote
			}
		}, failure.RootMismatch},
		{"root recomputed for the new label", func(tr *transcript.Transcript) {
			root, _ := transcript.RootChallenge(tr.CeremonyID, tr.Provenance, tr.Phase1.CommonsSHA256, tr.Circuit.R1CSSHA256)
			tr.Phase2.RootChallenge = hex.EncodeToString(root)
		}, failure.InitialMismatch},
		{"initial state recomputed", func(tr *transcript.Transcript) {
			r1cs, _, _ := transcript.ReadR1CS(c.r1cs)
			commons, _, _ := ptau.ImportFile(c.ptau, c.pin, transcript.DomainSize(r1cs))
			root, _ := hex.DecodeString(tr.Phase2.RootChallenge)
			_, initial, _, _ := transcript.InitialState(r1cs, commons, root)
			tr.Phase2.InitialStateSHA256 = transcript.Digest(initial)
		}, failure.ContributionChainBroken},
		{"first recorded challenge re-pointed", func(tr *transcript.Transcript) {
			tr.Phase2.Contributions[0].Challenge = tr.Phase2.InitialStateSHA256
		}, failure.ContributionChainBroken},
	}
	tr := c.load(t)
	for _, s := range steps {
		s.edit(tr)
		c.save(t, tr)
		rep, err := verifier.Verify(c.inputs())
		if rep != nil {
			t.Fatalf("%s: a relabelled transcript produced a report: %+v", s.name, rep)
		}
		if got := failure.CodeOf(err); got != s.want {
			t.Fatalf("%s: got %v (code %q), want %q", s.name, err, got, s.want)
		}
	}
	// Key metadata relabelled too: still refused at the chain.
	meta := transcript.MetadataFor(tr)
	transcript.WriteJSON(filepath.Join(c.dir, transcript.KeyMetadataFile), &meta)
	_, err = verifier.Verify(c.inputs())
	wantCode(t, err, failure.ContributionChainBroken)
}

// TestFullyConsistentRelabelRefused applies every relabelling edit at once —
// labels, contributor kinds, root, initial state, first challenge and key
// metadata — leaving nothing inconsistent but the contributions themselves.
// Only the root challenge's binding of the provenance refuses it.
func TestFullyConsistentRelabelRefused(t *testing.T) {
	c := base(t)
	tr := c.load(t)
	tr.Provenance, tr.ZeroValueOnly, tr.Notice = transcript.PermissionlessMultiParty, false, transcript.MultiPartyNotice
	for i := range tr.Phase2.Contributions {
		tr.Phase2.Contributions[i].Contributor.Kind = transcript.KindRemote
	}
	r1cs, _, _ := transcript.ReadR1CS(c.r1cs)
	commons, _, _ := ptau.ImportFile(c.ptau, c.pin, transcript.DomainSize(r1cs))
	root, _ := transcript.RootChallenge(tr.CeremonyID, tr.Provenance, tr.Phase1.CommonsSHA256, tr.Circuit.R1CSSHA256)
	_, initial, _, _ := transcript.InitialState(r1cs, commons, root)
	tr.Phase2.RootChallenge, tr.Phase2.InitialStateSHA256 = hex.EncodeToString(root), transcript.Digest(initial)
	tr.Phase2.Contributions[0].Challenge = tr.Phase2.InitialStateSHA256
	c.save(t, tr)
	meta := transcript.MetadataFor(tr)
	transcript.WriteJSON(filepath.Join(c.dir, transcript.KeyMetadataFile), &meta)

	rep, err := verifier.Verify(c.inputs())
	if rep != nil {
		t.Fatalf("a relabelled simulated transcript was reported as %s", rep.Provenance)
	}
	wantCode(t, err, failure.ContributionChainBroken)
}

// A multi-party transcript verifies and is reported as multi-party. This one
// is produced in-process by one test, which is exactly why the label is a
// claim about process that the verifier can bind but not prove: anyone can
// run "remote" contributors themselves. 1-of-N honesty is each contributor's
// own to rely on, by finding its contribution in the report.
func TestMultiPartyLabelIsReportedButProvesNoHonesty(t *testing.T) {
	root := t.TempDir()
	r1csPath, r := fixture.R1CS(t, root, "cubic", 5)
	ptauPath, pin := fixture.Ptau(t, root, fixture.Power(r))
	commons, info, err := ptau.ImportFile(ptauPath, pin, transcript.DomainSize(r))
	if err != nil {
		t.Fatal(err)
	}
	_, digest, _ := transcript.ReadR1CS(r1csPath)
	out := filepath.Join(root, "ceremony")
	co, err := coordinator.New(coordinator.Config{
		Dir: out, CeremonyID: "sham-multi-party", Provenance: transcript.PermissionlessMultiParty,
		Phase1:  transcript.Phase1{Source: "toy", File: filepath.Base(ptauPath), FileSize: info.FileSize, Pin: pin, Power: info.Power},
		Commons: commons, R1CS: r, R1CSSHA256: digest, CircuitLabel: "cubic",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"r1", "r2"} {
		ch, _ := co.Challenge()
		msg, err := contributor.Contribute(ch, transcript.Contributor{ID: id, Kind: transcript.KindRemote})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := co.Submit(msg); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := co.Seal(fixture.Beacon); err != nil {
		t.Fatal(err)
	}
	rep, err := verifier.Verify(verifier.Inputs{TranscriptPath: filepath.Join(out, transcript.TranscriptFile), PtauPath: ptauPath, R1CSPath: r1csPath})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.MultiParty() || rep.ZeroValueOnly || rep.Notice != transcript.MultiPartyNotice {
		t.Fatalf("report %+v", rep)
	}
	// Without out-of-band anchors the report is not authoritative either.
	if rep.Verdict != verifier.VerdictUnanchored || rep.Authoritative() {
		t.Fatalf("unanchored report has verdict %q", rep.Verdict)
	}
	// Relabelled down to simulated, the same contributions are refused too:
	// the binding runs both ways.
	tr, _ := transcript.Load(filepath.Join(out, transcript.TranscriptFile))
	tr.Provenance, tr.ZeroValueOnly, tr.Notice = transcript.SimulatedSingleParty, true, transcript.SimulatedNotice
	rootB, _ := transcript.RootChallenge(tr.CeremonyID, tr.Provenance, tr.Phase1.CommonsSHA256, tr.Circuit.R1CSSHA256)
	tr.Phase2.RootChallenge = hex.EncodeToString(rootB)
	transcript.WriteJSON(filepath.Join(out, transcript.TranscriptFile), tr)
	_, err = verifier.Verify(verifier.Inputs{TranscriptPath: filepath.Join(out, transcript.TranscriptFile), PtauPath: ptauPath, R1CSPath: r1csPath})
	wantCode(t, err, failure.InitialMismatch)
}

// The verifier command and package must not depend on the coordinator, the
// contributor or the re-run orchestration.
func TestVerifierIsIndependentOfTheCoordinator(t *testing.T) {
	forbidden := []string{"/apnt-pool-ceremony/coordinator", "/apnt-pool-ceremony/contributor", "/apnt-pool-ceremony/rerun"}
	deps := func(pkg string) string {
		out, err := exec.Command("go", "list", "-deps", pkg).CombinedOutput()
		if err != nil {
			t.Fatalf("go list %s: %v\n%s", pkg, err, out)
		}
		return string(out)
	}
	found := func(d, p string) bool { return strings.Contains(d, p+"\n") }

	// Negative control: the same detector finds them in the coordinator-side command.
	ctl := deps("../cmd/apnt-pool-ceremony")
	for _, p := range forbidden {
		if !found(ctl, p) {
			t.Fatalf("detector does not find %s in the coordinator command; the check would be vacuous", p)
		}
	}
	for _, pkg := range []string{"../cmd/apnt-pool-ceremony-verify", "."} {
		d := deps(pkg)
		if !found(d, "/apnt-pool-ceremony/verifier") {
			t.Fatalf("%s: listing does not include the verifier", pkg)
		}
		for _, p := range forbidden {
			if found(d, p) {
				t.Fatalf("%s depends on %s", pkg, p)
			}
		}
	}
}

// A transcript made on another gnark, here with the pre-ENG-367 v0.15.0 tool
// record, is refused: phase 2 must run on the gnark the action circuit's R1CS
// was compiled with. The unedited round trip is the control.
func TestRefusesOtherGnarkToolRecord(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*transcript.Transcript)
		want failure.Code
	}{
		{"unedited", func(*transcript.Transcript) {}, ""},
		{"gnark", func(tr *transcript.Transcript) { tr.Tool.Gnark = "v0.15.0" }, failure.TranscriptFormat},
		{"gnark-crypto", func(tr *transcript.Transcript) { tr.Tool.GnarkCrypto = "v0.20.1" }, failure.TranscriptFormat},
		{"proving-key encoding", func(tr *transcript.Transcript) {
			tr.Keys.ProvingKey.Encoding = "gnark-v0.15.0-groth16-bn254-WriteRawTo"
		}, failure.TranscriptFormat},
	} {
		c := base(t)
		tr := c.load(t)
		tc.edit(tr)
		c.save(t, tr)
		_, err := verifier.Verify(c.inputs())
		if got := failure.CodeOf(err); got != tc.want || (tc.want == "") != (err == nil) {
			t.Fatalf("%s: got %v (code %q), want code %q", tc.name, err, got, tc.want)
		}
	}
}
