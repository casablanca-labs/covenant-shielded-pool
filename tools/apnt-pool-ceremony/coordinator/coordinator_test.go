package coordinator_test

import (
	"os"
	"path/filepath"
	"testing"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/contributor"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/coordinator"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/internal/fixture"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

func wantCode(t *testing.T, err error, code failure.Code) {
	t.Helper()
	if got := failure.CodeOf(err); got != code {
		t.Fatalf("got %v (code %q), want code %q", err, got, code)
	}
}

func newCoordinator(t *testing.T, prov transcript.Provenance) *coordinator.Coordinator {
	t.Helper()
	dir := t.TempDir()
	r1csPath, r := fixture.R1CS(t, dir, "committed", 3)
	ptauPath, pin := fixture.Ptau(t, dir, fixture.Power(r))
	commons, info, err := ptau.ImportFile(ptauPath, pin, transcript.DomainSize(r))
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := transcript.ReadR1CS(r1csPath)
	if err != nil {
		t.Fatal(err)
	}
	c, err := coordinator.New(coordinator.Config{
		Dir:        filepath.Join(dir, "ceremony"),
		CeremonyID: "test-ceremony",
		Provenance: prov,
		Phase1:     transcript.Phase1{Source: "toy", File: filepath.Base(ptauPath), FileSize: info.FileSize, Pin: pin, Power: info.Power, CommonsSHA256: info.CommonsSHA256},
		Commons:    commons, R1CS: r, R1CSSHA256: digest, CircuitLabel: "committed-3",
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func contribute(t *testing.T, c *coordinator.Coordinator, who transcript.Contributor) []byte {
	t.Helper()
	ch, err := c.Challenge()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := contributor.Contribute(ch, who)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

var auto = transcript.Contributor{ID: "automated-01", Kind: transcript.KindAutomatedLocal}

func TestQueueAcceptsAutomatedContributions(t *testing.T) {
	c := newCoordinator(t, transcript.SimulatedSingleParty)
	queue := []coordinator.Contributor{contributor.NewAutomated("a1"), contributor.NewAutomated("a2"), contributor.NewAutomated("a3")}
	accepted, refused, err := c.RunQueue(queue)
	if err != nil || len(refused) != 0 || len(accepted) != 3 {
		t.Fatalf("accepted %d, refused %v, err %v", len(accepted), refused, err)
	}
	for i, a := range accepted {
		if a.Index != i+1 || a.Contributor.Kind != transcript.KindAutomatedLocal {
			t.Fatalf("record %d: %+v", i, a)
		}
		if i > 0 && a.Challenge != accepted[i-1].StateSHA256 {
			t.Fatal("challenge chain not recorded")
		}
	}
	tr, err := c.Seal(fixture.Beacon)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Status != transcript.StatusSealed || tr.Provenance != transcript.SimulatedSingleParty || !tr.ZeroValueOnly || tr.Notice != transcript.SimulatedNotice {
		t.Fatalf("sealed transcript labels: %+v", tr)
	}
	// Sealed ceremonies accept nothing more.
	_, err = c.Challenge()
	wantCode(t, err, failure.CeremonySealed)
	_, err = c.Seal(fixture.Beacon)
	wantCode(t, err, failure.CeremonySealed)
}

// replacePKK0 returns a contribution message whose state has its first PKK
// point moved by the generator: still a valid, canonically encoded curve
// point, so only the cryptographic update check can refuse it.
func replacePKK0(t *testing.T, msg []byte) []byte {
	t.Helper()
	h, state, err := transcript.DecodeMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	p, err := transcript.DecodeState(state)
	if err != nil {
		t.Fatal(err)
	}
	_, _, g1, _ := curve.Generators()
	p.Parameters.G1.PKK[0].Add(&p.Parameters.G1.PKK[0], &g1)
	nb, err := transcript.StateBytes(p)
	if err != nil {
		t.Fatal(err)
	}
	h.StateSHA256, h.StateLength = transcript.Digest(nb), int64(len(nb))
	out, err := transcript.EncodeMessage(h, nb)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCoordinatorRefusesTamperedContribution(t *testing.T) {
	c := newCoordinator(t, transcript.SimulatedSingleParty)
	honest := contribute(t, c, auto)
	_, err := c.Submit(replacePKK0(t, honest))
	wantCode(t, err, failure.ContributionInvalid)
	// The refusal changed nothing: the honest answer to the same challenge is
	// still accepted as contribution 1.
	rec, err := c.Submit(honest)
	if err != nil || rec.Index != 1 {
		t.Fatalf("honest contribution after a refusal: %+v %v", rec, err)
	}
	if n := len(c.Transcript().Phase2.Contributions); n != 1 {
		t.Fatalf("%d contributions recorded", n)
	}
}

func TestCoordinatorRefusesSkippedStep(t *testing.T) {
	c := newCoordinator(t, transcript.SimulatedSingleParty)
	first := contribute(t, c, auto)
	stale := contribute(t, c, transcript.Contributor{ID: "late", Kind: transcript.KindAutomatedLocal})
	if _, err := c.Submit(first); err != nil {
		t.Fatal(err)
	}
	// stale answers the initial state, which is no longer the latest.
	_, err := c.Submit(stale)
	wantCode(t, err, failure.ContributionSequence)

	// Relabel it as contribution 2 built on contribution 1: the envelope now
	// agrees, but the state inside was made on the initial state.
	h, state, _ := transcript.DecodeMessage(stale)
	h.Index = 2
	h.PreviousStateSHA256 = c.Transcript().Phase2.Contributions[0].StateSHA256
	forged, _ := transcript.EncodeMessage(h, state)
	_, err = c.Submit(forged)
	wantCode(t, err, failure.ContributionChainBroken)

	// Index right, previous state wrong.
	h.PreviousStateSHA256 = c.Transcript().Phase2.InitialStateSHA256
	forged, _ = transcript.EncodeMessage(h, state)
	_, err = c.Submit(forged)
	wantCode(t, err, failure.ContributionStale)
}

func TestCoordinatorRefusesMalformedMessages(t *testing.T) {
	c := newCoordinator(t, transcript.SimulatedSingleParty)
	msg := contribute(t, c, auto)
	h, state, _ := transcript.DecodeMessage(msg)

	other := h
	other.CeremonyID = "another"
	m, _ := transcript.EncodeMessage(other, state)
	_, err := c.Submit(m)
	wantCode(t, err, failure.MessageWrongCeremony)

	other = h
	other.Type = transcript.MessageChallenge
	m, _ = transcript.EncodeMessage(other, state)
	_, err = c.Submit(m)
	wantCode(t, err, failure.MessageMalformed)

	other = h
	other.Contributor = nil
	m, _ = transcript.EncodeMessage(other, state)
	_, err = c.Submit(m)
	wantCode(t, err, failure.MessageMalformed)

	// A length prefix inflated before decoding.
	bad := append([]byte(nil), state...)
	bad[34] = 0x7f
	other = h
	other.StateSHA256 = transcript.Digest(bad)
	m, _ = transcript.EncodeMessage(other, bad)
	_, err = c.Submit(m)
	wantCode(t, err, failure.ContributionShape)

	// The state does not match the header digest.
	tampered := append([]byte(nil), msg...)
	tampered[len(tampered)-5] ^= 1
	_, err = c.Submit(tampered)
	wantCode(t, err, failure.MessageDigestMismatch)

	if n := len(c.Transcript().Phase2.Contributions); n != 0 {
		t.Fatalf("%d contributions recorded after refusals", n)
	}
	if _, err := c.Submit(msg); err != nil {
		t.Fatal(err)
	}
}

func TestMultiPartyCeremonyRefusesAutomatedContributions(t *testing.T) {
	c := newCoordinator(t, transcript.PermissionlessMultiParty)
	// The automated contributor itself refuses to answer a multi-party challenge.
	ch, _ := c.Challenge()
	_, err := contributor.NewAutomated("a1").Contribute(ch)
	wantCode(t, err, failure.ProvenanceConflict)

	// A message relabelled by hand is refused by the coordinator.
	msg := contribute(t, c, transcript.Contributor{ID: "r1", Kind: transcript.KindRemote})
	h, state, _ := transcript.DecodeMessage(msg)
	h.Contributor = &transcript.Contributor{ID: "a1", Kind: transcript.KindAutomatedLocal}
	forged, _ := transcript.EncodeMessage(h, state)
	_, err = c.Submit(forged)
	wantCode(t, err, failure.ProvenanceConflict)

	_, refused, err := c.RunQueue([]coordinator.Contributor{contributor.NewAutomated("a2")})
	if err != nil || len(refused) != 1 || refused[0].Code != failure.ProvenanceConflict {
		t.Fatalf("queue refusal %+v %v", refused, err)
	}
	if _, err := c.Submit(msg); err != nil {
		t.Fatal(err)
	}
}

// A remote contributor exchanges the same message bytes through files.
func TestRemoteContributorFileRoundTrip(t *testing.T) {
	c := newCoordinator(t, transcript.SimulatedSingleParty)
	dir := t.TempDir()
	ch, err := c.Challenge()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "challenge.bin"), ch, 0o644); err != nil {
		t.Fatal(err)
	}
	in, _ := os.ReadFile(filepath.Join(dir, "challenge.bin"))
	answer, err := contributor.Contribute(in, transcript.Contributor{ID: "remote-1", Kind: transcript.KindRemote})
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "contribution.bin"), answer, 0o644)
	back, _ := os.ReadFile(filepath.Join(dir, "contribution.bin"))
	rec, err := c.Submit(back)
	if err != nil || rec.Contributor.Kind != transcript.KindRemote {
		t.Fatalf("%+v %v", rec, err)
	}
}

func TestSealPreconditions(t *testing.T) {
	c := newCoordinator(t, transcript.SimulatedSingleParty)
	_, err := c.Seal(fixture.Beacon)
	wantCode(t, err, failure.CeremonyNoContributions)
	if _, err := c.Submit(contribute(t, c, auto)); err != nil {
		t.Fatal(err)
	}
	for _, b := range []transcript.Beacon{
		{Value: "00", Source: "short"},
		{Value: fixture.Beacon.Value, Source: ""},
		{Value: "ZZ" + fixture.Beacon.Value[2:], Source: "x"},
		{Value: "A1" + fixture.Beacon.Value[2:], Source: "uppercase"},
	} {
		_, err := c.Seal(b)
		wantCode(t, err, failure.BeaconInvalid)
	}
}

func TestOutputDirectoryMustBeEmpty(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "old-transcript.json"), []byte("{}"), 0o644)
	_, err := coordinator.New(coordinator.Config{Dir: dir, Provenance: transcript.SimulatedSingleParty})
	wantCode(t, err, failure.OutputExists)
	_, err = coordinator.New(coordinator.Config{Dir: t.TempDir(), Provenance: "multi"})
	wantCode(t, err, failure.ProvenanceInvalid)
}
