package transcript_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/testcircuits"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

func wantCode(t *testing.T, err error, code failure.Code) {
	t.Helper()
	if got := failure.CodeOf(err); got != code {
		t.Fatalf("got %v (code %q), want code %q", err, got, code)
	}
}

const (
	d1 = "1111111111111111111111111111111111111111111111111111111111111111"
	d2 = "2222222222222222222222222222222222222222222222222222222222222222"
)

func TestRootChallengeBindsEveryField(t *testing.T) {
	base, err := transcript.RootChallenge("c", transcript.SimulatedSingleParty, d1, d2)
	if err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][4]string{
		"ceremony id": {"d", string(transcript.SimulatedSingleParty), d1, d2},
		"provenance":  {"c", string(transcript.PermissionlessMultiParty), d1, d2},
		"phase 1":     {"c", string(transcript.SimulatedSingleParty), d2, d2},
		"r1cs":        {"c", string(transcript.SimulatedSingleParty), d1, d1},
	} {
		other, err := transcript.RootChallenge(args[0], transcript.Provenance(args[1]), args[2], args[3])
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(base, other) {
			t.Fatalf("root does not bind the %s", name)
		}
	}
	_, err = transcript.RootChallenge("c", transcript.SimulatedSingleParty, "AB", d2)
	wantCode(t, err, failure.TranscriptFormat)
}

func TestProvenanceRules(t *testing.T) {
	for _, bad := range []string{"", "multi-party", "Simulated-Single-Party", "permissionless-multi-party "} {
		_, err := transcript.ParseProvenance(bad)
		wantCode(t, err, failure.ProvenanceInvalid)
	}
	if !transcript.SimulatedSingleParty.ZeroValueOnly() || transcript.PermissionlessMultiParty.ZeroValueOnly() {
		t.Fatal("zero-value rule inverted")
	}
	local := transcript.Contributor{ID: "a", Kind: transcript.KindAutomatedLocal}
	remote := transcript.Contributor{ID: "a", Kind: transcript.KindRemote}
	if err := transcript.CheckContributor(transcript.SimulatedSingleParty, local); err != nil {
		t.Fatal(err)
	}
	if err := transcript.CheckContributor(transcript.PermissionlessMultiParty, remote); err != nil {
		t.Fatal(err)
	}
	wantCode(t, transcript.CheckContributor(transcript.PermissionlessMultiParty, local), failure.ProvenanceConflict)
	wantCode(t, transcript.CheckContributor(transcript.SimulatedSingleParty, transcript.Contributor{Kind: transcript.KindRemote}), failure.ProvenanceConflict)
	wantCode(t, transcript.CheckContributor(transcript.SimulatedSingleParty, transcript.Contributor{ID: "x", Kind: "human"}), failure.ProvenanceConflict)
}

// initial builds an initialized phase-2 state for a test circuit on toy
// phase-1 parameters.
func initial(t *testing.T, name string, size int) (*mpcsetup.Phase2, []byte) {
	t.Helper()
	r, err := testcircuits.Compile(name, size)
	if err != nil {
		t.Fatal(err)
	}
	domain := transcript.DomainSize(r)
	power := uint32(0)
	for 1<<power < domain {
		power++
	}
	commons := ptau.ToyCommons(power, 7, 11, 13)
	root, _ := transcript.RootChallenge("c", transcript.SimulatedSingleParty, d1, d2)
	p, b, _, err := transcript.InitialState(r, commons, root)
	if err != nil {
		t.Fatal(err)
	}
	return p, b
}

// The shape guard's layout model must agree with gnark's real serialization,
// with and without commitments; otherwise it would refuse honest states or
// guard the wrong bytes.
func TestShapeModelMatchesGnark(t *testing.T) {
	for _, c := range []struct {
		name string
		size int
		k    int
	}{{"cubic", 5, 0}, {"chain", 40, 0}, {"committed", 3, 1}} {
		p, b := initial(t, c.name, c.size)
		if len(p.Parameters.G2.Sigma) != c.k {
			t.Fatalf("%s: %d commitments, want %d", c.name, len(p.Parameters.G2.Sigma), c.k)
		}
		if err := transcript.CheckShape(p, b, b); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		// The prefixes hold the lengths gnark wrote.
		if got := binary.BigEndian.Uint16(b[0:2]); int(got) != c.k {
			t.Fatalf("%s: commitment count prefix %d", c.name, got)
		}
		if got := binary.BigEndian.Uint32(b[34:38]); int(got) != len(p.Parameters.G1.PKK) {
			t.Fatalf("%s: PKK prefix %d, want %d", c.name, got, len(p.Parameters.G1.PKK))
		}
		// Every contribution keeps the shape.
		q, _ := transcript.DecodeState(b)
		q.Contribute()
		nb, _ := transcript.StateBytes(q)
		if err := transcript.CheckShape(p, b, nb); err != nil {
			t.Fatalf("%s: contribution changed shape: %v", c.name, err)
		}
	}
}

func TestCheckShapeRefusesPrefixAndLengthChanges(t *testing.T) {
	p, b := initial(t, "committed", 3)
	bad := append([]byte(nil), b...)
	bad[37] ^= 0x01 // PKK length prefix
	wantCode(t, transcript.CheckShape(p, b, bad), failure.ContributionShape)
	bad = append([]byte(nil), b...)
	bad[1] ^= 0x01 // commitment count
	wantCode(t, transcript.CheckShape(p, b, bad), failure.ContributionShape)
	wantCode(t, transcript.CheckShape(p, b, append(append([]byte(nil), b...), 0)), failure.ContributionShape)
}

func TestDecodeStateIsStrict(t *testing.T) {
	_, b := initial(t, "cubic", 5)
	if _, err := transcript.DecodeState(b); err != nil {
		t.Fatal(err)
	}
	_, err := transcript.DecodeState(append(append([]byte(nil), b...), 0))
	wantCode(t, err, failure.ContributionDecode)
	// δ₁ with x ≥ p under the compressed-point flag: not a field element.
	// (A random byte flip is not enough: on G1, cofactor 1, about half of all
	// x values decode to some valid point.)
	bad := append([]byte(nil), b...)
	for i := 2; i < 34; i++ {
		bad[i] = 0xff
	}
	bad[2] = 0xbf
	_, err = transcript.DecodeState(bad)
	wantCode(t, err, failure.ContributionDecode)
}

func TestMessageFraming(t *testing.T) {
	state := []byte("state bytes")
	h := transcript.MessageHeader{Type: transcript.MessageChallenge, Format: transcript.Format, CeremonyID: "c",
		Provenance: transcript.SimulatedSingleParty, Index: 1, StateSHA256: transcript.Digest(state), StateLength: int64(len(state))}
	msg, err := transcript.EncodeMessage(h, state)
	if err != nil {
		t.Fatal(err)
	}
	gh, gs, err := transcript.DecodeMessage(msg)
	if err != nil || gh != h || !bytes.Equal(gs, state) {
		t.Fatalf("round trip: %v", err)
	}
	tampered := append([]byte(nil), msg...)
	tampered[len(tampered)-1] ^= 1
	_, _, err = transcript.DecodeMessage(tampered)
	wantCode(t, err, failure.MessageDigestMismatch)
	_, _, err = transcript.DecodeMessage(msg[:len(msg)-1])
	wantCode(t, err, failure.MessageMalformed)
	_, _, err = transcript.DecodeMessage([]byte("garbage"))
	wantCode(t, err, failure.MessageMalformed)
}

// trailing lists what may and may not follow a JSON document. json.Decoder's
// More reports false for a stray closing bracket, so "}" and "]" are here on
// purpose.
var trailing = []struct {
	name   string
	suffix string
	ok     bool
}{
	{"nothing", "", true},
	{"whitespace", " \n\t\r\n", true},
	{"second object", "{}\n", false},
	{"second object, no newline", "{}", false},
	{"stray brace", "}\n", false},
	{"stray bracket", "]", false},
	{"number", "1", false},
	{"garbage", "x", false},
	{"object after whitespace", "\n\n{\"format\":\"x\"}\n", false},
}

func TestLoadKeyMetadataRejectsTrailingData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, transcript.KeyMetadataFile)
	want := transcript.KeyMetadata{Format: transcript.KeyMetadataFormat, CeremonyID: "c", Provenance: transcript.SimulatedSingleParty}
	if err := transcript.WriteJSON(path, &want); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	for _, c := range trailing {
		os.WriteFile(path, append(append([]byte(nil), b...), c.suffix...), 0o644)
		m, err := transcript.LoadKeyMetadata(path)
		if c.ok {
			if err != nil || *m != want {
				t.Fatalf("%s: %+v %v", c.name, m, err)
			}
			continue
		}
		if m != nil {
			t.Fatalf("%s: returned %+v", c.name, m)
		}
		wantCode(t, err, failure.KeyMetadataMalformed)
	}
	os.WriteFile(path, []byte(`{"format":"x","extra":1}`), 0o644)
	_, err := transcript.LoadKeyMetadata(path)
	wantCode(t, err, failure.KeyMetadataMalformed)
}

func TestLoadTranscriptRejectsTrailingData(t *testing.T) {
	path := filepath.Join(t.TempDir(), transcript.TranscriptFile)
	if err := transcript.WriteJSON(path, &transcript.Transcript{Format: transcript.Format, CeremonyID: "c"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	for _, c := range trailing {
		os.WriteFile(path, append(append([]byte(nil), b...), c.suffix...), 0o644)
		tr, err := transcript.Load(path)
		if c.ok {
			if err != nil || tr.CeremonyID != "c" {
				t.Fatalf("%s: %v", c.name, err)
			}
			continue
		}
		wantCode(t, err, failure.TranscriptFormat)
	}
}

func TestMessageHeaderRejectsTrailingData(t *testing.T) {
	state := []byte("state bytes")
	h := transcript.MessageHeader{Type: transcript.MessageChallenge, Format: transcript.Format, CeremonyID: "c",
		Provenance: transcript.SimulatedSingleParty, Index: 1, StateSHA256: transcript.Digest(state), StateLength: int64(len(state))}
	msg, err := transcript.EncodeMessage(h, state)
	if err != nil {
		t.Fatal(err)
	}
	n := binary.LittleEndian.Uint32(msg[8:12])
	header := msg[12 : 12+n]
	for _, c := range trailing {
		hb := append(append([]byte(nil), header...), c.suffix...)
		framed := append(append([]byte(nil), msg[:8]...), binary.LittleEndian.AppendUint32(nil, uint32(len(hb)))...)
		framed = append(append(framed, hb...), state...)
		gh, _, err := transcript.DecodeMessage(framed)
		if c.ok {
			if err != nil || gh != h {
				t.Fatalf("%s: %v", c.name, err)
			}
			continue
		}
		wantCode(t, err, failure.MessageMalformed)
	}
}
