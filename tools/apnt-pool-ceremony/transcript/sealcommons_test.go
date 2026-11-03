package transcript_test

import (
	"math/bits"
	"testing"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/testcircuits"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

// Sealing one state with SealCommons gives byte-identical keys to sealing it
// with the full phase-1 parameters, for a circuit with a commitment, and
// SealCommons holds no τ vector.
func TestSealCommonsSealsTheSameKeys(t *testing.T) {
	r, err := testcircuits.Compile("committed", 40)
	if err != nil {
		t.Fatal(err)
	}
	domain := transcript.DomainSize(r)
	commons := ptau.ToyCommons(uint32(bits.TrailingZeros64(domain)), 7, 11, 13)
	root := make([]byte, 32)
	beacon := []byte("a thirty-two byte test beacon!!!")

	// One contributed state; Seal modifies its receiver, so each seal below
	// decodes its own copy, with its own evaluations.
	p, _, _, err := transcript.InitialState(r, commons, root)
	if err != nil {
		t.Fatal(err)
	}
	p.Contribute()
	state, err := transcript.StateBytes(p)
	if err != nil {
		t.Fatal(err)
	}
	seal := func(trim bool) (string, string) {
		t.Helper()
		st, err := transcript.DecodeState(state)
		if err != nil {
			t.Fatal(err)
		}
		_, _, evals, err := transcript.InitialState(r, commons, root)
		if err != nil {
			t.Fatal(err)
		}
		sc := commons
		if trim {
			sc = transcript.SealCommons(commons)
		}
		pk, vk := st.Seal(sc, evals, beacon)
		pkSHA, err := transcript.DigestWriterTo(pk.WriteRawTo)
		if err != nil {
			t.Fatal(err)
		}
		vkSHA, err := transcript.DigestWriterTo(vk.WriteTo)
		if err != nil {
			t.Fatal(err)
		}
		return pkSHA, vkSHA
	}
	fullPK, fullVK := seal(false)
	trimPK, trimVK := seal(true)
	if fullPK != trimPK || fullVK != trimVK {
		t.Fatalf("SealCommons seals other keys: pk %s vs %s, vk %s vs %s", fullPK, trimPK, fullVK, trimVK)
	}
	sc := transcript.SealCommons(commons)
	if sc.G1.Tau != nil || sc.G2.Tau != nil || len(sc.G1.BetaTau) != 1 || uint64(len(sc.G1.AlphaTau)) != domain {
		t.Fatal("SealCommons keeps more than [α]₁ with the domain's length, [β]₁ and [β]₂")
	}
}
