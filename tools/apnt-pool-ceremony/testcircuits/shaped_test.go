package testcircuits_test

import (
	"path/filepath"
	"testing"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/testcircuits"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

// A reference shape with every coefficient class and word size present.
var ref = testcircuits.Shape{
	NbConstraints: 1000, NbInternal: 1250, NbSecret: 7, NbPublic: 3,
	L:             testcircuits.TermCount{One: 1600, MinusOne: 440, Two: 12, Other: 550, OtherWords: [4]int64{540, 4, 2, 4}},
	R:             testcircuits.TermCount{One: 1010, MinusOne: 3, Other: 22, OtherWords: [4]int64{21, 0, 0, 1}},
	O:             testcircuits.TermCount{Zero: 17, One: 998, MinusOne: 2, Other: 94, OtherWords: [4]int64{93, 1, 0, 0}},
	NbCommitments: 1, NbCommitted: 590,
}

// Shaped reproduces the reference's shape scaled to the requested size,
// exactly up to rounding, plus the one constraint that uses each
// commitment's wire, and each commitment's mask: one more internal and
// committed wire, from the Randomize hint, and its constraint. The R1CS
// round-trips through its file.
func TestShapedReproducesTheReferenceShape(t *testing.T) {
	r, err := testcircuits.Shaped(ref, 4000, 7)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "shaped.r1cs")
	if err := testcircuits.WriteR1CS(path, r); err != nil {
		t.Fatal(err)
	}
	back, _, err := transcript.ReadR1CS(path)
	if err != nil {
		t.Fatal(err)
	}
	got := testcircuits.ShapeOf(back)
	scaled := func(c testcircuits.TermCount) testcircuits.TermCount {
		out := testcircuits.TermCount{Zero: 4 * c.Zero, One: 4 * c.One, MinusOne: 4 * c.MinusOne, Two: 4 * c.Two}
		for w := range c.OtherWords {
			out.OtherWords[w] = 4 * c.OtherWords[w]
			out.Other += out.OtherWords[w]
		}
		out.One += 2 // the commitment wire's and the mask's constraints: one term per side each
		return out
	}
	want := testcircuits.Shape{
		NbConstraints: 4002, NbInternal: 5001, NbSecret: 7, NbPublic: 3, NbWires: 5011,
		L: scaled(ref.L), R: scaled(ref.R), O: scaled(ref.O),
		MaxTerms: got.MaxTerms, NbCommitments: 1, NbCommitted: 2361,
	}
	if got != want {
		t.Fatalf("shape\n got %+v\nwant %+v", got, want)
	}
	if got.MaxTerms < 2 {
		t.Fatal("no constraint has more than one term on a side")
	}
}

func TestShapedIsDeterministic(t *testing.T) {
	a, err := testcircuits.Shaped(ref, 500, 3)
	if err != nil {
		t.Fatal(err)
	}
	b, err := testcircuits.Shaped(ref, 500, 3)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pa, pb := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if testcircuits.WriteR1CS(pa, a) != nil || testcircuits.WriteR1CS(pb, b) != nil {
		t.Fatal("write")
	}
	_, da, _ := transcript.ReadR1CS(pa)
	_, db, _ := transcript.ReadR1CS(pb)
	if da != db {
		t.Fatal("the same seed built different R1CS files")
	}
}
