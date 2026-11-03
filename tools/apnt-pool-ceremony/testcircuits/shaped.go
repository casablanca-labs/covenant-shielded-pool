package testcircuits

import (
	"fmt"
	"math/big"
	"math/rand/v2"
	"slices"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

// Shaped builds an R1CS with nbConstraints constraints whose shape per
// constraint is ref's: internal wires, terms per side in each coefficient
// class and coefficient size, commitments and committed wires, all scaled by
// nbConstraints / ref.NbConstraints; public and secret wire counts are
// ref's own. As in a compiled circuit, each commitment's wire appears in one
// more constraint, and each commitment has one more committed wire, its mask:
// the output of gnark's Randomize hint, constrained by w·1 = w. It exists to
// measure phase 2 at sizes below a real circuit's, on the quantities phase 2's
// cost depends on. It is built directly, not
// compiled from a circuit, so it has no witness solver and cannot be proved;
// wire references and coefficient values are pseudo-random from seed.
// Nothing here may be used to set up a circuit that guards value.
func Shaped(ref Shape, nbConstraints int, seed uint64) (*cs.R1CS, error) {
	if ref.NbConstraints < 1 || nbConstraints < 1 || ref.NbPublic < 1 {
		return nil, fmt.Errorf("shaped: need a reference with constraints and the constant wire")
	}
	f := float64(nbConstraints) / float64(ref.NbConstraints)
	scale := func(v int64) int { return int(float64(v)*f + 0.5) }
	nbInternal := max(scale(int64(ref.NbInternal)), nbConstraints+ref.NbCommitments)
	nbCommitted := min(scale(int64(ref.NbCommitted)), nbInternal-ref.NbCommitments+ref.NbSecret)
	rng := rand.New(rand.NewPCG(seed, 0x5eed_c0ffee))

	r := cs.NewR1CS(nbConstraints)
	for i := range ref.NbPublic {
		if i == 0 {
			r.AddPublicVariable("1")
		} else {
			r.AddPublicVariable(fmt.Sprintf("p%d", i))
		}
	}
	for i := range ref.NbSecret {
		r.AddSecretVariable(fmt.Sprintf("s%d", i))
	}
	first := ref.NbPublic + ref.NbSecret // first internal wire
	for range nbInternal {
		r.AddInternalVariable()
	}
	nbWires := first + nbInternal
	// The last NbCommitments internal wires are the commitments' own wires.
	commitWires := make([]int, ref.NbCommitments)
	for i := range commitWires {
		commitWires[i] = nbWires - ref.NbCommitments + i
	}

	// Coefficient pools: 256 distinct values per 64-bit-word class w, each
	// with 64w+1..64(w+1) bits (at least 3, so never 0, 1 or 2; at most 253,
	// below r/2), half of them negated, so the smaller of c and r−c is in
	// class w.
	var pools [4][]uint32
	mod := fr.Modulus()
	cid := func(v *big.Int) uint32 { return r.MakeTerm(r.FromInterface(v), 0).CID }
	for w := range pools {
		lo, hi := max(3, 64*w+1), min(64*(w+1), mod.BitLen()-1)
		for range 256 {
			bits := lo + rng.IntN(hi-lo+1)
			v := new(big.Int)
			for v.BitLen() < bits { // each word has its top bit set
				v.Lsh(v, 64).Or(v, new(big.Int).SetUint64(rng.Uint64()|1<<63))
			}
			v.Rsh(v, uint(v.BitLen()-bits))
			if rng.IntN(2) == 1 {
				v.Sub(mod, v)
			}
			pools[w] = append(pools[w], cid(v))
		}
	}
	cidZero, cidOne, cidTwo, cidMinusOne := cid(big.NewInt(0)), cid(big.NewInt(1)), cid(big.NewInt(2)), cid(big.NewInt(-1))

	// For each side, the scaled multiset of coefficient ids, shuffled; the
	// first nbConstraints go one per constraint, the rest to random ones.
	side := func(c TermCount) ([]uint32, []int32) {
		var cids []uint32
		add := func(n int, pick func() uint32) {
			for range n {
				cids = append(cids, pick())
			}
		}
		add(scale(c.Zero), func() uint32 { return cidZero })
		add(scale(c.One), func() uint32 { return cidOne })
		add(scale(c.MinusOne), func() uint32 { return cidMinusOne })
		add(scale(c.Two), func() uint32 { return cidTwo })
		for w := range 4 {
			add(scale(c.OtherWords[w]), func() uint32 { return pools[w][rng.IntN(len(pools[w]))] })
		}
		for len(cids) < nbConstraints {
			cids = append(cids, cidOne)
		}
		rng.Shuffle(len(cids), func(i, j int) { cids[i], cids[j] = cids[j], cids[i] })
		owner := make([]int32, len(cids))
		for i := range owner {
			if i < nbConstraints {
				owner[i] = int32(i)
			} else {
				owner[i] = int32(rng.IntN(nbConstraints))
			}
		}
		return cids, owner
	}
	group := func(cids []uint32, owner []int32) [][]uint32 {
		out := make([][]uint32, nbConstraints)
		for i, o := range owner {
			out[o] = append(out[o], cids[i])
		}
		return out
	}
	L, R, O := group(side(ref.L)), group(side(ref.R)), group(side(ref.O))

	// Wire references: mostly recent wires, some earlier internal wires,
	// some inputs, and the internal wires no constraint outputs (as hint
	// outputs are in a compiled circuit). Constraint i outputs wire first+i.
	extra := first + nbConstraints
	wire := func(i int) uint32 {
		switch p := rng.IntN(10); {
		case p < 5 && i > 0:
			return uint32(first + max(0, i-1-rng.IntN(64)))
		case p < 8 && i > 0:
			return uint32(first + rng.IntN(i))
		case p < 9 && extra < nbWires-ref.NbCommitments:
			return uint32(extra + rng.IntN(nbWires-ref.NbCommitments-extra))
		default:
			return uint32(rng.IntN(first))
		}
	}
	bid := r.AddBlueprint(&constraint.BlueprintGenericR1C{})
	// gnark's instruction tree refuses a wire no earlier constraint set that
	// appears twice in one constraint, so wires within a constraint are
	// distinct.
	used := map[uint32]bool{}
	distinct := func(i int) uint32 {
		for {
			if w := wire(i); !used[w] {
				used[w] = true
				return w
			}
		}
	}
	for i := range nbConstraints {
		clear(used)
		used[uint32(first+i)] = true // the output, placed first in O
		var c constraint.R1C
		for _, id := range L[i] {
			c.L = append(c.L, constraint.Term{CID: id, VID: distinct(i)})
		}
		for _, id := range R[i] {
			c.R = append(c.R, constraint.Term{CID: id, VID: distinct(i)})
		}
		for k, id := range O[i] {
			w := uint32(first + i)
			if k > 0 {
				w = distinct(i)
			}
			c.O = append(c.O, constraint.Term{CID: id, VID: w})
		}
		r.AddR1C(c, bid)
		L[i], R[i], O[i] = nil, nil, nil
	}
	// The commitment wires appear in one constraint each, as in a compiled
	// circuit, where a commitment is used to derive challenges.
	for _, cw := range commitWires {
		r.AddR1C(constraint.R1C{
			L: constraint.LinearExpression{{CID: cidOne, VID: uint32(cw)}},
			R: constraint.LinearExpression{{CID: cidOne, VID: 0}},
			O: constraint.LinearExpression{{CID: cidOne, VID: uint32(first)}},
		}, bid)
	}

	// Committed wires: a pseudo-random set of secret and internal wires,
	// excluding the commitment wires, split across the commitments.
	if ref.NbCommitments > 0 {
		candidates := nbWires - ref.NbCommitments - ref.NbPublic
		pick := rng.Perm(candidates)[:nbCommitted]
		for i := range pick {
			pick[i] += ref.NbPublic
		}
		per := (nbCommitted + ref.NbCommitments - 1) / ref.NbCommitments
		randomize := solver.GetRegisteredHint(transcript.RandomizeHintID)
		if randomize == nil {
			return nil, fmt.Errorf("shaped: gnark registers no hint under the Randomize id")
		}
		for k, cw := range commitWires {
			chunk := pick[min(k*per, len(pick)):min((k+1)*per, len(pick))]
			committed := slices.Clone(chunk)
			slices.Sort(committed)
			// As gnark's Commit does: a mask from the Randomize hint, with
			// no input, committed last, and the constraint mask·1 = mask.
			// The ceremony verifier refuses a commitment without such a
			// mask (COMMITMENT_MASK_MISSING, COMMITMENT_MASK_NOT_RANDOMIZED).
			out, err := r.AddSolverHint(randomize, transcript.RandomizeHintID, nil, 1)
			if err != nil {
				return nil, err
			}
			mask := out[0]
			committed = append(committed, mask)
			if err := r.AddCommitment(constraint.Groth16Commitment{
				PublicAndCommitmentCommitted: []int{},
				PrivateCommitted:             committed,
				CommitmentIndex:              cw,
			}); err != nil {
				return nil, err
			}
			r.AddR1C(constraint.R1C{
				L: constraint.LinearExpression{{CID: cidOne, VID: uint32(mask)}},
				R: constraint.LinearExpression{{CID: cidOne, VID: 0}},
				O: constraint.LinearExpression{{CID: cidOne, VID: uint32(mask)}},
			}, bid)
		}
	}
	return r, nil
}
