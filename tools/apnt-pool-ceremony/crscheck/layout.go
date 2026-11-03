package crscheck

import (
	"errors"
	"fmt"
	"slices"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
)

// Wire classes, in gnark v0.16.3's Groth16 key layout
// (backend/groth16/bn254/setup.go, Setup): a public wire and a commitment's
// output wire go to vk.G1.K; a private wire committed to by commitment k goes
// to pk.CommitmentKeys[k].Basis; every other private wire goes to pk.G1.K.
const (
	classPrivate uint8 = iota
	classPublic
	classCommitmentWire
	classCommitted // committed private wire; see layout.commitOf
)

// layout is an R1CS's wire classification, the order of every key vector,
// and the constraint that makes each commitment hiding.
type layout struct {
	nbConstraints, nbWires, nbPublic int
	domain                           int

	class    []uint8
	commitOf []int32 // for classCommitted wires: the commitment index

	priv      []int32   // pk.G1.K order
	vkWires   []int32   // vk.G1.K order: public wires, then commitment wires
	committed [][]int32 // pk.CommitmentKeys[k].Basis order

	// masks[k] lists positions in committed[k] of wires w constrained by
	// w·1 = w. gnark's Commit (frontend/cs/r1cs/api.go) adds exactly such a
	// constraint for the random mask it appends to every commitment, so the
	// mask can reach the commitment; the mask is the commitment's only
	// randomness.
	masks [][]int

	publicAndCommitmentCommitted [][]int
}

// Domain is the FFT domain gnark v0.16.3's Groth16 setup uses for r: the
// smallest power of two at least its constraint count, and at least 2.
func Domain(r *cs.R1CS) int {
	n := int(ecc.NextPowerOfTwo(uint64(r.GetNbConstraints())))
	if n < 2 {
		n = 2
	}
	return n
}

func newLayout(r *cs.R1CS) (*layout, error) {
	nbInternal, nbSecret, nbPublic := r.GetNbVariables()
	l := &layout{
		nbConstraints: r.GetNbConstraints(),
		nbWires:       nbInternal + nbSecret + nbPublic,
		nbPublic:      nbPublic,
	}
	l.domain = Domain(r)
	info, ok := r.CommitmentInfo.(constraint.Groth16Commitments)
	if !ok {
		return nil, errors.New("R1CS commitment info is not Groth16")
	}
	l.class = make([]uint8, l.nbWires)
	l.commitOf = make([]int32, l.nbWires)
	for j := 0; j < nbPublic; j++ {
		l.class[j] = classPublic
	}
	cw := slices.Clone(info.CommitmentIndexes())
	slices.Sort(cw)
	for _, j := range cw {
		if j < nbPublic || j >= l.nbWires || l.class[j] != classPrivate {
			return nil, fmt.Errorf("commitment wire %d is out of place", j)
		}
		l.class[j] = classCommitmentWire
	}
	l.committed = make([][]int32, len(info))
	for k, pc := range info.GetPrivateCommitted() {
		if !slices.IsSorted(pc) {
			return nil, fmt.Errorf("commitment %d's committed wires are not sorted", k)
		}
		for _, j := range pc {
			if j < nbPublic || j >= l.nbWires || l.class[j] != classPrivate {
				return nil, fmt.Errorf("committed wire %d of commitment %d is out of place", j, k)
			}
			l.class[j] = classCommitted
			l.commitOf[j] = int32(k)
			l.committed[k] = append(l.committed[k], int32(j))
		}
	}
	for j := 0; j < l.nbWires; j++ {
		switch l.class[j] {
		case classPrivate:
			l.priv = append(l.priv, int32(j))
		case classPublic, classCommitmentWire:
			l.vkWires = append(l.vkWires, int32(j))
		}
	}
	l.masks = make([][]int, len(info))
	l.publicAndCommitmentCommitted = info.GetPublicAndCommitmentCommitted(info.CommitmentIndexes(), nbPublic)
	return l, nil
}

// powers returns 1, x, x², …, x^(n−1).
func powers(x fr.Element, n int) []fr.Element {
	p := make([]fr.Element, n)
	if n == 0 {
		return p
	}
	p[0].SetOne()
	for i := 1; i < n; i++ {
		p[i].Mul(&p[i-1], &x)
	}
	return p
}

// lagrangeSums holds, for per-wire weights ρ, the Lagrange-basis vectors
// (length = domain) whose i-th entry is the ρ-weighted sum of constraint
// i's terms:
//
//	u[i]  = Σ_{t∈Lᵢ} coeff(t)·ρ_wire(t)        (A polynomials)
//	v[i]  = Σ_{t∈Rᵢ} coeff(t)·ρ_wire(t)        (B polynomials)
//	w*[i] = Σ_{t∈Oᵢ, wire(t) in the class} coeff(t)·ρ_wire(t)   (C polynomials)
//
// so that Σᵢ u[i]·Lᵢ(τ) = Σⱼ ρⱼ·uⱼ(τ), with Lᵢ the Lagrange polynomial of ωⁱ.
type lagrangeSums struct {
	u, v, wPriv, wVK []fr.Element
	wComm            [][]fr.Element
}

// accumulate walks the constraints once, filling the sums and l.masks.
func (l *layout) accumulate(r *cs.R1CS, rho []fr.Element) (*lagrangeSums, error) {
	if len(rho) != l.nbWires {
		return nil, errors.New("weights do not cover the wires")
	}
	s := &lagrangeSums{
		u:     make([]fr.Element, l.domain),
		v:     make([]fr.Element, l.domain),
		wPriv: make([]fr.Element, l.domain),
		wVK:   make([]fr.Element, l.domain),
		wComm: make([][]fr.Element, len(l.committed)),
	}
	for k := range s.wComm {
		s.wComm[k] = make([]fr.Element, l.domain)
	}
	for k := range l.masks {
		l.masks[k] = nil
	}
	coeffs := r.Coefficients
	add := func(dst *fr.Element, t constraint.Term) error {
		j := int(t.WireID())
		cid := int(t.CoeffID())
		if j < 0 || j >= l.nbWires || cid >= len(coeffs) {
			return fmt.Errorf("term (wire %d, coefficient %d) out of range", j, cid)
		}
		switch cid {
		case constraint.CoeffIdZero:
		case constraint.CoeffIdOne:
			dst.Add(dst, &rho[j])
		default:
			var m fr.Element
			m.Mul(&coeffs[cid], &rho[j])
			dst.Add(dst, &m)
		}
		return nil
	}
	i := 0
	it := r.GetR1CIterator()
	for c := it.Next(); c != nil; c = it.Next() {
		if i >= l.nbConstraints {
			return nil, errors.New("more constraints than the R1CS reports")
		}
		for _, t := range c.L {
			if err := add(&s.u[i], t); err != nil {
				return nil, err
			}
		}
		for _, t := range c.R {
			if err := add(&s.v[i], t); err != nil {
				return nil, err
			}
		}
		for _, t := range c.O {
			j := int(t.WireID())
			if j < 0 || j >= l.nbWires {
				return nil, fmt.Errorf("term wire %d out of range", j)
			}
			var dst *fr.Element
			switch l.class[j] {
			case classPrivate:
				dst = &s.wPriv[i]
			case classPublic, classCommitmentWire:
				dst = &s.wVK[i]
			default:
				dst = &s.wComm[l.commitOf[j]][i]
			}
			if err := add(dst, t); err != nil {
				return nil, err
			}
		}
		// The mask constraint: L = {w: 1}, R = {one-wire: 1}, O = {w: 1}.
		if len(c.L) == 1 && len(c.R) == 1 && len(c.O) == 1 &&
			c.L[0].WireID() == c.O[0].WireID() && c.R[0].WireID() == 0 &&
			c.L[0].CoeffID() == constraint.CoeffIdOne && c.R[0].CoeffID() == constraint.CoeffIdOne &&
			c.O[0].CoeffID() == constraint.CoeffIdOne && int(c.L[0].WireID()) < l.nbWires &&
			l.class[c.L[0].WireID()] == classCommitted {
			j := int32(c.L[0].WireID())
			k := l.commitOf[j]
			p, _ := slices.BinarySearch(l.committed[k], j)
			l.masks[k] = append(l.masks[k], p)
		}
		i++
	}
	if i != l.nbConstraints {
		return nil, fmt.Errorf("iterated %d constraints, the R1CS reports %d", i, l.nbConstraints)
	}
	for k := range l.masks {
		slices.Sort(l.masks[k])
		l.masks[k] = slices.Compact(l.masks[k])
	}
	return s, nil
}
