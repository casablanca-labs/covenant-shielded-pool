package crscheck

import (
	"errors"
	"fmt"
	"slices"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

// Control is a negative control: a deliberate malformation of a loaded key,
// made in memory. Apply returns a function that restores the key exactly.
// A control fires when every check in MustFail failed and, if any of them is
// a zero-knowledge check, the verdict is MALFORMED. The controls on VK_K,
// VK_MATCHES_PK and PHASE1_ALPHA_BETA, which do not decide the verdict, show
// that the release gate's ancillary requirement is live.
type Control struct {
	Name     string   `json:"name"`
	Change   string   `json:"change"`
	MustFail []string `json:"mustFail"`
	apply    func(pk *groth16bn254.ProvingKey, vk *groth16bn254.VerifyingKey) (undo func())
}

// Apply makes the malformation and returns its undo.
func (c Control) Apply(pk *groth16bn254.ProvingKey, vk *groth16bn254.VerifyingKey) func() {
	return c.apply(pk, vk)
}

// Fired reports whether rep shows the control firing, and what failed.
func (c Control) Fired(rep *Report) (bool, string) {
	failed, zk := map[string]bool{}, map[string]bool{}
	var names []string
	for _, r := range rep.Results {
		zk[r.Name] = zk[r.Name] || r.ZK
		if !r.Pass && !failed[r.Name] {
			failed[r.Name] = true
			names = append(names, r.Name)
		}
	}
	needMalformed := false
	for _, m := range c.MustFail {
		if !failed[m] {
			return false, fmt.Sprintf("%s did not fail (verdict %s, failed %v)", m, rep.Verdict, names)
		}
		needMalformed = needMalformed || zk[m]
	}
	if needMalformed && rep.Verdict != VerdictMalformed {
		return false, "verdict " + rep.Verdict
	}
	return true, fmt.Sprintf("verdict %s, failed %v", rep.Verdict, names)
}

// pick is a fixed interior index, chosen without reference to any weight,
// or -1 if every index is avoided (it never loops: ENG-447 found a commitment
// whose only committed wire is mask-shaped made the old loop spin forever).
func pick(n int, avoid []int) int {
	if n == 0 {
		return -1
	}
	i := (n * 3) / 7
	for range n {
		if !slices.Contains(avoid, i) {
			return i
		}
		i = (i + 1) % n
	}
	return -1
}

// Controls returns the standard negative controls for a key checked with
// plan p. The first four are the ones ARCH-238 requires.
func (p *Plan) Controls(pk *groth16bn254.ProvingKey) ([]Control, error) {
	if len(pk.G1.Z) == 0 || len(pk.G1.K) == 0 || len(pk.G1.A) == 0 || len(pk.G2.B) == 0 || len(pk.G1.B) == 0 || len(p.l.vkWires) == 0 {
		return nil, errors.New("key vectors too short for the controls")
	}
	_, _, g1, g2 := curve.Generators()
	addG1 := func(v *curve.G1Affine) func() {
		old := *v
		v.Add(v, &g1)
		return func() { *v = old }
	}
	addG2 := func(v *curve.G2Affine) func() {
		old := *v
		v.Add(v, &g2)
		return func() { *v = old }
	}
	zi, ki, ai, bi := pick(len(pk.G1.Z), nil), pick(len(pk.G1.K), nil), pick(len(pk.G1.A), nil), pick(len(pk.G2.B), nil)
	vi := pick(len(p.l.vkWires), nil)
	cs := []Control{
		{
			Name: "delta-zeroed", Change: "[δ]₁ and [δ]₂ set to O in the proving key and the verifying key",
			MustFail: []string{CheckNonZero},
			apply: func(pk *groth16bn254.ProvingKey, vk *groth16bn254.VerifyingKey) func() {
				o1, o2, v1, v2 := pk.G1.Delta, pk.G2.Delta, vk.G1.Delta, vk.G2.Delta
				pk.G1.Delta.SetInfinity()
				pk.G2.Delta.SetInfinity()
				vk.G1.Delta.SetInfinity()
				vk.G2.Delta.SetInfinity()
				return func() { pk.G1.Delta, pk.G2.Delta, vk.G1.Delta, vk.G2.Delta = o1, o2, v1, v2 }
			},
		},
		{
			Name: "z-element-perturbed", Change: fmt.Sprintf("Z[%d] += g₁", zi), MustFail: []string{CheckZQuery},
			apply: func(pk *groth16bn254.ProvingKey, _ *groth16bn254.VerifyingKey) func() { return addG1(&pk.G1.Z[zi]) },
		},
		{
			Name: "k-element-perturbed", Change: fmt.Sprintf("K[%d] += g₁", ki), MustFail: []string{CheckKQuery},
			apply: func(pk *groth16bn254.ProvingKey, _ *groth16bn254.VerifyingKey) func() { return addG1(&pk.G1.K[ki]) },
		},
	}
	if len(pk.CommitmentKeys) > 0 && len(pk.CommitmentKeys[0].Basis) > 0 && len(p.Masks) > 0 {
		// With no committed wire besides the mask candidates there is nothing
		// to perturb: the controls on the basis and σ are then absent, and the
		// release gate refuses a key whose checks no control targets.
		if ci := pick(len(pk.CommitmentKeys[0].Basis), p.Masks[0]); ci >= 0 {
			cs = append(cs, Control{
				Name: "commitment-basis-perturbed", Change: fmt.Sprintf("commitment 0 Basis[%d] += g₁ (not the mask)", ci),
				MustFail: []string{CheckCommitBase},
				apply: func(pk *groth16bn254.ProvingKey, _ *groth16bn254.VerifyingKey) func() {
					return addG1(&pk.CommitmentKeys[0].Basis[ci])
				},
			}, Control{
				Name: "commitment-sigma-perturbed", Change: fmt.Sprintf("commitment 0 BasisExpSigma[%d] += g₁", ci),
				MustFail: []string{CheckCommitSig},
				apply: func(pk *groth16bn254.ProvingKey, _ *groth16bn254.VerifyingKey) func() {
					return addG1(&pk.CommitmentKeys[0].BasisExpSigma[ci])
				},
			})
		}
		if len(p.Masks[0]) > 0 {
			mi := p.Masks[0][0]
			cs = append(cs, Control{
				Name:     "commitment-mask-zeroed",
				Change:   fmt.Sprintf("commitment 0 Basis[%d] and BasisExpSigma[%d] (the mask) set to O, σ-consistent", mi, mi),
				MustFail: []string{CheckCommitMask},
				apply: func(pk *groth16bn254.ProvingKey, _ *groth16bn254.VerifyingKey) func() {
					ck := &pk.CommitmentKeys[0]
					ob, oe := ck.Basis[mi], ck.BasisExpSigma[mi]
					ck.Basis[mi].SetInfinity()
					ck.BasisExpSigma[mi].SetInfinity()
					return func() { ck.Basis[mi], ck.BasisExpSigma[mi] = ob, oe }
				},
			})
		}
	}
	cs = append(cs,
		Control{
			Name: "a-element-perturbed", Change: fmt.Sprintf("A[%d] += g₁", ai), MustFail: []string{CheckAQuery},
			apply: func(pk *groth16bn254.ProvingKey, _ *groth16bn254.VerifyingKey) func() { return addG1(&pk.G1.A[ai]) },
		},
		Control{
			Name: "b1-element-perturbed", Change: fmt.Sprintf("B₁[%d] += g₁", bi), MustFail: []string{CheckBQueryG1},
			apply: func(pk *groth16bn254.ProvingKey, _ *groth16bn254.VerifyingKey) func() { return addG1(&pk.G1.B[bi]) },
		},
		Control{
			Name: "b2-element-perturbed", Change: fmt.Sprintf("B₂[%d] += g₂", bi), MustFail: []string{CheckBQueryG2},
			apply: func(pk *groth16bn254.ProvingKey, _ *groth16bn254.VerifyingKey) func() { return addG2(&pk.G2.B[bi]) },
		},
		Control{
			Name: "beta-g2-perturbed", Change: "[β]₂ += g₂ in the proving key", MustFail: []string{CheckBeta},
			apply: func(pk *groth16bn254.ProvingKey, _ *groth16bn254.VerifyingKey) func() { return addG2(&pk.G2.Beta) },
		},
		Control{
			Name: "domain-generator-perturbed", Change: "pk.Domain.Generator squared", MustFail: []string{CheckDomain},
			apply: func(pk *groth16bn254.ProvingKey, _ *groth16bn254.VerifyingKey) func() {
				old := pk.Domain.Generator
				var sq fr.Element
				sq.Square(&old)
				pk.Domain.Generator = sq
				return func() { pk.Domain.Generator = old }
			},
		},
		// Ancillary: soundness, completeness and provenance (REV-195 H3).
		Control{
			Name: "vk-k-perturbed", Change: fmt.Sprintf("vk.K[%d] += g₁", vi), MustFail: []string{CheckVKK},
			apply: func(_ *groth16bn254.ProvingKey, vk *groth16bn254.VerifyingKey) func() {
				if vi >= len(vk.G1.K) {
					return func() {}
				}
				return addG1(&vk.G1.K[vi])
			},
		},
		Control{
			Name: "vk-alpha-perturbed", Change: "[α]₁ += g₁ in the verifying key", MustFail: []string{CheckVKMatch},
			apply: func(_ *groth16bn254.ProvingKey, vk *groth16bn254.VerifyingKey) func() { return addG1(&vk.G1.Alpha) },
		},
		Control{
			Name: "pk-alpha-not-phase1", Change: "[α]₁ += g₁ in the proving key", MustFail: []string{CheckPhase1},
			apply: func(pk *groth16bn254.ProvingKey, _ *groth16bn254.VerifyingKey) func() { return addG1(&pk.G1.Alpha) },
		},
	)
	return cs, nil
}
