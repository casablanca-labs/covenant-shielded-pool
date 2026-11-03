package ptau

import (
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	cryptompc "github.com/consensys/gnark-crypto/ecc/bn254/mpcsetup"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
)

// ValidateCommons checks that c is a well-formed powers-of-tau vector:
//
//   - lengths 2N−1, N, N, N for [τⁱ]₁, [τⁱ]₂, [ατⁱ]₁, [βτⁱ]₁ with N a power of two;
//   - [τ⁰]₁ and [τ⁰]₂ are the generators;
//   - all four vectors are geometric with one common ratio τ — the same
//     SameRatioMany check gnark's Phase1.Verify ends with;
//   - [β]₁ and [β]₂ carry the same β;
//   - τ and β are not degenerate (CheckNonDegenerate).
//
// It does not re-verify the contributions that produced the file; for the
// Perpetual Powers of Tau that is `snarkjs powersoftau verify` against the
// public record, and the whole-file pin binds the result to that record.
func ValidateCommons(c *mpcsetup.SrsCommons) error {
	n := len(c.G2.Tau)
	if n < 2 || n&(n-1) != 0 || len(c.G1.Tau) != 2*n-1 || len(c.G1.AlphaTau) != n || len(c.G1.BetaTau) != n {
		return failure.New(failure.Phase1NotPowersOfTau, "vector lengths %d/%d/%d/%d are not 2N−1/N/N/N",
			len(c.G1.Tau), len(c.G2.Tau), len(c.G1.AlphaTau), len(c.G1.BetaTau))
	}
	_, _, g1, g2 := curve.Generators()
	if !c.G1.Tau[0].Equal(&g1) || !c.G2.Tau[0].Equal(&g2) {
		return failure.New(failure.Phase1NotPowersOfTau, "[τ⁰] is not the generator")
	}
	if c.G1.AlphaTau[0].IsInfinity() || c.G1.BetaTau[0].IsInfinity() || c.G2.Beta.IsInfinity() {
		return failure.New(failure.Phase1NotPowersOfTau, "α or β is zero")
	}
	if !c.G2.Beta.IsOnCurve() || !c.G2.Beta.IsInSubGroup() {
		return failure.New(failure.Phase1NotPowersOfTau, "[β]₂ not in the prime-order subgroup")
	}
	if err := cryptompc.SameRatioMany(c.G1.Tau, c.G2.Tau, c.G1.AlphaTau, c.G1.BetaTau); err != nil {
		return failure.Wrap(failure.Phase1NotPowersOfTau, err, "vectors are not geometric with one common ratio")
	}
	// e([β]₁, g₂) = e(g₁, [β]₂)
	var negG1 curve.G1Affine
	negG1.Neg(&g1)
	ok, err := curve.PairingCheck(
		[]curve.G1Affine{c.G1.BetaTau[0], negG1},
		[]curve.G2Affine{g2, c.G2.Beta})
	if err != nil || !ok {
		return failure.New(failure.Phase1NotPowersOfTau, "[β]₁ and [β]₂ disagree")
	}
	return CheckNonDegenerate(c)
}

// CheckNonDegenerate refuses two values of phase 1 that pass every other check
// here, and every check of the phase-2 chain, yet leave keys built on them
// without zero knowledge (ARCH-238). N is the domain the parameters were
// truncated to, the circuit's.
//
//   - τ a root of unity of the domain, [τᴺ]₁ = [τ⁰]₁ (PHASE1_TAU_IN_DOMAIN).
//     Then t(τ) = τᴺ − 1 = 0: every Z element of the key is O, which breaks
//     soundness as well, and the basis element of the random mask gnark's
//     Commit adds, (β+1)·Lₖ(τ), is O unless τ = ωᵏ for the mask's own
//     constraint k.
//   - β = −1, [β]₁ = −[1]₁ (PHASE1_BETA_MINUS_ONE). The mask's basis element
//     is again O.
//
// With the mask's basis element O, a proof's BSB22 commitment is a fixed
// function of the committed private values, while the proofs still verify.
// Both values lie in phase 1, and γ = 1 in gnark's phase 2, so no phase-2
// contributor can repair them. c must already be a powers-of-tau vector with
// [τ⁰]₁ the generator, as ValidateCommons establishes before calling this.
func CheckNonDegenerate(c *mpcsetup.SrsCommons) error {
	n := len(c.G2.Tau)
	if n < 2 || len(c.G1.Tau) != 2*n-1 || len(c.G1.BetaTau) == 0 {
		return failure.New(failure.Phase1NotPowersOfTau, "vector lengths %d/%d/%d are not 2N−1/N/N",
			len(c.G1.Tau), len(c.G2.Tau), len(c.G1.BetaTau))
	}
	if c.G1.Tau[n].Equal(&c.G1.Tau[0]) {
		return failure.New(failure.Phase1TauInDomain, "[τ^%d]₁ = [τ⁰]₁: τ is a root of unity of the domain, so t(τ) = 0", n)
	}
	_, _, g1, _ := curve.Generators()
	var negG1 curve.G1Affine
	negG1.Neg(&g1)
	if c.G1.BetaTau[0].Equal(&negG1) {
		return failure.New(failure.Phase1BetaMinusOne, "[β]₁ = −[1]₁: β = −1")
	}
	return nil
}
