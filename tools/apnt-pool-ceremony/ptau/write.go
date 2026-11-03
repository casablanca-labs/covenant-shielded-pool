package ptau

import (
	"bufio"
	"encoding/binary"
	"io"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
)

// Write serializes c as a .ptau file of power log2(N), with an empty
// contributions section. It exists to build test fixtures; a ceremony's phase
// 1 must come from a pinned public file, never from this writer.
func Write(w io.Writer, c *mpcsetup.SrsCommons) error {
	n := len(c.G2.Tau)
	if n < 2 || n&(n-1) != 0 || len(c.G1.Tau) != 2*n-1 || len(c.G1.AlphaTau) != n || len(c.G1.BetaTau) != n {
		return failure.New(failure.Phase1NotPowersOfTau, "cannot write malformed parameters")
	}
	power := uint32(0)
	for 1<<power < n {
		power++
	}
	bw := bufio.NewWriterSize(w, 1<<20)
	u32 := func(v uint32) { binary.Write(bw, binary.LittleEndian, v) }
	u64 := func(v uint64) { binary.Write(bw, binary.LittleEndian, v) }

	bw.WriteString(fileMagic)
	u32(fileVersion)
	u32(7)

	u32(secHeader)
	u64(4 + n8 + 4 + 4)
	u32(n8)
	bw.Write(modulusLE[:])
	u32(power)
	u32(power)

	g1s := func(typ uint32, ps []curve.G1Affine) {
		u32(typ)
		u64(uint64(len(ps)) * g1Size)
		var b [g1Size]byte
		for i := range ps {
			encodeG1(b[:], &ps[i])
			bw.Write(b[:])
		}
	}
	g2s := func(typ uint32, ps []curve.G2Affine) {
		u32(typ)
		u64(uint64(len(ps)) * g2Size)
		var b [g2Size]byte
		for i := range ps {
			encodeG2(b[:], &ps[i])
			bw.Write(b[:])
		}
	}
	g1s(secTauG1, c.G1.Tau)
	g2s(secTauG2, c.G2.Tau)
	g1s(secAlphaTauG1, c.G1.AlphaTau)
	g1s(secBetaTauG1, c.G1.BetaTau)
	g2s(secBetaG2, []curve.G2Affine{c.G2.Beta})

	u32(secContribs)
	u64(4)
	u32(0)
	if err := bw.Flush(); err != nil {
		return failure.Wrap(failure.IO, err, "writing .ptau")
	}
	return nil
}

// ToyCommons returns powers-of-tau parameters for domain 2^power whose secret
// scalars τ, α, β are the given public constants. They are INSECURE by
// construction — anyone can forge proofs under keys built on them — and exist
// only to make deterministic test fixtures.
func ToyCommons(power uint32, tau, alpha, beta uint64) *mpcsetup.SrsCommons {
	var t, a, b fr.Element
	t.SetUint64(tau)
	a.SetUint64(alpha)
	b.SetUint64(beta)
	return ToyCommonsFr(power, t, a, b)
}

// ToyCommonsFr is ToyCommons with field-element scalars, so a test can pick
// values such as β = −1 or τ a root of unity. INSECURE by construction.
func ToyCommonsFr(power uint32, t, a, b fr.Element) *mpcsetup.SrsCommons {
	n := 1 << power
	pows := make([]fr.Element, 2*n-1)
	pows[0].SetOne()
	for i := 1; i < len(pows); i++ {
		pows[i].Mul(&pows[i-1], &t)
	}
	alphaPows := make([]fr.Element, n)
	betaPows := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		alphaPows[i].Mul(&pows[i], &a)
		betaPows[i].Mul(&pows[i], &b)
	}

	_, _, g1, g2 := curve.Generators()
	var c mpcsetup.SrsCommons
	c.G1.Tau = curve.BatchScalarMultiplicationG1(&g1, pows)
	c.G2.Tau = curve.BatchScalarMultiplicationG2(&g2, pows[:n])
	c.G1.AlphaTau = curve.BatchScalarMultiplicationG1(&g1, alphaPows)
	c.G1.BetaTau = curve.BatchScalarMultiplicationG1(&g1, betaPows)
	c.G2.Beta = curve.BatchScalarMultiplicationG2(&g2, []fr.Element{b})[0]
	return &c
}
