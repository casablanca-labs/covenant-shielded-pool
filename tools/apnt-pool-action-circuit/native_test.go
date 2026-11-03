package poolaction

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

// Test-only native mirror of the few host derivations the circuit-only
// negatives need (they perturb a host vector in ways the host has no input
// for). TestNativeMirrorMatchesHost checks every function here against the
// host's own vectors before any mutation uses it. It is not a second
// canonical implementation.

func nativeSha(tag string, parts ...[]byte) []byte {
	h := sha256.New()
	h.Write([]byte(tag))
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func nativeU64le(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

func nativeNkc(nk []byte) []byte { return nativeSha(tagNkc, nk) }

func nativeOwnerTag(ak33, nk []byte) []byte { return nativeSha(tagOwner, ak33, nativeNkc(nk)) }

func nativeCommitment(v uint64, owner, rho, rcm, tag []byte) []byte {
	return nativeSha(tagCommitment, nativeU64le(v), owner, rho, rcm, tag)
}

func nativeNullifier(nk, rho, cm []byte) []byte { return nativeSha(tagNullifier, nk, rho, cm) }

// nativeRcm is an output's derived rcm, SHA-256(rcm ‖ K ‖ ρ) (pad16).
func nativeRcm(K, rho []byte) []byte { return nativeSha(TagRcm, K, rho) }

// nativePacket is the pad16 packet (u64le(v) ⊕ d[0..8)) ‖ d[8..16), d = SHA-256(pad ‖ K ‖ ρ ‖ cm).
func nativePacket(v uint64, K, rho, cm []byte) []byte {
	d := nativeSha(TagPad, K, rho, cm)
	out := nativeU64le(v)
	for i := range out {
		out[i] ^= d[i]
	}
	return append(out, d[8:16]...)
}

func nativeNode(l, r []byte) []byte { return nativeSha(tagTreeNode, l, r) }

// nativeRoot walks a path; bits[h] = 1 means the running node is the right child.
func nativeRoot(leaf []byte, bits [TreeDepth]uint64, siblings [TreeDepth][]byte) []byte {
	cur := leaf
	for h := 0; h < TreeDepth; h++ {
		if bits[h] == 1 {
			cur = nativeNode(siblings[h], cur)
		} else {
			cur = nativeNode(cur, siblings[h])
		}
	}
	return cur
}

// ---- secp256k1 affine arithmetic over math/big ----

type nativePoint struct{ x, y *big.Int } // nil x means infinity

func modP(v *big.Int) *big.Int { return v.Mod(v, secpP) }

func nativeAdd(a, b nativePoint) nativePoint {
	if a.x == nil {
		return b
	}
	if b.x == nil {
		return a
	}
	var lambda *big.Int
	if a.x.Cmp(b.x) == 0 {
		if new(big.Int).Add(a.y, b.y).Mod(new(big.Int).Add(a.y, b.y), secpP).Sign() == 0 {
			return nativePoint{}
		}
		num := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(a.x, a.x))
		den := new(big.Int).Mul(big.NewInt(2), a.y)
		lambda = modP(num.Mul(num, new(big.Int).ModInverse(modP(den), secpP)))
	} else {
		num := new(big.Int).Sub(b.y, a.y)
		den := modP(new(big.Int).Sub(b.x, a.x))
		lambda = modP(num.Mul(num, new(big.Int).ModInverse(den, secpP)))
	}
	xr := modP(new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Mul(lambda, lambda), a.x), b.x))
	yr := modP(new(big.Int).Sub(new(big.Int).Mul(lambda, new(big.Int).Sub(a.x, xr)), a.y))
	return nativePoint{xr, yr}
}

func nativeMulBase(k *big.Int) nativePoint {
	acc := nativePoint{}
	add := nativePoint{new(big.Int).Set(secpGx), new(big.Int).Set(secpGy)}
	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			acc = nativeAdd(acc, add)
		}
		add = nativeAdd(add, add)
	}
	return acc
}

func nativeSEC1c(p nativePoint) []byte {
	out := make([]byte, 33)
	if p.x == nil {
		out[0] = 0x02
		return out
	}
	out[0] = 0x02 | byte(p.y.Bit(0))
	p.x.FillBytes(out[1:])
	return out
}

func nativeOnCurve(p nativePoint) bool {
	lhs := modP(new(big.Int).Mul(p.y, p.y))
	rhs := modP(new(big.Int).Add(new(big.Int).Exp(p.x, big.NewInt(3), secpP), big.NewInt(7)))
	return lhs.Cmp(rhs) == 0
}

func labelScalar(label string) *big.Int {
	return new(big.Int).Mod(new(big.Int).SetBytes(nativeSha("eng318:", []byte(label))), secpN)
}
