package pkload

import (
	"unsafe"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
)

func uintptrOf(p *byte) uintptr { return uintptr(unsafe.Pointer(p)) }

func bytePtr[E curve.G1Affine | curve.G2Affine](s []E) *byte {
	return (*byte)(unsafe.Pointer(&s[0]))
}

// alignedCopy is b in a 64-byte-aligned buffer, as ReadVerified returns.
func alignedCopy(b []byte) []byte {
	out := alignedBytes(int64(len(b)))
	copy(out, b)
	return out
}
