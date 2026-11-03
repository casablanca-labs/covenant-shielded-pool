// Package ptau reads snarkjs-format Powers of Tau files (.ptau) on BN254
// into gnark v0.16's phase-1 form, mpcsetup.SrsCommons, with a whole-file
// digest pin.
//
// File layout (snarkjs powersoftau_new.js and binfileutils; all integers
// little-endian):
//
//	"ptau" | u32 version | u32 nSections
//	repeated: u32 type | u64 size | body
//	  1 header      u32 n8 (=32) | n8-byte prime q | u32 power | u32 ceremonyPower
//	  2 tauG1       (2^power·2 − 1) G1 points
//	  3 tauG2       2^power G2 points
//	  4 alphaTauG1  2^power G1 points
//	  5 betaTauG1   2^power G1 points
//	  6 betaG2      1 G2 point
//	  7 contributions; 12–15 Lagrange bases in "prepared" files (not read, but hashed)
//
// A point is affine and uncompressed. Each base-field coordinate is n8 bytes,
// little-endian, in Montgomery form with R = 2^256 — the same internal form
// as gnark-crypto's fp.Element, so the four 64-bit limbs load directly. A G2
// coordinate is (c0, c1), matching gnark's E2{A0, A1}.
//
// The format knowledge comes from snarkjs (GPL-3.0) and
// worldcoin/ptau-deserializer (MIT); no code is taken from either.
package ptau

import (
	"encoding/binary"
	"runtime"
	"strconv"
	"sync"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
)

const (
	fileMagic   = "ptau"
	fileVersion = 1

	secHeader     = 1
	secTauG1      = 2
	secTauG2      = 3
	secAlphaTauG1 = 4
	secBetaTauG1  = 5
	secBetaG2     = 6
	secContribs   = 7

	n8     = 32
	g1Size = 2 * n8
	g2Size = 4 * n8

	// MaxPower is the largest power any published BN254 .ptau file carries.
	MaxPower = 28
)

var modulusLimbs = func() [4]uint64 {
	var be [32]byte
	fp.Modulus().FillBytes(be[:])
	var l [4]uint64
	for i := 0; i < 4; i++ {
		l[i] = binary.BigEndian.Uint64(be[32-8*(i+1) : 32-8*i])
	}
	return l
}()

// modulusLE is the BN254 base-field prime as 32 little-endian bytes, the form
// the header section stores it in.
var modulusLE = func() [32]byte {
	var le [32]byte
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(le[8*i:], modulusLimbs[i])
	}
	return le
}()

// loadFp loads a Montgomery-form coordinate and reports whether it is
// canonical (strictly below the modulus).
func loadFp(b []byte) (fp.Element, bool) {
	var e fp.Element
	for i := 0; i < 4; i++ {
		e[i] = binary.LittleEndian.Uint64(b[8*i:])
	}
	for i := 3; i >= 0; i-- {
		if e[i] != modulusLimbs[i] {
			return e, e[i] < modulusLimbs[i]
		}
	}
	return e, false
}

func storeFp(b []byte, e *fp.Element) {
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(b[8*i:], e[i])
	}
}

// decodeG1 decodes one point and refuses a non-canonical coordinate, the
// point at infinity (a powers-of-tau vector never holds it) and a point off
// the curve. G1 of BN254 has cofactor 1, so on-curve is in-subgroup.
func decodeG1(b []byte) (curve.G1Affine, error) {
	var p curve.G1Affine
	var okX, okY bool
	p.X, okX = loadFp(b[0:32])
	p.Y, okY = loadFp(b[32:64])
	if !okX || !okY {
		return p, failure.New(failure.Phase1PointInvalid, "G1 coordinate not canonical")
	}
	if p.IsInfinity() {
		return p, failure.New(failure.Phase1PointInvalid, "G1 point at infinity")
	}
	if !p.IsOnCurve() {
		return p, failure.New(failure.Phase1PointInvalid, "G1 point not on curve")
	}
	return p, nil
}

// decodeG2 decodes one point and refuses a non-canonical coordinate, the
// point at infinity, and a point off the curve or outside the prime-order
// subgroup.
func decodeG2(b []byte) (curve.G2Affine, error) {
	var p curve.G2Affine
	var ok [4]bool
	p.X.A0, ok[0] = loadFp(b[0:32])
	p.X.A1, ok[1] = loadFp(b[32:64])
	p.Y.A0, ok[2] = loadFp(b[64:96])
	p.Y.A1, ok[3] = loadFp(b[96:128])
	if !ok[0] || !ok[1] || !ok[2] || !ok[3] {
		return p, failure.New(failure.Phase1PointInvalid, "G2 coordinate not canonical")
	}
	if p.IsInfinity() {
		return p, failure.New(failure.Phase1PointInvalid, "G2 point at infinity")
	}
	if !p.IsOnCurve() || !p.IsInSubGroup() {
		return p, failure.New(failure.Phase1PointInvalid, "G2 point not in the prime-order subgroup")
	}
	return p, nil
}

func encodeG1(b []byte, p *curve.G1Affine) {
	storeFp(b[0:32], &p.X)
	storeFp(b[32:64], &p.Y)
}

func encodeG2(b []byte, p *curve.G2Affine) {
	storeFp(b[0:32], &p.X.A0)
	storeFp(b[32:64], &p.X.A1)
	storeFp(b[64:96], &p.Y.A0)
	storeFp(b[96:128], &p.Y.A1)
}

// parallel runs f over [0, n) in contiguous chunks and returns the error of
// the lowest failing chunk.
func parallel(n int, f func(start, end int) error) error {
	workers := runtime.GOMAXPROCS(0)
	if workers > n {
		workers = n
	}
	if workers <= 1 {
		return f(0, n)
	}
	errs := make([]error, workers)
	var wg sync.WaitGroup
	per := (n + workers - 1) / workers
	for w := 0; w < workers; w++ {
		start, end := w*per, min((w+1)*per, n)
		if start >= end {
			continue
		}
		wg.Add(1)
		go func(w, start, end int) {
			defer wg.Done()
			errs[w] = f(start, end)
		}(w, start, end)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func decodeG1Batch(dst []curve.G1Affine, raw []byte, base int) error {
	return parallel(len(dst), func(start, end int) error {
		for i := start; i < end; i++ {
			p, err := decodeG1(raw[i*g1Size : (i+1)*g1Size])
			if err != nil {
				err.(*failure.Error).Detail += " at index " + strconv.Itoa(base+i)
				return err
			}
			dst[i] = p
		}
		return nil
	})
}

func decodeG2Batch(dst []curve.G2Affine, raw []byte, base int) error {
	return parallel(len(dst), func(start, end int) error {
		for i := start; i < end; i++ {
			p, err := decodeG2(raw[i*g2Size : (i+1)*g2Size])
			if err != nil {
				err.(*failure.Error).Detail += " at index " + strconv.Itoa(base+i)
				return err
			}
			dst[i] = p
		}
		return nil
	})
}
