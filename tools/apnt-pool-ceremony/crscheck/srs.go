// Package crscheck is a RESEARCH PROTOTYPE (ARCH-238, run R-393), reviewed
// as a research basis by REV-195; package release (ENG-441) is the release
// gate built on it. It checks that a gnark v0.16.3 Groth16 BN254 proving
// key, with its verifying key, is a well-formed CRS for an R1CS and a phase-1
// powers-of-τ file: the conditions under which the prover's proofs are
// zero knowledge even if whoever made the key was malicious (Fuchsbauer,
// ePrint 2017/587, section 6, "CRS verification"), extended to gnark's BSB22
// Pedersen commitment. It does not use gnark's mpcsetup package: the checks
// are pairing and multi-scalar equations with random linear combinations,
// written from the definitions, so a defect in the ceremony code the
// verifier shares with the coordinator is not shared with this check.
//
// It is not the ceremony verifier and does not replace it. It guards prover
// privacy only; a key that passes can still be forgeable by whoever holds
// its trapdoor (soundness is the ceremony's 1-of-N assumption, not this).
package crscheck

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"runtime"
	"sync"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
)

// SRS is the part of phase 1 the check needs: [τ⁰]₁ … [τ^(2N−2)]₁ for the
// FFT domain N, and [τ]₂. Alpha1, Beta1 and Beta2 are phase 1's [α]₁, [β]₁
// and [β]₂; the check only reports whether the key's α and β equal them,
// which zero knowledge does not need.
type SRS struct {
	N      int
	TauG1  []curve.G1Affine // 2N−1 points
	Tau2   curve.G2Affine   // [τ]₂
	Alpha1 curve.G1Affine
	Beta1  curve.G1Affine
	Beta2  curve.G2Affine
	// Set by ReadPtau.
	Power      uint32
	FileSHA256 string
}

// ErrDigestMismatch is ReadPtau's refusal of a file that does not hash to
// the pin, before anything in it is parsed, or that changes while it is.
var ErrDigestMismatch = errors.New("digest mismatch")

// .ptau layout (snarkjs; documented in ../ptau/points.go, which this reader
// follows but does not import, so it can read only what it needs):
//
//	"ptau" | u32 version (1) | u32 nSections
//	repeated: u32 type | u64 size | body
//	  1 header   u32 n8 (32) | 32-byte prime | u32 power | [u32 ceremonyPower]
//	  2 tauG1 (2·2^power − 1 points)   3 tauG2 (2^power)
//	  4 alphaTauG1 (2^power)           5 betaTauG1 (2^power)   6 betaG2 (1)
//
// Points are affine, uncompressed; each coordinate is 32 bytes little-endian
// Montgomery form (gnark-crypto's fp.Element limbs).
const (
	g1Size = 64
	g2Size = 128
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

func decodeG1(b []byte) (curve.G1Affine, error) {
	var p curve.G1Affine
	var okX, okY bool
	p.X, okX = loadFp(b[0:32])
	p.Y, okY = loadFp(b[32:64])
	switch {
	case !okX || !okY:
		return p, errors.New("G1 coordinate not canonical")
	case p.IsInfinity():
		return p, errors.New("G1 point at infinity")
	case !p.IsOnCurve(): // cofactor 1: on the curve is in the group
		return p, errors.New("G1 point not on the curve")
	}
	return p, nil
}

func decodeG2(b []byte) (curve.G2Affine, error) {
	var p curve.G2Affine
	var ok [4]bool
	p.X.A0, ok[0] = loadFp(b[0:32])
	p.X.A1, ok[1] = loadFp(b[32:64])
	p.Y.A0, ok[2] = loadFp(b[64:96])
	p.Y.A1, ok[3] = loadFp(b[96:128])
	switch {
	case !ok[0] || !ok[1] || !ok[2] || !ok[3]:
		return p, errors.New("G2 coordinate not canonical")
	case p.IsInfinity():
		return p, errors.New("G2 point at infinity")
	case !p.IsOnCurve() || !p.IsInSubGroup():
		return p, errors.New("G2 point not in the prime-order subgroup")
	}
	return p, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, bufio.NewReaderSize(f, 1<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type reader struct {
	r   *bufio.Reader
	h   hash.Hash
	buf []byte
}

func (r *reader) full(n int) ([]byte, error) {
	if cap(r.buf) < n {
		r.buf = make([]byte, n)
	}
	b := r.buf[:n]
	_, err := io.ReadFull(r.r, b)
	return b, err
}

func (r *reader) u32() (uint32, error) {
	b, err := r.full(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (r *reader) u64() (uint64, error) {
	b, err := r.full(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

func (r *reader) skip(n uint64) error {
	_, err := io.CopyN(io.Discard, r.r, int64(n))
	return err
}

// ReadPtau reads the SRS for FFT domain n from a .ptau file. The whole file
// is hashed and compared with wantSHA256 before anything in it is parsed,
// then parsed while hashed again, and refused if the second digest differs,
// so the returned points come from bytes that hash to the pin. Every point
// read is canonical, not infinity, on the curve, and (G2) in the subgroup.
// Only [τⁱ]₁ for i < 2n−1, [τ⁰]₂, [τ]₂, [α]₁, [β]₁ and [β]₂ are decoded.
func ReadPtau(path, wantSHA256 string, n int) (*SRS, error) {
	if n < 2 || n&(n-1) != 0 {
		return nil, fmt.Errorf("domain %d is not a power of two ≥ 2", n)
	}
	first, err := hashFile(path)
	if err != nil {
		return nil, err
	}
	if wantSHA256 == "" || first != wantSHA256 {
		return nil, fmt.Errorf("%w: phase-1 file SHA-256 %s, want %q", ErrDigestMismatch, first, wantSHA256)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	r := &reader{r: bufio.NewReaderSize(io.TeeReader(f, h), 1<<20), h: h}
	s, err := parsePtau(r, n)
	if err != nil {
		return nil, err
	}
	if _, err := r.r.ReadByte(); err != io.EOF {
		return nil, errors.New("trailing bytes after the last section")
	}
	s.FileSHA256 = hex.EncodeToString(h.Sum(nil))
	if s.FileSHA256 != first {
		return nil, fmt.Errorf("%w: the phase-1 file changed between the digest pass and the parse pass", ErrDigestMismatch)
	}
	return s, nil
}

func parsePtau(r *reader, n int) (*SRS, error) {
	magic, err := r.full(4)
	if err != nil || string(magic) != "ptau" {
		return nil, errors.New("not a .ptau file")
	}
	version, err := r.u32()
	if err != nil || version != 1 {
		return nil, fmt.Errorf("version %d, want 1", version)
	}
	nSections, err := r.u32()
	if err != nil || nSections < 6 || nSections > 64 {
		return nil, fmt.Errorf("%d sections", nSections)
	}
	s := &SRS{N: n}
	seen := map[uint32]bool{}
	var power uint32
	_, _, g1, g2 := curve.Generators()
	for i := uint32(0); i < nSections; i++ {
		typ, err := r.u32()
		if err != nil {
			return nil, err
		}
		size, err := r.u64()
		if err != nil {
			return nil, err
		}
		if typ >= 1 && typ <= 6 {
			if seen[typ] {
				return nil, fmt.Errorf("section %d appears twice", typ)
			}
			seen[typ] = true
			if typ != 1 && !seen[1] {
				return nil, fmt.Errorf("section %d before the header", typ)
			}
		}
		np := uint64(1) << power
		switch typ {
		case 1:
			if size != 40 && size != 44 {
				return nil, fmt.Errorf("header section has %d bytes", size)
			}
			b, err := r.full(int(size))
			if err != nil {
				return nil, err
			}
			if binary.LittleEndian.Uint32(b[0:4]) != 32 {
				return nil, errors.New("n8 is not 32")
			}
			for j := 0; j < 4; j++ {
				if binary.LittleEndian.Uint64(b[4+8*j:]) != modulusLimbs[j] {
					return nil, errors.New("prime is not the BN254 base-field modulus")
				}
			}
			power = binary.LittleEndian.Uint32(b[36:40])
			if power < 1 || power > 28 || uint64(n) > uint64(1)<<power {
				return nil, fmt.Errorf("power %d cannot serve domain %d", power, n)
			}
			s.Power = power
			s.TauG1 = make([]curve.G1Affine, 2*n-1)
		case 2:
			if size != (2*np-1)*g1Size {
				return nil, fmt.Errorf("tauG1 section has %d bytes", size)
			}
			if err := readG1s(r, s.TauG1); err != nil {
				return nil, fmt.Errorf("tauG1: %w", err)
			}
			if err := r.skip(size - uint64(len(s.TauG1))*g1Size); err != nil {
				return nil, err
			}
		case 3:
			if size != np*g2Size {
				return nil, fmt.Errorf("tauG2 section has %d bytes", size)
			}
			var two [2]curve.G2Affine
			for j := range two {
				b, err := r.full(g2Size)
				if err != nil {
					return nil, err
				}
				if two[j], err = decodeG2(b); err != nil {
					return nil, fmt.Errorf("tauG2[%d]: %w", j, err)
				}
			}
			if !two[0].Equal(&g2) {
				return nil, errors.New("[τ⁰]₂ is not the generator")
			}
			s.Tau2 = two[1]
			if err := r.skip(size - 2*g2Size); err != nil {
				return nil, err
			}
		case 4, 5:
			if size != np*g1Size {
				return nil, fmt.Errorf("section %d has %d bytes", typ, size)
			}
			b, err := r.full(g1Size)
			if err != nil {
				return nil, err
			}
			p, err := decodeG1(b)
			if err != nil {
				return nil, fmt.Errorf("section %d point 0: %w", typ, err)
			}
			if typ == 4 {
				s.Alpha1 = p
			} else {
				s.Beta1 = p
			}
			if err := r.skip(size - g1Size); err != nil {
				return nil, err
			}
		case 6:
			if size != g2Size {
				return nil, fmt.Errorf("betaG2 section has %d bytes", size)
			}
			b, err := r.full(g2Size)
			if err != nil {
				return nil, err
			}
			if s.Beta2, err = decodeG2(b); err != nil {
				return nil, fmt.Errorf("betaG2: %w", err)
			}
		default:
			if err := r.skip(size); err != nil {
				return nil, err
			}
		}
	}
	for typ := uint32(1); typ <= 6; typ++ {
		if !seen[typ] {
			return nil, fmt.Errorf("section %d missing", typ)
		}
	}
	if !s.TauG1[0].Equal(&g1) {
		return nil, errors.New("[τ⁰]₁ is not the generator")
	}
	return s, nil
}

// readG1s decodes len(dst) consecutive G1 points, in chunks, in parallel.
func readG1s(r *reader, dst []curve.G1Affine) error {
	const chunk = 1 << 15
	raw := make([]byte, chunk*g1Size)
	workers := runtime.GOMAXPROCS(0)
	for start := 0; start < len(dst); start += chunk {
		end := min(start+chunk, len(dst))
		b := raw[:(end-start)*g1Size]
		if _, err := io.ReadFull(r.r, b); err != nil {
			return err
		}
		var wg sync.WaitGroup
		errs := make([]error, workers)
		per := (end - start + workers - 1) / workers
		for w := 0; w < workers; w++ {
			lo, hi := start+w*per, min(start+(w+1)*per, end)
			if lo >= hi {
				break
			}
			wg.Add(1)
			go func(w, lo, hi int) {
				defer wg.Done()
				for i := lo; i < hi; i++ {
					p, err := decodeG1(b[(i-start)*g1Size : (i-start+1)*g1Size])
					if err != nil {
						errs[w] = fmt.Errorf("point %d: %w", i, err)
						return
					}
					dst[i] = p
				}
			}(w, lo, hi)
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				return err
			}
		}
	}
	return nil
}
