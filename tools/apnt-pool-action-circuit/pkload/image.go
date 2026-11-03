package pkload

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
	"unsafe"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/pedersen"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

// The image is the proving key as this process holds it in memory, so that a
// verified buffer can be used in place. It is specific to the build's in-memory
// point layout and to little-endian 64-bit hosts; the header records both, and
// the reader refuses an image whose byte order, type sizes, layout fingerprint
// or gnark / gnark-crypto versions differ from its own build's (layout.go).
//
//	header, 256 bytes (integers little-endian):
//	  0  magic "APNT-PK-IMAGE-v2"
//	 16  u64 0x0102030405060708 (read back natively: refuses a big-endian host)
//	 24  u32 sizeof(G1Affine)  28 u32 sizeof(G2Affine)  32 u32 sizeof(fr.Element)
//	 36  u32 commitment keys   40 u64 wires  48 u64 NbInfinityA  56 u64 NbInfinityB
//	 64  u64 domain encoding length
//	 72  u64 len G1.A  80 len G1.B  88 len G1.Z  96 len G1.K  104 len G2.B
//	112  [32] layout fingerprint of the writing build
//	144  [32] gnark version, NUL-padded   176  [32] gnark-crypto version, NUL-padded
//	208  zero
//	sections, each at the next multiple of 64, in this order:
//	  domain       gnark fft.Domain WriteTo (the twiddles are recomputed on load)
//	  fixed        G1 Alpha, Beta, Delta, G2 Beta, Delta, in memory (448 bytes)
//	  commitments  one u64 per commitment key: its basis length
//	  InfinityA, InfinityB   one byte per wire, 0 or 1
//	  G1.A, G1.B, G1.Z, G1.K, G2.B, then per commitment key Basis, BasisExpSigma
//	The file ends where the last section ends.
const (
	imageMagic  = "APNT-PK-IMAGE-v2"
	imageOrder  = uint64(0x0102030405060708)
	imageHeader = 256
	hdrLayout   = 112
	hdrGnark    = 144
	hdrCrypto   = 176
	hdrPad      = 208
	fixedBytes  = 3*sizeG1 + 2*sizeG2
	sizeG1      = int(unsafe.Sizeof(curve.G1Affine{}))
	sizeG2      = int(unsafe.Sizeof(curve.G2Affine{}))
	sizeFr      = int(unsafe.Sizeof(fr.Element{}))
)

func align64(n int) int { return (n + 63) &^ 63 }

// WriteImage writes pk as an image. The caller decides where; the command
// writes only to a new file outside any git work tree.
func WriteImage(w io.Writer, pk *groth16bn254.ProvingKey) (int64, error) {
	if len(pk.InfinityA) != len(pk.InfinityB) {
		return 0, fmt.Errorf("InfinityA has %d wires, InfinityB %d", len(pk.InfinityA), len(pk.InfinityB))
	}
	var dom bytes.Buffer
	if _, err := pk.Domain.WriteTo(&dom); err != nil {
		return 0, err
	}
	hdr := make([]byte, imageHeader)
	copy(hdr, imageMagic)
	le := binary.LittleEndian
	le.PutUint64(hdr[16:], imageOrder)
	le.PutUint32(hdr[24:], uint32(sizeG1))
	le.PutUint32(hdr[28:], uint32(sizeG2))
	le.PutUint32(hdr[32:], uint32(sizeFr))
	le.PutUint32(hdr[36:], uint32(len(pk.CommitmentKeys)))
	le.PutUint64(hdr[40:], uint64(len(pk.InfinityA)))
	le.PutUint64(hdr[48:], pk.NbInfinityA)
	le.PutUint64(hdr[56:], pk.NbInfinityB)
	le.PutUint64(hdr[64:], uint64(dom.Len()))
	for i, s := range [][]curve.G1Affine{pk.G1.A, pk.G1.B, pk.G1.Z, pk.G1.K} {
		le.PutUint64(hdr[72+8*i:], uint64(len(s)))
	}
	le.PutUint64(hdr[104:], uint64(len(pk.G2.B)))
	layout := runtimeLayout()
	copy(hdr[hdrLayout:], layout[:])
	gnark, crypto, err := runtimeVersions()
	if err != nil {
		return 0, err
	}
	if err := putVersion(hdr[hdrGnark:hdrCrypto], gnark); err != nil {
		return 0, err
	}
	if err := putVersion(hdr[hdrCrypto:hdrPad], crypto); err != nil {
		return 0, err
	}

	fixed := make([]byte, 0, fixedBytes)
	for _, p := range []*curve.G1Affine{&pk.G1.Alpha, &pk.G1.Beta, &pk.G1.Delta} {
		fixed = append(fixed, unsafe.Slice((*byte)(unsafe.Pointer(p)), sizeG1)...)
	}
	for _, p := range []*curve.G2Affine{&pk.G2.Beta, &pk.G2.Delta} {
		fixed = append(fixed, unsafe.Slice((*byte)(unsafe.Pointer(p)), sizeG2)...)
	}
	commits := make([]byte, 8*len(pk.CommitmentKeys))
	for i, ck := range pk.CommitmentKeys {
		if len(ck.Basis) != len(ck.BasisExpSigma) {
			return 0, fmt.Errorf("commitment key %d: basis %d, basisExpSigma %d", i, len(ck.Basis), len(ck.BasisExpSigma))
		}
		le.PutUint64(commits[8*i:], uint64(len(ck.Basis)))
	}
	bools := func(v []bool) []byte {
		b := make([]byte, len(v))
		for i, x := range v {
			if x {
				b[i] = 1
			}
		}
		return b
	}

	sections := [][]byte{hdr, dom.Bytes(), fixed, commits, bools(pk.InfinityA), bools(pk.InfinityB),
		g1Bytes(pk.G1.A), g1Bytes(pk.G1.B), g1Bytes(pk.G1.Z), g1Bytes(pk.G1.K), g2Bytes(pk.G2.B)}
	for _, ck := range pk.CommitmentKeys {
		sections = append(sections, g1Bytes(ck.Basis), g1Bytes(ck.BasisExpSigma))
	}
	var n int64
	var zeros [64]byte
	for _, s := range sections {
		if pad := align64(int(n)) - int(n); pad > 0 {
			m, err := w.Write(zeros[:pad])
			n += int64(m)
			if err != nil {
				return n, err
			}
		}
		m, err := w.Write(s)
		n += int64(m)
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func g1Bytes(s []curve.G1Affine) []byte {
	if len(s) == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(&s[0])), len(s)*sizeG1)
}

func g2Bytes(s []curve.G2Affine) []byte {
	if len(s) == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(&s[0])), len(s)*sizeG2)
}

// cursor walks an image, bounds-checking every section.
type cursor struct {
	b   []byte
	off int
}

func (c *cursor) section(n uint64) ([]byte, error) {
	lo := align64(c.off)
	if lo > len(c.b) || n > uint64(len(c.b)-lo) {
		return nil, fmt.Errorf("section of %d bytes at %d runs past the %d-byte image", n, lo, len(c.b))
	}
	hi := lo + int(n)
	c.off = hi
	return c.b[lo:hi:hi], nil
}

func (c *cursor) points(count uint64, size int) ([]byte, error) {
	if count > uint64(len(c.b))/uint64(size) {
		return nil, fmt.Errorf("%d points of %d bytes cannot fit in the %d-byte image", count, size, len(c.b))
	}
	b, err := c.section(count * uint64(size))
	if err == nil && len(b) > 0 && uintptr(unsafe.Pointer(&b[0]))%8 != 0 {
		err = errors.New("point section is not 8-byte aligned; read the image with ReadVerified")
	}
	return b, err
}

func g1View(b []byte) []curve.G1Affine {
	if len(b) == 0 {
		return make([]curve.G1Affine, 0)
	}
	return unsafe.Slice((*curve.G1Affine)(unsafe.Pointer(&b[0])), len(b)/sizeG1)
}

func g2View(b []byte) []curve.G2Affine {
	if len(b) == 0 {
		return make([]curve.G2Affine, 0)
	}
	return unsafe.Slice((*curve.G2Affine)(unsafe.Pointer(&b[0])), len(b)/sizeG2)
}

// viewImage fills pk from an image in buf without copying the point slices:
// they alias buf. It checks the image's structure (every length and bound,
// the infinity flags against their counts) and nothing about the points.
func viewImage(buf []byte, pk *groth16bn254.ProvingKey) error {
	c := &cursor{b: buf}
	hdr, err := c.section(imageHeader)
	if err != nil {
		return err
	}
	if string(hdr[:16]) != imageMagic {
		return fmt.Errorf("not an image: magic %q", hdr[:16])
	}
	if binary.NativeEndian.Uint64(hdr[16:]) != imageOrder {
		return errors.New("the image's byte order is not this host's")
	}
	le := binary.LittleEndian
	if int(le.Uint32(hdr[24:])) != sizeG1 || int(le.Uint32(hdr[28:])) != sizeG2 || int(le.Uint32(hdr[32:])) != sizeFr {
		return fmt.Errorf("image point sizes %d/%d/%d, this build's %d/%d/%d", le.Uint32(hdr[24:]), le.Uint32(hdr[28:]), le.Uint32(hdr[32:]), sizeG1, sizeG2, sizeFr)
	}
	if want := runtimeLayout(); !bytes.Equal(hdr[hdrLayout:hdrGnark], want[:]) {
		return fmt.Errorf("image layout fingerprint %x is not this build's %x: it was written by a build that holds points differently in memory", hdr[hdrLayout:hdrGnark], want)
	}
	gnark, crypto, err := runtimeVersions()
	if err != nil {
		return err
	}
	for _, f := range []struct {
		name, want string
		field      []byte
	}{{"gnark", gnark, hdr[hdrGnark:hdrCrypto]}, {"gnark-crypto", crypto, hdr[hdrCrypto:hdrPad]}} {
		got, err := getVersion(f.field)
		if err != nil {
			return fmt.Errorf("image %s version: %w", f.name, err)
		}
		if got != f.want {
			return fmt.Errorf("image was written under %s %s; this build links %s", f.name, got, f.want)
		}
	}
	if !isZero(hdr[hdrPad:]) {
		return errors.New("image header padding is not zero")
	}
	nbCommit := le.Uint32(hdr[36:])
	nbWires := le.Uint64(hdr[40:])
	pk.NbInfinityA, pk.NbInfinityB = le.Uint64(hdr[48:]), le.Uint64(hdr[56:])
	var lens [5]uint64
	for i := range lens {
		lens[i] = le.Uint64(hdr[72+8*i:])
	}

	dom, err := c.section(le.Uint64(hdr[64:]))
	if err != nil {
		return err
	}
	if n, err := pk.Domain.ReadFrom(bytes.NewReader(dom)); err != nil || n != int64(len(dom)) {
		return fmt.Errorf("domain: read %d of %d bytes: %v", n, len(dom), err)
	}
	fixed, err := c.section(uint64(fixedBytes))
	if err != nil {
		return err
	}
	for i, p := range []*curve.G1Affine{&pk.G1.Alpha, &pk.G1.Beta, &pk.G1.Delta} {
		copy(unsafe.Slice((*byte)(unsafe.Pointer(p)), sizeG1), fixed[i*sizeG1:])
	}
	for i, p := range []*curve.G2Affine{&pk.G2.Beta, &pk.G2.Delta} {
		copy(unsafe.Slice((*byte)(unsafe.Pointer(p)), sizeG2), fixed[3*sizeG1+i*sizeG2:])
	}
	commits, err := c.section(8 * uint64(nbCommit))
	if err != nil {
		return err
	}
	if pk.InfinityA, err = c.flags(nbWires, pk.NbInfinityA); err != nil {
		return fmt.Errorf("InfinityA: %w", err)
	}
	if pk.InfinityB, err = c.flags(nbWires, pk.NbInfinityB); err != nil {
		return fmt.Errorf("InfinityB: %w", err)
	}
	g1s := []*[]curve.G1Affine{&pk.G1.A, &pk.G1.B, &pk.G1.Z, &pk.G1.K}
	for i, dst := range g1s {
		b, err := c.points(lens[i], sizeG1)
		if err != nil {
			return err
		}
		*dst = g1View(b)
	}
	b, err := c.points(lens[4], sizeG2)
	if err != nil {
		return err
	}
	pk.G2.B = g2View(b)
	pk.CommitmentKeys = make([]pedersen.ProvingKey, nbCommit)
	for i := range pk.CommitmentKeys {
		n := le.Uint64(commits[8*i:])
		basis, err := c.points(n, sizeG1)
		if err != nil {
			return err
		}
		sigma, err := c.points(n, sizeG1)
		if err != nil {
			return err
		}
		pk.CommitmentKeys[i] = pedersen.ProvingKey{Basis: g1View(basis), BasisExpSigma: g1View(sigma)}
	}
	if c.off != len(buf) {
		return fmt.Errorf("%d trailing bytes", len(buf)-c.off)
	}
	// The prover indexes the A and B wire values by these flags.
	if uint64(len(pk.G1.A)) != nbWires-pk.NbInfinityA || uint64(len(pk.G1.B)) != nbWires-pk.NbInfinityB || len(pk.G2.B) != len(pk.G1.B) {
		return fmt.Errorf("slice lengths A %d, B %d, G2.B %d disagree with %d wires and %d/%d infinities",
			len(pk.G1.A), len(pk.G1.B), len(pk.G2.B), nbWires, pk.NbInfinityA, pk.NbInfinityB)
	}
	return nil
}

func isZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// flags copies one byte per wire into a []bool, refusing any byte other than
// 0 or 1 and a count of set flags other than want.
func (c *cursor) flags(n, want uint64) ([]bool, error) {
	b, err := c.section(n)
	if err != nil {
		return nil, err
	}
	out := make([]bool, n)
	var set uint64
	for i, x := range b {
		switch x {
		case 0:
		case 1:
			out[i] = true
			set++
		default:
			return nil, fmt.Errorf("flag byte %d is %d", i, x)
		}
	}
	if set != want {
		return nil, fmt.Errorf("%d flags set, the header says %d", set, want)
	}
	return out, nil
}

// DeriveResult is what Derive measured and wrote.
type DeriveResult struct {
	Source        Pin     `json:"source"`
	SourceFormat  string  `json:"sourceEncoding"`
	CheckedDecode string  `json:"checkedDecode"`
	ReadSeconds   float64 `json:"readAndHashSeconds"`
	DecodeSeconds float64 `json:"checkedDecodeSeconds"`
	Out           Format  `json:"outFormat"`
	OutPin        Pin     `json:"outPin"`
	WriteSeconds  float64 `json:"writeAndHashSeconds"`
}

// Derive is the one-time step that makes a fast format from the ceremony's
// raw key (or a compressed WriteTo key). It reads the file into memory this
// process owns with ReadVerified and refuses unless its size and SHA-256 equal
// rawPin; only then does it decode those same bytes, with no second read of
// the path, using gnark's ReadFrom and every check (on-curve and subgroup, for
// every point). It then writes out (a new file; nothing is overwritten) as
// FormatImage or FormatDump and returns that file's pin. At the end of the
// decode it holds the raw bytes and the decoded key together, about twice the
// key's size.
func Derive(rawPath string, rawPin Pin, out string, outFormat Format) (*DeriveResult, error) {
	if outFormat != FormatImage && outFormat != FormatDump {
		return nil, fmt.Errorf("derive writes %s or %s, not %q", FormatImage, FormatDump, outFormat)
	}
	r := &DeriveResult{Source: rawPin, SourceFormat: "gnark WriteRawTo or WriteTo (ReadFrom reads either)", Out: outFormat,
		CheckedDecode: "gnark (*groth16/bn254.ProvingKey).ReadFrom over the pinned bytes: on-curve and subgroup checks on every point"}
	v, rs, err := ReadVerified(rawPath, rawPin)
	if rs != nil {
		r.ReadSeconds = rs.ReadSeconds
	}
	if err != nil {
		return r, err
	}
	start := time.Now()
	pk, err := checkedDecode(v)
	r.DecodeSeconds = time.Since(start).Seconds()
	if err != nil {
		return r, err
	}
	// The raw bytes are unreachable from here on; only the decoded key is written.

	start = time.Now()
	o, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return r, err
	}
	oh := sha256.New()
	bw := bufio.NewWriterSize(io.MultiWriter(o, oh), 8<<20)
	var n int64
	if outFormat == FormatImage {
		n, err = WriteImage(bw, pk)
	} else {
		cw := &countWriter{w: bw}
		err = pk.WriteDump(cw)
		n = cw.n
	}
	if err == nil {
		err = bw.Flush()
	}
	if err == nil {
		err = o.Sync()
	}
	if cerr := o.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(out)
		return r, err
	}
	r.OutPin = Pin{Bytes: n, SHA256: hex.EncodeToString(oh.Sum(nil))}
	r.WriteSeconds = time.Since(start).Seconds()
	return r, nil
}

// checkedDecode decodes verified bytes with gnark's checked ReadFrom, which
// runs the on-curve and subgroup checks the fast decoders skip.
func checkedDecode(v *Verified) (*groth16bn254.ProvingKey, error) {
	if err := v.check(); err != nil {
		return nil, err
	}
	decodeCalls.Add(1)
	pk := new(groth16bn254.ProvingKey)
	rd := bytes.NewReader(v.buf)
	if _, err := pk.ReadFrom(rd); err != nil {
		return nil, &Error{StageDecode, fmt.Errorf("checked decode: %w", err)}
	}
	if rd.Len() != 0 {
		return nil, &Error{StageDecode, fmt.Errorf("checked decode: %d trailing bytes", rd.Len())}
	}
	return pk, nil
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// RawDigest is the SHA-256 and length of pk's WriteRawTo encoding, streamed:
// the round trip that shows a fast-loaded key is the ceremony's key.
func RawDigest(pk *groth16bn254.ProvingKey) (Pin, error) {
	h := sha256.New()
	cw := &countWriter{w: h}
	bw := bufio.NewWriterSize(cw, 8<<20)
	if _, err := pk.WriteRawTo(bw); err != nil {
		return Pin{}, err
	}
	if err := bw.Flush(); err != nil {
		return Pin{}, err
	}
	return Pin{Bytes: cw.n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}
