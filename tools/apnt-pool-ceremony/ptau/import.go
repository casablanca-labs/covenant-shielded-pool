package ptau

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/bits"
	"os"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
)

// Section is one entry of a .ptau file's section table.
type Section struct {
	Type   uint32 `json:"type"`
	Offset int64  `json:"offset"` // offset of the section body
	Size   uint64 `json:"size"`
}

// Info describes an imported file.
type Info struct {
	Version       uint32    `json:"version"`
	Power         uint32    `json:"power"`
	CeremonyPower uint32    `json:"ceremonyPower"`
	Sections      []Section `json:"sections"`
	FileSize      int64     `json:"fileSize"`
	SHA256        string    `json:"sha256"`
	BLAKE2b512    string    `json:"blake2b512"`
	DomainSize    uint64    `json:"domainSize"`
	CommonsSHA256 string    `json:"commonsSha256"`
}

// expectedSize returns the body size a section of the given type must have
// in a file of the given power, or false for sections the importer skips.
func expectedSize(typ, power uint32) (uint64, bool) {
	n := uint64(1) << power
	switch typ {
	case secTauG1:
		return (2*n - 1) * g1Size, true
	case secTauG2:
		return n * g2Size, true
	case secAlphaTauG1, secBetaTauG1:
		return n * g1Size, true
	case secBetaG2:
		return g2Size, true
	}
	return 0, false
}

// ImportFile opens path and calls Import.
func ImportFile(path string, pin Pin, domain uint64) (*mpcsetup.SrsCommons, *Info, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, failure.Wrap(failure.IO, err, "opening phase-1 file")
	}
	defer f.Close()
	return Import(f, pin, domain)
}

// Import reads a .ptau file and returns gnark's phase-1 parameters truncated
// to the FFT domain size domain (a power of two, at least 2).
//
// The pin is checked twice. A first pass hashes the whole file and refuses a
// mismatch before any byte of it is parsed. The second pass parses while
// hashing again, and refuses unless that digest also matches, so the returned
// parameters come from bytes that hash to the pin even if the file changed
// between the passes. Every point is decoded canonically and checked on
// curve and in subgroup; ValidateCommons is then run on the result.
func Import(rs io.ReadSeeker, pin Pin, domain uint64) (*mpcsetup.SrsCommons, *Info, error) {
	if err := pin.Validate(); err != nil {
		return nil, nil, err
	}
	if domain < 2 || domain&(domain-1) != 0 {
		return nil, nil, failure.New(failure.Phase1DomainTooLarge, "domain %d is not a power of two ≥ 2", domain)
	}

	// Pass 1: digest only.
	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		return nil, nil, failure.Wrap(failure.IO, err, "seeking phase-1 file")
	}
	sha, b2, _, err := HashFile(rs)
	if err != nil {
		return nil, nil, err
	}
	if !pin.match(sha, b2) {
		return nil, nil, failure.New(failure.Phase1HashMismatch, "phase-1 file digest does not match pin %s", pin)
	}

	// Pass 2: parse while hashing.
	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		return nil, nil, failure.Wrap(failure.IO, err, "seeking phase-1 file")
	}
	h := newFileHasher()
	r := bufio.NewReaderSize(io.TeeReader(rs, h), 1<<20)
	commons, info, err := parse(r, domain)
	if err != nil {
		return nil, nil, err
	}
	// Anything after the last section is trailing garbage.
	if _, err := r.ReadByte(); err != io.EOF {
		return nil, nil, failure.New(failure.Phase1Format, "trailing bytes after the last section")
	}
	info.SHA256, info.BLAKE2b512 = h.digests()
	info.FileSize = h.size
	if !pin.match(info.SHA256, info.BLAKE2b512) {
		return nil, nil, failure.New(failure.Phase1HashMismatch, "phase-1 file changed between the digest pass and the parse pass")
	}
	if err := ValidateCommons(commons); err != nil {
		return nil, nil, err
	}
	info.DomainSize = domain
	info.CommonsSHA256, err = CommonsDigest(commons)
	if err != nil {
		return nil, nil, err
	}
	return commons, info, nil
}

type countingReader struct {
	r   *bufio.Reader
	pos int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.pos += int64(n)
	return n, err
}

func (c *countingReader) u32() (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

func (c *countingReader) u64() (uint64, error) {
	var b [8]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b[:]), nil
}

func formatErr(err error, what string) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return failure.New(failure.Phase1Format, "truncated file while reading %s", what)
	}
	return failure.Wrap(failure.IO, err, "reading %s", what)
}

// checkVersion is the one .ptau version check, shared by the importer and the
// ranged probe so the two cannot disagree on the version.
func checkVersion(version uint32) error {
	if version != fileVersion {
		return failure.New(failure.Phase1Format, "version %d, want %d", version, fileVersion)
	}
	return nil
}

// checkSectionEntry is the one section-table rule, applied in table order by
// the importer and by the ranged probe: each of the header and the five point
// sections appears at most once, and no point section comes before the header.
// seen records the sections met so far.
func checkSectionEntry(typ uint32, seen map[uint32]bool) error {
	if typ < secHeader || typ > secBetaG2 {
		return nil
	}
	if seen[typ] {
		return failure.New(failure.Phase1Format, "section %d appears twice", typ)
	}
	seen[typ] = true
	if typ != secHeader && !seen[secHeader] {
		return failure.New(failure.Phase1Format, "section %d before the header section", typ)
	}
	return nil
}

// readHeaderBody parses section 1 and returns power and ceremonyPower.
func readHeaderBody(body []byte) (power, ceremonyPower uint32, err error) {
	if len(body) != 4+n8+4 && len(body) != 4+n8+4+4 {
		return 0, 0, failure.New(failure.Phase1Format, "header section has %d bytes", len(body))
	}
	if got := binary.LittleEndian.Uint32(body[0:4]); got != n8 {
		return 0, 0, failure.New(failure.Phase1Format, "n8 is %d, want %d (BN254)", got, n8)
	}
	if !bytes.Equal(body[4:4+n8], modulusLE[:]) {
		return 0, 0, failure.New(failure.Phase1Format, "prime is not the BN254 base-field modulus")
	}
	power = binary.LittleEndian.Uint32(body[4+n8:])
	if power < 1 || power > MaxPower {
		return 0, 0, failure.New(failure.Phase1Format, "power %d outside [1, %d]", power, MaxPower)
	}
	if len(body) == 4+n8+8 {
		ceremonyPower = binary.LittleEndian.Uint32(body[4+n8+4:])
	}
	return power, ceremonyPower, nil
}

func parse(br *bufio.Reader, domain uint64) (*mpcsetup.SrsCommons, *Info, error) {
	r := &countingReader{r: br}
	var magic [4]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, nil, formatErr(err, "magic")
	}
	if string(magic[:]) != fileMagic {
		return nil, nil, failure.New(failure.Phase1Format, "magic is %q, want %q", magic[:], fileMagic)
	}
	version, err := r.u32()
	if err != nil {
		return nil, nil, formatErr(err, "version")
	}
	if err := checkVersion(version); err != nil {
		return nil, nil, err
	}
	nSections, err := r.u32()
	if err != nil {
		return nil, nil, formatErr(err, "section count")
	}
	if nSections < 6 || nSections > 64 {
		return nil, nil, failure.New(failure.Phase1Format, "%d sections", nSections)
	}

	info := &Info{Version: version}
	var c mpcsetup.SrsCommons
	seen := map[uint32]bool{}
	n := int(domain)

	for s := uint32(0); s < nSections; s++ {
		typ, err := r.u32()
		if err != nil {
			return nil, nil, formatErr(err, "section type")
		}
		size, err := r.u64()
		if err != nil {
			return nil, nil, formatErr(err, "section size")
		}
		info.Sections = append(info.Sections, Section{Type: typ, Offset: r.pos, Size: size})
		if err := checkSectionEntry(typ, seen); err != nil {
			return nil, nil, err
		}
		if typ > secHeader && typ <= secBetaG2 {
			if want, _ := expectedSize(typ, info.Power); size != want {
				return nil, nil, failure.New(failure.Phase1Format, "section %d has %d bytes, want %d for power %d", typ, size, want, info.Power)
			}
		}

		var used uint64
		switch typ {
		case secHeader:
			if size > 64 {
				return nil, nil, failure.New(failure.Phase1Format, "header section has %d bytes", size)
			}
			body := make([]byte, size)
			if _, err := io.ReadFull(r, body); err != nil {
				return nil, nil, formatErr(err, "header section")
			}
			used = size
			if info.Power, info.CeremonyPower, err = readHeaderBody(body); err != nil {
				return nil, nil, err
			}
			if domain > uint64(1)<<info.Power {
				return nil, nil, failure.New(failure.Phase1DomainTooLarge, "domain 2^%d exceeds the file's 2^%d", bits.TrailingZeros64(domain), info.Power)
			}
			c.G1.Tau = make([]curve.G1Affine, 2*n-1)
			c.G2.Tau = make([]curve.G2Affine, n)
			c.G1.AlphaTau = make([]curve.G1Affine, n)
			c.G1.BetaTau = make([]curve.G1Affine, n)
		case secTauG1:
			err, used = readG1Section(r, c.G1.Tau), uint64(len(c.G1.Tau))*g1Size
		case secTauG2:
			err, used = readG2Section(r, c.G2.Tau), uint64(len(c.G2.Tau))*g2Size
		case secAlphaTauG1:
			err, used = readG1Section(r, c.G1.AlphaTau), uint64(len(c.G1.AlphaTau))*g1Size
		case secBetaTauG1:
			err, used = readG1Section(r, c.G1.BetaTau), uint64(len(c.G1.BetaTau))*g1Size
		case secBetaG2:
			beta := make([]curve.G2Affine, 1)
			err, used = readG2Section(r, beta), g2Size
			c.G2.Beta = beta[0]
		}
		if err != nil {
			return nil, nil, err
		}
		if _, err := io.CopyN(io.Discard, r, int64(size-used)); err != nil {
			return nil, nil, formatErr(err, "section body")
		}
	}
	for typ := uint32(secHeader); typ <= secBetaG2; typ++ {
		if !seen[typ] {
			return nil, nil, failure.New(failure.Phase1Format, "section %d missing", typ)
		}
	}
	return &c, info, nil
}

const chunkPoints = 1 << 14

func readG1Section(r io.Reader, dst []curve.G1Affine) error {
	buf := make([]byte, min(len(dst), chunkPoints)*g1Size)
	for start := 0; start < len(dst); start += chunkPoints {
		end := min(start+chunkPoints, len(dst))
		raw := buf[:(end-start)*g1Size]
		if _, err := io.ReadFull(r, raw); err != nil {
			return formatErr(err, "G1 points")
		}
		if err := decodeG1Batch(dst[start:end], raw, start); err != nil {
			return err
		}
	}
	return nil
}

func readG2Section(r io.Reader, dst []curve.G2Affine) error {
	buf := make([]byte, min(len(dst), chunkPoints)*g2Size)
	for start := 0; start < len(dst); start += chunkPoints {
		end := min(start+chunkPoints, len(dst))
		raw := buf[:(end-start)*g2Size]
		if _, err := io.ReadFull(r, raw); err != nil {
			return formatErr(err, "G2 points")
		}
		if err := decodeG2Batch(dst[start:end], raw, start); err != nil {
			return err
		}
	}
	return nil
}

// CommonsDigest is the SHA-256 of gnark's own serialization of the phase-1
// parameters (SrsCommons.WriteTo), which is what a transcript records and
// what the ceremony root binds.
func CommonsDigest(c *mpcsetup.SrsCommons) (string, error) {
	h := sha256.New()
	if _, err := c.WriteTo(h); err != nil {
		return "", failure.Wrap(failure.IO, err, "serializing phase-1 parameters")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
