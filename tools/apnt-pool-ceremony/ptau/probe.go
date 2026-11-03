package ptau

import (
	"encoding/binary"
	"io"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
)

// ProbeScope is carried in every probe report. A passing probe is sampled
// evidence, not importer acceptance: the probe applies the importer's version
// and section-table rules, but it reads only the header, the section table
// and a few sampled points.
const ProbeScope = "sampled evidence only, not importer acceptance: the probe applies the importer's " +
	"version and section-table rules and checks the sampled points listed here; it does not hash the " +
	"file, and it does not check unsampled points or the file's phase-1 contribution history"

// ProbeReport is what a ranged probe of a .ptau file established. It reads
// the section table, the header and a few sampled points, never the whole
// file, so it proves nothing about the file's digest or about the points it
// did not read. Only a full import (ImportFile) establishes that the importer
// accepts a file.
type ProbeReport struct {
	Scope         string         `json:"scope"`
	FileSize      int64          `json:"fileSize"`
	Version       uint32         `json:"version"`
	Power         uint32         `json:"power"`
	CeremonyPower uint32         `json:"ceremonyPower"`
	Sections      []ProbeSection `json:"sections"`
	Samples       []ProbeSample  `json:"samples"`
	Checks        []ProbeCheck   `json:"checks"`
	BytesRead     int64          `json:"bytesRead"`
}

// ProbeSection is one section-table entry and whether its size matches the
// size the importer requires for the file's power.
type ProbeSection struct {
	Type         uint32 `json:"type"`
	Offset       int64  `json:"offset"`
	Size         uint64 `json:"size"`
	ExpectedSize uint64 `json:"expectedSize,omitempty"`
	SizeMatches  *bool  `json:"sizeMatches,omitempty"`
}

// ProbeSample names one decoded point.
type ProbeSample struct {
	Section uint32 `json:"section"`
	Index   uint64 `json:"index"`
}

// ProbeCheck is one pairing or equality check over sampled points.
type ProbeCheck struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
}

type countingReaderAt struct {
	ra io.ReaderAt
	n  int64
}

func (c *countingReaderAt) read(off int64, n int) ([]byte, error) {
	b := make([]byte, n)
	got, err := c.ra.ReadAt(b, off)
	c.n += int64(got)
	if got == n {
		return b, nil
	}
	return nil, formatErr(err, "probe range")
}

// Probe reads the layout of a .ptau file through ra. It applies the
// importer's version and section-table rules (checkVersion,
// checkSectionEntry), checks that section sizes match the power, and checks
// on sampled points only that the first points are the generators and that
// pairings confirm a common ratio across the start, the middle and the end of
// each vector. Its success is sampled evidence (ProbeScope); a file it passes
// can still be refused by the importer for a point it did not read.
func Probe(ra io.ReaderAt, size int64) (*ProbeReport, error) {
	c := &countingReaderAt{ra: ra}
	rep := &ProbeReport{Scope: ProbeScope, FileSize: size}
	head, err := c.read(0, 12)
	if err != nil {
		return nil, err
	}
	if string(head[0:4]) != fileMagic {
		return nil, failure.New(failure.Phase1Format, "magic is %q", head[0:4])
	}
	rep.Version = binary.LittleEndian.Uint32(head[4:8])
	if err := checkVersion(rep.Version); err != nil {
		return rep, err
	}
	nSections := binary.LittleEndian.Uint32(head[8:12])
	if nSections < 6 || nSections > 64 {
		return nil, failure.New(failure.Phase1Format, "%d sections", nSections)
	}
	offsets := map[uint32]int64{}
	pos := int64(12)
	seen := map[uint32]bool{}
	for s := uint32(0); s < nSections; s++ {
		h, err := c.read(pos, 12)
		if err != nil {
			return nil, err
		}
		typ := binary.LittleEndian.Uint32(h[0:4])
		sz := binary.LittleEndian.Uint64(h[4:12])
		rep.Sections = append(rep.Sections, ProbeSection{Type: typ, Offset: pos + 12, Size: sz})
		if err := checkSectionEntry(typ, seen); err != nil {
			return rep, err
		}
		offsets[typ] = pos + 12
		pos += 12 + int64(sz)
	}
	if pos != size {
		return nil, failure.New(failure.Phase1Format, "sections end at %d, file size is %d", pos, size)
	}
	hoff, ok := offsets[secHeader]
	if !ok {
		return nil, failure.New(failure.Phase1Format, "no header section")
	}
	var hsize uint64
	for _, s := range rep.Sections {
		if s.Type == secHeader {
			hsize = s.Size
		}
	}
	if hsize > 64 {
		return nil, failure.New(failure.Phase1Format, "header section has %d bytes", hsize)
	}
	hb, err := c.read(hoff, int(hsize))
	if err != nil {
		return nil, err
	}
	if rep.Power, rep.CeremonyPower, err = readHeaderBody(hb); err != nil {
		return nil, err
	}
	for i := range rep.Sections {
		if want, known := expectedSize(rep.Sections[i].Type, rep.Power); known {
			m := rep.Sections[i].Size == want
			rep.Sections[i].ExpectedSize, rep.Sections[i].SizeMatches = want, &m
			if !m {
				return rep, failure.New(failure.Phase1Format, "section %d has %d bytes, want %d", rep.Sections[i].Type, rep.Sections[i].Size, want)
			}
		}
	}
	for typ := uint32(secTauG1); typ <= secBetaG2; typ++ {
		if _, ok := offsets[typ]; !ok {
			return nil, failure.New(failure.Phase1Format, "section %d missing", typ)
		}
	}

	n := uint64(1) << rep.Power
	g1At := func(typ uint32, i uint64) (curve.G1Affine, error) {
		b, err := c.read(offsets[typ]+int64(i*g1Size), g1Size)
		if err != nil {
			return curve.G1Affine{}, err
		}
		rep.Samples = append(rep.Samples, ProbeSample{Section: typ, Index: i})
		return decodeG1(b)
	}
	g2At := func(typ uint32, i uint64) (curve.G2Affine, error) {
		b, err := c.read(offsets[typ]+int64(i*g2Size), g2Size)
		if err != nil {
			return curve.G2Affine{}, err
		}
		rep.Samples = append(rep.Samples, ProbeSample{Section: typ, Index: i})
		return decodeG2(b)
	}

	_, _, g1, g2 := curve.Generators()
	check := func(name string, ok bool) {
		rep.Checks = append(rep.Checks, ProbeCheck{Name: name, OK: ok})
	}
	// e(a, b) = e(c, d)
	pair := func(a curve.G1Affine, b curve.G2Affine, cc curve.G1Affine, d curve.G2Affine) bool {
		var na curve.G1Affine
		na.Neg(&a)
		ok, err := curve.PairingCheck([]curve.G1Affine{na, cc}, []curve.G2Affine{b, d})
		return err == nil && ok
	}

	tau1G1, err := g1At(secTauG1, 1)
	if err != nil {
		return rep, err
	}
	tau1G2, err := g2At(secTauG2, 1)
	if err != nil {
		return rep, err
	}
	first1, err := g1At(secTauG1, 0)
	if err != nil {
		return rep, err
	}
	first2, err := g2At(secTauG2, 0)
	if err != nil {
		return rep, err
	}
	check("tauG1[0] is the G1 generator", first1.Equal(&g1))
	check("tauG2[0] is the G2 generator", first2.Equal(&g2))
	check("e(tauG1[1], g2) = e(g1, tauG2[1])", pair(tau1G1, g2, g1, tau1G2))

	// Consecutive pairs (i, i+1) of each G1 vector: e(v[i+1], g2) = e(v[i], [τ]₂).
	g1Pairs := map[uint32][]uint64{
		secTauG1:      {0, 1, n - 2, n - 1, n, 2*n - 3},
		secAlphaTauG1: {0, n / 2, n - 2},
		secBetaTauG1:  {0, n / 2, n - 2},
	}
	for _, typ := range []uint32{secTauG1, secAlphaTauG1, secBetaTauG1} {
		length := n
		if typ == secTauG1 {
			length = 2*n - 1
		}
		for _, i := range pairStarts(g1Pairs[typ], length) {
			a, err := g1At(typ, i)
			if err != nil {
				return rep, err
			}
			b, err := g1At(typ, i+1)
			if err != nil {
				return rep, err
			}
			check(sectionName(typ)+"["+itoa(i)+"→"+itoa(i+1)+"] ratio is τ", pair(b, g2, a, tau1G2))
		}
	}
	// G2: e(g1, v[i+1]) = e([τ]₁, v[i]).
	for _, i := range pairStarts([]uint64{0, n / 2, n - 2}, n) {
		a, err := g2At(secTauG2, i)
		if err != nil {
			return rep, err
		}
		b, err := g2At(secTauG2, i+1)
		if err != nil {
			return rep, err
		}
		check("tauG2["+itoa(i)+"→"+itoa(i+1)+"] ratio is τ", pair(g1, b, tau1G1, a))
	}
	beta1, err := g1At(secBetaTauG1, 0)
	if err != nil {
		return rep, err
	}
	beta2, err := g2At(secBetaG2, 0)
	if err != nil {
		return rep, err
	}
	check("e(betaTauG1[0], g2) = e(g1, betaG2)", pair(beta1, g2, g1, beta2))

	rep.BytesRead = c.n
	for _, ch := range rep.Checks {
		if !ch.OK {
			return rep, failure.New(failure.Phase1ProbeInconsistent, "probe check failed: %s", ch.Name)
		}
	}
	return rep, nil
}

func sectionName(typ uint32) string {
	switch typ {
	case secTauG1:
		return "tauG1"
	case secTauG2:
		return "tauG2"
	case secAlphaTauG1:
		return "alphaTauG1"
	case secBetaTauG1:
		return "betaTauG1"
	case secBetaG2:
		return "betaG2"
	}
	return "section" + itoa(uint64(typ))
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// pairStarts keeps the distinct starts i with i+1 inside a vector of the
// given length, in order.
func pairStarts(starts []uint64, length uint64) []uint64 {
	var out []uint64
	seen := map[uint64]bool{}
	for _, i := range starts {
		if i+1 < length && !seen[i] {
			seen[i] = true
			out = append(out, i)
		}
	}
	return out
}
