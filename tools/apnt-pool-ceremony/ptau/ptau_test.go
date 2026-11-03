package ptau_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/internal/fixture"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
)

// toyPower8SHA256 pins the deterministic toy fixture (power 8, τ=7, α=11,
// β=13). It is a regression pin on the writer and ToyCommons, computed by
// this code, not an independent reference; the real-format evidence is
// TestRealPerpetualPowersOfTau.
const toyPower8SHA256 = "sha256:e91b6471315d0e2d7554f75bdf2415b29e1b72b455794b1a1cb9b0fc5a2ad877"

func toyBytes(t *testing.T, power uint32) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := ptau.Write(&b, ptau.ToyCommons(power, fixture.ToyTau, fixture.ToyAlpha, fixture.ToyBeta)); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func pinOf(t *testing.T, b []byte) ptau.Pin {
	t.Helper()
	sha, _, _, err := ptau.HashFile(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return ptau.Pin{Algorithm: ptau.AlgSHA256, Digest: sha}
}

func wantCode(t *testing.T, err error, code failure.Code) {
	t.Helper()
	if got := failure.CodeOf(err); got != code {
		t.Fatalf("got %v (code %q), want code %q", err, got, code)
	}
}

// offset of point i of a section in a toy file (sections in order 1..7).
func pointOffset(power uint32, section, i int) int {
	n := 1 << power
	off := 12 + 12 + 44 // file header, section-1 header and body
	sizes := map[int]int{2: (2*n - 1) * 64, 3: n * 128, 4: n * 64, 5: n * 64}
	for s := 2; s < section; s++ {
		off += 12 + sizes[s]
	}
	off += 12
	if section == 3 {
		return off + i*128
	}
	return off + i*64
}

func TestToyFixtureIsDeterministicAndPinned(t *testing.T) {
	b := toyBytes(t, 8)
	if got := pinOf(t, b).String(); got != toyPower8SHA256 {
		t.Fatalf("toy fixture digest %s, pinned %s", got, toyPower8SHA256)
	}
	if !bytes.Equal(b, toyBytes(t, 8)) {
		t.Fatal("toy fixture is not deterministic")
	}
}

func TestImportRoundTripAndTruncation(t *testing.T) {
	b := toyBytes(t, 5)
	pin := pinOf(t, b)
	for _, domain := range []uint64{2, 4, 16, 32} {
		c, info, err := ptau.Import(bytes.NewReader(b), pin, domain)
		if err != nil {
			t.Fatalf("domain %d: %v", domain, err)
		}
		// A prefix of powers of tau is the powers of tau of the smaller domain.
		power := uint32(0)
		for 1<<power < domain {
			power++
		}
		want, err := ptau.CommonsDigest(ptau.ToyCommons(power, fixture.ToyTau, fixture.ToyAlpha, fixture.ToyBeta))
		if err != nil {
			t.Fatal(err)
		}
		if info.CommonsSHA256 != want {
			t.Fatalf("domain %d: imported parameters differ from the toy parameters of that domain", domain)
		}
		if len(c.G1.Tau) != int(2*domain-1) || info.Power != 5 || info.FileSize != int64(len(b)) {
			t.Fatalf("domain %d: lengths %d, power %d, size %d", domain, len(c.G1.Tau), info.Power, info.FileSize)
		}
	}
}

func TestPhase1HashMismatchRefused(t *testing.T) {
	b := toyBytes(t, 4)
	pin := pinOf(t, b)
	// Flip a byte of the contributions section: every point stays valid, so
	// only the pin can catch it.
	tampered := append([]byte(nil), b...)
	tampered[len(tampered)-1] ^= 0x01
	_, _, err := ptau.Import(bytes.NewReader(tampered), pin, 16)
	wantCode(t, err, failure.Phase1HashMismatch)

	// A well-formed file under a wrong pin.
	other := toyBytes(t, 3)
	_, _, err = ptau.Import(bytes.NewReader(other), pin, 8)
	wantCode(t, err, failure.Phase1HashMismatch)

	// BLAKE2b-512 pins work and are checked too.
	_, b2, _, _ := ptau.HashFile(bytes.NewReader(b))
	if _, _, err := ptau.Import(bytes.NewReader(b), ptau.Pin{Algorithm: ptau.AlgBLAKE2b512, Digest: b2}, 16); err != nil {
		t.Fatal(err)
	}
	_, _, err = ptau.Import(bytes.NewReader(tampered), ptau.Pin{Algorithm: ptau.AlgBLAKE2b512, Digest: b2}, 16)
	wantCode(t, err, failure.Phase1HashMismatch)
}

func TestPinParsing(t *testing.T) {
	for _, bad := range []string{"", "sha256", "md5:00", "sha256:ABCD", "sha256:00", "blake2b-512:" + string(bytes.Repeat([]byte("0"), 64))} {
		if _, err := ptau.ParsePin(bad); failure.CodeOf(err) != failure.Phase1PinInvalid {
			t.Fatalf("pin %q accepted or wrong code: %v", bad, err)
		}
	}
	if _, err := ptau.ParsePin("sha256:" + string(bytes.Repeat([]byte("0"), 64))); err != nil {
		t.Fatal(err)
	}
}

func TestImportRefusesDomainTooLarge(t *testing.T) {
	b := toyBytes(t, 3)
	_, _, err := ptau.Import(bytes.NewReader(b), pinOf(t, b), 16)
	wantCode(t, err, failure.Phase1DomainTooLarge)
	_, _, err = ptau.Import(bytes.NewReader(b), pinOf(t, b), 6)
	wantCode(t, err, failure.Phase1DomainTooLarge)
}

// replaceG1 overwrites point i of a G1 section with p.
func replaceG1(b []byte, power uint32, section, i int, p curve.G1Affine) []byte {
	out := append([]byte(nil), b...)
	off := pointOffset(power, section, i)
	for l := 0; l < 4; l++ {
		binary.LittleEndian.PutUint64(out[off+8*l:], p.X[l])
		binary.LittleEndian.PutUint64(out[off+32+8*l:], p.Y[l])
	}
	return out
}

func TestImportRefusesBrokenPowersOfTau(t *testing.T) {
	const power = 4
	b := toyBytes(t, power)
	c := ptau.ToyCommons(power, fixture.ToyTau, fixture.ToyAlpha, fixture.ToyBeta)
	_, _, g1, _ := curve.Generators()
	for _, tc := range []struct {
		name    string
		section int
		index   int
		point   curve.G1Affine
	}{
		{"tauG1 middle point shifted", 2, 5, *new(curve.G1Affine).Add(&c.G1.Tau[5], &g1)},
		{"tauG1 last point shifted", 2, 2*16 - 2, *new(curve.G1Affine).Add(&c.G1.Tau[30], &g1)},
		{"alphaTau point swapped", 4, 3, c.G1.BetaTau[3]},
		{"betaTau[0] replaced by tau", 5, 0, c.G1.Tau[1]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := replaceG1(b, power, tc.section, tc.index, tc.point)
			// Pin the tampered file so that only the structure check can refuse it.
			_, _, err := ptau.Import(bytes.NewReader(bad), pinOf(t, bad), 16)
			wantCode(t, err, failure.Phase1NotPowersOfTau)
		})
	}
}

func TestImportRefusesInvalidPoints(t *testing.T) {
	const power = 3
	b := toyBytes(t, power)
	off := pointOffset(power, 2, 2)

	offCurve := append([]byte(nil), b...)
	offCurve[off] ^= 0x01 // x changes, y does not: off the curve
	_, _, err := ptau.Import(bytes.NewReader(offCurve), pinOf(t, offCurve), 8)
	wantCode(t, err, failure.Phase1PointInvalid)

	// x + q is the same field element in a non-canonical encoding.
	nonCanon := append([]byte(nil), b...)
	var x fp.Element
	for l := 0; l < 4; l++ {
		x[l] = binary.LittleEndian.Uint64(b[off+8*l:])
	}
	q := fp.Modulus()
	var xs [32]byte
	for l := 0; l < 4; l++ {
		binary.BigEndian.PutUint64(xs[24-8*l:], x[l])
	}
	sum := new(big.Int).SetBytes(xs[:])
	sum.Add(sum, q)
	sb := sum.FillBytes(make([]byte, 32))
	for l := 0; l < 4; l++ {
		binary.LittleEndian.PutUint64(nonCanon[off+8*l:], binary.BigEndian.Uint64(sb[24-8*l:]))
	}
	_, _, err = ptau.Import(bytes.NewReader(nonCanon), pinOf(t, nonCanon), 8)
	wantCode(t, err, failure.Phase1PointInvalid)

	// The point at infinity.
	inf := append([]byte(nil), b...)
	copy(inf[off:off+64], make([]byte, 64))
	_, _, err = ptau.Import(bytes.NewReader(inf), pinOf(t, inf), 8)
	wantCode(t, err, failure.Phase1PointInvalid)
}

func TestImportRefusesFormatErrors(t *testing.T) {
	b := toyBytes(t, 3)
	for name, bad := range map[string][]byte{
		"trailing byte": append(append([]byte(nil), b...), 0),
		"truncated":     b[:len(b)-3],
		"bad magic":     append([]byte("ptaX"), b[4:]...),
		"bad prime":     func() []byte { c := append([]byte(nil), b...); c[12+12+4] ^= 1; return c }(),
		"bad version":   func() []byte { c := append([]byte(nil), b...); c[4] = 2; return c }(),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := ptau.Import(bytes.NewReader(bad), pinOf(t, bad), 8)
			wantCode(t, err, failure.Phase1Format)
		})
	}
}

func TestProbeFixture(t *testing.T) {
	const power = 5
	b := toyBytes(t, power)
	rep, err := ptau.Probe(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Power != power || len(rep.Checks) < 10 {
		t.Fatalf("power %d, %d checks", rep.Power, len(rep.Checks))
	}
	// A point the probe samples near the far end of tauG1.
	c := ptau.ToyCommons(power, fixture.ToyTau, fixture.ToyAlpha, fixture.ToyBeta)
	_, _, g1, _ := curve.Generators()
	last := 2*(1<<power) - 2
	bad := replaceG1(b, power, 2, last, *new(curve.G1Affine).Add(&c.G1.Tau[last], &g1))
	_, err = ptau.Probe(bytes.NewReader(bad), int64(len(bad)))
	wantCode(t, err, failure.Phase1ProbeInconsistent)
}

// versionOverlay reads through ra but reports version v in the file header,
// so a large real file can be presented as another version without a copy.
type versionOverlay struct {
	ra interface {
		ReadAt([]byte, int64) (int, error)
	}
	v uint32
}

func (o versionOverlay) ReadAt(p []byte, off int64) (int, error) {
	n, err := o.ra.ReadAt(p, off)
	var v [4]byte
	binary.LittleEndian.PutUint32(v[:], o.v)
	for i := 0; i < 4; i++ {
		if at := 4 + int64(i) - off; at >= 0 && at < int64(n) {
			p[at] = v[i]
		}
	}
	return n, err
}

// The probe refuses exactly the versions the importer refuses, with the same
// code; a version-2 file must not pass the probe and then fail the import.
func TestProbeRefusesUnsupportedVersion(t *testing.T) {
	b := toyBytes(t, 5)
	// Control: the unmodified file passes both.
	if _, err := ptau.Probe(bytes.NewReader(b), int64(len(b))); err != nil {
		t.Fatalf("control probe: %v", err)
	}
	if _, _, err := ptau.Import(bytes.NewReader(b), pinOf(t, b), 32); err != nil {
		t.Fatalf("control import: %v", err)
	}
	for _, v := range []uint32{0, 2, 3, 1 << 31} {
		bad := append([]byte(nil), b...)
		binary.LittleEndian.PutUint32(bad[4:8], v)
		rep, err := ptau.Probe(bytes.NewReader(bad), int64(len(bad)))
		wantCode(t, err, failure.Phase1Format)
		if rep == nil || rep.Version != v || len(rep.Checks) != 0 {
			t.Fatalf("version %d: report %+v", v, rep)
		}
		_, _, err = ptau.Import(bytes.NewReader(bad), pinOf(t, bad), 32)
		wantCode(t, err, failure.Phase1Format)
	}
}

// The probe applies the importer's section-table rule: an intact point
// section moved before the header is refused by both, with the same code, and
// the refused probe samples no point (REV-152).
func TestProbeRefusesSectionBeforeHeader(t *testing.T) {
	b := toyBytes(t, 5)
	// Control: the original order passes both.
	rep, err := ptau.Probe(bytes.NewReader(b), int64(len(b)))
	if err != nil || rep.Scope != ptau.ProbeScope {
		t.Fatalf("control probe: %+v %v", rep, err)
	}
	if _, _, err := ptau.Import(bytes.NewReader(b), pinOf(t, b), 32); err != nil {
		t.Fatalf("control import: %v", err)
	}
	for typ := uint32(2); typ <= 6; typ++ {
		bad := fixture.MoveSectionFirst(t, b, typ)
		if len(bad) != len(b) || bytes.Equal(bad, b) {
			t.Fatalf("section %d: reorder did not change only the order", typ)
		}
		rep, err := ptau.Probe(bytes.NewReader(bad), int64(len(bad)))
		wantCode(t, err, failure.Phase1Format)
		if rep == nil || len(rep.Checks) != 0 || len(rep.Samples) != 0 {
			t.Fatalf("section %d: refused probe report %+v", typ, rep)
		}
		_, _, err = ptau.Import(bytes.NewReader(bad), pinOf(t, bad), 32)
		wantCode(t, err, failure.Phase1Format)
	}
	// A point section repeated after the header: both refuse the duplicate.
	_, err = ptau.Probe(bytes.NewReader(dupSection(t, b, 6)), int64(len(dupSection(t, b, 6))))
	wantCode(t, err, failure.Phase1Format)
}

// dupSection appends a second copy of section typ and bumps the count.
func dupSection(t *testing.T, b []byte, typ uint32) []byte {
	t.Helper()
	n := binary.LittleEndian.Uint32(b[8:12])
	pos := 12
	for s := uint32(0); s < n; s++ {
		sz := int(binary.LittleEndian.Uint64(b[pos+4 : pos+12]))
		if binary.LittleEndian.Uint32(b[pos:pos+4]) == typ {
			out := append(append([]byte(nil), b...), b[pos:pos+12+sz]...)
			binary.LittleEndian.PutUint32(out[8:12], n+1)
			return out
		}
		pos += 12 + sz
	}
	t.Fatalf("section %d not found", typ)
	return nil
}

// maxWholeRead bounds the real-file reorder negative, which holds the whole
// file in memory. PSE's 2^8 file is 388,242 bytes; the 2^23 file, 9.66 GB,
// stays on the ranged-probe path.
const maxWholeRead = 1 << 24

// reorderNegative moves an intact tauG1 section before the header of a real
// .ptau file and requires the probe and the importer to refuse it. It decides
// on the file's measured size before reading anything: above maxWholeRead it
// skips without calling read. It reports whether it ran.
func reorderNegative(t *testing.T, size int64, read func() ([]byte, error)) bool {
	t.Helper()
	if size > maxWholeRead {
		t.Logf("reorder negative skipped: %d bytes exceeds the %d-byte whole-read limit", size, maxWholeRead)
		return false
	}
	whole, err := read()
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(whole)) != size {
		t.Fatalf("read %d bytes, measured %d", len(whole), size)
	}
	reordered := fixture.MoveSectionFirst(t, whole, 2)
	_, err = ptau.Probe(bytes.NewReader(reordered), int64(len(reordered)))
	wantCode(t, err, failure.Phase1Format)
	_, _, err = ptau.Import(bytes.NewReader(reordered), pinOf(t, reordered), 2)
	wantCode(t, err, failure.Phase1Format)
	t.Logf("reorder negative ran on %d bytes", size)
	return true
}

// The reorder negative's size limit is applied before any read (REV-154). A
// sparse file one byte over the limit is skipped with no read call; control:
// a file under the limit is read once and the negative runs.
func TestReorderNegativeSizeGuardPrecedesRead(t *testing.T) {
	big := filepath.Join(t.TempDir(), "sparse.ptau")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxWholeRead + 1); err != nil {
		t.Fatal(err)
	}
	st, err := f.Stat()
	f.Close()
	if err != nil || st.Size() != maxWholeRead+1 {
		t.Fatalf("sparse file: %v %v", st, err)
	}
	reads := 0
	refuse := func() ([]byte, error) {
		reads++
		return nil, errors.New("whole-file read attempted above the size limit")
	}
	if reorderNegative(t, st.Size(), refuse) || reads != 0 {
		t.Fatalf("above the limit: ran or read (%d reads)", reads)
	}

	small := toyBytes(t, 5)
	reads = 0
	count := func() ([]byte, error) { reads++; return small, nil }
	if !reorderNegative(t, int64(len(small)), count) || reads != 1 {
		t.Fatalf("under the limit: did not run once (%d reads)", reads)
	}
}

// TestRealPerpetualPowersOfTau imports a real Perpetual Powers of Tau
// prepared file when one is supplied, e.g. PSE's ppot_0080_08.ptau:
//
//	APNT_CEREMONY_PPOT=/path/ppot_0080_08.ptau APNT_CEREMONY_PPOT_PIN=sha256:<hex> go test ./ptau
func TestRealPerpetualPowersOfTau(t *testing.T) {
	path, pinText := os.Getenv("APNT_CEREMONY_PPOT"), os.Getenv("APNT_CEREMONY_PPOT_PIN")
	if path == "" || pinText == "" {
		t.Skip("APNT_CEREMONY_PPOT and APNT_CEREMONY_PPOT_PIN not set: real-file import not exercised")
	}
	pin, err := ptau.ParsePin(pinText)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	rep, err := ptau.Probe(f, st.Size())
	if err != nil {
		t.Fatalf("probe of %s: %v", filepath.Base(path), err)
	}
	if rep.Version != 1 {
		t.Fatalf("real file reports version %d", rep.Version)
	}
	// The same real file with its version field rewritten to 2 is refused.
	_, err = ptau.Probe(versionOverlay{f, 2}, st.Size())
	wantCode(t, err, failure.Phase1Format)
	// The same real file with an intact tauG1 section moved before the header
	// is refused by the probe and by the importer, if it is small enough to
	// hold in memory.
	reorderNegative(t, st.Size(), func() ([]byte, error) { return os.ReadFile(path) })
	domain := uint64(1) << rep.Power
	_, info, err := ptau.ImportFile(path, pin, domain)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s: power %d, %d sections, %d bytes, sha256 %s, blake2b-512 %s, commons %s",
		filepath.Base(path), info.Power, len(info.Sections), info.FileSize, info.SHA256, info.BLAKE2b512, info.CommonsSHA256)
}
