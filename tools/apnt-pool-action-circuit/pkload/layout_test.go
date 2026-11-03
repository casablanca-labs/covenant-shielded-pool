package pkload

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"

	poolaction "github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit"
)

// TestImageHeaderNamesTheLinkedVersions: an image's header names the gnark and
// gnark-crypto versions it was written under (F1).
func TestImageHeaderNamesTheLinkedVersions(t *testing.T) {
	s := newSetup(t)
	img, err := os.ReadFile(s.image)
	if err != nil {
		t.Fatal(err)
	}
	head := img[:256]
	for _, v := range []string{"gnark " + poolaction.GnarkVersion, "gnark-crypto " + poolaction.GnarkCryptoVersion} {
		ver := v[strings.LastIndex(v, " ")+1:]
		if !bytes.Contains(head, []byte(ver)) {
			t.Errorf("the image header does not name %s; an image written under another version would be read as this one", v)
		}
	}
}

// swapHalves swaps the two halves of every block of n bytes.
func swapHalves(b []byte, n int) []byte {
	out := bytes.Clone(b)
	for i := 0; i+n <= len(out); i += n {
		h := n / 2
		copy(out[i:i+h], b[i+h:i+n])
		copy(out[i+h:i+n], b[i:i+h])
	}
	return out
}

// reverseLimbs reverses the four 8-byte limbs of every 32-byte element.
func reverseLimbs(b []byte) []byte {
	out := bytes.Clone(b)
	for e := 0; e+32 <= len(out); e += 32 {
		for l := 0; l < 4; l++ {
			copy(out[e+8*l:e+8*l+8], b[e+8*(3-l):e+8*(3-l)+8])
		}
	}
	return out
}

func regular(e *fp.Element) []byte {
	var b [32]byte
	for i, w := range e.Bits() {
		binary.LittleEndian.PutUint64(b[8*i:], w)
	}
	return b[:]
}

// TestLayoutFingerprintSeesLayoutChanges: the fingerprint changes when a
// build would hold the same points differently, with every type size equal.
func TestLayoutFingerprintSeesLayoutChanges(t *testing.T) {
	real := runtimeLayoutDesc()
	want := real.fingerprint()
	if runtimeLayout() != want || real.fingerprint() != want {
		t.Fatal("the runtime fingerprint is not stable")
	}
	_, _, g1, g2 := curve.Generators()
	var one fp.Element
	one.SetOne()
	var g1x2 curve.G1Affine
	g1x2.Double(&g1)
	variants := map[string]func(d *layoutDesc){
		"affine field order (Y, X)": func(d *layoutDesc) {
			d.values[0], d.values[1], d.values[2] = swapHalves(d.values[0], 64), swapHalves(d.values[1], 64), swapHalves(d.values[2], 128)
		},
		"E2 coefficient order (A1, A0)": func(d *layoutDesc) { d.values[2] = swapHalves(d.values[2], 64) },
		"limb order (most significant first)": func(d *layoutDesc) {
			for i := range d.values {
				d.values[i] = reverseLimbs(d.values[i])
			}
		},
		"regular form, not Montgomery": func(d *layoutDesc) {
			d.values[0] = append(regular(&g1.X), regular(&g1.Y)...)
			d.values[1] = append(regular(&g1x2.X), regular(&g1x2.Y)...)
			d.values[2] = bytes.Join([][]byte{regular(&g2.X.A0), regular(&g2.X.A1), regular(&g2.Y.A0), regular(&g2.Y.A1)}, nil)
			d.values[3] = regular(&one)
		},
		"field offsets": func(d *layoutDesc) { d.shape[1], d.shape[2] = d.shape[2], d.shape[1] },
	}
	for name, mutate := range variants {
		d := layoutDesc{shape: append([]uint64(nil), real.shape...), values: append([][]byte(nil), real.values...)}
		mutate(&d)
		if bytes.Equal(bytes.Join(d.values, nil), bytes.Join(real.values, nil)) && name != "field offsets" {
			t.Fatalf("%s: the variant equals the real layout; the check proves nothing", name)
		}
		if d.fingerprint() == want {
			t.Errorf("%s: same fingerprint as this build", name)
		}
	}
}

func repinned(t *testing.T, dir, name string, b []byte) (string, Pin) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(b)
	return p, Pin{Bytes: int64(len(b)), SHA256: hex.EncodeToString(d[:])}
}

// TestImageRefusesAnotherBuildsLayout plays a build that holds points with
// another layout (fingerprint) and one that links other module versions. The
// images keep this build's byte order and type sizes, so only the new checks
// can refuse them.
func TestImageRefusesAnotherBuildsLayout(t *testing.T) {
	s := newSetup(t)
	other := runtimeLayoutDesc()
	other.values[0] = swapHalves(other.values[0], 64)
	otherLayout := other.fingerprint()
	restore := func() {
		runtimeLayout = func() [32]byte { return runtimeLayoutDesc().fingerprint() }
		runtimeVersions = testVersions
	}
	defer restore()

	// An image written by this build, read by the other.
	runtimeLayout = func() [32]byte { return otherLayout }
	_, _, _, err := Load(s.image, FormatImage, s.imagePin)
	if StageOf(err) != StageDecode || !strings.Contains(err.Error(), "layout fingerprint") {
		t.Fatalf("this build's image under another layout: %v", err)
	}
	restore()

	// An image written by the other build, read by this one.
	runtimeLayout = func() [32]byte { return otherLayout }
	var b bytes.Buffer
	if _, err := WriteImage(&b, s.pk); err != nil {
		t.Fatal(err)
	}
	restore()
	if !bytes.Equal(b.Bytes()[24:36], mustRead(t, s.image)[24:36]) {
		t.Fatal("the other build's image does not keep this build's type sizes; the refusal could come from the size check")
	}
	p, pin := repinned(t, s.dir, "other-layout.image", b.Bytes())
	refused(t, "another build's image", StageDecode, func() error { _, _, _, err := Load(p, FormatImage, pin); return err })
	if _, _, _, err := Load(p, FormatImage, pin); !strings.Contains(err.Error(), "layout fingerprint") {
		t.Fatalf("refused, but not by the layout check: %v", err)
	}

	// Other module versions, same layout.
	for name, v := range map[string]func() (string, string, error){
		"gnark-crypto": func() (string, string, error) { return poolaction.GnarkVersion, "v0.21.1", nil },
		"gnark":        func() (string, string, error) { return "v0.16.4", poolaction.GnarkCryptoVersion, nil },
	} {
		runtimeVersions = v
		_, _, _, err := Load(s.image, FormatImage, s.imagePin)
		restore()
		if StageOf(err) != StageDecode || !strings.Contains(err.Error(), "written under "+name+" ") {
			t.Fatalf("image read by a build linking another %s: %v", name, err)
		}
	}
	// And the unmodified image still loads.
	if _, _, _, err := Load(s.image, FormatImage, s.imagePin); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
