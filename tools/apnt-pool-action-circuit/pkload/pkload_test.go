package pkload

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/devprove"
)

// The small test circuit (not the pool action circuit): its byte range checks
// go through gnark's commitment path, so its key has a commitment key.
const rounds = 2000

type setup struct {
	ccs                       constraint.ConstraintSystem
	pk                        *groth16bn254.ProvingKey
	vk                        groth16.VerifyingKey
	ref                       *groth16bn254.ProvingKey // pk re-read with gnark's checked ReadFrom
	dir                       string
	raw, dump, image          string
	rawPin, dumpPin, imagePin Pin
}

func newSetup(t *testing.T) *setup {
	t.Helper()
	target := devprove.SmallTarget(rounds)
	ccs, err := target.Compile()
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	s := &setup{ccs: ccs, pk: pk.(*groth16bn254.ProvingKey), vk: vk, dir: t.TempDir()}
	if len(s.pk.CommitmentKeys) == 0 {
		t.Fatal("the small circuit's key has no commitment key; the commitment path would go untested")
	}
	s.raw, s.rawPin = writeKey(t, s.dir, "raw", func(w io.Writer) error { _, err := s.pk.WriteRawTo(w); return err })
	s.dump, s.dumpPin = writeKey(t, s.dir, "dump", s.pk.WriteDump)
	s.image, s.imagePin = writeKey(t, s.dir, "image", func(w io.Writer) error { _, err := WriteImage(w, s.pk); return err })
	raw, _ := os.ReadFile(s.raw)
	s.ref = new(groth16bn254.ProvingKey)
	if _, err := s.ref.ReadFrom(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	return s
}

func writeKey(t *testing.T, dir, name string, w func(io.Writer) error) (string, Pin) {
	t.Helper()
	var b bytes.Buffer
	if err := w(&b); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(b.Bytes())
	return p, Pin{Bytes: int64(b.Len()), SHA256: hex.EncodeToString(d[:])}
}

func TestEveryFormatLoadsTheSameKey(t *testing.T) {
	s := newSetup(t)
	for _, c := range []struct {
		f    Format
		path string
		pin  Pin
	}{{FormatRaw, s.raw, s.rawPin}, {FormatDump, s.dump, s.dumpPin}, {FormatImage, s.image, s.imagePin}} {
		pk, rs, ds, err := Load(c.path, c.f, c.pin)
		if err != nil {
			t.Fatalf("%s: %v", c.f, err)
		}
		if rs.SHA256 != c.pin.SHA256 || ds.ZeroCopy != (c.f == FormatImage) {
			t.Fatalf("%s: stats %+v %+v", c.f, rs, ds)
		}
		if !reflect.DeepEqual(pk, s.ref) {
			t.Fatalf("%s: the loaded key differs from gnark's checked ReadFrom of the raw key", c.f)
		}
		// The round trip back to the ceremony encoding.
		if got, err := RawDigest(pk); err != nil || got != s.rawPin {
			t.Fatalf("%s: WriteRawTo of the loaded key is %+v (%v), the raw pin is %+v", c.f, got, err, s.rawPin)
		}
	}
}

func TestImageKeyIsAViewOfTheVerifiedBuffer(t *testing.T) {
	s := newSetup(t)
	v, _, err := ReadVerified(s.image, s.imagePin)
	if err != nil {
		t.Fatal(err)
	}
	buf := v.buf
	pk, _, err := Decode(FormatImage, v)
	if err != nil {
		t.Fatal(err)
	}
	lo, hi := &buf[0], &buf[len(buf)-1]
	for name, p := range map[string]*byte{
		"G1.A": bytePtr(pk.G1.A), "G1.Z": bytePtr(pk.G1.Z), "G2.B": bytePtr(pk.G2.B),
		"commitment basis": bytePtr(pk.CommitmentKeys[0].Basis),
	} {
		if uintptrOf(p) < uintptrOf(lo) || uintptrOf(p) > uintptrOf(hi) {
			t.Fatalf("%s is not inside the verified buffer: it was copied", name)
		}
	}
}

func TestImageKeyProvesAndVerifies(t *testing.T) {
	s := newSetup(t)
	pk, _, _, err := Load(s.image, FormatImage, s.imagePin)
	if err != nil {
		t.Fatal(err)
	}
	a, _, err := devprove.SmallTarget(rounds).Assignment()
	if err != nil {
		t.Fatal(err)
	}
	full, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(s.ccs, pk, full)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := full.Public()
	if err := groth16.Verify(proof, s.vk, pub); err != nil {
		t.Fatalf("a proof under the image-loaded key does not verify: %v", err)
	}
	// Negative control: the same proof against one flipped public input.
	pub2, _ := full.Public()
	vec := pub2.Vector().(fr.Vector)
	var one fr.Element
	one.SetOne()
	vec[2].Add(&vec[2], &one)
	if err := groth16.Verify(proof, s.vk, pub2); err == nil {
		t.Fatal("the proof verifies against a flipped public input")
	}
}

// refused asserts a load stops at stage and never reaches a decoder.
func refused(t *testing.T, name string, stage Stage, load func() error) {
	t.Helper()
	before := decodeCalls.Load()
	err := load()
	if got := StageOf(err); got != stage {
		t.Fatalf("%s: stage %q (%v), want %q", name, got, err, stage)
	}
	if stage != StageDecode && decodeCalls.Load() != before {
		t.Fatalf("%s: a decoder ran before the refusal", name)
	}
}

func TestRefusals(t *testing.T) {
	s := newSetup(t)
	for _, c := range []struct {
		f    Format
		path string
		pin  Pin
	}{{FormatRaw, s.raw, s.rawPin}, {FormatDump, s.dump, s.dumpPin}, {FormatImage, s.image, s.imagePin}} {
		orig, _ := os.ReadFile(c.path)

		// One flipped byte, in the middle of the point data.
		flipped := bytes.Clone(orig)
		flipped[len(flipped)/2] ^= 0x01
		fp := filepath.Join(s.dir, string(c.f)+".flipped")
		os.WriteFile(fp, flipped, 0o600)
		refused(t, string(c.f)+" flipped byte", StageDigest, func() error { _, _, _, err := Load(fp, c.f, c.pin); return err })
		// The detector matters: the unexported unchecked decoder, given the
		// same bytes with no pin, accepts them and yields a different key (or
		// fails).
		if pk, _, err := decode(c.f, alignedCopy(flipped)); err == nil && reflect.DeepEqual(pk, s.ref) {
			t.Fatalf("%s: the flipped byte does not change the decoded key; the negative control proves nothing", c.f)
		}

		// Truncated by one byte: refused from fstat, before any read.
		tp := filepath.Join(s.dir, string(c.f)+".truncated")
		os.WriteFile(tp, orig[:len(orig)-1], 0o600)
		refused(t, string(c.f)+" truncated", StageSize, func() error { _, _, _, err := Load(tp, c.f, c.pin); return err })
		// Truncated, with a pin naming the truncated length: refused at the digest.
		refused(t, string(c.f)+" truncated, length re-pinned", StageDigest, func() error {
			_, _, _, err := Load(tp, c.f, Pin{Bytes: c.pin.Bytes - 1, SHA256: c.pin.SHA256})
			return err
		})
		// One byte appended.
		ap := filepath.Join(s.dir, string(c.f)+".appended")
		os.WriteFile(ap, append(bytes.Clone(orig), 0), 0o600)
		refused(t, string(c.f)+" appended", StageSize, func() error { _, _, _, err := Load(ap, c.f, c.pin); return err })
	}

	// A file that grew between fstat and the read: bytes past the pinned
	// length are refused even when the pinned prefix is the key.
	orig, _ := os.ReadFile(s.image)
	refused(t, "grew after fstat", StageRead, func() error {
		_, _, err := readPinned(bytes.NewReader(append(orig, 0)), "grown", s.imagePin)
		return err
	})
	if _, _, err := readPinned(bytes.NewReader(orig), "exact", s.imagePin); err != nil {
		t.Fatalf("the exact image is refused by readPinned: %v", err)
	}

	// A digest pinned for another key: a second Setup of the same circuit has
	// the same image length and different points.
	other := newSetup(t)
	if other.imagePin.Bytes != s.imagePin.Bytes || other.imagePin.SHA256 == s.imagePin.SHA256 {
		t.Fatalf("the second setup's image is not a same-length different key: %+v vs %+v", other.imagePin, s.imagePin)
	}
	refused(t, "another key's pin", StageDigest, func() error { _, _, _, err := Load(s.image, FormatImage, other.imagePin); return err })
	refused(t, "another key's pin (raw)", StageDigest, func() error { _, _, _, err := Load(s.raw, FormatRaw, other.rawPin); return err })

	// Malformed pins.
	refused(t, "no digest", StagePin, func() error { _, _, _, err := Load(s.image, FormatImage, Pin{Bytes: s.imagePin.Bytes}); return err })
	refused(t, "upper-case digest", StagePin, func() error {
		_, _, _, err := Load(s.image, FormatImage, Pin{Bytes: s.imagePin.Bytes, SHA256: "AB" + s.imagePin.SHA256[2:]})
		return err
	})
	refused(t, "zero length", StagePin, func() error { _, _, _, err := Load(s.image, FormatImage, Pin{SHA256: s.imagePin.SHA256}); return err })
	refused(t, "missing file", StageOpen, func() error {
		_, _, _, err := Load(filepath.Join(s.dir, "absent"), FormatImage, s.imagePin)
		return err
	})
	refused(t, "a directory", StageOpen, func() error { _, _, _, err := Load(s.dir, FormatImage, s.imagePin); return err })
}

// An image that matches its pin but is structurally wrong is refused by the
// view's own checks (defence in depth: the digest is the gate).
func TestImageStructureChecks(t *testing.T) {
	s := newSetup(t)
	orig, _ := os.ReadFile(s.image)
	for name, mutate := range map[string]func([]byte) []byte{
		"magic":                func(b []byte) []byte { b[0] ^= 1; return b },
		"byte order":           func(b []byte) []byte { b[16], b[23] = b[23], b[16]; return b },
		"G1 size":              func(b []byte) []byte { b[24]++; return b },
		"header padding":       func(b []byte) []byte { b[220] = 1; return b },
		"layout fingerprint":   func(b []byte) []byte { b[120] ^= 1; return b },
		"gnark-crypto version": func(b []byte) []byte { b[176+5] ^= 1; return b },
		"version padding":      func(b []byte) []byte { b[176+30] = 'x'; return b },
		"G1.A length":          func(b []byte) []byte { b[72]++; return b },
		"huge G1.K": func(b []byte) []byte {
			copy(b[96:104], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f})
			return b
		},
		"NbInfinityA":   func(b []byte) []byte { b[48]++; return b },
		"trailing byte": func(b []byte) []byte { return append(b, 0) },
		"truncated":     func(b []byte) []byte { return b[:len(b)-1] },
		"domain length": func(b []byte) []byte { b[64]++; return b },
	} {
		b := mutate(bytes.Clone(orig))
		p := filepath.Join(s.dir, "struct-"+name)
		os.WriteFile(p, b, 0o600)
		d := sha256.Sum256(b)
		refused(t, name, StageDecode, func() error {
			_, _, _, err := Load(p, FormatImage, Pin{Bytes: int64(len(b)), SHA256: hex.EncodeToString(d[:])})
			return err
		})
	}
	// A buffer not from ReadVerified, misaligned by one byte.
	mis := make([]byte, len(orig)+64)
	off := 1
	for uintptrOf(&mis[off])%8 == 0 {
		off++
	}
	copy(mis[off:], orig)
	if err := viewImage(mis[off:off+len(orig)], new(groth16bn254.ProvingKey)); err == nil {
		t.Fatal("a misaligned image buffer was viewed")
	}
}

func TestDerive(t *testing.T) {
	s := newSetup(t)
	for _, f := range []Format{FormatImage, FormatDump} {
		out := filepath.Join(s.dir, "derived."+string(f))
		r, err := Derive(s.raw, s.rawPin, out, f)
		if err != nil {
			t.Fatal(err)
		}
		want := map[Format]Pin{FormatImage: s.imagePin, FormatDump: s.dumpPin}[f]
		if r.OutPin != want {
			t.Fatalf("derived %s pin %+v, direct write %+v: the derivation is not deterministic", f, r.OutPin, want)
		}
		// Never overwrites.
		if _, err := Derive(s.raw, s.rawPin, out, f); err == nil {
			t.Fatalf("derive overwrote %s", out)
		}
	}
}

// A Verified that ReadVerified did not make is refused before any decoder runs.
func TestDecodeRefusesAnUnverifiedBuffer(t *testing.T) {
	for name, v := range map[string]*Verified{"nil": nil, "zero value": {}} {
		for _, f := range []Format{FormatRaw, FormatDump, FormatImage} {
			refused(t, name+" "+string(f), StageUnverified, func() error { _, _, err := Decode(f, v); return err })
		}
	}
}
