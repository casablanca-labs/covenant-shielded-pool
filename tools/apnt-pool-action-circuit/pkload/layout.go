package pkload

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"runtime/debug"
	"unsafe"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	poolaction "github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit"
)

// An image is the key's points as this build holds them in memory, cast in
// place on load, so a reader must hold them exactly as the writer did. Type
// sizes and byte order (checked in the header) are not enough: a gnark-crypto
// release could keep every size and change the field order within an affine
// point, the limb order, or the Montgomery form. The header therefore carries
// a layout fingerprint computed at run time from known points, and the gnark
// and gnark-crypto versions; the reader refuses any image whose fingerprint
// or versions differ from its own build's (ENG-435 F1).

// layoutDesc is how this build lays out what an image casts: the sizes and
// field offsets of the point types, and the in-memory bytes of fixed values.
type layoutDesc struct {
	shape  []uint64
	values [][]byte
}

func bytesOf[T any](p *T) []byte {
	return append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(p)), unsafe.Sizeof(*p))...)
}

// runtimeLayoutDesc is this build's layout. The reference values are the G1
// and G2 generators, twice the G1 generator, and fp's one, whose in-memory
// bytes change with the field order of an affine point, the order of an E2's
// coefficients, the limb order and the Montgomery form.
func runtimeLayoutDesc() layoutDesc {
	_, _, g1, g2 := curve.Generators()
	var g1x2 curve.G1Affine
	g1x2.ScalarMultiplication(&g1, big.NewInt(2))
	var one fp.Element
	one.SetOne()
	var p1 curve.G1Affine
	var p2 curve.G2Affine
	return layoutDesc{
		shape: []uint64{
			uint64(unsafe.Sizeof(p1)), uint64(unsafe.Offsetof(p1.X)), uint64(unsafe.Offsetof(p1.Y)),
			uint64(unsafe.Sizeof(p2)), uint64(unsafe.Offsetof(p2.X)), uint64(unsafe.Offsetof(p2.Y)),
			uint64(unsafe.Offsetof(p2.X.A0)), uint64(unsafe.Offsetof(p2.X.A1)),
			uint64(unsafe.Sizeof(one)), uint64(unsafe.Sizeof(fr.Element{})),
		},
		values: [][]byte{bytesOf(&g1), bytesOf(&g1x2), bytesOf(&g2), bytesOf(&one)},
	}
}

func (d layoutDesc) fingerprint() [32]byte {
	h := sha256.New()
	h.Write([]byte("APNT-PK-IMAGE layout fingerprint v1\x00"))
	var b [8]byte
	put := func(v uint64) { binary.LittleEndian.PutUint64(b[:], v); h.Write(b[:]) }
	put(uint64(len(d.shape)))
	for _, v := range d.shape {
		put(v)
	}
	put(uint64(len(d.values)))
	for _, v := range d.values {
		put(uint64(len(v)))
		h.Write(v)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// runtimeLayout and runtimeVersions describe the running build. They are
// unexported variables only so that this package's tests can play a build
// with another layout or other module versions, and can give go test
// binaries, which carry no dependency records, a record source (see
// TestMain); nothing outside the tests assigns them, and the wallet API
// cannot reach them.
var (
	runtimeLayout   = func() [32]byte { return runtimeLayoutDesc().fingerprint() }
	runtimeVersions = linkedVersions
)

const (
	gnarkModule       = "github.com/consensys/gnark"
	gnarkCryptoModule = "github.com/consensys/gnark-crypto"
	versionField      = 32
)

// The refusals of moduleVersions. Each has its own error so that a caller or
// test can tell them apart with errors.Is.
var (
	ErrNoBuildInfo    = errors.New("the binary carries no module build info, so the gnark and gnark-crypto it links cannot be verified")
	ErrModuleMissing  = errors.New("the binary's build info has no record of a module the image format is bound to")
	ErrModuleReplaced = errors.New("the binary replaces a module the image format is bound to")
	ErrModuleVersion  = errors.New("the binary links another version of a module the image format is bound to")
)

// linkedVersions is the gnark and gnark-crypto versions this build links,
// from its own module build info. It fails closed (moduleVersions): a binary
// without affirmative, unreplaced records of both modules at the registry's
// versions cannot read or write images. go build records them; go test
// binaries list no dependencies and are refused.
func linkedVersions() (gnark, crypto string, err error) {
	return moduleVersions(debug.ReadBuildInfo())
}

// moduleVersions decides, from a build's module records alone, whether it
// links exactly the gnark and gnark-crypto versions the registry names (held
// equal to go.mod by TestGnarkVersionsMatchGoMod). It requires an affirmative
// record of each module, with Replace == nil and Version equal to the
// registry's, and refuses absent build info (ErrNoBuildInfo), a missing
// module (ErrModuleMissing), a replaced module (ErrModuleReplaced) and another
// version (ErrModuleVersion). Nothing is assumed for a record that is absent.
func moduleVersions(bi *debug.BuildInfo, ok bool) (gnark, crypto string, err error) {
	if !ok || bi == nil {
		return "", "", ErrNoBuildInfo
	}
	want := []struct{ path, version string }{
		{gnarkModule, poolaction.GnarkVersion},
		{gnarkCryptoModule, poolaction.GnarkCryptoVersion},
	}
	for _, w := range want {
		var rec *debug.Module
		for _, d := range bi.Deps {
			if d != nil && d.Path == w.path {
				if rec != nil {
					return "", "", fmt.Errorf("%w: %s is recorded twice", ErrModuleVersion, w.path)
				}
				rec = d
			}
		}
		switch {
		case rec == nil:
			return "", "", fmt.Errorf("%w: %s", ErrModuleMissing, w.path)
		case rec.Replace != nil:
			return "", "", fmt.Errorf("%w: %s %s => %s %s", ErrModuleReplaced, w.path, rec.Version, rec.Replace.Path, rec.Replace.Version)
		case rec.Version != w.version:
			return "", "", fmt.Errorf("%w: %s %s, the image format is bound to %s", ErrModuleVersion, w.path, rec.Version, w.version)
		}
	}
	return want[0].version, want[1].version, nil
}

// putVersion writes v into a NUL-padded field.
func putVersion(field []byte, v string) error {
	if len(v) == 0 || len(v) > len(field) {
		return fmt.Errorf("version %q does not fit a %d-byte field", v, len(field))
	}
	copy(field, v)
	return nil
}

// getVersion reads a NUL-padded field, refusing anything but a string
// followed only by NULs.
func getVersion(field []byte) (string, error) {
	n := 0
	for n < len(field) && field[n] != 0 {
		n++
	}
	if n == 0 || !isZero(field[n:]) {
		return "", fmt.Errorf("malformed version field %q", field)
	}
	return string(field[:n]), nil
}
