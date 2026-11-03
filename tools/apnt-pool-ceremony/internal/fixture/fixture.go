// Package fixture builds test inputs: INSECURE deterministic phase-1 files
// and test-circuit R1CS files. Test use only.
package fixture

import (
	"encoding/binary"
	"math/bits"
	"os"
	"path/filepath"
	"testing"

	cs "github.com/consensys/gnark/constraint/bn254"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/testcircuits"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

// Toy secret scalars. Public, so the fixture is insecure by construction.
const (
	ToyTau   = 7
	ToyAlpha = 11
	ToyBeta  = 13
)

// Ptau writes a toy .ptau file of the given power and returns its path and
// SHA-256 pin.
func Ptau(t testing.TB, dir string, power uint32) (string, ptau.Pin) {
	t.Helper()
	return PtauWith(t, dir, power, ToyTau, ToyAlpha, ToyBeta)
}

// PtauWith is Ptau with chosen scalars.
func PtauWith(t testing.TB, dir string, power uint32, tau, alpha, beta uint64) (string, ptau.Pin) {
	t.Helper()
	path := filepath.Join(dir, "toy-"+itoa(int(power))+"-"+itoa(int(tau))+".ptau")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ptau.Write(f, ptau.ToyCommons(power, tau, alpha, beta)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path, PinOf(t, path)
}

// PinOf returns the SHA-256 pin of a file.
func PinOf(t testing.TB, path string) ptau.Pin {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sha, _, _, err := ptau.HashFile(f)
	if err != nil {
		t.Fatal(err)
	}
	return ptau.Pin{Algorithm: ptau.AlgSHA256, Digest: sha}
}

// R1CS compiles a test circuit, writes it and returns the path and system.
func R1CS(t testing.TB, dir, name string, size int) (string, *cs.R1CS) {
	t.Helper()
	r, err := testcircuits.Compile(name, size)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+"-"+itoa(size)+".r1cs")
	if err := testcircuits.WriteR1CS(path, r); err != nil {
		t.Fatal(err)
	}
	return path, r
}

// Power returns log2 of the circuit's domain.
func Power(r *cs.R1CS) uint32 {
	return uint32(bits.TrailingZeros64(transcript.DomainSize(r)))
}

// Beacon is a fixed 32-byte test beacon.
var Beacon = transcript.Beacon{
	Value:  "a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00",
	Source: "fixed test beacon (not a public randomness source)",
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// MoveSectionFirst returns a copy of the .ptau bytes b with the section of
// type typ moved, intact, to the front of the section table. Section contents
// and count are unchanged; only their order differs.
func MoveSectionFirst(t testing.TB, b []byte, typ uint32) []byte {
	t.Helper()
	n := binary.LittleEndian.Uint32(b[8:12])
	var moved []byte
	var rest []byte
	pos := 12
	for s := uint32(0); s < n; s++ {
		sz := int(binary.LittleEndian.Uint64(b[pos+4 : pos+12]))
		sec := b[pos : pos+12+sz]
		if binary.LittleEndian.Uint32(b[pos:pos+4]) == typ && moved == nil {
			moved = sec
		} else {
			rest = append(rest, sec...)
		}
		pos += 12 + sz
	}
	if pos != len(b) || moved == nil {
		t.Fatalf("MoveSectionFirst: section %d not found or bad layout", typ)
	}
	out := append(append([]byte(nil), b[:12]...), moved...)
	return append(out, rest...)
}
