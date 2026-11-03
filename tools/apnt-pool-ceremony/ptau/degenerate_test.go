package ptau_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
)

// ENG-440 negative controls (ARCH-238): phase-1 files whose every point is
// valid and whose vectors are powers of one τ, α and β, but whose τ or β is
// degenerate. Before ENG-440 the importer accepted both.

func frOf(v uint64) fr.Element {
	var e fr.Element
	e.SetUint64(v)
	return e
}

func toyFrBytes(t *testing.T, power uint32, tau, alpha, beta fr.Element) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := ptau.Write(&b, ptau.ToyCommonsFr(power, tau, alpha, beta)); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// τ a primitive N-th root of unity, in a file of power log₂N + 1: t(τ) =
// τᴺ − 1 = 0 on the domain of size N and on the file's whole domain 2N, so
// the importer refuses both. On the domain N/2, τ^(N/2) = −1 and t(τ) ≠ 0, so
// the same file is accepted there: the check is t(τ) for the domain asked for.
func TestImportRefusesTauInDomain(t *testing.T) {
	for p := uint32(1); p <= 4; p++ {
		n := uint64(1) << p
		omega := fft.NewDomain(n).Generator
		b := toyFrBytes(t, p+1, omega, frOf(11), frOf(13))
		pin := pinOf(t, b)
		for _, domain := range []uint64{n, 2 * n} {
			t.Run(fmt.Sprintf("τ=ω_%d/domain=%d/refused", n, domain), func(t *testing.T) {
				_, _, err := ptau.Import(bytes.NewReader(b), pin, domain)
				wantCode(t, err, failure.Phase1TauInDomain)
			})
		}
		if n/2 >= 2 {
			t.Run(fmt.Sprintf("τ=ω_%d/domain=%d/accepted", n, n/2), func(t *testing.T) {
				if _, _, err := ptau.Import(bytes.NewReader(b), pin, n/2); err != nil {
					t.Fatalf("τ^%d = −1: %v", n/2, err)
				}
			})
		}
	}
	// τ = −1 = ω₂ is a root of unity of every domain.
	var minusOne fr.Element
	minusOne.SetOne()
	minusOne.Neg(&minusOne)
	b := toyFrBytes(t, 3, minusOne, frOf(11), frOf(13))
	for _, domain := range []uint64{2, 4, 8} {
		t.Run(fmt.Sprintf("τ=−1/domain=%d/refused", domain), func(t *testing.T) {
			_, _, err := ptau.Import(bytes.NewReader(b), pinOf(t, b), domain)
			wantCode(t, err, failure.Phase1TauInDomain)
		})
	}
}

// β = −1 is refused at every domain; β = −2 and β = 1, the values beside it,
// are accepted.
func TestImportRefusesBetaMinusOne(t *testing.T) {
	var minusOne, minusTwo fr.Element
	minusOne.SetOne()
	minusOne.Neg(&minusOne)
	minusTwo.Double(&minusOne)
	b := toyFrBytes(t, 4, frOf(7), frOf(11), minusOne)
	for _, domain := range []uint64{2, 16} {
		t.Run(fmt.Sprintf("β=−1/domain=%d/refused", domain), func(t *testing.T) {
			_, _, err := ptau.Import(bytes.NewReader(b), pinOf(t, b), domain)
			wantCode(t, err, failure.Phase1BetaMinusOne)
		})
	}
	for name, beta := range map[string]fr.Element{"β=−2": minusTwo, "β=1": frOf(1)} {
		t.Run(name+"/accepted", func(t *testing.T) {
			b := toyFrBytes(t, 4, frOf(7), frOf(11), beta)
			if _, _, err := ptau.Import(bytes.NewReader(b), pinOf(t, b), 16); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// ToyCommons is ToyCommonsFr on the same scalars.
func TestToyCommonsFrMatchesToyCommons(t *testing.T) {
	a, err := ptau.CommonsDigest(ptau.ToyCommons(5, 7, 11, 13))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ptau.CommonsDigest(ptau.ToyCommonsFr(5, frOf(7), frOf(11), frOf(13)))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("ToyCommonsFr differs from ToyCommons on the same scalars")
	}
}
