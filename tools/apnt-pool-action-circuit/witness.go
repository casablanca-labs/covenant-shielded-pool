package poolaction

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// Corpus is the host-derived parity corpus
// (packages/protocol-runtime/test-vectors/apnt-pool-v1-action-circuit-vectors.json).
type Corpus struct {
	Description          string        `json:"description"`
	HostRelationIdentity string        `json:"hostRelationIdentity"`
	Encoding             string        `json:"encoding"`
	Entries              []CorpusEntry `json:"entries"`
}

type CorpusEntry struct {
	Name            string         `json:"name"`
	Kind            string         `json:"kind"`
	HostFailureCode *string        `json:"hostFailureCode"`
	Representable   bool           `json:"representable"`
	Note            string         `json:"note"`
	Record          *string        `json:"record"`
	Witness         *CorpusWitness `json:"witness"`
}

type CorpusWitness struct {
	Inputs  [2]CorpusInput  `json:"inputs"`
	Outputs [2]CorpusOutput `json:"outputs"`
}

// UnmarshalJSON keeps the shared witness decoder closed and refuses array
// truncation/zero padding by encoding/json's fixed-size array decoder.
func (w *CorpusWitness) UnmarshalJSON(raw []byte) error {
	var v struct {
		Inputs  []CorpusInput  `json:"inputs"`
		Outputs []CorpusOutput `json:"outputs"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&v); err != nil {
		return err
	}
	if len(v.Inputs) != 2 || len(v.Outputs) != 2 {
		return fmt.Errorf("witness requires two inputs and two outputs")
	}
	copy(w.Inputs[:], v.Inputs)
	copy(w.Outputs[:], v.Outputs)
	return nil
}

type CorpusInput struct {
	ValueSats              string          `json:"valueSats"`
	SpendKey33             string          `json:"spendKey33"`
	NullifierKey32         string          `json:"nullifierKey32"`
	Rho32                  string          `json:"rho32"`
	CommitmentRandomness32 string          `json:"commitmentRandomness32"`
	RecoveryTag32          string          `json:"recoveryTag32"`
	Rerandomizer           string          `json:"rerandomizer"`
	Membership             *CorpusMemberOf `json:"membership"`
}

type CorpusMemberOf struct {
	Position uint64   `json:"position"`
	Siblings []string `json:"siblings"`
}

// CorpusOutput is an output witness: no rcm, which the relation derives from
// K and ρ (revision 3, pad16). The strict decoder refuses an output carrying one.
type CorpusOutput struct {
	ValueSats     string `json:"valueSats"`
	OwnerTag32    string `json:"ownerTag32"`
	Rho32         string `json:"rho32"`
	RecoveryKey32 string `json:"recoveryKey32"`
}

// LoadCorpus reads and strictly decodes the corpus.
func LoadCorpus(path string) (*Corpus, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return DecodeCorpus(raw)
}

// DecodeCorpus is the shared strict decoder for corpus and live wallet bytes.
func DecodeCorpus(raw []byte) (*Corpus, error) {
	var c Corpus
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("decode corpus: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("decode corpus: trailing data")
	}
	if c.HostRelationIdentity != "apnt-pool-action-host-rel-v1" {
		return nil, fmt.Errorf("unexpected host relation %q", c.HostRelationIdentity)
	}
	return &c, nil
}

// ---- secp256k1 over math/big (assignment only; nothing here is in-circuit) ----

var (
	secpP, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	secpN, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secpGx, _ = new(big.Int).SetString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16)
	secpGy, _ = new(big.Int).SetString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16)
)

// Decompress returns (x, y) of a SEC1-compressed secp256k1 point, or ok =
// false when the bytes are not one.
func Decompress(b []byte) (x, y *big.Int, ok bool) {
	if len(b) != 33 || (b[0] != 0x02 && b[0] != 0x03) {
		return nil, nil, false
	}
	x = new(big.Int).SetBytes(b[1:])
	if x.Cmp(secpP) >= 0 {
		return nil, nil, false
	}
	rhs := new(big.Int).Exp(x, big.NewInt(3), secpP)
	rhs.Add(rhs, big.NewInt(7)).Mod(rhs, secpP)
	y = new(big.Int).ModSqrt(rhs, secpP)
	if y == nil {
		return nil, nil, false
	}
	if y.Bit(0) != uint(b[0]&1) {
		y.Sub(secpP, y)
	}
	return x, y, true
}

// ---- assignment ----

func mustHex(s string, n int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if n >= 0 && len(b) != n {
		return nil, fmt.Errorf("expected %d bytes, got %d", n, len(b))
	}
	return b, nil
}

func u8s(b []byte) []uints.U8 { return uints.NewU8Array(b) }

func copy32(dst *[32]uints.U8, s string) error {
	b, err := mustHex(s, 32)
	if err != nil {
		return err
	}
	copy(dst[:], u8s(b))
	return nil
}

var two64 = new(big.Int).Lsh(big.NewInt(1), 64)

// valueBytes is the circuit's u64le value. A host value in [0, 2^64) is its
// u64le encoding. A value ≥ 2^64 (the host's field-wrap negatives) has no
// u64le encoding; its circuit form keeps the low seven bytes and puts
// v >> 56 in the top "byte", which the byte range checks must refuse. That
// top element must be below the BN254 modulus: nothing is reduced silently.
func valueBytes(dst *[8]uints.U8, decimal string) error {
	v, ok := new(big.Int).SetString(decimal, 10)
	if !ok {
		return fmt.Errorf("value %q", decimal)
	}
	if v.Sign() < 0 {
		return fmt.Errorf("negative value has no circuit form")
	}
	rest := new(big.Int).Set(v)
	for i := 0; i < 7; i++ {
		dst[i] = uints.U8{Val: new(big.Int).And(rest, big.NewInt(0xff))}
		rest.Rsh(rest, 8)
	}
	if rest.Cmp(bn254Modulus) >= 0 {
		return fmt.Errorf("value top element not below the BN254 modulus")
	}
	dst[7] = uints.U8{Val: rest}
	return nil
}

// limbs splits a non-negative integer below 2^256 into gnark's four 64-bit
// emulated limbs without reducing it modulo the emulated field, so an
// out-of-range α (for example n_G itself) reaches the circuit as is. A
// negative integer, which has no limb form, is represented by its native-field
// negation in limb 0 (limb width checks must refuse it).
func limbs(v *big.Int) ([]frontend.Variable, error) {
	if v.Sign() < 0 {
		neg := new(big.Int).Add(bn254Modulus, v)
		if neg.Sign() < 0 {
			return nil, fmt.Errorf("negative value below -r")
		}
		return []frontend.Variable{neg, big.NewInt(0), big.NewInt(0), big.NewInt(0)}, nil
	}
	if v.BitLen() > 256 {
		return nil, fmt.Errorf("value wider than 256 bits")
	}
	out := make([]frontend.Variable, 4)
	mask := new(big.Int).Sub(two64, big.NewInt(1))
	rest := new(big.Int).Set(v)
	for i := range out {
		out[i] = new(big.Int).And(rest, mask)
		rest.Rsh(rest, 64)
	}
	return out, nil
}

func fpElement(v *big.Int) (emulated.Element[Fp], error) {
	l, err := limbs(v)
	return emulated.Element[Fp]{Limbs: l}, err
}

func frElement(v *big.Int) (emulated.Element[Fr], error) {
	l, err := limbs(v)
	return emulated.Element[Fr]{Limbs: l}, err
}

// SpendKeyCoordinates maps the host's 33-byte ak to circuit coordinates. A
// valid point decompresses. Bytes that are not a point have no curve
// coordinates; the circuit form keeps their x and takes the smallest nonzero y
// of the stated parity (1 odd, 2 even), which is off the curve and never
// gnark's (0,0) infinity encoding.
func SpendKeyCoordinates(b []byte) (x, y *big.Int, onCurve bool) {
	if px, py, ok := Decompress(b); ok {
		return px, py, true
	}
	x = new(big.Int).SetBytes(b[1:])
	if b[0]&1 == 1 {
		return x, big.NewInt(1), false
	}
	return x, big.NewInt(2), false
}

// Assignment builds the full circuit assignment of a representable entry. Its
// public input is the honest x of the entry's own record, so a refusal comes
// from the relation, never from a disagreement between x and A.
func (e *CorpusEntry) Assignment() (*ActionCircuit, error) {
	if !e.Representable || e.Record == nil || e.Witness == nil {
		return nil, fmt.Errorf("%s: not representable", e.Name)
	}
	record, err := mustHex(*e.Record, RecordBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: record: %w", e.Name, err)
	}
	var c ActionCircuit
	copy(c.Record[:], u8s(record))
	if c.RecordHash, err = PublicInput(record); err != nil {
		return nil, fmt.Errorf("%s: public input: %w", e.Name, err)
	}
	for s, in := range e.Witness.Inputs {
		slot := &c.In[s]
		if err := valueBytes(&slot.Value, in.ValueSats); err != nil {
			return nil, fmt.Errorf("%s: input %d: %w", e.Name, s, err)
		}
		ak, err := mustHex(in.SpendKey33, 33)
		if err != nil {
			return nil, err
		}
		x, y, _ := SpendKeyCoordinates(ak)
		if slot.AkX, err = fpElement(x); err != nil {
			return nil, err
		}
		if slot.AkY, err = fpElement(y); err != nil {
			return nil, err
		}
		for _, f := range []struct {
			dst *[32]uints.U8
			src string
		}{{&slot.Nk, in.NullifierKey32}, {&slot.Rho, in.Rho32}, {&slot.Rcm, in.CommitmentRandomness32}, {&slot.RecoveryTag, in.RecoveryTag32}} {
			if err := copy32(f.dst, f.src); err != nil {
				return nil, fmt.Errorf("%s: input %d: %w", e.Name, s, err)
			}
		}
		alpha, ok := new(big.Int).SetString(in.Rerandomizer, 10)
		if !ok {
			return nil, fmt.Errorf("%s: rerandomizer %q", e.Name, in.Rerandomizer)
		}
		if slot.Alpha, err = frElement(alpha); err != nil {
			return nil, err
		}
		for h := 0; h < TreeDepth; h++ {
			slot.PositionBits[h] = 0
			for i := range slot.Siblings[h] {
				slot.Siblings[h][i] = uints.NewU8(0)
			}
		}
		if in.Membership != nil {
			if len(in.Membership.Siblings) != TreeDepth || in.Membership.Position >= 1<<TreeDepth {
				return nil, fmt.Errorf("%s: membership shape", e.Name)
			}
			for h := 0; h < TreeDepth; h++ {
				slot.PositionBits[h] = (in.Membership.Position >> h) & 1
				if err := copy32(&slot.Siblings[h], in.Membership.Siblings[h]); err != nil {
					return nil, err
				}
			}
		}
	}
	for j, out := range e.Witness.Outputs {
		slot := &c.Out[j]
		if err := valueBytes(&slot.Value, out.ValueSats); err != nil {
			return nil, fmt.Errorf("%s: output %d: %w", e.Name, j, err)
		}
		for _, f := range []struct {
			dst *[32]uints.U8
			src string
		}{{&slot.OwnerTag, out.OwnerTag32}, {&slot.Rho, out.Rho32}, {&slot.RecoveryKey, out.RecoveryKey32}} {
			if err := copy32(f.dst, f.src); err != nil {
				return nil, fmt.Errorf("%s: output %d: %w", e.Name, j, err)
			}
		}
	}
	return &c, nil
}
