package transcript

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
)

// StateBytes serializes a phase-2 state in gnark's canonical form. Its
// SHA-256 is what gnark's Phase2 hashes to, and so what the next
// contribution's Challenge must equal.
func StateBytes(p *mpcsetup.Phase2) ([]byte, error) {
	var b bytes.Buffer
	if _, err := p.WriteTo(&b); err != nil {
		return nil, failure.Wrap(failure.IO, err, "serializing phase-2 state")
	}
	return b.Bytes(), nil
}

// prefixSpans lists the byte ranges of every length prefix in p's
// serialization, and returns the total length that layout implies. The
// layout is gnark v0.16.3's Phase2.WriteTo (source unchanged from v0.15.0)
// with compressed points:
//
//	u16 nbCommitments | δ₁ | PKK | Z | δ₂ | SigmaCKK[i]… | σ₂[i]… |
//	δ proof | σ proofs… | u8 len | challenge
//
// where each slice carries a u32 big-endian length prefix, G1 points are 32
// bytes, G2 points 64 bytes and an update proof 96 bytes.
func prefixSpans(p *mpcsetup.Phase2) ([][2]int, int) {
	const g1, g2, proof = curve.SizeOfG1AffineCompressed, curve.SizeOfG2AffineCompressed, curve.SizeOfG1AffineCompressed + curve.SizeOfG2AffineCompressed
	k := len(p.Parameters.G2.Sigma)
	spans := [][2]int{{0, 2}}
	off := 2 + g1
	spans = append(spans, [2]int{off, off + 4})
	off += 4 + g1*len(p.Parameters.G1.PKK)
	spans = append(spans, [2]int{off, off + 4})
	off += 4 + g1*len(p.Parameters.G1.Z)
	off += g2
	for i := 0; i < k; i++ {
		spans = append(spans, [2]int{off, off + 4})
		off += 4 + g1*len(p.Parameters.G1.SigmaCKK[i])
	}
	off += g2 * k
	off += proof * (1 + k)
	spans = append(spans, [2]int{off, off + 1})
	off += 1 + len(p.Challenge)
	return spans, off
}

// CheckShape refuses a candidate state whose length or length prefixes differ
// from the reference state's. A valid contribution never changes the shape,
// and gnark's decoder allocates from those prefixes before reading, so this
// guard runs before any untrusted byte is decoded. It is a resource guard,
// not a soundness check.
func CheckShape(ref *mpcsetup.Phase2, refBytes, candidate []byte) error {
	spans, total := prefixSpans(ref)
	if total != len(refBytes) {
		return failure.New(failure.ContributionShape, "reference state layout model disagrees with its serialization (%d vs %d bytes)", total, len(refBytes))
	}
	if len(candidate) != len(refBytes) {
		return failure.New(failure.ContributionShape, "state is %d bytes, want %d", len(candidate), len(refBytes))
	}
	for _, s := range spans {
		if !bytes.Equal(candidate[s[0]:s[1]], refBytes[s[0]:s[1]]) {
			return failure.New(failure.ContributionShape, "length prefix at offset %d differs from the previous state", s[0])
		}
	}
	return nil
}

// DecodeState decodes a phase-2 state and refuses trailing bytes and any
// encoding that does not re-serialize to the same bytes. gnark's decoder
// checks every point is on the curve and in the subgroup.
func DecodeState(b []byte) (p *mpcsetup.Phase2, err error) {
	defer func() {
		if r := recover(); r != nil {
			p, err = nil, failure.New(failure.ContributionDecode, "decoder panicked: %v", r)
		}
	}()
	p = new(mpcsetup.Phase2)
	r := bytes.NewReader(b)
	if _, err := p.ReadFrom(r); err != nil {
		return nil, failure.Wrap(failure.ContributionDecode, err, "decoding phase-2 state")
	}
	if r.Len() != 0 {
		return nil, failure.New(failure.ContributionDecode, "%d trailing bytes after the phase-2 state", r.Len())
	}
	again, err := StateBytes(p)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, b) {
		return nil, failure.New(failure.ContributionDecode, "phase-2 state is not canonically encoded")
	}
	return p, nil
}

// InitialState runs gnark's deterministic Phase2.Initialize and places the
// root challenge in the initial state's Challenge field. It returns the state,
// its bytes and the evaluations sealing needs.
func InitialState(r1cs *cs.R1CS, commons *mpcsetup.SrsCommons, root []byte) (*mpcsetup.Phase2, []byte, *mpcsetup.Phase2Evaluations, error) {
	if len(root) != 32 {
		return nil, nil, nil, failure.New(failure.RootMismatch, "root challenge must be 32 bytes")
	}
	p := new(mpcsetup.Phase2)
	evals := p.Initialize(r1cs, commons)
	p.Challenge = append([]byte(nil), root...)
	b, err := StateBytes(p)
	if err != nil {
		return nil, nil, nil, err
	}
	return p, b, &evals, nil
}

// SealCommons returns the part of the phase-1 parameters gnark v0.16.3's
// Phase2.Seal reads: [α]₁ with the vector's length (the domain), [β]₁ and
// [β]₂. The [τⁱ]₁ and [τⁱ]₂ vectors and [βτⁱ]₁ past index 0 are left out, so
// once the caller drops c they can be freed before sealing allocates the
// proving key (about 2.5 GiB at 2^23). Nothing is replaced by another value:
// if Seal read anything left out, it would index a nil or one-element slice
// and panic, not seal different keys. TestSealCommonsSealsTheSameKeys holds
// the keys equal to a seal with the full parameters.
func SealCommons(c *mpcsetup.SrsCommons) *mpcsetup.SrsCommons {
	s := new(mpcsetup.SrsCommons)
	s.G1.AlphaTau = c.G1.AlphaTau
	s.G1.BetaTau = []curve.G1Affine{c.G1.BetaTau[0]}
	s.G2.Beta = c.G2.Beta
	return s
}

// ReadR1CS reads a gnark bn254 R1CS file and returns it with its SHA-256.
func ReadR1CS(path string) (_ *cs.R1CS, _ string, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", failure.Wrap(failure.IO, err, "reading R1CS")
	}
	defer func() {
		if p := recover(); p != nil {
			err = failure.New(failure.R1CSDecode, "decoder panicked: %v", p)
		}
	}()
	// The zero value, as gnark's groth16.NewCS builds it for reading.
	r := &cs.R1CS{}
	rd := bytes.NewReader(b)
	if _, err := r.ReadFrom(rd); err != nil {
		return nil, "", failure.Wrap(failure.R1CSDecode, err, "decoding R1CS")
	}
	if rd.Len() != 0 {
		return nil, "", failure.New(failure.R1CSDecode, "%d trailing bytes after the R1CS", rd.Len())
	}
	return r, Digest(b), nil
}

// DescribeCircuit returns the circuit record of r1cs.
func DescribeCircuit(label string, r1cs *cs.R1CS, digest string) Circuit {
	internal, secret, public := r1cs.GetNbVariables()
	return Circuit{
		Label:         label,
		R1CSSHA256:    digest,
		NbConstraints: r1cs.GetNbConstraints(),
		NbPublic:      public,
		NbSecret:      secret,
		NbInternal:    internal,
		NbCommitments: len(r1cs.CommitmentInfo.(constraint.Groth16Commitments)),
	}
}

// DomainSize is the Groth16 FFT domain gnark's own Setup would use.
func DomainSize(r1cs *cs.R1CS) uint64 {
	return ecc.NextPowerOfTwo(uint64(r1cs.GetNbConstraints()))
}

// Message types.
const (
	MessageChallenge    = "challenge"
	MessageContribution = "contribution"

	messageMagic     = "APNTCRM1"
	maxMessageHeader = 1 << 16
)

// MessageHeader is the JSON header of a challenge or contribution message.
// Local automated contributors and remote contributors exchange the same
// bytes: magic ‖ u32le(len(header)) ‖ header JSON ‖ phase-2 state.
type MessageHeader struct {
	Type                string       `json:"type"`
	Format              string       `json:"format"`
	CeremonyID          string       `json:"ceremonyId"`
	Provenance          Provenance   `json:"provenance"`
	Index               int          `json:"index"`
	PreviousStateSHA256 string       `json:"previousStateSha256,omitempty"`
	StateSHA256         string       `json:"stateSha256"`
	StateLength         int64        `json:"stateLength"`
	Contributor         *Contributor `json:"contributor,omitempty"`
}

// EncodeMessage frames a header and a state.
func EncodeMessage(h MessageHeader, state []byte) ([]byte, error) {
	hb, err := json.Marshal(h)
	if err != nil {
		return nil, failure.Wrap(failure.MessageMalformed, err, "encoding message header")
	}
	out := make([]byte, 0, len(messageMagic)+4+len(hb)+len(state))
	out = append(out, messageMagic...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(hb)))
	out = append(out, hb...)
	return append(out, state...), nil
}

// DecodeMessage parses a framed message and checks the state's length and
// digest against its header.
func DecodeMessage(b []byte) (MessageHeader, []byte, error) {
	var h MessageHeader
	if len(b) < len(messageMagic)+4 || string(b[:len(messageMagic)]) != messageMagic {
		return h, nil, failure.New(failure.MessageMalformed, "not a ceremony message")
	}
	n := binary.LittleEndian.Uint32(b[len(messageMagic):])
	rest := b[len(messageMagic)+4:]
	if n > maxMessageHeader || int(n) > len(rest) {
		return h, nil, failure.New(failure.MessageMalformed, "bad header length %d", n)
	}
	if err := decodeStrict(rest[:n], &h, failure.MessageMalformed, "message header"); err != nil {
		return h, nil, err
	}
	if h.Format != Format {
		return h, nil, failure.New(failure.MessageMalformed, "message format %q, want %q", h.Format, Format)
	}
	state := rest[n:]
	if int64(len(state)) != h.StateLength {
		return h, nil, failure.New(failure.MessageMalformed, "state is %d bytes, header says %d", len(state), h.StateLength)
	}
	if Digest(state) != h.StateSHA256 {
		return h, nil, failure.New(failure.MessageDigestMismatch, "state digest does not match the message header")
	}
	return h, state, nil
}
