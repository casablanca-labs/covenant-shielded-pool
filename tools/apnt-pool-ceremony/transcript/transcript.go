// Package transcript defines the ceremony transcript, the contribution
// message format and the derivations both the coordinator and the
// standalone verifier compute. Both sides run this same code, so a defect
// here is common to them. It holds no coordinator state.
package transcript

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
)

const (
	Format            = "apnt-pool-ceremony-transcript/v1"
	KeyMetadataFormat = "apnt-pool-ceremony-keys/v1"

	StatusOpen   = "open"
	StatusSealed = "sealed"

	// Key encodings: the proving key in gnark's raw form (fast to load), the
	// verifying key in gnark's compressed form.
	ProvingKeyEncoding   = "gnark-v0.16.3-groth16-bn254-WriteRawTo"
	VerifyingKeyEncoding = "gnark-v0.16.3-groth16-bn254-WriteTo"

	TranscriptFile   = "transcript.json"
	ProvingKeyFile   = "proving.key"
	VerifyingKeyFile = "verifying.key"
	KeyMetadataFile  = "keys.meta.json"

	rootDomain = "APNT-POOL-v1:ceremony-root"

	// MinBeaconBytes: a beacon is at least one 32-byte block hash or drand round.
	MinBeaconBytes = 32
)

// Tool records the implementation the ceremony ran on.
type Tool struct {
	Name        string `json:"name"`
	Gnark       string `json:"gnark"`
	GnarkCrypto string `json:"gnarkCrypto"`
	Curve       string `json:"curve"`
	Backend     string `json:"backend"`
}

// CurrentTool is this build's tool record. TestToolRecordMatchesGoMod holds
// its versions equal to this module's go.mod and to the pool action circuit
// module's, whose R1CS phase 2 takes.
var CurrentTool = Tool{
	Name:        "apnt-pool-ceremony",
	Gnark:       "v0.16.3",
	GnarkCrypto: "v0.21.0",
	Curve:       "bn254",
	Backend:     "groth16",
}

// Phase1 records the Powers of Tau input.
type Phase1 struct {
	Source        string   `json:"source"`
	File          string   `json:"file"`
	FileSize      int64    `json:"fileSize"`
	Pin           ptau.Pin `json:"pin"`
	Power         uint32   `json:"power"`
	DomainSize    uint64   `json:"domainSize"`
	CommonsSHA256 string   `json:"commonsSha256"`
}

// Circuit records the R1CS the ceremony is for.
type Circuit struct {
	Label         string `json:"label"`
	R1CSSHA256    string `json:"r1csSha256"`
	NbConstraints int    `json:"nbConstraints"`
	NbPublic      int    `json:"nbPublic"`
	NbSecret      int    `json:"nbSecret"`
	NbInternal    int    `json:"nbInternal"`
	NbCommitments int    `json:"nbCommitments"`
}

// Contribution is one accepted phase-2 contribution.
type Contribution struct {
	Index int `json:"index"`
	// File holds the phase-2 state after this contribution, in gnark's
	// Phase2.WriteTo form, relative to the transcript's directory.
	File        string `json:"file"`
	StateSHA256 string `json:"stateSha256"`
	// Challenge is the SHA-256 of the previous state: gnark's Phase2.Challenge,
	// which the contribution's proofs of knowledge are bound to.
	Challenge   string      `json:"challenge"`
	Contributor Contributor `json:"contributor"`
}

// Phase2Record records the circuit-specific phase.
type Phase2Record struct {
	RootChallenge      string         `json:"rootChallenge"`
	InitialStateSHA256 string         `json:"initialStateSha256"`
	StateLength        int64          `json:"stateLength"`
	Contributions      []Contribution `json:"contributions"`
}

// Beacon is the public randomness applied at sealing. Value is the exact byte
// string used, as hex; for a BCH block hash, Source must say which height and
// which byte order (display order, as block explorers and getblockhash show it).
type Beacon struct {
	Value  string `json:"value"`
	Source string `json:"source"`
}

// KeyFile is one key file and its digest.
type KeyFile struct {
	File     string `json:"file"`
	SHA256   string `json:"sha256"`
	Encoding string `json:"encoding"`
}

// Keys are the sealed outputs.
type Keys struct {
	ProvingKey   KeyFile `json:"provingKey"`
	VerifyingKey KeyFile `json:"verifyingKey"`
	Metadata     string  `json:"metadata"`
}

// Transcript is the whole record of one ceremony, from phase 1 to the sealed
// keys. Everything in it except the contributions' randomness is public and
// re-derivable by the verifier.
type Transcript struct {
	Format        string       `json:"format"`
	Status        string       `json:"status"`
	CeremonyID    string       `json:"ceremonyId"`
	Provenance    Provenance   `json:"provenance"`
	ZeroValueOnly bool         `json:"zeroValueOnly"`
	Notice        string       `json:"notice"`
	Tool          Tool         `json:"tool"`
	Phase1        Phase1       `json:"phase1"`
	Circuit       Circuit      `json:"circuit"`
	Phase2        Phase2Record `json:"phase2"`
	Beacon        *Beacon      `json:"beacon,omitempty"`
	Keys          *Keys        `json:"keys,omitempty"`
}

// KeyMetadata travels next to the key files and carries the provenance label.
type KeyMetadata struct {
	Format             string     `json:"format"`
	CeremonyID         string     `json:"ceremonyId"`
	Provenance         Provenance `json:"provenance"`
	ZeroValueOnly      bool       `json:"zeroValueOnly"`
	Notice             string     `json:"notice"`
	CircuitLabel       string     `json:"circuitLabel"`
	R1CSSHA256         string     `json:"r1csSha256"`
	Phase1Pin          ptau.Pin   `json:"phase1Pin"`
	BeaconValue        string     `json:"beaconValue"`
	ProvingKeySHA256   string     `json:"provingKeySha256"`
	VerifyingKeySHA256 string     `json:"verifyingKeySha256"`
	Contributions      int        `json:"contributions"`
}

// MetadataFor derives the key metadata a sealed transcript implies.
func MetadataFor(t *Transcript) KeyMetadata {
	return KeyMetadata{
		Format:             KeyMetadataFormat,
		CeremonyID:         t.CeremonyID,
		Provenance:         t.Provenance,
		ZeroValueOnly:      t.ZeroValueOnly,
		Notice:             t.Notice,
		CircuitLabel:       t.Circuit.Label,
		R1CSSHA256:         t.Circuit.R1CSSHA256,
		Phase1Pin:          t.Phase1.Pin,
		BeaconValue:        t.Beacon.Value,
		ProvingKeySHA256:   t.Keys.ProvingKey.SHA256,
		VerifyingKeySHA256: t.Keys.VerifyingKey.SHA256,
		Contributions:      len(t.Phase2.Contributions),
	}
}

// Digest returns the lowercase hex SHA-256 of b.
func Digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// DigestWriterTo returns the lowercase hex SHA-256 of what write writes,
// without holding it.
func DigestWriterTo(write func(io.Writer) (int64, error)) (string, error) {
	h := sha256.New()
	if _, err := write(h); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// DigestFile returns the lowercase hex SHA-256 of a file, read as a stream.
func DigestFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func decodeDigest(name, h string) ([]byte, error) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != sha256.Size || hex.EncodeToString(b) != h {
		return nil, failure.New(failure.TranscriptFormat, "%s is not a lowercase SHA-256 hex digest", name)
	}
	return b, nil
}

// RootChallenge derives the value placed in the initial phase-2 state's
// Challenge field. gnark hashes that field into the initial state, so the
// first contribution's proofs of knowledge — and through the challenge chain
// every later one — are bound to the transcript format, the ceremony id, the
// provenance label, the phase-1 parameters and the R1CS. Contributions made
// under one label can never verify under another.
//
//	SHA-256("APNT-POOL-v1:ceremony-root" ‖ lp(format) ‖ lp(ceremonyId) ‖
//	        lp(provenance) ‖ commonsSha256 ‖ r1csSha256)
//
// with lp(x) = u16le(len(x)) ‖ x and both digests as 32 raw bytes.
func RootChallenge(ceremonyID string, p Provenance, commonsSHA256, r1csSHA256 string) ([]byte, error) {
	commons, err := decodeDigest("commonsSha256", commonsSHA256)
	if err != nil {
		return nil, err
	}
	r1cs, err := decodeDigest("r1csSha256", r1csSHA256)
	if err != nil {
		return nil, err
	}
	if len(ceremonyID) == 0 || len(ceremonyID) > 128 {
		return nil, failure.New(failure.TranscriptFormat, "ceremony id must be 1..128 bytes")
	}
	h := sha256.New()
	h.Write([]byte(rootDomain))
	for _, s := range []string{Format, ceremonyID, string(p)} {
		var l [2]byte
		binary.LittleEndian.PutUint16(l[:], uint16(len(s)))
		h.Write(l[:])
		h.Write([]byte(s))
	}
	h.Write(commons)
	h.Write(r1cs)
	return h.Sum(nil), nil
}

// Load reads a transcript strictly: unknown fields are refused.
func Load(path string) (*Transcript, error) {
	t, _, err := LoadDigest(path)
	return t, err
}

// LoadDigest is Load that also returns the SHA-256 of exactly the bytes it
// parsed: the file is read once, and those bytes are both hashed and decoded.
func LoadDigest(path string) (*Transcript, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", failure.Wrap(failure.IO, err, "reading transcript")
	}
	var t Transcript
	if err := decodeStrict(b, &t, failure.TranscriptFormat, "transcript"); err != nil {
		return nil, "", err
	}
	if t.Format != Format {
		return nil, "", failure.New(failure.TranscriptFormat, "format %q, want %q", t.Format, Format)
	}
	return &t, Digest(b), nil
}

// LoadKeyMetadata reads a key metadata file strictly.
func LoadKeyMetadata(path string) (*KeyMetadata, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, failure.Wrap(failure.IO, err, "reading key metadata")
	}
	var m KeyMetadata
	if err := decodeStrict(b, &m, failure.KeyMetadataMalformed, "key metadata"); err != nil {
		return nil, err
	}
	return &m, nil
}

// DecodeStrict is decodeStrict for other packages' records.
func DecodeStrict(b []byte, v any, code failure.Code, what string) error {
	return decodeStrict(b, v, code, what)
}

// decodeStrict decodes b as exactly one JSON value with no unknown fields.
// Only whitespace may follow it: a second value, or a stray closing bracket
// that json.Decoder.More would not report, is refused with code.
func decodeStrict(b []byte, v any, code failure.Code, what string) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return failure.Wrap(code, err, "decoding %s", what)
	}
	if _, err := dec.Token(); err != io.EOF {
		return failure.New(code, "trailing data after the %s", what)
	}
	return nil
}

// WriteJSON writes v as indented JSON with a trailing newline.
func WriteJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return failure.Wrap(failure.IO, err, "encoding %s", path)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		return failure.Wrap(failure.IO, err, "writing %s", path)
	}
	return nil
}

// DecodeBeacon checks a beacon record and returns its bytes.
func DecodeBeacon(b Beacon) ([]byte, error) {
	v, err := hex.DecodeString(b.Value)
	if err != nil || hex.EncodeToString(v) != b.Value {
		return nil, failure.New(failure.BeaconInvalid, "beacon value is not lowercase hex")
	}
	if len(v) < MinBeaconBytes || len(v) > 255 {
		return nil, failure.New(failure.BeaconInvalid, "beacon is %d bytes, want %d..255", len(v), MinBeaconBytes)
	}
	if b.Source == "" {
		return nil, failure.New(failure.BeaconInvalid, "beacon source is empty")
	}
	return v, nil
}
