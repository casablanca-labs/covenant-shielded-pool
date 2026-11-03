// Package pkload loads the pool action circuit's Groth16 proving key for
// wallet proving without gnark's per-point checks, and only after the file's
// size and SHA-256 match a pin (task ENG-424, ARCH-191).
//
// RESEARCH PROTOTYPE — NOT REVIEWED. Nothing on the privacy-default path uses
// it yet.
//
// Every loader here reads the whole file into memory this process owns,
// hashing each byte as it lands, and compares the size and digest with a pin
// before any byte of the file is interpreted. The size is checked from fstat
// before anything is read. Only after both match does a decoder run, and the
// decoders skip gnark's on-curve and subgroup checks on the point slices:
//
//	FormatRaw    gnark (*ProvingKey).WriteRawTo, the ceremony's encoding,
//	             decoded with gnark's UnsafeReadFrom (a copy of every point)
//	FormatDump   gnark (*ProvingKey).WriteDump, decoded with gnark's ReadDump
//	             (a copy of every point)
//	FormatImage  this package's image (image.go): the point slices are views
//	             into the verified buffer, with no copy and no decoding
//
// What the pin gives, and what it does not. The pin gives byte identity with
// a known key: the raw key's digest is the one the ceremony transcript names
// (its verifier re-derives the key from the verified contribution chain and
// hashes its WriteRawTo encoding), and an image's digest is what Derive makes
// from that raw key after decoding every point with gnark's checks. Skipping
// gnark's per-point checks relies on that identity only: these are the bytes
// that were already checked. It does not establish that the key is a
// well-formed Groth16 CRS. Zero knowledge under the pinned key also depends on
// the ceremony verifier covering CRS well-formedness (delta non-zero, the K
// and Z elements, the Pedersen commitment key), which is open (ARCH-238); this
// package does not claim it. A pin that names any other bytes voids even the
// byte identity.
//
// The package writes a key only in WriteImage and Derive, which the command
// runs in a sub-directory of the caller's choosing; it never writes a key
// beside the circuit sources. The root package's rule (no Setup, no proof, no
// key) is unchanged.
package pkload

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"regexp"
	"sync/atomic"
	"time"
	"unsafe"

	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

// Notice labels every result of this package and its command.
const Notice = "research prototype — not reviewed (ENG-424); the keys it loads are zero-value test keys"

// Format names a proving-key encoding.
type Format string

const (
	FormatRaw   Format = "raw"   // gnark WriteRawTo
	FormatDump  Format = "dump"  // gnark WriteDump
	FormatImage Format = "image" // this package's image
)

// Pin is what a loader requires of a key file before it decodes anything.
type Pin struct {
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Validate refuses a malformed pin; there is no default.
func (p Pin) Validate() error {
	if p.Bytes <= 0 {
		return fmt.Errorf("pin: byte length %d is not positive", p.Bytes)
	}
	if !hex64.MatchString(p.SHA256) {
		return fmt.Errorf("pin: SHA-256 %q is not 64 lowercase hex characters", p.SHA256)
	}
	return nil
}

// Stage is where a load stopped.
type Stage string

const (
	StagePin    Stage = "pin"    // the pin itself is malformed
	StageOpen   Stage = "open"   // the file cannot be opened or is not a regular file
	StageSize   Stage = "size"   // fstat size differs from the pin; nothing was read
	StageRead   Stage = "read"   // I/O error, short read, or bytes past the pinned length
	StageDigest Stage = "digest" // SHA-256 differs from the pin; nothing was decoded
	StageDecode Stage = "decode" // the verified bytes did not decode
	// StageUnverified: a decoder was handed a Verified that ReadVerified did
	// not make (a zero value or nil); nothing was decoded.
	StageUnverified Stage = "unverified"
)

// Error is a refused or failed load.
type Error struct {
	Stage Stage
	Err   error
}

func (e *Error) Error() string { return fmt.Sprintf("pkload %s: %v", e.Stage, e.Err) }
func (e *Error) Unwrap() error { return e.Err }

// StageOf is the stage of a load error, or "" for any other error.
func StageOf(err error) Stage {
	var e *Error
	if errors.As(err, &e) {
		return e.Stage
	}
	return ""
}

// decodeCalls counts decoder entries. The tests read it to show that a
// refused file never reaches a decoder.
var decodeCalls atomic.Int64

// ReadStats is what reading and hashing a key file measured.
type ReadStats struct {
	Bytes       int64   `json:"bytes"`
	SHA256      string  `json:"sha256"`
	ReadSeconds float64 `json:"readAndHashSeconds"`
}

// chunk is the unit handed from the reader to the hasher.
const chunk = 8 << 20

// alignedBytes returns n zeroed bytes whose first byte is 64-byte aligned.
func alignedBytes(n int64) []byte {
	words := make([]uint64, (n+63)/8+8)
	p := uintptr(unsafe.Pointer(&words[0]))
	skip := int((64 - p%64) % 64)
	all := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(words)*8)
	return all[skip : skip+int(n) : skip+int(n)]
}

// Verified is a key file's bytes whose length and SHA-256 matched a pin. Only
// ReadVerified makes one: its fields are unexported, a zero Verified is refused
// by every decoder, and the bytes are not reachable from outside this package.
// Decode and Derive take a *Verified, never a byte slice, so no exported path
// decodes bytes that have not passed a pin.
type Verified struct {
	buf []byte
	pin Pin
	ok  bool
}

// Pin is the pin these bytes matched.
func (v *Verified) Pin() Pin { return v.pin }

func (v *Verified) check() error {
	if v == nil || !v.ok {
		return &Error{StageUnverified, errors.New("not a verified buffer: only ReadVerified makes one")}
	}
	return nil
}

// ReadVerified reads the file at path into a new 64-byte-aligned buffer and
// returns it, as a Verified, only if its size and SHA-256 equal pin. The size
// is checked from fstat before any read, and the file must end exactly at the
// pinned length. One goroutine reads while another hashes what has landed.
func ReadVerified(path string, pin Pin) (*Verified, *ReadStats, error) {
	if err := pin.Validate(); err != nil {
		return nil, nil, &Error{StagePin, err}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, &Error{StageOpen, err}
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, nil, &Error{StageOpen, err}
	}
	if !st.Mode().IsRegular() {
		return nil, nil, &Error{StageOpen, fmt.Errorf("%s is not a regular file", path)}
	}
	if st.Size() != pin.Bytes {
		return nil, nil, &Error{StageSize, fmt.Errorf("%s is %d bytes, the pin says %d", path, st.Size(), pin.Bytes)}
	}
	return readPinned(f, path, pin)
}

// readPinned reads exactly pin.Bytes from r into a new aligned buffer,
// requires r to end there (a file may have grown since fstat), and compares
// the SHA-256.
func readPinned(r io.Reader, name string, pin Pin) (*Verified, *ReadStats, error) {
	start := time.Now()
	buf := alignedBytes(pin.Bytes)
	h := sha256.New()
	if err := readHashed(r, buf, h); err != nil {
		return nil, nil, &Error{StageRead, err}
	}
	var one [1]byte
	if n, err := r.Read(one[:]); n != 0 || !errors.Is(err, io.EOF) {
		return nil, nil, &Error{StageRead, fmt.Errorf("%s has bytes past the pinned %d", name, pin.Bytes)}
	}
	got := hex.EncodeToString(h.Sum(nil))
	stats := &ReadStats{Bytes: pin.Bytes, SHA256: got, ReadSeconds: time.Since(start).Seconds()}
	if got != pin.SHA256 {
		return nil, stats, &Error{StageDigest, fmt.Errorf("%s has SHA-256 %s, the pin says %s", name, got, pin.SHA256)}
	}
	return &Verified{buf: buf, pin: pin, ok: true}, stats, nil
}

// readHashed fills buf from r in chunks; h hashes each chunk after it lands,
// in order, while the next one is read.
func readHashed(r io.Reader, buf []byte, h hash.Hash) error {
	type span struct{ lo, hi int }
	ready := make(chan span, 4)
	errc := make(chan error, 1)
	go func() {
		defer close(ready)
		for lo := 0; lo < len(buf); lo += chunk {
			hi := min(lo+chunk, len(buf))
			if _, err := io.ReadFull(r, buf[lo:hi]); err != nil {
				errc <- err
				return
			}
			ready <- span{lo, hi}
		}
	}()
	for s := range ready {
		h.Write(buf[s.lo:s.hi])
	}
	select {
	case err := <-errc:
		return err
	default:
		return nil
	}
}

// DecodeStats is what decoding a verified buffer measured.
type DecodeStats struct {
	Format        Format  `json:"format"`
	DecodeSeconds float64 `json:"decodeSeconds"`
	// ZeroCopy is true when the point slices are views into the verified
	// buffer (FormatImage), which then lives as long as the key.
	ZeroCopy bool `json:"zeroCopy"`
}

// Decode decodes bytes ReadVerified returned. It runs no on-curve or subgroup
// check on the point slices (see the package comment). A Verified that
// ReadVerified did not make is refused before anything is decoded.
func Decode(format Format, v *Verified) (*groth16bn254.ProvingKey, *DecodeStats, error) {
	if err := v.check(); err != nil {
		return nil, nil, err
	}
	return decode(format, v.buf)
}

// decode is the unchecked decoder. It interprets any bytes it is given, so it
// stays unexported: the only callers are Decode, after a pin passed, and the
// tests' controls that show what it would accept without one.
func decode(format Format, buf []byte) (*groth16bn254.ProvingKey, *DecodeStats, error) {
	decodeCalls.Add(1)
	start := time.Now()
	pk := new(groth16bn254.ProvingKey)
	st := &DecodeStats{Format: format}
	var err error
	switch format {
	case FormatRaw:
		r := bytes.NewReader(buf)
		if _, err = pk.UnsafeReadFrom(r); err == nil && r.Len() != 0 {
			err = fmt.Errorf("%d trailing bytes", r.Len())
		}
	case FormatDump:
		r := bytes.NewReader(buf)
		if err = pk.ReadDump(r); err == nil && r.Len() != 0 {
			err = fmt.Errorf("%d trailing bytes", r.Len())
		}
	case FormatImage:
		err = viewImage(buf, pk)
		st.ZeroCopy = true
	default:
		err = fmt.Errorf("unknown format %q", format)
	}
	st.DecodeSeconds = time.Since(start).Seconds()
	if err != nil {
		return nil, st, &Error{StageDecode, err}
	}
	return pk, st, nil
}

// Load is ReadVerified then Decode. For FormatRaw and FormatDump the buffer
// is garbage once Decode returns; for FormatImage the key keeps it alive.
func Load(path string, format Format, pin Pin) (*groth16bn254.ProvingKey, *ReadStats, *DecodeStats, error) {
	v, rs, err := ReadVerified(path, pin)
	if err != nil {
		return nil, rs, nil, err
	}
	pk, ds, err := Decode(format, v)
	return pk, rs, ds, err
}
