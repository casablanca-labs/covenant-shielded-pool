package ptau

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"strings"

	"golang.org/x/crypto/blake2b"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
)

// Pin algorithms. BLAKE2b-512 is what snarkjs and the Perpetual Powers of Tau
// records publish for .ptau files; SHA-256 is accepted for files the project
// pins itself.
const (
	AlgSHA256     = "sha256"
	AlgBLAKE2b512 = "blake2b-512"
)

// Pin is the expected digest of a whole .ptau file.
type Pin struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
}

func (p Pin) String() string { return p.Algorithm + ":" + p.Digest }

// ParsePin parses "sha256:<64 hex>" or "blake2b-512:<128 hex>".
func ParsePin(s string) (Pin, error) {
	alg, digest, ok := strings.Cut(s, ":")
	if !ok {
		return Pin{}, failure.New(failure.Phase1PinInvalid, "pin %q is not <algorithm>:<hex>", s)
	}
	p := Pin{Algorithm: alg, Digest: strings.ToLower(digest)}
	return p, p.Validate()
}

// Validate checks the algorithm and the digest length.
func (p Pin) Validate() error {
	var want int
	switch p.Algorithm {
	case AlgSHA256:
		want = sha256.Size
	case AlgBLAKE2b512:
		want = blake2b.Size
	default:
		return failure.New(failure.Phase1PinInvalid, "unknown pin algorithm %q", p.Algorithm)
	}
	raw, err := hex.DecodeString(p.Digest)
	if err != nil || len(raw) != want || hex.EncodeToString(raw) != p.Digest {
		return failure.New(failure.Phase1PinInvalid, "pin digest is not %d lowercase hex bytes", want)
	}
	return nil
}

// fileHasher computes both digests of a byte stream.
type fileHasher struct {
	sha  hash.Hash
	b2   hash.Hash
	size int64
}

func newFileHasher() *fileHasher {
	b2, err := blake2b.New512(nil)
	if err != nil {
		panic(err) // unreachable: a nil key is always valid
	}
	return &fileHasher{sha: sha256.New(), b2: b2}
}

func (h *fileHasher) Write(p []byte) (int, error) {
	h.sha.Write(p)
	h.b2.Write(p)
	h.size += int64(len(p))
	return len(p), nil
}

func (h *fileHasher) digests() (sha, b2 string) {
	return hex.EncodeToString(h.sha.Sum(nil)), hex.EncodeToString(h.b2.Sum(nil))
}

// match reports whether the pinned digest equals the computed one.
func (p Pin) match(sha, b2 string) bool {
	switch p.Algorithm {
	case AlgSHA256:
		return p.Digest == sha
	case AlgBLAKE2b512:
		return p.Digest == b2
	}
	return false
}

// HashFile returns the SHA-256 and BLAKE2b-512 digests and the size of r.
func HashFile(r io.Reader) (sha, b2 string, size int64, err error) {
	h := newFileHasher()
	if _, err = io.Copy(h, r); err != nil {
		return "", "", 0, failure.Wrap(failure.IO, err, "hashing phase-1 file")
	}
	sha, b2 = h.digests()
	return sha, b2, h.size, nil
}
