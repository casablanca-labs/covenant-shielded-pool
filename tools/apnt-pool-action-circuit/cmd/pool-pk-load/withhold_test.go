package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/devprove"
)

// longHex finds hex runs longer than a SHA-256 digest: proof bytes in any field.
var longHex = regexp.MustCompile(`[0-9a-f]{65,}`)

// TestWrongKeyProofIsWithheld: a proof made with a well-formed key from
// another Setup does not verify under the pinned verifying key, and nothing of
// it (bytes, size or digest) reaches the result (F3). The same command with
// the right key does record its proof, so the check is not vacuous.
func TestWrongKeyProofIsWithheld(t *testing.T) {
	defer protectedPanic(t)
	f := newFiles(t)
	ccs, err := devprove.SmallTarget(devprove.SmallRounds).Compile()
	if err != nil {
		protectedFatal(t, err)
	}
	other, _, err := groth16.Setup(ccs)
	if err != nil {
		protectedFatal(t, err)
	}
	wrong := filepath.Join(f.dir, "wrong.raw.key")
	write(t, wrong, func(w io.Writer) error { _, err := other.(*groth16bn254.ProvingKey).WriteRawTo(w); return err })
	wrongPin := pinOf(t, wrong)

	prove := func(key string, pin [2]string) (*Result, []byte, error) {
		args := append([]string{"prove", "--target", "small", "--format", "raw", "--key", key}, pinArgs(pin)...)
		args = append(args, "--r1cs", f.r1cs, "--r1cs-bytes", f.r1csPin[0], "--r1cs-sha256", f.r1csPin[1],
			"--vk", f.vk, "--vk-bytes", f.vkPin[0], "--vk-sha256", f.vkPin[1])
		r, err := f.run(t, args...)
		raw, rerr := os.ReadFile(filepath.Join(f.dir, fmt.Sprintf("result-%d.json", runs)))
		if rerr != nil {
			protectedFatal(t, rerr)
		}
		return r, raw, err
	}

	r, raw, err := prove(wrong, wrongPin)
	if err == nil || r.Prove == nil || r.Prove.Verified {
		protectedFatal(t, "the wrong key's proof verified or the command succeeded: %v %+v", err, r.Prove)
	}
	if r.Prove.ProofHex != "" || r.Prove.ProofSHA256 != "" || r.Prove.ProofBytes != 0 {
		protectedError(t, "an unverified proof reached the result: %d bytes, sha256 %q, hex %d chars", r.Prove.ProofBytes, r.Prove.ProofSHA256, len(r.Prove.ProofHex))
	}
	if m := longHex.FindAll(raw, -1); len(m) != 0 {
		protectedError(t, "the result file holds %d hex runs longer than a digest; the first is %d chars", len(m), len(m[0]))
	}

	r, raw, err = prove(f.raw, f.rawPin)
	if err != nil || !r.Prove.Verified || r.Prove.ProofBytes == 0 || len(r.Prove.ProofHex) != 2*r.Prove.ProofBytes || len(longHex.FindAll(raw, -1)) != 1 {
		protectedFatal(t, "the right key's verified proof is not recorded: %v %+v", err, r.Prove)
	}
	if !bytes.Contains(raw, []byte(r.Prove.ProofHex)) {
		protectedFatal(t, "the recorded proof is not in the result file")
	}
}
