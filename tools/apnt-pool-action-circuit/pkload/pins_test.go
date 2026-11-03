package pkload

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	poolaction "github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit"
)

// TestChipnetZeroValueRevision3Pins: every pin is well formed and labelled;
// R1CS, RawKey and VerifyingKey are the registry's own values (the verifying
// key pin names the recorded vp's bytes); the image pin was derived on this
// build's point layout, whose fingerprint the pin's comment names; and no two
// files share a pin.
func TestChipnetZeroValueRevision3Pins(t *testing.T) {
	p := ChipnetZeroValueRevision3
	if p.Label != "SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY" {
		t.Fatalf("label %q", p.Label)
	}
	pins := map[string]Pin{"r1cs": p.R1CS, "rawKey": p.RawKey, "image": p.Image, "verifyingKey": p.VerifyingKey}
	seen := map[string]string{}
	for name, pin := range pins {
		if err := pin.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if other, dup := seen[pin.SHA256]; dup {
			t.Fatalf("%s and %s share a digest", name, other)
		}
		seen[pin.SHA256] = name
	}
	vp, err := poolaction.ChipnetZeroValueRevision3VP()
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(vp); p.VerifyingKey.Bytes != int64(len(vp)) || p.VerifyingKey.SHA256 != hex.EncodeToString(sum[:]) || len(vp) != 528 {
		t.Fatalf("verifying-key pin %+v is not the recorded vp (%d bytes)", p.VerifyingKey, len(vp))
	}
	if p.R1CS != (Pin{371_275_956, "7c32a8f691c8b3a60bd1c89364a9fc1a76b1a5fc576d21722eb4fc7f9155d31e"}) ||
		p.RawKey != (Pin{2_751_007_465, "59e2a2f190a5f021936c88b32b9a470ff3de8dd18befb3a110f75661d8e742fc"}) {
		t.Fatalf("R1CS or raw-key pin moved: %+v %+v", p.R1CS, p.RawKey)
	}
	// The image holds the same points as the raw key plus the header and
	// section alignment, so it is a little larger, never smaller.
	if d := p.Image.Bytes - p.RawKey.Bytes; d <= 0 || d > 4096 {
		t.Fatalf("image is %d bytes longer than the raw key", d)
	}
	fp := runtimeLayoutDesc().fingerprint()
	if got := hex.EncodeToString(fp[:]); got != "09386ce7fc49a455fce316162db5d696a9690978b4eee439355d626741869e6b" {
		t.Fatalf("this build's layout fingerprint is %s, not the one the image pin was derived on", got)
	}
}
