package pkload

import poolaction "github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit"

// KeyPins are the files a wallet loads to prove one registry vp's action
// proofs, each pinned: the circuit, the ceremony's raw proving key (the
// anchor: its digest is the one the ceremony transcript names), the image
// Derive makes from that raw key, and the verifying key the wallet checks its
// own proof under before it releases it.
type KeyPins struct {
	Label        string `json:"label"`
	R1CS         Pin    `json:"r1cs"`
	RawKey       Pin    `json:"rawKey"`
	Image        Pin    `json:"image"`
	VerifyingKey Pin    `json:"verifyingKey"`
}

// ChipnetZeroValueRevision3 pins registry entry 1 revision 3's Chipnet keys:
// the task-5.1c simulated single-party ceremony re-run on revision 3 (ENG-483;
// ceremony chipnet-pool-action-5.1c-20260926T212317Z). SIMULATED SINGLE-PARTY
// SETUP - ZERO-VALUE TEST ONLY: the project could forge proofs under these
// keys, so they never guard value (ENG-446).
//
// R1CS, RawKey and VerifyingKey are the registry's own values, so nothing here
// restates them. Image is what Derive made from RawKey (R-466: two derivations
// in separate processes, byte-identical), in APNT-PK-IMAGE-v2 under this
// build's point layout (fingerprint 09386ce7…9e6b, gnark v0.16.3,
// gnark-crypto v0.21.0, little-endian 64-bit). A build with another layout
// refuses the image at decode and must fall back to RawKey with gnark's
// checked ReadFrom; an image it derives itself will not match this pin.
//
// Revision 2's ceremony keys (vk a82a7248…) were never pinned here. They key
// R1CS 25d3f54d…, not revision 3's, and their image (2,794,088,576 bytes)
// fails this Image pin at the size check.
var ChipnetZeroValueRevision3 = KeyPins{
	Label:        poolaction.ChipnetZeroValueLabel,
	R1CS:         Pin{Bytes: poolaction.Revision3R1CSBytes, SHA256: poolaction.Revision3R1CSSha256},
	RawKey:       Pin{Bytes: poolaction.ChipnetZeroValueRevision3ProvingKeyBytes, SHA256: poolaction.ChipnetZeroValueRevision3ProvingKeySha256},
	Image:        Pin{Bytes: 2_751_007_808, SHA256: "eff8cdbd21f567d39d48eb4b10583193a4b0aa9305009c4cb9205e8bbac24654"},
	VerifyingKey: Pin{Bytes: int64(len(poolaction.ChipnetZeroValueRevision3VPHex) / 2), SHA256: poolaction.ChipnetZeroValueRevision3VPSha256},
}
