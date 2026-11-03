package poolaction

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/pedersen"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
)

// Proof-system registry entry 1 (apnt-pool-proof-system; ENG-271), revision 3
// (pad16, HUM-84, ENG-454): the public input is one hash of the 314-byte
// record, and the circuit is revision 2's with each output's rcm derived from
// K and ρ and the 16-byte SHA-256-pad packet in place of AES-256-GCM.
//
//	system_id  1: gnark Groth16 on BN254, gnark v0.16.3 / gnark-crypto v0.21.0.
//	vp         the verifying key's gnark v0.16.3 compressed serialization,
//	           (*groth16/bn254.VerifyingKey).WriteTo, byte for byte:
//	             [α]1 ‖ [β]1 ‖ [β]2 ‖ [γ]2 ‖ [δ]1 ‖ [δ]2          32+32+64+64+32+64
//	             ‖ u32be(|K|) ‖ K[0..|K|−1]                          4 + 32·|K|
//	             ‖ PublicAndCommitmentCommitted as u32be(outer) ‖ (u32be(inner) ‖ u64be…)…
//	             ‖ u32be(|CommitmentKeys|) ‖ (G ‖ GSigmaNeg)…          64+64 each
//	           G1 points are 32 bytes and G2 points 64, compressed with
//	           gnark-crypto's flag bits in the top two bits of the first byte.
//	           |K| = 1 + 1 + (number of BSB22 commitments).
//	public     one scalar, x = int_be(SHA-256(A)) mod r over the 314 bytes of
//	           A (PublicInput); every verifier derives it from A itself.
//	verify     gnark v0.16.3 groth16/bn254 Verify with its BSB22 commitment
//	           extension: the Pedersen knowledge check under CommitmentKeys, the
//	           commitment wire hashed to Fr with expand_message_xmd(SHA-256),
//	           domain "bsb22-commitment", 48 bytes, then the pairing check.
//	profile_id SHA-256("APNT-POOL-v1:profile" ‖ u16le(1) ‖ u64le(len(vp)) ‖ vp).
//
// Revision 1 took the 396 record bytes as 396 public scalars (|K| = 398,
// len(vp) = 13,168). It was revised before any vp was allowlisted anywhere; its
// vector file stays, unchanged, as the superseded revision's record, and so do
// the task-5.1c keys made for it (superseded evidence, never a vp).
//
// Revision 2 (HUM-80, ENG-437; R1CS 25d3f54d…, 6,135,851 constraints) took
// one hashed public input over the 396-byte record with the 57-byte AES-256-GCM
// packet. Its Chipnet simulated-ceremony keys exist (task 5.1c re-run, ENG-445;
// vk 528 bytes, SHA-256 a82a7248…): SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE
// TEST ONLY, and never a vp for revision 3, whose R1CS they do not key. Its
// vector file stays unchanged as that revision's record. Revision 3 keeps its
// vp topology (2 public variables, one commitment, |K| = 3, 528 bytes), so
// the two revisions' serialization shape vectors are byte-identical: a shape
// vector names a layout, never a key.
//
// Revision 3's one vp so far is the Chipnet zero-value vp below
// (ChipnetZeroValueRevision3VP): the task-5.1c re-run on revision 3 (ENG-483).
// Every setup (a project-run simulated setup, a ceremony, a re-run after any
// circuit change) produces a different vp and so a different profile_id;
// profile_id names one exact key, never "the gnark route".
const (
	SystemIDGnarkGroth16BN254 uint16 = 1
	SystemIDHalo2IPAPasta     uint16 = 2
	// 3 is reserved for Binius64 and, like 0 and every unlisted id, refused.
	profileTag = "APNT-POOL-v1:profile"
)

// The gnark and gnark-crypto versions this module builds with, and so the
// versions registry entry 1 names. TestGnarkVersionsMatchGoMod requires them
// to equal this module's go.mod and tools/apnt-pool-ceremony's go.mod, so the
// ceremony's phase 2 and this circuit use one gnark.
const (
	GnarkVersion       = "v0.16.3"
	GnarkCryptoVersion = "v0.21.0"
)

// Revision3R1CSSha256 and Revision3R1CSBytes are registry entry 1 revision
// 3's R1CS (pad16, ENG-454): gnark v0.16.3's serialization of Compile(), which
// carries no source paths in a normal build (TestRevision3R1CS). It equals
// ARCH-247's pad16 prototype R1CS (R-406, 46a238c6), so that prototype's
// parity evidence reads over this exact constraint system, and it is what the
// task-5.1c re-run on revision 3 keys.
const (
	Revision3R1CSSha256 = "7c32a8f691c8b3a60bd1c89364a9fc1a76b1a5fc576d21722eb4fc7f9155d31e"
	Revision3R1CSBytes  = 371_275_956
)

// ChipnetZeroValueLabel labels revision 3's Chipnet vp and everything made
// under its keys.
const ChipnetZeroValueLabel = "SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY"

// Revision 3's Chipnet zero-value vp: the verifying key of the task-5.1c
// simulated single-party ceremony re-run on revision 3 (ENG-483; ceremony
// chipnet-pool-action-5.1c-20260926T212317Z), in the vp serialization above.
// SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY: the project ran every
// contribution and could have kept the randomness, so it can forge proofs
// under this key. It must never guard value. It is a vp for a labelled
// zero-value Chipnet deployment only; mainnet needs a permissionless
// multi-party ceremony (AGENTS.md). Recording it here does not allowlist it:
// the aggregate program's canonical allowlist is task 5.4 slice 2's.
//
// Provenance: the ceremony verifier's anchored verify was VALID with the
// phase-1 pin, beacon and R1CS anchors (transcript SHA-256
// ChipnetZeroValueRevision3TranscriptSha256), over R1CS Revision3R1CSSha256; its
// proving key is ChipnetZeroValueRevision3ProvingKey*;
// the CRS release gate (ENG-441, ENG-447) returned RELEASE-OK with no
// refusals, report SHA-256 ChipnetZeroValueRevision3ReleaseReportSha256
// (its statement's SHA-256 ChipnetZeroValueRevision3ReleaseStatementSha256).
// External ceremony evidence is identified by the frozen registry vector
// and the release/transcript digests above; no local archive is required here.
const (
	ChipnetZeroValueRevision3VPHex = "e45229d9b076b3c0e8a4d70bde8c1cccffa08a9fae7557b165b3b0dbd653e2c7" +
		"a3eba1776012a292e6780582e7a197913f375a4043e411358d4791b66f53c1d9" +
		"87090a82e8fabbd39299be24705b92cf208ee8b3487f6f2b39ff27978a29a1db" +
		"2424bcc1f60a5472685fd50705b2809626e170120acaf441e133a2bd5e61d244" +
		"998e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2" +
		"1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed" +
		"81aea72385d8f8c28e5e089d03bdfd570842951ba3f9af8c4fec013acc10a51a" +
		"8cfe7bae9848dad418e9d6fc9dfaac414b5a5b5c890f333652acc8d9f1da407b" +
		"19a060fe5ff05550577b6f50c7253f1ac04cb531c15409d28b4aa0f1b821aa30" +
		"00000003e178a30bc3186ddf25642ac5b4a95db70a8ed186055505253658c952" +
		"89d35e31ef1946ad278505e94aca56ca0f1d53e9d806860a40710c69abab071b" +
		"18962762d488cf077531b34faac3050c07b3b2bc32858d9ff5ec54ef04554a8a" +
		"8000f767000000010000000000000001998e9393920d483a7260bfb731fb5d25" +
		"f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479" +
		"674322d4f75edadd46debd5cd992f6edeeaa526537d9ab60dd84815cfd7a63a4" +
		"ecc2884be62dbc8ad23c3510cab626a026a1619aebf078f0ea2f649d3a9b6608" +
		"c6a993615a381d1fe5e0e7bb6d5eb26b"
	ChipnetZeroValueRevision3VPSha256               = "35c2bdb2e52ce2f2795e9ef57445a2e11f96836345b3829ebe6520e3603860ff"
	ChipnetZeroValueRevision3ProfileID              = "ea3d52d762f394b2959740126c3fb441165236696a02314a19498b48e2f1c1f2"
	ChipnetZeroValueRevision3CeremonyID             = "chipnet-pool-action-5.1c-20260926T212317Z"
	ChipnetZeroValueRevision3TranscriptSha256       = "31def5325285375ef7ed9c4324104ef2b7c4dd4f800f136510e2ceb2b2ef7d62"
	ChipnetZeroValueRevision3ReleaseReportSha256    = "54c07aeac05f377d551fb19154326927e8d44f627eb08bb108d39d773d12f49c"
	ChipnetZeroValueRevision3ReleaseStatementSha256 = "deb7c6d2fc9f3e0849eb0c4a147d1d733dd979ffad63bd7db3cdf39ea70ba7f3"
	ChipnetZeroValueRevision3ProvingKeySha256       = "59e2a2f190a5f021936c88b32b9a470ff3de8dd18befb3a110f75661d8e742fc"
	ChipnetZeroValueRevision3ProvingKeyBytes        = 2_751_007_465
	ChipnetZeroValueRevision3BeaconDisplayOrder     = "000000004e3c15b9c2c35e38cfbdf50cb3a1205b512213671bedccb9b3250051"
	ChipnetZeroValueRevision3BeaconHeight           = 325_218
)

// ChipnetZeroValueRevision3VP is the vp bytes, with its SHA-256 and
// profile_id checked against the constants above.
func ChipnetZeroValueRevision3VP() ([]byte, error) {
	vp, err := hex.DecodeString(ChipnetZeroValueRevision3VPHex)
	if err != nil {
		return nil, err
	}
	if sum := sha256.Sum256(vp); hex.EncodeToString(sum[:]) != ChipnetZeroValueRevision3VPSha256 {
		return nil, fmt.Errorf("the recorded vp has SHA-256 %x", sum)
	}
	id, err := ProfileID(SystemIDGnarkGroth16BN254, vp)
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(id) != ChipnetZeroValueRevision3ProfileID {
		return nil, fmt.Errorf("the recorded vp has profile_id %x", id)
	}
	return vp, nil
}

// ProfileID mirrors the host's deriveAPNTPoolProfileIdV1, including its
// refusal of every system id outside the registry's listed {1, 2}.
func ProfileID(systemID uint16, vp []byte) ([]byte, error) {
	if systemID != SystemIDGnarkGroth16BN254 && systemID != SystemIDHalo2IPAPasta {
		return nil, fmt.Errorf("system id %d is not listed", systemID)
	}
	h := sha256.New()
	h.Write([]byte(profileTag))
	var id [2]byte
	binary.LittleEndian.PutUint16(id[:], systemID)
	h.Write(id[:])
	var n [8]byte
	binary.LittleEndian.PutUint64(n[:], uint64(len(vp)))
	h.Write(n[:])
	h.Write(vp)
	return h.Sum(nil), nil
}

// PublicInput is registry entry 1's public-input rule, x = int_be(SHA-256(A))
// mod r, with r the BN254 scalar field order: SHA-256 over the 314 record
// bytes with no tag, the digest read big-endian. It mirrors the host's
// deriveAPNTPoolActionPublicInputV1 and refuses any other length.
func PublicInput(record []byte) (*big.Int, error) {
	if len(record) != RecordBytes {
		return nil, fmt.Errorf("record is %d bytes, not %d", len(record), RecordBytes)
	}
	d := sha256.Sum256(record)
	return new(big.Int).Mod(new(big.Int).SetBytes(d[:]), bn254Modulus), nil
}

// VPTopology is what the compiled circuit fixes about vp before any Setup.
type VPTopology struct {
	PublicVariables              int     `json:"publicVariables"` // including the constant one
	Commitments                  int     `json:"commitments"`
	KLength                      int     `json:"kLength"`
	PublicAndCommitmentCommitted [][]int `json:"publicAndCommitmentCommitted"`
	VPBytes                      int     `json:"vpBytes"`
}

// Topology reads the vp-relevant shape from a compiled constraint system,
// exactly as gnark v0.16.3's groth16/bn254 Setup would shape the key.
func Topology(ccs constraint.ConstraintSystem) (VPTopology, error) {
	info, ok := ccs.GetCommitments().(constraint.Groth16Commitments)
	if !ok {
		return VPTopology{}, fmt.Errorf("no Groth16 commitment info")
	}
	nbPublic := ccs.GetNbPublicVariables()
	t := VPTopology{
		PublicVariables:              nbPublic,
		Commitments:                  len(info),
		KLength:                      nbPublic + len(info),
		PublicAndCommitmentCommitted: info.GetPublicAndCommitmentCommitted(info.CommitmentIndexes(), nbPublic),
	}
	inner := 0
	for _, c := range t.PublicAndCommitmentCommitted {
		inner += 4 + 8*len(c)
	}
	t.VPBytes = 32 + 32 + 64 + 64 + 32 + 64 + 4 + 32*t.KLength + 4 + inner + 4 + 128*t.Commitments
	return t, nil
}

// ShapeVP builds a serialization shape vector: a structurally complete
// verifying key with this circuit's exact topology whose every point is a
// hash-to-curve image of a public label. It is NOT a verifying key: no Setup
// produced it, no proof is meant to verify under it, and its profile_id must
// never be allowlisted. It pins vp's byte layout and length before Setup.
func ShapeVP(t VPTopology) ([]byte, error) {
	const dst = "APNT-POOL-v1 vp serialization shape vector, not a verifying key"
	g1 := func(label string) (bn254.G1Affine, error) { return bn254.HashToG1([]byte(label), []byte(dst)) }
	g2 := func(label string) (bn254.G2Affine, error) { return bn254.HashToG2([]byte(label), []byte(dst)) }
	vk := &groth16bn254.VerifyingKey{}
	var err error
	if vk.G1.Alpha, err = g1("alpha"); err != nil {
		return nil, err
	}
	if vk.G1.Beta, err = g1("beta-g1"); err != nil {
		return nil, err
	}
	if vk.G1.Delta, err = g1("delta-g1"); err != nil {
		return nil, err
	}
	if vk.G2.Beta, err = g2("beta-g2"); err != nil {
		return nil, err
	}
	if vk.G2.Gamma, err = g2("gamma-g2"); err != nil {
		return nil, err
	}
	if vk.G2.Delta, err = g2("delta-g2"); err != nil {
		return nil, err
	}
	vk.G1.K = make([]bn254.G1Affine, t.KLength)
	for i := range vk.G1.K {
		if vk.G1.K[i], err = g1(fmt.Sprintf("K-%d", i)); err != nil {
			return nil, err
		}
	}
	vk.CommitmentKeys = make([]pedersen.VerifyingKey, t.Commitments)
	for i := range vk.CommitmentKeys {
		if vk.CommitmentKeys[i].G, err = g2(fmt.Sprintf("commitment-%d-G", i)); err != nil {
			return nil, err
		}
		if vk.CommitmentKeys[i].GSigmaNeg, err = g2(fmt.Sprintf("commitment-%d-GSigmaNeg", i)); err != nil {
			return nil, err
		}
	}
	vk.PublicAndCommitmentCommitted = t.PublicAndCommitmentCommitted
	var buf bytes.Buffer
	if _, err := vk.WriteTo(&buf); err != nil {
		return nil, err
	}
	if buf.Len() != t.VPBytes {
		return nil, fmt.Errorf("shape vp is %d bytes, topology says %d", buf.Len(), t.VPBytes)
	}
	// Round trip through gnark's own reader (with its curve and subgroup checks).
	back := groth16.NewVerifyingKey(bn254.ID)
	if _, err := back.ReadFrom(bytes.NewReader(buf.Bytes())); err != nil {
		return nil, fmt.Errorf("shape vp does not read back: %w", err)
	}
	var again bytes.Buffer
	if _, err := back.WriteTo(&again); err != nil {
		return nil, err
	}
	if !bytes.Equal(again.Bytes(), buf.Bytes()) {
		return nil, fmt.Errorf("shape vp does not re-serialize identically")
	}
	return buf.Bytes(), nil
}
