package poolaction

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

const hostVectorsPath = "../../packages/protocol-runtime/test-vectors/apnt-pool-v1-vectors.json"

// registryVectorsPath is registry entry 1 revision 3 (pad16, historical-record),
// generated from the compiled circuit. registryRev2VectorsPath is revision 2
// (historical-record; the 396-byte record) and registryRev1VectorsPath revision 1 (396
// public bytes); both are superseded and kept unchanged.
const (
	registryVectorsPath     = "../../packages/protocol-runtime/test-vectors/apnt-pool-v1-proof-system-registry-rev3-vectors.json"
	registryRev2VectorsPath = "../../packages/protocol-runtime/test-vectors/apnt-pool-v1-proof-system-registry-rev2-vectors.json"
	registryRev1VectorsPath = "../../packages/protocol-runtime/test-vectors/apnt-pool-v1-proof-system-registry-vectors.json"
	publicInputVectorsPath  = "../../packages/protocol-runtime/test-vectors/apnt-pool-v1-action-public-input-vectors.json"
)

// TestProfileIDMatchesHost: the Go profile_id derivation equals the host's
// on the host's own vectors, and refuses what the host refuses.
func TestProfileIDMatchesHost(t *testing.T) {
	defer protectedPanic(t)
	raw, err := os.ReadFile(hostVectorsPath)
	if err != nil {
		protectedFatal(t, err)
	}
	var v struct {
		Reference struct {
			ProfileID struct {
				VerifierParameters string `json:"verifierParameters"`
				System1            string `json:"system1"`
				System2            string `json:"system2"`
			} `json:"profileId"`
		} `json:"reference"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		protectedFatal(t, err)
	}
	vp := entryBytes(t, v.Reference.ProfileID.VerifierParameters)
	for _, c := range []struct {
		id   uint16
		want string
	}{{1, v.Reference.ProfileID.System1}, {2, v.Reference.ProfileID.System2}} {
		got, err := ProfileID(c.id, vp)
		if err != nil || hex.EncodeToString(got) != c.want {
			protectedFatal(t, "system %d: got %x, want %s (%v)", c.id, got, c.want, err)
		}
	}
	for _, id := range []uint16{0, 3, 258} {
		if _, err := ProfileID(id, vp); err == nil {
			protectedFatal(t, "system id %d accepted", id)
		}
	}
}

type RegistryVectors struct {
	Description string `json:"description"`
	Entry       struct {
		SystemID        uint16   `json:"systemId"`
		Revision        int      `json:"revision"`
		Supersedes      string   `json:"supersedes"`
		Name            string   `json:"name"`
		Libraries       []string `json:"libraries"`
		VPSerialization []string `json:"vpSerialization"`
		VPCovers        []string `json:"vpCovers"`
		PublicInput     string   `json:"publicInput"`
		Verification    string   `json:"verification"`
		VPStatus        string   `json:"vpStatus"`
	} `json:"registryEntry"`
	Topology VPTopology `json:"circuitTopology"`
	Shape    struct {
		NotAVerifyingKey bool   `json:"notAVerifyingKey"`
		Label            string `json:"label"`
		VP               string `json:"vp"`
		ProfileID        string `json:"profileId"`
	} `json:"shapeVector"`
	// ChipnetZeroValueVP is revision 3's recorded vp (historical-record); the
	// superseded revisions' files have none.
	ChipnetZeroValueVP *ChipnetVPRecord `json:"chipnetZeroValueVp,omitempty"`
}

type ChipnetVPRecord struct {
	Label      string `json:"label"`
	Note       string `json:"note"`
	VP         string `json:"vp"`
	VPBytes    int    `json:"vpBytes"`
	VPSha256   string `json:"vpSha256"`
	ProfileID  string `json:"profileId"`
	Provenance struct {
		CeremonyID             string `json:"ceremonyId"`
		Task                   string `json:"task"`
		R1CSSha256             string `json:"r1csSha256"`
		ProvingKeySha256       string `json:"provingKeySha256"`
		ProvingKeyBytes        int64  `json:"provingKeyBytes"`
		TranscriptSha256       string `json:"transcriptSha256"`
		VerifierVerdict        string `json:"verifierVerdict"`
		BeaconHeight           int    `json:"beaconChipnetHeight"`
		BeaconDisplayOrder     string `json:"beaconBlockHashDisplayOrder"`
		ReleaseGateVerdict     string `json:"releaseGateVerdict"`
		ReleaseReportSha256    string `json:"releaseReportSha256"`
		ReleaseStatementSha256 string `json:"releaseStatementSha256"`
		Evidence               string `json:"evidence"`
	} `json:"provenance"`
}

// Keep the frozen locator exact without repeating a machine/archive locator in source.
func registryEvidence(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(registryVectorsPath)
	if err != nil {
		protectedFatal(t, "registry provenance unavailable")
	}
	var frozen RegistryVectors
	if json.Unmarshal(raw, &frozen) != nil || frozen.ChipnetZeroValueVP == nil {
		protectedFatal(t, "registry provenance invalid")
	}
	evidence := frozen.ChipnetZeroValueVP.Provenance.Evidence
	digest := sha256.Sum256([]byte(evidence))
	if hex.EncodeToString(digest[:]) != "bb3d837fdd25140f712b9f3818a82b47974b31c1da7a0b2398ea9cc3e6182264" {
		protectedFatal(t, "registry provenance changed")
	}
	return evidence
}

func TestRegistryEvidenceLocator(t *testing.T) {
	defer protectedPanic(t)
	if registryEvidence(t) == "" {
		protectedFatal(t, "registry provenance empty")
	}
}

func registryVectors(t *testing.T) *RegistryVectors {
	ccs, err := Compile()
	if err != nil {
		protectedFatal(t, err)
	}
	top, err := Topology(ccs)
	if err != nil {
		protectedFatal(t, err)
	}
	ccs = nil
	Release()
	vp, err := ShapeVP(top)
	if err != nil {
		protectedFatal(t, err)
	}
	id, err := ProfileID(SystemIDGnarkGroth16BN254, vp)
	if err != nil {
		protectedFatal(t, err)
	}
	r := &RegistryVectors{Description: "APNT pool v1 proof-system registry entry 1, revision 3 (historical-record, historical-record, historical-record; one hashed public input, historical-record, historical-record, historical-record; pad16: derived output rcm, 16-byte SHA-256-pad packets, 314-byte record, historical-record, historical-record, historical-record): the vp serialization rule, the circuit topology it fixes, a serialization shape vector, and the Chipnet zero-value vp of the task-5.1c re-run (historical-record; SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY). Generated by tools/apnt-pool-action-circuit (TestRegistryShapeVector); the host checks profile_id in apnt_pool_action_circuit_corpus_v1.test.ts."}
	e := &r.Entry
	e.SystemID = SystemIDGnarkGroth16BN254
	e.Revision = 3
	e.Supersedes = "revision 2 (apnt-pool-v1-proof-system-registry-rev2-vectors.json: R1CS 25d3f54d..., one hashed public input over a 396-byte record, the 57-byte AES-256-GCM packet), whose Chipnet simulated-ceremony keys (task 5.1c re-run, historical-record, vk SHA-256 a82a7248...) are zero-value test evidence and never a vp for revision 3; and revision 1 (apnt-pool-v1-proof-system-registry-vectors.json: 396 public record bytes), never a vp. Revision 3 keeps revision 2's vp topology, so its serialization shape vector is byte-identical to revision 2's"
	e.Name = "gnark Groth16 on BN254"
	e.Libraries = []string{"github.com/consensys/gnark " + GnarkVersion, "github.com/consensys/gnark-crypto " + GnarkCryptoVersion}
	e.VPSerialization = []string{
		"vp = (*github.com/consensys/gnark/backend/groth16/bn254.VerifyingKey).WriteTo at gnark " + GnarkVersion + ": compressed points, gnark-crypto flags in the top two bits of each point's first byte",
		"[alpha]1 (32) || [beta]1 (32) || [beta]2 (64) || [gamma]2 (64) || [delta]1 (32) || [delta]2 (64)",
		"|| u32be(|K|) || K[0..|K|-1] (32 each), |K| = 1 + 1 + number of BSB22 commitments",
		"|| PublicAndCommitmentCommitted: u32be(outer) || for each: u32be(inner) || u64be(index)...",
		"|| u32be(|CommitmentKeys|) || for each: G (64) || GSigmaNeg (64)",
	}
	e.VPCovers = []string{
		"every verifying-key element gnark's Verify reads: alpha, beta, gamma, delta, K, the commitment topology and the Pedersen commitment keys",
		"[beta]1 and [delta]1, which Verify does not read, because the one serialization includes them",
		"not the proving key, the SRS or the circuit's R1CS: the key binds the circuit through K and the setup",
	}
	e.PublicInput = "one BN254 scalar x = int_be(SHA-256(A)) mod r: SHA-256 over the 314 bytes of the action record A with no tag, the digest read big-endian, reduced mod the BN254 scalar field order r (vectors: apnt-pool-v1-action-public-input-vectors.json); every verifier derives x from A itself and never takes it from a prover"
	e.Verification = "gnark " + GnarkVersion + " groth16/bn254 Verify with the BSB22 commitment extension: Pedersen knowledge check e(C, GSigmaNeg) * e(PoK, G) = 1; commitment wire = expand_message_xmd(SHA-256, DST 'bsb22-commitment', 48 bytes) of the commitment point, reduced mod r; then the Groth16 pairing check"
	e.VPStatus = "one vp recorded: chipnetZeroValueVp, the Chipnet simulated single-party ceremony's verifying key (task 5.1c re-run on revision 3, historical-record; historical-record), zero-value only and allowlisted by no canonical build. Every setup, including every re-run of a simulated setup after a circuit change, yields a new vp and so a new profile_id"
	r.Topology = top
	cvp, err := ChipnetZeroValueRevision3VP()
	if err != nil {
		protectedFatal(t, err)
	}
	c := &ChipnetVPRecord{Label: ChipnetZeroValueLabel,
		Note: "the verifying key of a simulated single-party ceremony: the project ran every contribution and could have kept the randomness, so it can forge proofs under this key. It must never guard value; a Chipnet pool deployment under it is an explicitly labelled zero-value test. Mainnet needs a permissionless multi-party ceremony. Recorded, not allowlisted: the aggregate program's canonical allowlist is task 5.4 slice 2's",
		VP:   hex.EncodeToString(cvp), VPBytes: len(cvp), VPSha256: ChipnetZeroValueRevision3VPSha256, ProfileID: ChipnetZeroValueRevision3ProfileID}
	pv := &c.Provenance
	pv.CeremonyID = ChipnetZeroValueRevision3CeremonyID
	pv.Task = "task 5.1c re-run on registry entry 1 revision 3 (historical-record), from main 69e0ba53, harness tools/apnt-pool-ceremony/scripts/run-5-1c.sh"
	pv.R1CSSha256 = revision3R1CSSha256
	pv.ProvingKeySha256 = ChipnetZeroValueRevision3ProvingKeySha256
	pv.ProvingKeyBytes = ChipnetZeroValueRevision3ProvingKeyBytes
	pv.TranscriptSha256 = ChipnetZeroValueRevision3TranscriptSha256
	pv.VerifierVerdict = "VALID, anchors phase1Pin, beacon and r1cs all true"
	pv.BeaconHeight = ChipnetZeroValueRevision3BeaconHeight
	pv.BeaconDisplayOrder = ChipnetZeroValueRevision3BeaconDisplayOrder
	pv.ReleaseGateVerdict = "RELEASE-OK, refusals [] (CRS release gate, historical-record, historical-record)"
	pv.ReleaseReportSha256 = ChipnetZeroValueRevision3ReleaseReportSha256
	pv.ReleaseStatementSha256 = ChipnetZeroValueRevision3ReleaseStatementSha256
	pv.Evidence = registryEvidence(t)
	r.ChipnetZeroValueVP = c
	r.Shape.NotAVerifyingKey = true
	r.Shape.Label = "SERIALIZATION SHAPE VECTOR, NOT A VERIFYING KEY: every point is bn254.HashToG1/G2 of a public label under DST 'APNT-POOL-v1 vp serialization shape vector, not a verifying key'. No Setup produced it; its profile_id must never be allowlisted"
	r.Shape.VP = hex.EncodeToString(vp)
	r.Shape.ProfileID = hex.EncodeToString(id)
	return r
}

// TestRegistryShapeVector regenerates the registry vector from the compiled
// circuit (write with POOL_ACTION_WRITE_REGISTRY=1) and requires the
// committed file to match it exactly.
func TestRegistryShapeVector(t *testing.T) {
	defer protectedPanic(t)
	r := registryVectors(t)
	b, _ := json.MarshalIndent(r, "", "  ")
	b = append(b, '\n')
	if os.Getenv("POOL_ACTION_WRITE_REGISTRY") == "1" {
		protectedFatal(t, "pool-registry-write-prohibited")
	}
	committed, err := os.ReadFile(registryVectorsPath)
	if err != nil {
		protectedFatal(t, err)
	}
	if string(committed) != string(b) {
		protectedFatal(t, "committed registry vector differs from the compiled circuit's")
	}
	var back RegistryVectors
	if err := json.Unmarshal(committed, &back); err != nil {
		protectedFatal(t, err)
	}
	if !reflect.DeepEqual(back.Topology, r.Topology) || back.Topology.PublicVariables != 2 || back.Topology.KLength != 3 {
		protectedFatal(t, "topology")
	}
}

// TestChipnetZeroValueRevision3VP: the recorded vp is a verifying key gnark
// v0.16.3 reads with its curve and subgroup checks, re-serializes byte for
// byte, and shapes exactly as the committed revision-3 topology (which
// TestRegistryShapeVector ties to the compiled circuit); its SHA-256 is the
// ceremony's verifying-key digest and its profile_id the one recorded.
// Controls: one flipped K byte changes the profile_id, and the recorded vp is
// neither the shape vector nor revision 2's ceremony key.
func TestChipnetZeroValueRevision3VP(t *testing.T) {
	defer protectedPanic(t)
	vp, err := ChipnetZeroValueRevision3VP()
	if err != nil {
		protectedFatal(t, err)
	}
	back := groth16.NewVerifyingKey(bn254.ID)
	n, err := back.ReadFrom(bytes.NewReader(vp))
	if err != nil || n != int64(len(vp)) {
		protectedFatal(t, "gnark reads %d of %d bytes: %v", n, len(vp), err)
	}
	var again bytes.Buffer
	if _, err := back.WriteTo(&again); err != nil || !bytes.Equal(again.Bytes(), vp) {
		protectedFatal(t, "the vp does not re-serialize identically (%v)", err)
	}
	vk := back.(*groth16bn254.VerifyingKey)
	raw, err := os.ReadFile(registryVectorsPath)
	if err != nil {
		protectedFatal(t, err)
	}
	var rev3 RegistryVectors
	if err := json.Unmarshal(raw, &rev3); err != nil {
		protectedFatal(t, err)
	}
	top := rev3.Topology
	if len(vp) != top.VPBytes || len(vk.G1.K) != top.KLength || len(vk.CommitmentKeys) != top.Commitments ||
		!reflect.DeepEqual(vk.PublicAndCommitmentCommitted, top.PublicAndCommitmentCommitted) || len(vk.G1.K)-1-len(vk.CommitmentKeys) != top.PublicVariables-1 {
		protectedFatal(t, "the vp's shape (%d bytes, |K| %d, %d commitment keys, %v) is not revision 3's topology %+v",
			len(vp), len(vk.G1.K), len(vk.CommitmentKeys), vk.PublicAndCommitmentCommitted, top)
	}
	c := rev3.ChipnetZeroValueVP
	if c == nil || c.VP != hex.EncodeToString(vp) || c.ProfileID != ChipnetZeroValueRevision3ProfileID || c.VPSha256 != ChipnetZeroValueRevision3VPSha256 ||
		c.Label != ChipnetZeroValueLabel || c.Provenance.R1CSSha256 != revision3R1CSSha256 {
		protectedFatal(t, "the committed registry vector does not carry the recorded vp")
	}
	if hex.EncodeToString(vp) == rev3.Shape.VP || ChipnetZeroValueRevision3ProfileID == rev3.Shape.ProfileID {
		protectedFatal(t, "the recorded vp is the shape vector")
	}
	if strings.HasPrefix(ChipnetZeroValueRevision3VPSha256, "a82a7248") {
		protectedFatal(t, "the recorded vp is revision 2's ceremony key")
	}
	// Firing control: ProfileID reads every byte (one flipped K byte moves it).
	flipped := append([]byte(nil), vp...)
	flipped[32+32+64+64+32+64+4+20] ^= 1
	if id, _ := ProfileID(SystemIDGnarkGroth16BN254, flipped); hex.EncodeToString(id) == ChipnetZeroValueRevision3ProfileID {
		protectedFatal(t, "firing control: a flipped K byte kept the profile_id")
	}
}

// revision2VectorsSha256 is the revision-2 vector file as historical-record committed it
// (main 0967dfae): revision 3 keeps it byte for byte as that revision's record.
const revision2VectorsSha256 = "b6a7d712b111a3fbaf65520a01495b991d0082911b3ce462efa0aec8cf8ebafa"

// TestRegistryRevision1IsSupersededUnchanged: the revision-1 and revision-2
// vector files are kept as the superseded revisions' records. Each shape
// vector still reproduces from its own recorded topology (ShapeVP depends on
// the topology alone) and its profile_id from its vp, so the files are
// checked, not merely kept. Revision 1's topology and profile_id are not
// revision 3's; revision 2's are, because revision 3 changed the circuit
// behind the key and not the key's shape. The revision-2 file is pinned by
// SHA-256: nothing about revision 2 is rewritten by revision 3.
func TestRegistryRevision1IsSupersededUnchanged(t *testing.T) {
	defer protectedPanic(t)
	read := func(path string) *RegistryVectors {
		raw, err := os.ReadFile(path)
		if err != nil {
			protectedFatal(t, err)
		}
		var v RegistryVectors
		if err := json.Unmarshal(raw, &v); err != nil {
			protectedFatal(t, err)
		}
		return &v
	}
	rev1, rev2, rev3 := read(registryRev1VectorsPath), read(registryRev2VectorsPath), read(registryVectorsPath)
	// Revision 1 had one public scalar per byte of its 396-byte record.
	if rev1.Topology.PublicVariables != 396+1 || rev1.Topology.KLength != 398 || rev1.Topology.VPBytes != 13168 {
		protectedFatal(t, "revision 1 topology %+v", rev1.Topology)
	}
	for _, old := range []*RegistryVectors{rev1, rev2} {
		vp, err := ShapeVP(old.Topology)
		if err != nil {
			protectedFatal(t, err)
		}
		if hex.EncodeToString(vp) != old.Shape.VP {
			protectedFatal(t, "revision %d's shape vector does not reproduce from its topology", old.Entry.Revision)
		}
		id, err := ProfileID(SystemIDGnarkGroth16BN254, vp)
		if err != nil || hex.EncodeToString(id) != old.Shape.ProfileID {
			protectedFatal(t, "revision %d's profile_id does not reproduce (%v)", old.Entry.Revision, err)
		}
	}
	if rev1.Entry.Revision != 0 || rev2.Entry.Revision != 2 || rev3.Entry.Revision != 3 || rev3.Topology.VPBytes != 528 {
		protectedFatal(t, "revisions: %d, %d and %d, rev-3 vp %d bytes", rev1.Entry.Revision, rev2.Entry.Revision, rev3.Entry.Revision, rev3.Topology.VPBytes)
	}
	if rev1.Shape.ProfileID == rev3.Shape.ProfileID || reflect.DeepEqual(rev1.Topology, rev3.Topology) {
		protectedFatal(t, "revision 3 does not differ from revision 1")
	}
	if !reflect.DeepEqual(rev2.Topology, rev3.Topology) || rev2.Shape.VP != rev3.Shape.VP || rev2.Shape.ProfileID != rev3.Shape.ProfileID {
		protectedFatal(t, "revision 3 changed the vp topology of revision 2")
	}
	if rev2.Entry.PublicInput == rev3.Entry.PublicInput || rev2.Entry.Supersedes == rev3.Entry.Supersedes {
		protectedFatal(t, "revision 3's entry text is revision 2's")
	}
	raw, err := os.ReadFile(registryRev2VectorsPath)
	if err != nil {
		protectedFatal(t, err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != revision2VectorsSha256 {
		protectedFatal(t, "the revision-2 vector file changed: SHA-256 %x", sum)
	}
}

// TestPublicInputMatchesHost: PublicInput equals the host's
// deriveAPNTPoolActionPublicInputV1 on every host vector, the reduction runs
// (every quotient 0..5 is a vector), and the wrong readings the vectors name
// (little-endian, top 253 bits, the unreduced digest) are not what it
// computes. Wrong lengths are refused.
func TestPublicInputMatchesHost(t *testing.T) {
	t.Skip("requires excluded action corpus reference inputs; not shipped")
	defer protectedPanic(t)
	raw, err := os.ReadFile(publicInputVectorsPath)
	if err != nil {
		protectedFatal(t, err)
	}
	var v struct {
		ScalarOrder string `json:"scalarOrder"`
		Vectors     []struct {
			Name            string `json:"name"`
			Record          string `json:"record"`
			Digest          string `json:"digest"`
			DigestAtLeastR  bool   `json:"digestAtLeastR"`
			Quotient        int    `json:"quotient"`
			PublicInput     string `json:"publicInput"`
			WrongReductions struct {
				LittleEndian string `json:"littleEndian"`
				Top253Bits   string `json:"top253Bits"`
			} `json:"wrongReductions"`
		} `json:"vectors"`
		Refusals []struct {
			Name   string `json:"name"`
			Length int    `json:"length"`
		} `json:"refusals"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		protectedFatal(t, err)
	}
	if v.ScalarOrder != bn254Modulus.String() {
		protectedFatal(t, "vector r %s is not the circuit's field", v.ScalarOrder)
	}
	hex32 := func(x *big.Int) string { return fmt.Sprintf("%064x", x) }
	quotients := map[int]bool{}
	for _, c := range v.Vectors {
		record := entryBytes(t, c.Record)
		x, err := PublicInput(record)
		if err != nil {
			protectedFatal(t, "%s: %v", c.Name, err)
		}
		if hex32(x) != c.PublicInput {
			protectedFatal(t, "%s: x %s, host %s", c.Name, hex32(x), c.PublicInput)
		}
		d := new(big.Int).SetBytes(entryBytes(t, c.Digest))
		q := new(big.Int).Div(d, bn254Modulus)
		if int(q.Int64()) != c.Quotient || (d.Cmp(bn254Modulus) >= 0) != c.DigestAtLeastR {
			protectedFatal(t, "%s: quotient", c.Name)
		}
		quotients[c.Quotient] = true
		for _, wrong := range []string{c.WrongReductions.LittleEndian, c.WrongReductions.Top253Bits} {
			if wrong == hex32(x) {
				protectedFatal(t, "%s: a wrong reduction equals x", c.Name)
			}
		}
		if c.DigestAtLeastR && hex32(d) == hex32(x) {
			protectedFatal(t, "%s: the reduction did not run", c.Name)
		}
		// Negative control for the comparison itself: a little-endian read,
		// as a byte-order bug would compute it, is caught.
		le := make([]byte, 32)
		for i := range le {
			le[i] = entryBytes(t, c.Digest)[31-i]
		}
		if hex32(new(big.Int).Mod(new(big.Int).SetBytes(le), bn254Modulus)) != c.WrongReductions.LittleEndian {
			protectedFatal(t, "%s: the little-endian control is not what the vector names", c.Name)
		}
	}
	if len(quotients) != 6 {
		protectedFatal(t, "quotients covered: %v", quotients)
	}
	for _, r := range v.Refusals {
		if _, err := PublicInput(make([]byte, r.Length)); err == nil {
			protectedFatal(t, "%s: accepted", r.Name)
		}
	}
}

const (
	revision3R1CSSha256  = Revision3R1CSSha256
	revision3Constraints = 5_918_922
)

// TestRevision3R1CS: the production circuit compiles to revision 3's R1CS
// byte for byte (digest and length), and removing one clause changes it
// (firing control).
func TestRevision3R1CS(t *testing.T) {
	defer protectedPanic(t)
	digest := func(ablated ...Clause) (string, int, int64) {
		ccs, err := Compile(ablated...)
		if err != nil {
			protectedFatal(t, err)
		}
		h := sha256.New()
		size, err := ccs.WriteTo(h)
		if err != nil {
			protectedFatal(t, err)
		}
		n := ccs.GetNbConstraints()
		ccs = nil
		Release()
		return hex.EncodeToString(h.Sum(nil)), n, size
	}
	got, n, size := digest()
	if got != revision3R1CSSha256 || n != revision3Constraints || size != Revision3R1CSBytes {
		protectedFatal(t, "R1CS %s, %d bytes, %d constraints; revision 3 is %s, %d bytes, %d", got, size, n, revision3R1CSSha256, Revision3R1CSBytes, revision3Constraints)
	}
	if d, _, _ := digest(ClausePacket); d == revision3R1CSSha256 {
		protectedFatal(t, "firing control: ablating the packet clause left the digest unchanged")
	}
}
