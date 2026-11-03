// Package poolaction is the APNT shielded pool v1 action circuit: gnark
// v0.16.3, Groth16 on BN254 (proof-system registry id 1).
//
// The canonical relation is the host's
// (packages/protocol-runtime/src/apnt_pool_action_relation_v1.ts,
// design.md "Actions" 1–7). This circuit must match it and never redefine it:
// every host check has a named clause below, and the parity tests in this
// module run the host's own positive and negative vectors through the compiled
// constraint system.
//
// Public input: one BN254 scalar, x = int_be(SHA-256(A)) mod r, with r the
// BN254 scalar field order (HUM-80, ENG-437). The 314 bytes of the action
// record A are private witness; clause record-hash hashes the same record
// variables every other clause reads and binds x to them. Every verifier
// derives x from the A it holds and never takes it from a prover.
//
// Registry entry 1 revision 3 (pad16, HUM-84, ENG-454): each output's rcm is
// derived in-circuit, rcm = SHA-256("APNT-POOL-v1:rcm" ‖ K ‖ ρ), and its packet
// is 16 bytes, (u64le(v) ⊕ d[0..8)) ‖ d[8..16) with
// d = SHA-256("APNT-POOL-v1:pad" ‖ K ‖ ρ ‖ cm). There is no AES-GCM in the
// circuit. The clauses, their order and the witness field names are those of
// ARCH-247's pad16 prototype (lane/pool-packet-compress 46a238c6,
// compactpacket), so this circuit compiles to its R1CS; revision 2 (R1CS
// 25d3f54d…, the 57-byte AES-256-GCM packet and a payer-chosen rcm) is
// superseded and its record is kept (registry.go).
//
// Private witness: the record A, and per input slot: the value's u64le bytes, ak as affine
// secp256k1 coordinates, nk, ρ, rcm, the note's recovery tag, α and a depth-32
// membership path. Per output slot: the value's u64le bytes, the recipient's
// owner tag O, ρ and K; no rcm, which the circuit derives. There is no field
// for ask or rsk: a delegate that holds the whole witness can prove and still
// cannot sign.
//
// This package compiles and checks parity only: it runs no Setup and no
// proof. Package devprove runs Setup and prove under development zero-value
// parameters, for the task-5.1b measurement.
package poolaction

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/rangecheck"
)

// Fp and Fr are secp256k1's base and scalar fields, emulated over BN254.
type (
	Fp = emulated.Secp256k1Fp
	Fr = emulated.Secp256k1Fr
)

// MaxMoneySats is BCH MAX_MONEY. MaxMoneySats < 2^51, so v ≤ MAX_MONEY exactly
// when MAX_MONEY − v, taken in the native field, lies in [0, 2^51) for any
// v ∈ [0, 2^64).
const (
	MaxMoneySats = 2_100_000_000_000_000
	maxMoneyBits = 51
	RecordBytes  = 314
	TreeDepth    = 32
	PacketBytes  = 16
)

// Record offsets, design.md "Action record A" (revision 3: the fields after
// the 16-byte packets moved up by 82 bytes).
const (
	OffAnchor     = 0
	OffNullifier0 = 32
	OffNullifier1 = 64
	OffRk0        = 96
	OffRk1        = 129
	OffCm0        = 162
	OffCm1        = 194
	OffPacket0    = 226
	OffPacket1    = 242
	OffDeposit    = 258
	OffWithdrawal = 266
	OffFee        = 274
	OffWlock      = 282
)

// Domain tags, design.md "Canonical encodings". ASCII, no length prefix.
const (
	tagCommitment  = "APNT-POOL-v1:cm"
	tagNullifier   = "APNT-POOL-v1:nf"
	tagOwner       = "APNT-POOL-v1:owner"
	tagNkc         = "APNT-POOL-v1:nkc"
	tagRecoveryTag = "APNT-POOL-v1:rt"
	tagTreeNode    = "APNT-POOL-v1:node"
	TagRcm         = "APNT-POOL-v1:rcm" // rcm = SHA-256(rcm ‖ K ‖ ρ)
	TagPad         = "APNT-POOL-v1:pad" // d = SHA-256(pad ‖ K ‖ ρ ‖ cm)
	// tagRetiredPacketKey is revision 2's AES-256-GCM packet-key tag, retired
	// by pad16. Only mutationPadUnderPacketKeyTag uses it.
	tagRetiredPacketKey = "APNT-POOL-v1:pk"
)

// InputSlot is one spent note, real or dummy.
type InputSlot struct {
	Value        [8]uints.U8 // u64le(v)
	AkX, AkY     emulated.Element[Fp]
	Nk           [32]uints.U8
	Rho          [32]uints.U8
	Rcm          [32]uints.U8
	RecoveryTag  [32]uints.U8 // the spent note's tag = SHA-256(rt ‖ K)
	Alpha        emulated.Element[Fr]
	Siblings     [TreeDepth][32]uints.U8 // leaf level first
	PositionBits [TreeDepth]frontend.Variable
}

// OutputSlot is one created note, real or dummy. It has no rcm field: the
// circuit derives rcm from RecoveryKey and Rho (clause output-commitment).
type OutputSlot struct {
	Value       [8]uints.U8 // u64le(v)
	OwnerTag    [32]uints.U8
	Rho         [32]uints.U8
	RecoveryKey [32]uints.U8 // K
}

// ActionCircuit is the complete action relation. The zero value (or
// NewActionCircuit) is the production circuit; ablated is set only by this
// package's mutation tests.
//
// RecordHash is the only public variable. Record is private: its bytes are
// range-checked by clause record-bytes (and again by the record-hash SHA-256
// gadget), exactly as when they were public.
type ActionCircuit struct {
	RecordHash frontend.Variable `gnark:",public"`
	Record     [RecordBytes]uints.U8
	In         [2]InputSlot
	Out        [2]OutputSlot

	ablated map[Clause]bool `gnark:"-"`
}

// NewActionCircuit returns the production circuit: no clause ablated.
func NewActionCircuit() *ActionCircuit { return &ActionCircuit{} }

// Clause names one guard of the relation. Each host failure code maps to one
// or more clauses (see ClauseHostCode).
type Clause string

const (
	ClauseRecordBytes       Clause = "record-bytes"           // every A byte in [0, 255]
	ClauseWitnessBytes      Clause = "witness-bytes"          // every private byte in [0, 255]
	ClauseRecordAmounts     Clause = "record-amounts"         // deposit, withdrawal, fee ≤ MAX_MONEY
	ClauseWithdrawalLock    Clause = "withdrawal-lock"        // wlock_hash = 0^32 iff withdrawal = 0
	ClauseValueMaxMoney     Clause = "value-max-money"        // each note value ≤ MAX_MONEY
	ClauseSpendKeyOnCurve   Clause = "spend-key-on-curve"     // ak on secp256k1 (or (0,0))
	ClauseSpendKeyFinite    Clause = "spend-key-not-infinity" // ak ≠ (0,0)
	ClauseAlphaRange        Clause = "alpha-range"            // α < n_G
	ClauseRkFinite          Clause = "rk-not-infinity"        // ak + α·G ≠ infinity
	ClauseRkEqual           Clause = "rk-equals-record"       // SEC1c(ak + α·G) = A.rk_s
	ClauseOwnerTagOverNkc   Clause = "owner-tag-over-nkc"     // O takes nkc = SHA-256(nkc ‖ nk) of the nullifier's nk
	ClauseNullifier         Clause = "nullifier"              // SHA-256(nf ‖ nk ‖ ρ ‖ cm_in) = A.nf_s
	ClauseNullifierDistinct Clause = "nullifier-distinct"     // A.nf_0 ≠ A.nf_1
	ClausePositionBits      Clause = "position-bits-boolean"  // membership position bits in {0, 1}
	ClauseMembership        Clause = "membership"             // v ≠ 0 ⇒ path root = A.anchor
	ClauseRhoIndex          Clause = "rho-index"              // ρ_out_j = A.nf_j
	ClauseOutputCommitment  Clause = "output-commitment"      // cm_j = A.cm_j, over rcm = SHA-256(rcm ‖ K ‖ ρ)
	ClausePacket            Clause = "packet"                 // pad16 packet_j = A.packet_j
	ClauseBalance           Clause = "balance"                // Σ v_in + deposit = Σ v_out + withdrawal + fee
	ClauseRecordHash        Clause = "record-hash"            // x = int_be(SHA-256(A)) mod r, the one public input
)

// mutationMembershipAlways is a test-only mutation, not a clause: it enforces
// membership for every input whatever its value (a completeness control for
// the v ≠ 0 exemption).
const mutationMembershipAlways Clause = "mutation-membership-always"

// mutationNullifierOverNkc is a test-only mutation, not a clause: the faulty
// build that feeds nkc where the nullifier needs nk (ENG-329). A holder of nkc
// could then compute nf.
const mutationNullifierOverNkc Clause = "mutation-nullifier-over-nkc"

// mutationRecordHashUnbound is a test-only mutation, not a clause: clause
// record-hash computes the record's hash and range-checks its digest bytes
// but does not compare the result with the public input. The binding-ablated
// hint-negative phase uses it, so that no computed value is compared with a
// public one there; ablating ClauseRecordHash instead removes the whole hash.
const mutationRecordHashUnbound Clause = "mutation-record-hash-unbound"

// Test-only mutations of the pad16 output side (ARCH-247), never a
// production path: each is a faulty build that admits its own corpus negative
// and refuses the honest record.
const (
	mutationRcmWithoutRho        Clause = "mutation-rcm-without-rho"       // output 0's rcm = SHA-256(rcm ‖ K): ρ left out of the derivation
	mutationRcmOtherSlotRho      Clause = "mutation-rcm-other-slot-rho"    // output 0's rcm over output 1's ρ
	mutationPacketKeyWithoutCm   Clause = "mutation-packet-key-without-cm" // output 0's d = SHA-256(pad ‖ K ‖ ρ): the pre-REV-129 key's shape
	mutationPadCheckUnbound      Clause = "mutation-pad-check-unbound"     // neither output's 8-byte key check compared
	mutationPadUnderPacketKeyTag Clause = "mutation-pad-under-pk-tag"      // output 0's d under revision 2's pk tag
)

// Measurement-only variants, set only by this package's tests: each omits a
// whole computation block (not just its assertion) so the block's marginal
// constraint cost can be compared with the ARCH-141 memo's variants. They are
// never a production path.
const (
	measureOmitMembership Clause = "measure-omit-membership" // the depth-32 paths and their check
	measureOmitRk         Clause = "measure-omit-rk"         // α range, α·G, ak + α·G, SEC1c(R) and its checks
	measureOmitPacket     Clause = "measure-omit-packet"     // the packet digest hash and the pad
	measureOmitRcmHash    Clause = "measure-omit-rcm"        // the rcm derivation: rcm taken as 32 zero bytes, no hash
)

// Clauses lists every clause in Define order.
var Clauses = []Clause{
	ClauseRecordBytes, ClauseWitnessBytes, ClauseRecordAmounts, ClauseWithdrawalLock, ClauseValueMaxMoney,
	ClauseSpendKeyOnCurve, ClauseSpendKeyFinite, ClauseAlphaRange, ClauseRkFinite, ClauseRkEqual,
	ClauseOwnerTagOverNkc, ClauseNullifier, ClauseNullifierDistinct, ClausePositionBits, ClauseMembership, ClauseRhoIndex,
	ClauseOutputCommitment, ClausePacket, ClauseBalance, ClauseRecordHash,
}

// ClauseHostCode is the host failure code (apnt_pool_contract_v1.ts) each
// clause enforces. Several clauses can serve one code. The two byte-range
// clauses are structural in the host, whose record and witness fields are
// byte arrays by type: the nearest host codes are the strict record decoder's
// and the witness shape's. Clause record-hash is structural in the host too:
// the host relation evaluates A itself, and the public-input rule
// (deriveAPNTPoolActionPublicInputV1) takes exactly 314 bytes and refuses
// anything else with the record decoder's length code.
var ClauseHostCode = map[Clause]string{
	ClauseRecordBytes:       "pool-record-length",
	ClauseWitnessBytes:      "pool-witness-shape",
	ClauseRecordAmounts:     "pool-record-amount",
	ClauseWithdrawalLock:    "pool-record-withdrawal-lock",
	ClauseValueMaxMoney:     "pool-value-range",
	ClauseSpendKeyOnCurve:   "pool-spend-key",
	ClauseSpendKeyFinite:    "pool-spend-key",
	ClauseAlphaRange:        "pool-rerandomizer",
	ClauseRkFinite:          "pool-rerandomized-key",
	ClauseRkEqual:           "pool-rerandomized-key",
	ClauseOwnerTagOverNkc:   "pool-nullifier",
	ClauseNullifier:         "pool-nullifier",
	ClauseNullifierDistinct: "pool-nullifier-duplicate",
	ClausePositionBits:      "pool-membership",
	ClauseMembership:        "pool-membership",
	ClauseRhoIndex:          "pool-rho-index",
	ClauseOutputCommitment:  "pool-output-commitment",
	ClausePacket:            "pool-packet",
	ClauseBalance:           "pool-balance",
	ClauseRecordHash:        "pool-record-length",
}

func (c *ActionCircuit) on(cl Clause) bool { return !c.ablated[cl] }

// action carries the gadgets one Define call shares.
type action struct {
	api   frontend.API
	bytes *uints.Bytes
	rc    frontend.Rangechecker
	fp    *emulated.Field[Fp]
	fr    *emulated.Field[Fr]
	curve *sw_emulated.Curve[Fp, Fr]
	c     *ActionCircuit
}

// Define is the relation. Clause order follows the host's checkAction.
func (c *ActionCircuit) Define(api frontend.API) error {
	b, err := uints.NewBytes(api)
	if err != nil {
		return fmt.Errorf("bytes: %w", err)
	}
	fp, err := emulated.NewField[Fp](api)
	if err != nil {
		return fmt.Errorf("fp: %w", err)
	}
	fr, err := emulated.NewField[Fr](api)
	if err != nil {
		return fmt.Errorf("fr: %w", err)
	}
	curve, err := sw_emulated.New[Fp, Fr](api, sw_emulated.GetSecp256k1Params())
	if err != nil {
		return fmt.Errorf("curve: %w", err)
	}
	a := &action{api: api, bytes: b, rc: rangecheck.New(api), fp: fp, fr: fr, curve: curve, c: c}
	A := c.Record[:]

	a.clauseByteRanges()
	a.clauseRecordAmounts(A)
	a.clauseWithdrawalLock(A)
	a.clauseValueMaxMoney()

	var inputCm [2][]uints.U8
	for s := 0; s < 2; s++ {
		in := &c.In[s]
		ak := sw_emulated.AffinePoint[Fp]{X: in.AkX, Y: in.AkY}
		a.clauseSpendKey(&ak)
		if !c.ablated[measureOmitRk] {
			a.clauseRerandomizedKey(&ak, &in.Alpha, A[OffRk0+33*s:OffRk0+33*(s+1)])
		}
		inputCm[s] = a.clauseNullifier(s, in, &ak, A[OffNullifier0+32*s:OffNullifier0+32*(s+1)])
	}
	a.clauseNullifierDistinct(A[OffNullifier0:OffNullifier0+32], A[OffNullifier1:OffNullifier1+32])
	for s := 0; s < 2 && !c.ablated[measureOmitMembership]; s++ {
		a.clauseMembership(&c.In[s], inputCm[s], A[OffAnchor:OffAnchor+32])
	}
	for j := 0; j < 2; j++ {
		out := &c.Out[j]
		a.clauseRhoIndex(out, A[OffNullifier0+32*j:OffNullifier0+32*(j+1)])
		cm := a.clauseOutputCommitment(j, out, A[OffCm0+32*j:OffCm0+32*(j+1)])
		if !c.ablated[measureOmitPacket] {
			a.clausePacket(j, out, cm, A[OffPacket0+PacketBytes*j:OffPacket0+PacketBytes*(j+1)])
		}
	}
	a.clauseBalance(A)
	a.clauseRecordHash(A)
	return nil
}

// --- byte helpers ---

func constBytes(s string) []uints.U8 { return uints.NewU8Array([]byte(s)) }

func (a *action) sha256(parts ...[]uints.U8) []uints.U8 {
	h, err := sha2.New(a.api)
	if err != nil {
		panic(err)
	}
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum()
}

// raw is a byte's variable without a range check. Every byte this circuit
// reads raw is range-checked by clauseByteRanges, or is produced by a gadget
// whose output is a byte by construction.
func (a *action) raw(v uints.U8) frontend.Variable { return a.bytes.ValueUnchecked(v) }

// u64le recomposes eight bytes, least significant first.
func (a *action) u64le(v []uints.U8) frontend.Variable {
	acc := frontend.Variable(0)
	for i := 7; i >= 0; i-- {
		acc = a.api.Add(a.api.Mul(acc, 256), a.raw(v[i]))
	}
	return acc
}

func (a *action) assertBytesEqual(x, y []uints.U8) {
	if len(x) != len(y) {
		panic("length mismatch")
	}
	for i := range x {
		a.api.AssertIsEqual(a.raw(x[i]), a.raw(y[i]))
	}
}

// sec1c is SEC1 compressed encoding of an affine point: 0x02 + parity(y),
// then x big-endian, both from the canonical (fully reduced) representative.
func (a *action) sec1c(x, y *emulated.Element[Fp]) []uints.U8 {
	xb := a.fp.ToBitsCanonical(x)
	yb := a.fp.ToBitsCanonical(y)
	out := make([]uints.U8, 33)
	out[0] = uints.U8{Val: a.api.Add(2, yb[0])}
	for i := 0; i < 32; i++ {
		byteIndex := 31 - i // xb is little-endian
		v := frontend.Variable(0)
		for k := 7; k >= 0; k-- {
			v = a.api.Add(a.api.Mul(v, 2), xb[8*byteIndex+k])
		}
		out[1+i] = uints.U8{Val: v}
	}
	return out
}

// --- clauses ---

// clauseByteRanges: every byte of the record A, and every other private
// byte, is in [0, 255].
//
// Record bytes are read raw by every relation clause. This clause
// range-checks them first (629 constraints at 314 bytes, measured with clause
// record-hash also removed; 792 at revision 2's 396); clause record-hash's SHA-256
// gadget checks the same variables again, deduplicated, so since ENG-437 it
// overlaps this clause for the record (the parity suite records it). Other
// private bytes are also range-checked by the
// gadget that consumes them (SHA-256 message words through uints.Value, the
// value bytes again through the packet's lookup XORs), deduplicated per
// variable, so for them this clause adds nothing. Membership siblings are the exception: they
// feed the linear selection, and the SHA-256 gadget checks the selected
// left/right bytes, which with boolean position bits implies the sibling's
// range. Their explicit checks (2,048 bytes, 4,100 constraints) are therefore
// redundant; they are kept, and the parity suite records the overlap.
func (a *action) clauseByteRanges() {
	if a.c.on(ClauseRecordBytes) {
		for i := range a.c.Record {
			a.bytes.Value(a.c.Record[i])
		}
	}
	if a.c.on(ClauseWitnessBytes) {
		check := func(v []uints.U8) {
			for i := range v {
				a.bytes.Value(v[i])
			}
		}
		for s := range a.c.In {
			in := &a.c.In[s]
			check(in.Value[:])
			check(in.Nk[:])
			check(in.Rho[:])
			check(in.Rcm[:])
			check(in.RecoveryTag[:])
			for h := range in.Siblings {
				check(in.Siblings[h][:])
			}
		}
		for j := range a.c.Out {
			out := &a.c.Out[j]
			check(out.Value[:])
			check(out.OwnerTag[:])
			check(out.Rho[:])
			check(out.RecoveryKey[:])
		}
	}
}

// clauseRecordAmounts: deposit, withdrawal and fee are each ≤ MAX_MONEY
// (host: the record decoder, pool-record-amount).
func (a *action) clauseRecordAmounts(A []uints.U8) {
	if !a.c.on(ClauseRecordAmounts) {
		return
	}
	for _, off := range []int{OffDeposit, OffWithdrawal, OffFee} {
		a.rc.Check(a.api.Sub(MaxMoneySats, a.u64le(A[off:off+8])), maxMoneyBits)
	}
}

// clauseWithdrawalLock: wlock_hash is 32 zero bytes if and only if the
// withdrawal is 0 (host: pool-record-withdrawal-lock). Bytes are in range, so
// the byte sums below cannot wrap.
func (a *action) clauseWithdrawalLock(A []uints.U8) {
	if !a.c.on(ClauseWithdrawalLock) {
		return
	}
	sum := frontend.Variable(0)
	for i := 0; i < 32; i++ {
		sum = a.api.Add(sum, a.raw(A[OffWlock+i]))
	}
	withdrawal := frontend.Variable(0)
	for i := 0; i < 8; i++ {
		withdrawal = a.api.Add(withdrawal, a.raw(A[OffWithdrawal+i]))
	}
	a.api.AssertIsEqual(a.api.IsZero(withdrawal), a.api.IsZero(sum))
}

// clauseValueMaxMoney: every note value is ≤ MAX_MONEY (host:
// pool-value-range). The value's eight bytes already bound it to [0, 2^64).
func (a *action) clauseValueMaxMoney() {
	if !a.c.on(ClauseValueMaxMoney) {
		return
	}
	for s := range a.c.In {
		a.rc.Check(a.api.Sub(MaxMoneySats, a.u64le(a.c.In[s].Value[:])), maxMoneyBits)
	}
	for j := range a.c.Out {
		a.rc.Check(a.api.Sub(MaxMoneySats, a.u64le(a.c.Out[j].Value[:])), maxMoneyBits)
	}
}

// clauseSpendKey: ak is a secp256k1 point and not the point at infinity
// (host: pool-spend-key). gnark's AssertIsOnCurve admits (0,0) as its
// infinity convention, so the second check is separate.
func (a *action) clauseSpendKey(ak *sw_emulated.AffinePoint[Fp]) {
	if a.c.on(ClauseSpendKeyOnCurve) {
		a.curve.AssertIsOnCurve(ak)
	}
	if a.c.on(ClauseSpendKeyFinite) {
		a.api.AssertIsEqual(a.api.And(a.fp.IsZero(&ak.X), a.fp.IsZero(&ak.Y)), 0)
	}
}

// clauseRerandomizedKey: α ∈ [0, n_G) (host: pool-rerandomizer);
// R = ak + α·G is not infinity and SEC1c(R) = A.rk_s (host:
// pool-rerandomized-key). A.rk_s is then a valid compressed point, which is
// the host's pool-record-key check.
func (a *action) clauseRerandomizedKey(ak *sw_emulated.AffinePoint[Fp], alpha *emulated.Element[Fr], rk []uints.U8) {
	if a.c.on(ClauseAlphaRange) {
		a.fr.AssertIsInRange(alpha)
	}
	// Complete arithmetic (the default): α = 0 gives (0,0), and AddUnified
	// handles (0,0), doubling and p = −q.
	R := a.curve.AddUnified(ak, a.curve.ScalarMulBase(alpha))
	if a.c.on(ClauseRkFinite) {
		a.api.AssertIsEqual(a.api.And(a.fp.IsZero(&R.X), a.fp.IsZero(&R.Y)), 0)
	}
	if a.c.on(ClauseRkEqual) {
		a.assertBytesEqual(a.sec1c(&R.X, &R.Y), rk)
	}
}

// clauseOwnerTagOverNkc returns what the input's owner tag commits to in
// place of nk: nkc = SHA-256("APNT-POOL-v1:nkc" ‖ nk), computed from the same
// nk variable the nullifier takes (ENG-329; host: the owner tag inside
// pool-nullifier). Removing the clause hashes nk into the owner tag directly,
// the pre-ENG-329 owner tag: a witness could then present a note's nkc as its
// nk, and its nf would be SHA-256(nf ‖ nkc ‖ ρ ‖ cm), which a holder of nkc
// computes.
func (a *action) clauseOwnerTagOverNkc(in *InputSlot) []uints.U8 {
	if !a.c.on(ClauseOwnerTagOverNkc) {
		return in.Nk[:]
	}
	return a.sha256(constBytes(tagNkc), in.Nk[:])
}

// clauseNullifier computes the input note's commitment under its owner tag
// and checks its nullifier (host: pool-nullifier). It returns cm_in.
//
//	nkc   = SHA-256("APNT-POOL-v1:nkc" ‖ nk)
//	O     = SHA-256("APNT-POOL-v1:owner" ‖ SEC1c(ak) ‖ nkc)
//	cm_in = SHA-256("APNT-POOL-v1:cm" ‖ u64le(v) ‖ O ‖ ρ ‖ rcm ‖ tag)
//	nf    = SHA-256("APNT-POOL-v1:nf" ‖ nk ‖ ρ ‖ cm_in)
func (a *action) clauseNullifier(s int, in *InputSlot, ak *sw_emulated.AffinePoint[Fp], nfPublic []uints.U8) []uints.U8 {
	nkc := a.clauseOwnerTagOverNkc(in)
	owner := a.sha256(constBytes(tagOwner), a.sec1c(&ak.X, &ak.Y), nkc)
	cm := a.sha256(constBytes(tagCommitment), in.Value[:], owner, in.Rho[:], in.Rcm[:], in.RecoveryTag[:])
	nfKey := in.Nk[:]
	if a.c.ablated[mutationNullifierOverNkc] {
		nfKey = nkc
	}
	nf := a.sha256(constBytes(tagNullifier), nfKey, in.Rho[:], cm)
	if a.c.on(ClauseNullifier) {
		a.assertBytesEqual(nf, nfPublic)
	}
	return cm
}

// clauseNullifierDistinct: A.nf_0 ≠ A.nf_1 (host: pool-nullifier-duplicate).
// Each nullifier is packed injectively into a 31-byte and a 1-byte element.
func (a *action) clauseNullifierDistinct(nf0, nf1 []uints.U8) {
	if !a.c.on(ClauseNullifierDistinct) {
		return
	}
	pack := func(v []uints.U8) frontend.Variable {
		acc := frontend.Variable(0)
		for i := range v {
			acc = a.api.Add(a.api.Mul(acc, 256), a.raw(v[i]))
		}
		return acc
	}
	high := a.api.Sub(pack(nf0[:31]), pack(nf1[:31]))
	low := a.api.Sub(pack(nf0[31:]), pack(nf1[31:]))
	a.api.AssertIsEqual(a.api.And(a.api.IsZero(high), a.api.IsZero(low)), 0)
}

// clauseMembership: the input's commitment reaches A.anchor along its depth-32
// path whenever v ≠ 0, and only then (host: pool-membership). Bit h set means
// the running node is the right child at level h.
//
//	node(l, r) = SHA-256("APNT-POOL-v1:node" ‖ l ‖ r)
func (a *action) clauseMembership(in *InputSlot, leaf []uints.U8, anchor []uints.U8) {
	if a.c.on(ClausePositionBits) {
		for h := range in.PositionBits {
			a.api.AssertIsBoolean(in.PositionBits[h])
		}
	}
	current := leaf
	for h := 0; h < TreeDepth; h++ {
		bit := in.PositionBits[h]
		sibling := in.Siblings[h][:]
		left := make([]uints.U8, 32)
		right := make([]uints.U8, 32)
		for i := 0; i < 32; i++ {
			// left = bit ? sibling : current; right = bit ? current : sibling.
			// Linear selection: booleanity is ClausePositionBits' alone.
			d := a.api.Mul(bit, a.api.Sub(a.raw(sibling[i]), a.raw(current[i])))
			left[i] = uints.U8{Val: a.api.Add(a.raw(current[i]), d)}
			right[i] = uints.U8{Val: a.api.Sub(a.raw(sibling[i]), d)}
		}
		current = a.sha256(constBytes(tagTreeNode), left, right)
	}
	if !a.c.on(ClauseMembership) {
		return
	}
	nonzero := a.api.Sub(1, a.api.IsZero(a.u64le(in.Value[:])))
	if a.c.ablated[mutationMembershipAlways] {
		nonzero = 1
	}
	for i := 0; i < 32; i++ {
		a.api.AssertIsEqual(a.api.Mul(nonzero, a.api.Sub(a.raw(current[i]), a.raw(anchor[i]))), 0)
	}
}

// clauseRhoIndex: ρ_out_j = nf_in_j, the public A.nf_j (host: pool-rho-index).
func (a *action) clauseRhoIndex(out *OutputSlot, nfPublic []uints.U8) {
	if a.c.on(ClauseRhoIndex) {
		a.assertBytesEqual(out.Rho[:], nfPublic)
	}
}

// outputRcm is the output's commitment randomness,
//
//	rcm = SHA-256("APNT-POOL-v1:rcm" ‖ K ‖ ρ)
//
// over the same K and ρ variables the recovery tag, the packet digest and the
// ρ index rule read (HUM-84; host: deriveAPNTPoolCommitmentRandomnessV1). It
// is part of clause output-commitment: there is no rcm witness to check it
// against, and removing the clause's comparison leaves rcm computed.
func (a *action) outputRcm(j int, out *OutputSlot) []uints.U8 {
	if a.c.ablated[measureOmitRcmHash] {
		return uints.NewU8Array(make([]byte, 32))
	}
	if a.c.ablated[mutationRcmWithoutRho] && j == 0 {
		return a.sha256(constBytes(TagRcm), out.RecoveryKey[:])
	}
	rho := out.Rho[:]
	if a.c.ablated[mutationRcmOtherSlotRho] && j == 0 {
		rho = a.c.Out[1].Rho[:]
	}
	return a.sha256(constBytes(TagRcm), out.RecoveryKey[:], rho)
}

// clauseOutputCommitment computes and checks the output's commitment (host:
// pool-output-commitment). It returns the computed cm_j.
//
//	tag  = SHA-256("APNT-POOL-v1:rt" ‖ K)
//	rcm  = SHA-256("APNT-POOL-v1:rcm" ‖ K ‖ ρ)
//	cm_j = SHA-256("APNT-POOL-v1:cm" ‖ u64le(v) ‖ O ‖ ρ ‖ rcm ‖ tag)
func (a *action) clauseOutputCommitment(j int, out *OutputSlot, cmPublic []uints.U8) []uints.U8 {
	tag := a.sha256(constBytes(tagRecoveryTag), out.RecoveryKey[:])
	cm := a.sha256(constBytes(tagCommitment), out.Value[:], out.OwnerTag[:], out.Rho[:], a.outputRcm(j, out), tag)
	if a.c.on(ClauseOutputCommitment) {
		a.assertBytesEqual(cm, cmPublic)
	}
	return cm
}

// clausePacket: packet_j = (u64le(v) ⊕ d[0..8)) ‖ d[8..16) with
// d = SHA-256("APNT-POOL-v1:pad" ‖ K ‖ ρ ‖ cm_j) (host: pool-packet). cm_j is
// the computed commitment, as in the host. The value bytes are range-checked
// (clause witness-bytes) and d's are SHA-256 output bytes, so each XOR is a
// byte-table lookup. The packet has no MAC: this clause and the record hash
// are its integrity; d[8..16) is a key check for trial decryption only.
func (a *action) clausePacket(j int, out *OutputSlot, cm []uints.U8, packetPublic []uints.U8) {
	keyTag := TagPad
	if a.c.ablated[mutationPadUnderPacketKeyTag] && j == 0 {
		keyTag = tagRetiredPacketKey
	}
	var key []uints.U8
	if a.c.ablated[mutationPacketKeyWithoutCm] && j == 0 {
		key = a.sha256(constBytes(keyTag), out.RecoveryKey[:], out.Rho[:])
	} else {
		key = a.sha256(constBytes(keyTag), out.RecoveryKey[:], out.Rho[:], cm)
	}
	packet := make([]uints.U8, 0, PacketBytes)
	for i := 0; i < 8; i++ {
		packet = append(packet, a.bytes.Xor(out.Value[i], key[i]))
	}
	packet = append(packet, key[8:16]...)
	if !a.c.on(ClausePacket) {
		return
	}
	n := len(packet)
	if a.c.ablated[mutationPadCheckUnbound] {
		n = 8
	}
	a.assertBytesEqual(packet[:n], packetPublic[:n])
}

// clauseBalance: Σ v_in + deposit = Σ v_out + withdrawal + fee over the
// integers (host: pool-balance). Every term is < 2^64, so neither side reaches
// the BN254 modulus and field equality is integer equality.
func (a *action) clauseBalance(A []uints.U8) {
	if !a.c.on(ClauseBalance) {
		return
	}
	left := a.api.Add(a.u64le(a.c.In[0].Value[:]), a.u64le(a.c.In[1].Value[:]), a.u64le(A[OffDeposit:OffDeposit+8]))
	right := a.api.Add(a.u64le(a.c.Out[0].Value[:]), a.u64le(a.c.Out[1].Value[:]), a.u64le(A[OffWithdrawal:OffWithdrawal+8]), a.u64le(A[OffFee:OffFee+8]))
	a.api.AssertIsEqual(left, right)
}

// clauseRecordHash: the one public input is x = int_be(SHA-256(A)) mod r
// over the record variables every other clause reads (registry entry 1
// revisions 2 and 3; host: deriveAPNTPoolActionPublicInputV1). The SHA-256
// gadget range-checks the 314 message bytes and this clause the 32 digest bytes, so
// Σ d_j·256^(31−j) is the digest's big-endian integer, below 2^256; as a
// native element it is that integer mod r, at no further cost. The proof
// therefore binds a field element, not an integer spelling of it: verifiers
// derive x from A. Ablated (test only), no hash is computed and x binds
// nothing, which leaves exactly the relation's constraints.
func (a *action) clauseRecordHash(A []uints.U8) {
	if !a.c.on(ClauseRecordHash) {
		return
	}
	acc := frontend.Variable(0)
	for _, d := range a.sha256(A) {
		acc = a.api.Add(a.api.Mul(acc, 256), a.bytes.Value(d))
	}
	if a.c.ablated[mutationRecordHashUnbound] {
		return
	}
	a.api.AssertIsEqual(acc, a.c.RecordHash)
}

// bn254Modulus is the circuit's native field, taken from gnark-crypto (a
// hand-typed copy of it has already been wrong once). Witness assignment
// reduces nothing silently: see witness.go.
var bn254Modulus = ecc.BN254.ScalarField()
