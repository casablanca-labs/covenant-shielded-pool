package poolaction

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark/logger"
	"math/big"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// ENG-318 parity (ENG-289): the host's positives satisfy the compiled
// constraint system, every representable host negative does not, and each
// clause is shown load-bearing by a mutation witness: with that clause
// removed, a named negative becomes satisfiable. Negatives that stay refused
// under their own clause's removal are recorded as overlaps, with the clause
// set that does admit them.
//
// Every assignment carries the honest public input x of the record it
// assigns (ENG-437), so a refusal comes from the relation unless a case
// names x itself: the hashed-input negatives (hashInputCases) set x and the
// private record apart on purpose.
//
// "Unsatisfied" here means gnark's solver, running the honest hint functions,
// finds the constraints violated. It is not a proof that no assignment of the
// internal (hinted) variables satisfies them; that soundness rests on gnark's
// gadgets. "Satisfied" is definitive: a satisfying assignment was found.

type parityCase struct {
	name      string
	source    string // host-corpus | circuit-only
	hostCode  string
	expectSat bool
	build     func() (*ActionCircuit, error)
	note      string
}

type scenario struct {
	label   string
	ablated []Clause
	cases   []parityCase
}

type CaseResult struct {
	Scenario      string   `json:"scenario"`
	Ablated       []Clause `json:"ablated"`
	Case          string   `json:"case"`
	Source        string   `json:"source"`
	HostCode      string   `json:"hostFailureCode"`
	Expect        string   `json:"expect"`
	Got           string   `json:"got"`
	SolverMessage string   `json:"solverMessage,omitempty"`
	SolveSeconds  float64  `json:"solveSeconds"`
	Note          string   `json:"note,omitempty"`
}

type ScenarioResult struct {
	Scenario       string   `json:"scenario"`
	Ablated        []Clause `json:"ablated"`
	Constraints    int      `json:"constraints"`
	CompileSeconds float64  `json:"compileSeconds"`
}

func satWord(b bool) string {
	if b {
		return "satisfied"
	}
	return "unsatisfied"
}

func loadEntries(t *testing.T) map[string]*CorpusEntry {
	t.Helper()
	c, err := LoadCorpus(corpusPath)
	if err != nil {
		protectedFatal(t, err)
	}
	out := map[string]*CorpusEntry{}
	for i := range c.Entries {
		out[c.Entries[i].Name] = &c.Entries[i]
	}
	return out
}

func hostCode(e *CorpusEntry) string {
	if e.HostFailureCode == nil {
		return ""
	}
	return *e.HostFailureCode
}

func fromEntry(e *CorpusEntry, expectSat bool, note string) parityCase {
	return parityCase{name: e.Name, source: "host-corpus", hostCode: hostCode(e), expectSat: expectSat, build: e.Assignment, note: note}
}

func setByte(u *uints.U8, v int64) { *u = uints.U8{Val: big.NewInt(v)} }

func byteOf(u uints.U8) int64 {
	switch v := u.Val.(type) {
	case uint8:
		return int64(v)
	case *big.Int:
		return v.Int64()
	}
	panic(fmt.Sprintf("unexpected byte type %T", u.Val))
}

func entryBytes(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		protectedFatal(t, err)
	}
	return b
}

// setRecord assigns a byte record and its honest public input.
func setRecord(t *testing.T, a *ActionCircuit, record []byte) {
	x, err := PublicInput(record)
	if err != nil {
		protectedFatal(t, err)
	}
	copy(a.Record[:], uints.NewU8Array(record))
	a.RecordHash = x
}

// ---- circuit-only negatives ----

// invalidCurveTheft is the delegated-prover attack the on-curve check stops.
// The delegate holds REL1's slot-0 witness (ak, nk, α) but not ask. It keeps
// ak's x and y-parity, so SEC1c(ak), the owner tag, cm and nf are unchanged,
// but uses an off-curve y'. gnark's unified addition then applies the chord
// formula to (x, y') and α·G, and y' is solved so that the result has the
// x-coordinate of r·G for an r the delegate chose. rk = SEC1c of that result
// is ±r·G: a key the delegate can sign for.
type theft struct {
	assignment *ActionCircuit
	honestY    *ActionCircuit // same record and α, the true y: must stay refused
	rk         []byte
	signingKey *big.Int
	alpha      *big.Int
	tries      int
}

func buildInvalidCurveTheft(t *testing.T, rel1 *CorpusEntry) theft {
	ak := entryBytes(t, rel1.Witness.Inputs[0].SpendKey33)
	x, y, ok := Decompress(ak)
	if !ok {
		protectedFatal(t, "REL1 ak is not a point")
	}
	r := labelScalar("invalid-curve:delegate-signing-key")
	T := nativeMulBase(r)
	for k := 0; k < 256; k++ {
		alpha := labelScalar(fmt.Sprintf("invalid-curve:alpha:%d", k))
		Q := nativeMulBase(alpha)
		c := modP(new(big.Int).Add(new(big.Int).Add(new(big.Int).Set(T.x), x), Q.x))
		root := new(big.Int).ModSqrt(c, secpP)
		if root == nil {
			continue
		}
		for _, lambda := range []*big.Int{root, new(big.Int).Sub(secpP, root)} {
			yPrime := modP(new(big.Int).Sub(Q.y, new(big.Int).Mul(lambda, new(big.Int).Sub(Q.x, x))))
			if yPrime.Bit(0) != y.Bit(0) || nativeOnCurve(nativePoint{x, yPrime}) {
				continue
			}
			yr := modP(new(big.Int).Sub(new(big.Int).Mul(lambda, new(big.Int).Sub(x, T.x)), yPrime))
			rk := make([]byte, 33)
			rk[0] = 0x02 | byte(yr.Bit(0))
			T.x.FillBytes(rk[1:])
			// rk decodes to T or −T; the delegate knows the discrete log of both.
			px, py, ok := Decompress(rk)
			if !ok || px.Cmp(T.x) != 0 {
				protectedFatal(t, "attacker rk does not decode")
			}
			key := new(big.Int).Set(r)
			if py.Cmp(T.y) != 0 {
				key.Sub(secpN, r)
			}
			if !bytes.Equal(nativeSEC1c(nativeMulBase(key)), rk) {
				protectedFatal(t, "attacker does not hold rk's discrete log")
			}
			record := entryBytes(t, *rel1.Record)
			copy(record[OffRk0:OffRk0+33], rk)
			build := func(yWitness *big.Int) *ActionCircuit {
				a, err := rel1.Assignment()
				if err != nil {
					protectedFatal(t, err)
				}
				setRecord(t, a, record)
				if a.In[0].AkY, err = fpElement(yWitness); err != nil {
					protectedFatal(t, err)
				}
				if a.In[0].Alpha, err = frElement(alpha); err != nil {
					protectedFatal(t, err)
				}
				return a
			}
			return theft{assignment: build(yPrime), honestY: build(y), rk: rk, signingKey: key, alpha: alpha, tries: k + 1}
		}
	}
	protectedFatal(t, "no invalid-curve witness in 256 tries")
	return theft{}
}

// positionBitTwo gives REL2's real input a position bit of 2 at level 0. With
// linear selection, left = 2s − cur and right = 2cur − s; s is chosen so both
// stay bytes, and the anchor is the root this path then reaches. No boolean
// position reaches it (checked natively).
func buildPositionBitTwo(t *testing.T, rel2 *CorpusEntry) *ActionCircuit {
	in := rel2.Witness.Inputs[0]
	v, _ := new(big.Int).SetString(in.ValueSats, 10)
	owner := nativeOwnerTag(entryBytes(t, in.SpendKey33), entryBytes(t, in.NullifierKey32))
	cm := nativeCommitment(v.Uint64(), owner, entryBytes(t, in.Rho32), entryBytes(t, in.CommitmentRandomness32), entryBytes(t, in.RecoveryTag32))
	sibling := make([]byte, 32)
	left := make([]byte, 32)
	right := make([]byte, 32)
	changed := 0
	for i := range cm {
		c := int(cm[i])
		s := c
		if c >= 1 && c <= 253 {
			s = c + 1
			changed++
		}
		sibling[i] = byte(s)
		left[i] = byte(2*s - c)
		right[i] = byte(2*c - s)
	}
	if changed == 0 {
		protectedFatal(t, "no byte can move")
	}
	node := nativeNode(left, right)
	var bits [TreeDepth]uint64
	var siblings [TreeDepth][]byte
	for h := 0; h < TreeDepth; h++ {
		bits[h] = (in.Membership.Position >> h) & 1
		siblings[h] = entryBytes(t, in.Membership.Siblings[h])
	}
	for h := 1; h < TreeDepth; h++ {
		if bits[h] == 1 {
			node = nativeNode(siblings[h], node)
		} else {
			node = nativeNode(node, siblings[h])
		}
	}
	anchor := node
	for _, b0 := range []uint64{0, 1} {
		bb := bits
		bb[0] = b0
		ss := siblings
		ss[0] = sibling
		if bytes.Equal(nativeRoot(cm, bb, ss), anchor) {
			protectedFatal(t, "a boolean position reaches the forged anchor")
		}
	}
	a, err := rel2.Assignment()
	if err != nil {
		protectedFatal(t, err)
	}
	record := entryBytes(t, *rel2.Record)
	copy(record[OffAnchor:OffAnchor+32], anchor)
	setRecord(t, a, record)
	a.In[0].PositionBits[0] = 2
	copy(a.In[0].Siblings[0][:], uints.NewU8Array(sibling))
	return a
}

// malleate moves 256 from byte k+1 into byte k of an eight-byte little-endian
// amount: the same integer, a non-byte encoding.
func malleate(t *testing.T, v []uints.U8) {
	for k := 0; k < 7; k++ {
		if byteOf(v[k+1]) >= 1 {
			setByte(&v[k], byteOf(v[k])+256)
			setByte(&v[k+1], byteOf(v[k+1])-1)
			return
		}
	}
	protectedFatal(t, "amount has no movable byte")
}

// ---- the hashed public input (ENG-437) ----

// hashInputs builds the negatives particular to the one public input on one
// host positive: x and the private record disagreeing, and x reduced some
// other way. The positive is REL1 when REL1's digest is at least r, else the
// first positive in name order whose digest is (with the 314-byte record of
// revision 3, REL1's is not): below r the reduction negatives would be
// vacuous. It is named in each case's note.
type hashInputs struct {
	t        *testing.T
	rel1     *CorpusEntry // the chosen positive
	record   []byte
	tampered []byte // its record with the fee's low byte flipped
	honest   *big.Int
	digest   *big.Int // int_be(SHA-256(A)), at least r
}

func hashInputCases(t *testing.T, E map[string]*CorpusEntry) hashInputs {
	names := make([]string, 0, len(E))
	for name, e := range E {
		if e.Kind == "positive" && name != "rel1-real-real-deposit-withdrawal" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range append([]string{"rel1-real-real-deposit-withdrawal"}, names...) {
		e := E[name]
		record := entryBytes(t, *e.Record)
		d := sha256.Sum256(record)
		digest := new(big.Int).SetBytes(d[:])
		if digest.Cmp(bn254Modulus) < 0 {
			continue
		}
		honest, err := PublicInput(record)
		if err != nil {
			protectedFatal(t, err)
		}
		tampered := append([]byte(nil), record...)
		tampered[OffFee] ^= 1
		return hashInputs{t: t, rel1: e, record: record, tampered: tampered, honest: honest, digest: digest}
	}
	protectedFatal(t, "no positive's digest is at least r: the reduction negatives would be vacuous")
	return hashInputs{}
}

// with assigns the chosen positive's witness with the private record private
// (nil keeps its own) and the public input x.
func (h hashInputs) with(x *big.Int, private []byte) func() (*ActionCircuit, error) {
	return func() (*ActionCircuit, error) {
		a, err := h.rel1.Assignment()
		if err != nil {
			return nil, err
		}
		if private != nil {
			copy(a.Record[:], uints.NewU8Array(private))
		}
		a.RecordHash = new(big.Int).Set(x)
		return a, nil
	}
}

func (h hashInputs) control(name string, x *big.Int) *big.Int {
	if x.Cmp(h.honest) == 0 {
		protectedFatal(h.t, "control %s equals the honest public input", name)
	}
	return x
}

func (h hashInputs) hashCase(name, analogue, note string, sat bool, build func() (*ActionCircuit, error)) parityCase {
	return parityCase{name: name, source: "hashed-input", hostCode: analogue, expectSat: sat, build: build, note: note + " [on " + h.rel1.Name + "]"}
}

func (h hashInputs) otherRecord(sat bool, note string) parityCase {
	x, err := PublicInput(h.tampered)
	if err != nil {
		protectedFatal(h.t, err)
	}
	return h.hashCase("hash-of-other-record", ClauseHostCode[ClauseRecordHash],
		h.rel1.Name+"'s witness and private record intact; x = the public input of its record with the fee byte flipped (A and x disagree)"+note,
		sat, h.with(h.control("hash-of-other-record", x), nil))
}

func (h hashInputs) tamperedHonestX() parityCase {
	return h.hashCase("private-record-tampered-honest-x", ClauseHostCode[ClauseRecordHash],
		"private record's fee byte flipped, x = the honest record's: the relation (balance) and record-hash both refuse it",
		false, h.with(h.honest, h.tampered))
}

func (h hashInputs) tamperedSelfConsistentX() parityCase {
	x, err := PublicInput(h.tampered)
	if err != nil {
		protectedFatal(h.t, err)
	}
	return h.hashCase("private-record-tampered-self-consistent-x", "pool-balance",
		"private record's fee byte flipped and x its own public input: the relation (balance) must refuse",
		false, h.with(x, h.tampered))
}

func (h hashInputs) plusOne(sat bool, note string) parityCase {
	x := new(big.Int).Mod(new(big.Int).Add(h.honest, big.NewInt(1)), bn254Modulus)
	return h.hashCase("x-plus-one", ClauseHostCode[ClauseRecordHash], "x = honest + 1 mod r"+note, sat, h.with(h.control("x-plus-one", x), nil))
}

func (h hashInputs) top253(sat bool, note string) parityCase {
	x := new(big.Int).Rsh(h.digest, 3)
	return h.hashCase("x-truncated-to-top-253-bits", ClauseHostCode[ClauseRecordHash],
		"x = int_be(digest) >> 3: truncation in place of mod r"+note, sat, h.with(h.control("top-253-bits", x), nil))
}

func (h hashInputs) low253(sat bool) parityCase {
	x := new(big.Int).Mod(h.digest, new(big.Int).Lsh(big.NewInt(1), 253))
	return h.hashCase("x-low-253-bits", ClauseHostCode[ClauseRecordHash], "x = int_be(digest) mod 2^253", sat, h.with(h.control("low-253-bits", x), nil))
}

// unreduced assigns x as the integer int_be(d) ≥ r: gnark reduces it to the
// same field element, so the proof binds the element, not an integer
// spelling; verifiers derive x from A and never take it from a prover.
func (h hashInputs) unreduced() parityCase {
	return h.hashCase("x-as-unreduced-integer", ClauseHostCode[ClauseRecordHash],
		"x = int_be(digest) >= r assigned as an integer: the same field element as the honest x (expected satisfied)", true, h.with(h.digest, nil))
}

// ---- the scenarios ----

func scenarios(t *testing.T) []scenario {
	E := loadEntries(t)
	rel1 := E["rel1-real-real-deposit-withdrawal"]
	rel2 := E["rel2-real-dummy-dummy-output"]
	control := func() []parityCase {
		return []parityCase{fromEntry(rel1, true, "positive control"), fromEntry(rel2, true, "positive control")}
	}
	host := func(name string, sat bool, note string) parityCase { return fromEntry(E[name], sat, note) }
	// The pad16 wrong-rcm-derivation negatives: each output's cm and packet
	// self-consistent under an rcm that is not SHA-256(rcm ‖ K ‖ ρ).
	rcmNegatives := func(sat bool, note string) []parityCase {
		var cs []parityCase
		for _, name := range []string{"output-rcm-not-derived", "output-rcm-without-rho", "output-rcm-other-key", "output-rcm-other-slot-rho", "output-rcm-not-derived-dummy"} {
			cs = append(cs, host(name, sat, note))
		}
		return cs
	}
	theftCase := buildInvalidCurveTheft(t, rel1)
	circuitOnly := func(name, analogue string, sat bool, note string, build func() (*ActionCircuit, error)) parityCase {
		return parityCase{name: name, source: "circuit-only", hostCode: analogue, expectSat: sat, build: build, note: note}
	}
	theftC := func(sat bool) parityCase {
		return circuitOnly("circuit-invalid-curve-ak-delegate-rk", "pool-rerandomized-key", sat,
			fmt.Sprintf("delegate keeps SEC1c(ak) but uses an off-curve y'; rk decodes to a key the delegate holds (found in %d tries)", theftCase.tries),
			func() (*ActionCircuit, error) { return theftCase.assignment, nil })
	}
	theftHonestY := func() parityCase {
		return circuitOnly("circuit-invalid-curve-control-true-y", "pool-rerandomized-key", false,
			"the same forged record and α with ak's true y: the attack needs the off-curve y'",
			func() (*ActionCircuit, error) { return theftCase.honestY, nil })
	}
	akInfinity := func(sat bool) parityCase {
		return circuitOnly("circuit-ak-infinity-convention", "pool-spend-key", sat,
			"spend-key-infinity-bytes-self-consistent with ak assigned as gnark's (0,0), whose SEC1c is 0x02 ‖ 0^32",
			func() (*ActionCircuit, error) {
				a, err := E["spend-key-infinity-bytes-self-consistent"].Assignment()
				if err != nil {
					return nil, err
				}
				zero := big.NewInt(0)
				if a.In[0].AkX, err = fpElement(zero); err != nil {
					return nil, err
				}
				a.In[0].AkY, err = fpElement(zero)
				return a, err
			})
	}
	positionTwo := func(sat bool) parityCase {
		return circuitOnly("circuit-position-bit-two", "pool-membership", sat,
			"REL2's real input with position bit 0 = 2 and an anchor only that non-boolean path reaches",
			func() (*ActionCircuit, error) { return buildPositionBitTwo(t, rel2), nil })
	}
	anchorByte := func(sat bool, note string) parityCase {
		return circuitOnly("circuit-record-anchor-byte-plus-256", "pool-record-length", sat,
			"dummy-dummy-deposit with record anchor byte 0 raised by 256: a non-byte record element the relation otherwise ignores; x is the unmodified record's (no byte string has this element)"+note,
			func() (*ActionCircuit, error) {
				a, err := E["dummy-dummy-deposit"].Assignment()
				if err != nil {
					return nil, err
				}
				setByte(&a.Record[0], byteOf(a.Record[0])+256)
				return a, nil
			})
	}
	depositBytes := func(sat bool, note string) parityCase {
		return circuitOnly("circuit-record-deposit-bytes-malleated", "pool-record-length", sat,
			"REL1 with the deposit's bytes re-split (256 moved down a byte): same integer, non-byte record elements; x is the unmodified record's"+note,
			func() (*ActionCircuit, error) {
				a, err := rel1.Assignment()
				if err != nil {
					return nil, err
				}
				malleate(t, a.Record[OffDeposit:OffDeposit+8])
				return a, nil
			})
	}
	valueBytes := func(sat bool) parityCase {
		return circuitOnly("circuit-output-value-bytes-malleated", "pool-value-range", sat,
			"REL1 with output 1's value bytes re-split: same integer, non-byte witness",
			func() (*ActionCircuit, error) {
				a, err := rel1.Assignment()
				if err != nil {
					return nil, err
				}
				malleate(t, a.Out[1].Value[:])
				return a, nil
			})
	}

	siblingBytes := func(sat bool) parityCase {
		return circuitOnly("circuit-sibling-bytes-malleated", "pool-membership", sat,
			"REL1 input 0's level-3 sibling bytes re-split: same integer, non-byte witness; the SHA-256 gadget range-checks the selected left/right bytes",
			func() (*ActionCircuit, error) {
				a, err := rel1.Assignment()
				if err != nil {
					return nil, err
				}
				malleate(t, a.In[0].Siblings[3][:8])
				return a, nil
			})
	}

	var out []scenario

	// Production: every positive satisfied, every representable negative and every circuit-only negative refused.
	prod := scenario{label: "production"}
	names := make([]string, 0, len(E))
	for name := range E {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		e := E[name]
		if !e.Representable {
			continue
		}
		prod.cases = append(prod.cases, fromEntry(e, e.Kind == "positive", e.Note))
	}
	prod.cases = append(prod.cases, theftC(false), theftHonestY(), akInfinity(false), positionTwo(false), anchorByte(false, ""), depositBytes(false, ""), valueBytes(false), siblingBytes(false))
	hx := hashInputCases(t, E)
	prod.cases = append(prod.cases, hx.otherRecord(false, ""), hx.tamperedHonestX(), hx.tamperedSelfConsistentX(), hx.plusOne(false, ""),
		hx.top253(false, ""), hx.low253(false), hx.unreduced())
	out = append(out, prod)

	// One clause removed: its isolated negatives become satisfiable.
	single := []struct {
		clause Clause
		cases  []parityCase
	}{
		{ClauseRecordBytes, []parityCase{
			anchorByte(false, "; overlap: the record-hash SHA-256 gadget range-checks every message byte"),
			depositBytes(false, "; overlap: the record-hash SHA-256 gadget range-checks every message byte"),
		}},
		{ClauseWitnessBytes, []parityCase{
			valueBytes(false), siblingBytes(false),
			host("value-field-wrap-bn254", false, "overlap: the gadgets consuming a value byte (SHA-256 message words, the packet's pad xors) range-check it"),
		}},
		{ClauseRecordAmounts, []parityCase{host("record-fee-above-max-money-balanced", true, ""), host("record-fee-above-max-money", false, "overlap: balance also refuses")}},
		{ClauseWithdrawalLock, []parityCase{host("record-wlock-zero-with-withdrawal", true, ""), host("record-wlock-set-without-withdrawal", true, "")}},
		{ClauseValueMaxMoney, []parityCase{host("value-output-above-max-money-self-consistent", true, ""), host("value-output-above-max-money", false, "overlap: cm, packet and balance also refuse")}},
		{ClauseSpendKeyOnCurve, []parityCase{theftC(true), theftHonestY(), host("spend-key-not-a-point", false, "overlap: the owner tag, hence nf and membership, and rk also refuse"),
			host("spend-key-infinity-bytes-self-consistent", false, "overlap: with (0, 2) the unified addition misses α·G, so rk refuses")}},
		{ClauseSpendKeyFinite, []parityCase{akInfinity(true)}},
		{ClauseAlphaRange, []parityCase{host("alpha-n-self-consistent", true, ""), host("alpha-n", false, "overlap: rk also refuses"), host("alpha-negative-one", false, "overlap: gnark's emulated limb width check refuses a limb of r − 1")}},
		{ClauseRkFinite, []parityCase{host("rk-at-infinity-self-consistent", true, "host refuses this record at decode: rk_0 is not a point (pool-record-key)"), host("rk-at-infinity", false, "overlap: rk, nf and membership also refuse")}},
		{ClauseRkEqual, []parityCase{host("rk-unrandomized-ak", true, ""), host("rk-other-alpha", true, ""), host("dummy-rk-other-alpha", true, ""), host("record-rk-not-a-point", true, "host's pool-record-key is implied by the rk clause")}},
		{ClauseNullifier, []parityCase{host("nullifier-fake-self-consistent", true, "the double-spend shape"), host("dummy-nullifier-key-flipped", true, "a dummy input is bound only by its nullifier"), host("nullifier-record-flipped", false, "overlap: the ρ index rule also refuses"),
			host("nullifier-over-nkc", true, "the nullifiers a holder of nkc computes, under the true nk"),
			host("input-nullifier-key-is-nkc", false, "overlap: nkc as nk names another owner tag, so membership also refuses")}},
		{ClauseNullifierDistinct, []parityCase{host("one-note-both-slots", true, "")}},
		{ClausePositionBits, []parityCase{positionTwo(true)}},
		{ClauseMembership, []parityCase{host("membership-absent-note", true, ""), host("membership-no-path", true, ""), host("membership-self-built-tree", true, "")}},
		{ClauseRhoIndex, []parityCase{host("rho-faerie-gold", true, ""), host("rho-swapped", true, "")}},
		{ClauseOutputCommitment, append([]parityCase{host("output-cm-flipped", true, "")},
			rcmNegatives(false, "overlap: the packet digest binds the computed cm, whose rcm is derived")...)},
		{ClausePacket, append([]parityCase{host("packet-ciphertext-flipped", true, ""), host("packet-check-flipped", true, ""), host("packet-pre-fix-key-without-cm", true, ""),
			host("packet-wrong-recovery-key", true, ""), host("packet-dummy-output-flipped", true, ""), host("packet-for-another-value", true, ""),
			host("packet-for-value-zero", true, ""), host("packet-reused-sibling-key", true, "REV-129 H1-R2-3: the sibling candidate's pad"),
			host("packet-check-wrong-slice", true, ""), host("packet-pad-under-pk-tag", true, "")},
			rcmNegatives(false, "overlap: output-commitment refuses a cm over an rcm not derived from K and ρ")...)},
		{ClauseBalance, []parityCase{host("balance-fee-plus-one", true, ""), host("balance-deposit-minus-one", true, ""), host("balance-overdraw-withdrawal", true, "")}},
		{ClauseRecordHash, []parityCase{
			hx.otherRecord(true, "; with record-hash removed x binds nothing: the disagreement is satisfiable"),
			hx.plusOne(true, "; with record-hash removed any x is satisfiable"),
			hx.top253(true, "; with record-hash removed any x is satisfiable"),
			hx.tamperedHonestX(),
		}},
	}
	for _, s := range single {
		out = append(out, scenario{label: "ablate:" + string(s.clause), ablated: []Clause{s.clause}, cases: append(control(), s.cases...)})
	}

	// Overlapping negatives: the clause set that admits each.
	multi := []struct {
		clauses []Clause
		cases   []parityCase
	}{
		{[]Clause{ClauseRecordAmounts, ClauseBalance}, []parityCase{host("record-fee-above-max-money", true, "")}},
		{[]Clause{ClauseValueMaxMoney, ClauseOutputCommitment, ClausePacket, ClauseBalance}, []parityCase{host("value-output-above-max-money", true, "")}},
		{[]Clause{ClauseSpendKeyOnCurve, ClauseNullifier, ClauseMembership, ClauseRkEqual}, []parityCase{host("spend-key-not-a-point", true, "")}},
		{[]Clause{ClauseSpendKeyOnCurve, ClauseRkEqual}, []parityCase{host("spend-key-infinity-bytes-self-consistent", true, "")}},
		{[]Clause{ClauseAlphaRange, ClauseRkEqual}, []parityCase{host("alpha-n", true, "")}},
		{[]Clause{ClauseRkFinite, ClauseRkEqual, ClauseNullifier, ClauseMembership}, []parityCase{host("rk-at-infinity", true, "")}},
		{[]Clause{ClauseNullifier, ClauseRhoIndex}, []parityCase{host("nullifier-record-flipped", true, "")}},
		{[]Clause{ClauseNullifier, ClauseMembership}, []parityCase{host("input-nullifier-key-is-nkc", true, "")}},
		{[]Clause{ClauseRecordBytes, ClauseRecordHash}, []parityCase{anchorByte(true, ""), depositBytes(true, "")}},
		{[]Clause{ClauseOutputCommitment, ClausePacket}, rcmNegatives(true, "")},
	}
	for _, m := range multi {
		parts := make([]string, len(m.clauses))
		for i, c := range m.clauses {
			parts[i] = string(c)
		}
		out = append(out, scenario{label: "ablate:" + strings.Join(parts, "+"), ablated: m.clauses, cases: append(control(), m.cases...)})
	}

	// ENG-329: the owner tag over nkc. Removing the nkc clause gives the
	// pre-ENG-329 owner tag over nk; the mutation feeds nkc into nf. Neither is
	// a relaxation of this relation but a different one: every positive's notes
	// are formed over nkc and their nullifiers over nk, so both refuse them (as
	// ARCH-173 S1.7c found for the pre-change host). Each admits exactly its own
	// negative, a record whose nullifiers a holder of nkc computes.
	out = append(out,
		scenario{label: "ablate:" + string(ClauseOwnerTagOverNkc), ablated: []Clause{ClauseOwnerTagOverNkc}, cases: []parityCase{
			fromEntry(rel1, false, "notes formed over nkc: the owner tag over nk refuses them"),
			fromEntry(rel2, false, "notes formed over nkc: the owner tag over nk refuses them"),
			host("input-nullifier-key-is-nkc", true, "nkc presented as nk: the owner tag over nk accepts it, with nf = SHA-256(nf ‖ nkc ‖ ρ ‖ cm)"),
			host("nullifier-over-nkc", false, "the true nk under the owner tag over nk names another note"),
		}},
		scenario{label: "mutation:nullifier-over-nkc", ablated: []Clause{mutationNullifierOverNkc}, cases: []parityCase{
			fromEntry(rel1, false, "nullifiers over nk: the faulty build refuses them"),
			fromEntry(rel2, false, "nullifiers over nk: the faulty build refuses them"),
			host("nullifier-over-nkc", true, "the faulty build accepts the nullifiers a holder of nkc computes"),
			host("input-nullifier-key-is-nkc", false, "nkc presented as nk names another owner tag"),
		}},
	)

	// pad16 (ARCH-247, HUM-84): each mutation is a faulty build of the output
	// side, not a relaxation. It admits its own negative and refuses an honest
	// record, whose rcm and packet are the true derivations.
	mutation := func(m Clause, own string, note string) scenario {
		return scenario{label: "mutation:" + strings.TrimPrefix(string(m), "mutation-"), ablated: []Clause{m}, cases: []parityCase{
			host(own, true, note),
			fromEntry(rel1, false, "an honest record is refused by the faulty build"),
		}}
	}
	out = append(out,
		mutation(mutationRcmWithoutRho, "output-rcm-without-rho", "the faulty build's own note: rcm = SHA-256(rcm ‖ K)"),
		mutation(mutationRcmOtherSlotRho, "output-rcm-other-slot-rho", "the faulty build's own note: rcm over output 1's ρ"),
		mutation(mutationPacketKeyWithoutCm, "packet-pre-fix-key-without-cm", "the pre-REV-129 key's shape: the faulty build's own packet"),
		mutation(mutationPadUnderPacketKeyTag, "packet-pad-under-pk-tag", "the faulty build's own packet, under revision 2's pk tag"),
		scenario{label: "mutation:pad-check-unbound", ablated: []Clause{mutationPadCheckUnbound}, cases: append(control(),
			host("packet-check-flipped", true, "the 8-byte key check is load-bearing"),
			host("packet-check-wrong-slice", true, ""),
			host("packet-ciphertext-flipped", false, "the padded value is still compared"),
		)},
	)

	// Every relation clause removed: what gnark's own gadgets still refuse.
	out = append(out, scenario{label: "ablate:all-clauses", ablated: Clauses, cases: append(control(),
		host("value-field-wrap-bn254", false, "a value byte above 255 is refused inside gnark's gadgets"),
		host("value-field-wrap-pallas", false, "a value byte above 255 is refused inside gnark's gadgets"),
		host("value-field-wrap-host-test-constant", false, "a value byte above 255 is refused inside gnark's gadgets"),
		host("alpha-negative-one", false, "a limb of r − 1 is refused by gnark's emulated limb width check"),
		valueBytes(false), siblingBytes(false),
	)})

	// Completeness control: enforcing membership for every input breaks dummy inputs.
	out = append(out, scenario{label: "mutation:membership-always", ablated: []Clause{mutationMembershipAlways}, cases: []parityCase{
		fromEntry(rel1, true, "two real inputs are unaffected"),
		fromEntry(rel2, false, "a dummy input has no path: the v ≠ 0 exemption is needed"),
		host("dummy-dummy-deposit", false, "two dummy inputs"),
	}})
	return out
}

func TestParity(t *testing.T) {
	t.Skip("requires protected action witnesses; not shipped")
	defer protectedPanic(t)
	var results []CaseResult
	var compiles []ScenarioResult
	for _, sc := range scenarios(t) {
		start := time.Now()
		ccs, err := Compile(sc.ablated...)
		if err != nil {
			protectedFatal(t, "%s: compile: %v", sc.label, err)
		}
		compiles = append(compiles, ScenarioResult{Scenario: sc.label, Ablated: sc.ablated, Constraints: ccs.GetNbConstraints(), CompileSeconds: time.Since(start).Seconds()})
		for _, pc := range sc.cases {
			a, err := pc.build()
			if err != nil {
				protectedFatal(t, "%s/%s: assignment: %v", sc.label, pc.name, err)
			}
			start := time.Now()
			serr := Solve(ccs, a)
			r := CaseResult{Scenario: sc.label, Ablated: sc.ablated, Case: pc.name, Source: pc.source, HostCode: pc.hostCode,
				Expect: satWord(pc.expectSat), Got: satWord(serr == nil), SolveSeconds: time.Since(start).Seconds(), Note: pc.note}
			if serr != nil {
				r.SolverMessage = "pool-solver-refusal"
			}
			results = append(results, r)
			if r.Expect != r.Got {
				protectedError(t, "%s / %s: expected %s, got %s (%s)", sc.label, pc.name, r.Expect, r.Got, r.SolverMessage)
			}
		}
		ccs = nil
		Release()
	}
	if path := os.Getenv("POOL_ACTION_PARITY_RESULTS"); path != "" {
		b, _ := json.MarshalIndent(struct {
			Compiles         int  `json:"compiles"`
			Cases            int  `json:"cases"`
			ValuesSuppressed bool `json:"valuesSuppressed"`
		}{len(compiles), len(results), true}, "", "  ")
		if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
			protectedFatal(t, err)
		}
	}
}

// TestNativeMirrorMatchesHost validates the test-only native mirror against
// the host corpus before any circuit-only negative relies on it.
func TestNativeMirrorMatchesHost(t *testing.T) {
	t.Skip("requires protected action witnesses; not shipped")
	defer protectedPanic(t)
	E := loadEntries(t)
	checked, outputs := 0, 0
	for _, e := range E {
		if e.Kind != "positive" {
			continue
		}
		record := entryBytes(t, *e.Record)
		for s, in := range e.Witness.Inputs {
			v, _ := new(big.Int).SetString(in.ValueSats, 10)
			ak := entryBytes(t, in.SpendKey33)
			owner := nativeOwnerTag(ak, entryBytes(t, in.NullifierKey32))
			cm := nativeCommitment(v.Uint64(), owner, entryBytes(t, in.Rho32), entryBytes(t, in.CommitmentRandomness32), entryBytes(t, in.RecoveryTag32))
			nf := nativeNullifier(entryBytes(t, in.NullifierKey32), entryBytes(t, in.Rho32), cm)
			if !bytes.Equal(nf, record[OffNullifier0+32*s:OffNullifier0+32*(s+1)]) {
				protectedFatal(t, "%s: native nf_%d differs from the host record", e.Name, s)
			}
			x, y, ok := Decompress(ak)
			if !ok {
				protectedFatal(t, "%s: ak_%d", e.Name, s)
			}
			alpha, _ := new(big.Int).SetString(in.Rerandomizer, 10)
			rk := nativeSEC1c(nativeAdd(nativePoint{x, y}, nativeMulBase(alpha)))
			if !bytes.Equal(rk, record[OffRk0+33*s:OffRk0+33*(s+1)]) {
				protectedFatal(t, "%s: native rk_%d differs from the host record", e.Name, s)
			}
			if in.Membership != nil && v.Sign() != 0 {
				var bits [TreeDepth]uint64
				var siblings [TreeDepth][]byte
				for h := 0; h < TreeDepth; h++ {
					bits[h] = (in.Membership.Position >> h) & 1
					siblings[h] = entryBytes(t, in.Membership.Siblings[h])
				}
				if !bytes.Equal(nativeRoot(cm, bits, siblings), record[OffAnchor:OffAnchor+32]) {
					protectedFatal(t, "%s: native root_%d differs from the host anchor", e.Name, s)
				}
			}
			checked++
		}
		// The output side (pad16): rcm derived from K and ρ, cm over it, and the 16-byte packet.
		for j, out := range e.Witness.Outputs {
			v, _ := new(big.Int).SetString(out.ValueSats, 10)
			K, rho := entryBytes(t, out.RecoveryKey32), entryBytes(t, out.Rho32)
			cm := nativeCommitment(v.Uint64(), entryBytes(t, out.OwnerTag32), rho, nativeRcm(K, rho), nativeSha(tagRecoveryTag, K))
			if !bytes.Equal(cm, record[OffCm0+32*j:OffCm0+32*(j+1)]) {
				protectedFatal(t, "%s: native cm_%d differs from the host record", e.Name, j)
			}
			// Firing control: a zero rcm (no derivation) gives another cm.
			if bytes.Equal(nativeCommitment(v.Uint64(), entryBytes(t, out.OwnerTag32), rho, make([]byte, 32), nativeSha(tagRecoveryTag, K)), cm) {
				protectedFatal(t, "%s: a zero rcm gives the same cm_%d", e.Name, j)
			}
			if !bytes.Equal(nativePacket(v.Uint64(), K, rho, cm), record[OffPacket0+PacketBytes*j:OffPacket0+PacketBytes*(j+1)]) {
				protectedFatal(t, "%s: native packet_%d differs from the host record", e.Name, j)
			}
			outputs++
		}
	}
	if checked < 20 || outputs < 30 {
		protectedFatal(t, "only %d input slots and %d outputs checked", checked, outputs)
	}
	protectedLog(t, "native mirror matches the host on %d input slots and %d outputs", checked, outputs)
}

// TestNkcNegativesAreWhatTheyClaim checks the two ENG-329 corpus negatives
// with the native mirror: one record whose nullifiers are
// SHA-256(nf ‖ nkc ‖ ρ ‖ cm) for notes formed over nkc, and two witnesses for
// it, the true nk and nkc presented as nk.
func TestNkcNegativesAreWhatTheyClaim(t *testing.T) {
	t.Skip("requires protected action witnesses; not shipped")
	defer protectedPanic(t)
	E := loadEntries(t)
	trueNk, nkcAsNk := E["nullifier-over-nkc"], E["input-nullifier-key-is-nkc"]
	if *trueNk.Record != *nkcAsNk.Record {
		protectedFatal(t, "the two ENG-329 negatives do not share one record")
	}
	record := entryBytes(t, *trueNk.Record)
	for s, in := range trueNk.Witness.Inputs {
		v, _ := new(big.Int).SetString(in.ValueSats, 10)
		nk := entryBytes(t, in.NullifierKey32)
		nkc := nativeNkc(nk)
		cm := nativeCommitment(v.Uint64(), nativeOwnerTag(entryBytes(t, in.SpendKey33), nk), entryBytes(t, in.Rho32), entryBytes(t, in.CommitmentRandomness32), entryBytes(t, in.RecoveryTag32))
		nf := record[OffNullifier0+32*s : OffNullifier0+32*(s+1)]
		if !bytes.Equal(nf, nativeNullifier(nkc, entryBytes(t, in.Rho32), cm)) || bytes.Equal(nf, nativeNullifier(nk, entryBytes(t, in.Rho32), cm)) {
			protectedFatal(t, "slot %d: the record nullifier is not the one over nkc", s)
		}
		if !bytes.Equal(entryBytes(t, nkcAsNk.Witness.Inputs[s].NullifierKey32), nkc) {
			protectedFatal(t, "slot %d: the second witness does not present nkc as nk", s)
		}
	}
}

// TestWitnessHasNoSpendAuthority: the circuit's private input is exactly these
// fields; none is ask or rsk, and the public input is exactly one element,
// x = int_be(SHA-256(A)) mod r.
func TestWitnessHasNoSpendAuthority(t *testing.T) {
	t.Skip("requires protected action witnesses; not shipped")
	defer protectedPanic(t)
	fields := func(v any) []string {
		ty := reflect.TypeOf(v)
		var out []string
		for i := 0; i < ty.NumField(); i++ {
			out = append(out, ty.Field(i).Name)
		}
		return out
	}
	if got, want := fields(InputSlot{}), []string{"Value", "AkX", "AkY", "Nk", "Rho", "Rcm", "RecoveryTag", "Alpha", "Siblings", "PositionBits"}; !reflect.DeepEqual(got, want) {
		protectedFatal(t, "input slot fields %v", got)
	}
	if got, want := fields(OutputSlot{}), []string{"Value", "OwnerTag", "Rho", "RecoveryKey"}; !reflect.DeepEqual(got, want) {
		protectedFatal(t, "output slot fields %v", got)
	}
	var exported []string
	for _, f := range fields(ActionCircuit{}) {
		if f[0] >= 'A' && f[0] <= 'Z' {
			exported = append(exported, f)
		}
	}
	if want := []string{"RecordHash", "Record", "In", "Out"}; !reflect.DeepEqual(exported, want) {
		protectedFatal(t, "circuit fields %v", exported)
	}
	E := loadEntries(t)
	a, err := E["rel1-real-real-deposit-withdrawal"].Assignment()
	if err != nil {
		protectedFatal(t, err)
	}
	if bn254Modulus.Cmp(ecc.BN254.ScalarField()) != 0 {
		protectedFatal(t, "bn254Modulus is not the BN254 scalar field")
	}
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		protectedFatal(t, err)
	}
	pub, err := w.Public()
	if err != nil {
		protectedFatal(t, err)
	}
	vec := reflect.ValueOf(pub.Vector())
	if vec.Len() != 1 {
		protectedFatal(t, "public witness has %d elements", vec.Len())
	}
	record := entryBytes(t, *E["rel1-real-real-deposit-withdrawal"].Record)
	x, err := PublicInput(record)
	if err != nil {
		protectedFatal(t, err)
	}
	el := vec.Index(0).Addr().Interface().(interface{ BigInt(*big.Int) *big.Int })
	if el.BigInt(new(big.Int)).Cmp(x) != 0 {
		protectedFatal(t, "the public element is not int_be(SHA-256(A)) mod r")
	}
	if NewActionCircuit().ablated != nil {
		protectedFatal(t, "production circuit carries an ablation")
	}
}

// TestFieldWrapNegativesWrapTheCircuitField: the BN254 wrap negative balances
// modulo the circuit's own field and not over the integers. The host relation
// test's "BN254_R" constant is not that field, and its copy is labelled so.
func TestFieldWrapNegativesWrapTheCircuitField(t *testing.T) {
	t.Skip("requires protected action witnesses; not shipped")
	defer protectedPanic(t)
	E := loadEntries(t)
	imbalance := func(e *CorpusEntry) *big.Int {
		record := entryBytes(t, *e.Record)
		amount := func(off int) *big.Int {
			return new(big.Int).SetUint64(binaryLE(record[off : off+8]))
		}
		sum := func(vs ...string) *big.Int {
			acc := new(big.Int)
			for _, v := range vs {
				x, _ := new(big.Int).SetString(v, 10)
				acc.Add(acc, x)
			}
			return acc
		}
		left := sum(e.Witness.Inputs[0].ValueSats, e.Witness.Inputs[1].ValueSats)
		left.Add(left, amount(OffDeposit))
		right := sum(e.Witness.Outputs[0].ValueSats, e.Witness.Outputs[1].ValueSats)
		right.Add(right, amount(OffWithdrawal)).Add(right, amount(OffFee))
		return left.Sub(left, right)
	}
	bn := imbalance(E["value-field-wrap-bn254"])
	if bn.Sign() == 0 || new(big.Int).Mod(bn, ecc.BN254.ScalarField()).Sign() != 0 {
		protectedFatal(t, "value-field-wrap-bn254 does not wrap BN254's scalar field")
	}
	hostConst := imbalance(E["value-field-wrap-host-test-constant"])
	if new(big.Int).Mod(hostConst, ecc.BN254.ScalarField()).Sign() == 0 {
		protectedFatal(t, "the host test constant unexpectedly wraps BN254's scalar field")
	}
}

func binaryLE(b []byte) uint64 {
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

// Only fixed rules reach testing.T. Arguments still evaluate at the original
// assertion site; no String/Error method or formatter is invoked here.
func protectedFatal(t testing.TB, _ ...any) { t.Helper(); t.Fatal("pool-test-fatal") }
func protectedError(t testing.TB, _ ...any) { t.Helper(); t.Error("pool-test-error") }
func protectedLog(t testing.TB, _ ...any)   { t.Helper(); t.Log("pool-test-log") }
func protectedSkip(t testing.TB, _ ...any)  { t.Helper(); t.Skip("pool-test-source-skip") }
func protectedPanic(t testing.TB) {
	if recover() != nil {
		t.Helper()
		t.Fatal("pool-test-panic")
	}
}

// Suppress dependency diagnostic bodies before a test can enter the solver.
func init() { logger.Disable() }
