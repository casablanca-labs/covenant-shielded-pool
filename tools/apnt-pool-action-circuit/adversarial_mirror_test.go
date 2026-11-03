package poolaction

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	csbn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/rangecheck"
)

// Attribution of hints and constraints to gadgets. mirrorCircuit is a
// test-only copy of ActionCircuit.Define that makes the same gadget calls in
// the same order and, when markers is set, emits a marker hint before each
// gadget call. A marker adds one hint instruction and one wire and no
// constraint, so the constraint sequence is unchanged and every instruction
// between two markers belongs to the gadget the first one names. Deferred
// work (range-check decompositions, lookup arguments, emulated deferred
// checks, the commitment) follows the last marker.
//
// The copy is checked, not trusted: without markers it must compile to the
// production R1CS byte for byte (TestHintAttribution), and with markers its
// instruction sequence minus the markers must match the compiled one it is
// used for (buildSegmentMap's fingerprint against productionFingerprint,
// checked wherever a segment map is used, including the binding-ablated
// variant, which only that fingerprint checks).

type mirrorCircuit struct {
	RecordHash frontend.Variable `gnark:",public"`
	Record     [RecordBytes]uints.U8
	In         [2]InputSlot
	Out        [2]OutputSlot

	markers bool            `gnark:"-"`
	names   *[]string       `gnark:"-"`
	ablated map[Clause]bool `gnark:"-"`
}

// bindingClauses are the clauses that compare a computed value with the
// record: the rerandomized key, the nullifier, the membership root, the
// output commitment and the packet; and, since ENG-437, the comparison of the
// record's hash with the public input x (mutationRecordHashUnbound, which
// keeps the hash itself). With them removed (test only), a forged hint that
// changes a computed value is not caught by a comparison with A or x, and
// gadget constraints must refuse it. Removing them also removes the work that
// only feeds them: SEC1c(R) under ClauseRkEqual, IsZero(v) under
// ClauseMembership, and the deferred range checks of SEC1c(R) (see
// ablationDelta); every other gadget stays.
var bindingClauses = []Clause{ClauseRkEqual, ClauseNullifier, ClauseMembership, ClauseOutputCommitment, ClausePacket, mutationRecordHashUnbound}

func segmentMarker(_ *big.Int, _, out []*big.Int) error {
	for i := range out {
		out[i].SetUint64(0)
	}
	return nil
}

func (m *mirrorCircuit) Define(api frontend.API) error {
	mark := func(name string) {
		*m.names = append(*m.names, name)
		if m.markers {
			if _, err := api.Compiler().NewHint(segmentMarker, 1); err != nil {
				panic(err)
			}
		}
	}
	mark("setup")
	b, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	fp, err := emulated.NewField[Fp](api)
	if err != nil {
		return err
	}
	fr, err := emulated.NewField[Fr](api)
	if err != nil {
		return err
	}
	curve, err := sw_emulated.New[Fp, Fr](api, sw_emulated.GetSecp256k1Params())
	if err != nil {
		return err
	}
	c := &ActionCircuit{RecordHash: m.RecordHash, Record: m.Record, In: m.In, Out: m.Out, ablated: m.ablated}
	a := &action{api: api, bytes: b, rc: rangecheck.New(api), fp: fp, fr: fr, curve: curve, c: c}
	A := c.Record[:]

	mark("byte-ranges")
	a.clauseByteRanges()
	mark("record-amounts")
	a.clauseRecordAmounts(A)
	mark("withdrawal-lock")
	a.clauseWithdrawalLock(A)
	mark("value-max-money")
	a.clauseValueMaxMoney()

	var inputCm [2][]uints.U8
	for s := 0; s < 2; s++ {
		in := &c.In[s]
		p := fmt.Sprintf("in%d.", s)
		ak := sw_emulated.AffinePoint[Fp]{X: in.AkX, Y: in.AkY}
		// clauseSpendKey
		mark(p + "spend-key.on-curve")
		a.curve.AssertIsOnCurve(&ak)
		mark(p + "spend-key.finite")
		a.api.AssertIsEqual(a.api.And(a.fp.IsZero(&ak.X), a.fp.IsZero(&ak.Y)), 0)
		// clauseRerandomizedKey
		mark(p + "rk.alpha-range")
		a.fr.AssertIsInRange(&in.Alpha)
		mark(p + "rk.scalar-mul-base")
		q := a.curve.ScalarMulBase(&in.Alpha)
		mark(p + "rk.add-unified")
		R := a.curve.AddUnified(&ak, q)
		mark(p + "rk.finite")
		a.api.AssertIsEqual(a.api.And(a.fp.IsZero(&R.X), a.fp.IsZero(&R.Y)), 0)
		mark(p + "rk.sec1c")
		if c.on(ClauseRkEqual) {
			rkEnc := a.sec1c(&R.X, &R.Y)
			mark(p + "rk.equal")
			a.assertBytesEqual(rkEnc, A[OffRk0+33*s:OffRk0+33*(s+1)])
		} else {
			mark(p + "rk.equal")
		}
		// clauseNullifier (with clauseOwnerTagOverNkc)
		mark(p + "nf.nkc-sha")
		nkc := a.sha256(constBytes(tagNkc), in.Nk[:])
		mark(p + "nf.sec1c-ak")
		akEnc := a.sec1c(&ak.X, &ak.Y)
		mark(p + "nf.owner-sha")
		owner := a.sha256(constBytes(tagOwner), akEnc, nkc)
		mark(p + "nf.cm-sha")
		cm := a.sha256(constBytes(tagCommitment), in.Value[:], owner, in.Rho[:], in.Rcm[:], in.RecoveryTag[:])
		mark(p + "nf.nf-sha")
		nf := a.sha256(constBytes(tagNullifier), in.Nk[:], in.Rho[:], cm)
		mark(p + "nf.equal")
		if c.on(ClauseNullifier) {
			a.assertBytesEqual(nf, A[OffNullifier0+32*s:OffNullifier0+32*(s+1)])
		}
		inputCm[s] = cm
	}
	mark("nullifier-distinct")
	a.clauseNullifierDistinct(A[OffNullifier0:OffNullifier0+32], A[OffNullifier1:OffNullifier1+32])
	for s := 0; s < 2; s++ {
		in := &c.In[s]
		p := fmt.Sprintf("in%d.", s)
		// clauseMembership
		mark(p + "membership.bits")
		for h := range in.PositionBits {
			a.api.AssertIsBoolean(in.PositionBits[h])
		}
		mark(p + "membership.path-sha")
		current := inputCm[s]
		for h := 0; h < TreeDepth; h++ {
			bit := in.PositionBits[h]
			sibling := in.Siblings[h][:]
			left := make([]uints.U8, 32)
			right := make([]uints.U8, 32)
			for i := 0; i < 32; i++ {
				d := a.api.Mul(bit, a.api.Sub(a.raw(sibling[i]), a.raw(current[i])))
				left[i] = uints.U8{Val: a.api.Add(a.raw(current[i]), d)}
				right[i] = uints.U8{Val: a.api.Sub(a.raw(sibling[i]), d)}
			}
			current = a.sha256(constBytes(tagTreeNode), left, right)
		}
		mark(p + "membership.equal")
		if c.on(ClauseMembership) {
			nonzero := a.api.Sub(1, a.api.IsZero(a.u64le(in.Value[:])))
			anchor := A[OffAnchor : OffAnchor+32]
			for i := 0; i < 32; i++ {
				a.api.AssertIsEqual(a.api.Mul(nonzero, a.api.Sub(a.raw(current[i]), a.raw(anchor[i]))), 0)
			}
		}
	}
	for j := 0; j < 2; j++ {
		out := &c.Out[j]
		p := fmt.Sprintf("out%d.", j)
		mark(p + "rho-index")
		a.clauseRhoIndex(out, A[OffNullifier0+32*j:OffNullifier0+32*(j+1)])
		// clauseOutputCommitment (outputRcm is evaluated as the cm hash's argument, after the tag)
		mark(p + "cm.tag-sha")
		tag := a.sha256(constBytes(tagRecoveryTag), out.RecoveryKey[:])
		mark(p + "cm.rcm-sha")
		rcm := a.sha256(constBytes(TagRcm), out.RecoveryKey[:], out.Rho[:])
		mark(p + "cm.cm-sha")
		cm := a.sha256(constBytes(tagCommitment), out.Value[:], out.OwnerTag[:], out.Rho[:], rcm, tag)
		mark(p + "cm.equal")
		if c.on(ClauseOutputCommitment) {
			a.assertBytesEqual(cm, A[OffCm0+32*j:OffCm0+32*(j+1)])
		}
		// clausePacket
		mark(p + "packet.pad-sha")
		key := a.sha256(constBytes(TagPad), out.RecoveryKey[:], out.Rho[:], cm)
		mark(p + "packet.pad-xor")
		packet := make([]uints.U8, 0, PacketBytes)
		for i := 0; i < 8; i++ {
			packet = append(packet, a.bytes.Xor(out.Value[i], key[i]))
		}
		packet = append(packet, key[8:16]...)
		mark(p + "packet.equal")
		if c.on(ClausePacket) {
			a.assertBytesEqual(packet, A[OffPacket0+PacketBytes*j:OffPacket0+PacketBytes*(j+1)])
		}
	}
	mark("balance")
	a.clauseBalance(A)
	// clauseRecordHash
	mark("record-hash.sha")
	acc := frontend.Variable(0)
	for _, d := range a.sha256(A) {
		acc = a.api.Add(a.api.Mul(acc, 256), a.bytes.Value(d))
	}
	mark("record-hash.equal")
	if !c.ablated[mutationRecordHashUnbound] {
		a.api.AssertIsEqual(acc, c.RecordHash)
	}
	mark("deferred")
	return nil
}

func compileMirror(markers bool, ablated ...Clause) (*csbn254.R1CS, []string, error) {
	var names []string
	m := &mirrorCircuit{markers: markers, names: &names}
	if len(ablated) > 0 {
		m.ablated = map[Clause]bool{}
		for _, cl := range ablated {
			m.ablated[cl] = true
		}
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, m)
	if err != nil {
		return nil, nil, err
	}
	r, ok := ccs.(*csbn254.R1CS)
	if !ok {
		return nil, nil, fmt.Errorf("constraint system is %T", ccs)
	}
	return r, names, nil
}

// segmentMap is what the marked mirror says about each gadget.
type segmentMap struct {
	Names []string `json:"segments"`
	// CIDStart[i] is the first constraint id of segment i.
	CIDStart []int `json:"-"`
	// instrSeg[k] is the segment of production instruction k.
	instrSeg []uint16
	// wireStart[i] is the marker wire of segment i: wires allocated in the
	// segment are above it.
	wireStart []uint32
	nbInputs  uint32
	// Hints[segment][hint] = instructions; Lookups[segment] = lookup instructions.
	Hints   map[string]map[string]int `json:"hintsBySegment"`
	Lookups map[string]int            `json:"lookupsBySegment"`
	R1Cs    map[string]int            `json:"constraintsBySegment"`
	// Decompose["segment|bits=N"] = deferred DecomposeHint calls by the
	// segment that allocated the checked value's highest wire (inputs for
	// circuit inputs) and the checked width.
	Decompose   map[string]int `json:"decomposeByOrigin"`
	Fingerprint string         `json:"fingerprint"`
	Constraints int            `json:"constraints"`
	Markers     int            `json:"markers"`
	// Deferred sub-blocks. The deferred callbacks first emit the range
	// checks' recompositions, then the commitment; then gnark's multicommit
	// runs one callback per log-derivative argument and per emulated field's
	// deferred checks, handing callback i the commitment's (i+1)-th power
	// through one R1C rootCmt·c_{i-1} = c_i. Those R1Cs are the boundaries.
	CommitmentCID int        `json:"commitmentConstraintOffset"`
	Callbacks     []callback `json:"deferredCallbacks"`
}

// callback is one multicommit callback: a log-derivative argument (it has a
// batch inverse, one output per query) or an emulated field's deferred
// checks (it has none).
type callback struct {
	StartCID            int    `json:"startConstraint"`
	EndCID              int    `json:"endConstraint"`
	BatchInverseOutputs int    `json:"batchInverseOutputs"`
	Label               string `json:"label"`
}

// instructionKind names an instruction's blueprint (the hint name for a hint).
func instructionKind(r *csbn254.R1CS, pi constraint.PackedInstruction, hm *constraint.HintMapping) (string, bool) {
	bp := r.Blueprints[pi.BlueprintID]
	if bh, ok := bp.(constraint.BlueprintHint); ok {
		bh.DecompressHint(hm, pi.Unpack(&r.System))
		return r.MHintsDependencies[hm.HintID], true
	}
	return fmt.Sprintf("%T", bp), false
}

// fingerprint hashes the instruction kinds, constraint offsets and blueprint
// types in order, skipping markers.
type fingerprinter struct {
	h   interface{ Write([]byte) (int, error) }
	sum func() []byte
}

func newFingerprinter() *fingerprinter {
	h := sha256.New()
	return &fingerprinter{h: h, sum: func() []byte { return h.Sum(nil) }}
}

func (f *fingerprinter) add(kind string, cid uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], cid)
	f.h.Write([]byte(kind))
	f.h.Write(b[:])
}

// productionFingerprint is the fingerprint of the production system.
func productionFingerprint(r *csbn254.R1CS) string {
	f := newFingerprinter()
	var hm constraint.HintMapping
	for _, pi := range r.Instructions {
		kind, _ := instructionKind(r, pi, &hm)
		f.add(kind, pi.ConstraintOffset)
	}
	return fmt.Sprintf("%x", f.sum())
}

func constantOf(r *csbn254.R1CS, le constraint.LinearExpression) (uint64, bool) {
	if len(le) != 1 || !le[0].IsConstant() {
		return 0, false
	}
	var v big.Int
	r.Coefficients[le[0].CID].BigInt(&v)
	if !v.IsUint64() {
		return 0, false
	}
	return v.Uint64(), true
}

// buildSegmentMap walks the marked mirror.
func buildSegmentMap(r *csbn254.R1CS, names []string) (*segmentMap, error) {
	marker := solver.GetHintName(segmentMarker)
	sm := &segmentMap{
		Names:     names,
		Hints:     map[string]map[string]int{},
		Lookups:   map[string]int{},
		R1Cs:      map[string]int{},
		Decompose: map[string]int{},
		nbInputs:  uint32(r.GetNbPublicVariables() + r.GetNbSecretVariables()),
	}
	f := newFingerprinter()
	seg := -1
	var hm constraint.HintMapping
	var rc constraint.R1C
	lookupQueries := map[constraint.BlueprintID]int{}
	sm.CommitmentCID = -1
	var commitWire, prevCmt uint32
	type pending struct {
		wire uint32
		bits uint64
	}
	var decomposes []pending
	for _, pi := range r.Instructions {
		kind, isHint := instructionKind(r, pi, &hm)
		if isHint && kind == marker {
			seg++
			if seg >= len(names) {
				return nil, fmt.Errorf("more markers than names")
			}
			sm.CIDStart = append(sm.CIDStart, int(pi.ConstraintOffset))
			sm.wireStart = append(sm.wireStart, hm.OutputRange.Start)
			sm.Markers++
			continue
		}
		if seg < 0 {
			return nil, fmt.Errorf("instruction before the first marker")
		}
		f.add(kind, pi.ConstraintOffset)
		sm.instrSeg = append(sm.instrSeg, uint16(seg))
		name := names[seg]
		bp := r.Blueprints[pi.BlueprintID]
		switch {
		case isHint:
			if kind == hintCommitment {
				sm.CommitmentCID = int(pi.ConstraintOffset)
				commitWire = hm.OutputRange.Start
				prevCmt = commitWire
				sm.Callbacks = append(sm.Callbacks, callback{StartCID: sm.CommitmentCID})
			}
			if sm.Hints[name] == nil {
				sm.Hints[name] = map[string]int{}
			}
			sm.Hints[name][kind]++
			if kind == hintDecompose && name == "deferred" {
				bits, _ := constantOf(r, hm.Inputs[0])
				var top uint32
				for _, t := range hm.Inputs[2] {
					if !t.IsConstant() && t.VID > top {
						top = t.VID
					}
				}
				decomposes = append(decomposes, pending{wire: top, bits: bits})
			}
		case strings.Contains(kind, "BlueprintLookupHint"):
			sm.Lookups[name]++
			lookupQueries[pi.BlueprintID] += bp.NbOutputs(pi.Unpack(&r.System))
		case strings.Contains(kind, "BlueprintBatchInverse"):
			if n := len(sm.Callbacks); n > 0 {
				sm.Callbacks[n-1].BatchInverseOutputs += bp.NbOutputs(pi.Unpack(&r.System))
			}
		default:
			if b, ok := bp.(constraint.BlueprintR1C); ok {
				sm.R1Cs[name]++
				if name == "deferred" && sm.CommitmentCID >= 0 {
					b.DecompressR1C(&rc, pi.Unpack(&r.System))
					if len(rc.L) == 1 && len(rc.R) == 1 && len(rc.O) == 1 &&
						((rc.L[0].VID == commitWire && rc.R[0].VID == prevCmt) || (rc.R[0].VID == commitWire && rc.L[0].VID == prevCmt)) {
						prevCmt = rc.O[0].VID
						sm.Callbacks[len(sm.Callbacks)-1].EndCID = int(pi.ConstraintOffset) - 1
						sm.Callbacks = append(sm.Callbacks, callback{StartCID: int(pi.ConstraintOffset) + 1})
					}
				}
			}
		}
	}
	if seg != len(names)-1 {
		return nil, fmt.Errorf("%d markers for %d names", seg+1, len(names))
	}
	for _, d := range decomposes {
		origin := "inputs"
		if d.wire >= sm.nbInputs {
			// the last segment whose marker wire is below the checked wire
			i := sort.Search(len(sm.wireStart), func(i int) bool { return sm.wireStart[i] > d.wire }) - 1
			if i >= 0 {
				origin = names[i]
			}
		}
		sm.Decompose[fmt.Sprintf("%s|bits=%d", origin, d.bits)]++
	}
	// name each callback: a log-derivative argument by its query count (the
	// xor and and tables' queries are their hints' calls), any other one with
	// a batch inverse the range-check table; one without, emulated checks.
	// Revision 3 has no lookup-blueprint table (revision 2's AES S-box and
	// xtime tables went with the AES-GCM packet); a lookup blueprint in the
	// inventory would be an unattacked one (checkCoverage).
	total := func(hint string) int {
		n := 0
		for _, hs := range sm.Hints {
			n += hs[hint]
		}
		return n
	}
	var lookupIDs []constraint.BlueprintID
	for id := range lookupQueries {
		lookupIDs = append(lookupIDs, id)
	}
	sort.Slice(lookupIDs, func(i, j int) bool { return lookupIDs[i] < lookupIDs[j] })
	if n := len(sm.Callbacks); n > 0 {
		sm.Callbacks[n-1].EndCID = r.GetNbConstraints() - 1
	}
	emulated := 0
	for i := range sm.Callbacks {
		c := &sm.Callbacks[i]
		switch {
		case c.BatchInverseOutputs == 0:
			c.Label = fmt.Sprintf("emulated-checks-%d", emulated)
			emulated++
		case c.BatchInverseOutputs == total(hintXor):
			c.Label = "xor-table-argument"
		case c.BatchInverseOutputs == total(hintAnd):
			c.Label = "and-table-argument"
		case len(lookupIDs) > 0 && c.BatchInverseOutputs == lookupQueries[lookupIDs[0]]:
			c.Label = "lookup-table-argument"
		default:
			c.Label = "range-table-argument"
		}
	}
	sm.Fingerprint = fmt.Sprintf("%x", f.sum())
	sm.Constraints = r.GetNbConstraints()
	return sm, nil
}

// segmentOfCID returns the segment containing constraint id cid.
func (sm *segmentMap) segmentOfCID(cid int) string {
	if cid < 0 {
		return ""
	}
	i := sort.Search(len(sm.CIDStart), func(i int) bool { return sm.CIDStart[i] > cid }) - 1
	// several empty segments can share a start: the constraint belongs to
	// the last of them
	if i < 0 {
		return ""
	}
	if sm.Names[i] != "deferred" {
		return sm.Names[i]
	}
	if sm.CommitmentCID < 0 || cid < sm.CommitmentCID {
		return "deferred.range-recomposition"
	}
	k := sort.Search(len(sm.Callbacks), func(k int) bool { return sm.Callbacks[k].StartCID > cid }) - 1
	if k < 0 {
		return "deferred.commitment"
	}
	c := sm.Callbacks[k]
	switch {
	case cid > c.EndCID:
		return "deferred.commitment-power"
	case cid == c.EndCID:
		return "deferred." + c.Label + ".last-constraint"
	}
	return "deferred." + c.Label
}

// solveOrder lists, for each hint name, the production instruction indices of
// its calls in the order a single-task solver makes them (level by level).
func solveOrder(r *csbn254.R1CS) map[string][]uint32 {
	out := map[string][]uint32{}
	var hm constraint.HintMapping
	for _, level := range r.Levels {
		for _, k := range level {
			pi := r.Instructions[k]
			if bh, ok := r.Blueprints[pi.BlueprintID].(constraint.BlueprintHint); ok {
				bh.DecompressHint(&hm, pi.Unpack(&r.System))
				name := r.MHintsDependencies[hm.HintID]
				out[name] = append(out[name], k)
			}
		}
	}
	return out
}

// TestHintAttribution compiles the production circuit and the mirror twice.
// The unmarked mirror must reproduce the production R1CS digest; the marked
// mirror then attributes every hint and constraint to a gadget. Three
// compiles of the action circuit, so it runs only with
// POOL_ACTION_HINT_ATTRIBUTION=FILE.json.
func TestHintAttribution(t *testing.T) {
	defer protectedPanic(t)
	out := os.Getenv("POOL_ACTION_HINT_ATTRIBUTION")
	if out == "" {
		protectedSkip(t, "set POOL_ACTION_HINT_ATTRIBUTION=FILE.json (three action-circuit compiles)")
	}
	digest := func(ccs constraint.ConstraintSystem) string {
		h := sha256.New()
		if _, err := ccs.WriteTo(h); err != nil {
			protectedFatal(t, err)
		}
		return fmt.Sprintf("%x", h.Sum(nil))
	}
	ccs, err := Compile()
	if err != nil {
		protectedFatal(t, err)
	}
	prod := asR1CS(t, ccs)
	prodDigest := digest(prod)
	prodFP := productionFingerprint(prod)
	inv := inventory(prod)
	prodConstraints := prod.GetNbConstraints()
	ccs, prod = nil, nil
	Release()

	plain, _, err := compileMirror(false)
	if err != nil {
		protectedFatal(t, err)
	}
	plainDigest := digest(plain)
	plain = nil
	Release()
	protectedLog(t, "production R1CS sha256 %s", prodDigest)
	protectedLog(t, "mirror (no markers)    %s", plainDigest)
	if plainDigest != prodDigest {
		protectedFatal(t, "the unmarked mirror does not reproduce the production R1CS: the attribution would not be about this circuit")
	}

	marked, names, err := compileMirror(true)
	if err != nil {
		protectedFatal(t, err)
	}
	sm, err := buildSegmentMap(marked, names)
	if err != nil {
		protectedFatal(t, err)
	}
	marked = nil
	Release()
	if sm.Fingerprint != prodFP || sm.Constraints != prodConstraints {
		protectedFatal(t, "marked mirror fingerprint %s / %d constraints, production %s / %d", sm.Fingerprint, sm.Constraints, prodFP, prodConstraints)
	}
	// every hint count adds up to the production inventory
	sums := map[string]int{}
	for _, hs := range sm.Hints {
		for name, n := range hs {
			sums[name] += n
		}
	}
	for _, h := range inv.Hints {
		if sums[h.Name] != h.Instructions {
			protectedError(t, "hint %s: %d attributed, %d in production", h.Name, sums[h.Name], h.Instructions)
		}
	}
	writeResults(t, "POOL_ACTION_HINT_ATTRIBUTION", struct {
		ProductionDigest string        `json:"productionR1CSSha256"`
		MirrorDigest     string        `json:"unmarkedMirrorR1CSSha256"`
		Inventory        hintInventory `json:"inventory"`
		Segments         *segmentMap   `json:"attribution"`
	}{prodDigest, plainDigest, inv, sm})
}
