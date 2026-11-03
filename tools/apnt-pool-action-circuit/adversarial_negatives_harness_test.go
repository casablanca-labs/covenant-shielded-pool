package poolaction

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	csbn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

// ENG-369 (R-339): negatives for the hint-assisted gadgets of gnark v0.16.3.
// A hint is prover-chosen: the solver's honest hint is one choice, and an
// adversarial prover may return anything. These tests override hints (and the
// batch-inverse blueprint, which is not a hint; revision 2 also had the AES
// lookup blueprints) and require
// that a constraint refuses every output that would make a false value flow
// on.
//
// Only an R1C that evaluates unequal counts as a refusal. gnark also returns
// an *UnsatisfiedConstraintError when a blueprint's Solve fails (the lookup
// blueprint's "lookup query too large"), and a plain error when a hint fails
// (countHint's "query element not in table", polyMvHint's "asserted zero
// evaluation has non-zero remainder"). Neither is constraint soundness: a
// prover can always compute those wires some other way. The adversary layer
// below replaces those downstream hints and the lookup blueprint with
// versions that never fail, so the verdict comes from a constraint.

// Fully qualified names of the hints this suite overrides (gnark v0.16.3).
const (
	hintCombRecode    = "github.com/consensys/gnark/std/algebra/emulated/sw_emulated.combRecodeHint"
	hintCombLambda    = "github.com/consensys/gnark/std/algebra/emulated/sw_emulated.combChainLambdaHint"
	hintUnifiedSlope  = "github.com/consensys/gnark/std/algebra/emulated/sw_emulated.unifiedSlopeHint"
	hintInvZero       = "github.com/consensys/gnark/constraint/solver.InvZeroHint"
	hintMul           = mulHintName
	hintPolyMv        = "github.com/consensys/gnark/std/math/emulated.polyMvHint"
	hintDecompose     = "github.com/consensys/gnark/std/rangecheck.DecomposeHint"
	hintXor           = "github.com/consensys/gnark/std/math/uints.xorHint"
	hintAnd           = "github.com/consensys/gnark/std/math/uints.andHint"
	hintToBytes       = "github.com/consensys/gnark/std/math/uints.toBytes"
	hintPartition     = "github.com/consensys/gnark/std/math/bitslice.partitionHint"
	hintNBits         = "github.com/consensys/gnark/std/math/bits.nBits"
	hintLogderivCount = "github.com/consensys/gnark/std/internal/logderivarg.countHint"
	hintCommitment    = "github.com/consensys/gnark/frontend/cs.Bsb22CommitmentComputePlaceholder"
	hintRandomize     = "github.com/consensys/gnark/internal/hints.Randomize"
)

// Coverage. The action circuit's inventory has 15 hint ids and two solver
// blueprints besides the R1Cs. The negatives attack 13 of the hint ids and
// both blueprints (attackedHints, attackedBlueprints). The other two hint
// ids are the backend's (backendHints) and have no refusal negative:
//
//   - Bsb22CommitmentComputePlaceholder stands in for the commitment the
//     Groth16 backend computes from the committed wires when it proves; the
//     verifier recomputes it from the proof. No R1C pins it and no R1C can:
//     it is the Fiat–Shamir challenge of the lookup arguments and emulated
//     deferred checks, bound by the proof system, not by the constraint
//     system. The solver runs here use commitmentStandIn (a hash of the
//     committed wires), so forged outputs move the challenge as they would.
//   - Randomize is the commitment's hiding mask. Any value is a valid
//     witness (its only R1C is mask·1 = mask), so there is no dishonest
//     output to refuse. maskStandIn fixes it.
//
// A solver-level suite cannot test those two; their soundness is the
// backend's (the commitment's binding), outside this R1CS. checkCoverage
// fails if the inventory gains a hint id or blueprint in neither list, or if
// an attacked one has no refused negative that forged it.
var (
	attackedHints = []string{
		hintCombRecode, hintCombLambda, hintUnifiedSlope, hintInvZero, hintMul, hintPolyMv, hintDecompose,
		hintXor, hintAnd, hintToBytes, hintPartition, hintNBits, hintLogderivCount,
	}
	backendHints       = []string{hintCommitment, hintRandomize}
	blueprintBatchInv  = fmt.Sprintf("%T", &constraint.BlueprintBatchInverse[constraint.U64]{})
	blueprintLookup    = fmt.Sprintf("%T", &constraint.BlueprintLookupHint[constraint.U64]{})
	attackedBlueprints = []string{blueprintBatchInv, blueprintLookup}
)

// checkCoverage returns every coverage gap of one phase: an inventoried hint
// id or solver blueprint that is neither attacked nor the backend's, and an
// attacked one with no negative that forged ≥1 call and was refused by an R1C.
func checkCoverage(inv hintInventory, cases []caseResult) []string {
	in := func(list []string, name string) bool {
		for _, n := range list {
			if n == name {
				return true
			}
		}
		return false
	}
	refused := map[string]bool{}
	for _, c := range cases {
		if c.Kind == "negative" && c.ForgedCalls > 0 && c.Verdict.Got == gotConstraint {
			refused[c.Target] = true
		}
	}
	gaps := []string{}
	for _, h := range inv.Hints {
		switch {
		case in(backendHints, h.Name):
		case !in(attackedHints, h.Name):
			gaps = append(gaps, "unattacked hint id "+h.Name)
		case !refused[h.Name]:
			gaps = append(gaps, "no refused negative forges hint "+h.Name)
		}
	}
	for _, b := range inv.Blueprints {
		switch {
		case !in(attackedBlueprints, b.Type):
			gaps = append(gaps, "unattacked solver blueprint "+b.Type)
		case !refused[b.Type]:
			gaps = append(gaps, "no refused negative forges blueprint "+b.Type)
		}
	}
	return gaps
}

var nativeQ = ecc.BN254.ScalarField()

// modQ reduces v into [0, q).
func modQ(v *big.Int) *big.Int { return new(big.Int).Mod(v, nativeQ) }

// r1cMismatch is the text of gnark's R1C check failure, "a ⋅ b != c".
var r1cMismatch = regexp.MustCompile(` ⋅ .* != `)

// verdict classifies a solve: satisfied, refused by an R1C (with its
// constraint id), or refused by something that is not a constraint.
type verdict struct {
	Got     string `json:"got"` // satisfied | refused-by-constraint | refused-other
	CID     int    `json:"constraint"`
	Message string `json:"message,omitempty"`
}

const (
	gotSatisfied  = "satisfied"
	gotConstraint = "refused-by-constraint"
	gotOther      = "refused-other"
)

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func classify(err error, nbConstraints int) verdict {
	if err == nil {
		return verdict{Got: gotSatisfied, CID: -1}
	}
	var u *csbn254.UnsatisfiedConstraintError
	if errors.As(err, &u) && u.CID >= 0 && u.CID < nbConstraints && u.Err != nil && r1cMismatch.MatchString(u.Err.Error()) {
		return verdict{Got: gotConstraint, CID: u.CID, Message: "pool-solver-refusal"}
	}
	return verdict{Got: gotOther, CID: -1, Message: "pool-solver-refusal"}
}

// hintIDs maps each hint name the compiled system depends on to its id.
func hintIDs(r *csbn254.R1CS) map[string]solver.HintID {
	out := map[string]solver.HintID{}
	for id, name := range r.MHintsDependencies {
		out[name] = id
	}
	return out
}

// ---- deterministic Fiat–Shamir for solver runs ----

// commitmentStandIn replaces gnark's test-mode commitment placeholder, which
// draws a fresh random value each solve. It hashes every committed wire, so
// the challenge depends on the (possibly overridden) hint outputs, as the
// prover's commitment would, and a run is reproducible.
func commitmentStandIn(_ *big.Int, in, out []*big.Int) error {
	h := sha256.New()
	var buf [32]byte
	for _, v := range in {
		modQ(v).FillBytes(buf[:])
		h.Write(buf[:])
	}
	out[0].SetBytes(h.Sum(nil))
	out[0].Mod(out[0], nativeQ)
	if out[0].Sign() == 0 {
		out[0].SetUint64(1)
	}
	return nil
}

// maskStandIn fixes the commitment's hiding mask (free by design).
func maskStandIn(_ *big.Int, _, out []*big.Int) error {
	sum := sha256.Sum256([]byte("apnt-pool ENG-369 commitment mask"))
	for i := range out {
		out[i].SetBytes(sum[:])
		out[i].Mod(out[i], nativeQ)
	}
	return nil
}

// ---- the adversary layer: downstream hints that never fail ----

// tolerantCount is logderivarg's countHint without its refusal: a query row
// that is not a table row is skipped (counted in unmatched) instead of
// failing the solve. For honest queries it returns the same multiplicities.
func tolerantCount(unmatched *int64) solver.Hint {
	return func(_ *big.Int, in, out []*big.Int) error {
		nbTable, nbRow := int(in[0].Int64()), int(in[1].Int64())
		key := func(off int) string {
			buf := make([]byte, 32*nbRow)
			for j := 0; j < nbRow; j++ {
				modQ(in[off+j]).FillBytes(buf[32*j : 32*(j+1)])
			}
			return string(buf)
		}
		pos := make(map[string]int, nbTable)
		for i := 0; i < nbTable; i++ {
			pos[key(2+nbRow*i)] = i
		}
		counts := make([]int64, nbTable)
		nbQueries := (len(in) - 2 - nbTable*nbRow) / nbRow
		for i := 0; i < nbQueries; i++ {
			if p, ok := pos[key(2+nbRow*nbTable+nbRow*i)]; ok {
				counts[p]++
			} else {
				atomic.AddInt64(unmatched, 1)
			}
		}
		for i := range out {
			out[i].SetInt64(counts[i])
		}
		return nil
	}
}

// decomposeMode is how the adversarial DecomposeHint answers.
type decomposeMode int

const (
	// decomposeExact returns the honest limbs when the value fits; when it
	// does not, the low limbs are honest and the top limb absorbs the rest,
	// so the recomposition constraint holds and only the table (the
	// log-derivative argument over the limbs) can refuse.
	decomposeExact decomposeMode = iota
	// decomposeNative is gnark's own DecomposeHint: the value's low bits
	// only, so an out-of-range value fails its recomposition constraint.
	decomposeNative
)

// decomposeLimbs splits v like DecomposeHint, then (exact mode) moves the
// remainder into the top limb, modulo q.
func decomposeLimbs(mode decomposeMode, in, out []*big.Int) error {
	if mode == decomposeNative {
		return rangecheck.DecomposeHint(nativeQ, in, out)
	}
	limbSize := uint(in[1].Uint64())
	v := modQ(in[2])
	base := new(big.Int).Lsh(big.NewInt(1), limbSize)
	rest := new(big.Int).Set(v)
	for i := range out {
		out[i].Mod(rest, base)
		rest.Rsh(rest, limbSize)
	}
	if rest.Sign() == 0 {
		return nil
	}
	// v − Σ_{i<n−1} l_i·2^{k·i}, divided by 2^{k·(n−1)} in F_q
	n := len(out)
	low := new(big.Int)
	for i := n - 2; i >= 0; i-- {
		low.Lsh(low, limbSize)
		low.Add(low, out[i])
	}
	top := new(big.Int).Sub(v, low)
	shift := new(big.Int).Lsh(big.NewInt(1), limbSize*uint(n-1))
	top.Mul(top, new(big.Int).ModInverse(shift, nativeQ))
	out[n-1].Set(modQ(top))
	return nil
}

// tolerantToBytes is uints' toBytes without its refusal of an input wider
// than 64 bits (which only a forged upstream value produces): it returns the
// low bytes, and the recomposition constraint decides.
func tolerantToBytes(_ *big.Int, in, out []*big.Int) error {
	v := modQ(in[1])
	mask := big.NewInt(0xff)
	for i := range out {
		out[i].And(new(big.Int).Rsh(v, uint(8*i)), mask)
	}
	return nil
}

// referencedWires marks every wire an R1C or a hint input refers to.
func referencedWires(r *csbn254.R1CS) []bool {
	nb := r.GetNbPublicVariables() + r.GetNbSecretVariables() + r.GetNbInternalVariables()
	used := make([]bool, nb)
	mark := func(le constraint.LinearExpression) {
		for _, t := range le {
			if !t.IsConstant() && int(t.VID) < nb {
				used[t.VID] = true
			}
		}
	}
	var hm constraint.HintMapping
	var c constraint.R1C
	for _, pi := range r.Instructions {
		switch b := r.Blueprints[pi.BlueprintID].(type) {
		case constraint.BlueprintR1C:
			b.DecompressR1C(&c, pi.Unpack(&r.System))
			mark(c.L)
			mark(c.R)
			mark(c.O)
		case constraint.BlueprintHint:
			b.DecompressHint(&hm, pi.Unpack(&r.System))
			for _, le := range hm.Inputs {
				mark(le)
			}
		}
	}
	return used
}

// mulRemainderUsed reports, for each mulHint call in solve order, whether
// any of its remainder outputs is referenced. A reduction's remainder is the
// reduced value; checkZero's remainder outputs exist but nothing reads them
// (free wires: forging them forges nothing).
func mulRemainderUsed(r *csbn254.R1CS, order []uint32) ([]bool, error) {
	used := referencedWires(r)
	var hm constraint.HintMapping
	out := make([]bool, len(order))
	for k, ins := range order {
		pi := r.Instructions[ins]
		r.Blueprints[pi.BlueprintID].(constraint.BlueprintHint).DecompressHint(&hm, pi.Unpack(&r.System))
		nbLimbs, ok1 := constantOf(r, hm.Inputs[1])
		nbQuo, ok2 := constantOf(r, hm.Inputs[3])
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("mulHint call %d: limb counts are not constants", k)
		}
		start := hm.OutputRange.Start + uint32(nbQuo)
		for w := start; w < start+uint32(nbLimbs); w++ {
			if used[w] {
				out[k] = true
			}
		}
	}
	return out, nil
}

// ---- lookup blueprints (revision 2's AES S-box and xtime tables; none in revision 3) ----

// lookupForge decides the value a lookup query returns. idx is the query
// index, entry the honest table value (nil when the index is out of range).
// It returns nil for the honest value (0 when out of range).
type lookupForge func(table int, call int64, idx uint64, entry *big.Int) *big.Int

// lookupProxy wraps gnark's lookup blueprint. It answers as the original
// does, except that an out-of-range index yields 0 instead of failing the
// solve, and forge may replace any answer. It never touches a constraint.
type lookupProxy struct {
	*constraint.BlueprintLookupHint[constraint.U64]
	table   int
	calls   *int64
	oor     *int64
	forge   lookupForge
	entries []constraint.U64
}

func (p *lookupProxy) Solve(s constraint.Solver[constraint.U64], inst constraint.Instruction) error {
	nbEntries := int(inst.Calldata[1])
	if len(p.entries) < nbEntries {
		p.entries = p.entries[:0]
		off := 0
		for i := 0; i < nbEntries; i++ {
			e, d := s.Read(p.EntriesCalldata[off:])
			off += d
			p.entries = append(p.entries, e)
		}
	}
	nbInputs := int(inst.Calldata[2])
	off := 3
	for i := 0; i < nbInputs; i++ {
		in, d := s.Read(inst.Calldata[off:])
		off += d
		call := atomic.AddInt64(p.calls, 1) - 1
		idx, ok := s.Uint64(in)
		var entry *big.Int
		val := s.FromInterface(0)
		if ok && idx < uint64(nbEntries) {
			val = p.entries[idx]
			entry = s.ToBigInt(val)
		} else {
			atomic.AddInt64(p.oor, 1)
		}
		if p.forge != nil {
			if f := p.forge(p.table, call, idx, entry); f != nil {
				val = s.FromInterface(modQ(f))
			}
		}
		s.SetValue(uint32(i+int(inst.WireOffset)), val)
	}
	return nil
}

// batchInverseForge decides the value a batch-inverse output takes: call is
// the batch-inverse instruction's index in solve order, i the output's index
// in it, inv the honest inverse. It returns nil for the honest value.
type batchInverseForge func(call int64, i int, inv *big.Int) *big.Int

// batchInverseProxy wraps gnark's batch-inverse blueprint (the lookup
// arguments' 1/(X − q) inverses; each output is then checked by one R1C,
// out·in = 1). forge may replace any output; nothing else changes.
type batchInverseProxy struct {
	*constraint.BlueprintBatchInverse[constraint.U64]
	calls *int64
	forge batchInverseForge
}

type setValueHook struct {
	constraint.Solver[constraint.U64]
	hook func(vID uint32, v constraint.U64) constraint.U64
}

func (s *setValueHook) SetValue(vID uint32, v constraint.U64) { s.Solver.SetValue(vID, s.hook(vID, v)) }

func (p *batchInverseProxy) Solve(s constraint.Solver[constraint.U64], inst constraint.Instruction) error {
	call := atomic.AddInt64(p.calls, 1) - 1
	hooked := &setValueHook{Solver: s, hook: func(vID uint32, v constraint.U64) constraint.U64 {
		if f := p.forge(call, int(vID-inst.WireOffset), s.ToBigInt(v)); f != nil {
			return s.FromInterface(modQ(f))
		}
		return v
	}}
	return p.BlueprintBatchInverse.Solve(hooked, inst)
}

// ---- running one case ----

// adversary is everything one case overrides.
type adversary struct {
	hints map[string]solver.Hint // by hint name
	// layer installs the tolerant countHint and polyMvHint (unless the case
	// overrides them), the exact DecomposeHint (unless decompose is set to
	// native) and the tolerant lookup blueprint.
	layer        bool
	decompose    decomposeMode
	lookup       lookupForge
	batchInverse batchInverseForge
}

// caseResult is one solver run as the evidence records it.
type caseResult struct {
	Phase    string  `json:"phase"`
	Case     string  `json:"case"`
	Family   string  `json:"family"`
	Kind     string  `json:"kind"` // control | negative | statement-negative | alternative-witness | observation
	Positive string  `json:"positive"`
	Target   string  `json:"target,omitempty"` // the hint or blueprint a negative forges
	Forged   string  `json:"forged"`
	Expect   string  `json:"expect"`
	Verdict  verdict `json:"verdict"`
	Segment  string  `json:"refusingSegment,omitempty"`
	// ForgedCalls counts the hint calls (for the blueprints: lookup queries,
	// batch-inverse outputs) whose answer the adversary changed, not wires.
	ForgedCalls int64            `json:"forgedCalls"`
	Fired       map[string]int64 `json:"overrideCalls"`
	Unmatched   int64            `json:"countHintUnmatchedQueries"`
	LookupOOR   int64            `json:"lookupOutOfRange"`
	Seconds     float64          `json:"seconds"`
	Note        string           `json:"note,omitempty"`
	Pass        bool             `json:"pass"`
}

// hintHarness solves one compiled system under adversaries.
type hintHarness struct {
	t   testing.TB
	r   *csbn254.R1CS
	ids map[string]solver.HintID
	nbC int
	// lookup blueprints, by blueprint id (revision 2's AES tables; none in revision 3)
	lookups []constraint.BlueprintID
	// batch-inverse blueprints
	inverses []constraint.BlueprintID
}

func newHintHarness(t testing.TB, r *csbn254.R1CS) *hintHarness {
	h := &hintHarness{t: t, r: r, ids: hintIDs(r), nbC: r.GetNbConstraints()}
	for i, bp := range r.Blueprints {
		if _, ok := bp.(*constraint.BlueprintLookupHint[constraint.U64]); ok {
			h.lookups = append(h.lookups, constraint.BlueprintID(i))
		}
		if _, ok := bp.(*constraint.BlueprintBatchInverse[constraint.U64]); ok {
			h.inverses = append(h.inverses, constraint.BlueprintID(i))
		}
	}
	return h
}

// has reports whether the compiled system calls the named hint.
func (h *hintHarness) has(name string) bool { _, ok := h.ids[name]; return ok }

// solve runs the solver once, single-task (so hint calls arrive in level
// order and the first failing constraint is deterministic), under adv.
func (h *hintHarness) solve(assignment frontend.Circuit, adv adversary) (verdict, map[string]int64, int64, int64, time.Duration) {
	w, err := frontend.NewWitness(assignment, nativeQ)
	if err != nil {
		protectedFatal(h.t, "witness: %v", err)
	}
	fired := map[string]*int64{}
	var unmatched, oor int64
	opts := []solver.Option{solver.WithNbTasks(1)}
	override := func(name string, fn solver.Hint) {
		id, ok := h.ids[name]
		if !ok {
			protectedFatal(h.t, "hint %s is not in the constraint system", name)
		}
		c := new(int64)
		fired[name] = c
		opts = append(opts, solver.OverrideHint(id, func(m *big.Int, in, out []*big.Int) error {
			atomic.AddInt64(c, 1)
			if err := fn(m, in, out); err != nil {
				return err
			}
			for i := range out {
				out[i].Mod(out[i], nativeQ)
			}
			return nil
		}))
	}
	if h.has(hintCommitment) {
		override(hintCommitment, commitmentStandIn)
	}
	if h.has(hintRandomize) {
		override(hintRandomize, maskStandIn)
	}
	layer := map[string]solver.Hint{}
	if adv.layer {
		if h.has(hintLogderivCount) {
			layer[hintLogderivCount] = tolerantCount(&unmatched)
		}
		if h.has(hintPolyMv) {
			layer[hintPolyMv] = polyMvAdversary(polyMvTolerant, nil)
		}
		if h.has(hintDecompose) {
			mode := adv.decompose
			layer[hintDecompose] = func(_ *big.Int, in, out []*big.Int) error { return decomposeLimbs(mode, in, out) }
		}
		if h.has(hintToBytes) {
			layer[hintToBytes] = tolerantToBytes
		}
	}
	for name, fn := range adv.hints {
		layer[name] = fn
	}
	names := make([]string, 0, len(layer))
	for name := range layer {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		override(name, layer[name])
	}
	// the lookup blueprints, swapped in for this solve only
	var lookupCalls int64
	if adv.layer || adv.lookup != nil {
		saved := make([]constraint.Blueprint, len(h.lookups))
		for i, id := range h.lookups {
			saved[i] = h.r.Blueprints[id]
			h.r.Blueprints[id] = &lookupProxy{
				BlueprintLookupHint: saved[i].(*constraint.BlueprintLookupHint[constraint.U64]),
				table:               i, calls: &lookupCalls, oor: &oor, forge: adv.lookup,
			}
		}
		defer func() {
			for i, id := range h.lookups {
				h.r.Blueprints[id] = saved[i]
			}
		}()
	}
	var inverseCalls int64
	if adv.batchInverse != nil {
		saved := make([]constraint.Blueprint, len(h.inverses))
		for i, id := range h.inverses {
			saved[i] = h.r.Blueprints[id]
			h.r.Blueprints[id] = &batchInverseProxy{
				BlueprintBatchInverse: saved[i].(*constraint.BlueprintBatchInverse[constraint.U64]),
				calls:                 &inverseCalls, forge: adv.batchInverse,
			}
		}
		defer func() {
			for i, id := range h.inverses {
				h.r.Blueprints[id] = saved[i]
			}
		}()
	}
	start := time.Now()
	err = func() (err error) {
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("pool-solver-panic")
			}
		}()
		return h.r.IsSolved(w, opts...)
	}()
	elapsed := time.Since(start)
	calls := map[string]int64{}
	for name, c := range fired {
		calls[name] = atomic.LoadInt64(c)
	}
	if adv.layer || adv.lookup != nil {
		calls["lookup-blueprint"] = lookupCalls
	}
	if adv.batchInverse != nil {
		calls["batch-inverse-blueprint"] = inverseCalls
	}
	return classify(err, h.nbC), calls, unmatched, oor, elapsed
}

// writeResults writes the cases to the file named by env, if set.
func writeResults(t testing.TB, env string, v any) {
	path := os.Getenv(env)
	if path == "" {
		return
	}
	b, err := json.MarshalIndent(struct {
		ValuesSuppressed bool `json:"valuesSuppressed"`
	}{true}, "", "  ")
	if err != nil {
		protectedFatal(t, err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		protectedFatal(t, err)
	}
}
