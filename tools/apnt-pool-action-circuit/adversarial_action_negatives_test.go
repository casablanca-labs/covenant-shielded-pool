package poolaction

import (
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/consensys/gnark/constraint/solver"
)

// TestActionHintNegatives runs the hint negatives on the action circuit
// (gnark v0.16.3), starting from host positives of the committed corpus, in
// two phases:
//
//   - production: the production circuit (registry entry 1 revision 3, R1CS
//     7c32a8f6…, ENG-454; revision 2's 25d3f54d… before pad16). A forged
//     hint that changes a computed value may be refused by the comparison of
//     that value with the record A, or by the gadget's own constraints,
//     whichever the solver reaches first.
//   - binding-ablated: a test-only compile without the five clauses that
//     compare computed values with A and without the comparison of A's hash
//     with the public input x (bindingClauses). A changed rk, nf, path root,
//     cm, packet or record hash is no longer compared with A or x, so the refusal
//     must come from gadget constraints (booleanity, recompositions, range
//     checks, lookup arguments, emulated deferred checks). This compile is
//     smaller than production by more than the five comparisons: SEC1c(R),
//     which only feeds the rk comparison, membership's IsZero(v), which only
//     gates the anchor comparison, and their deferred range-check work go
//     with them (4,949 constraints at a042b497… and at 25d3f54d…, 4,868 at
//     7c32a8f6…; ablationDelta checks that the
//     difference lies only there and records it). Every other gadget's
//     constraints and hint calls are identical in both compiles, the pad's
//     byte xors and the rcm hash included.
//
// Each negative is an adversary: some hint outputs (or the batch-inverse
// blueprint's answers) replaced by wrong-but-plausible values,
// including coordinated changes to several outputs of one call, the item-1
// forgery (another value mod p, the quotient and carries recomputed mod q)
// and changes to every call of a hint at once. Every negative must change
// the answer of at least one call (else it proves nothing) and be refused by
// an R1C. checkCoverage requires a refused negative for each of the 13
// attackable hint ids and both solver blueprints, and fails on an inventory
// id it does not know (backendHints lists the two it cannot attack). The adversary layer (tolerant
// countHint, polyMvHint and toBytes, exact DecomposeHint, tolerant lookups)
// keeps downstream hints from failing first. Controls show the harness
// reports acceptance: the honest positives, the adversary layer passing
// through, every hint overridden with gnark's own function, and non-honest
// outputs that are valid alternatives (the same statement).
//
// Per phase: one compile of the marked mirror (attribution, then released)
// and one of the circuit, then one single-task solve per case.
// POOL_ACTION_HINT_NEGATIVES=FILE.json writes every case.
func TestActionHintNegatives(t *testing.T) {
	t.Skip("requires protected action witnesses; not shipped")
	defer protectedPanic(t)
	E := loadEntries(t)
	rel1 := E["rel1-real-real-deposit-withdrawal"]
	dbl := E["alpha-equals-ask-rk-doubling"]
	dummy := E["dummy-dummy-deposit"] // zero values: several IsZero inputs are 0
	if rel1 == nil || dbl == nil || dummy == nil {
		protectedFatal(t, "corpus positives missing")
	}
	type phaseOut struct {
		Phase     string        `json:"phase"`
		Ablated   []Clause      `json:"ablated"`
		Inventory hintInventory `json:"inventory"`
		Segments  *segmentMap   `json:"attribution"`
		Coverage  []string      `json:"coverageGaps"`
		// for the binding-ablated phase: production minus this compile, per
		// segment that differs
		Delta []segmentDelta `json:"deltaFromProduction,omitempty"`
		Cases []caseResult   `json:"cases"`
	}
	var phases []phaseOut
	for _, ph := range []struct {
		name    string
		ablated []Clause
	}{{"production", nil}, {"binding-ablated", bindingClauses}} {
		inv, sm, cases := runHintNegatives(t, ph.name, ph.ablated, rel1, dbl, dummy)
		gaps := checkCoverage(inv, cases)
		for _, g := range gaps {
			protectedError(t, "%s: coverage: %s", ph.name, g)
		}
		protectedLog(t, "%s: coverage: %d attacked hint ids, %d backend hint ids, %d solver blueprints, %d gaps",
			ph.name, len(attackedHints), len(backendHints), len(attackedBlueprints), len(gaps))
		phases = append(phases, phaseOut{Phase: ph.name, Ablated: ph.ablated, Inventory: inv, Segments: sm, Coverage: gaps, Cases: cases})
		Release()
	}
	delta, problems := ablationDelta(phases[0].Segments, phases[1].Segments)
	phases[1].Delta = delta
	total := phases[0].Segments.Constraints - phases[1].Segments.Constraints
	protectedLog(t, "binding-ablated: %d fewer constraints than production", total)
	for _, d := range delta {
		protectedLog(t, "  %-32s constraints −%d, hint calls −%v, lookups −%d", d.Segment, d.R1Cs, d.Hints, d.Lookups)
	}
	for _, p := range problems {
		protectedError(t, "binding ablation: %s", p)
	}
	writeResults(t, "POOL_ACTION_HINT_NEGATIVES", phases)

	var accepted []string
	for _, ph := range phases {
		for _, c := range ph.Cases {
			if c.Kind == "negative" && c.Verdict.Got == gotSatisfied {
				accepted = append(accepted, ph.Phase+"/"+c.Case)
			}
			if !c.Pass {
				protectedError(t, "%s/%s (%s): expected %s, got %s (forged calls %d): %s %s", ph.Phase, c.Case, c.Kind, c.Expect, c.Verdict.Got, c.ForgedCalls, c.Verdict.Message, c.Note)
			}
		}
	}
	if len(accepted) > 0 {
		protectedError(t, "SATISFIED NEGATIVES (stop condition): %s", strings.Join(accepted, ", "))
	}
	if os.Getenv("POOL_ACTION_HINT_NEGATIVES") == "" {
		protectedLog(t, "set POOL_ACTION_HINT_NEGATIVES=FILE.json to write every case")
	}
}

func runHintNegatives(t *testing.T, phase string, ablated []Clause, rel1, dbl, dummy *CorpusEntry) (hintInventory, *segmentMap, []caseResult) {
	marked, names, err := compileMirror(true, ablated...)
	if err != nil {
		protectedFatal(t, err)
	}
	sm, err := buildSegmentMap(marked, names)
	if err != nil {
		protectedFatal(t, err)
	}
	marked = nil
	Release()

	ccs, err := Compile(ablated...)
	if err != nil {
		protectedFatal(t, err)
	}
	r := asR1CS(t, ccs)
	if fp := productionFingerprint(r); fp != sm.Fingerprint {
		protectedFatal(t, "%s: marked mirror does not match the compiled instruction sequence (%s vs %s)", phase, sm.Fingerprint, fp)
	}
	inv := inventory(r)
	invCount := map[string]int64{}
	for _, h := range inv.Hints {
		invCount[h.Name] = int64(h.Instructions)
	}
	h := newHintHarness(t, r)
	order := solveOrder(r)
	segOf := func(instr uint32) string { return sm.Names[sm.instrSeg[instr]] }
	firstIn := func(hint, prefix string) int64 {
		for k, ins := range order[hint] {
			if strings.HasPrefix(segOf(ins), prefix) {
				return int64(k)
			}
		}
		protectedFatal(t, "%s: no %s call in %s*", phase, hint, prefix)
		return -1
	}
	callSeg := func(hint string, k int64) string {
		if k < 0 || int(k) >= len(order[hint]) {
			return "?"
		}
		return segOf(order[hint][k])
	}
	for _, name := range []string{hintCombRecode, hintCombLambda, hintUnifiedSlope, hintInvZero, hintMul, hintPolyMv} {
		n := map[string]int{}
		for _, ins := range order[name] {
			n[segOf(ins)]++
		}
		keys := make([]string, 0, len(n))
		for k := range n {
			keys = append(keys, fmt.Sprintf("%s×%d", k, n[k]))
		}
		sort.Strings(keys)
		protectedLog(t, "%s: calls of %s: %s", phase, name[strings.LastIndex(name, ".")+1:], strings.Join(keys, ", "))
	}
	remUsed, err := mulRemainderUsed(r, order[hintMul])
	if err != nil {
		protectedFatal(t, err)
	}
	var firstReduce int64 = -1
	nbReduce := 0
	for k, u := range remUsed {
		if u {
			nbReduce++
			if firstReduce < 0 {
				firstReduce = int64(k)
			}
		}
	}
	reduceCalls := func(k int64) bool { return remUsed[k] }
	checkZeroCalls := func(k int64) bool { return !remUsed[k] }
	protectedLog(t, "%s: mulHint calls whose remainder is used (reductions): %d of %d; the rest are checkZero", phase, nbReduce, len(remUsed))

	assign := func(e *CorpusEntry) *ActionCircuit {
		a, err := e.Assignment()
		if err != nil {
			protectedFatal(t, err)
		}
		return a
	}
	honest := func(name string) solver.Hint {
		f, err := honestHint(name)
		if err != nil {
			protectedFatal(t, err)
		}
		return f
	}

	var results []caseResult
	run := func(c caseResult, a *ActionCircuit, adv adversary, forged *int64) {
		v, fired, unm, oor, dt := h.solve(a, adv)
		c.Phase = phase
		c.Verdict, c.Fired, c.Unmatched, c.LookupOOR, c.Seconds = v, fired, unm, oor, dt.Seconds()
		c.Segment = sm.segmentOfCID(v.CID)
		if forged != nil {
			c.ForgedCalls = *forged
		}
		c.Pass = c.Expect == "" || v.Got == c.Expect
		if (c.Kind == "negative" || c.Kind == "alternative-witness") && c.ForgedCalls == 0 {
			c.Pass = false
			c.Note = strings.TrimSpace(c.Note + " VACUOUS: the adversary changed no call's answer")
		}
		results = append(results, c)
		protectedLog(t, "%-15s %-4s %-44s %-21s forgedCalls=%-6d cid=%-8d seg=%-46s %.1fs %s %s", phase, map[bool]string{true: "ok", false: "FAIL"}[c.Pass], c.Case, v.Got, c.ForgedCalls, v.CID, c.Segment, c.Seconds, clip(v.Message, 80), c.Note)
	}
	neg := func(family, target, name, forged string) caseResult {
		return caseResult{Case: name, Family: family, Kind: "negative", Positive: rel1.Name, Target: target, Forged: forged, Expect: gotConstraint}
	}
	layer := func(hints map[string]solver.Hint) adversary { return adversary{hints: hints, layer: true} }
	// wrapInexact adds the item-1 forgery to every emulated deferred check a
	// forged value leaves inexact: polyMv asserted-zero evaluations and
	// mulHint checkZero calls get K ≡ L/p (mod q) and carries mod q.
	wrapInexact := func(hints map[string]solver.Hint, st *mulStats, pst *polyMvStats, wrapped *int64) map[string]solver.Hint {
		pst.alsoWrapped = wrapped
		hints[hintPolyMv] = polyMvAdversaryStats(polyMvWrapInexact, nil, pst)
		hints[hintMul] = mulAdversaryStats(mulWrapInexact, checkZeroCalls, st, wrapped)
		return hints
	}
	wrapNote := func(st *mulStats, pst *polyMvStats) string {
		return fmt.Sprintf("polyMv asserted-zero inexact %d, wrapped %d (quotient over-wide %d), impossible %d; checkZero inexact %d, wrapped %d (quotient over-wide %d), impossible %d",
			pst.inexact, pst.wrapped+pst.wideQuotient, pst.wideQuotient, pst.wrapImpossible, st.inexact, st.forged, st.wideQuotient, st.wrapImpossible)
	}

	// ---------------- controls ----------------

	run(caseResult{Case: "control.honest", Family: "controls", Kind: "control", Positive: rel1.Name,
		Forged: "nothing (deterministic commitment and mask only)", Expect: gotSatisfied}, assign(rel1), adversary{}, nil)
	run(caseResult{Case: "control.adversary-layer-pass-through", Family: "controls", Kind: "control", Positive: rel1.Name,
		Forged: "nothing: tolerant countHint, polyMvHint and toBytes, exact DecomposeHint, tolerant lookups", Expect: gotSatisfied},
		assign(rel1), adversary{layer: true}, nil)
	for _, name := range []string{hintLogderivCount, hintPolyMv, hintDecompose, hintToBytes} {
		if got := results[len(results)-1].Fired[name]; got != invCount[name] {
			protectedError(t, "%s: firing control: %s fired %d times, inventory has %d calls", phase, name, got, invCount[name])
		}
	}
	all := map[string]solver.Hint{}
	for name := range invCount {
		if f, err := honestHint(name); err == nil {
			all[name] = f
		}
	}
	run(caseResult{Case: "control.every-hint-pass-through", Family: "controls", Kind: "control", Positive: rel1.Name,
		Forged: "nothing: every hint the test can import overridden by gnark's own function (countHint, internal to gnark, by the tolerant equivalent)", Expect: gotSatisfied}, assign(rel1), layer(all), nil)
	for name := range all {
		if got := results[len(results)-1].Fired[name]; got != invCount[name] {
			protectedError(t, "%s: firing control: %s fired %d times, inventory has %d calls", phase, name, got, invCount[name])
		}
	}
	// Revision 3 has no lookup blueprint (revision 2's were the AES tables), so
	// the proxy must answer no query; with one it would have to answer some.
	if got := results[len(results)-1].Fired["lookup-blueprint"]; (got == 0) != (len(h.lookups) == 0) {
		protectedError(t, "%s: firing control: the lookup proxy answered %d queries over %d lookup blueprints", phase, got, len(h.lookups))
	}
	run(caseResult{Case: "control.honest-doubling-positive", Family: "controls", Kind: "control", Positive: dbl.Name,
		Forged: "nothing", Expect: gotSatisfied}, assign(dbl), adversary{}, nil)
	run(caseResult{Case: "control.honest-dummy-positive", Family: "controls", Kind: "control", Positive: dummy.Name,
		Forged: "nothing", Expect: gotSatisfied}, assign(dummy), adversary{}, nil)

	// ---------------- ScalarMulBase: comb recoding ----------------

	fam := "comb-recode"
	{
		forged := new(int64)
		run(caseResult{Case: "recode.alternative-same-scalar", Family: fam, Kind: "alternative-witness", Positive: rel1.Name,
			Forged: "call 0: 2c + b0 = s + 2^n − n_G, a second recoding of the same scalar ([s]G unchanged)", Expect: gotSatisfied},
			assign(rel1), layer(map[string]solver.Hint{hintCombRecode: forgeInstead(honest(hintCombRecode), callSet(0), forged, recodeHint(recodeAlternative))}), forged)
		if *forged != 1 {
			protectedError(t, "%s: recode alternative forged %d calls, want 1", phase, *forged)
		}
	}
	for _, x := range []struct {
		name, forged string
		kind         recodeForgery
		target       func(int64) bool
		wrap         bool
	}{
		{"recode.b0-flip", "call 0 (" + callSeg(hintCombRecode, 0) + "): parity bit flipped, digits kept", recodeB0Flip, callSet(0), false},
		{"recode.scalar-plus-one", "call 0: all 257 outputs a consistent recoding of α + 1", recodePlusOne, callSet(0), false},
		{"recode.scalar-plus-one-carries-mod-q", "call 0: the recoding of α + 1; every inexact deferred check answered with K ≡ L/p (mod q), carries mod q", recodePlusOne, callSet(0), true},
		{"recode.scalar-negated", "call 0: all 257 outputs a consistent recoding of n_G − α (rk's y parity flips)", recodeNegated, callSet(0), false},
		{"recode.scalar-negated-carries-mod-q", "call 0: the recoding of n_G − α; carries mod q as above", recodeNegated, callSet(0), true},
		{"recode.non-boolean-digit-pair", "call 0: digits 0,1 → 2,0 at one place (2c + b0 kept)", recodeNonBoolean, callSet(0), false},
		{"recode.scalar-negated-every-call", "both calls: recoding of n_G − α", recodeNegated, everyCall, false},
	} {
		forged := new(int64)
		hints := map[string]solver.Hint{hintCombRecode: forgeInstead(honest(hintCombRecode), x.target, forged, recodeHint(x.kind))}
		st, pst := &mulStats{}, &polyMvStats{}
		c := neg(fam, hintCombRecode, x.name, x.forged)
		if x.wrap {
			hints = wrapInexact(hints, st, pst, new(int64))
		}
		run(c, assign(rel1), layer(hints), forged)
		if x.wrap {
			results[len(results)-1].Note = wrapNote(st, pst)
		}
	}

	// ---------------- ScalarMulBase: comb chain slopes ----------------

	fam = "comb-chain-lambda"
	mid := int64(len(order[hintCombLambda]) / 4)
	for _, x := range []struct {
		name, forged string
		kind         slopeForgery
		target       func(int64) bool
		wrap         bool
	}{
		{"lambda.plus-one", "call 0 (" + callSeg(hintCombLambda, 0) + "): λ + 1", slopePlusOne, callSet(0), false},
		{"lambda.negated", fmt.Sprintf("call %d (%s): −λ", mid, callSeg(hintCombLambda, mid)), slopeNegated, callSet(mid), false},
		{"lambda.chord-to-minus-T-every-call", "every call: the chord to −T, from each call's own (forged) inputs", slopeOther, everyCall, false},
		{"lambda.plus-one-every-call", "every call: λ + 1", slopePlusOne, everyCall, false},
		{"lambda.plus-q-carries-mod-q", "call 0: λ ± q (another value mod p); every inexact deferred check answered with K ≡ L/p (mod q), carries mod q", slopePlusQ, callSet(0), true},
		{"lambda.plus-q-carries-mod-q-every-call", "every call: λ ± q; carries mod q as above", slopePlusQ, everyCall, true},
	} {
		forged := new(int64)
		hints := map[string]solver.Hint{hintCombLambda: forgeInstead(honest(hintCombLambda), x.target, forged, combLambdaHint(x.kind))}
		st, pst := &mulStats{}, &polyMvStats{}
		if x.wrap {
			hints = wrapInexact(hints, st, pst, new(int64))
		}
		run(neg(fam, hintCombLambda, x.name, x.forged), assign(rel1), layer(hints), forged)
		if x.wrap {
			results[len(results)-1].Note = wrapNote(st, pst)
		}
	}

	// ---------------- AddUnified: unified slope ----------------

	fam = "unified-slope"
	for _, x := range []struct {
		name, forged string
		kind         slopeForgery
		target       func(int64) bool
		wrap         bool
		positive     *CorpusEntry
	}{
		{"slope.plus-one", "call 0 (" + callSeg(hintUnifiedSlope, 0) + "): λ + 1", slopePlusOne, callSet(0), false, rel1},
		{"slope.tangent-for-chord", "call 0: the tangent slope 3x1²/2y1 where the chord is due", slopeOther, callSet(0), false, rel1},
		{"slope.plus-q-carries-mod-q", "call 0: λ ± q; every inexact deferred check answered with carries mod q", slopePlusQ, callSet(0), true, rel1},
		{"slope.negated-every-call", "every call: −λ", slopeNegated, everyCall, false, rel1},
		{"slope.doubling-plus-one", "every call of the doubling positive: λ + 1 (its in0 add-unified call takes the tangent)", slopePlusOne, everyCall, false, dbl},
	} {
		forged := new(int64)
		hints := map[string]solver.Hint{hintUnifiedSlope: forgeInstead(honest(hintUnifiedSlope), x.target, forged, unifiedSlopeForge(x.kind, honest(hintUnifiedSlope)))}
		st, pst := &mulStats{}, &polyMvStats{}
		if x.wrap {
			hints = wrapInexact(hints, st, pst, new(int64))
		}
		c := neg(fam, hintUnifiedSlope, x.name, x.forged)
		c.Positive = x.positive.Name
		run(c, assign(x.positive), layer(hints), forged)
		if x.wrap {
			results[len(results)-1].Note = wrapNote(st, pst)
		}
	}

	// ---------------- api.IsZero ----------------

	fam = "inv-zero"
	for _, x := range []struct {
		name, forged string
		kind         invZeroForgery
		target       func(int64) bool
		kindOf       string
		expect       string
		positive     *CorpusEntry
	}{
		{"invzero.claims-zero", "first call with a ≠ 0: m = 0, so IsZero would read 1", invZeroClaimsZero, callSet(0), "negative", gotConstraint, rel1},
		{"invzero.wrong-inverse", "first call with a ≠ 0: m = 2/a", invZeroWrongInverse, callSet(0), "negative", gotConstraint, rel1},
		{"invzero.claims-zero-every-nonzero-call", "every call with a ≠ 0: m = 0", invZeroClaimsZero, everyCall, "negative", gotConstraint, rel1},
		{"invzero.claims-zero-dummy-positive", "the zero-value positive, every call with a ≠ 0: m = 0", invZeroClaimsZero, everyCall, "negative", gotConstraint, dummy},
		{"invzero.free-witness-at-zero", "the zero-value positive, every call with a = 0: m = 1 (IsZero(0) = 1 − 0·m whatever m is)", invZeroFreeWitness, everyCall, "alternative-witness", gotSatisfied, dummy},
	} {
		forged, eligible := new(int64), new(int64)
		c := neg(fam, hintInvZero, x.name, x.forged)
		c.Kind, c.Expect, c.Positive = x.kindOf, x.expect, x.positive.Name
		run(c, assign(x.positive), layer(map[string]solver.Hint{hintInvZero: invZeroHint(x.kind, x.target, forged, eligible)}), forged)
		results[len(results)-1].Note = fmt.Sprintf("%d eligible calls reached", *eligible)
	}

	// ---------------- emulated multiplication and evaluation ----------------

	fam = "emulated-mul"
	for _, x := range []struct {
		name, forged string
		mode         mulMode
		target       func(int64) bool
	}{
		{"mul.reduce-remainder-plus-one", fmt.Sprintf("first reduction (call %d, %s): r + 1, honest carries", firstReduce, callSeg(hintMul, firstReduce)), mulRemPlusOne, callSet(firstReduce)},
		{"mul.reduce-carry-wrap", fmt.Sprintf("first reduction (call %d): r ± q (≢ r mod p), quotient kept, carries recomputed mod q (R-333's forgery)", firstReduce), mulCarryWrap, callSet(firstReduce)},
		{"mul.reduce-carry-wrap-every-call", fmt.Sprintf("every reduction (%d calls): r ± q, carries mod q", nbReduce), mulCarryWrap, reduceCalls},
	} {
		forged := new(int64)
		run(neg(fam, hintMul, x.name, x.forged), assign(rel1), layer(map[string]solver.Hint{hintMul: mulAdversary(x.mode, x.target, forged)}), forged)
	}
	fam = "emulated-polymv"
	for _, x := range []struct {
		name, forged string
		mode         polyMvMode
		target       func(int64) bool
	}{
		{"polymv.eval-remainder-plus-one", "first Eval call: r + 1, honest carries", polyMvEvalRemPlusOne, callSet(0)},
		{"polymv.eval-carry-wrap", "first Eval call: r ± q, quotient kept, carries mod q", polyMvEvalRemWrap, callSet(0)},
		{"polymv.eval-carry-wrap-every-call", "every Eval call: r ± q, carries mod q", polyMvEvalRemWrap, everyCall},
	} {
		st := &polyMvStats{}
		run(neg(fam, hintPolyMv, x.name, x.forged), assign(rel1), layer(map[string]solver.Hint{hintPolyMv: polyMvAdversaryStats(x.mode, x.target, st)}), &st.forged)
		results[len(results)-1].Note = fmt.Sprintf("Eval calls %d, asserted-zero calls %d", st.evalCalls, st.assertCalls)
	}
	// the delegated-prover invalid-curve theft (parity's circuit-only
	// negative: off-curve y', rk a key the delegate holds). Its only false
	// statement is ak's curve equation; the strong variant answers every
	// deferred check it leaves inexact with the item-1 forgery.
	{
		th := buildInvalidCurveTheft(t, rel1)
		st, pst := &mulStats{}, &polyMvStats{}
		c := neg(fam, hintMul, "theft.invalid-curve-carries-mod-q", "parity's invalid-curve theft witness (off-curve y', rk the delegate's key); every inexact checkZero and asserted-zero evaluation answered with K ≡ L/p (mod q), carries mod q")
		c.Positive = rel1.Name + " (invalid-curve theft)"
		wrapped := new(int64)
		run(c, th.assignment, layer(wrapInexact(map[string]solver.Hint{}, st, pst, wrapped)), wrapped)
		results[len(results)-1].Note = wrapNote(st, pst)
		c = caseResult{Case: "theft.invalid-curve-tolerant", Family: fam, Kind: "statement-negative", Positive: rel1.Name + " (invalid-curve theft)",
			Forged: "the same witness under the adversary layer only: no hint output forged", Expect: gotConstraint}
		run(c, th.assignment, adversary{layer: true}, nil)
	}

	// ---------------- range checks ----------------

	fam = "range-check"
	for _, x := range []struct {
		name, forged string
		kind         decomposeForgery
		target       func(int64) bool
	}{
		{"decompose.alias-limb", "first multi-limb decomposition: l0 + 2^k, l1 − 1 (same value, l0 outside the table)", decomposeAlias, callSet(0)},
		{"decompose.alias-limb-every-call", "every multi-limb decomposition: l0 + 2^k, l1 − 1", decomposeAlias, everyCall},
		{"decompose.plus-one", "first decomposition: l0 + 1", decomposePlusOne, callSet(0)},
	} {
		forged := new(int64)
		run(neg(fam, hintDecompose, x.name, x.forged), assign(rel1), layer(map[string]solver.Hint{hintDecompose: decomposeForge(x.kind, x.target, forged)}), forged)
	}
	malleated := func() *ActionCircuit {
		a := assign(rel1)
		malleate(t, a.Record[OffDeposit:OffDeposit+8])
		return a
	}
	{
		pos := rel1.Name + " (deposit bytes malleated)"
		run(caseResult{Case: "non-byte-record-element.gnark-hints", Family: fam, Kind: "observation", Positive: pos,
			Forged: "parity's malleated deposit bytes (a record 'byte' ≥ 256) with gnark's own hints: which check refuses"}, malleated(), adversary{}, nil)
		run(caseResult{Case: "non-byte-record-element.tolerant-count", Family: fam, Kind: "statement-negative", Positive: pos,
			Forged: "the same witness, tolerant countHint, gnark's DecomposeHint", Expect: gotConstraint}, malleated(), adversary{layer: true, decompose: decomposeNative}, nil)
		run(caseResult{Case: "non-byte-record-element.exact-decompose", Family: fam, Kind: "statement-negative", Positive: pos,
			Forged: "the same witness, exact DecomposeHint (recomposition holds) and tolerant countHint", Expect: gotConstraint}, malleated(), adversary{layer: true}, nil)
	}

	// ---------------- uints byte operations (advisory item 8, ENG-370) ----------------

	fam = "byte-ops"
	xorMem := firstIn(hintXor, "in0.membership.path-sha")
	andMem := firstIn(hintAnd, "in0.membership.path-sha")
	xorPad := firstIn(hintXor, "out0.packet.pad-xor")
	for _, x := range []struct {
		name, forged string
		hint         string
		mutate       func(in, out []*big.Int) error
		target       func(int64) bool
		decompose    decomposeMode
	}{
		{"xor.flip-result", fmt.Sprintf("xor call %d (%s): z ⊕ 1", xorMem, callSeg(hintXor, xorMem)), hintXor, byteOpMutate(byteFlip, xorOp), callSet(xorMem), decomposeExact},
		{"xor.alias-result.gnark-decompose", fmt.Sprintf("xor call %d: z' = f(x, y±1) ± 2^-8, another table row's key (the advisory's Xor(1,0) = 1/256); gnark's DecomposeHint", xorMem), hintXor, byteOpMutate(byteAlias, xorOp), callSet(xorMem), decomposeNative},
		{"xor.alias-result.exact-decompose", fmt.Sprintf("xor call %d: the alias, with an exact DecomposeHint for its range check", xorMem), hintXor, byteOpMutate(byteAlias, xorOp), callSet(xorMem), decomposeExact},
		{"and.alias-result.exact-decompose", fmt.Sprintf("and call %d (%s): the alias", andMem, callSeg(hintAnd, andMem)), hintAnd, byteOpMutate(byteAlias, andOp), callSet(andMem), decomposeExact},
		{"xor.alias-result-in-pad.exact-decompose", fmt.Sprintf("xor call %d (%s): the alias in the packet's pad xor", xorPad, callSeg(hintXor, xorPad)), hintXor, byteOpMutate(byteAlias, xorOp), callSet(xorPad), decomposeExact},
		{"xor.flip-result-every-call", "every xor call: z ⊕ 1", hintXor, byteOpMutate(byteFlip, xorOp), everyCall, decomposeExact},
		{"xor.alias-result-every-call", "every xor call: the alias", hintXor, byteOpMutate(byteAlias, xorOp), everyCall, decomposeExact},
	} {
		forged := new(int64)
		adv := layer(map[string]solver.Hint{x.hint: forgeAfter(honest(x.hint), x.target, forged, x.mutate)})
		adv.decompose = x.decompose
		run(neg(fam, x.hint, x.name, x.forged), assign(rel1), adv, forged)
	}

	// ---------------- SHA-256 word arithmetic: partition, toBytes; bits ----------------

	fam = "bit-decompositions"
	partMem := firstIn(hintPartition, "in0.membership.path-sha")
	for _, x := range []struct {
		name, forged string
		hint         string
		mutate       func(in, out []*big.Int) error
		target       func(int64) bool
	}{
		{"partition.shift", fmt.Sprintf("partition call %d (%s): upper + 1, lower − 2^split", partMem, callSeg(hintPartition, partMem)), hintPartition, partitionShift, callSet(partMem)},
		{"partition.shift-every-call", "every partition call: upper + 1, lower − 2^split", hintPartition, partitionShift, everyCall},
		{"tobytes.carry", "toBytes call 0 (" + callSeg(hintToBytes, 0) + "): byte0 + 256, byte1 − 1", hintToBytes, toBytesCarry, callSet(0)},
		{"tobytes.carry-every-call", "every toBytes call: byte0 + 256, byte1 − 1", hintToBytes, toBytesCarry, everyCall},
		{"nbits.flip", "nBits call 0 (" + callSeg(hintNBits, 0) + "): bit 0 flipped", hintNBits, nBitsFlip, callSet(0)},
		{"nbits.non-boolean-pair", "nBits call 0: bits 0,1 → 2,0 at one place (value kept)", hintNBits, nBitsNonBoolean, callSet(0)},
		{"nbits.non-boolean-pair-every-call", "every nBits call: bits 0,1 → 2,0 at one place", hintNBits, nBitsNonBoolean, everyCall},
	} {
		forged := new(int64)
		run(neg(fam, x.hint, x.name, x.forged), assign(rel1), layer(map[string]solver.Hint{x.hint: forgeAfter(honest(x.hint), x.target, forged, x.mutate)}), forged)
	}

	// ---------------- lookup arguments ----------------

	fam = "lookup-arguments"
	for k := int64(0); k < invCount[hintLogderivCount]; k++ {
		forged, unmatched := new(int64), new(int64)
		run(neg(fam, hintLogderivCount, fmt.Sprintf("count.shift-multiplicity.call-%d", k), fmt.Sprintf("countHint call %d: one multiplicity moved to the next table row", k)),
			assign(rel1), layer(map[string]solver.Hint{hintLogderivCount: countShift(callSet(k), forged, unmatched)}), forged)
	}
	// Revision 2's AES S-box and xtime lookup blueprints went with the AES-GCM
	// packet; revision 3 has no lookup blueprint to forge. The inventory is
	// the authority: checkCoverage flags any lookup blueprint that reappears.
	if len(h.lookups) != 0 {
		protectedError(t, "%s: %d lookup blueprints in revision 3's inventory, none expected", phase, len(h.lookups))
	}
	// the batch-inverse blueprint (not a hint): a wrong inverse
	for _, x := range []struct {
		name, forged string
		every        bool
	}{
		{"batch-inverse.wrong-output", "the first batch inverse in solve order, output 0: 2/x", false},
		{"batch-inverse.wrong-every-output", "the first batch inverse in solve order, every output: 2/x", true},
	} {
		x := x
		forged := new(int64)
		forge := func(call int64, i int, inv *big.Int) *big.Int {
			if call != 0 || (i != 0 && !x.every) || inv.Sign() == 0 {
				return nil
			}
			*forged++
			return new(big.Int).Lsh(inv, 1)
		}
		run(neg(fam, blueprintBatchInv, x.name, x.forged), assign(rel1), adversary{layer: true, batchInverse: forge}, forged)
	}
	return inv, sm, results
}

// segmentDelta is how one attribution segment of the production circuit
// exceeds the binding-ablated compile.
type segmentDelta struct {
	Segment string         `json:"segment"`
	R1Cs    int            `json:"constraints"`
	Hints   map[string]int `json:"hintCalls,omitempty"`
	Lookups int            `json:"lookups,omitempty"`
}

// elidedByBindingAblation names the segments the binding clauses own: the
// five comparisons, SEC1c(R) (computed only for the rk comparison) and
// membership's IsZero(v) (in the membership.equal segment), plus the deferred
// block, which holds their range checks and emulated checks.
func elidedByBindingAblation(seg string) bool {
	for _, suffix := range []string{".rk.sec1c", ".rk.equal", ".nf.equal", ".membership.equal", ".cm.equal", ".packet.equal"} {
		if strings.HasSuffix(seg, suffix) {
			return true
		}
	}
	return seg == "deferred" || seg == "record-hash.equal"
}

// ablationDelta compares the two phases' attributions. Every segment outside
// the binding clauses must have identical constraints, hint calls and
// lookups; the elided segments other than the deferred block must be empty in
// the ablated compile; and the deferred block may lose only the range-check
// decompositions whose value SEC1c(R) computed.
func ablationDelta(prod, abl *segmentMap) ([]segmentDelta, []string) {
	var deltas []segmentDelta
	var problems []string
	if strings.Join(prod.Names, "|") != strings.Join(abl.Names, "|") {
		return nil, []string{"the two compiles have different segment lists"}
	}
	for _, seg := range prod.Names {
		d := segmentDelta{Segment: seg, R1Cs: prod.R1Cs[seg] - abl.R1Cs[seg], Hints: map[string]int{}, Lookups: prod.Lookups[seg] - abl.Lookups[seg]}
		for name, n := range prod.Hints[seg] {
			if k := n - abl.Hints[seg][name]; k != 0 {
				d.Hints[name[strings.LastIndex(name, "/")+1:]] = k
			}
		}
		for name := range abl.Hints[seg] {
			if _, ok := prod.Hints[seg][name]; !ok {
				d.Hints[name[strings.LastIndex(name, "/")+1:]] = -abl.Hints[seg][name]
			}
		}
		if d.R1Cs == 0 && len(d.Hints) == 0 && d.Lookups == 0 {
			continue
		}
		deltas = append(deltas, d)
		if !elidedByBindingAblation(seg) {
			problems = append(problems, fmt.Sprintf("segment %s differs outside the binding clauses: %+v", seg, d))
		}
		if seg != "deferred" && (abl.R1Cs[seg] != 0 || len(abl.Hints[seg]) != 0 || abl.Lookups[seg] != 0) {
			problems = append(problems, fmt.Sprintf("elided segment %s is not empty in the ablated compile", seg))
		}
	}
	// the deferred decompositions lost are exactly those SEC1c(R) requested
	sec1c := 0
	for key, n := range prod.Decompose {
		if strings.Contains(key, ".rk.sec1c|") {
			sec1c += n
		}
	}
	lost := 0
	for _, d := range deltas {
		if d.Segment == "deferred" {
			lost = d.Hints["rangecheck.DecomposeHint"]
		}
	}
	if lost != sec1c {
		problems = append(problems, fmt.Sprintf("deferred block lost %d range-check decompositions, SEC1c(R) requested %d", lost, sec1c))
	}
	return deltas, problems
}
