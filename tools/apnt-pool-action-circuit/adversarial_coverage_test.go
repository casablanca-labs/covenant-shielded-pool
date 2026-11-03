package poolaction

import (
	"strings"
	"testing"
)

// TestHintCoverageCheck is the negative control for checkCoverage, which
// TestActionHintNegatives applies to the compiled inventory: on a synthetic
// inventory and case list, a complete one has no gap, and each kind of gap
// is reported.
func TestHintCoverageCheck(t *testing.T) {
	defer protectedPanic(t)
	inventoryWith := func(extraHint, extraBlueprint string) hintInventory {
		var inv hintInventory
		for _, n := range append(append([]string{}, attackedHints...), backendHints...) {
			inv.Hints = append(inv.Hints, hintCount{Name: n, Instructions: 1})
		}
		for _, b := range attackedBlueprints {
			inv.Blueprints = append(inv.Blueprints, blueprintCount{Type: b, Instructions: 1})
		}
		if extraHint != "" {
			inv.Hints = append(inv.Hints, hintCount{Name: extraHint, Instructions: 1})
		}
		if extraBlueprint != "" {
			inv.Blueprints = append(inv.Blueprints, blueprintCount{Type: extraBlueprint, Instructions: 1})
		}
		return inv
	}
	refused := func(target string) caseResult {
		return caseResult{Kind: "negative", Target: target, ForgedCalls: 1, Verdict: verdict{Got: gotConstraint}}
	}
	complete := func(skip string) []caseResult {
		var cs []caseResult
		for _, n := range append(append([]string{}, attackedHints...), attackedBlueprints...) {
			if n != skip {
				cs = append(cs, refused(n))
			}
		}
		return cs
	}
	if len(attackedHints) != 13 || len(backendHints) != 2 || len(attackedBlueprints) != 2 {
		protectedFatal(t, "lists: %d attacked hints, %d backend hints, %d blueprints; want 13, 2, 2", len(attackedHints), len(backendHints), len(attackedBlueprints))
	}
	for _, c := range []struct {
		name  string
		inv   hintInventory
		cases []caseResult
		want  string // "" = no gap
	}{
		{"complete", inventoryWith("", ""), complete(""), ""},
		{"an unknown hint id", inventoryWith("example.org/gadget.newHint", ""), complete(""), "unattacked hint id example.org/gadget.newHint"},
		{"an unknown solver blueprint", inventoryWith("", "*constraint.BlueprintNew"), complete(""), "unattacked solver blueprint *constraint.BlueprintNew"},
		{"an attacked hint without a negative", inventoryWith("", ""), complete(hintPartition), "no refused negative forges hint " + hintPartition},
		{"a blueprint without a negative", inventoryWith("", ""), complete(blueprintLookup), "no refused negative forges blueprint " + blueprintLookup},
		{"a negative that forged nothing", inventoryWith("", ""), append(complete(hintXor), caseResult{Kind: "negative", Target: hintXor, Verdict: verdict{Got: gotConstraint}}), "no refused negative forges hint " + hintXor},
		{"a satisfied negative", inventoryWith("", ""), append(complete(hintXor), caseResult{Kind: "negative", Target: hintXor, ForgedCalls: 1, Verdict: verdict{Got: gotSatisfied}}), "no refused negative forges hint " + hintXor},
	} {
		gaps := checkCoverage(c.inv, c.cases)
		switch {
		case c.want == "" && len(gaps) != 0:
			protectedError(t, "%s: unexpected gaps %v", c.name, gaps)
		case c.want != "" && (len(gaps) != 1 || !strings.Contains(gaps[0], c.want)):
			protectedError(t, "%s: gaps %v, want exactly %q", c.name, gaps, c.want)
		}
	}
}
