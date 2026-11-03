package walletresources

import (
	"math"
	"testing"
)

func TestResourcePolicyBoundaries(t *testing.T) {
	const T, R, H, B = minimumTotalBytes, requiredBytes, headroomBytes, minimumRemainingBytes
	base := resourceState{T, B, 100, 7, ""}
	lowTotal := resourceState{T - 1, B, 100, 7, ""}
	shortBudget := resourceState{T, B - 1, 100, 7, ""}
	zero := resourceState{}
	rows := []struct {
		name   string
		before resourceState
		phase  resourcePhase
		sample resourceSample
		want   code
		after  resourceState
	}{
		{"initial-equality", zero, phaseInitial, resourceSample{T, R, 0, 100, 7, pressureNormal}, "", base},
		{"initial-total-low", zero, phaseInitial, resourceSample{T - 1, R, 0, 100, 7, pressureNormal}, codeMemory, zero},
		{"initial-available-low", zero, phaseInitial, resourceSample{T, R - 1, 0, 100, 7, pressureNormal}, codeMemory, zero},
		{"final-equality", base, phaseFinal, resourceSample{T, R, 0, 100, 7, pressureNormal}, "", base},
		{"final-swap-decrease", base, phaseFinal, resourceSample{T, R, 0, 99, 7, pressureNormal}, "", base},
		{"running-swap-decrease", base, phaseRunning, resourceSample{T, H, B, 0, 7, pressureNormal}, "", base},
		{"final-total-low", lowTotal, phaseFinal, resourceSample{T - 1, R, 0, 100, 7, pressureNormal}, codeMemory, lowTotal},
		{"final-available-low", base, phaseFinal, resourceSample{T, R - 1, 0, 100, 7, pressureNormal}, codeMemory, base},
		{"final-remaining-low", shortBudget, phaseFinal, resourceSample{T, R, 0, 100, 7, pressureNormal}, codeMemory, shortBudget},
		{"final-remaining-zero", base, phaseFinal, resourceSample{T, R, B + 1, 100, 7, pressureNormal}, codeMemory, base},
		{"running-equality", base, phaseRunning, resourceSample{T, H, B, 100, 7, pressureNormal}, "", base},
		{"running-budget-high", base, phaseRunning, resourceSample{T, H, B + 1, 100, 7, pressureNormal}, codeBudget, base},
		{"running-headroom-low", base, phaseRunning, resourceSample{T, H - 1, 0, 100, 7, pressureNormal}, codeHeadroom, base},
		{"running-zero-available", base, phaseRunning, resourceSample{T, 0, 0, 100, 7, pressureNormal}, codeHeadroom, base},
		{"owned-peak-consumption", base, phaseRunning, resourceSample{T, R - peakBytes, peakBytes, 100, 7, pressureNormal}, "", base},
		{"initial-warning", zero, phaseInitial, resourceSample{T, R, 0, 100, 7, pressureWarning}, codePressure, zero},
		{"initial-critical", zero, phaseInitial, resourceSample{T, R, 0, 100, 7, pressureCritical}, codePressure, zero},
		{"final-warning", base, phaseFinal, resourceSample{T, R, 0, 100, 7, pressureWarning}, codePressure, base},
		{"final-critical", base, phaseFinal, resourceSample{T, R, 0, 100, 7, pressureCritical}, codePressure, base},
		{"running-warning", base, phaseRunning, resourceSample{T, H, B, 100, 7, pressureWarning}, codePressure, base},
		{"running-critical", base, phaseRunning, resourceSample{T, H, B, 100, 7, pressureCritical}, codePressure, base},
		{"initial-unknown-pressure", zero, phaseInitial, resourceSample{T, R, 0, 100, 7, 0}, codeSampleInvalid, zero},
		{"final-unknown-pressure", base, phaseFinal, resourceSample{T, R, 0, 100, 7, 4}, codeSampleInvalid, base},
		{"running-unknown-pressure", base, phaseRunning, resourceSample{T, H, B, 100, 7, 255}, codeSampleInvalid, base},
		{"initial-zero-total", zero, phaseInitial, resourceSample{0, 0, H, 0, 0, pressureNormal}, codeSampleInvalid, zero},
		{"initial-available-over-total", zero, phaseInitial, resourceSample{T, T + 1, 0, 0, 0, pressureNormal}, codeSampleInvalid, zero},
		{"final-total-mutated", base, phaseFinal, resourceSample{T + 1, R, 0, 100, 7, pressureNormal}, codeSampleInvalid, base},
		{"running-total-mutated", base, phaseRunning, resourceSample{T + 1, H, B, 100, 7, pressureNormal}, codeSampleInvalid, base},
		{"final-available-over-total", base, phaseFinal, resourceSample{T, T + 1, 0, 100, 7, pressureNormal}, codeSampleInvalid, base},
		{"running-available-over-total", base, phaseRunning, resourceSample{T, T + 1, 0, 100, 7, pressureNormal}, codeSampleInvalid, base},
		{"initial-add-overflow", zero, phaseInitial, resourceSample{T, R, math.MaxUint64, 0, 0, pressureNormal}, codeSampleInvalid, zero},
		{"initial-sub-underflow", zero, phaseInitial, resourceSample{T, 0, 0, 0, 0, pressureNormal}, codeSampleInvalid, zero},
		{"initial-max-valid", zero, phaseInitial, resourceSample{T, R, math.MaxUint64 - R, 100, 7, pressureNormal}, "", resourceState{T, math.MaxUint64 - H, 100, 7, ""}},
		{"final-add-overflow", base, phaseFinal, resourceSample{T, R, math.MaxUint64, 100, 7, pressureNormal}, codeSampleInvalid, base},
		{"running-add-overflow", base, phaseRunning, resourceSample{T, H + 1, math.MaxUint64, 100, 7, pressureNormal}, codeSampleInvalid, base},
		{"final-swap-one", base, phaseFinal, resourceSample{T, R, 0, 101, 7, pressureNormal}, codeSwapGrowth, base},
		{"running-swap-one", base, phaseRunning, resourceSample{T, H, B, 101, 7, pressureNormal}, codeSwapGrowth, base},
		{"final-swapouts-flat-used", base, phaseFinal, resourceSample{T, R, 0, 100, 8, pressureNormal}, codeSwapGrowth, base},
		{"running-swapouts-flat-used", base, phaseRunning, resourceSample{T, H, B, 100, 8, pressureNormal}, codeSwapGrowth, base},
		{"final-counter-rollback", base, phaseFinal, resourceSample{T, R, 0, 100, 6, pressureNormal}, codeSampleInvalid, base},
		{"running-counter-rollback", base, phaseRunning, resourceSample{T, H, B, 100, 6, pressureNormal}, codeSampleInvalid, base},
		{"invalid-before-pressure", base, phaseRunning, resourceSample{T, H, B, 101, 6, pressureWarning}, codeSampleInvalid, base},
		{"overflow-before-pressure", base, phaseFinal, resourceSample{T, R, math.MaxUint64, 101, 7, pressureWarning}, codeSampleInvalid, base},
		{"pressure-before-swap", base, phaseFinal, resourceSample{T, R - 1, 0, 101, 7, pressureCritical}, codePressure, base},
		{"swap-before-memory", base, phaseFinal, resourceSample{T, R - 1, 0, 101, 7, pressureNormal}, codeSwapGrowth, base},
		{"swap-before-headroom", base, phaseRunning, resourceSample{T, H - 1, B + 1, 101, 7, pressureNormal}, codeSwapGrowth, base},
		{"headroom-before-budget", base, phaseRunning, resourceSample{T, H - 1, B + 1, 100, 7, pressureNormal}, codeHeadroom, base},
		{"zero-state-final", zero, phaseFinal, resourceSample{T, R, 0, 100, 7, pressureNormal}, codeProtocol, zero},
		{"zero-state-running", zero, phaseRunning, resourceSample{T, R, 0, 100, 7, pressureNormal}, codeProtocol, zero},
		{"repeat-initial", base, phaseInitial, resourceSample{T, R, 0, 100, 7, pressureNormal}, codeProtocol, base},
		{"unknown-phase-low", base, 0, resourceSample{T, R, 0, 100, 7, pressureNormal}, codeProtocol, base},
		{"unknown-phase-high", base, 255, resourceSample{T, R, 0, 100, 7, pressureNormal}, codeProtocol, base},
		{"unknown-latched-code", resourceState{trip: "pool-wallet-prover-"}, phaseRunning, resourceSample{}, codeProtocol, zero},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got, c := row.before.evaluate(row.phase, row.sample)
			want := row.after
			want.trip = row.want
			if got != want || c != row.want {
				t.Fatalf("state/code = %+v/%q, want %+v/%q", got, c, want, row.want)
			}
		})
	}
	for _, row := range []struct {
		name       string
		a, b, want uint64
	}{
		{"clamp-zero", 0, 1, 0},
		{"clamp-equality", 100, 100, 0},
		{"clamp-one-below", 99, 100, 0},
		{"clamp-one-above", 101, 100, 1},
		{"clamp-maximum", math.MaxUint64, 0, math.MaxUint64},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := clampedDifference(row.a, row.b); got != row.want {
				t.Fatalf("difference = %d, want %d", got, row.want)
			}
		})
	}
}

func TestResourcePolicyTrajectories(t *testing.T) {
	const T, R, H, B = minimumTotalBytes, requiredBytes, headroomBytes, minimumRemainingBytes
	state := resourceState{}
	steps := []struct {
		name   string
		phase  resourcePhase
		sample resourceSample
		want   resourceState
	}{
		{"initial-rss-nonzero-swap", phaseInitial, resourceSample{T, R + 1000, 200, 100, 7, pressureNormal}, resourceState{T, B + 1200, 100, 7, ""}},
		{"final-larger-capacity", phaseFinal, resourceSample{T, R + 2000, 200, 100, 7, pressureNormal}, resourceState{T, B + 1200, 100, 7, ""}},
		{"outside-depletion", phaseRunning, resourceSample{T, R - 1000, 200, 90, 7, pressureNormal}, resourceState{T, B - 800, 100, 7, ""}},
		{"capacity-return-no-expansion", phaseRunning, resourceSample{T, R + 2000, 200, 95, 7, pressureNormal}, resourceState{T, B - 800, 100, 7, ""}},
		{"final-shrunk-remaining-refusal", phaseFinal, resourceSample{T, R, 0, 80, 7, pressureNormal}, resourceState{T, B - 800, 100, 7, codeMemory}},
		{"sticky-pressure", phaseRunning, resourceSample{T, H, 0, 101, 8, pressureCritical}, resourceState{T, B - 800, 100, 7, codeMemory}},
		{"sticky-invalid-phase", 0, resourceSample{}, resourceState{T, B - 800, 100, 7, codeMemory}},
		{"sticky-reinitialization", phaseInitial, resourceSample{T, R, 0, 100, 7, pressureNormal}, resourceState{T, B - 800, 100, 7, codeMemory}},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			next, c := state.evaluate(step.phase, step.sample)
			if next != step.want || c != step.want.trip {
				t.Fatalf("state/code = %+v/%q, want %+v/%q", next, c, step.want, step.want.trip)
			}
			state = next
		})
	}
}
