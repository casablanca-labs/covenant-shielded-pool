package walletresources

import (
	"math"
	"testing"
)

// Synthetic typed B1 layout reuses its recorded SDK geometry, not an OS query.
func probeNormalizeFixture() (probeRaw, probeRaw) {
	sdk := probeRaw{Calls: [9]probeRawCall{
		0: {Unit: 1, Required: 8, Capacity: 8},
		1: {Unit: 1, Required: 28, Capacity: 32},
		2: {Unit: 1, Required: 4, Capacity: 4},
		3: {Unit: 8, Required: 8, Capacity: 8, Kind: 2},
		4: {Unit: 4, Required: 128, Capacity: 416},
		8: {Unit: 1, Kind: 2},
	}}
	v := probeRaw{Calls: sdk.Calls, Memory: probeRawMemory{
		Total: 17_179_869_184, Page: 16_384, Free: 65_536, Inactive: 32_768,
		Speculative: 1_024, Purgeable: 65_535, SwapTotal: 1_073_741_824,
		SwapAvailable: 805_306_368, SwapUsed: 268_435_456, SwapPage: 4_096,
		Swapouts: 42, Pressure: 1,
	}}
	for _, i := range []int{0, 1, 2, 3, 4, 8} {
		v.Calls[i].Attempted = 1
		v.Calls[i].Count = (v.Calls[i].Required + v.Calls[i].Unit - 1) / v.Calls[i].Unit
	}
	return v, sdk
}

func TestProbeNormalizeFacts(t *testing.T) {
	v, sdk := probeNormalizeFixture()
	want := probeMemoryFacts{raw: probeRawMemory{
		Total: 17_179_869_184, Page: 16_384, Free: 65_536, Inactive: 32_768,
		Speculative: 1_024, Purgeable: 65_535, SwapTotal: 1_073_741_824,
		SwapAvailable: 805_306_368, SwapUsed: 268_435_456, SwapPage: 4_096,
		Swapouts: 42, Pressure: 1,
	}, eligible: 1_610_612_736}
	got, reason := probeNormalize(v, sdk)
	if got != want || reason != probeNormalizePressureUnclassified {
		t.Fatalf("facts=%+v reason=%d", got, reason)
	}
	// Minimum field coverage is sufficient; current full SDK sizes are not required.
	for _, i := range []int{0, 1, 2, 3, 4} {
		v.Calls[i].Count = v.Calls[i].Capacity / v.Calls[i].Unit
	}
	if full, why := probeNormalize(v, sdk); full != want || why != probeNormalizePressureUnclassified {
		t.Fatalf("full SDK body changed facts: %+v %d", full, why)
	}
}

func TestProbeNormalizeArithmetic(t *testing.T) {
	cases := []struct {
		name     string
		memory   probeRawMemory
		eligible uint64
	}{
		{"zero-eligible-below-policy-minimum", probeRawMemory{Total: 1, Page: 1, SwapPage: 2}, 0},
		{"page-limit-no-speculative-or-purgeable-credit", probeRawMemory{Total: 5_242_880, Page: 1_048_576,
			Free: 2, Inactive: 3, Speculative: 2, Purgeable: math.MaxUint64, SwapPage: 4_096}, 5_242_880},
		{"no-speculative-credit", probeRawMemory{Total: 100, Page: 1, Free: 20, Inactive: 5, Speculative: 20, SwapPage: 1}, 25},
		{"no-purgeable-credit", probeRawMemory{Total: 100, Page: 1, Free: 20, Inactive: 5, Purgeable: 50, SwapPage: 1}, 25},
		{"uint64-exact-boundary", probeRawMemory{Total: math.MaxUint64, Page: 1, Free: math.MaxUint64,
			Speculative: math.MaxUint64, Purgeable: math.MaxUint64, SwapTotal: math.MaxUint64,
			SwapUsed: math.MaxUint64 - 1, SwapAvailable: 1, SwapPage: 1, Swapouts: math.MaxUint64}, math.MaxUint64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, sdk := probeNormalizeFixture()
			v.Memory = tc.memory
			got, why := probeNormalize(v, sdk)
			if got.eligible != tc.eligible || got.raw != tc.memory || why != probeNormalizePressureUnclassified {
				t.Fatalf("facts=%+v reason=%d want eligible=%d", got, why, tc.eligible)
			}
		})
	}
}

func TestProbeNormalizeFailures(t *testing.T) {
	cases := []struct {
		name   string
		change func(*probeRaw, *probeRaw)
		want   probeNormalizeReason
	}{
		{"missing-pressure", func(v, s *probeRaw) { v.Calls[2] = probeRawCall{} }, probeNormalizeMissing},
		{"denied-pressure", func(v, s *probeRaw) { v.Calls[2].Errno = 13 }, probeNormalizeReadError},
		{"absent-native-name", func(v, s *probeRaw) { v.Calls[2].Errno = 2 }, probeNormalizeReadError},
		{"failed-sysctl", func(v, s *probeRaw) { v.Calls[0].Result = -1 }, probeNormalizeReadError},
		{"failed-Mach-call", func(v, s *probeRaw) { v.Calls[4].Result = 5 }, probeNormalizeReadError},
		{"failed-host-release", func(v, s *probeRaw) { v.Calls[8].Result = 5 }, probeNormalizeReadError},
		{"raw-unit-mismatch", func(v, s *probeRaw) { v.Calls[4].Unit = 1 }, probeNormalizeUnit},
		{"raw-zero-unit", func(v, s *probeRaw) { v.Calls[4].Unit = 0 }, probeNormalizeUnit},
		{"required-field-tamper", func(v, s *probeRaw) { v.Calls[4].Required = 124 }, probeNormalizeShape},
		{"capacity-tamper", func(v, s *probeRaw) { v.Calls[4].Capacity = 420 }, probeNormalizeShape},
		{"kind-tamper", func(v, s *probeRaw) { v.Calls[3].Kind = 0 }, probeNormalizeShape},
		{"attempt-shape", func(v, s *probeRaw) { v.Calls[0].Attempted = 2 }, probeNormalizeShape},
		{"truncated-scalar", func(v, s *probeRaw) { v.Calls[0].Count = 7 }, probeNormalizeShort},
		{"truncated-VM-field", func(v, s *probeRaw) { v.Calls[4].Count = 31 }, probeNormalizeShort},
		{"oversized-scalar", func(v, s *probeRaw) { v.Calls[0].Count = 9 }, probeNormalizeOversized},
		{"oversized-VM-body", func(v, s *probeRaw) { v.Calls[4].Count = 105 }, probeNormalizeOversized},
		{"native-count-overflow", func(v, s *probeRaw) { v.Calls[4].Count = math.MaxUint64 }, probeNormalizeOverflow},
		{"missing-layout", func(v, s *probeRaw) { s.Calls[0] = probeRawCall{} }, probeNormalizeLayout},
		{"layout-zero-required", func(v, s *probeRaw) { s.Calls[1].Required = 0 }, probeNormalizeLayout},
		{"layout-short-capacity", func(v, s *probeRaw) { s.Calls[1].Capacity = 27 }, probeNormalizeLayout},
		{"layout-result", func(v, s *probeRaw) { s.Calls[0].Result = 1 }, probeNormalizeLayout},
		{"layout-count", func(v, s *probeRaw) { s.Calls[0].Count = 8 }, probeNormalizeLayout},
		{"layout-attempted", func(v, s *probeRaw) { s.Calls[0].Attempted = 1 }, probeNormalizeLayout},
		{"layout-kind", func(v, s *probeRaw) { s.Calls[3].Kind = 0 }, probeNormalizeLayout},
		{"release-body", func(v, s *probeRaw) { s.Calls[8].Capacity = 1 }, probeNormalizeLayout},
		{"zero-total", func(v, s *probeRaw) { v.Memory.Total = 0 }, probeNormalizeZero},
		{"zero-page", func(v, s *probeRaw) { v.Memory.Page = 0 }, probeNormalizeZero},
		{"zero-swap-page", func(v, s *probeRaw) { v.Memory.SwapPage = 0 }, probeNormalizeZero},
		{"page-not-power-two", func(v, s *probeRaw) { v.Memory.Page = 3 }, probeNormalizeUnit},
		{"page-above-limit", func(v, s *probeRaw) { v.Memory.Page = 1 << 21 }, probeNormalizeUnit},
		{"swap-page-not-power-two", func(v, s *probeRaw) { v.Memory.SwapPage = 3 }, probeNormalizeUnit},
		{"swap-page-above-limit", func(v, s *probeRaw) { v.Memory.SwapPage = 1 << 21 }, probeNormalizeUnit},
		{"page-sum-overflow", func(v, s *probeRaw) {
			v.Memory.Free, v.Memory.Inactive, v.Memory.Page = math.MaxUint64, 1, 1
		}, probeNormalizeOverflow},
		{"eligible-multiply-overflow", func(v, s *probeRaw) {
			v.Memory.Free, v.Memory.Inactive, v.Memory.Page = math.MaxUint64, 0, 2
		}, probeNormalizeOverflow},
		{"swap-sum-overflow", func(v, s *probeRaw) {
			v.Memory.SwapUsed, v.Memory.SwapAvailable = math.MaxUint64, 1
		}, probeNormalizeOverflow},
		{"eligible-above-total", func(v, s *probeRaw) { v.Memory.Total = 1_610_612_735 }, probeNormalizeInconsistent},
		{"speculative-above-free", func(v, s *probeRaw) { v.Memory.Speculative = 65_537 }, probeNormalizeInconsistent},
		{"swap-sum-inconsistent", func(v, s *probeRaw) { v.Memory.SwapAvailable-- }, probeNormalizeInconsistent},
		{"used-above-total", func(v, s *probeRaw) {
			v.Memory.SwapUsed, v.Memory.SwapAvailable = 1_073_741_825, 0
		}, probeNormalizeInconsistent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, sdk := probeNormalizeFixture()
			tc.change(&v, &sdk)
			if got, why := probeNormalize(v, sdk); got != (probeMemoryFacts{}) || why != tc.want {
				t.Fatalf("facts=%+v reason=%d want=%d", got, why, tc.want)
			}
		})
	}
}

func TestProbeNormalizePressure(t *testing.T) {
	for _, pressure := range []int64{math.MinInt64, -1, 0, 1, 2, 4, 99, math.MaxInt64} {
		v, sdk := probeNormalizeFixture()
		v.Memory.Pressure = pressure
		got, why := probeNormalize(v, sdk)
		if got.eligible != 1_610_612_736 || got.raw.Pressure != pressure || why != probeNormalizePressureUnclassified {
			t.Fatalf("raw pressure %d became qualified: %+v %d", pressure, got, why)
		}
	}
}

func TestProbeNormalizeCoverage(t *testing.T) {
	for _, slot := range []int{0, 1, 2, 3, 4, 8} {
		v, sdk := probeNormalizeFixture()
		v.Calls[slot].Attempted = 0
		if got, why := probeNormalize(v, sdk); got != (probeMemoryFacts{}) || why != probeNormalizeMissing {
			t.Fatalf("missing slot %d: %+v %d", slot, got, why)
		}
		v, sdk = probeNormalizeFixture()
		v.Calls[slot].Count = sdk.Calls[slot].Capacity/sdk.Calls[slot].Unit + 1
		if got, why := probeNormalize(v, sdk); got != (probeMemoryFacts{}) || why != probeNormalizeOversized {
			t.Fatalf("oversized slot %d: %+v %d", slot, got, why)
		}
		if sdk.Calls[slot].Required != 0 {
			v.Calls[slot].Count = (sdk.Calls[slot].Required - 1) / sdk.Calls[slot].Unit
			if got, why := probeNormalize(v, sdk); got != (probeMemoryFacts{}) || why != probeNormalizeShort {
				t.Fatalf("truncated slot %d: %+v %d", slot, got, why)
			}
		}
	}
}

func TestProbeNormalizeScope(t *testing.T) {
	v, sdk := probeNormalizeFixture()
	v.Process = probeRawProcess{PID: 999, RSS: math.MaxUint64}
	v.Calls[6] = probeRawCall{Result: -1, Errno: 13, Attempted: 1}
	got, why := probeNormalize(v, sdk)
	if got.eligible != 1_610_612_736 || why != probeNormalizePressureUnclassified {
		t.Fatalf("process data affected memory facts: %+v %d", got, why)
	}
}
