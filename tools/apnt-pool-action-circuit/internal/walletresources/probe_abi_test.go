package walletresources

import (
	"math"
	"testing"
)

func probeTestCount(c probeRawCall, count uint64) probeRawCall {
	c.Attempted, c.Count = 1, count
	if c.Kind == 1 {
		c.Result = int64(count)
	}
	return c
}
func TestProbeRawABI(t *testing.T) {
	cases := []struct {
		name string
		call probeRawCall
		want int
	}{
		{"absent", probeRawCall{}, probeAbsent},
		{"denied", probeRawCall{Result: -1, Errno: 13, Attempted: 1}, probeReadError},
		{"missing", probeRawCall{Result: -1, Errno: 2, Attempted: 1}, probeReadError},
		{"Mach-failure", probeRawCall{Result: 5, Attempted: 1}, probeReadError},
		{"errno-preserved", probeRawCall{Errno: 13, Attempted: 1}, probeReadError},
		{"zero-unit", probeRawCall{Attempted: 1}, probeInvalidShape},
		{"unknown-kind", probeRawCall{Unit: 1, Kind: 3, Attempted: 1}, probeInvalidShape},
		{"bad-range", probeRawCall{Unit: 1, Required: 2, Capacity: 1, Attempted: 1}, probeInvalidShape},
		{"count-overflow", probeRawCall{Count: math.MaxUint64, Unit: 2, Capacity: math.MaxUint64, Attempted: 1}, probeOverflow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.call.availability(); got != tc.want {
				t.Fatalf("availability=%d want=%d", got, tc.want)
			}
		})
	}
	backend := probeBackend{}
	if !probeNativeBuild {
		raw, c := backend.acquire(0)
		if c != codePlatform || raw != (probeRaw{}) {
			t.Fatalf("unsupported platform: %s %+v", c, raw)
		}
		return
	}
	layout, geometry := backend.layout()
	for i, slot := range []int{1, 4, 5, 6} {
		c := layout.Calls[slot]
		if [2]uint64{c.Required, c.Capacity} != geometry[i] {
			t.Fatalf("SDK field end/sizeof slot%d: %+v", slot, c)
		}
	}
	for i, c := range layout.Calls {
		if c.availability() != probeAbsent || c.Unit == 0 || c.Required > c.Capacity {
			t.Fatalf("SDK shape slot%d: %+v", i, c)
		}
		minimum := (c.Required + c.Unit - 1) / c.Unit
		if got := probeTestCount(c, minimum).availability(); got != probeAvailable {
			t.Fatalf("minimum slot%d: %d", i, got)
		}
		if c.Required > 0 {
			if got := probeTestCount(c, minimum-1).availability(); got != probeShort {
				t.Fatalf("truncated slot%d: %d", i, got)
			}
		}
		if got := probeTestCount(c, c.Capacity/c.Unit+1).availability(); got != probeOversized {
			t.Fatalf("oversized slot%d: %d", i, got)
		}
		t.Logf("SDK slot%d required=%d capacity=%d unit=%d kind=%d", i, c.Required, c.Capacity, c.Unit, c.Kind)
	}
	fact := probeRawCall{-19, 13, 7, 4, 16, 128, 1, 1}
	if got := backend.transfer(fact); got != fact {
		t.Fatalf("native fact propagation: %+v", got)
	}
}
