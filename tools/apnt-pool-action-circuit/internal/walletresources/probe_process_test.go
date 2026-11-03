//go:build darwin && arm64 && cgo

package walletresources

import (
	"math"
	"testing"
)

func probeProcessFixture() (probeRaw, probeRaw) {
	sdk := probeRaw{Calls: [9]probeRawCall{
		5: {Unit: 1, Kind: 1, Required: 136, Capacity: 136},
		6: {Unit: 1, Kind: 1, Required: 16, Capacity: 96},
		7: {Unit: 1, Kind: 1, Required: 136, Capacity: 136},
	}}
	v := probeRaw{Calls: sdk.Calls, Process: probeRawProcess{
		PID: 101, UID: 501, PGID: 71, Status: 3, Seconds: 1_700_000_123, Micros: 123_456, RSS: 1_234_567,
		AfterPID: 101, AfterUID: 501, AfterPGID: 71, AfterSeconds: 1_700_000_123, AfterMicros: 123_456,
	}}
	for _, i := range []int{5, 6, 7} {
		v.Calls[i].Attempted, v.Calls[i].Count, v.Calls[i].Result = 1, v.Calls[i].Required, int64(v.Calls[i].Required)
	}
	return v, sdk
}

func TestProbeProcessFacts(t *testing.T) {
	v, sdk := probeProcessFixture()
	want := probeRawProcess{PID: 101, UID: 501, PGID: 71, Status: 3, Seconds: 1_700_000_123, Micros: 123_456, RSS: 1_234_567,
		AfterPID: 101, AfterUID: 501, AfterPGID: 71, AfterSeconds: 1_700_000_123, AfterMicros: 123_456}
	got, why := probeProcess(v, sdk)
	if got.raw != want || got.calls != [3]probeRawCall{v.Calls[5], v.Calls[6], v.Calls[7]} || why != probeProcessScopeUnconfirmed {
		t.Fatalf("facts=%+v reason=%d", got, why)
	}
	v.Calls[6].Count, v.Calls[6].Result = 96, 96
	if full, reason := probeProcess(v, sdk); full.raw != want || full.calls[1].Count != 96 || reason != probeProcessScopeUnconfirmed {
		t.Fatalf("full task changed facts: %+v %d", full, reason)
	}
}

func TestProbeProcessWidths(t *testing.T) {
	got := probeProcessNativeLimits()
	want := probeProcessLimits{pid: 2_147_483_647, pgid: 2_147_483_647, uid: 4_294_967_295, status: 4_294_967_295,
		seconds: math.MaxUint64, micros: math.MaxUint64, rss: math.MaxUint64, result: 2_147_483_647,
		bsdEnd: 136, bsdSize: 136, taskEnd: 16, taskSize: 96}
	if got != want {
		t.Fatalf("SDK-bound limits=%+v", got)
	}
	t.Logf("SDK-bound field limits: %+v; no process/OS qualification", got)
}

func TestProbeProcessCallBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		change func(*probeRawCall)
		want   probeProcessReason
	}{
		{"unattempted", func(c *probeRawCall) { c.Attempted = 0 }, probeProcessMissing},
		{"denied", func(c *probeRawCall) { c.Errno = 13 }, probeProcessReadError},
		{"missing", func(c *probeRawCall) { c.Errno = 2 }, probeProcessReadError},
		{"zero-return", func(c *probeRawCall) { c.Result = 0 }, probeProcessReadError},
		{"negative-return", func(c *probeRawCall) { c.Result = -1 }, probeProcessReadError},
		{"bad-unit", func(c *probeRawCall) { c.Unit = 4 }, probeProcessUnit},
		{"zero-unit", func(c *probeRawCall) { c.Unit = 0 }, probeProcessUnit},
		{"bad-kind", func(c *probeRawCall) { c.Kind = 0 }, probeProcessShape},
		{"bad-attempt", func(c *probeRawCall) { c.Attempted = 2 }, probeProcessShape},
		{"field-end", func(c *probeRawCall) { c.Required-- }, probeProcessShape},
		{"capacity", func(c *probeRawCall) { c.Capacity++ }, probeProcessShape},
		{"short", func(c *probeRawCall) {
			c.Count--
			c.Result--
		}, probeProcessShort},
		{"oversized", func(c *probeRawCall) { c.Count, c.Result = c.Capacity+1, int64(c.Capacity+1) }, probeProcessOversized},
		{"return-count", func(c *probeRawCall) { c.Result++ }, probeProcessReturnCount},
	}
	for _, slot := range []int{5, 6, 7} {
		for _, tc := range cases {
			v, sdk := probeProcessFixture()
			tc.change(&v.Calls[slot])
			if got, why := probeProcess(v, sdk); got != (probeProcessFacts{}) || why != tc.want {
				t.Fatalf("slot=%d case=%s facts=%+v reason=%d want=%d", slot, tc.name, got, why, tc.want)
			}
		}
	}
}

func TestProbeProcessRefusals(t *testing.T) {
	cases := []struct {
		name   string
		change func(*probeRaw, *probeRaw)
		want   probeProcessReason
	}{
		{"layout-mismatch", func(v, s *probeRaw) { s.Calls[7].Required-- }, probeProcessLayout},
		{"layout-unit", func(v, s *probeRaw) { s.Calls[6].Unit = 0 }, probeProcessLayout},
		{"layout-kind", func(v, s *probeRaw) { s.Calls[6].Kind = 0 }, probeProcessLayout},
		{"layout-range", func(v, s *probeRaw) { s.Calls[6].Capacity = math.MaxUint64 }, probeProcessLayout},
		{"layout-empty", func(v, s *probeRaw) { s.Calls[6].Required = 0 }, probeProcessLayout},
		{"layout-attempt", func(v, s *probeRaw) { s.Calls[6].Attempted = 1 }, probeProcessLayout},
		{"PID-zero", func(v, s *probeRaw) { v.Process.PID = 0 }, probeProcessIdentifier},
		{"after-PID-zero", func(v, s *probeRaw) { v.Process.AfterPID = 0 }, probeProcessIdentifier},
		{"PGID-zero", func(v, s *probeRaw) { v.Process.PGID = 0 }, probeProcessIdentifier},
		{"after-PGID-zero", func(v, s *probeRaw) { v.Process.AfterPGID = 0 }, probeProcessIdentifier},
		{"PID-range", func(v, s *probeRaw) { v.Process.PID = 2_147_483_648 }, probeProcessRange},
		{"after-PID-range", func(v, s *probeRaw) { v.Process.AfterPID = 2_147_483_648 }, probeProcessRange},
		{"UID-range", func(v, s *probeRaw) { v.Process.UID = 4_294_967_296 }, probeProcessRange},
		{"after-UID-range", func(v, s *probeRaw) { v.Process.AfterUID = 4_294_967_296 }, probeProcessRange},
		{"PGID-range", func(v, s *probeRaw) { v.Process.PGID = 2_147_483_648 }, probeProcessRange},
		{"after-PGID-range", func(v, s *probeRaw) { v.Process.AfterPGID = 2_147_483_648 }, probeProcessRange},
		{"status-range", func(v, s *probeRaw) { v.Process.Status = 4_294_967_296 }, probeProcessRange},
		{"microsecond-range", func(v, s *probeRaw) { v.Process.Micros = 1_000_000 }, probeProcessTime},
		{"after-microsecond-range", func(v, s *probeRaw) { v.Process.AfterMicros = 1_000_000 }, probeProcessTime},
		{"zero-start", func(v, s *probeRaw) { v.Process.Seconds, v.Process.Micros = 0, 0 }, probeProcessStartUnconfirmed},
		{"zero-after-start", func(v, s *probeRaw) { v.Process.AfterSeconds, v.Process.AfterMicros = 0, 0 }, probeProcessStartUnconfirmed},
		{"PID-drift", func(v, s *probeRaw) { v.Process.AfterPID++ }, probeProcessReuse},
		{"seconds-drift", func(v, s *probeRaw) { v.Process.AfterSeconds++ }, probeProcessReuse},
		{"microseconds-drift", func(v, s *probeRaw) { v.Process.AfterMicros++ }, probeProcessReuse},
		{"UID-drift", func(v, s *probeRaw) { v.Process.AfterUID++ }, probeProcessDrift},
		{"PGID-drift", func(v, s *probeRaw) { v.Process.AfterPGID++ }, probeProcessDrift},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, sdk := probeProcessFixture()
			tc.change(&v, &sdk)
			if got, why := probeProcess(v, sdk); got != (probeProcessFacts{}) || why != tc.want {
				t.Fatalf("facts=%+v reason=%d want=%d", got, why, tc.want)
			}
		})
	}
}

func TestProbeProcessBoundaries(t *testing.T) {
	v, sdk := probeProcessFixture()
	v.Process = probeRawProcess{PID: 2_147_483_647, AfterPID: 2_147_483_647, UID: 4_294_967_295, AfterUID: 4_294_967_295,
		PGID: 2_147_483_647, AfterPGID: 2_147_483_647, Seconds: math.MaxUint64, AfterSeconds: math.MaxUint64,
		Micros: 999_999, AfterMicros: 999_999, RSS: math.MaxUint64, Status: 4_294_967_295}
	if got, why := probeProcess(v, sdk); got.raw != v.Process || why != probeProcessScopeUnconfirmed {
		t.Fatalf("native field boundaries: %+v %d", got, why)
	}
	v.Process.UID, v.Process.AfterUID = 0, 0
	v.Process.Seconds, v.Process.AfterSeconds, v.Process.Micros, v.Process.AfterMicros = 0, 0, 1, 1
	if got, why := probeProcess(v, sdk); got.raw != v.Process || why != probeProcessScopeUnconfirmed {
		t.Fatalf("UID zero/unsigned start pair: %+v %d", got, why)
	}
}

func TestProbeProcessZeroRSS(t *testing.T) {
	for _, status := range []uint64{0, 1, 2, 5, 4_294_967_295} {
		v, sdk := probeProcessFixture()
		v.Process.Status = status
		if got, why := probeProcess(v, sdk); got.raw.Status != status || why != probeProcessScopeUnconfirmed {
			t.Fatalf("status interpreted: %+v %d", got, why)
		}
		v.Process.RSS = 0
		if got, why := probeProcess(v, sdk); got != (probeProcessFacts{}) || why != probeProcessZeroRSSUnconfirmed {
			t.Fatalf("status %d granted exit authority: %+v %d", status, got, why)
		}
	}
}
