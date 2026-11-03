//go:build darwin && arm64 && cgo

package walletresources

import (
	"math"
	"reflect"
	"strconv"
	"testing"
)

// Synthetic injection is test-only. It cannot construct probeNativeGroup or an
// authenticated registration, and never calls proc_listpgrppids/proc_pidinfo.
type probeMembershipStep struct {
	size bool
	pids []int32
	edit func(*probeRawCall)
}
type probeMembershipSynthetic struct {
	t        *testing.T
	steps    []probeMembershipStep
	calls    []probeRawCall
	reads    map[uint64]int
	versions map[uint64][]probeRaw
}

func probeMembershipSample(pid, pgid, rss uint64) probeRaw {
	sdk, _ := (probeBackend{}).layout()
	raw := probeRaw{Calls: sdk.Calls, Process: probeRawProcess{
		PID: pid, AfterPID: pid, UID: 501, AfterUID: 501, PGID: pgid, AfterPGID: pgid,
		Seconds: 1_700_000_123, AfterSeconds: 1_700_000_123, Micros: 123_456, AfterMicros: 123_456, RSS: rss,
	}}
	for _, slot := range []int{5, 6, 7} {
		raw.Calls[slot].Attempted = 1
		raw.Calls[slot].Count = raw.Calls[slot].Capacity
		raw.Calls[slot].Result = int64(raw.Calls[slot].Count)
	}
	return raw
}
func (s *probeMembershipSynthetic) group(pgid uint64, buf []int32) probeRawCall {
	s.t.Helper()
	if pgid != 71 || len(s.steps) == 0 {
		s.t.Fatalf("unexpected synthetic enumeration pgid=%d steps=%d", pgid, len(s.steps))
	}
	step := s.steps[0]
	s.steps = s.steps[1:]
	if step.size != (buf == nil) {
		s.t.Fatal("size/read phase changed")
	}
	c := probeMembershipNativeLayout()
	c.Attempted, c.Count, c.Capacity = 1, uint64(len(step.pids)), uint64(len(buf))*c.Unit
	if step.size {
		c.Count = 8
	} else {
		copy(buf, step.pids)
	}
	c.Result = int64(c.Count)
	if step.edit != nil {
		step.edit(&c)
	}
	s.calls = append(s.calls, c)
	return c
}
func (s *probeMembershipSynthetic) process(pid uint64) probeRaw {
	s.t.Helper()
	if s.reads == nil {
		s.reads = map[uint64]int{}
	}
	n := s.reads[pid]
	s.reads[pid]++
	if versions := s.versions[pid]; len(versions) != 0 {
		if n >= len(versions) {
			n = len(versions) - 1
		}
		return versions[n]
	}
	return probeMembershipSample(pid, 71, pid)
}
func probeMembershipSteps(before, after []int32) []probeMembershipStep {
	return []probeMembershipStep{{size: true}, {pids: before}, {pids: after}}
}

func TestProbeMembershipSDK(t *testing.T) {
	got := probeMembershipNativeLayout()
	if got != (probeRawCall{Unit: 4, Kind: 3}) {
		t.Fatalf("SDK count-result layout=%+v", got)
	}
	if max := probeProcessNativeLimits().result; max/got.Unit != 536_870_911 {
		t.Fatalf("SDK signed buffersize range=%d", max)
	}
	t.Log("SDK layout only; no native process enumeration or runtime qualification")
}

func TestProbeMembershipGroupCalls(t *testing.T) {
	cases := []struct {
		name     string
		capacity uint64
		edit     func(*probeRawCall)
		want     probeMembershipReason
	}{
		{"negative", 8, func(c *probeRawCall) { c.Result = -1; c.Count = 0 }, probeMembershipRead},
		{"denied-zero", 8, func(c *probeRawCall) { c.Result = 0; c.Count = 0; c.Errno = 13 }, probeMembershipRead},
		{"errno-with-count", 8, func(c *probeRawCall) { c.Errno = 1 }, probeMembershipRead},
		{"absent", 8, func(c *probeRawCall) { c.Attempted = 0 }, probeMembershipShape},
		{"attempt-count", 8, func(c *probeRawCall) { c.Attempted = 2 }, probeMembershipShape},
		{"unit", 8, func(c *probeRawCall) { c.Unit = 8 }, probeMembershipShape},
		{"kind", 8, func(c *probeRawCall) { c.Kind = 1 }, probeMembershipShape},
		{"minimum", 8, func(c *probeRawCall) { c.Required = 4 }, probeMembershipShape},
		{"byte-capacity", 8, func(c *probeRawCall) { c.Capacity++ }, probeMembershipShape},
		{"bytes-as-count", 8, func(c *probeRawCall) { c.Result = 8 }, probeMembershipCount},
		{"count-disagreement", 8, func(c *probeRawCall) { c.Count++ }, probeMembershipCount},
		{"full", 8, func(c *probeRawCall) { c.Result = 8; c.Count = 8 }, probeMembershipTruncated},
		{"oversized", 8, func(c *probeRawCall) { c.Result = 9; c.Count = 9 }, probeMembershipTruncated},
		{"count-overflow", 8, func(c *probeRawCall) { c.Count = math.MaxUint64 }, probeMembershipSize},
		{"buffer-overflow", math.MaxUint64, func(c *probeRawCall) {}, probeMembershipShape},
		{"int-byte-overflow", 8, func(c *probeRawCall) { c.Result = 536_870_912; c.Count = 536_870_912 }, probeMembershipSize},
		{"empty-estimate", 0, func(c *probeRawCall) { c.Result = 0; c.Count = 0 }, probeMembershipSize},
		{"allocation-bound", 0, func(c *probeRawCall) { c.Result = probeMembershipMaxPIDs + 1; c.Count = probeMembershipMaxPIDs + 1 }, probeMembershipSize},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := probeMembershipNativeLayout()
			c.Attempted, c.Result, c.Count, c.Capacity = 1, 2, 2, tc.capacity*4
			tc.edit(&c)
			f := probeGroupCall(c, tc.capacity)
			if f.reason != tc.want || f.call != c {
				t.Fatalf("failure=%+v want=%d call=%+v", f, tc.want, c)
			}
		})
	}
	for _, capacity := range []uint64{0, 8} {
		c := probeMembershipNativeLayout()
		c.Attempted, c.Result, c.Count, c.Capacity = 1, 2, 2, capacity*c.Unit
		if f := probeGroupCall(c, capacity); f.reason != 0 {
			t.Fatalf("valid count=%+v", f)
		}
	}
}

func TestProbeMembershipCollect(t *testing.T) {
	s := &probeMembershipSynthetic{t: t, steps: probeMembershipSteps([]int32{101, 71, 101}, []int32{71, 101})}
	got, f := probeCollectGroup(s, 71)
	if f.reason != 0 || got.pgid != 71 || !reflect.DeepEqual(got.pids, []uint64{71, 101}) ||
		len(got.processes) != 2 || len(got.calls) != 3 || len(s.steps) != 0 || s.reads[101] != 1 || s.reads[71] != 1 {
		t.Fatalf("group=%+v failure=%+v reads=%v remaining=%d", got, f, s.reads, len(s.steps))
	}
	// Changing only a capacity estimate is never evidence of changed membership.
	if got.calls[0].Count != 8 || got.calls[1].Count != 3 || got.calls[2].Count != 2 {
		t.Fatalf("PID counts lost: %+v", got.calls)
	}
}

func TestProbeMembershipChanges(t *testing.T) {
	cases := []struct {
		name  string
		steps []probeMembershipStep
		want  probeMembershipReason
		calls int
	}{
		{"addition-then-stable", append(probeMembershipSteps([]int32{71}, []int32{71, 101}), probeMembershipSteps([]int32{101, 71}, []int32{71, 101})...), 0, 6},
		{"added-member-disappears-before-repeat", append(probeMembershipSteps([]int32{71}, []int32{71, 101}), probeMembershipSteps([]int32{71}, []int32{71})...), probeMembershipDisappearanceUnconfirmed, 5},
		{"second-addition", append(probeMembershipSteps([]int32{71}, []int32{71, 101}), probeMembershipSteps([]int32{71, 101}, []int32{71, 101, 102})...), probeMembershipChanged, 6},
		{"disappearance", probeMembershipSteps([]int32{71, 101}, []int32{71}), probeMembershipDisappearanceUnconfirmed, 3},
		{"replacement", probeMembershipSteps([]int32{71, 101}, []int32{71, 102}), probeMembershipDisappearanceUnconfirmed, 3},
		{"empty-group", probeMembershipSteps(nil, nil), probeMembershipDisappearanceUnconfirmed, 2},
		{"invalid-PID", probeMembershipSteps([]int32{0, 71}, []int32{71}), probeMembershipIdentifier, 2},
		{"negative-PID", probeMembershipSteps([]int32{-1, 71}, []int32{71}), probeMembershipIdentifier, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &probeMembershipSynthetic{t: t, steps: tc.steps}
			got, f := probeCollectGroup(s, 71)
			if f.reason != tc.want || len(s.calls) != tc.calls {
				t.Fatalf("failure=%+v calls=%d", f, len(s.calls))
			}
			if tc.want != 0 && !reflect.DeepEqual(got, probeGroupObservation{}) {
				t.Fatal("partial sample escaped")
			}
		})
	}
	for _, pgid := range []uint64{0, math.MaxUint64} {
		s := &probeMembershipSynthetic{t: t}
		if _, f := probeCollectGroup(s, pgid); f.reason != probeMembershipIdentifier || len(s.calls) != 0 {
			t.Fatalf("invalid PGID read: %+v", f)
		}
	}
}

func TestProbeMembershipReadStops(t *testing.T) {
	for _, phase := range []int{0, 1, 2} {
		t.Run([]string{"size", "before", "after"}[phase], func(t *testing.T) {
			steps := probeMembershipSteps([]int32{71}, []int32{71})
			steps[phase].edit = func(c *probeRawCall) { c.Result = 0; c.Count = 0; c.Errno = 13 }
			s := &probeMembershipSynthetic{t: t, steps: steps}
			got, f := probeCollectGroup(s, 71)
			if f.reason != probeMembershipRead || f.call.Errno != 13 || f.call.Result != 0 || len(s.calls) != phase+1 ||
				!reflect.DeepEqual(got, probeGroupObservation{}) {
				t.Fatalf("refusal=%+v calls=%d", f, len(s.calls))
			}
		})
	}
	for _, phase := range []int{1, 2} {
		t.Run([]string{"", "full-before", "full-after"}[phase], func(t *testing.T) {
			steps := probeMembershipSteps([]int32{71}, []int32{71})
			steps[phase].edit = func(c *probeRawCall) { c.Result = 8; c.Count = 8 }
			s := &probeMembershipSynthetic{t: t, steps: steps}
			if _, f := probeCollectGroup(s, 71); f.reason != probeMembershipTruncated || len(s.calls) != phase+1 {
				t.Fatalf("full retried: %+v", f)
			}
		})
	}
}

func TestProbeMembershipProcessStops(t *testing.T) {
	cases := []struct {
		name    string
		edit    func(*probeRaw)
		reason  probeMembershipReason
		process probeProcessReason
	}{
		{"BSD-short", func(v *probeRaw) { v.Calls[5].Result--; v.Calls[5].Count-- }, probeMembershipProcessInvalid, probeProcessShort},
		{"task-short", func(v *probeRaw) { v.Calls[6].Result = 15; v.Calls[6].Count = 15 }, probeMembershipProcessInvalid, probeProcessShort},
		{"after-short", func(v *probeRaw) { v.Calls[7].Result--; v.Calls[7].Count-- }, probeMembershipProcessInvalid, probeProcessShort},
		{"oversized", func(v *probeRaw) { v.Calls[6].Result++; v.Calls[6].Count++ }, probeMembershipProcessInvalid, probeProcessOversized},
		{"denied", func(v *probeRaw) { v.Calls[6].Result = 0; v.Calls[6].Count = 0; v.Calls[6].Errno = 13 }, probeMembershipProcessInvalid, probeProcessReadError},
		{"missing", func(v *probeRaw) { v.Calls[5].Result = 0; v.Calls[5].Count = 0; v.Calls[5].Errno = 3 }, probeMembershipProcessInvalid, probeProcessReadError},
		{"PID-reuse", func(v *probeRaw) { v.Process.AfterSeconds++ }, probeMembershipProcessInvalid, probeProcessReuse},
		{"UID-drift", func(v *probeRaw) { v.Process.AfterUID++ }, probeMembershipProcessInvalid, probeProcessDrift},
		{"wrong-PID", func(v *probeRaw) { v.Process.PID++; v.Process.AfterPID++ }, probeMembershipBinding, 0},
		{"wrong-group", func(v *probeRaw) { v.Process.PGID++; v.Process.AfterPGID++ }, probeMembershipBinding, 0},
		{"zero-RSS", func(v *probeRaw) { v.Process.RSS = 0 }, probeMembershipExitUnavailable, probeProcessZeroRSSUnconfirmed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := probeMembershipSample(71, 71, 71)
			tc.edit(&v)
			s := &probeMembershipSynthetic{t: t, steps: probeMembershipSteps([]int32{71}, []int32{71}), versions: map[uint64][]probeRaw{71: {v}}}
			got, f := probeCollectGroup(s, 71)
			if f.reason != tc.reason || f.processReason != tc.process || len(s.calls) != 2 || s.reads[71] != 1 || !reflect.DeepEqual(got, probeGroupObservation{}) {
				t.Fatalf("failure=%+v calls=%d reads=%v", f, len(s.calls), s.reads)
			}
			if tc.name == "denied" && f.call != v.Calls[6] {
				t.Fatal("native errno/result lost")
			}
		})
	}
	for _, change := range []string{"reuse", "UID"} {
		t.Run("between-enumerations-"+change, func(t *testing.T) {
			first := probeMembershipSample(71, 71, 71)
			second := first
			want := probeMembershipReuse
			if change == "reuse" {
				second.Process.Seconds++
				second.Process.AfterSeconds++
			} else {
				second.Process.UID++
				second.Process.AfterUID++
				want = probeMembershipBinding
			}
			s := &probeMembershipSynthetic{t: t, steps: append(probeMembershipSteps([]int32{71}, []int32{71, 101}), probeMembershipSteps([]int32{71, 101}, []int32{71, 101})...), versions: map[uint64][]probeRaw{71: {first, second}}}
			if _, f := probeCollectGroup(s, 71); f.reason != want || len(s.calls) != 5 {
				t.Fatalf("identity replaced: %+v calls=%d", f, len(s.calls))
			}
		})
	}
}

func probeMembershipFixture() ([]probeRegistrationRow, []uint64, []probeRaw) {
	samples := []probeRaw{
		probeMembershipSample(201, 201, 10), probeMembershipSample(202, 202, 20), probeMembershipSample(203, 202, 30),
		probeMembershipSample(71, 71, 40), probeMembershipSample(101, 71, 50), probeMembershipSample(102, 71, 60),
	}
	rows := []probeRegistrationRow{
		{probeRoleSlot{role: probeRoleWallet}, probeIdentity(samples[0].Process)},
		{probeRoleSlot{role: probeRoleAdapter}, probeIdentity(samples[0].Process)},
		{probeRoleSlot{role: probeRoleGuardian}, probeIdentity(samples[1].Process)},
		{probeRoleSlot{role: probeRoleSampler}, probeIdentity(samples[2].Process)},
		{probeRoleSlot{role: probeRoleLeader}, probeIdentity(samples[3].Process)},
		{probeRoleSlot{role: probeRoleWorker}, probeIdentity(samples[4].Process)},
		{probeRoleSlot{role: probeRoleHelper, helper: 1}, probeIdentity(samples[5].Process)},
	}
	return rows, []uint64{71, 101, 102}, samples
}

func TestProbeMembershipAccounting(t *testing.T) {
	rows, group, samples := probeMembershipFixture()
	// Wallet/adapter share a process; repeated exact observations count once.
	group = append(group, 101)
	samples = append(samples, samples[3])
	got, f := probeCompareMembership(71, rows, group, samples)
	if got != (probeMembershipAccounting{rss: 210, processes: 6}) || f.reason != probeMembershipRegistrationUnavailable {
		t.Fatalf("accounting=%+v authority=%+v", got, f)
	}
	for i := range samples {
		samples[i].Process.RSS = 1
	}
	samples[0].Process.RSS = math.MaxUint64 - 5
	got, f = probeCompareMembership(71, rows, group, samples)
	if got.rss != math.MaxUint64 || got.processes != 6 || f.reason != probeMembershipRegistrationUnavailable {
		t.Fatalf("uint64 boundary=%+v %+v", got, f)
	}
	samples[5].Process.RSS++
	got, f = probeCompareMembership(71, rows, group, samples)
	if got != (probeMembershipAccounting{}) || f.reason != probeMembershipOverflow {
		t.Fatalf("overflow=%+v %+v", got, f)
	}
}

func TestProbeMembershipRegistration(t *testing.T) {
	cases := []struct {
		name string
		edit func(*[]probeRegistrationRow, *[]uint64, *[]probeRaw)
		want probeMembershipReason
	}{
		{"absent", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) { *r = nil }, probeMembershipRegistrationUnavailable},
		{"duplicate-role", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) { *r = append(*r, (*r)[0]) }, probeMembershipRole},
		{"conflicting-role", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) { (*r)[1].slot = (*r)[0].slot }, probeMembershipRole},
		{"unknown-role", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) { (*r)[0].slot.role = 99 }, probeMembershipRole},
		{"helper-slot", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) { (*r)[6].slot.helper = 0 }, probeMembershipRole},
		{"nonhelper-slot", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) { (*r)[0].slot.helper = 1 }, probeMembershipRole},
		{"missing-role", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) { *r = (*r)[1:] }, probeMembershipRole},
		{"overlapping-children", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) {
			*r = append(*r, probeRegistrationRow{probeRoleSlot{role: probeRoleAdmission}, (*r)[5].identity})
		}, probeMembershipRole},
		{"registered-PID-reuse", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) { (*r)[1].identity.seconds++ }, probeMembershipReuse},
		{"registered-UID-conflict", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) { (*r)[1].identity.uid++ }, probeMembershipBinding},
		{"registered-PGID-conflict", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) { (*r)[1].identity.pgid++ }, probeMembershipBinding},
		{"leader-binding", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) { (*r)[4].identity.pgid++ }, probeMembershipBinding},
		{"unconfirmed-start", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) {
			(*r)[0].identity.seconds = 0
			(*r)[0].identity.micros = 0
		}, probeMembershipIdentifier},
		{"PID-range", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) { (*r)[0].identity.pid = math.MaxUint64 }, probeMembershipIdentifier},
		{"UID-range", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) { (*r)[0].identity.uid = math.MaxUint64 }, probeMembershipIdentifier},
		{"extra-member", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) { *g = append(*g, 999) }, probeMembershipUnowned},
		{"missing-member", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) { *g = (*g)[:2] }, probeMembershipDisappearanceUnconfirmed},
		{"extra-outside-group", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) { *g = append(*g, 201) }, probeMembershipBinding},
		{"missing-RSS", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) { *s = (*s)[:5] }, probeMembershipDisappearanceUnconfirmed},
		{"extra-RSS", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) {
			*s = append(*s, probeMembershipSample(999, 71, 1))
		}, probeMembershipUnowned},
		{"sample-PID-reuse", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) {
			(*s)[4].Process.Seconds++
			(*s)[4].Process.AfterSeconds++
		}, probeMembershipReuse},
		{"sample-UID-binding", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) {
			(*s)[4].Process.UID++
			(*s)[4].Process.AfterUID++
		}, probeMembershipBinding},
		{"sample-PGID-binding", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) {
			(*s)[4].Process.PGID++
			(*s)[4].Process.AfterPGID++
		}, probeMembershipBinding},
		{"duplicate-RSS-conflict", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) {
			v := (*s)[4]
			v.Process.RSS++
			*s = append(*s, v)
		}, probeMembershipConflict},
		{"partial-RSS", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) {
			(*s)[4].Calls[6].Count = 15
			(*s)[4].Calls[6].Result = 15
		}, probeMembershipProcessInvalid},
		{"zero-RSS", func(r *[]probeRegistrationRow, g *[]uint64, s *[]probeRaw) { (*s)[4].Process.RSS = 0 }, probeMembershipExitUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows, group, samples := probeMembershipFixture()
			tc.edit(&rows, &group, &samples)
			got, f := probeCompareMembership(71, rows, group, samples)
			if got != (probeMembershipAccounting{}) || f.reason != tc.want {
				t.Fatalf("accounting=%+v refusal=%+v want=%d", got, f, tc.want)
			}
		})
	}
}

func TestProbeMembershipAuthority(t *testing.T) {
	// Fully matching synthetic rows and kernel-shaped facts do not grant origin,
	// live-peer/writer-lock/parent-child ownership, freshness or admission.
	rows, group, samples := probeMembershipFixture()
	if got, f := probeCompareMembership(71, rows, group, samples); got.rss != 210 || f.reason != probeMembershipRegistrationUnavailable {
		t.Fatalf("synthetic input issued authority: %+v %+v", got, f)
	}
	if got, f := (probeBackend{}).membership(); got != (probeMembershipAccounting{}) || f.reason != probeMembershipRegistrationUnavailable {
		t.Fatalf("missing production authority accepted: %+v %+v", got, f)
	}
	for _, status := range []uint64{0, 1, 2, 3, 5, math.MaxUint32} {
		t.Run("opaque-status-"+strconv.FormatUint(status, 10), func(t *testing.T) {
			rows, group, samples := probeMembershipFixture()
			samples[4].Process.RSS = 0
			samples[4].Process.Status = status
			got, f := probeCompareMembership(71, rows, group, samples)
			if got != (probeMembershipAccounting{}) || f.reason != probeMembershipExitUnavailable || f.processReason != probeProcessZeroRSSUnconfirmed {
				t.Fatalf("status granted exit: %+v %+v", got, f)
			}
		})
	}
}
