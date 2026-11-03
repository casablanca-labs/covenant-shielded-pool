//go:build darwin && arm64 && cgo

package walletresources

import (
	"math"
	"slices"
)

type probeMembershipReason uint8

const (
	probeMembershipRegistrationUnavailable probeMembershipReason = iota + 1
	probeMembershipLayout
	probeMembershipRead
	probeMembershipShape
	probeMembershipCount
	probeMembershipSize
	probeMembershipTruncated
	probeMembershipIdentifier
	probeMembershipChanged
	probeMembershipDisappearanceUnconfirmed
	probeMembershipProcessInvalid
	probeMembershipExitUnavailable
	probeMembershipReuse
	probeMembershipBinding
	probeMembershipRole
	probeMembershipUnowned
	probeMembershipConflict
	probeMembershipOverflow
)

type probeMembershipFailure struct {
	reason        probeMembershipReason
	processReason probeProcessReason
	call          probeRawCall // Exact failing native result/count/errno, when present.
}

type probeGroupObservation struct {
	pgid      uint64
	pids      []uint64
	processes []probeRaw
	calls     []probeRawCall
}

// This collector can be exercised with synthetic readers. Its result never
// authenticates origin, registration, parent/child ownership or confirmed exit.
type probeMembershipReader interface {
	group(uint64, []int32) probeRawCall
	process(uint64) probeRaw
}

// Allocation bound only, not a claimed Darwin PID or process-count limit.
const probeMembershipMaxPIDs = 65_536

func probeGroupCall(c probeRawCall, capacity uint64) probeMembershipFailure {
	fail := func(r probeMembershipReason) probeMembershipFailure {
		return probeMembershipFailure{reason: r, call: c}
	}
	sdk := probeMembershipNativeLayout()
	limits := probeProcessNativeLimits()
	if sdk.Unit == 0 || sdk.Unit != 4 || sdk.Kind != 3 || sdk.Required != 0 || sdk.Capacity != 0 ||
		sdk.Attempted != 0 || sdk.Result != 0 || sdk.Errno != 0 || sdk.Count != 0 {
		return fail(probeMembershipLayout)
	}
	if c.Errno != 0 || c.Result < 0 {
		return fail(probeMembershipRead)
	}
	if c.Attempted != 1 || c.Kind != sdk.Kind || c.Unit != sdk.Unit || c.Required != 0 ||
		capacity > limits.result/sdk.Unit || c.Capacity != capacity*sdk.Unit {
		return fail(probeMembershipShape)
	}
	if c.Count > math.MaxUint64/c.Unit || c.Count*c.Unit > limits.result {
		return fail(probeMembershipSize)
	}
	if uint64(c.Result) != c.Count || uint64(c.Result) > limits.result {
		return fail(probeMembershipCount)
	}
	// A NULL-buffer result is a capacity estimate, not group membership/count.
	if capacity == 0 {
		if c.Count == 0 || c.Count > probeMembershipMaxPIDs {
			return fail(probeMembershipSize)
		}
	} else if c.Count >= capacity {
		// Even equality may mean truncation. Do not retry a partial acquisition.
		return fail(probeMembershipTruncated)
	}
	return probeMembershipFailure{}
}

func probeGroupPIDs(reader probeMembershipReader, pgid uint64, capacity uint64) ([]uint64, probeRawCall, probeMembershipFailure) {
	buf := make([]int32, int(capacity))
	c := reader.group(pgid, buf)
	if f := probeGroupCall(c, capacity); f.reason != 0 {
		return nil, c, f
	}
	out := make([]uint64, 0, c.Count)
	for _, pid := range buf[:int(c.Count)] {
		if pid <= 0 || uint64(pid) > probeProcessNativeLimits().pid {
			return nil, c, probeMembershipFailure{reason: probeMembershipIdentifier, call: c}
		}
		out = append(out, uint64(pid))
	}
	slices.Sort(out)
	return slices.Compact(out), c, probeMembershipFailure{}
}

func probeProcessFailure(raw probeRaw, why probeProcessReason) probeMembershipFailure {
	f := probeMembershipFailure{reason: probeMembershipProcessInvalid, processReason: why}
	if why == probeProcessZeroRSSUnconfirmed {
		f.reason = probeMembershipExitUnavailable
	}
	for _, slot := range []int{5, 6, 7} {
		c := raw.Calls[slot]
		if c.availability() != probeAvailable || c.Result < 0 || uint64(c.Result) != c.Count {
			f.call = c
			break
		}
	}
	return f
}

func probeCollectGroup(reader probeMembershipReader, pgid uint64) (probeGroupObservation, probeMembershipFailure) {
	fail := func(r probeMembershipReason) (probeGroupObservation, probeMembershipFailure) {
		return probeGroupObservation{}, probeMembershipFailure{reason: r}
	}
	if pgid == 0 || pgid > probeProcessNativeLimits().pgid {
		return fail(probeMembershipIdentifier)
	}
	sdk, _ := (probeBackend{}).layout() // SDK geometry only, no native query.
	var calls []probeRawCall
	previous := map[uint64]probeProcessIdentity{}
	var lastEnumeration []uint64
	for attempt := 0; attempt < 2; attempt++ {
		size := reader.group(pgid, nil)
		calls = append(calls, size)
		if f := probeGroupCall(size, 0); f.reason != 0 {
			return probeGroupObservation{}, f
		}
		before, c, f := probeGroupPIDs(reader, pgid, size.Count)
		calls = append(calls, c)
		if f.reason != 0 {
			return probeGroupObservation{}, f
		}
		for _, pid := range lastEnumeration {
			if _, present := slices.BinarySearch(before, pid); !present {
				return fail(probeMembershipDisappearanceUnconfirmed)
			}
		}
		if len(before) == 0 {
			return fail(probeMembershipDisappearanceUnconfirmed)
		}
		processes := make([]probeRaw, 0, len(before))
		for _, pid := range before {
			raw := reader.process(pid)
			facts, why := probeProcess(raw, sdk)
			if why != probeProcessScopeUnconfirmed {
				return probeGroupObservation{}, probeProcessFailure(raw, why)
			}
			if facts.raw.PID != pid || facts.raw.PGID != pgid {
				return fail(probeMembershipBinding)
			}
			if old, seen := previous[pid]; seen && old != probeIdentity(facts.raw) {
				if old.seconds != facts.raw.Seconds || old.micros != facts.raw.Micros {
					return fail(probeMembershipReuse)
				}
				return fail(probeMembershipBinding)
			}
			previous[pid] = probeIdentity(facts.raw)
			processes = append(processes, raw)
		}
		after, c, f := probeGroupPIDs(reader, pgid, size.Count)
		calls = append(calls, c)
		if f.reason != 0 {
			return probeGroupObservation{}, f
		}
		for _, pid := range before {
			if _, present := slices.BinarySearch(after, pid); !present {
				// Repeating must never erase an unconfirmed disappearance.
				return fail(probeMembershipDisappearanceUnconfirmed)
			}
		}
		if slices.Equal(before, after) {
			return probeGroupObservation{pgid: pgid, pids: before, processes: processes, calls: calls}, probeMembershipFailure{}
		}
		lastEnumeration = after
		// Only an actual changed enumeration (additions) permits one repeat.
	}
	return fail(probeMembershipChanged)
}

type probeProcessIdentity struct{ pid, seconds, micros, uid, pgid uint64 }

func probeIdentity(p probeRawProcess) probeProcessIdentity {
	return probeProcessIdentity{p.PID, p.Seconds, p.Micros, p.UID, p.PGID}
}
func (id probeProcessIdentity) valid() bool {
	l := probeProcessNativeLimits()
	return id.pid > 0 && id.pid <= l.pid && id.pgid > 0 && id.pgid <= l.pgid && id.uid <= l.uid &&
		id.seconds <= l.seconds && id.micros <= l.micros && id.micros < 1_000_000 && (id.seconds != 0 || id.micros != 0)
}

type probeMemberRole uint8

const (
	probeRoleWallet probeMemberRole = iota + 1
	probeRoleAdapter
	probeRoleGuardian
	probeRoleSampler
	probeRoleLeader
	probeRoleAdmission
	probeRoleWorker
	probeRoleHelper
)

type probeRoleSlot struct {
	role   probeMemberRole
	helper uint64 // Nonzero only for independently registered helper slots.
}

// Descriptive comparison input only. There is no caller-owned/exited/current
// bit and no constructor that upgrades these values to owned registration.
type probeRegistrationRow struct {
	slot     probeRoleSlot
	identity probeProcessIdentity
}
type probeMembershipAccounting struct{ rss, processes uint64 }

// Pure comparison/arithmetic, NEVER an ownership or origin issuer. Even a fully
// matching input returns RegistrationUnavailable. The authenticated live peer,
// writer-lock and owned parent/child registration producer is outside this scope.
func probeCompareMembership(pgid uint64, rows []probeRegistrationRow, group []uint64, samples []probeRaw) (probeMembershipAccounting, probeMembershipFailure) {
	fail := func(r probeMembershipReason) (probeMembershipAccounting, probeMembershipFailure) {
		return probeMembershipAccounting{}, probeMembershipFailure{reason: r}
	}
	if len(rows) == 0 {
		return fail(probeMembershipRegistrationUnavailable)
	}
	if pgid == 0 || pgid > probeProcessNativeLimits().pgid {
		return fail(probeMembershipIdentifier)
	}
	roles := map[probeRoleSlot]bool{}
	registered := map[uint64]probeProcessIdentity{}
	for _, row := range rows {
		s, id := row.slot, row.identity
		if s.role < probeRoleWallet || s.role > probeRoleHelper || (s.role == probeRoleHelper) != (s.helper != 0) || roles[s] {
			return fail(probeMembershipRole)
		}
		roles[s] = true
		if !id.valid() {
			return fail(probeMembershipIdentifier)
		}
		if old, ok := registered[id.pid]; ok && old != id {
			if old.seconds != id.seconds || old.micros != id.micros {
				return fail(probeMembershipReuse)
			}
			return fail(probeMembershipBinding)
		}
		registered[id.pid] = id
		if s.role == probeRoleLeader && (id.pid != pgid || id.pgid != pgid) {
			return fail(probeMembershipBinding)
		}
	}
	for _, role := range []probeMemberRole{probeRoleWallet, probeRoleAdapter, probeRoleGuardian, probeRoleSampler, probeRoleLeader} {
		if !roles[probeRoleSlot{role: role}] {
			return fail(probeMembershipRole)
		}
	}
	if roles[probeRoleSlot{role: probeRoleAdmission}] && roles[probeRoleSlot{role: probeRoleWorker}] {
		return fail(probeMembershipRole)
	}
	enumerated := map[uint64]bool{}
	for _, pid := range group {
		id, ok := registered[pid]
		if !ok {
			return fail(probeMembershipUnowned)
		}
		if id.pgid != pgid {
			return fail(probeMembershipBinding)
		}
		enumerated[pid] = true
	}
	for pid, id := range registered {
		if id.pgid == pgid && !enumerated[pid] {
			return fail(probeMembershipDisappearanceUnconfirmed)
		}
	}
	sdk, _ := (probeBackend{}).layout()
	seen := map[uint64]probeRawProcess{}
	var total probeMembershipAccounting
	for _, raw := range samples {
		facts, why := probeProcess(raw, sdk)
		if why != probeProcessScopeUnconfirmed {
			return probeMembershipAccounting{}, probeProcessFailure(raw, why)
		}
		p := facts.raw
		id, ok := registered[p.PID]
		if !ok {
			return fail(probeMembershipUnowned)
		}
		if p.Seconds != id.seconds || p.Micros != id.micros {
			return fail(probeMembershipReuse)
		}
		if probeIdentity(p) != id {
			return fail(probeMembershipBinding)
		}
		if old, duplicate := seen[p.PID]; duplicate {
			if old != p {
				return fail(probeMembershipConflict)
			}
			continue // Identical PID/start observations and shared roles count once.
		}
		if total.rss > math.MaxUint64-p.RSS {
			return fail(probeMembershipOverflow)
		}
		total.rss += p.RSS
		total.processes++
		seen[p.PID] = p
	}
	if len(seen) != len(registered) {
		return fail(probeMembershipDisappearanceUnconfirmed)
	}
	// Shared-page RSS may exceed physical T; no total-memory cap or subtraction.
	return total, probeMembershipFailure{reason: probeMembershipRegistrationUnavailable}
}

// Production has no authenticated registration producer yet. Refuse BEFORE any
// process read; arbitrary PIDs/rows/booleans cannot select the acquisition path.
func (probeBackend) membership() (probeMembershipAccounting, probeMembershipFailure) {
	return probeMembershipAccounting{}, probeMembershipFailure{reason: probeMembershipRegistrationUnavailable}
}
