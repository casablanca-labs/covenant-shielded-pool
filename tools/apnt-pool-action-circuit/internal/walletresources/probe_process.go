//go:build darwin && arm64 && cgo

package walletresources

/*
#include <sys/types.h>
#include <sys/proc_info.h>
*/
import "C"
import "unsafe"

type probeProcessReason uint8

const (
	probeProcessMissing probeProcessReason = iota + 1
	probeProcessReadError
	probeProcessLayout
	probeProcessUnit
	probeProcessShape
	probeProcessShort
	probeProcessOversized
	probeProcessReturnCount
	probeProcessIdentifier
	probeProcessRange
	probeProcessTime
	probeProcessStartUnconfirmed
	probeProcessReuse
	probeProcessDrift
	probeProcessZeroRSSUnconfirmed
	probeProcessScopeUnconfirmed
)

type probeProcessFacts struct {
	raw   probeRawProcess
	calls [3]probeRawCall
}
type probeProcessLimits struct {
	pid, uid, pgid, status, seconds, micros, rss, result uint64
	bsdEnd, bsdSize, taskEnd, taskSize                   uint64
}

func probeProcessUnsignedLimit(size uintptr) uint64 {
	if size == 0 || size > 8 {
		return 0
	}
	return ^uint64(0) >> (64 - size*8)
}

// Only compiler-bound field widths: no native function or process query.
func probeProcessNativeLimits() probeProcessLimits {
	var b C.struct_proc_bsdinfo
	var t C.struct_proc_taskinfo
	pid := probeProcessUnsignedLimit(unsafe.Sizeof(C.pid_t(0))) >> 1
	return probeProcessLimits{
		pid:      min(pid, probeProcessUnsignedLimit(unsafe.Sizeof(b.pbi_pid))),
		pgid:     min(pid, probeProcessUnsignedLimit(unsafe.Sizeof(b.pbi_pgid))),
		uid:      probeProcessUnsignedLimit(unsafe.Sizeof(b.pbi_uid)),
		status:   probeProcessUnsignedLimit(unsafe.Sizeof(b.pbi_status)),
		seconds:  probeProcessUnsignedLimit(unsafe.Sizeof(b.pbi_start_tvsec)),
		micros:   probeProcessUnsignedLimit(unsafe.Sizeof(b.pbi_start_tvusec)),
		rss:      probeProcessUnsignedLimit(unsafe.Sizeof(t.pti_resident_size)),
		result:   probeProcessUnsignedLimit(unsafe.Sizeof(C.int(0))) >> 1,
		bsdEnd:   uint64(unsafe.Offsetof(b.pbi_start_tvusec) + unsafe.Sizeof(b.pbi_start_tvusec)),
		bsdSize:  uint64(unsafe.Sizeof(b)),
		taskEnd:  uint64(unsafe.Offsetof(t.pti_resident_size) + unsafe.Sizeof(t.pti_resident_size)),
		taskSize: uint64(unsafe.Sizeof(t)),
	}
}

// sdk is B1's compiled layout, not wire data or proof of input origin.
func probeProcess(v probeRaw, sdk probeRaw) (probeProcessFacts, probeProcessReason) {
	var empty probeProcessFacts
	r := probeProcessNativeLimits()
	if r.pid == 0 || r.uid == 0 || r.pgid == 0 || r.status == 0 ||
		r.seconds == 0 || r.micros == 0 || r.rss == 0 || r.result == 0 || sdk.Calls[5] != sdk.Calls[7] {
		return empty, probeProcessLayout
	}
	for _, i := range []int{5, 6, 7} {
		c, w := v.Calls[i], sdk.Calls[i]
		required, capacity := r.bsdEnd, r.bsdSize
		if i == 6 {
			required, capacity = r.taskEnd, r.taskSize
		}
		if w.Required != required || w.Capacity != capacity {
			return empty, probeProcessLayout
		}
		if w.Unit != 1 || w.Kind != 1 || w.Required == 0 || w.Required > w.Capacity ||
			w.Capacity > r.result || w.Attempted != 0 || w.Result != 0 || w.Errno != 0 || w.Count != 0 {
			return empty, probeProcessLayout
		}
		if c.Attempted == 0 {
			return empty, probeProcessMissing
		}
		if c.Unit != w.Unit {
			return empty, probeProcessUnit
		}
		if c.Kind != w.Kind || c.Required != w.Required || c.Capacity != w.Capacity {
			return empty, probeProcessShape
		}
		switch c.availability() {
		case probeAvailable:
		case probeReadError:
			return empty, probeProcessReadError
		case probeShort:
			return empty, probeProcessShort
		case probeOversized:
			return empty, probeProcessOversized
		default:
			return empty, probeProcessShape
		}
		if uint64(c.Result) != c.Count || uint64(c.Result) > r.result {
			return empty, probeProcessReturnCount
		}
	}
	p := v.Process
	// UID zero is raw data; positive PID/PGID values grant no ownership.
	if p.PID == 0 || p.AfterPID == 0 || p.PGID == 0 || p.AfterPGID == 0 {
		return empty, probeProcessIdentifier
	}
	if p.PID > r.pid || p.AfterPID > r.pid || p.PGID > r.pgid || p.AfterPGID > r.pgid ||
		p.UID > r.uid || p.AfterUID > r.uid || p.Status > r.status || p.RSS > r.rss ||
		p.Seconds > r.seconds || p.AfterSeconds > r.seconds || p.Micros > r.micros || p.AfterMicros > r.micros {
		return empty, probeProcessRange
	}
	if p.Micros >= 1_000_000 || p.AfterMicros >= 1_000_000 {
		return empty, probeProcessTime
	}
	if (p.Seconds == 0 && p.Micros == 0) || (p.AfterSeconds == 0 && p.AfterMicros == 0) {
		return empty, probeProcessStartUnconfirmed
	}
	if p.PID != p.AfterPID || p.Seconds != p.AfterSeconds || p.Micros != p.AfterMicros {
		return empty, probeProcessReuse
	}
	if p.UID != p.AfterUID || p.PGID != p.AfterPGID {
		return empty, probeProcessDrift
	}
	// Opaque status integers never establish confirmed exit or live membership.
	if p.RSS == 0 {
		return empty, probeProcessZeroRSSUnconfirmed
	}
	return probeProcessFacts{raw: p, calls: [3]probeRawCall{v.Calls[5], v.Calls[6], v.Calls[7]}}, probeProcessScopeUnconfirmed
}
