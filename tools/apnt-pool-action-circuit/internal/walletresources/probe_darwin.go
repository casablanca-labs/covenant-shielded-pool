//go:build darwin && arm64 && cgo

package walletresources

/*
#cgo LDFLAGS: -lproc
#include "probe_darwin.h"
#include <mach/mach.h>
#include <sys/sysctl.h>
#include <sys/proc_info.h>
*/
import "C"
import "unsafe"

const probeNativeBuild = true

type probeBackend struct{}

func probeCopyCall(c C.pr_call) probeRawCall {
	return probeRawCall{int64(c.result), int64(c.error), uint64(c.count), uint64(c.unit),
		uint64(c.required), uint64(c.capacity), uint64(c.kind), uint64(c.attempted)}
}
func probeCopyRaw(v C.pr_raw) probeRaw {
	o := probeRaw{Memory: probeRawMemory{uint64(v.memory.total), uint64(v.memory.page), uint64(v.memory.free),
		uint64(v.memory.inactive), uint64(v.memory.speculative), uint64(v.memory.purgeable), uint64(v.memory.swap_total),
		uint64(v.memory.swap_available), uint64(v.memory.swap_used), uint64(v.memory.swap_page), uint64(v.memory.swapouts), int64(v.memory.pressure)},
		Process: probeRawProcess{uint64(v.process.pid), uint64(v.process.uid), uint64(v.process.pgid), uint64(v.process.status),
			uint64(v.process.seconds), uint64(v.process.micros), uint64(v.process.rss), uint64(v.process.after_pid),
			uint64(v.process.after_uid), uint64(v.process.after_pgid), uint64(v.process.after_seconds), uint64(v.process.after_micros)}}
	for i := range o.Calls {
		o.Calls[i] = probeCopyCall(v.calls[i])
	}
	return o
}
func (probeBackend) layout() (probeRaw, [4][2]uint64) {
	var raw C.pr_raw
	C.pr_layout(&raw)
	var s C.struct_xsw_usage
	var v C.vm_statistics64_data_t
	var b C.struct_proc_bsdinfo
	var t C.struct_proc_taskinfo
	return probeCopyRaw(raw), [4][2]uint64{
		{uint64(unsafe.Offsetof(s.xsu_pagesize) + unsafe.Sizeof(s.xsu_pagesize)), uint64(unsafe.Sizeof(s))},
		{uint64(unsafe.Offsetof(v.swapouts) + unsafe.Sizeof(v.swapouts)), uint64(unsafe.Sizeof(v))},
		{uint64(unsafe.Offsetof(b.pbi_start_tvusec) + unsafe.Sizeof(b.pbi_start_tvusec)), uint64(unsafe.Sizeof(b))},
		{uint64(unsafe.Offsetof(t.pti_resident_size) + unsafe.Sizeof(t.pti_resident_size)), uint64(unsafe.Sizeof(t))},
	}
}
func (probeBackend) acquire(pid int32) (probeRaw, code) {
	var v C.pr_raw
	C.pr_acquire(C.int32_t(pid), &v)
	return probeCopyRaw(v), ""
}
func (probeBackend) transfer(c probeRawCall) probeRawCall {
	return probeCopyCall(C.pr_call{result: C.int64_t(c.Result), error: C.int64_t(c.Errno), count: C.uint64_t(c.Count),
		unit: C.uint64_t(c.Unit), required: C.uint64_t(c.Required), capacity: C.uint64_t(c.Capacity), kind: C.uint64_t(c.Kind), attempted: C.uint64_t(c.Attempted)})
}

// This type is constructed only at the native acquisition boundary below.
// Machine origin is not authenticated registration, exit, freshness or admission.
type probeNativeGroup struct{ observation probeGroupObservation }

type probeNativeMembershipReader struct{}

func probeMembershipNativeLayout() probeRawCall {
	var c C.pr_call
	C.pr_group_layout(&c)
	return probeCopyCall(c)
}
func (probeNativeMembershipReader) group(pgid uint64, pids []int32) probeRawCall {
	var c C.pr_call
	var ptr *C.int32_t
	if len(pids) != 0 {
		ptr = (*C.int32_t)(unsafe.Pointer(&pids[0]))
	}
	C.pr_group_list(C.int32_t(pgid), ptr, C.uint64_t(len(pids)), &c)
	return probeCopyCall(c)
}
func (probeNativeMembershipReader) process(pid uint64) probeRaw {
	var raw C.pr_raw
	C.pr_process_acquire(C.int32_t(pid), &raw)
	return probeCopyRaw(raw)
}
func (probeBackend) acquireGroup(pgid uint64) (probeNativeGroup, probeMembershipFailure) {
	// Injection exists only in the unconfirmed collector; arbitrary raw objects
	// have no conversion to this native-origin wrapper.
	observed, failure := probeCollectGroup(probeNativeMembershipReader{}, pgid)
	if failure.reason != 0 {
		return probeNativeGroup{}, failure
	}
	return probeNativeGroup{observation: observed}, probeMembershipFailure{}
}
