//go:build darwin && arm64 && cgo

#include "probe_darwin.h"
#include <errno.h>
#include <stddef.h>
#include <mach/mach.h>
#include <sys/sysctl.h>
#include <sys/proc_info.h>
#include <libproc.h>
#define END(T, F) (offsetof(T, F) + sizeof(((T *)0)->F))
#define SHAPE(U, MIN, MAX, K) {0, 0, 0, U, MIN, MAX, K, 0}
void pr_layout(pr_raw *out) {
    *out = (pr_raw){.calls = {
        SHAPE(1, sizeof(uint64_t), sizeof(uint64_t), 0),
        SHAPE(1, END(struct xsw_usage, xsu_pagesize), sizeof(struct xsw_usage), 0),
        SHAPE(1, sizeof(int), sizeof(int), 0),
        SHAPE(sizeof(vm_size_t), sizeof(vm_size_t), sizeof(vm_size_t), 2),
        SHAPE(sizeof(integer_t), END(vm_statistics64_data_t, swapouts), sizeof(vm_statistics64_data_t), 0),
        SHAPE(1, END(struct proc_bsdinfo, pbi_start_tvusec), sizeof(struct proc_bsdinfo), 1),
        SHAPE(1, END(struct proc_taskinfo, pti_resident_size), sizeof(struct proc_taskinfo), 1),
        SHAPE(1, END(struct proc_bsdinfo, pbi_start_tvusec), sizeof(struct proc_bsdinfo), 1),
        SHAPE(1, 0, 0, 2)
    }};
}
void pr_acquire(int32_t pid, pr_raw *out) {
    uint64_t total = 0;
    int pressure = 0;
    struct xsw_usage swap = {0};
    vm_size_t page = 0;
    vm_statistics64_data_t vm = {0};
    struct proc_bsdinfo before = {0}, after = {0};
    struct proc_taskinfo task = {0};
    void *buffers[3] = {&total, &swap, &pressure};
    const char *names[3] = {"hw.memsize", "vm.swapusage", "kern.memorystatus_vm_pressure_level"};
    pr_layout(out);
    for (int i = 0; i < 3; i++) {
        pr_call *c = &out->calls[i];
        size_t length = c->capacity;
        c->result = sysctlbyname(names[i], buffers[i], &length, NULL, 0);
        c->error = c->result ? errno : 0;
        c->count = length;
        c->attempted = 1;
        if (c->result) {
            goto emit;
        }
    }
    host_t host = mach_host_self();
    out->calls[3].result = host_page_size(host, &page);
    out->calls[3].count = 1; // Declared typed width; this API returns no count.
    out->calls[3].attempted = 1;
    if (out->calls[3].result == KERN_SUCCESS) {
        mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
        out->calls[4].result = host_statistics64(host, HOST_VM_INFO64, (host_info64_t)&vm, &count);
        out->calls[4].count = count;
        out->calls[4].attempted = 1;
    }
    out->calls[8].result = mach_port_deallocate(mach_task_self(), host);
    out->calls[8].attempted = 1;
    if (out->calls[3].result || out->calls[4].result || out->calls[8].result) {
        goto emit;
    }
    void *processes[3] = {&before, &task, &after};
    int flavors[3] = {PROC_PIDTBSDINFO, PROC_PIDTASKINFO, PROC_PIDTBSDINFO};
    for (int i = 0; i < 3; i++) {
        pr_call *c = &out->calls[5+i];
        c->result = proc_pidinfo(pid, flavors[i], 0, processes[i], c->capacity);
        c->error = c->result <= 0 ? errno : 0;
        c->count = c->result > 0 ? c->result : 0;
        c->attempted = 1;
        if (c->result <= 0) {
            goto emit;
        }
    }
emit:
    out->memory = (pr_memory){total, page, vm.free_count, vm.inactive_count, vm.speculative_count, vm.purgeable_count,
        swap.xsu_total, swap.xsu_avail, swap.xsu_used, swap.xsu_pagesize, vm.swapouts, pressure};
    out->process = (pr_process){before.pbi_pid, before.pbi_uid, before.pbi_pgid, before.pbi_status,
        before.pbi_start_tvsec, before.pbi_start_tvusec, task.pti_resident_size, after.pbi_pid,
        after.pbi_uid, after.pbi_pgid, after.pbi_start_tvsec, after.pbi_start_tvusec};
}

#include <limits.h>
_Static_assert(sizeof(pid_t) == sizeof(int32_t), "PID buffer width");
_Static_assert(sizeof(pid_t) == sizeof(int), "libproc count divisor");
void pr_group_layout(pr_call *out) {
    *out = (pr_call)SHAPE(sizeof(pid_t), 0, 0, 3);
}
void pr_group_list(int32_t pgid, int32_t *pids, uint64_t capacity, pr_call *out) {
    pr_group_layout(out);
    // capacity is elements. Never narrow an overflowing byte count to int.
    if (pgid <= 0 || capacity > INT_MAX / sizeof(pid_t) ||
        ((pids == NULL) != (capacity == 0))) {
        out->result = -1;
        out->error = EINVAL;
        return;
    }
    out->capacity = capacity * sizeof(pid_t);
    errno = 0;
    out->result = proc_listpgrppids((pid_t)pgid, pids, (int)out->capacity);
    out->error = errno;
    out->count = out->result > 0 ? (uint64_t)out->result : 0;
    out->attempted = 1;
}
// Separate per-member acquisition: no pressure/memory query, argv or environment.
void pr_process_acquire(int32_t pid, pr_raw *out) {
    struct proc_bsdinfo before = {0}, after = {0};
    struct proc_taskinfo task = {0};
    void *buffers[3] = {&before, &task, &after};
    int flavors[3] = {PROC_PIDTBSDINFO, PROC_PIDTASKINFO, PROC_PIDTBSDINFO};
    pr_layout(out);
    for (int i = 0; i < 3; i++) {
        pr_call *c = &out->calls[5+i];
        errno = 0;
        c->result = proc_pidinfo(pid, flavors[i], 0, buffers[i], (int)c->capacity);
        c->error = errno;
        c->count = c->result > 0 ? (uint64_t)c->result : 0;
        c->attempted = 1;
        // A malformed/denied read stops this member without another native read.
        if (c->error || c->result < (int)c->required || c->result > (int)c->capacity) {
            break;
        }
    }
    out->process = (pr_process){before.pbi_pid, before.pbi_uid, before.pbi_pgid, before.pbi_status,
        before.pbi_start_tvsec, before.pbi_start_tvusec, task.pti_resident_size, after.pbi_pid,
        after.pbi_uid, after.pbi_pgid, after.pbi_start_tvsec, after.pbi_start_tvusec};
}
