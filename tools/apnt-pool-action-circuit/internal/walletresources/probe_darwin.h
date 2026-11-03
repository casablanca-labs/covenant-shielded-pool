#ifndef WALLET_RAW_PROBE_H
#define WALLET_RAW_PROBE_H
#include <stdint.h>
typedef struct {
    int64_t result, error;
    uint64_t count, unit, required, capacity, kind, attempted;
} pr_call;
typedef struct {
    uint64_t total, page, free, inactive, speculative, purgeable;
    uint64_t swap_total, swap_available, swap_used, swap_page, swapouts;
    int64_t pressure;
} pr_memory;
typedef struct {
    uint64_t pid, uid, pgid, status, seconds, micros, rss;
    uint64_t after_pid, after_uid, after_pgid, after_seconds, after_micros;
} pr_process;
typedef struct { pr_memory memory; pr_process process; pr_call calls[9]; } pr_raw;
void pr_layout(pr_raw *out);
void pr_acquire(int32_t pid, pr_raw *out);
// Group results are PID counts, while buffers/capacities are bytes.
void pr_group_layout(pr_call *out);
void pr_group_list(int32_t pgid, int32_t *pids, uint64_t capacity, pr_call *out);
void pr_process_acquire(int32_t pid, pr_raw *out);
#endif
