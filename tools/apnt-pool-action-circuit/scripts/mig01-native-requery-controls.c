/* Ordinary API-sequence controls only. No real process query or live input.
 * Include the actual reader; production has no injection or selector hook. */
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
static int query_sysctl(int *, unsigned, void *, size_t *, void *, size_t);
static int query_path(int, void *, uint32_t);
static int query_task(int, int, uint64_t, void *, int);
static int query_clock(clockid_t, struct timespec *);
static int query_sleep(const struct timespec *, struct timespec *);
static void *query_calloc(size_t, size_t);
static char *query_strdup(const char *);
static void query_free(void *);
#define sysctl query_sysctl
#define proc_pidpath query_path
#define proc_pidinfo query_task
#define clock_gettime query_clock
#define nanosleep query_sleep
#define calloc query_calloc
#define strdup query_strdup
#define free query_free
#define main reader_main
#ifndef REQUERY_READER
#define REQUERY_READER "../../pool-action-modules/private-runner-process.c"
#endif
#include REQUERY_READER
#undef main
#undef calloc
#undef strdup
#undef free

static const char *scenario;
static unsigned arguments, additional, confirmations, paths, tasks, waits, clocks;
static unsigned row_calls[32], row_confirmations[32], resets, argument_wipes, identity_wipes;
static unsigned char *argument_storage;
static char *identity_storage;
static size_t identity_size;
static uint64_t now = 1000000000, wait_values[32];
static unsigned issue_checks;
static unsigned active_row;
static int is(const char *name) { return !strcmp(scenario, name); }
static int has(const char *name) { return strstr(scenario, name) != NULL; }
static int zero(const void *bytes, size_t size) {
    const unsigned char *at = bytes;
    while (size--) if (*at++) return 0;
    return 1;
}
static void row(struct kinfo_proc *value, int pid) {
    memset(value, 0, sizeof(*value)); value->kp_proc.p_pid = pid;
    value->kp_proc.p_stat = SRUN; value->kp_eproc.e_ucred.cr_uid = geteuid();
    value->kp_proc.p_starttime.tv_sec = 123; value->kp_proc.p_starttime.tv_usec = 456;
    if (has("foreign")) value->kp_eproc.e_ucred.cr_uid++;
}
static void *query_calloc(size_t count, size_t size) {
    void *value = calloc(count, size);
    if (size == 4096 && count == 1) argument_storage = value;
    return value;
}
static char *query_strdup(const char *value) {
    if (strstr(value, "SYNTHETIC_ARG_CANARY") || strstr(value, "SYNTHETIC_ENV_CANARY")) resets++;
    if (is("identity-allocation") || is("foreign-allocation")) { errno = ENOMEM; return NULL; }
    identity_storage = strdup(value); identity_size = strlen(value) + 1;
    if (is("recovery-below")) now += 239999999;
    if (is("recovery-at")) now += 240000000;
    if ((is("alternating-episodes") || is("cumulative-episodes")) && active_row%2 == 0) now += 50000000;
    return identity_storage;
}
static void query_free(void *value) {
    if (value && value == argument_storage) { if (!zero(value, 4096)) resets++; argument_wipes++; argument_storage = NULL; }
    if (value && value == identity_storage) { if (!zero(value, identity_size)) resets++; identity_wipes++; identity_storage = NULL; }
    free(value);
}
static int query_clock(clockid_t kind, struct timespec *value) {
    if (kind != CLOCK_MONOTONIC) resets++;
    clocks++;
    if (is("issue-boundary") && confirmations == 2 && arguments == 1 && ++issue_checks == 3) now += 250000000;
    if (is("clock-error")) { errno = EIO; return -1; }
    if (is("clock-backwards") && clocks == 2) now -= 1;
    value->tv_sec = (time_t)(now / 1000000000); value->tv_nsec = (long)(now % 1000000000);
    if (is("clock-negative")) value->tv_sec = -1;
    if (is("clock-bad-nsec")) value->tv_nsec = 1000000000;
    if (is("clock-negative-nsec")) value->tv_nsec = -1;
    if (is("clock-overflow")) value->tv_sec = (time_t)(UINT64_MAX / 1000000000 + 1);
    if (is("wait-overflow")) { uint64_t time = UINT64_MAX-5; value->tv_sec = (time_t)(time/1000000000); value->tv_nsec = (long)(time%1000000000); }
    return 0;
}
static int query_sleep(const struct timespec *request, struct timespec *remaining) {
    (void)remaining;
    if (request->tv_sec != 0 || request->tv_nsec <= 0 || request->tv_nsec > 40000000 || errno) resets++;
    if (waits < 32) wait_values[waits] = (uint64_t)request->tv_nsec;
    waits++;
    if (is("wait-error")) { errno = EIO; return -1; }
    if (is("wait-no-errno")) { errno = 0; return -1; }
    if (is("wait-interrupted") && waits == 1) { now += 4000000; errno = EINTR; return -1; }
    if (is("wait-interrupted-budget")) { now += 250000000; errno = EINTR; return -1; }
    now += (uint64_t)request->tv_nsec;
    return 0;
}
static int query_path(int pid, void *out, uint32_t size) {
    (void)pid; paths++;
    return snprintf(out, size, "/synthetic/neutral");
}
static int fixture_name(void *out, size_t size) { return snprintf(out, size, "neutral"); }
static int query_task(int pid, int flavor, uint64_t arg, void *out, int size) {
    (void)pid; (void)flavor; (void)arg; tasks++;
    if (is("rss-failure")) { errno = EIO; return 0; }
    memset(out, 0, (size_t)size); ((struct proc_taskinfo *)out)->pti_resident_size = 123 * 1024;
    return size;
}
static int query_sysctl(int *mib, unsigned length, void *out, size_t *size, void *in, size_t insize) {
    (void)length; (void)in; (void)insize;
    if (mib[1] == KERN_ARGMAX) { *(int *)out = 4096; *size = sizeof(int); return 0; }
    if (mib[1] == KERN_PROC && mib[2] == KERN_PROC_ALL) {
        int count = is("quota") ? 18 : is("quota-edge") ? 16 : is("many-time") || is("alternating-episodes") ? 6 :
            is("cumulative-episodes") || is("exit-cumulative") ? 10 :
            has("partial") || is("positive-before-exit") || has("-tail") || is("slow-before") ? 2 : 1;
        if (!out) { *size = (size_t)count * sizeof(struct kinfo_proc); return 0; }
        struct kinfo_proc *table = out;
        for (int i = 0; i < count; i++) row(table + i, 700 + i);
        if (is("snapshot-no-birth")) table->kp_proc.p_starttime.tv_sec = 0;
        if (is("snapshot-bad-usec")) table->kp_proc.p_starttime.tv_usec = 1000000;
        if (is("snapshot-negative-usec")) table->kp_proc.p_starttime.tv_usec = -1;
        *size = (size_t)count * sizeof(*table); return 0;
    }
    if (mib[1] == KERN_PROC && mib[2] == KERN_PROC_PID) {
        unsigned which = (unsigned)(mib[3] - 700), call = ++row_confirmations[which]; confirmations++;
        if (is("exit-tail") || is("exit-cumulative")) now += 60000000;
        if (is("confirm-error") || (is("confirm-error-after") && call == 3)) { errno = EPERM; return -1; }
        if (is("confirm-short")) { *size = sizeof(struct kinfo_proc) - 1; return 0; }
        if (is("exit") || is("exit-tail") || is("exit-cumulative") || (is("exit-before") && call == 2) || (is("exit-after") && call == 3) ||
            (is("positive-before-exit") && which == 1)) { *size = 0; return 0; }
        struct kinfo_proc *value = out; row(value, mib[3]); *size = sizeof(*value);
        if (is("confirm-pid")) value->kp_proc.p_pid++;
        if (is("zombie")) value->kp_proc.p_stat = SZOMB;
        if (is("birth-first") || (is("birth-before") && call == 2) || (is("birth-after") && call == 3)) value->kp_proc.p_starttime.tv_usec++;
        if (is("uid-first") || (is("uid-before") && call == 2) || (is("uid-after") && call == 3)) value->kp_eproc.e_ucred.cr_uid++;
        if (is("confirm-no-birth")) value->kp_proc.p_starttime.tv_sec = 0;
        if (is("confirm-state-zero")) value->kp_proc.p_stat = 0;
        if (is("confirm-state-unknown")) value->kp_proc.p_stat = SZOMB+1;
        if (has("state-sleep")) value->kp_proc.p_stat = SSLEEP;
        if (has("state-stop")) value->kp_proc.p_stat = SSTOP;
        if (is("clock-after-confirm")) now += 250000000;
        return 0;
    }
    if (mib[1] == KERN_PROCARGS2) {
        unsigned which = (unsigned)(mib[2] - 700), call = ++row_calls[which]; arguments++;
        active_row=which;
        if (call > 1) additional++;
        if (errno || *size != 4096 || !zero(out, 4096)) resets++;
        int ordinary = ((has("-tail") || is("slow-before")) && which == (unsigned)(is("slow-before") ? 0 : 1)) ||
            ((is("alternating-episodes") || is("cumulative-episodes") || is("exit-cumulative")) && which%2);
        int clean = ordinary || is("valid") || is("identity-allocation") || is("rss-failure") || has("initial-bad") ||
            (which == 0 && (has("partial") || is("positive-before-exit")));
        int denied = is("eperm") || is("eintr") || is("enomem") || is("esrch") || is("efault");
        int failed = !clean && (call <= (has("second") || is("many-time") ? 2u : 1u) || has("persistent") || has("partial") || denied);
        if (failed) {
            if (is("slow-initial-error")) now += 3000000000;
            memset(out, 'S', 16); *size = 16;
            errno = is("eperm") ? EPERM : is("eintr") ? EINTR : is("enomem") ? ENOMEM :
                is("esrch") ? ESRCH : is("efault") ? EFAULT : has("eio") ? EIO : EINVAL;
            return -1;
        }
        if (ordinary) now += 2000000000;
        int count = 2; memcpy(out, &count, sizeof(count));
        const char benign[] = "/synthetic/neutral\0\0neutral\0SYNTHETIC_ARG_CANARY\0SYNTHETIC_ENV_CANARY\0";
        const char alias[] = "/synthetic/neutral\0\0pool-pk-load\0SYNTHETIC_ARG_CANARY\0SYNTHETIC_ENV_CANARY\0";
        const char executable[] = "/synthetic/pool-pk-load\0\0neutral\0SYNTHETIC_ARG_CANARY\0SYNTHETIC_ENV_CANARY\0";
        int matching = has("alias") || has("rss") || (is("positive-before-exit") && which == 0);
        const char *data = matching ? alias : is("executable-only") ? executable : benign;
        size_t data_size = matching ? sizeof(alias) : is("executable-only") ? sizeof(executable) : sizeof(benign);
        memcpy((char *)out + sizeof(count), data, data_size); *size = sizeof(count) + data_size;
        if (has("bad-size")) *size = sizeof(count);
        if (has("bad-large")) *size = 4097;
        if (has("bad-count")) { count = 0; memcpy(out, &count, sizeof(count)); }
        if (has("bad-executable")) { memset((char *)out + sizeof(count), 'X', 16); *size = sizeof(count) + 16; }
        if (has("bad-argv")) { const char bad[] = "/worker\0\0unfinished"; memcpy((char *)out + sizeof(count), bad, sizeof(bad)-1); *size = sizeof(count)+sizeof(bad)-1; }
        if (has("bad-empty")) { const char bad[] = "/worker\0\0\0"; memcpy((char *)out + sizeof(count), bad, sizeof(bad)); *size = sizeof(count)+sizeof(bad); }
        if (has("bad-delimiter") || has("bad-cr") || has("bad-tab"))
            ((char *)out)[sizeof(count) + sizeof("/synthetic/neutral") + 1] = has("bad-cr") ? '\r' : has("bad-tab") ? '\t' : '\n';
        if (is("clock-after-query") && call > 1) now += 250000000;
        errno = ENOTTY; /* Success must not inherit this as a query error. */
        return 0;
    }
    errno = EIO; return -1;
}

int main(int argc, char **argv) {
    if (argc != 3 && argc != 4) return 2;
    scenario = argv[1];
    if (argc == 4) { char *args[] = {"reader", "-axo", argv[2]}; return reader_main(3, args); }
    unsigned fallback_controls = 0;
    if (has("persistent")) {
        char path[128], name[128];
        if (query_path(700, path, sizeof(path)) > 0 && !strcmp(path,"/synthetic/neutral")) fallback_controls++;
        if (fixture_name(name, sizeof(name)) > 0 && !strcmp(name,"neutral")) fallback_controls++;
        paths = 0; /* Count production fallback calls independently below. */
    }
    FILE *captured = tmpfile(); int saved = dup(STDOUT_FILENO);
    if (!captured || saved < 0 || fflush(stdout) || dup2(fileno(captured), STDOUT_FILENO) < 0) return 3;
    /* Inspect the same internal scan body used by the production CLI, without
     * adding a selector or diagnostic field to that CLI. Poisoned input proves
     * the inventory resets its own storage. */
    struct recovery_budget budget = {.additional=99, .active=1, .started=1, .spent=999999999};
    int status = scan_inventory(!strcmp(argv[2], "rss=,comm="), &budget);
    if (fflush(stdout) || dup2(saved, STDOUT_FILENO) < 0 || fseek(captured, 0, SEEK_SET)) return 4;
    close(saved);
    char rows[65536] = {0}; size_t bytes = fread(rows, 1, sizeof(rows)-1, captured); fclose(captured);
    unsigned emitted = 0, named = 0;
    for (size_t i = 0; i < bytes; i++) if (rows[i] == '\n') emitted++;
    for (char *at = rows; (at = strstr(at, " pool-pk-load\n")) != NULL; at++) named++;
    printf("{\"readerStatus\":%d,\"reason\":\"%s\",\"errno\":%d,\"confirmation\":\"%s\",\"confirmationErrno\":%d,\"arguments\":%u,\"additional\":%u,\"confirmations\":%u,\"paths\":%u,\"tasks\":%u,\"waits\":%u,\"elapsedNs\":%llu,\"firstWaitNs\":%llu,\"secondWaitNs\":%llu,\"resetViolations\":%u,\"argumentWipes\":%u,\"identityWipes\":%u,\"rows\":%u,\"namedRows\":%u,\"canaryOutput\":%d,\"fallbackControls\":%u,\"chargedAdditional\":%u,\"recoveryNs\":%llu,\"episodeActive\":%d}\n",
        status, status ? closed_reason : "none", status ? closed_errno : 0,
        status && closed_confirmation ? closed_confirmation : "none", status ? closed_confirmation_errno : 0,
        arguments, additional, confirmations, paths, tasks, waits, (unsigned long long)(now >= 1000000000 ? now-1000000000 : 0),
        (unsigned long long)wait_values[0], (unsigned long long)wait_values[1], resets, argument_wipes, identity_wipes,
        emitted, named, strstr(rows,"SYNTHETIC_ARG_CANARY") != NULL || strstr(rows,"SYNTHETIC_ENV_CANARY") != NULL, fallback_controls,
        budget.additional, (unsigned long long)(budget.spent + (budget.active && now >= budget.started ? now-budget.started : 0)), budget.active);
    return 0;
}
