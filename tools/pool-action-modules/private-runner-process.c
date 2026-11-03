/* MIG01: the runner's exact read-only process queries, without executing the
 * setuid /bin/ps inside its denied-read profile. Build with the macOS SDK.
 * Parent-query output is consumed privately by the existing guards, never a
 * user report. Global scans expose only pid/RSS and same-UID argv[0] or
 * foreign-UID executable paths, never other arguments or environment.
 * KERN_PROCARGS2's buffer is wiped after use. No input file,
 * wallet or source descriptor is opened here. No setuid or sandbox exception.
 */
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Fixed labels and errno only. No identity, argv, environment or partial row
 * is included in an error. The caller must still reject a nonzero scan. */
static const char *closed_reason = "unclassified";
static int closed_errno;
static const char *closed_confirmation;
static int closed_confirmation_errno;
static int closed_fail(const char *reason, int error, int status) {
    closed_reason = reason;
    closed_errno = error > 0 ? error : 0;
    if (strcmp(reason, "arguments-query")) {
        closed_confirmation = NULL;
        closed_confirmation_errno = 0;
    }
    return status;
}

static void wipe(char *bytes, size_t size) {
    volatile char *at = bytes;
    while (size--) *at++ = 0;
}
static void clear_name(const char **name) {
    if (*name) { wipe((char *)*name, strlen(*name)); free((void *)*name); *name = NULL; }
}

/* One cumulative recovery allowance per inventory. Only unresolved episodes
 * are active: initial eligible failure through confirmation/validation/wipe.
 * Ordinary work after resolution is excluded; accumulated work never resets.
 * Neither this admission bound nor the wait deadline preempts a syscall. */
struct recovery_budget {
    unsigned additional;
    int active;
    uint64_t started;
    uint64_t spent;
};
static int monotonic_ns(uint64_t *now) {
    struct timespec time;
    errno = 0;
    if (clock_gettime(CLOCK_MONOTONIC, &time) != 0) return closed_fail("requery-clock", errno, 0);
    if (time.tv_sec < 0 || time.tv_nsec < 0 || time.tv_nsec >= 1000000000 ||
        (uint64_t)time.tv_sec > (UINT64_MAX - (uint64_t)time.tv_nsec) / 1000000000)
        return closed_fail("requery-clock", 0, 0);
    *now = (uint64_t)time.tv_sec * 1000000000 + (uint64_t)time.tv_nsec;
    return 1;
}
static int recovery_check(struct recovery_budget *budget, uint64_t *time) {
    if (!budget->active) return 1;
    uint64_t now;
    if (!monotonic_ns(&now)) return 0;
    if (now < budget->started) return closed_fail("requery-clock", 0, 0);
    if (budget->spent >= 250000000 || now - budget->started >= 250000000 - budget->spent)
        return closed_fail("requery-budget", 0, 0);
    if (time) *time = now;
    return 1;
}
static int recovery_begin(struct recovery_budget *budget) {
    if (!budget->active) {
        if (!monotonic_ns(&budget->started)) return 0;
        budget->active = 1;
    }
    return recovery_check(budget, NULL);
}
static int recovery_finish(struct recovery_budget *budget) {
    if (!budget->active) return 1;
    uint64_t now;
    if (!recovery_check(budget, &now)) return 0;
    budget->spent += now - budget->started;
    budget->active = 0;
    return 1;
}
static int recovery_wait(struct recovery_budget *budget, uint64_t delay) {
    uint64_t now;
    if (!recovery_check(budget, &now)) return 0;
    if (now > UINT64_MAX - delay) return closed_fail("requery-clock", 0, 0);
    const uint64_t deadline = now + delay;
    while (now < deadline) {
        struct timespec remaining = {0, (long)(deadline - now)};
        errno = 0;
        int status = nanosleep(&remaining, NULL), wait_errno = errno;
        if (!recovery_check(budget, &now)) return 0;
        if (status && wait_errno != EINTR) return closed_fail("requery-wait", wait_errno, 0);
        /* Recompute the remaining delay from the original monotonic deadline,
         * including after EINTR; neither clock nor allowance is reset. */
    }
    return 1;
}

/* -2 distinguishes a failed syscall from a malformed/unconfirmed record.
 * The ordinary process() wrapper preserves its existing tri-state API. */
static int process_query(pid_t pid, struct kinfo_proc *value, int *query_errno) {
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    size_t size = sizeof(*value);
    memset(value, 0, size);
    if (query_errno) *query_errno = 0;
    errno = 0;
    if (sysctl(mib, 4, value, &size, NULL, 0) != 0) {
        if (query_errno) *query_errno = errno > 0 ? errno : 0;
        return -2;
    }
    if (size == 0) return 0; /* Exited since the process-table snapshot. */
    return size == sizeof(*value) && value->kp_proc.p_pid == pid ? 1 : -1;
}

static int process(pid_t pid, struct kinfo_proc *value) {
    int status = process_query(pid, value, NULL);
    return status == -2 ? -1 : status;
}

static int path_of(pid_t pid, char *path, size_t size) {
    memset(path, 0, size);
    int length = proc_pidpath(pid, path, (uint32_t)size);
    return length > 0 && (size_t)length < size && path[0] == '/' &&
        memchr(path, 0, size) != NULL && strchr(path, '\n') == NULL && strchr(path, '\r') == NULL;
}

static int arguments_of(pid_t pid) {
    int mib[] = {CTL_KERN, KERN_ARGMAX};
    int capacity = 0;
    size_t size = sizeof(capacity);
    if (sysctl(mib, 2, &capacity, &size, NULL, 0) != 0 || size != sizeof(capacity) ||
        capacity < (int)sizeof(int) || capacity > 16 * 1024 * 1024) return 1;
    char *bytes = calloc(1, (size_t)capacity);
    if (!bytes) return 1;
    int query[] = {CTL_KERN, KERN_PROCARGS2, pid};
    size = (size_t)capacity;
    int result = 1, argc = 0;
    if (sysctl(query, 3, bytes, &size, NULL, 0) != 0 || size <= sizeof(argc) || size > (size_t)capacity) goto done;
    memcpy(&argc, bytes, sizeof(argc));
    if (argc <= 0 || argc > 4096) goto done;
    char *at = bytes + sizeof(argc), *end = bytes + size;
    char *separator = memchr(at, 0, (size_t)(end - at));
    if (!separator) goto done;
    at = separator + 1; /* Kernel executable path, followed by NUL padding. */
    while (at < end && *at == 0) at++;
    char *start = at;
    /* Validate the complete argv before emitting anything. Environment bytes
     * after argc entries are neither parsed nor emitted. */
    for (int i = 0; i < argc; i++) {
        if (at >= end) goto done;
        separator = memchr(at, 0, (size_t)(end - at));
        if (!separator || memchr(at, '\n', (size_t)(separator - at)) || memchr(at, '\r', (size_t)(separator - at))) goto done;
        at = separator + 1;
    }
    at = start;
    for (int i = 0; i < argc; i++) {
        if (i) putchar(' ');
        fputs(at, stdout);
        at += strlen(at) + 1;
    }
    putchar('\n');
    result = ferror(stdout) ? 1 : 0;
done:
    memset(bytes, 0, (size_t)capacity);
    free(bytes);
    return result;
}

static int single(pid_t pid, const char *field, int both) {
    struct kinfo_proc value;
    char path[PROC_PIDPATHINFO_MAXSIZE];
    if (process(pid, &value) != 1) return 1;
    if (!strcmp(field, "args=")) return arguments_of(pid);
    if ((!strcmp(field, "comm=") || both) && !path_of(pid, path, sizeof(path))) return 1;
    if (both) printf("%d %s\n", value.kp_eproc.e_ppid, path);
    else if (!strcmp(field, "ppid=")) printf("%d\n", value.kp_eproc.e_ppid);
    else printf("%s\n", path);
    return ferror(stdout) ? 1 : 0;
}

/* Match ps comm= for this UID (full argv[0], never truncated p_comm).
 * Foreign-UID argv is unavailable without ps's root privilege: use the full
 * kernel executable path, and refuse if that identity cannot be obtained.
 * Same-UID matching does not also inspect executable names. A foreign-UID
 * matching argv[0] on a nonmatching executable can be missed. This boundary
 * is accepted only for the single-operator dev/Chipnet host (ENG-1436 option
 * A); cross-UID admission belongs to ENG-1446. Any other
 * query/shape failure refuses unless a separate query confirms process exit.
 * 0 = exited/zombie, 1 = name, -1 = unavailable inventory. */
static int same_incarnation(const struct kinfo_proc *snapshot, const struct kinfo_proc *current) {
    return snapshot->kp_proc.p_pid == current->kp_proc.p_pid &&
        snapshot->kp_eproc.e_ucred.cr_uid == geteuid() &&
        current->kp_eproc.e_ucred.cr_uid == snapshot->kp_eproc.e_ucred.cr_uid &&
        snapshot->kp_proc.p_starttime.tv_sec > 0 &&
        snapshot->kp_proc.p_starttime.tv_usec >= 0 && snapshot->kp_proc.p_starttime.tv_usec < 1000000 &&
        current->kp_proc.p_starttime.tv_sec == snapshot->kp_proc.p_starttime.tv_sec &&
        current->kp_proc.p_starttime.tv_usec == snapshot->kp_proc.p_starttime.tv_usec &&
        current->kp_proc.p_stat >= SIDL && current->kp_proc.p_stat <= SZOMB;
}
static int arguments_refusal(int error, int present, int confirmation_errno) {
    closed_confirmation = present == -2 ? "query-error" : present == 1 ? "live" : "unconfirmed";
    closed_confirmation_errno = confirmation_errno;
    return closed_fail("arguments-query", error, -1);
}
static int confirm_recovery(const struct kinfo_proc *snapshot, struct recovery_budget *budget, int error) {
    struct kinfo_proc current;
    int confirmation_errno = 0;
    if (!recovery_check(budget, NULL)) return -1;
    int present = process_query(snapshot->kp_proc.p_pid, &current, &confirmation_errno);
    if (!recovery_check(budget, NULL)) return -1;
    if (!present) return 0;
    if (present != 1) return arguments_refusal(error, present, confirmation_errno);
    if (!same_incarnation(snapshot, &current)) return closed_fail("requery-identity", 0, -1);
    return current.kp_proc.p_stat == SZOMB ? 0 : 1;
}

/* On success, *name owns a separate identity-only allocation. Argument storage
 * is wiped on every exit, including success; the caller frees that identity. */
static int command_of(const struct kinfo_proc *value, char *bytes, size_t capacity, const char **name,
                      struct recovery_budget *budget) {
    pid_t pid = value->kp_proc.p_pid;
    int result = -1;
    *name = NULL;
    wipe(bytes, capacity);
    if (pid == 0 || value->kp_proc.p_stat == SZOMB) return 0;
    if (pid < 0) return closed_fail("pid", 0, -1);
    if (value->kp_eproc.e_ucred.cr_uid != geteuid()) {
        size_t limit = capacity < PROC_PIDPATHINFO_MAXSIZE ? capacity : PROC_PIDPATHINFO_MAXSIZE;
        if (!recovery_check(budget, NULL)) goto done;
        errno = 0;
        int valid = path_of(pid, bytes, limit), path_errno = errno;
        if (!recovery_check(budget, NULL)) goto done;
        if (!valid) {
            struct kinfo_proc current;
            if (!recovery_check(budget, NULL)) goto done;
            int present = process(pid, &current);
            if (!recovery_check(budget, NULL)) goto done;
            result = present == 0 || (present == 1 && current.kp_proc.p_stat == SZOMB) ? 0 : closed_fail("foreign-path", path_errno, -1);
            goto done;
        }
        if (strchr(bytes, '\t')) { closed_fail("foreign-delimiter", 0, -1); goto done; }
        errno = 0;
        *name = strdup(bytes);
        result = *name ? 1 : closed_fail("identity-allocation", errno, -1);
        goto done;
    }
    int mib[] = {CTL_KERN, KERN_PROCARGS2, pid}, argc = 0;
    int query_errno = 0;
    unsigned retries = 0;
    for (;;) {
        size_t size = capacity;
        argc = 0;
        *name = NULL;
        /* Entry and the previous failed attempt leave all argument storage
         * zero; confirmations and waits never write into it. */
        if (!recovery_check(budget, NULL)) goto done;
        /* Charge only a query actually about to be issued. No intervening
         * clock check can turn this into an unissued reservation. */
        if (retries) {
            if (budget->additional >= 16) { closed_fail("requery-limit", 0, -1); goto done; }
            budget->additional++;
        }
        errno = 0;
        int status = sysctl(mib, 3, bytes, &size, NULL, 0);
        query_errno = status ? errno : 0;
        /* Begin immediately after the initial eligible syscall returns, before
         * clearing its buffer or confirming exit; retries keep this episode. */
        if (status && (query_errno == EINVAL || query_errno == EIO) && !recovery_begin(budget)) goto done;
        if (!recovery_check(budget, NULL)) goto done;
        if (!status) {
            if (size <= sizeof(argc) || size > capacity) { closed_fail("arguments-size", 0, -1); goto done; }
            memcpy(&argc, bytes, sizeof(argc));
            if (argc <= 0) { closed_fail("arguments-count", 0, -1); goto done; }
            char *at = bytes + sizeof(argc), *end = bytes + size;
            char *separator = memchr(at, 0, (size_t)(end - at));
            if (!separator) { closed_fail("executable-terminator", 0, -1); goto done; }
            at = separator + 1;
            while (at < end && *at == 0) at++;
            if (at == end || !memchr(at, 0, (size_t)(end - at))) { closed_fail("argv0-terminator", 0, -1); goto done; }
            if (strpbrk(at, "\r\n\t")) { closed_fail("argv0-delimiter", 0, -1); goto done; }
            if (retries) {
                result = confirm_recovery(value, budget, query_errno);
                if (result != 1) goto done;
            }
            errno = 0;
            *name = strdup(at);
            result = *name ? 1 : closed_fail("identity-allocation", errno, -1);
            goto done;
        }
        wipe(bytes, capacity);
        if (query_errno != EINVAL && query_errno != EIO) {
            struct kinfo_proc current;
            int confirmation_errno = 0;
            if (!recovery_check(budget, NULL)) goto done;
            int present = process_query(pid, &current, &confirmation_errno);
            if (!recovery_check(budget, NULL)) goto done;
            result = present == 0 || (present == 1 && current.kp_proc.p_stat == SZOMB) ? 0 :
                arguments_refusal(query_errno, present, confirmation_errno);
            goto done;
        }
        result = confirm_recovery(value, budget, query_errno);
        if (result != 1) goto done;
        result = -1;
        if (retries == 2) { arguments_refusal(query_errno, 1, 0); goto done; }
        if (budget->additional >= 16) { closed_fail("requery-limit", 0, -1); goto done; }
        if (!recovery_wait(budget, retries == 0 ? 10000000 : 40000000)) goto done;
        result = confirm_recovery(value, budget, query_errno);
        if (result != 1) goto done;
        result = -1;
        if (!recovery_check(budget, NULL)) goto done;
        retries++;
    }
done:
    wipe(bytes, capacity);
    if (!(result >= 0 ? recovery_finish(budget) : recovery_check(budget, NULL))) {
        clear_name(name);
        return -1;
    }
    return result;
}

static int scan_inventory(int rss, struct recovery_budget *recovery) {
    /* Local storage is supplied by global_scan; no selector or external hook. */
    memset(recovery, 0, sizeof(*recovery));
    closed_reason = "unclassified";
    closed_errno = 0;
    closed_confirmation = NULL;
    closed_confirmation_errno = 0;
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    struct kinfo_proc *table = NULL;
    size_t size = 0;
    int ready = 0;
    /* Bounded retries for processes starting during allocation. A truncated
     * or failed table never reports a successful empty inventory. */
    for (int attempt = 0; attempt < 4; attempt++) {
        size = 0;
        errno = 0;
        if (sysctl(mib, 4, NULL, &size, NULL, 0) != 0) { closed_fail("process-table-size", errno, 1); break; }
        if (!size || size > 16 * 1024 * 1024) { closed_fail("process-table-size-shape", 0, 1); break; }
        size_t capacity = size + 64 * sizeof(*table);
        free(table); table = calloc(1, capacity);
        if (!table) { closed_fail("process-table-allocation", errno, 1); break; }
        size = capacity;
        errno = 0;
        if (sysctl(mib, 4, table, &size, NULL, 0) == 0) {
            if (size && size < capacity && size % sizeof(*table) == 0) ready = 1;
            else closed_fail("process-table-fetch-shape", 0, 1);
            break;
        }
        closed_fail("process-table-fetch", errno, 1);
        if (errno != ENOMEM) break;
    }
    int argmax = 0;
    size_t argmax_size = sizeof(argmax);
    int args_mib[] = {CTL_KERN, KERN_ARGMAX};
    if (!ready) { free(table); return 1; }
    errno = 0;
    if (sysctl(args_mib, 2, &argmax, &argmax_size, NULL, 0) != 0) {
        int query_errno = errno; free(table); return closed_fail("argmax-query", query_errno, 1);
    }
    if (argmax_size != sizeof(argmax) || argmax <= (int)sizeof(int) || argmax > 16 * 1024 * 1024) {
        free(table); return closed_fail("argmax-shape", 0, 1);
    }
    char *bytes = calloc(1, (size_t)argmax);
    if (!bytes) { int query_errno = errno; free(table); return closed_fail("arguments-allocation", query_errno, 1); }
    int result = 1;
    const char *name = NULL;
    for (size_t i = 0; i < size / sizeof(*table); i++) {
        if (!recovery_check(recovery, NULL)) goto done;
        int found = command_of(&table[i], bytes, (size_t)argmax, &name, recovery);
        if (found < 0) goto done;
        if (!found) continue;
        if (!rss) {
            if (printf("%d %s\n", table[i].kp_proc.p_pid, name) < 0) { closed_fail("stdout", errno, 1); goto done; }
        }
        else {
            const char *base = strrchr(name, '/'); base = base ? base + 1 : name;
            if (!strcmp(base, "pool-pk-load")) {
                struct proc_taskinfo task;
                if (!recovery_check(recovery, NULL)) goto done;
                errno = 0;
                int read_size = proc_pidinfo(table[i].kp_proc.p_pid, PROC_PIDTASKINFO, 0, &task, sizeof(task));
                int query_errno = errno;
                if (!recovery_check(recovery, NULL)) goto done;
                if (read_size != sizeof(task)) {
                    struct kinfo_proc current;
                    if (!recovery_check(recovery, NULL)) goto done;
                    int present = process(table[i].kp_proc.p_pid, &current);
                    if (!recovery_check(recovery, NULL)) goto done;
                    if (present == 0) {
                        clear_name(&name);
                        continue;
                    }
                    closed_fail("rss-query", query_errno, 1);
                    goto done;
                }
                /* The existing shell consumes KiB and multiplies by 1024. */
                if (printf("%llu %s\n", (unsigned long long)(task.pti_resident_size / 1024), name) < 0) { closed_fail("stdout", errno, 1); goto done; }
            }
        }
        clear_name(&name);
    }
    if (!recovery_check(recovery, NULL)) goto done;
    result = ferror(stdout) ? closed_fail("stdout", errno, 1) : 0;
done:
    clear_name(&name);
    wipe(bytes, (size_t)argmax);
    free(bytes); free(table);
    return result;
}

static int global_scan(int rss) {
    struct recovery_budget recovery;
    return scan_inventory(rss, &recovery);
}

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "-axo")) {
        int rss;
        if (!strcmp(argv[2], "pid=,comm=")) rss = 0;
        else if (!strcmp(argv[2], "rss=,comm=")) rss = 1;
        else return 1;
        int status = global_scan(rss);
        if (status) {
            if (closed_confirmation) fprintf(stderr, "{\"status\":1,\"reason\":\"%s\",\"errno\":%d,\"confirmation\":\"%s\",\"confirmationErrno\":%d}\n",
                closed_reason, closed_errno, closed_confirmation, closed_confirmation_errno);
            else fprintf(stderr, "{\"status\":1,\"reason\":\"%s\",\"errno\":%d}\n", closed_reason, closed_errno);
        }
        return status;
    }
    int at = argc > 1 && !strcmp(argv[1], "-ww") ? 2 : 1;
    if ((argc != at + 4 && argc != at + 6) || strcmp(argv[at], "-p") || strcmp(argv[at + 2], "-o")) return 1;
    char *end = NULL;
    errno = 0;
    long pid = strtol(argv[at + 1], &end, 10);
    if (errno || !end || *end || pid <= 1 || pid > INT_MAX) return 1;
    const char *field = argv[at + 3];
    int both = argc == at + 6;
    if (both && (strcmp(field, "ppid=") || strcmp(argv[at + 4], "-o") || strcmp(argv[at + 5], "comm="))) return 1;
    if (strcmp(field, "ppid=") && strcmp(field, "comm=") && strcmp(field, "args=")) return 1;
    return single((pid_t)pid, field, both);
}
