/* Bounded real-API owned-exec fixture. Only KERN_PROC_ALL is narrowed to our
 * one independently queried child; every argument/confirmation call is real
 * and forwarded unchanged. Not a natural-host census or production selector. */
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <libproc.h>
#include <fcntl.h>
#include <signal.h>
static int forwarded_sysctl(int *, unsigned, void *, size_t *, void *, size_t);
static int forwarded_path(int, void *, uint32_t);
#define sysctl forwarded_sysctl
#define proc_pidpath forwarded_path
#define main reader_main
#ifndef REQUERY_READER
#define REQUERY_READER "../../pool-action-modules/private-runner-process.c"
#endif
#include REQUERY_READER
#undef main
#undef sysctl
#undef proc_pidpath

static pid_t owned;
static int settle_fd = -1, armed, settled;
static unsigned queries, confirmations, matching_confirmations, paths, real_einval, live_einval;
static struct kinfo_proc baseline;

static int forwarded_path(int pid, void *bytes, uint32_t size) {
    if (armed) paths++;
    return proc_pidpath(pid, bytes, size);
}
static int forwarded_sysctl(int *mib, unsigned length, void *out, size_t *size, void *in, size_t insize) {
    if (mib[1] == KERN_PROC && mib[2] == KERN_PROC_ALL) {
        if (!out) { *size = sizeof(struct kinfo_proc); return 0; }
        /* Each inventory gets a fresh real row, including actual birth/UID. */
        int query[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, owned};
        size_t actual = sizeof(baseline);
        int result = sysctl(query, 4, &baseline, &actual, NULL, 0), error = errno;
        if (result || actual != sizeof(baseline) || baseline.kp_proc.p_pid != owned) {
            errno = result ? error : ESRCH; return -1;
        }
        if (*size < actual) { errno = ENOMEM; return -1; }
        memcpy(out, &baseline, actual); *size = actual; return 0;
    }
    int result = sysctl(mib, length, out, size, in, insize), error = errno;
    if (armed && mib[1] == KERN_PROCARGS2 && mib[2] == owned) {
        queries++;
        if (result != 0 && error == EINVAL) real_einval++;
    }
    if (armed && queries && mib[1] == KERN_PROC && mib[2] == KERN_PROC_PID && mib[3] == owned) {
        confirmations++;
        const struct kinfo_proc *value = out;
        /* Independent witness predicate, rather than the guard's helper. */
        int live = result == 0 && *size == sizeof(*value) && value->kp_proc.p_pid == owned &&
            baseline.kp_proc.p_pid == owned && baseline.kp_eproc.e_ucred.cr_uid == geteuid() &&
            value->kp_eproc.e_ucred.cr_uid == baseline.kp_eproc.e_ucred.cr_uid &&
            baseline.kp_proc.p_starttime.tv_sec > 0 &&
            value->kp_proc.p_starttime.tv_sec == baseline.kp_proc.p_starttime.tv_sec &&
            value->kp_proc.p_starttime.tv_usec == baseline.kp_proc.p_starttime.tv_usec &&
            value->kp_proc.p_stat >= SIDL && value->kp_proc.p_stat < SZOMB;
        if (live) matching_confirmations++;
        if (real_einval && live && !settled) {
            live_einval++;
            /* Stop churn only after a real EINVAL's independent live check.
             * Subsequent production retries still use real syscalls. */
            if (write(settle_fd, "S", 1) == 1) settled = 1;
        }
    }
    errno = error; return result;
}

static int worker(const char *mode, const char *descriptor) {
    int fd = atoi(descriptor);
    if (fd < 3) return 3;
    if (!strcmp(mode, "--settled")) {
        if (fcntl(fd, F_SETFL, 0)) return 4;
        char byte = 0; int received;
        do { received = (int)read(fd, &byte, 1); } while (received < 0 && errno == EINTR);
        return received == 0 || (received == 1 && byte == 'Q') ? 0 : 5;
    }
    char path[PROC_PIDPATHINFO_MAXSIZE];
    if (!path_of(getpid(), path, sizeof(path))) return 6;
    char byte; int received = (int)read(fd, &byte, 1);
    if (received == 0 || (received == 1 && byte == 'Q')) return 0;
    if (received < 0 && errno != EAGAIN && errno != EINTR) return 7;
    char *args[] = {received == 1 && byte == 'S' ? "pool-pk-load" : "neutral",
                   received == 1 && byte == 'S' ? "--settled" : "--churn",
                   (char *)descriptor, "SYNTHETIC_ARG_CANARY", NULL};
    char *environment[] = {"LANG=C", "SYNTHETIC_ENV_CANARY=synthetic", NULL};
    execve(path, args, environment);
    return 8;
}

int main(int argc, char **argv) {
    struct rlimit cores = {0, 0};
    if (setrlimit(RLIMIT_CORE, &cores)) return 2;
    if (argc == 4 && (!strcmp(argv[1], "--churn") || !strcmp(argv[1], "--settled")))
        return worker(argv[1], argv[2]);
    if (argc != 4 || strcmp(argv[2], "-axo") || strcmp(argv[3], "pid=,comm=")) return 2;
    char executable[PROC_PIDPATHINFO_MAXSIZE];
    if (!path_of(getpid(), executable, sizeof(executable))) return 3;
    int channel[2];
    if (pipe(channel) || fcntl(channel[0], F_SETFL, O_NONBLOCK)) return 4;
    owned = fork();
    if (owned < 0) return 5;
    if (!owned) {
        /* Set once before the first exec. The alarm survives subsequent execs
         * and bounds churn even if its parent blocks or is interrupted. */
        alarm(30);
        close(channel[1]); char descriptor[32]; snprintf(descriptor, sizeof(descriptor), "%d", channel[0]);
        char *args[] = {"neutral", "--churn", descriptor, "SYNTHETIC_ARG_CANARY", NULL};
        char *environment[] = {"LANG=C", "SYNTHETIC_ENV_CANARY=synthetic", NULL};
        execve(executable, args, environment); _exit(6);
    }
    close(channel[0]); settle_fd = channel[1];
    /* Discard non-event observations. Stop at the FIRST real EINVAL, even
     * if it cannot be confirmed/recovered. Never search past a failed event. */
    uint64_t started, now;
    if (!monotonic_ns(&started)) { close(settle_fd); kill(owned, SIGKILL); waitpid(owned, NULL, 0); return 7; }
    unsigned attempts = 0; int reader_status = 1, recovered = 0;
    char selected[4096] = {0}; size_t selected_size = 0;
    const char *outcome = "event-missing";
    int original_stdout = dup(STDOUT_FILENO);
    FILE *sink = tmpfile();
    if (original_stdout < 0 || !sink) { close(settle_fd); kill(owned, SIGKILL); waitpid(owned, NULL, 0); return 8; }
    for (; attempts < 50000; ) {
        if (!monotonic_ns(&now) || now < started || now - started >= 25000000000) break;
        if (fflush(stdout) || ftruncate(fileno(sink), 0) || fseek(sink, 0, SEEK_SET) || dup2(fileno(sink), STDOUT_FILENO) < 0) break;
        queries = confirmations = matching_confirmations = paths = real_einval = live_einval = 0;
        armed = 1; attempts++;
        reader_status = global_scan(0);
        armed = 0;
        if (fflush(stdout) || fseek(sink, 0, SEEK_SET)) break;
        if (!real_einval) continue;
        selected_size = fread(selected, 1, sizeof(selected)-1, sink);
        char expected[128]; int expected_size = snprintf(expected, sizeof(expected), "%d pool-pk-load\n", owned);
        recovered = reader_status == 0 && live_einval == 1 && settled && queries >= 2 && queries <= 3 &&
            confirmations >= 3 && matching_confirmations == confirmations && paths == 0 &&
            selected_size == (size_t)expected_size && !memcmp(selected, expected, selected_size);
        outcome = recovered ? "recovered" : "unresolved";
        break;
    }
    if (dup2(original_stdout, STDOUT_FILENO) < 0) recovered = 0;
    close(original_stdout); fclose(sink);
    /* Bounded fixture lifetime, including all refusal paths. The worker also
     * exits on EOF if its parent is interrupted; no detached child remains. */
    signal(SIGPIPE, SIG_IGN);
    (void)write(settle_fd, "Q", 1); close(settle_fd);
    int child_status = 0, reaped = waitpid(owned, &child_status, 0) == owned;
    if (!reaped || !WIFEXITED(child_status) || WEXITSTATUS(child_status)) recovered = 0;
    int metadata = open(argv[1], O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0600);
    if (metadata < 0) recovered = 0;
    else {
        dprintf(metadata,"{\"outcome\":\"%s\",\"readerStatus\":%d,\"attempts\":%u,\"realEinval\":%u,\"liveEinval\":%u,\"queries\":%u,\"confirmations\":%u,\"matchingConfirmations\":%u,\"paths\":%u,\"recovered\":%d,\"childReaped\":%d}\n",
                outcome, reader_status, attempts, real_einval, live_einval, queries, confirmations, matching_confirmations, paths, recovered, reaped);
        close(metadata);
    }
    if (recovered) {
        if (fwrite(selected, 1, selected_size, stdout) != selected_size || fflush(stdout)) recovered = 0;
    }
    wipe(selected, sizeof(selected));
    return recovered ? 0 : real_einval ? 1 : 77;
}
