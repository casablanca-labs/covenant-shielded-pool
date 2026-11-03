#!/usr/bin/env python3
"""ENG-517: the process side of scripts/prover-supervision.sh; run by it, not by hand.

  prover-processes.py keeper RUN-DIR WORKDIR TAG REAL-DOCKER SHIM-DIR COMMAND [ARGUMENT...]
      The prover's parent. It forks COMMAND as a new session (the leader), holds the leader
      unreaped until the harness closes the hold (stdin, the FIFO RUN-DIR/hold), and signals the
      leader's process group only on the harness's command. An unreaped leader keeps its pid, and
      so the group's id, from being reused, so a group signal cannot reach another process group.
      stdin lines: go (exec the leader), TERM or KILL (signal its process group); EOF: exit.
      RUN-DIR/leader: the leader's pid, written before the leader may exec.
      RUN-DIR/exit: the leader's exit status (128 + signal if signalled), written without reaping.
      RUN-DIR/keeper.lock: flocked for the keeper's whole life; free means the keeper is gone.
  prover-processes.py members RUN-DIR TAG
      "PID RSS-KIB" for every live process of the run. Exit 1 if ps cannot answer, 4 if the
      keeper no longer holds the leader (then the group rule is unsound and nothing is listed).
  prover-processes.py signal RUN-DIR TAG TERM|KILL
      As members, then signals each listed process whose identity a fresh check, made
      immediately before its signal, confirms. Prints the processes it listed.

A process is of the run if it is the leader or in its process group, carries TAG in its
environment as ps -E shows it, descends from a process of the run, or matches an identity in
RUN-DIR/registry. The registry is append-only: every member's identity (pid, start time to the
microsecond, executable name) is recorded when first seen, so a member stays one after its
ancestors die. A registry entry names a process only while that pid still has that identity.
Every signal to a single pid is preceded by a fresh identity check against that record; the
remaining window is the one between the check and kill(2). Group signals go only through the
keeper, which alone can make them safe.
"""
import ctypes
import fcntl
import os
import select
import signal
import subprocess
import sys

TAG_VARIABLE = "BCH_CLOAK_PROVER_RUN"
NOTE_EXITSTATUS = 0x04000000  # <sys/event.h>: the exit status in the event's data (children only)
PS_SECONDS = 20
SIGNALS = {"TERM": signal.SIGTERM, "KILL": signal.SIGKILL}
KEEPER_LOST = 4


class BSDInfo(ctypes.Structure):  # <sys/proc_info.h> struct proc_bsdinfo (PROC_PIDTBSDINFO)
    _fields_ = [("flags", ctypes.c_uint32), ("status", ctypes.c_uint32), ("xstatus", ctypes.c_uint32),
                ("pid", ctypes.c_uint32), ("ppid", ctypes.c_uint32), ("uid", ctypes.c_uint32),
                ("gid", ctypes.c_uint32), ("ruid", ctypes.c_uint32), ("rgid", ctypes.c_uint32),
                ("svuid", ctypes.c_uint32), ("svgid", ctypes.c_uint32), ("rfu", ctypes.c_uint32),
                ("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32), ("nfiles", ctypes.c_uint32),
                ("pgid", ctypes.c_uint32), ("pjobc", ctypes.c_uint32), ("tdev", ctypes.c_uint32),
                ("tpgid", ctypes.c_uint32), ("nice", ctypes.c_int32),
                ("start_sec", ctypes.c_uint64), ("start_usec", ctypes.c_uint64)]


_libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
_libproc.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
_libproc.proc_pidinfo.restype = ctypes.c_int
PROC_PIDTBSDINFO = 3


def identity(pid):
    """(start seconds, start microseconds, executable name) of a live process, or None."""
    info = BSDInfo()
    if _libproc.proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, ctypes.byref(info), ctypes.sizeof(info)) != ctypes.sizeof(info):
        return None
    if info.pid != pid:
        return None
    return (int(info.start_sec), int(info.start_usec), info.comm.decode("utf-8", "replace"))


def same_process(fresh, recorded):
    """True only if a fresh identity is the recorded one: same start time and executable."""
    return fresh is not None and fresh == recorded


def path(run_dir, name):
    return os.path.join(run_dir, name)


def write_atomically(run_dir, name, text):
    tmp = path(run_dir, name + ".tmp")
    with open(tmp, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path(run_dir, name))


# ---- keeper ----
def keeper(run_dir, workdir, tag, real_docker, shim_dir, command):
    for s in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGQUIT):
        signal.signal(s, signal.SIG_IGN)  # the harness ends the keeper by closing the hold
    lock = os.open(path(run_dir, "keeper.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    env = dict(os.environ)
    env.update({TAG_VARIABLE: tag, "PATH": shim_dir + ":" + env.get("PATH", ""), "BCH_CLOAK_PROVER_REAL_DOCKER": real_docker})
    go_r, go_w = os.pipe()
    leader = os.fork()
    if leader == 0:
        try:
            os.close(lock)
            os.close(go_w)
            os.setsid()
            for s in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGQUIT, signal.SIGPIPE, signal.SIGXFSZ):
                signal.signal(s, signal.SIG_DFL)
            if os.read(go_r, 1) == b"g":
                os.close(go_r)
                os.chdir(workdir)
                null = os.open(os.devnull, os.O_RDONLY)
                os.dup2(null, 0)
                os.close(null)
                os.execve(command[0], command, env)
        finally:
            os._exit(127)
    os.close(go_r)
    try:
        os.close(9)  # the shared flock's descriptor goes to the leader; the keeper keeps none of it
    except OSError:
        pass
    kq = select.kqueue()
    kq.control([select.kevent(leader, select.KQ_FILTER_PROC, select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
                              select.KQ_NOTE_EXIT | NOTE_EXITSTATUS)], 0)
    write_atomically(run_dir, "leader", f"{leader}\n")
    pending = b""
    exited = False
    while True:
        # A FIFO's EOF is not reported by kqueue's read filter on macOS (measured); select reports it.
        ready, _, _ = select.select([0, kq.fileno()], [], [])
        if kq.fileno() in ready and not exited:
            for ev in kq.control(None, 1, 0):
                status = ev.data
                code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status)
                write_atomically(run_dir, "exit", f"{code}\n")  # not reaped: the pid stays the leader's
                exited = True
        if 0 in ready:
            chunk = os.read(0, 4096)
            if not chunk:
                break
            pending += chunk
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                word = line.decode("ascii", "replace").strip()
                if word == "go" and go_w is not None:
                    os.write(go_w, b"g")
                    os.close(go_w)
                    go_w = None
                elif word in SIGNALS:
                    try:
                        os.killpg(leader, SIGNALS[word])  # safe: the leader is unreaped
                    except (ProcessLookupError, PermissionError):
                        pass
    # Released (or the harness is gone). A leader that never got go exits 127 on its own; an exited
    # one is reaped here; a live one is left to launchd with its group.
    if go_w is not None:
        os.close(go_w)
    try:
        os.waitpid(leader, os.WNOHANG)
    except ChildProcessError:
        pass


# ---- membership ----
def keeper_alive(run_dir):
    fd = os.open(path(run_dir, "keeper.lock"), os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    finally:
        os.close(fd)
    return False


def read_registry(run_dir):
    entries = []
    try:
        with open(path(run_dir, "registry")) as f:
            for line in f:
                parts = line.rstrip("\n").split(" ", 3)
                if len(parts) == 4 and parts[0].isdigit():
                    entries.append((int(parts[0]), (int(parts[1]), int(parts[2]), parts[3])))
    except FileNotFoundError:
        pass
    return entries


def members(run_dir, tag):
    """{pid: (rss_kib, identity)} for every live process of the run, as of one ps listing."""
    with open(path(run_dir, "leader")) as f:
        leader = int(f.read())
    if leader <= 1:
        raise SystemExit("prover-processes: bad leader pid")
    listing = subprocess.run(["/bin/ps", "-axwwE", "-o", "pid=,ppid=,pgid=,rss=,stat=,command="],
                             capture_output=True, text=True, timeout=PS_SECONDS, check=True).stdout
    live = {}
    for line in listing.splitlines():
        f = line.split(None, 5)
        if len(f) < 5 or f[4].startswith("Z"):
            continue
        live[int(f[0])] = (int(f[1]), int(f[2]), int(f[3]), f[5] if len(f) > 5 else "")
    needle = f" {TAG_VARIABLE}={tag} "
    want = {p for p, (ppid, pgid, rss, cmd) in live.items() if p == leader or pgid == leader or needle in f" {cmd} "}
    known = {}
    for pid, recorded in read_registry(run_dir):
        if pid in live and same_process(identity(pid), recorded):
            want.add(pid)
            known[pid] = recorded
    changed = True
    while changed:
        changed = False
        for p, (ppid, _, _, _) in live.items():
            if p not in want and ppid in want:
                want.add(p)
                changed = True
    want -= {os.getpid(), os.getppid()}
    result = {}
    fresh_lines = []
    for p in sorted(want):
        if p <= 1:
            continue
        ident = known.get(p) or identity(p)
        if ident is None:
            continue  # gone since the listing
        result[p] = (live[p][2], ident)
        if p not in known:
            fresh_lines.append(f"{p} {ident[0]} {ident[1]} {ident[2]}\n")
    # The group rule held for the whole listing only if the keeper still held the leader after it.
    if not keeper_alive(run_dir):
        print("prover-processes: keeper-lost: the leader is no longer held; its pid may be reused", file=sys.stderr)
        raise SystemExit(KEEPER_LOST)
    if fresh_lines:
        with open(path(run_dir, "registry"), "a") as f:
            for line in fresh_lines:  # one write per line: O_APPEND keeps each whole
                f.write(line)
                f.flush()
    return result


def signal_members(run_dir, tag, sig):
    found = members(run_dir, tag)
    for pid, (_, recorded) in found.items():
        if same_process(identity(pid), recorded):  # immediately before its signal
            try:
                os.kill(pid, sig)
            except (ProcessLookupError, PermissionError):
                pass
    return found


def main(argv):
    command = argv[1] if len(argv) > 1 else ""
    if command == "keeper" and len(argv) >= 8:
        keeper(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7:])
        return 0
    if command in ("members", "signal") and len(argv) == (4 if command == "members" else 5):
        try:
            found = members(argv[2], argv[3]) if command == "members" else signal_members(argv[2], argv[3], SIGNALS[argv[4]])
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as e:
            print(f"prover-processes: {command} failed: {type(e).__name__}", file=sys.stderr)
            return 1
        sys.stdout.write("".join(f"{p} {rss}\n" for p, (rss, _) in sorted(found.items())))
        return 0
    print(__doc__.split("\n\n")[1], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
