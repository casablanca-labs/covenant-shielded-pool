#!/usr/bin/env python3
"""ENG-514, ENG-517, ENG-518 abort test: runs, records and judges one case of
test/aggregate-proof-runner-abort.test.sh.

  checks.py driver CASE-DIR TIMEOUT LIBRARY STUB-MODE
        run driver.sh as this process's child and write CASE-DIR/driver.exit. TERM to this process
        is passed on as TERM and USR1 as KILL, only while the child is unreaped. After TIMEOUT
        seconds the driver is KILLed, CASE-DIR/driver.timeout is written and the exit is 124.
  checks.py shape CASE-DIR
        at stub-ready: each recorded stub's and test helper's parent, group, start time and
        command (shape.json), from one ps listing; exit 1 if ps cannot answer
  checks.py teardown CASE-DIR
        ENG-518: create CASE-DIR/teardown, on which every stub, fake CLI and fake daemon exits by
        itself, then confirm that each recorded process is gone. One still alive after 5 s is
        KILLed only if a fresh ps shows the start time and command recorded for it. Exit 0: all
        gone; 1: some left; 2: not verifiable (ps cannot answer, or shape.json is missing) - then
        no pid is signalled and the processes are left to exit on the teardown file.
  checks.py observe CASE-DIR SECONDS
        take CASE-DIR's shared flock the moment it is released and, at that instant, record what
        still runs (observer.json, then observer-2.json)
  checks.py drain CASE-DIR SECONDS
        wait until the fake daemon has answered every request, then record its containers and
        events (drain.json)
  checks.py judge CASE-DIR KIND EXIT [ERROR]
        print PASS/FAIL per check; exit 1 if any fails. KIND: confirmed | clean |
        unconfirmed-stuck | unconfirmed-ps | delayed-start | delayed-create | late-created-start |
        pid-reuse | unkillable | keeper-lost

The observer is the test's witness of the release order: it holds no state of the harness and
learns of the release only from the kernel granting it the flock.
"""
import fcntl
import json
import os
import re
import signal
import subprocess
import sys
import time

GNARK_PREFIX = "ghcr.io/succinctlabs/sp1-gnark:"
PS = os.environ.get("ABORT_TEST_PS", "/bin/ps")  # the ENG-518 case points it at a ps that is denied
HERE = os.path.dirname(os.path.realpath(__file__))
FULL_TREE = ("confirmed", "unconfirmed-stuck", "unconfirmed-ps", "pid-reuse")
RELEASED = ("confirmed", "clean", "pid-reuse", "delayed-start", "delayed-create", "late-created-start")
DRAINED = ("delayed-start", "delayed-create", "late-created-start")


def processes():
    """{pid: (ppid, pgid, start time, command)} for every live (not zombie) process."""
    out = subprocess.run([PS, "-axww", "-o", "pid=,ppid=,pgid=,stat=,lstart=,command="],
                         capture_output=True, text=True, check=True, timeout=20).stdout
    table = {}
    for line in out.splitlines():
        f = line.split(None, 9)
        if len(f) < 9 or f[3].startswith("Z"):
            continue
        table[int(f[0])] = (int(f[1]), int(f[2]), " ".join(f[4:9]), f[9] if len(f) > 9 else "")
    return table


def pairs(case, name):
    try:
        return [(n, int(p)) for n, p in (line.split() for line in open(os.path.join(case, name)) if line.strip())]
    except FileNotFoundError:
        return []


def recorded(case):
    return pairs(case, "stub-pids")


def helpers(case):
    return pairs(case, "helper-pids")


def container_files(case, where):
    d = os.path.join(case, "docker", "state", where)
    return {n: open(os.path.join(d, n)).read().strip().split("|") for n in sorted(os.listdir(d)) if not n.startswith(".")}


def markers(case):
    paths = [os.path.join(case, "claims", "sp1-exclusive"), os.path.join(case, "claims", "scratch-marker", "prover.lock")]
    return [p for p in paths if os.path.lexists(p)]


def read(case, name, default=""):
    try:
        return open(os.path.join(case, name)).read()
    except FileNotFoundError:
        return default


def write_json(case, name, obj):
    tmp = os.path.join(case, "." + name)
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1)
    os.rename(tmp, os.path.join(case, name))


def driver(case, timeout, library, mode):
    with open(os.path.join(case, "driver.out"), "w") as out, open(os.path.join(case, "driver.err"), "w") as err:
        child = subprocess.Popen(["bash", os.path.join(HERE, "driver.sh"), library, case, mode], stdout=out, stderr=err)

    def forward(signum, _frame):  # Popen.send_signal polls first and never signals a reaped pid
        child.send_signal(signal.SIGTERM if signum == signal.SIGTERM else signal.SIGKILL)

    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGUSR1, forward)
    try:
        child.wait(timeout)
        code = child.returncode if child.returncode >= 0 else 128 - child.returncode
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()
        with open(os.path.join(case, "driver.timeout"), "w") as f:
            f.write(f"the driver was still running after {timeout} s and was KILLed\n")
        code = 124
    with open(os.path.join(case, "driver.exit"), "w") as f:
        f.write(f"{code}\n")
    return code


def shape(case):
    table = processes()
    write_json(case, "shape.json", {n: list(table[p]) if p in table else None for n, p in recorded(case) + helpers(case)})


def teardown(case):
    open(os.path.join(case, "teardown"), "a").close()
    wanted = recorded(case) + helpers(case)
    try:
        shapes = json.load(open(os.path.join(case, "shape.json")))
    except (FileNotFoundError, ValueError):
        shapes = None

    def ours_alive():
        table = processes()
        return [(n, p) for n, p in wanted if shapes.get(n) and p in table and list(table[p][2:]) == shapes[n][2:]]

    def unverified(reason):
        time.sleep(1)  # every stub polls the teardown file at least every 0.2 s
        print(f"teardown-unverified: {reason}; recorded: {' '.join(f'{n}={p}' for n, p in wanted) or 'none'}; each exits "
              "by itself on the case's teardown file; no pid was signalled", file=sys.stderr)
        return 2

    if shapes is None:
        return unverified("shape.json is missing")
    deadline = time.monotonic() + 5
    while True:
        try:
            alive = ours_alive()
        except (OSError, subprocess.SubprocessError):
            return unverified("ps cannot answer")
        if not alive:
            return 0
        if time.monotonic() > deadline:
            break
        time.sleep(0.1)
    try:
        table = processes()
    except (OSError, subprocess.SubprocessError):
        return unverified("ps cannot answer")
    for n, p in alive:  # KILL only a pid that a fresh ps shows with its recorded start time and command
        if p in table and list(table[p][2:]) == shapes[n][2:]:
            try:
                os.kill(p, signal.SIGKILL)
            except ProcessLookupError:
                pass
    time.sleep(0.3)
    try:
        left = ours_alive()
    except (OSError, subprocess.SubprocessError):
        return unverified("ps cannot answer")
    if left:
        print(f"teardown: still alive: {left}", file=sys.stderr)
        return 1
    return 0


def observe(case, seconds):
    fd = os.open(os.path.join(case, "claims", "shared.lock"), os.O_WRONLY | os.O_APPEND)
    deadline = time.monotonic() + seconds
    acquired = False
    while time.monotonic() < deadline:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
            break
        except BlockingIOError:
            time.sleep(0.005)
    snap = {"acquired": acquired, "at": time.time()}
    if acquired:
        table = processes()
        runner = dict(recorded(case)).get("runner")
        snap["alive"] = [f"{n} {p}" for n, p in recorded(case) if p in table]
        snap["group_alive"] = sorted(p for p, v in table.items() if runner is not None and v[1] == runner)
        current = container_files(case, "containers")
        snap["containers_running"] = sorted(i for i, v in current.items() if v[3] == "running")
        snap["containers_any"] = sorted(current)
        snap["docker_calls"] = read(case, "docker/state/calls").splitlines()
        snap["markers"] = markers(case)
    write_json(case, "observer.json" if not os.path.exists(os.path.join(case, "observer.json")) else "observer-2.json", snap)
    os.close(fd)


def drain(case, seconds):
    requests = os.path.join(case, "docker", "state", "requests")
    deadline = time.monotonic() + seconds

    def pending():
        return [n for n in os.listdir(requests) if not n.startswith(".")]

    while pending() and time.monotonic() < deadline:
        time.sleep(0.05)
    time.sleep(0.3)
    write_json(case, "drain.json", {"pending": pending(), "containers": container_files(case, "containers"),
                                    "events": read(case, "docker/state/events").splitlines()})


def events(drained):
    """[(seq, time, kind, container)] from the fake daemon's event log."""
    return [(int(s), float(t), k, c) for s, t, k, c in (line.split() for line in drained["events"])]


def judge(case, kind, want_exit, want_error):
    failures = []

    def check(name, ok, detail=""):
        print(f"{'PASS' if ok else 'FAIL'} {name}" + (f"   [{detail}]" if not ok and detail != "" else ""))
        if not ok:
            failures.append(name)

    def verdict():
        print("verdict " + ("PASS" if not failures else "FAIL " + " ".join(failures)))
        return 1 if failures else 0

    got_exit = int(read(case, "driver.exit", "-1"))
    timed_out = os.path.exists(os.path.join(case, "driver.timeout"))
    err = read(case, "driver.err")
    tail = err.strip().splitlines()[-4:]
    check("driver-exit", got_exit == want_exit and not timed_out, f"got {got_exit}{' after the timeout' if timed_out else ''}, want {want_exit}")
    if want_error:
        check("driver-error", f"error={want_error}" in err, tail)
    obs = json.load(open(os.path.join(case, "observer.json")))
    stubs = dict(recorded(case))
    runner_pid = stubs.get("runner")

    if kind == "unkillable":
        check("unkillable-loud-message", "PROVER REAP UNCONFIRMED" in err, tail)
        check("unkillable-survivor-named", re.search(rf"prover_survivors=([0-9 ]* )?{runner_pid} ", err) is not None, tail)
        check("unkillable-flock-still-held-after-exit-while-the-survivor-lives", not obs["acquired"], obs)
        check("unkillable-markers-kept-after-exit", len(markers(case)) == 2, markers(case))
        check("unkillable-survivor-still-alive-after-exit", runner_pid in processes(), runner_pid)
        return verdict()

    check("observer-took-the-flock", obs["acquired"])
    if not obs["acquired"]:
        return verdict()
    if kind == "keeper-lost":
        s = json.load(open(os.path.join(case, "shape.json")))
        table = processes()
        check("keeper-lost-reported", "prover-processes: keeper-lost" in err, tail)
        check("keeper-lost-markers-kept-at-release", len(obs["markers"]) == 2, obs["markers"])
        check("keeper-lost-markers-kept-after-exit", len(markers(case)) == 2, markers(case))
        # Once the leader is no longer held, no process of the run is signalled: every stub still lives.
        check("keeper-lost-no-stub-was-signalled",
              all(p in table and s.get(n) and list(table[p][2:]) == s[n][2:] for n, p in recorded(case)),
              [f"{n} {p}" for n, p in recorded(case) if p not in table])
        return verdict()
    started = {**container_files(case, "containers"), **container_files(case, "removed")}
    tag = read(case, "stub-identity").split()[1]
    removals = [c for c in obs["docker_calls"] if c.split()[:1] == ["rm"]]

    if kind in FULL_TREE:
        s = json.load(open(os.path.join(case, "shape.json")))
        runner = s["runner"]
        check("shape-runner-leads-its-own-process-group", runner is not None and runner[1] == runner_pid, s)
        check("shape-own-session-child-left-the-group", s["own-session"] is not None and s["own-session"][1] != runner_pid, s)
        check("shape-escapee-adopted-by-launchd-outside-the-group",
              s["escapee"] is not None and s["escapee"][0] == 1 and s["escapee"][1] != runner_pid, s)
        labelled = [c for c in started.values() if c[2]]
        unlabelled = [c for c in started.values() if not c[2]]
        check("shim-labelled-one-container-with-the-run-tag", len(labelled) == 1 and labelled[0][2] == tag, started)
        check("one-unlabelled-container-of-the-sp1-gnark-image",
              len(unlabelled) == 1 and unlabelled[0][1].startswith(GNARK_PREFIX), started)

    if kind in RELEASED:
        check("at-release-no-stub-process-alive", obs["alive"] == [], obs["alive"])
        check("at-release-no-process-left-in-the-runner-group", obs["group_alive"] == [], obs["group_alive"])
        check("at-release-no-container-running", obs["containers_running"] == [], obs["containers_running"])
        check("at-release-no-container-in-any-state", obs["containers_any"] == [], obs["containers_any"])
        check("at-release-markers-removed", obs["markers"] == [], obs["markers"])
        if kind in FULL_TREE:
            named = {w for c in removals for w in c.split()}
            check("at-release-every-container-was-removed-by-the-harness", all(i in named for i in started), removals)
        if kind == "clean":
            check("clean-no-removal-was-needed", removals == [], removals)
    else:
        check("unconfirmed-host-processes-reaped", obs["alive"] == [], obs["alive"])
        check("unconfirmed-markers-kept-at-release", len(obs["markers"]) == 2, obs["markers"])
        check("unconfirmed-markers-kept-after-exit", len(markers(case)) == 2, markers(case))
        if kind == "unconfirmed-stuck":
            check("unconfirmed-stuck-containers-still-running", len(obs["containers_running"]) == 2, obs["containers_running"])
            check("unconfirmed-stuck-removal-attempted", removals != [], obs["docker_calls"])
        else:
            check("unconfirmed-ps-docker-listing-attempted", any(c.startswith("ps ") for c in obs["docker_calls"]), obs["docker_calls"])

    if kind in DRAINED:
        drained = json.load(open(os.path.join(case, "drain.json")))
        ev = events(drained)
        check("after-drain-every-request-answered", drained["pending"] == [], drained["pending"])
        check("after-drain-no-container-running",
              not [c for c in drained["containers"].values() if c[3] == "running"], drained["containers"])
        if kind == "late-created-start":
            calls = read(case, "docker/state/calls").splitlines()
            rm_at = [i for i, c in enumerate(calls) if c.startswith("rm ")]
            listings_before = sum(1 for c in calls[:rm_at[0]] if c.startswith("ps --all ")) if rm_at else 0
            check("late-created-start-removed-only-by-the-final-removal", len(rm_at) == 1 and listings_before >= 2, calls)
        if kind in ("delayed-start", "late-created-start"):
            created = [c for _, _, k, c in ev if k == "create"]
            removed_at = {c: s for s, _, k, c in ev if k == "remove"}
            refused = [(s, t, c) for s, t, k, c in ev if k == "start-refused"]
            check("delayed-start-one-container-was-created", len(created) == 1, ev)
            check("delayed-start-arrived-after-the-release",
                  any(k in ("start", "start-refused") and t > obs["at"] for _, t, k, _ in ev), (obs["at"], ev))
            check("delayed-start-was-refused-because-the-container-was-removed-first",
                  len(refused) == 1 and refused[0][2] in removed_at and removed_at[refused[0][2]] < refused[0][0], ev)
        else:
            late = [(t, c) for _, t, k, c in ev if k == "create"]
            check("delayed-create-landed-after-the-release", len(late) == 1 and late[0][0] > obs["at"], (obs["at"], ev))
            check("delayed-create-left-a-container-that-never-started",
                  len(late) == 1 and drained["containers"].get(late[0][1], [None] * 4)[3] == "created"
                  and not any(k == "start" for _, _, k, _ in ev), drained)
            admission_err = read(case, "admission.err")
            check("next-admission-refuses-the-late-container",
                  read(case, "admission.exit").strip() == "1" and "error=prover-container-present" in admission_err,
                  (read(case, "admission.exit").strip(), admission_err.strip().splitlines()[-2:]))

    if kind == "pid-reuse":
        bystander = dict(helpers(case)).get("bystander")
        shapes = json.load(open(os.path.join(case, "shape.json")))
        now = processes()
        check("pid-reuse-bystander-still-alive-after-exit",
              bystander in now and shapes.get("bystander") and list(now[bystander][2:]) == shapes["bystander"][2:], bystander)
        check("pid-reuse-bystander-received-no-signal", read(case, "bystander.log") == "", read(case, "bystander.log"))

    table = processes()
    left = [f"{n} {p}" for n, p in recorded(case) if p in table]
    check("after-exit-no-stub-process-alive", left == [], left)
    return verdict()


if __name__ == "__main__":
    command, case_dir = sys.argv[1], sys.argv[2]
    if command == "driver":
        sys.exit(driver(case_dir, float(sys.argv[3]), sys.argv[4], sys.argv[5]))
    elif command == "shape":
        shape(case_dir)
    elif command == "teardown":
        sys.exit(teardown(case_dir))
    elif command == "observe":
        observe(case_dir, float(sys.argv[3]))
    elif command == "drain":
        drain(case_dir, float(sys.argv[3]))
    elif command == "judge":
        sys.exit(judge(case_dir, sys.argv[3], int(sys.argv[4]), sys.argv[5] if len(sys.argv) > 5 else ""))
    else:
        sys.exit(f"unknown command {command}")
