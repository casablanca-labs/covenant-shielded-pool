#!/usr/bin/env bash
# ENG-514, ENG-517, ENG-518: the abort path of scripts/aggregate-proof-runner.sh, executed against
# a harmless process tree. No SP1, no setup, no Docker daemon, no proof; nothing here names the
# machine-wide shared flock or markers - every case has its own under SCRATCH-DIR.
#
# Each case runs test/aggregate-proof-runner-abort/driver.sh (through checks.py driver, which
# bounds it), which sources the harness's own scripts/prover-supervision.sh (claims, markers,
# launch, keeper, supervision, reap and release) and runs runner-stub.sh as the prover: a runner
# that ignores TERM, grandchildren that ignore TERM (one nested, one in its own session, one
# double-forked out of the tree and adopted by launchd), and fake wrap containers behind a fake
# Docker CLI and a fake daemon (fake-dockerd) that answers each request after a set delay, even
# after the CLI that sent it has died. checks.py observe takes the case's shared flock the instant
# the driver releases it and records, at that instant, which stub processes live, which fake
# containers exist, which docker calls were made and which markers exist.
#
# Cases:
#   rss-trip, swap-trip  a trip from fake measurements; the runner never exits by itself
#   sigterm              TERM to the harness mid-run
#   prover-error         the runner exits 7, leaving its tree and containers behind
#   normal               the runner exits 0, leaving its tree and containers behind
#   clean                the runner exits 0 with no tree: nothing to remove, nothing refused
#   For each: every stub process gone and every container removed BEFORE the flock is released,
#   and the markers removed; the tree had the shapes above.
#   unconfirmed-stuck    the fake containers cannot be removed: exit 3, the markers stay
#   unconfirmed-ps       docker ps cannot reach the daemon at the reap: exit 3, the markers stay
#   harness-sigkill      SIGKILL to the harness (no cleanup can run): the markers stay and the
#                        flock stays held by the prover's inherited descriptor until its tree dies
# ENG-517:
#   delayed-start        the daemon answers the wrap container's start 6 s late, after the CLI
#                        that sent it is dead and after the release: the container (created) is
#                        removed first, the late start is refused, and nothing ever runs
#   delayed-create       the daemon answers the create 6 s late, after the release: it leaves a
#                        container that is never started, and the next prove admission refuses it
#   late-created-start   the create is held until the reap's early listing has come back empty,
#                        then answered while the CLI still lives; its start comes 6 s later. Only
#                        the removal made once no process is left can find the container: it
#                        removes it, the late start is refused, and nothing ever runs
#   pid-reuse            the run's identity record holds a pid that now belongs to an unrelated
#                        process (a bystander, in its own session): it gets no signal and lives
#   keeper-lost          the keeper is KILLed from outside mid-run: the group rule is no longer
#                        sound, so the harness signals nothing, keeps the markers and exits 3
#   unkillable           a test double of the keeper and member signals in which the kernel
#                        cannot end the runner: exit 3 within the reap's bounds, a loud message,
#                        the markers kept, and the flock held while the survivor lives
# ENG-518 (ps denied: a ps that exits 1 with "Operation not permitted"):
#   teardown-without-shape  shape.json is missing and ps is denied
#   teardown-without-ps     shape.json is there and ps is denied
#                        for each, the teardown signals no pid, reports itself unverified (exit 2),
#                        and every stub still exits, by the teardown file
# Negative controls - each against a mutated copy of the library, helper or teardown, and each of
# which must make the named check fail:
#   release-first        claims released before the reap     -> at-release-no-stub-process-alive
#   direct-pid-only      only the runner's own pid is killed  -> at-release-no-stub-process-alive
#                        (the pre-ENG-514 scope)                 and after-exit-no-stub-process-alive
#   no-container-removal containers are never removed        -> at-release-no-container-running
#   running-only-start   the pre-ENG-517 listing (running containers only), delayed-start
#                                                             -> after-drain-no-container-running
#   running-only-create  the same listing, delayed-create     -> next-admission-refuses-the-late-container
#   no-final-removal     no removal once no process is left, late-created-start
#                                                             -> after-drain-no-container-running
#   pid-only-identity    an identity is its pid alone         -> pid-reuse-bystander-still-alive-after-exit
#                                                                and pid-reuse-bystander-received-no-signal
#   unbounded-wait       the reap waits for the runner's exit -> driver-exit (the bound expires)
#   no-keeper-check      membership trusts the group without the keeper, keeper-lost
#                                                             -> keeper-lost-no-stub-was-signalled
#   legacy-teardown-without-shape, legacy-teardown-without-ps
#                        the pre-ENG-518 teardown (no teardown file; nothing done without
#                        shape.json)                          -> teardown-without-ps-stubs-exited
#
# usage: test/aggregate-proof-runner-abort.test.sh SCRATCH-DIR   (new). Exit 0 only if every case
# passes and every negative control fails as named. About three minutes.
set -euo pipefail
[[ $# -eq 1 ]] || { sed -n '2,72p' "$0" >&2; exit 2; }
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
lib="$here/scripts/prover-supervision.sh"
helper="$here/scripts/prover-processes.py"
fixtures="$here/test/aggregate-proof-runner-abort"
checks="$fixtures/checks.py"
[[ ! -e $1 ]] || { echo "aggregate-proof-runner-abort: $1 exists" >&2; exit 2; }
mkdir -p "$1"
S="$(cd "$1" && pwd -P)"

# Static guard: neither the library, its helper nor a fixture names a real lock or marker; the harness does.
if /usr/bin/grep -v '^[[:space:]]*#' "$lib" "$helper" "$fixtures"/* | /usr/bin/grep -nE 'apnt-gnark-r2-proof|bch-cloak-sp1-prover-exclusive|proof-scratch'; then
	echo "aggregate-proof-runner-abort: a real lock or marker path is named; refusing" >&2
	exit 1
fi

failures=0
report() { # PASS|FAIL TEXT
	printf '%s %s\n' "$1" "$2"
	[[ $1 == PASS ]] || failures=$((failures + 1))
}
wait_file() { # FILE: up to 20 s
	for _ in $(seq 1 200); do [[ -e $1 ]] && return 0; /bin/sleep 0.1; done
	return 1
}
json() { # FILE PYTHON-EXPRESSION-OVER-j
	/usr/bin/python3 -B -c 'import json, sys; j = json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$1" "$2"
}
# ENG-518: every stub exits by itself on CASE/teardown; checks.py teardown then confirms it by
# recorded pid, start time and command, and KILLs a recorded stub only on that match.
teardown() { # CASE-DIR [CHECKS]
	local st=0
	/usr/bin/python3 -B "${2:-$checks}" teardown "$1" 2>>"$1/teardown.err" || st=$?
	((st == 0)) || echo "teardown of $1: exit $st ($(tail -1 "$1/teardown.err"))" >&2
	return "$st"
}
all_cases=()
teardown_all() {
	local c
	for c in ${all_cases[@]+"${all_cases[@]}"}; do teardown "$c" || true; done
}
trap teardown_all EXIT

new_case() { # NAME -> C, with its own claims, fake CLI and fake daemon
	C="$S/cases/$1"
	all_cases+=("$C")
	mkdir -p "$C/claims" "$C/fake" "$C/docker/state/"{containers,removed,requests,responses}
	cp "$fixtures/fake-docker" "$C/docker/docker"
	: >"$C/docker/state/calls"
	: >"$C/stub-pids"
	: >"$C/helper-pids"
	echo 1024 >"$C/fake/rss-kib"
	echo 0 >"$C/fake/swap-bytes"
	/usr/bin/python3 -B "$fixtures/fake-dockerd" "$C" &
	echo "fake-dockerd $!" >>"$C/helper-pids"
}
start() { # LIBRARY STUB-MODE [no-observer] [TIMEOUT] -> dpid, opid; returns once the stub tree is up
	opid=""
	/usr/bin/python3 -B "$checks" driver "$C" "${4:-60}" "$1" "$2" &
	dpid=$!
	wait_file "$C/claimed" || { report FAIL "$(basename "$C"): the driver never claimed"; return 1; }
	if [[ ${3:-} != no-observer ]]; then
		/usr/bin/python3 -B "$checks" observe "$C" 60 &
		opid=$!
	fi
	wait_file "$C/stub-ready" || { report FAIL "$(basename "$C"): the stub tree never came up"; return 1; }
	/usr/bin/python3 -B "$checks" shape "$C" ||
		{ report FAIL "$(basename "$C"): cannot record the stub tree's identities (ps)"; return 1; }
}
finish() { # -> the driver's exit recorded (by checks.py driver) and the observer done
	wait "$dpid" || true
	[[ -z $opid ]] || wait "$opid" || true
}
trigger() { # rss | swap | term | go | kill
	case $1 in
	rss) echo $((31 * 1024 * 1024)) >"$C/fake/rss-kib" ;;
	swap) echo $((17 * 1024 * 1024 * 1024)) >"$C/fake/swap-bytes" ;;
	term) kill -TERM "$dpid" ;; # checks.py driver passes it on to its unreaped child
	kill) kill -USR1 "$dpid" ;; # and this as KILL
	go) : >"$C/stub-go" ;;
	esac
}
judge() { # KIND EXIT [ERROR] -> judge status; the verdict lines in C/judge.txt
	local st=0
	/usr/bin/python3 -B "$checks" judge "$C" "$@" >"$C/judge.txt" 2>&1 || st=$?
	return "$st"
}
verdict() { # NAME: report the judge's verdict
	if [[ $(tail -1 "$C/judge.txt") == "verdict PASS" ]]; then
		report PASS "$1: $(tail -1 "$C/judge.txt")"
	else
		report FAIL "$1: $(tail -1 "$C/judge.txt") (details: $C/judge.txt)"
	fi
}
must_fail_at() { # NAME CHECK...: a negative control's judge must fail at each named check
	local name=$1 missing="" check
	shift
	if [[ $(tail -1 "$C/judge.txt") == "verdict PASS" ]]; then
		report FAIL "$name: the negative control passed; the test cannot see this mutation"
		return
	fi
	for check in "$@"; do /usr/bin/grep -qE "^FAIL $check( |\$)" "$C/judge.txt" || missing+=" $check"; done
	if [[ -z $missing ]]; then report PASS "$name: fails as it must ($*)"; else report FAIL "$name: failed, but not at:$missing ($C/judge.txt)"; fi
}
mutant() { # NAME [FILE ORIGINAL REPLACEMENT]... -> the mutated library's path; FILE is prover-supervision.sh or prover-processes.py
	local d="$S/mutants/$1"
	shift
	mkdir -p "$d"
	cp "$lib" "$d/prover-supervision.sh"
	cp "$helper" "$d/prover-processes.py"
	cp -R "$here/scripts/docker-shim" "$d/docker-shim"
	substitute "$d" "$@" || exit 1
	echo "$d/prover-supervision.sh"
}
substitute() { # DIRECTORY [FILE ORIGINAL REPLACEMENT]...: each ORIGINAL must occur exactly once
	/usr/bin/python3 -B - "$@" <<'PY'
import os, sys
d, rest = sys.argv[1], sys.argv[2:]
if not rest or len(rest) % 3:
    sys.exit("substitute: FILE ORIGINAL REPLACEMENT triples")
for i in range(0, len(rest), 3):
    name, old, new = rest[i:i + 3]
    p = os.path.join(d, name)
    s = open(p).read()
    if s.count(old) != 1:
        sys.exit(f"substitute: original text found {s.count(old)} times in {name}: {old[:70]!r}")
    open(p, "w").write(s.replace(old, new))
PY
}

# ---- one case: start, trigger, finish, judge; a negative control names the checks it must fail ----
run_case() { # NAME LIBRARY STUB-MODE TRIGGER KIND EXIT ERROR [SETUP-FILE] [MUST-FAIL-CHECK...]
	local name=$1 library=$2 mode=$3 how=$4 kind=$5 want=$6 error=$7 setup=${8:-}
	shift 8 2>/dev/null || shift $#
	new_case "$name"
	case $mode in delayed-start) echo 6 >"$C/docker/state/start-delay" ;; delayed-create) echo 6 >"$C/docker/state/create-delay" ;; esac
	start "$library" "$mode" || { teardown "$C" || true; return; }
	[[ -z $setup ]] || : >"$C/docker/state/$setup"
	trigger "$how"
	finish
	case $kind in
	delayed-start | delayed-create) /usr/bin/python3 -B "$checks" drain "$C" 20 ;;
	esac
	if [[ $kind == delayed-create ]]; then
		local st=0
		bash "$fixtures/driver.sh" "$library" "$C" admission >/dev/null 2>"$C/admission.err" || st=$?
		echo "$st" >"$C/admission.exit"
	fi
	judge "$kind" "$want" "$error" || true
	if (($# == 0)); then verdict "$name"; else must_fail_at "$name" "$@"; fi
	teardown "$C" || report FAIL "$name: teardown could not confirm that every stub is gone"
}

# ---- the ENG-514 cases ----
run_case rss-trip "$lib" hold rss confirmed 1 30-gib-rss-trip
run_case swap-trip "$lib" hold swap confirmed 1 swap-growth-trip
run_case sigterm "$lib" hold term confirmed 143 ""
run_case prover-error "$lib" exit-7 go confirmed 1 prover-failed-with-status-7
run_case normal "$lib" exit-0 go confirmed 0 ""
run_case clean "$lib" clean go clean 0 ""
run_case unconfirmed-stuck "$lib" hold rss unconfirmed-stuck 3 prover-reap-unconfirmed stuck
run_case unconfirmed-ps "$lib" hold rss unconfirmed-ps 3 prover-reap-unconfirmed ps-fails

# ---- SIGKILL to the harness: nothing of it runs, so the markers and the inherited flock hold ----
new_case harness-sigkill
if start "$lib" hold-keeping-lock no-observer; then
	trigger kill
	finish
	# Only now, with the harness dead, does the observer start: for 3 s it must be refused.
	/usr/bin/python3 -B "$checks" observe "$C" 3
	alive_before="$(/usr/bin/python3 -B -c '
import subprocess, sys
live = {int(l.split()[0]) for l in subprocess.run(["/bin/ps", "-axo", "pid=,stat="], capture_output=True, text=True).stdout.splitlines() if "Z" not in l.split()[1]}
print(sum(int(l.split()[1]) in live for l in open(sys.argv[1]) if l.strip()), sum(1 for l in open(sys.argv[1]) if l.strip()))' "$C/stub-pids")"
	[[ "$(cat "$C/driver.exit")" == 137 && "$(json "$C/observer.json" 'j["acquired"]')" == False ]] &&
		report PASS "harness-sigkill: the flock stays held while the prover's tree lives (observer refused for 3 s)" ||
		report FAIL "harness-sigkill: exit $(cat "$C/driver.exit"), observer $(cat "$C/observer.json")"
	[[ -d $C/claims/sp1-exclusive && -f $C/claims/scratch-marker/prover.lock ]] &&
		report PASS "harness-sigkill: both markers stay" || report FAIL "harness-sigkill: a marker was removed"
	read -r alive total <<<"$alive_before"
	[[ $alive == "$total" && $total -ge 8 ]] &&
		report PASS "harness-sigkill: the stub tree ($total processes) still runs, as a real orphaned prover would" ||
		report FAIL "harness-sigkill: $alive of $total stub processes alive"
	teardown "$C" || report FAIL "harness-sigkill: teardown could not confirm that every stub is gone"
	/usr/bin/python3 -B "$checks" observe "$C" 10
	[[ "$(json "$C/observer-2.json" 'j["acquired"]')" == True ]] &&
		report PASS "harness-sigkill control: the flock is released once that tree is gone" ||
		report FAIL "harness-sigkill control: the flock is still held after the tree was killed"
else
	teardown "$C" || true
fi

# ---- ENG-517: a late Docker start or create, a reused pid, an unkillable runner ----
run_case delayed-start "$lib" delayed-start rss delayed-start 1 30-gib-rss-trip
run_case delayed-create "$lib" delayed-create rss delayed-create 1 30-gib-rss-trip

late_created_case() { # NAME LIBRARY [MUST-FAIL-CHECK...]
	local name=$1 library=$2
	shift 2
	new_case "$name"
	: >"$C/docker/state/create-gate"
	echo 6 >"$C/docker/state/start-delay"
	if start "$library" delayed-create; then
		trigger rss
		# The reap's first container listing (the early removal) is the first ps the daemon answers:
		# only once it has come back empty is the create let through, to the CLI that still lives.
		for _ in $(seq 1 100); do compgen -G "$C/docker/state/responses/*.ps" >/dev/null && break; /bin/sleep 0.05; done
		rm -f "$C/docker/state/create-gate"
		finish
		/usr/bin/python3 -B "$checks" drain "$C" 20
		judge late-created-start 1 30-gib-rss-trip || true
		if (($# == 0)); then verdict "$name"; else must_fail_at "$name" "$@"; fi
	fi
	teardown "$C" || report FAIL "$name: teardown could not confirm that every stub is gone"
}
late_created_case late-created-start "$lib"

pid_reuse_case() { # NAME LIBRARY [MUST-FAIL-CHECK...]
	local name=$1 library=$2 bystander
	shift 2
	new_case "$name"
	# The bystander: an unrelated process of this user in its own session, which logs any TERM.
	: >"$C/bystander.log"
	/usr/bin/python3 -B -c '
import os, signal, sys, time
os.setsid()
signal.signal(signal.SIGTERM, lambda *_: open(sys.argv[1], "a").write("TERM\n"))
while not os.path.exists(sys.argv[2]):
    time.sleep(0.2)' "$C/bystander.log" "$C/teardown" &
	bystander=$!
	echo "bystander $bystander" >>"$C/helper-pids"
	if start "$library" hold; then
		# As if a process of the run had once had this pid, then exited, and the pid were reused.
		printf '%s 1 0 bystander\n' "$bystander" >>"$C/run/registry"
		trigger rss
		finish
		judge pid-reuse 1 30-gib-rss-trip || true
		if (($# == 0)); then verdict "$name"; else must_fail_at "$name" "$@"; fi
	fi
	teardown "$C" || report FAIL "$name: teardown could not confirm that every stub is gone"
}
pid_reuse_case pid-reuse "$lib"

keeper_lost_case() { # NAME LIBRARY [MUST-FAIL-CHECK...]
	local name=$1 library=$2 keeper
	shift 2
	new_case "$name"
	if start "$library" hold; then
		# The keeper is the runner's parent; KILL it only if a fresh ps shows it is that keeper.
		keeper="$(json "$C/shape.json" 'j["runner"][0]')"
		[[ "$(/bin/ps -ww -o command= -p "$keeper")" == *"prover-processes.py keeper $C/run "* ]] && kill -KILL "$keeper"
		# A trip, so that a harness which still trusted the group would go on to reap (and signal) the run;
		# this one's next sample already fails, the leader no longer held.
		trigger rss
		finish
		judge keeper-lost 3 prover-reap-unconfirmed || true
		if (($# == 0)); then verdict "$name"; else must_fail_at "$name" "$@"; fi
	fi
	teardown "$C" || report FAIL "$name: teardown could not confirm that every stub is gone"
}
keeper_lost_case keeper-lost "$lib"

unkillable_case() { # NAME LIBRARY [MUST-FAIL-CHECK...]
	local name=$1 library=$2
	shift 2
	new_case "$name"
	if start "$library" bare-keeping-lock no-observer 30; then
		trigger rss
		finish
		/usr/bin/python3 -B "$checks" observe "$C" 3
		judge unkillable 3 prover-reap-unconfirmed || true
		if (($# == 0)); then verdict "$name"; else must_fail_at "$name" "$@"; fi
		teardown "$C" || report FAIL "$name: teardown could not confirm that every stub is gone"
		/usr/bin/python3 -B "$checks" observe "$C" 10
		if (($# == 0)); then
			[[ "$(json "$C/observer-2.json" 'j["acquired"]')" == True ]] &&
				report PASS "$name control: the flock is released once the survivor is gone" ||
				report FAIL "$name control: the flock is still held after the survivor was gone"
		fi
	else
		teardown "$C" || true
	fi
}
# The test double: the kernel cannot end the runner (the leader). Its group signal and its own pid
# signal are dropped; every other process is signalled as the library does it.
kernel_cannot_end_leader=(
	prover-processes.py
	$'                        os.killpg(leader, SIGNALS[word])  # safe: the leader is unreaped\n'
	$'                        pass  # TEST DOUBLE: the kernel cannot end the leader\n'
	prover-processes.py
	$'            try:\n                os.kill(pid, sig)\n'
	$'            try:\n                if pid != int(open(path(run_dir, "leader")).read()):  # TEST DOUBLE\n                    os.kill(pid, sig)\n'
)
unkillable_case unkillable "$(mutant unkillable "${kernel_cannot_end_leader[@]}")"

# ---- ENG-518: the teardown needs neither ps nor shape.json ----
denied_ps="$S/denied-ps"
printf '#!/bin/sh\necho "ps: Operation not permitted" >&2\nexit 1\n' >"$denied_ps"
chmod +x "$denied_ps"
teardown_without_ps() { # NAME CHECKS-PY HIDE-SHAPE(yes|no) [MUST-FAIL-CHECK...]
	local name=$1 teardown_checks=$2 hide=$3 st=0 left
	shift 3
	new_case "$name"
	if start "$lib" hold no-observer; then
		cp "$C/shape.json" "$C/shape.json.kept"
		[[ $hide == no ]] || rm "$C/shape.json"
		ABORT_TEST_PS="$denied_ps" /usr/bin/python3 -B "$teardown_checks" teardown "$C" 2>"$C/teardown-without-ps.err" || st=$?
		/bin/sleep 1
		left="$(/usr/bin/python3 -B - "$C" <<'PY'
import json, subprocess, sys, os
case = sys.argv[1]
shapes = json.load(open(os.path.join(case, "shape.json.kept")))
rows = subprocess.run(["/bin/ps", "-axww", "-o", "pid=,lstart=,command="], capture_output=True, text=True, check=True).stdout.splitlines()
live = {int(r.split(None, 1)[0]): r.split(None, 1)[1] for r in rows}
names = [l.split() for l in open(os.path.join(case, "stub-pids")) if l.strip()] + [l.split() for l in open(os.path.join(case, "helper-pids")) if l.strip()]
print(" ".join(f"{n}={p}" for n, p in names if shapes.get(n) and int(p) in live and live[int(p)].startswith(shapes[n][2])))
PY
)"
		{
			echo "$( ((st == 2)) && echo PASS || echo FAIL) teardown-without-ps-reports-unverified   [exit $st: $(tail -1 "$C/teardown-without-ps.err")]"
			echo "$([[ -z $left ]] && echo PASS || echo FAIL) teardown-without-ps-stubs-exited   [alive: ${left:-none}]"
		} >"$C/judge.txt"
		/usr/bin/grep -q '^FAIL' "$C/judge.txt" && echo "verdict FAIL" >>"$C/judge.txt" || echo "verdict PASS" >>"$C/judge.txt"
		if (($# == 0)); then verdict "$name"; else must_fail_at "$name" "$@"; fi
		cp "$C/shape.json.kept" "$C/shape.json"
	fi
	teardown "$C" || report FAIL "$name: teardown could not confirm that every stub is gone"
	finish
}
teardown_without_ps teardown-without-shape "$checks" yes
teardown_without_ps teardown-without-ps "$checks" no

# ---- negative controls (a mutant that cannot be made stops the test) ----
C="$S/mutants/legacy-teardown"
mkdir -p "$C"
cp "$checks" "$C/checks.py"
substitute "$C" checks.py $'def teardown(case):\n    open(os.path.join(case, "teardown"), "a").close()\n' \
	$'def teardown(case):\n    if not os.path.exists(os.path.join(case, "shape.json")):\n        return 0  # the pre-ENG-518 teardown: no shape.json, nothing done\n' || exit 1
legacy_checks="$C/checks.py"
release_first="$(mutant release-first prover-supervision.sh \
	$'\tif prover_reap; then\n\t\trelease_prover_claims\n' \
	$'\trelease_prover_claims\n\tif prover_reap; then\n\t\t:\n')"
direct_pid_only="$(mutant direct-pid-only prover-supervision.sh \
	$'prover_reap() { # succeeds only when no process of the run is left and, after that, no prover container in any state\n' \
	$'prover_reap() { # succeeds only when no process of the run is left and, after that, no prover container in any state\n\tkill -KILL "$prover_pid" 2>/dev/null; return 0\n')"
no_container_removal="$(mutant no-container-removal prover-supervision.sh \
	$'remove_prover_containers() { # remove every prover container in any state; succeeds only when a listing of all states then shows none\n' \
	$'remove_prover_containers() { # remove every prover container in any state; succeeds only when a listing of all states then shows none\n\treturn 0\n')"
running_only="$(mutant running-only prover-supervision.sh \
	$'listing="$(docker_call ps --all --no-trunc --format "$PROVER_CONTAINER_FORMAT")" || return 1' \
	$'listing="$(docker_call ps --no-trunc --format "$PROVER_CONTAINER_FORMAT")" || return 1')"
no_final_removal="$(mutant no-final-removal prover-supervision.sh \
	$'\tremove_prover_containers || return 1\n' \
	$'\t: # mutant: no removal once no process is left\n')"
no_keeper_check="$(mutant no-keeper-check prover-processes.py \
	$'    if not keeper_alive(run_dir):\n' \
	$'    if False:  # mutant: the group rule without the keeper\n')"
pid_only_identity="$(mutant pid-only-identity prover-processes.py \
	$'    return fresh is not None and fresh == recorded\n' \
	$'    return fresh is not None\n')"
unbounded_wait="$(mutant unbounded-wait "${kernel_cannot_end_leader[@]}" prover-supervision.sh \
	$'\t# No process of the run is left, so none can send Docker another request ...\n' \
	$'\twhile [[ ! -s $prover_run_dir/exit ]]; do sleep 0.2; done # the pre-ENG-517 unbounded wait for the runner\n\t# No process of the run is left, so none can send Docker another request ...\n')"

run_case release-first "$release_first" hold rss confirmed 1 30-gib-rss-trip "" at-release-no-stub-process-alive
run_case direct-pid-only "$direct_pid_only" hold rss confirmed 1 30-gib-rss-trip "" \
	at-release-no-stub-process-alive after-exit-no-stub-process-alive
run_case no-container-removal "$no_container_removal" hold rss confirmed 1 30-gib-rss-trip "" at-release-no-container-running
run_case running-only-start "$running_only" delayed-start rss delayed-start 1 30-gib-rss-trip "" after-drain-no-container-running
run_case running-only-create "$running_only" delayed-create rss delayed-create 1 30-gib-rss-trip "" \
	next-admission-refuses-the-late-container
late_created_case no-final-removal "$no_final_removal" after-drain-no-container-running
pid_reuse_case pid-only-identity "$pid_only_identity" pid-reuse-bystander-still-alive-after-exit pid-reuse-bystander-received-no-signal

unkillable_case unbounded-wait "$unbounded_wait" driver-exit
keeper_lost_case no-keeper-check "$no_keeper_check" keeper-lost-no-stub-was-signalled
teardown_without_ps legacy-teardown-without-shape "$legacy_checks" yes teardown-without-ps-stubs-exited
teardown_without_ps legacy-teardown-without-ps "$legacy_checks" no teardown-without-ps-stubs-exited

echo "aggregate-proof-runner-abort: $failures failure(s); cases in $S/cases"
((failures == 0))
