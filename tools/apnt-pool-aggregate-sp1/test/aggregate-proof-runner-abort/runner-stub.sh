#!/bin/bash
# ENG-514, ENG-517 abort test: a harmless stand-in for the prover's process tree. Proves nothing.
# It ignores TERM, and every process it starts ignores TERM too. Every one of them exits by itself
# once CASE-DIR/teardown exists, so the test's cleanup needs neither ps nor a signal (ENG-518).
# Trees, by MODE:
#   hold, hold-keeping-lock, exit-0, exit-7: the full tree -
#     sleeper       a child in the run's process group
#     nester/nested a child and its own child
#     own-session   a child that made itself a new session (out of the process group)
#     escapee       a double fork into a new session whose parent exits, so launchd adopts it:
#                   out of the process group and out of the parent-pid tree; only the run's
#                   environment tag names it
#     two fake wrap containers, running: one through `docker` on PATH (the harness's shim labels
#     it; an image the harness does not know) and one past the shim by the real CLI's path
#     (unlabelled; SP1's gnark image). Each CLI stays attached, as `docker run` does.
#   delayed-start, delayed-create: one CLI through the shim, up once the fake daemon holds its
#     start (or its create) request unanswered (state/start-delay, state/create-delay)
#   clean, bare-keeping-lock: no tree
# Endings: exit-0, exit-7 and clean exit once CASE-DIR/stub-go exists, leaving the tree; every
# other mode stays until the teardown. hold-keeping-lock and bare-keeping-lock keep the inherited
# shared flock; every other mode first closes it, as a descendant may, so that a release the
# harness makes too early is visible to the test. Every pid goes to CASE-DIR/stub-pids;
# CASE-DIR/stub-ready marks the tree up.
# usage: runner-stub.sh CASE-DIR MODE
case_dir=$1
mode=$2
case $mode in hold-keeping-lock | bare-keeping-lock) ;; *) exec 9>&- ;; esac
trap '' TERM
pids="$case_dir/stub-pids"
teardown="$case_dir/teardown"
state="$(dirname "$BCH_CLOAK_PROVER_REAL_DOCKER")/state"
linger() { while [[ ! -e $teardown ]]; do { /bin/sleep 0.2; } 2>/dev/null; done; } # no job notice when the reap kills the sleep
up_within_10s() { # CONDITION-COMMAND...
	for _ in $(seq 1 100); do "$@" && return 0; /bin/sleep 0.1; done
	return 1
}
running_containers() { [[ $(/usr/bin/grep -l '|running$' "$state"/containers/* 2>/dev/null | /usr/bin/wc -l) -ge $1 ]]; }
pending() { /bin/ls "$state/requests" | /usr/bin/grep -q "\\.$1\$"; }
echo "runner $$" >>"$pids"
printf 'tag %s\n' "$BCH_CLOAK_PROVER_RUN" >"$case_dir/stub-identity"
case $mode in
hold | hold-keeping-lock | exit-0 | exit-7)
	(trap '' TERM; linger) &
	echo "sleeper $!" >>"$pids"
	(
		trap '' TERM
		(trap '' TERM; linger) &
		echo "nested $!" >>"$pids"
		wait
	) &
	echo "nester $!" >>"$pids"
	/usr/bin/python3 -B -c '
import os, signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
os.setsid()
while not os.path.exists(sys.argv[1]):
    time.sleep(0.2)' "$teardown" &
	echo "own-session $!" >>"$pids"
	/usr/bin/python3 -B -c '
import os, signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        with open(sys.argv[1], "a") as f:
            f.write(f"escapee {os.getpid()}\n")
        while not os.path.exists(sys.argv[2]):
            time.sleep(0.2)
        os._exit(0)
    os._exit(0)
os.wait()' "$pids" "$teardown"
	docker run --rm -v "$case_dir:/circuit" stub/wrap-not-gnark:1 prove --system groth16 /circuit &
	echo "docker-cli-shim $!" >>"$pids"
	"$BCH_CLOAK_PROVER_REAL_DOCKER" run --rm -v "$case_dir:/circuit" ghcr.io/succinctlabs/sp1-gnark:v6.1.0 prove --system groth16 /circuit &
	echo "docker-cli-direct $!" >>"$pids"
	up_within_10s running_containers 2
	up_within_10s /usr/bin/grep -q '^escapee ' "$pids"
	;;
delayed-start | delayed-create)
	docker run --rm -v "$case_dir:/circuit" stub/wrap-not-gnark:1 prove --system groth16 /circuit &
	echo "docker-cli-shim $!" >>"$pids"
	up_within_10s pending "${mode#delayed-}"
	;;
esac
: >"$case_dir/stub-ready"
case $mode in
exit-0 | exit-7 | clean)
	while [[ ! -e $case_dir/stub-go && ! -e $teardown ]]; do /bin/sleep 0.1; done
	[[ $mode == exit-7 ]] && exit 7
	exit 0
	;;
esac
linger
