# shellcheck shell=bash
# ENG-514, ENG-517: the one-prover claims, the prover's supervision and the ordered release of
# scripts/aggregate-proof-runner.sh. Sourced by it, and by test/aggregate-proof-runner-abort.test.sh
# so that test runs this exact code against a harmless process tree. Not executable on its own.
#
# The sourcing script first sets SHARED_PROVER_LOCK, SP1_EXCLUSIVE_MARKER, SCRATCH_PROVER_LOCK,
# DOCKER_BIN, POLL_SECONDS, TRIP_RSS_KIB, SWAP_GROWTH_TRIP_BYTES, REAP_TERM_SECONDS,
# REAP_KILL_SECONDS and DOCKER_CALL_SECONDS. Sourcing installs the EXIT, HUP, INT and TERM traps.
#
# The prover (the leader) is forked as its own session by a keeper, scripts/prover-processes.py,
# with a fresh run tag in its environment (BCH_CLOAK_PROVER_RUN) and scripts/docker-shim first on
# its PATH; the shim labels every `docker run` with the tag (bch-cloak.prover-run). A process
# belongs to the run if it is in the leader's process group, carries the tag in its environment,
# descends from a process of the run, or still has the identity recorded when it was first seen as
# one. A container belongs to a prover run if it carries the label or is of SP1's gnark image;
# prove admission requires that none exists in any state, so under the one-prover claims every
# such container is this run's.
#
# Invariants, and what enforces them (ENG-517):
#   - No signal reaches a process outside the run. The process group is signalled only by the
#     keeper, which holds the leader unreaped until the release, so the group's id cannot be
#     reused. A single pid is signalled only after a fresh check, made immediately before its
#     signal, that it still has the start time and executable recorded for it.
#   - The claims are released only when no process of the run is left and, after that, no prover
#     container is left in any state. A container runs only after a start request naming the ID
#     from its create response, and only a `docker run` CLI of the run sends one (measured on
#     Docker 29.5.3: create, attach, start). With no process of the run left no new request can
#     be sent; every container whose create was answered is listed by `docker ps --all`, whatever
#     its state; and a removed container cannot be started by a start request still in flight
#     (measured: KILLing the CLI while its container was `created` left it `running` 3 s later,
#     6 of 6; removing it at once left nothing, 8 of 8). A create still in flight can at most make
#     a container that is never started; the next prove admission refuses on it.
#   - Nothing waits without a bound: the keeper reports the leader's exit, every ps and docker
#     call has a timeout, and each reap step has a deadline. What cannot be confirmed within them
#     is reported unconfirmed: exit 3, the markers kept.
#
# On every exit - success, refusal, prover failure, memory trip, HUP, INT or TERM - cleanup ignores
# further HUP, INT and TERM and:
#   1. sends TERM to the run (its process group through the keeper, and each member), removes every
#      prover container once to free the Docker VM's memory, waits up to REAP_TERM_SECONDS, then
#      sends KILL the same way and waits up to REAP_KILL_SECONDS;
#   2. confirms by a listing that no process of the run is left; only then removes every prover
#      container in any state, confirms by a listing of all states that none is left, and confirms
#      again that no process is;
#   3. only then removes the markers this run created, closes the shared flock and releases the
#      keeper, which reaps the leader.
# If step 2 cannot confirm - a survivor, a container that will not go, the keeper lost, or ps or
# docker cannot answer - both markers stay, the script prints error=prover-reap-unconfirmed and
# exits 3. The leader inherits the flock's descriptor, so the kernel keeps the flock held while any
# descendant that kept it lives, even if this script is itself killed.
# `ps -E` shows the environment of ordinary binaries (measured: an ad-hoc-signed binary such as
# the runner, and Docker's CLI) but not of Apple platform binaries (/bin/sleep, /bin/bash), which
# only the group, parent and recorded-identity rules find. Not covered: a descendant that leaves
# the process group and loses every ancestor in the run before any listing sees it, and either
# clears the tag or is a platform binary.

: "${SHARED_PROVER_LOCK:?}" "${SP1_EXCLUSIVE_MARKER:?}" "${SCRATCH_PROVER_LOCK:?}" "${DOCKER_BIN:?}"
: "${POLL_SECONDS:?}" "${TRIP_RSS_KIB:?}" "${SWAP_GROWTH_TRIP_BYTES:?}"
: "${REAP_TERM_SECONDS:?}" "${REAP_KILL_SECONDS:?}" "${DOCKER_CALL_SECONDS:?}"
PROVER_SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P)" &&
	[[ -f $PROVER_SCRIPTS_DIR/docker-shim/docker && -x $PROVER_SCRIPTS_DIR/docker-shim/docker ]] ||
	{ echo "error=docker-shim-missing" >&2; exit 1; }
[[ -f $PROVER_SCRIPTS_DIR/prover-processes.py ]] || { echo "error=prover-processes-missing" >&2; exit 1; }
readonly PROVER_DOCKER_SHIM_DIR="$PROVER_SCRIPTS_DIR/docker-shim"
readonly PROVER_PROCESSES="$PROVER_SCRIPTS_DIR/prover-processes.py"
readonly RUN_TAG_VARIABLE=BCH_CLOAK_PROVER_RUN
# SP1 6.3.1 runs its Groth16 wrap as `docker run --rm ... ghcr.io/succinctlabs/sp1-gnark:v6.1.0`
# (sp1-recursion-gnark-ffi src/ffi/docker.rs) unless SP1_GNARK_IMAGE names another image.
readonly SP1_GNARK_IMAGE_PREFIX="ghcr.io/succinctlabs/sp1-gnark:"
readonly PROVER_CONTAINER_FORMAT='{{.ID}}|{{.Image}}|{{.Label "bch-cloak.prover-run"}}|{{.State}}'
readonly PROVER_CONTAINER_REMOVALS=10

marker_created=false
scratch_marker_created=false
build_dir=""
prover_pid=""
prover_run_dir=""
run_tag=""

fail() {
	echo "error=$1" >&2
	[[ -z ${2:-} ]] || echo "operator_action=$2" >&2
	exit 1
}

# ---- the claims ----
claim_shared_prover_lock() { # fd 9 holds the shared prover flock until release_prover_claims
	[[ ! -L $SHARED_PROVER_LOCK ]] || fail "shared-prover-lock-is-a-symlink"
	exec 9>>"$SHARED_PROVER_LOCK"
	local lock_status=0
	/usr/bin/python3 -B - <<'PY' || lock_status=$?
import fcntl, sys
try:
    fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit(3)
PY
	((lock_status == 0)) || fail "shared-prover-lock-held" "a live process holds $SHARED_PROVER_LOCK; the kernel releases it when that process exits; never delete the file to proceed"
}
create_prover_markers() { # create_prover_markers BATCH OUTPUT
	mkdir "$SP1_EXCLUSIVE_MARKER" 2>/dev/null || fail "sp1-exclusive-marker-acquire-failed"
	marker_created=true
	printf 'pid=%s\nbatch=%s\n' "$$" "$1" >"$SP1_EXCLUSIVE_MARKER/owner"
	mkdir -p "$(dirname "$SCRATCH_PROVER_LOCK")"
	(set -o noclobber; printf 'pid %s\nscript %s\nout %s\nstarted %s\n' "$$" "$0" "$2" "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ)" >"$SCRATCH_PROVER_LOCK") 2>/dev/null ||
		fail "scratch-prover-marker-acquire-failed"
	scratch_marker_created=true
}
release_prover_claims() { # only after a confirmed reap: this run's markers, the shared flock, then the keeper
	if $scratch_marker_created && [[ -f $SCRATCH_PROVER_LOCK && ! -L $SCRATCH_PROVER_LOCK ]] && grep -q "^pid $$\$" "$SCRATCH_PROVER_LOCK"; then
		rm -f "$SCRATCH_PROVER_LOCK"
	fi
	if $marker_created; then
		rm -f "$SP1_EXCLUSIVE_MARKER/owner" 2>/dev/null
		rmdir "$SP1_EXCLUSIVE_MARKER" 2>/dev/null
	fi
	exec 9>&-
	exec 8>&- # the hold's EOF: the keeper reaps the leader and exits
}

# ---- containers ----
docker_call() { # docker_call ARGUMENT...: the docker CLI, killed after DOCKER_CALL_SECONDS (exit 124)
	/usr/bin/python3 -B -c '
import subprocess, sys
try:
    sys.exit(subprocess.run(sys.argv[2:], timeout=float(sys.argv[1])).returncode)
except subprocess.TimeoutExpired:
    sys.exit(124)' "$DOCKER_CALL_SECONDS" "$DOCKER_BIN" "$@" 8>&- 9>&-
}
prover_containers() { # the IDs of every container, in ANY state, labelled by a prover run or of SP1's gnark image
	local listing
	listing="$(docker_call ps --all --no-trunc --format "$PROVER_CONTAINER_FORMAT")" || return 1
	/usr/bin/awk -F '|' -v prefix="$SP1_GNARK_IMAGE_PREFIX" \
		'NF && ($3 != "" || index($2, prefix) == 1) { printf "%s ", $1 }' <<<"$listing"
}
require_no_prover_containers() { # prove admission: none in any state, so that every one the reap finds is this run's
	local ids
	[[ -z ${SP1_GNARK_IMAGE+set} ]] ||
		fail "sp1-gnark-image-override-set" "unset SP1_GNARK_IMAGE: an unlabelled wrap container is recognised by SP1's own image"
	ids="$(prover_containers)" || fail "docker-container-listing-failed"
	[[ -z $ids ]] || fail "prover-container-present: $ids" \
		"a gnark wrap or labelled prover container exists, running or not: find the run that created it and remove it (docker rm --force) before proving"
}
remove_prover_containers() { # remove every prover container in any state; succeeds only when a listing of all states then shows none
	local ids attempt=0 attempts=${1:-$PROVER_CONTAINER_REMOVALS} # [ATTEMPTS]
	ids="$(prover_containers)" || return 1
	while [[ -n $ids ]]; do
		((attempt < attempts)) || return 1
		((attempt == 0)) || sleep 0.5
		attempt=$((attempt + 1))
		echo "prover_containers_removing=$ids" >&2
		# shellcheck disable=SC2086 # container IDs are hex
		docker_call rm --force $ids >/dev/null 2>&1
		ids="$(prover_containers)" || return 1
	done
}

# ---- processes (scripts/prover-processes.py) ----
run_processes() { # "PID RSS-KIB" for every live process of the run; fails if ps cannot answer or the keeper lost the leader
	/usr/bin/python3 -B "$PROVER_PROCESSES" members "$prover_run_dir" "$run_tag" 8>&- 9>&-
}
signal_group() { # signal_group TERM|KILL: the leader's process group, sent by the keeper, which alone holds the leader
	# One line per reap phase and one go: a few bytes, far below the hold's measured 8,190-byte
	# capacity, so this write never blocks even if the keeper is gone.
	{ printf '%s\n' "$1" >&8; } 2>/dev/null
}
signal_members() { # signal_members TERM|KILL: each process of the run whose recorded identity a fresh check
	# confirms immediately before its signal; prints the processes listed ("PID RSS-KIB")
	/usr/bin/python3 -B "$PROVER_PROCESSES" signal "$prover_run_dir" "$run_tag" "$1" 8>&- 9>&-
}
prover_rss_kib() { # the run's resident set in KiB, summed over its host processes
	local table
	table="$(run_processes)" || return 1
	/usr/bin/awk '{ t += $2 } END { printf "%.0f\n", t }' <<<"$table"
}
swap_used_bytes() {
	/usr/sbin/sysctl -n vm.swapusage | /usr/bin/awk '{
		for (i = 1; i <= NF; i++) if ($i == "used") { v = $(i + 2); u = substr(v, length(v), 1); a = substr(v, 1, length(v) - 1) + 0
			m = u == "K" ? 1024 : u == "M" ? 1048576 : u == "G" ? 1073741824 : 0; if (m == 0) exit 1; printf "%.0f\n", a * m; found = 1 } }
		END { if (!found) exit 1 }'
}
prover_launch() { # prover_launch RUN-DIR WORKDIR COMMAND [ARGUMENT...]: the prover, as its own session under the keeper
	local i dir
	run_tag="$(/usr/bin/od -An -N16 -tx1 /dev/urandom | /usr/bin/tr -d ' \n')"
	[[ $run_tag =~ ^[0-9a-f]{32}$ ]] || fail "run-tag-unavailable"
	mkdir -m 700 "$1" 2>/dev/null || fail "prover-run-directory-unavailable"
	prover_run_dir="$(cd "$1" && pwd -P)"
	dir=$2
	shift 2
	/usr/bin/mkfifo -m 600 "$prover_run_dir/hold" || fail "prover-hold-unavailable"
	exec 8<>"$prover_run_dir/hold"
	# fd 9 stays open: the keeper hands it to the leader, so the prover inherits the shared flock.
	(exec /usr/bin/python3 -B "$PROVER_PROCESSES" keeper "$prover_run_dir" "$dir" "$run_tag" "$DOCKER_BIN" \
		"$PROVER_DOCKER_SHIM_DIR" "$@" <"$prover_run_dir/hold" 8>&-) &
	for ((i = 0; i < 100; i++)); do
		[[ -s $prover_run_dir/leader ]] && break
		sleep 0.1
	done
	# Without go the leader never execs: until prover_pid is set, nothing of the prover has run.
	i="$(cat "$prover_run_dir/leader" 2>/dev/null)"
	[[ $i =~ ^[1-9][0-9]*$ ]] || fail "prover-launch-failed"
	prover_pid=$i
	printf 'go\n' >&8
	echo "prover_pid=$prover_pid prover_run_tag=$run_tag" >&2
}
prover_supervise() { # prover_supervise MEMORY-LOG: sample until the keeper reports the leader's exit; needs swap_baseline
	local rss swap trip="" status
	: "${swap_baseline:?}"
	swap_peak=$swap_baseline
	rss_peak_kib=0
	started=$SECONDS
	printf 'elapsed_s\trss_kib\tswap_used_bytes\n' >"$1"
	while [[ ! -s $prover_run_dir/exit ]]; do
		rss="$(prover_rss_kib)" || trip="rss-measurement-failed"
		swap="$(swap_used_bytes)" || trip="swap-measurement-failed"
		if [[ -z $trip ]]; then
			((rss > rss_peak_kib)) && rss_peak_kib=$rss
			((swap > swap_peak)) && swap_peak=$swap
			printf '%s\t%s\t%s\n' "$((SECONDS - started))" "$rss" "$swap" >>"$1"
			((rss >= TRIP_RSS_KIB)) && trip="30-gib-rss-trip"
			((swap > swap_baseline && swap - swap_baseline > SWAP_GROWTH_TRIP_BYTES)) && trip="swap-growth-trip"
		fi
		# The EXIT trap reaps the prover's whole run before anything is released.
		[[ -z $trip ]] || fail "$trip (rss_peak_kib=$rss_peak_kib swap_baseline=$swap_baseline swap_peak=$swap_peak)"
		sleep "$POLL_SECONDS"
	done
	status="$(cat "$prover_run_dir/exit")"
	[[ $status =~ ^[0-9]+$ ]] || fail "prover-exit-status-unreadable"
	((status == 0)) || fail "prover-failed-with-status-$status"
}

# ---- reap, then release ----
report_survivors() { # TABLE
	echo "prover_survivors=$(/usr/bin/awk '{ printf "%s ", $1 }' <<<"$1")" >&2
}
prover_reap() { # succeeds only when no process of the run is left and, after that, no prover container in any state
	[[ -n $prover_pid ]] || return 0
	local signal deadline table early_removal=true
	for signal in TERM KILL; do
		if [[ $signal == TERM ]]; then deadline=$((SECONDS + REAP_TERM_SECONDS)); else deadline=$((SECONDS + REAP_KILL_SECONDS)); fi
		signal_group "$signal"
		while :; do
			table="$(signal_members "$signal")" || return 1
			[[ -n $table ]] || break 2
			# Free the Docker VM's memory now; the removal below confirms it once no process is left.
			if $early_removal; then early_removal=false; remove_prover_containers 1; fi
			((SECONDS < deadline)) || break
			sleep 0.2
		done
	done
	# No process of the run is left, so none can send Docker another request ...
	table="$(run_processes)" || return 1
	[[ -z $table ]] || { report_survivors "$table"; return 1; }
	# ... and every container it created is listed, whatever its state, and removed for good.
	remove_prover_containers || return 1
	table="$(run_processes)" || return 1
	[[ -z $table ]] || { report_survivors "$table"; return 1; }
}
prover_cleanup() {
	local status=$?
	set +e
	trap '' HUP INT TERM
	if prover_reap; then
		release_prover_claims
		case "$build_dir" in /private/tmp/pool-aggregate-prover-build.*) rm -rf -- "$build_dir" ;; esac
	else
		echo "error=prover-reap-unconfirmed" >&2
		echo "PROVER REAP UNCONFIRMED: this run's markers are kept and no other prover may start until an operator has confirmed that nothing of this run is left" >&2
		echo "operator_action=a process or container of this prover run may still be running (process group $prover_pid; identities recorded in ${prover_run_dir:-none}/registry; ps -axwwE | grep $RUN_TAG_VARIABLE=$run_tag; docker ps --all --filter label=bch-cloak.prover-run=$run_tag; any sp1-gnark container); this run's markers stay until you have stopped it: $SP1_EXCLUSIVE_MARKER $SCRATCH_PROVER_LOCK; build directory kept: ${build_dir:-none}" >&2
		status=3
	fi
	exit "$status"
}
trap prover_cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
