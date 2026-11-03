#!/usr/bin/env bash
# Tests scripts/prove-dev-batch.sh's lock and marker protocol (ENG-430) without
# proving and without the real locks. The pattern is
# tools/apnt-pool-ceremony/scripts/test-harness-binding.sh's: everything runs
# in a sparse scratch clone of this repository at HEAD. The clone's copy of the
# wrapper has, each replaced exactly once:
#
#   the shared flock path, the SP1 exclusive marker and ~/proof-scratch/.prover.lock
#                             -> scratch paths
#   the process scan (ps)     -> a scratch process list (empty unless a case fills it)
#   the 20 GiB memory floor   -> 1 byte, so the test runs beside a ceremony
#   the gnark-reference build -> a copy of a compiled stub named gnark-reference
#   (kill case only) the 30 GiB RSS trip -> 1 byte
#
# A static guard refuses to run anything if a real lock or marker path is left
# in the copy's code. The stub records whether the marker exists, and its first
# line, while it runs; then it succeeds, fails, or sleeps until killed.
#
# Cases, each with its firing control:
#   success     marker present during the run with this run's pid; removed after
#   failure     the prover exits 3; marker removed
#   rss-trip    the sampler kills the prover; marker removed, stub gone
#   sigterm     TERM to the wrapper mid-run; stub stopped, marker removed
#   foreign-marker  a marker that is not this run's refuses before the build and
#               is left byte for byte; control: the same run proceeds without it
#   flock-held  another process holds the shared flock: refused, no marker;
#               control: the same run proceeds once it is released
#
# usage: test/prove-dev-batch-lock.test.sh SCRATCH-DIR   (new or empty; outside
#        any git repository). Exit 0 only if every case passes. It never opens
#        /private/tmp/apnt-gnark-r2-proof-$UID.lock and never reads or writes
#        ~/proof-scratch/.prover.lock.
set -euo pipefail

[[ $# -eq 1 ]] || { sed -n '2,31p' "$0" >&2; exit 2; }
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
repo="$(git -C "$here" rev-parse --show-toplevel)"
[[ -z "$(git -C "$repo" status --porcelain -- tools/apnt-pool-aggregate-sp1/scripts tools/apnt-pool-aggregate-sp1/test)" ]] ||
	{ echo "prove-dev-batch-lock: commit tools/apnt-pool-aggregate-sp1/scripts and test first; the clone tests HEAD" >&2; exit 1; }
# The wrapper's kill path is pkill -x gnark-reference: never run beside a real one.
if /usr/bin/pgrep -x gnark-reference >/dev/null; then
	echo "prove-dev-batch-lock: a gnark-reference process is running; refusing" >&2
	exit 1
fi
head="$(git -C "$repo" rev-parse HEAD)"
mkdir -p "$1"
S="$(cd "$1" && pwd -P)"
[[ -z "$(ls -A "$S")" ]] || { echo "prove-dev-batch-lock: $S is not empty" >&2; exit 1; }
! git -C "$S" rev-parse --git-dir >/dev/null 2>&1 || { echo "prove-dev-batch-lock: $S is inside a git repository" >&2; exit 1; }

C="$S/clone"
T="$C/tools/apnt-pool-aggregate-sp1"
git clone --quiet --shared --no-checkout "$repo" "$C"
git -C "$C" sparse-checkout set --cone tools/apnt-pool-aggregate-sp1
git -C "$C" checkout --quiet --detach "$head"
W="$T/scripts/prove-dev-batch.sh"
cp "$W" "$S/prove-dev-batch.committed.sh"

LOCKS="$S/locks"
SHARED="$LOCKS/shared.lock"
SP1MARK="$LOCKS/sp1-exclusive"
# Not the real layout, so the static guard below can match the real path.
MARKER="$S/markers/prover.lock"
PS_LIST="$S/ps.txt"
STUB_LOG="$S/stub.log"
mkdir -p "$LOCKS" "$S/keys" "$S/stub"
: >"$PS_LIST"
: >"$STUB_LOG"
printf 'test keys: not a key directory\n' >"$S/keys/PARAMETERS-LABEL.txt"

# The stub prover: its executable name is gnark-reference, so the wrapper's
# RSS sampler and pkill see it. The mode is the --entries value.
cat >"$S/stub/stub.c" <<EOF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
int main(int argc, char **argv) {
	const char *mode = "";
	for (int i = 1; i + 1 < argc; i++) if (!strcmp(argv[i], "--entries")) mode = argv[i + 1];
	char line[512] = "";
	FILE *m = fopen("$MARKER", "r");
	if (m) { if (!fgets(line, sizeof line, m)) line[0] = 0; fclose(m); }
	line[strcspn(line, "\n")] = 0;
	FILE *log = fopen("$STUB_LOG", "a");
	fprintf(log, "mode=%s pid=%d marker=%s first=%s\n", mode, (int)getpid(), m ? "present" : "absent", line);
	fclose(log);
	if (!strcmp(mode, "stub-long")) { sleep(120); return 0; }
	sleep(6);
	if (!strcmp(mode, "stub-fail")) return 3;
	mkdir(argv[argc - 2], 0755);
	FILE *r = fopen(argv[argc - 1], "w");
	fprintf(r, "{}\n");
	fclose(r);
	return 0;
}
EOF
/usr/bin/cc -O1 -o "$S/stub/gnark-reference" "$S/stub/stub.c"

substitute() { # file original replacement
	/usr/bin/python3 - "$@" <<'PY'
import sys
p, old, new = sys.argv[1:4]
s = open(p).read()
if s.count(old) != 1:
    sys.exit(f"substitute: original text found {s.count(old)} times: {old[:60]}")
open(p, "w").write(s.replace(old, new))
PY
}
prepare() { # rss-trip(yes|no)
	cp "$S/prove-dev-batch.committed.sh" "$W"
	substitute "$W" 'readonly SHARED_PROVER_LOCK="/private/tmp/apnt-gnark-r2-proof-$UID.lock"' "readonly SHARED_PROVER_LOCK=\"$SHARED\""
	substitute "$W" 'readonly SP1_EXCLUSIVE_MARKER="/private/tmp/bch-cloak-sp1-prover-exclusive-v1"' "readonly SP1_EXCLUSIVE_MARKER=\"$SP1MARK\""
	substitute "$W" 'readonly PROVER_MARKER="$HOME/proof-scratch/.prover.lock"' "readonly PROVER_MARKER=\"$MARKER\""
	substitute "$W" 'readonly MIN_AVAILABLE_BYTES=$((20 * 1024 * 1024 * 1024))' 'readonly MIN_AVAILABLE_BYTES=1'
	substitute "$W" '	/bin/ps -axo pid=,comm= | /usr/bin/awk -v self="$$" '"'" "	/bin/cat \"$PS_LIST\" | /usr/bin/awk -v self=\"\$\$\" '"
	substitute "$W" '(cd "$here/gnark-reference" && GOPROXY=off GOFLAGS=-mod=readonly go build -o "$out/bin/" .)' "/bin/cp \"$S/stub/gnark-reference\" \"\$out/bin/gnark-reference\""
	if [[ $1 == yes ]]; then
		substitute "$W" 'readonly RSS_TRIP_BYTES=$((30 * 1024 * 1024 * 1024))' 'readonly RSS_TRIP_BYTES=1'
	fi
	# Static guard: no real lock or marker path left in the code.
	if /usr/bin/grep -v '^[[:space:]]*#' "$W" | /usr/bin/grep -nE '/private/tmp/apnt-gnark-r2-proof|proof-scratch/\.prover\.lock|bch-cloak-sp1-prover-exclusive|go build'; then
		echo "prove-dev-batch-lock: the scratch copy still names a real lock, marker or build; refusing" >&2
		exit 1
	fi
}

failures=0
n=0
check() { # verdict-condition description
	if eval "$1"; then
		printf 'PASS %s\n' "$2"
	else
		printf 'FAIL %s   [%s]\n' "$2" "$1"
		failures=$((failures + 1))
	fi
}
run_bg() { # mode -> sets wpid, wout, wlog
	n=$((n + 1))
	wout="$S/out-$n"
	wlog="$S/run-$n.log"
	bash "$W" "$S/keys" "$wout" "$1" 2 >"$wlog" 2>&1 &
	wpid=$!
}
# Not in a command substitution: a subshell cannot wait for this shell's job.
wait_status() { st=0; wait "$wpid" || st=$?; }
stub_lines() { /usr/bin/wc -l <"$STUB_LOG" | tr -d ' '; }
last_stub() { tail -1 "$STUB_LOG"; }
no_stub_running() { ! /usr/bin/pgrep -x gnark-reference >/dev/null; }

prepare no

# ---- success ----
run_bg stub-success
wait_status
check "[[ $st == 0 ]]" "success: the wrapper exits 0"
check "[[ '$(last_stub)' == 'mode=stub-success '*' marker=present first=pid $wpid' ]]" "success: the marker existed during the run with this run's pid ($wpid)"
check "[[ ! -e '$MARKER' ]]" "success: the marker is removed after the run"
check "[[ -f '$wout/result.json' ]]" "success: the prover's result was written"

# ---- failure ----
run_bg stub-fail
wait_status
check "[[ $st == 3 ]]" "failure: the wrapper exits with the prover's status 3"
check "[[ '$(last_stub)' == 'mode=stub-fail '*' marker=present first=pid $wpid' ]]" "failure: the marker existed during the run"
check "[[ ! -e '$MARKER' ]]" "failure: the marker is removed"

# ---- sigterm to the wrapper ----
run_bg stub-long
before="$(stub_lines)"
for _ in $(seq 1 40); do [[ "$(stub_lines)" -gt "$before" ]] && break; sleep 0.25; done
check "[[ '$(last_stub)' == 'mode=stub-long '*' marker=present first=pid $wpid' ]]" "sigterm: the marker existed during the run"
kill -TERM "$wpid"
wait_status
check "[[ $st == 143 ]]" "sigterm: the wrapper exits 143"
check "no_stub_running" "sigterm: the prover stub was stopped"
check "[[ ! -e '$MARKER' ]]" "sigterm: the marker is removed"

# ---- foreign marker, and its control ----
mkdir -p "$(dirname "$MARKER")"
printf 'pid 99999\nscript foreign\nout /nowhere\nstarted earlier\n' >"$MARKER"
foreign_sha="$(/usr/bin/shasum -a 256 "$MARKER" | cut -d' ' -f1)"
before="$(stub_lines)"
run_bg stub-success
wait_status
check "[[ $st == 1 ]] && /usr/bin/grep -q 'is present and not this run' '$wlog'" "foreign-marker: refused before the build"
check "[[ '$(stub_lines)' == $before ]]" "foreign-marker: the prover never ran"
check "[[ \"\$(/usr/bin/shasum -a 256 '$MARKER' | cut -d' ' -f1)\" == $foreign_sha ]]" "foreign-marker: the foreign marker is left byte for byte"
rm -f "$MARKER"
run_bg stub-success
wait_status
check "[[ $st == 0 && ! -e '$MARKER' ]]" "foreign-marker control: the same run proceeds without it and cleans up"

# ---- flock held by another process, and its control ----
ready="$S/holder.ready"
/usr/bin/python3 -B - "$SHARED" "$ready" <<'PY' &
import fcntl, sys, time
f = open(sys.argv[1], "a")
fcntl.flock(f, fcntl.LOCK_EX)
open(sys.argv[2], "w").close()
time.sleep(60)
PY
holder=$!
for _ in $(seq 1 40); do [[ -e $ready ]] && break; sleep 0.25; done
before="$(stub_lines)"
run_bg stub-success
wait_status
check "[[ $st == 1 ]] && /usr/bin/grep -q 'prover lock .* is held' '$wlog'" "flock-held: refused while another process holds the shared flock"
check "[[ ! -e '$MARKER' && '$(stub_lines)' == $before ]]" "flock-held: no marker was created and the prover never ran"
kill "$holder" 2>/dev/null || true
wait "$holder" 2>/dev/null || true
run_bg stub-success
wait_status
check "[[ $st == 0 && ! -e '$MARKER' ]]" "flock-held control: the same run proceeds once the flock is released"

# ---- the sampler's RSS trip ----
prepare yes
run_bg stub-long
wait_status
check "[[ $st == 1 ]] && /usr/bin/grep -q 'killed: RSS' '$wlog'" "rss-trip: the sampler killed the prover and the wrapper refused"
check "[[ '$(last_stub)' == 'mode=stub-long '*' marker=present first=pid $wpid' ]]" "rss-trip: the marker existed during the run"
check "no_stub_running" "rss-trip: no prover stub is left"
check "[[ ! -e '$MARKER' ]]" "rss-trip: the marker is removed"

cp "$S/prove-dev-batch.committed.sh" "$W"
echo "prove-dev-batch-lock: $failures failure(s); logs in $S"
((failures == 0))
