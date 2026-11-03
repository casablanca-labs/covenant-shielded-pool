#!/usr/bin/env bash
# RESEARCH PROTOTYPE, NOT REVIEWED (ARCH-238, run R-393).
#
# with-prover-lock.sh MIN-AVAILABLE-GIB -- COMMAND [ARG...]
#
# Runs COMMAND holding the machine-wide prover lock the way
# ../../scripts/run-phased.sh takes it: fd 9 opened for append on
# /private/tmp/apnt-gnark-r2-proof-$UID.lock and locked with a non-blocking
# flock, then ~/proof-scratch/.prover.lock created with noclobber and removed
# on exit only if it still names this process. It refuses (exit 75, nothing
# run) if the lock is held, a marker it did not create is present, the SP1
# exclusive marker is present, another prover or ceremony process runs, or
# free + inactive + speculative memory is below MIN-AVAILABLE-GIB. It never
# breaks or deletes a lock or marker it did not create; the caller waits and
# retries. COMMAND's exit status is returned.
set -euo pipefail

readonly SHARED_PROVER_LOCK="/private/tmp/apnt-gnark-r2-proof-$UID.lock"
readonly SP1_EXCLUSIVE_MARKER="/private/tmp/bch-cloak-sp1-prover-exclusive-v1"
readonly PROVER_MARKER="$HOME/proof-scratch/.prover.lock"

refuse() {
	echo "with-prover-lock: refusing: $*" >&2
	exit 75
}

[[ $# -ge 3 && $2 == "--" && $1 =~ ^[0-9]+$ ]] || {
	sed -n '2,16p' "$0" >&2
	exit 2
}
min_gib=$1
shift 2

marker_owned=false
cleanup() {
	if $marker_owned && [[ -f $PROVER_MARKER ]] && grep -q "^pid $$\$" "$PROVER_MARKER" 2>/dev/null; then
		rm -f "$PROVER_MARKER"
	fi
}
trap cleanup EXIT

available_bytes() {
	/usr/bin/vm_stat | /usr/bin/awk '
		NR == 1 && match($0, /page size of [0-9]+ bytes/) {
			v = substr($0, RSTART, RLENGTH); gsub(/[^0-9]/, "", v); page = v + 0
		}
		/^Pages (free|inactive|speculative):/ { v = $3; gsub(/\./, "", v); pages += v + 0 }
		END { if (page <= 0) exit 1; printf "%.0f\n", pages * page }'
}

other_provers() {
	/bin/ps -axo pid=,comm= | /usr/bin/awk -v self="$$" '
		{ exe = $0; sub(/^ *[0-9]+ +/, "", exe); sub(/^.*\//, "", exe) }
		$1 == self { next }
		exe == "pool-action-circuit" || exe == "apnt-pool-action-circuit.test" { print; next }
		exe ~ /^apnt-pool-ceremony/ || exe ~ /^apnt-pool-crscheck/ || exe == "crscheck.test" { print; next }
		exe ~ /^(cargo-prove|sp1-prover|sp1_core)(-|$)/ { print; next }
		exe ~ /^apnt-.*-(runner|prover)(-[[:alnum:]_.-]+)?$/ { print; next }
		exe ~ /(^|[-_])(prove|prover)([-_]|$)/ { print; next }'
}

[[ ! -L $SHARED_PROVER_LOCK ]] || refuse "$SHARED_PROVER_LOCK is a symlink"
exec 9>>"$SHARED_PROVER_LOCK"
lock_status=0
/usr/bin/python3 -B - <<'PY' || lock_status=$?
import fcntl, sys
try:
    fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit(3)
PY
((lock_status == 0)) || { ((lock_status == 3)) && refuse "the machine-wide prover lock is held by another prover"; refuse "could not take the lock (status $lock_status)"; }

others="$(other_provers)"
[[ -z $others ]] || refuse "another prover or ceremony process is running:
$others"
[[ ! -e $SP1_EXCLUSIVE_MARKER && ! -L $SP1_EXCLUSIVE_MARKER ]] || refuse "the SP1 exclusive marker is present"
[[ ! -e $PROVER_MARKER ]] || refuse "$PROVER_MARKER is present and not ours:
$(cat "$PROVER_MARKER" 2>/dev/null)"
avail="$(available_bytes)" || refuse "vm_stat unreadable"
((avail >= min_gib * 1073741824)) || refuse "$avail bytes available, below the floor of $min_gib GiB"

mkdir -p "$(dirname "$PROVER_MARKER")"
(
	set -o noclobber
	printf 'pid %s\nscript %s\ncommand %s\nstarted %s\n' "$$" "$0" "$*" "$(/bin/date)" >"$PROVER_MARKER"
) 2>/dev/null || refuse "could not create $PROVER_MARKER"
marker_owned=true
echo "with-prover-lock: holding the prover lock; available $avail bytes at start" >&2

status=0
"$@" || status=$?
exit "$status"
