#!/usr/bin/env bash
# ENG-421 (task 5.4 slice 1): prove host positives of the pool action circuit
# under DEVELOPMENT ZERO-VALUE parameters (toxic waste not destroyed;
# forgeable; never for value), or, with --ceremony (ENG-486), under registry
# entry 1 revision 3's Chipnet simulated-ceremony keys (SIMULATED SINGLE-PARTY
# SETUP - ZERO-VALUE TEST ONLY; the project could forge proofs under them), so
# the pool aggregate has B distinct child proofs to execute over. This is
# proving. It loads the R1CS and proving key once (gnark-reference
# prove-batch) and proves the named entries one after another in one process.
#
# usage: scripts/prove-dev-batch.sh [--ceremony R1CS] KEYS-DIR OUT-DIR ENTRY[,ENTRY...] [GOMAXPROCS]
#
# KEYS-DIR is a devsetup directory (tools/apnt-pool-action-circuit, task
# 5.1b), or with --ceremony the task-5.1c ceremony directory (proving.key,
# verifying.key, keys.meta.json) and R1CS its circuit; gnark-reference checks
# each against the registry's pins. The entries come from the action-circuit
# corpus and fixtures/pool-aggregate-batch-corpus-v2.json (314-byte records).
# OUT-DIR must be new and outside any git repository; it receives
# proofs/<entry>.proof.bin, result.json, time.txt, samples.tsv, stderr.txt,
# run.json and bin/.
#
# The machine checks are tools/apnt-pool-action-circuit/scripts/measure-5-1b.sh's:
# before the build and the run it refuses unless at least 20 GiB is available
# (free + inactive + speculative), no pool-action-circuit or known prover
# process is running, the SP1 exclusive marker is absent, and it holds the
# machine-wide prover lock for the whole run. The run is killed if swap grows
# more than 16 GiB over its baseline or its RSS passes 30 GiB, sampled every 5 s.
#
# Locks, as tools/apnt-pool-ceremony/scripts/run-phased.sh takes them (ENG-430):
# first the shared flock on /private/tmp/apnt-gnark-r2-proof-$UID.lock (fd 9,
# LOCK_EX|LOCK_NB, held until this script and every child it started have
# exited), so this run and a ceremony exclude each other; then, after the
# quiet-machine check, the marker ~/proof-scratch/.prover.lock, created with
# noclobber and holding "pid / script / out / started", so tools and people
# that look only at the marker see a running development prove. Any marker
# that is not this run's refuses. On exit (success, failure, a tripped kill,
# or INT/TERM/HUP, which first stop the prover child) the marker is removed
# only if this run created it and its pid line is this run's. A SIGKILL leaves
# it in place: a stale marker blocks, it never admits.
set -euo pipefail

readonly SAMPLE_SECONDS=5
readonly MIN_AVAILABLE_BYTES=$((20 * 1024 * 1024 * 1024))
readonly SWAP_GROWTH_TRIP_BYTES=$((16 * 1024 * 1024 * 1024))
readonly RSS_TRIP_BYTES=$((30 * 1024 * 1024 * 1024))
# Shared with measure-5-1b.sh, aggregate-proof-runner.sh and relation_r2_measure.py.
readonly SHARED_PROVER_LOCK="/private/tmp/apnt-gnark-r2-proof-$UID.lock"
readonly SP1_EXCLUSIVE_MARKER="/private/tmp/bch-cloak-sp1-prover-exclusive-v1"
readonly PROVER_MARKER="$HOME/proof-scratch/.prover.lock"

die() { echo "prove-dev-batch: refusing: $*" >&2; exit 1; }

marker_owned=false
pid=""
cleanup() {
	if [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null; then
		/usr/bin/pkill -TERM -x gnark-reference || true
		kill -TERM "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	fi
	if $marker_owned && [[ -f $PROVER_MARKER && ! -L $PROVER_MARKER ]] && grep -q "^pid $$\$" "$PROVER_MARKER" 2>/dev/null; then
		rm -f "$PROVER_MARKER"
	fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

ceremony_r1cs=""
if [[ ${1:-} == --ceremony ]]; then
	[[ $# -ge 2 ]] || { echo "usage: $0 [--ceremony R1CS] KEYS-DIR OUT-DIR ENTRY[,ENTRY...] [GOMAXPROCS]" >&2; exit 2; }
	ceremony_r1cs=$2
	shift 2
fi
[[ $# -eq 3 || $# -eq 4 ]] || { echo "usage: $0 [--ceremony R1CS] KEYS-DIR OUT-DIR ENTRY[,ENTRY...] [GOMAXPROCS]" >&2; exit 2; }
keys=$1
out=$2
entries=$3
procs=${4:-4}
[[ $procs =~ ^[1-9][0-9]?$ ]] || die "GOMAXPROCS must be 1-99"
[[ $entries =~ ^[a-z0-9-]+(,[a-z0-9-]+)*$ ]] || die "ENTRY names are lowercase, digits and hyphens, comma-separated"

here="$(cd "$(dirname "$0")/.." && pwd -P)"
repo="$(git -C "$here" rev-parse --show-toplevel)"
[[ ! -e $out ]] || die "$out already exists"
parent="$(cd "$(dirname "$out")" && pwd -P)"
if git -C "$parent" rev-parse --show-toplevel >/dev/null 2>&1; then die "$out is inside a git work tree"; fi
if [[ -n $ceremony_r1cs ]]; then
	[[ -f $keys/keys.meta.json && -f $ceremony_r1cs ]] || die "$keys has no ceremony key metadata, or $ceremony_r1cs is not a file"
	key_args=(--ceremony-keys "$keys" --r1cs "$ceremony_r1cs")
	parameters="SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY: the project could forge proofs under these keys; never for value"
else
	[[ -f $keys/PARAMETERS-LABEL.txt ]] || die "$keys has no development parameter label"
	key_args=(--keys "$keys")
	parameters="DEVELOPMENT ZERO-VALUE — toxic waste not destroyed; forgeable; never for value"
fi
dirty="$(git -C "$repo" status --porcelain -- tools/apnt-pool-aggregate-sp1/gnark-reference tools/apnt-pool-aggregate-sp1/fixtures/pool-aggregate-batch-corpus-v2.json tools/apnt-pool-action-circuit packages/protocol-runtime/test-vectors/apnt-pool-v1-action-circuit-vectors.json)"
[[ -z $dirty ]] || die "uncommitted changes in the prover, the circuit or a corpus:
$dirty"

available_bytes() {
	/usr/bin/vm_stat | /usr/bin/awk '
		NR == 1 && match($0, /page size of [0-9]+ bytes/) {
			v = substr($0, RSTART, RLENGTH); gsub(/[^0-9]/, "", v); page = v + 0
		}
		/^Pages (free|inactive|speculative):/ { v = $3; gsub(/\./, "", v); pages += v + 0 }
		END { if (page <= 0) exit 1; printf "%.0f\n", pages * page }'
}
swap_used_bytes() {
	/usr/sbin/sysctl -n vm.swapusage | /usr/bin/awk '
		{
			for (i = 1; i <= NF; i++) if ($i == "used") {
				v = $(i + 2); u = substr(v, length(v), 1); a = substr(v, 1, length(v) - 1) + 0
				m = u == "K" ? 1024 : u == "M" ? 1048576 : u == "G" ? 1073741824 : 0
				if (m == 0) exit 1
				printf "%.0f\n", a * m; found = 1
			}
		}
		END { if (!found) exit 1 }'
}
run_rss_bytes() {
	/bin/ps -axo rss=,comm= | /usr/bin/awk '
		{ exe = $0; sub(/^ *[0-9]+ +/, "", exe); sub(/^.*\//, "", exe) }
		exe == "gnark-reference" { kib += $1 }
		END { printf "%.0f\n", kib * 1024 }'
}
other_provers() {
	/bin/ps -axo pid=,comm= | /usr/bin/awk -v self="$$" '
		{ exe = $0; sub(/^ *[0-9]+ +/, "", exe); sub(/^.*\//, "", exe) }
		$1 == self { next }
		exe == "gnark-reference" || exe == "pool-action-circuit" || exe == "apnt-pool-action-circuit.test" { print; next }
		exe ~ /^apnt-pool-ceremony/ { print; next }
		exe ~ /^(cargo-prove|sp1-prover|sp1_core)(-|$)/ { print; next }
		exe ~ /^apnt-.*-(runner|prover)(-[[:alnum:]_.-]+)?$/ { print; next }
		exe ~ /(^|[-_])(prove|prover)([-_]|$)/ { print; next }
		exe ~ /^(r2-run|r3-run|relation-r2-run|apnt-successor-child-circuits(\.test)?|apnt-child-circuits-cost(\.test)?)$/ { print; next }'
}
require_quiet_machine() {
	local phase=$1 others avail
	others="$(other_provers)"
	[[ -z $others ]] || die "$phase: another prover is running:
$others"
	[[ ! -e $SP1_EXCLUSIVE_MARKER && ! -L $SP1_EXCLUSIVE_MARKER ]] || die "$phase: the SP1 exclusive marker $SP1_EXCLUSIVE_MARKER is present"
	if [[ -e $PROVER_MARKER || -L $PROVER_MARKER ]] && ! { $marker_owned && grep -q "^pid $$\$" "$PROVER_MARKER" 2>/dev/null; }; then
		die "$phase: $PROVER_MARKER is present and not this run's:
$(cat "$PROVER_MARKER" 2>/dev/null)"
	fi
	avail="$(available_bytes)" || die "$phase: vm_stat unreadable"
	((avail >= MIN_AVAILABLE_BYTES)) || die "$phase: $avail bytes available, below the floor of $MIN_AVAILABLE_BYTES"
}

[[ ! -L $SHARED_PROVER_LOCK ]] || die "$SHARED_PROVER_LOCK is a symlink"
exec 9>>"$SHARED_PROVER_LOCK"
lock_status=0
/usr/bin/python3 -B - <<'PY' || lock_status=$?
import fcntl, sys
try:
    fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit(3)
PY
((lock_status == 0)) || die "the machine-wide prover lock $SHARED_PROVER_LOCK is held (status $lock_status)"

require_quiet_machine build
mkdir -p "$(dirname "$PROVER_MARKER")"
(
	set -o noclobber
	printf 'pid %s\nscript %s\nout %s\nstarted %s\n' "$$" "$0" "$parent/$(basename "$out")" "$(/bin/date)" >"$PROVER_MARKER"
) 2>/dev/null || die "could not create $PROVER_MARKER"
marker_owned=true

mkdir -p "$out/bin"
(cd "$here/gnark-reference" && GOPROXY=off GOFLAGS=-mod=readonly go build -o "$out/bin/" .)
bin="$out/bin/gnark-reference"
[[ -x $bin ]] || die "the build produced no binary"

/usr/bin/python3 - "$out/run.json" "$repo" "$bin" "$keys" "$entries" "$procs" "$parameters" "$ceremony_r1cs" <<'PY'
import json, subprocess, sys
out, repo, binary, keys, entries, procs, parameters, r1cs = sys.argv[1:]
sh = lambda *a: subprocess.run(a, capture_output=True, text=True).stdout.strip()
json.dump({
    "parameters": parameters,
    "ceremonyR1cs": r1cs or None,
    "script": "tools/apnt-pool-aggregate-sp1/scripts/prove-dev-batch.sh",
    "startedUtc": sh("/bin/date", "-u", "+%Y-%m-%dT%H:%M:%SZ"),
    "repo": repo,
    "headCommit": sh("git", "-C", repo, "rev-parse", "HEAD"),
    "keys": keys,
    "entries": entries.split(","),
    "gomaxprocs": int(procs),
    "binarySha256": sh("/usr/bin/shasum", "-a", "256", binary).split()[0],
    "goVersion": sh("go", "version"),
    "hwMemsizeBytes": int(sh("/usr/sbin/sysctl", "-n", "hw.memsize")),
    "cpu": sh("/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"),
    "os": sh("/usr/bin/sw_vers", "-productVersion"),
}, open(out, "w"), indent=2)
PY

require_quiet_machine run
samples="$out/samples.tsv"
printf 'epoch_s\tswap_used_bytes\tavailable_bytes\trss_bytes\n' >"$samples"
swap0="$(swap_used_bytes)" || die "vm.swapusage unreadable"
echo "prove-dev-batch: started $(/bin/date)"
GOMAXPROCS=$procs /usr/bin/caffeinate -i /usr/bin/time -l -o "$out/time.txt" \
	/usr/bin/nice -n 10 "$bin" prove-batch "${key_args[@]}" \
	--corpus "$repo/packages/protocol-runtime/test-vectors/apnt-pool-v1-action-circuit-vectors.json" \
	--corpus "$here/fixtures/pool-aggregate-batch-corpus-v2.json" \
	--entries "$entries" "$out/proofs" "$out/result.json" 2>"$out/stderr.txt" &
pid=$!
status=0 tripped="" n=0
while kill -0 "$pid" 2>/dev/null; do
	sleep 1
	n=$((n + 1))
	((n % SAMPLE_SECONDS == 0)) || continue
	swap="$(swap_used_bytes)" || swap=-1
	avail="$(available_bytes)" || avail=-1
	rss="$(run_rss_bytes)" || rss=-1
	printf '%s\t%s\t%s\t%s\n' "$(/bin/date +%s)" "$swap" "$avail" "$rss" >>"$samples"
	if ((swap >= 0 && swap - swap0 > SWAP_GROWTH_TRIP_BYTES)); then
		tripped="swap grew $((swap - swap0)) bytes over its baseline $swap0"
	elif ((rss > RSS_TRIP_BYTES)); then
		tripped="RSS $rss bytes"
	fi
	if [[ -n $tripped ]]; then
		/usr/bin/pkill -TERM -x gnark-reference || true
		break
	fi
done
wait "$pid" || status=$?
echo "prove-dev-batch: finished $(/bin/date) status $status"
[[ -z $tripped ]] || die "killed: $tripped"
exit "$status"
