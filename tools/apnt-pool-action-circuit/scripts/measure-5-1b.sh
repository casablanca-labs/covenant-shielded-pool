#!/usr/bin/env bash
# Task 5.1b step B: the pool action circuit's Groth16 Setup, prove and verify
# under DEVELOPMENT ZERO-VALUE parameters (toxic waste not destroyed;
# forgeable; never for value). Each phase is its own process: devsetup, then
# devprove, then devverify, serially, under nice and caffeinate -i. For each
# it records wall time and peak RSS twice (in-process getrusage, and
# /usr/bin/time -l), and samples swap, available memory and the phase's RSS
# every 5 s.
#
# usage: scripts/measure-5-1b.sh OUT-DIR EXPECTED-R1CS-SHA256 [GOMAXPROCS]
#
# OUT-DIR must be new or empty and outside any git repository. It receives:
#   keys/     R1CS, pk, vk, label, manifest, proof, public witness (the tool's DIR)
#   results/  <phase>.json (the tool's result), <phase>.time (/usr/bin/time -l),
#             <phase>.samples.tsv, <phase>.stderr, <phase>.summary.json,
#             run.json, summary.json
#   bin/      the pool-action-circuit binary built for this run
# GOMAXPROCS defaults to 4.
#
# Before every phase it refuses unless at least 20 GiB is available (free +
# inactive + speculative pages), no pool-action-circuit or known prover
# process is running, and the SP1 exclusive marker is absent. It holds the
# machine-wide prover lock for the whole run. A phase is killed if swap grows
# more than 16 GiB over the phase's baseline or its RSS passes 30 GiB (both
# checked every 5 s, so a phase shorter than that is never sampled mid-run).
#
# DEVPROVE_TARGET=small runs the same pipeline on the small test circuit (not
# the pool action circuit) to test this script, with a 2 GiB floor.
set -euo pipefail

readonly SAMPLE_SECONDS=5
# Shared with tools/apnt-successor-aggregate-sp1/aggregate-proof-runner.sh and
# tools/apnt-successor-child-circuits/relation_r2_measure.py.
readonly SHARED_PROVER_LOCK="/private/tmp/apnt-gnark-r2-proof-$UID.lock"
readonly SP1_EXCLUSIVE_MARKER="/private/tmp/bch-cloak-sp1-prover-exclusive-v1"

out=""
die() {
	echo "measure-5-1b: refusing: $*" >&2
	[[ -z $out ]] || echo "measure-5-1b: outputs so far: $out" >&2
	exit 1
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
	echo "usage: $0 OUT-DIR EXPECTED-R1CS-SHA256 [GOMAXPROCS]" >&2
	exit 2
fi
out_arg=$1
expect=$2
procs=${3:-4}
target=${DEVPROVE_TARGET:-action}
[[ $expect =~ ^[0-9a-f]{64}$ ]] || die "the expected R1CS SHA-256 must be 64 lowercase hex characters"
[[ $procs =~ ^[1-9][0-9]?$ ]] || die "GOMAXPROCS must be 1-99, got $procs"
[[ $target == action || $target == small ]] || die "DEVPROVE_TARGET must be action or small"

# Each threshold can be tightened, never loosened, from the environment
# (MEASURE_MIN_AVAILABLE_BYTES raises the floor; MEASURE_SWAP_GROWTH_TRIP_BYTES
# and MEASURE_RSS_TRIP_BYTES lower the trips); the script's own tests use this.
# The small test circuit peaks near 25 MB, so its floor is 2 GiB; --target
# small can set up nothing but that circuit.
tighten() { # default override direction(min|max)
	local v=$1
	if [[ -n $2 ]]; then
		[[ $2 =~ ^[1-9][0-9]{0,17}$ ]] || { echo "measure-5-1b: refusing: threshold override $2 is not a positive integer" >&2; exit 1; }
		if [[ $3 == max ]]; then ((v = $2 > v ? $2 : v)); else ((v = $2 < v ? $2 : v)); fi
	fi
	echo "$v"
}
floor=$((20 * 1024 * 1024 * 1024))
[[ $target == small ]] && floor=$((2 * 1024 * 1024 * 1024))
MIN_AVAILABLE_BYTES="$(tighten "$floor" "${MEASURE_MIN_AVAILABLE_BYTES:-}" max)"
SWAP_GROWTH_TRIP_BYTES="$(tighten $((16 * 1024 * 1024 * 1024)) "${MEASURE_SWAP_GROWTH_TRIP_BYTES:-}" min)"
RSS_TRIP_BYTES="$(tighten $((30 * 1024 * 1024 * 1024)) "${MEASURE_RSS_TRIP_BYTES:-}" min)"
readonly MIN_AVAILABLE_BYTES SWAP_GROWTH_TRIP_BYTES RSS_TRIP_BYTES

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
repo="$(git -C "$here" rev-parse --show-toplevel)"
corpus="$repo/packages/protocol-runtime/test-vectors/apnt-pool-v1-action-circuit-vectors.json"

# ---- output directory ----
created=false
if [[ -e $out_arg || -L $out_arg ]]; then
	[[ -d $out_arg && ! -L $out_arg ]] || die "$out_arg is not a directory"
	[[ -z "$(ls -A "$out_arg")" ]] || die "$out_arg is not empty; a measurement is never overwritten"
else
	mkdir -p "$out_arg"
	created=true
fi
resolved="$(cd "$out_arg" && pwd -P)"
if git -C "$resolved" rev-parse --git-dir >/dev/null 2>&1; then
	$created && rmdir "$resolved"
	die "$resolved is inside a git repository; outputs live outside the repository"
fi
out=$resolved
keys="$out/keys"
results="$out/results"
mkdir "$results" "$out/bin"

# ---- source state ----
dirty="$(git -C "$repo" status --porcelain -- tools/apnt-pool-action-circuit packages/protocol-runtime/test-vectors/apnt-pool-v1-action-circuit-vectors.json)"
[[ -z $dirty ]] || die "uncommitted changes in the tool or the corpus:
$dirty"
head_commit="$(git -C "$repo" rev-parse HEAD)"
git_dir="$(cd "$repo" && cd "$(git rev-parse --git-dir)" && pwd -P)"
common_dir="$(cd "$repo" && cd "$(git rev-parse --git-common-dir)" && pwd -P)"
main_checkout=false
[[ $git_dir == "$common_dir" ]] && main_checkout=true

# ---- machine checks ----
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

# Resident bytes of every pool-action-circuit process (there is at most one:
# every phase starts only when none is running).
phase_rss_bytes() {
	/bin/ps -axo rss=,comm= | /usr/bin/awk '
		{ exe = $0; sub(/^ *[0-9]+ +/, "", exe); sub(/^.*\//, "", exe) }
		exe == "pool-action-circuit" { kib += $1 }
		END { printf "%.0f\n", kib * 1024 }'
}

other_provers() {
	/bin/ps -axo pid=,comm= | /usr/bin/awk -v self="$$" '
		{ exe = $0; sub(/^ *[0-9]+ +/, "", exe); sub(/^.*\//, "", exe) }
		$1 == self { next }
		exe == "pool-action-circuit" || exe == "apnt-pool-action-circuit.test" { print; next }
		exe ~ /^apnt-pool-ceremony/ { print; next }
		exe ~ /^(cargo-prove|sp1-prover|sp1_core)(-|$)/ { print; next }
		exe ~ /^apnt-.*-(runner|prover)(-[[:alnum:]_.-]+)?$/ { print; next }
		exe ~ /(^|[-_])(prove|prover)([-_]|$)/ { print; next }
		exe ~ /^(r2-run|r3-run|relation-r2-run|apnt-successor-child-circuits(\.test)?|apnt-child-circuits-cost(\.test)?)$/ { print; next }'
}

require_quiet_machine() {
	local phase=$1 others avail
	others="$(other_provers)"
	[[ -z $others ]] || die "$phase: another prover or pool-action-circuit process is running:
$others"
	[[ ! -e $SP1_EXCLUSIVE_MARKER && ! -L $SP1_EXCLUSIVE_MARKER ]] || die "$phase: the SP1 exclusive marker $SP1_EXCLUSIVE_MARKER is present"
	avail="$(available_bytes)" || die "$phase: vm_stat unreadable"
	((avail >= MIN_AVAILABLE_BYTES)) || die "$phase: $avail bytes available (free + inactive + speculative), below the floor of $MIN_AVAILABLE_BYTES"
}

# The machine-wide prover lock, held on fd 9 until this script and every
# phase it started have exited. Status 3 alone means another holder.
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
((lock_status == 0)) || { ((lock_status == 3)) && die "the machine-wide prover lock $SHARED_PROVER_LOCK is held by another prover"; die "could not take $SHARED_PROVER_LOCK (status $lock_status)"; }

require_quiet_machine "build"

# ---- build (fresh, into this run's bin/) ----
(cd "$here" && GOPROXY=off GOFLAGS=-mod=readonly go build -o "$out/bin/" ./cmd/pool-action-circuit)
bin="$out/bin/pool-action-circuit"
[[ -x $bin ]] || die "the build produced no binary"

/usr/bin/python3 - "$results/run.json" <<PY
import json, subprocess, sys
def sh(*a):
    return subprocess.run(a, capture_output=True, text=True).stdout.strip()
json.dump({
    "parameters": "DEVELOPMENT ZERO-VALUE — toxic waste not destroyed; forgeable; never for value",
    "script": "tools/apnt-pool-action-circuit/scripts/measure-5-1b.sh",
    "startedUtc": sh("/bin/date", "-u", "+%Y-%m-%dT%H:%M:%SZ"),
    "target": "$target",
    "expectedR1csSha256": "$expect",
    "gomaxprocs": $procs,
    "repo": "$repo",
    "headCommit": "$head_commit",
    "mainCheckout": "$main_checkout" == "true",
    "corpus": "$corpus",
    "outDir": "$out",
    "binarySha256": sh("/usr/bin/shasum", "-a", "256", "$bin").split()[0],
    "goVersion": sh("go", "version"),
    "hwMemsizeBytes": int(sh("/usr/sbin/sysctl", "-n", "hw.memsize")),
    "cpu": sh("/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"),
    "ncpu": int(sh("/usr/sbin/sysctl", "-n", "hw.ncpu")),
    "os": sh("/usr/bin/sw_vers", "-productVersion"),
    "thresholds": {"minAvailableBytes": $MIN_AVAILABLE_BYTES, "swapGrowthTripBytes": $SWAP_GROWTH_TRIP_BYTES,
                   "rssTripBytes": $RSS_TRIP_BYTES, "sampleSeconds": $SAMPLE_SECONDS},
}, open(sys.argv[1], "w"), indent=2)
PY

# ---- phases ----
sample() { # phase-file swap0 -> prints "swap avail rss"
	local swap avail rss
	swap="$(swap_used_bytes)" || swap=-1
	avail="$(available_bytes)" || avail=-1
	rss="$(phase_rss_bytes)" || rss=-1
	printf '%s\t%s\t%s\t%s\n' "$(/bin/date +%s)" "$swap" "$avail" "$rss" >>"$1"
	echo "$swap $avail $rss"
}

run_phase() {
	local phase=$1
	shift
	require_quiet_machine "$phase"
	local samples="$results/$phase.samples.tsv" swap0 status=0 tripped="" pid swap avail rss n
	printf 'epoch_s\tswap_used_bytes\tavailable_bytes\tphase_rss_bytes\n' >"$samples"
	swap0="$(swap_used_bytes)" || die "$phase: vm.swapusage unreadable"
	sample "$samples" >/dev/null
	echo "measure-5-1b: $phase started $(/bin/date)"
	GOMAXPROCS=$procs /usr/bin/caffeinate -i /usr/bin/time -l -o "$results/$phase.time" \
		/usr/bin/nice -n 10 "$bin" "$phase" "$@" "$keys" "$results/$phase.json" 2>"$results/$phase.stderr" &
	pid=$!
	n=0
	while kill -0 "$pid" 2>/dev/null; do
		sleep 1
		n=$((n + 1))
		((n % SAMPLE_SECONDS == 0)) || continue
		read -r swap avail rss <<<"$(sample "$samples")"
		if ((swap >= 0 && swap - swap0 > SWAP_GROWTH_TRIP_BYTES)); then
			tripped="swap grew $((swap - swap0)) bytes over its baseline $swap0"
		elif ((rss > RSS_TRIP_BYTES)); then
			tripped="phase RSS $rss bytes"
		fi
		if [[ -n $tripped ]]; then
			/usr/bin/pkill -TERM -x pool-action-circuit || true
			break
		fi
	done
	wait "$pid" || status=$?
	sample "$samples" >/dev/null
	/usr/bin/python3 - "$results" "$phase" "$status" "$swap0" "$tripped" <<'PY'
import json, os, re, sys
results, phase, status, swap0, tripped = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
rows = [l.rstrip("\n").split("\t") for l in open(f"{results}/{phase}.samples.tsv")][1:]
swaps = [int(r[1]) for r in rows if int(r[1]) >= 0]
avails = [int(r[2]) for r in rows if int(r[2]) >= 0]
rss = [int(r[3]) for r in rows if int(r[3]) >= 0]
s = {"phase": phase, "exitStatus": status, "tripped": tripped or None, "samples": len(rows),
     "swapBaselineBytes": swap0, "swapMaxBytes": max(swaps), "swapEndBytes": swaps[-1],
     "swapGrowthMaxBytes": max(swaps) - swap0, "availableMinBytes": min(avails), "sampledRSSMaxBytes": max(rss)}
tf = f"{results}/{phase}.time"
if os.path.exists(tf) and os.path.getsize(tf):
    t = open(tf).read()
    real = re.search(r"([\d.]+) real", t)
    mrss = re.search(r"(\d+)\s+maximum resident set size", t)
    foot = re.search(r"(\d+)\s+peak memory footprint", t)
    s["timeRealSeconds"] = float(real.group(1)) if real else None
    s["timeMaxRSSBytes"] = int(mrss.group(1)) if mrss else None
    s["timePeakMemoryFootprintBytes"] = int(foot.group(1)) if foot else None
jf = f"{results}/{phase}.json"
if os.path.exists(jf):
    j = json.load(open(jf))
    s["parameters"] = j.get("parameters")
    s["processWallSeconds"] = j.get("processWallSeconds")
    s["processMaxRSSBytes"] = j.get("processMaxRSSBytes")
    s["error"] = j.get("error")
    s["steps"] = {p["name"]: {"seconds": p["seconds"], "maxRSSBytesAtEnd": p["maxRSSBytesAtEnd"], "goHeldPeakBytes": p["goHeldPeakBytes"]} for p in (j.get("phases") or [])}
json.dump(s, open(f"{results}/{phase}.summary.json", "w"), indent=2)
PY
	echo "measure-5-1b: $phase ended $(/bin/date) with status $status"
	[[ -z $tripped ]] || die "$phase killed: $tripped"
	((status == 0)) || die "$phase exited with status $status; see $results/$phase.stderr"
}

run_phase devsetup --target "$target" --expect-r1cs-sha256 "$expect"
run_phase devprove --target "$target" --corpus "$corpus"
run_phase devverify --target "$target" --corpus "$corpus"

/usr/bin/python3 - "$results" <<'PY'
import json, sys
r = sys.argv[1]
json.dump({"run": json.load(open(f"{r}/run.json")),
           "phases": [json.load(open(f"{r}/{p}.summary.json")) for p in ("devsetup", "devprove", "devverify")]},
          open(f"{r}/summary.json", "w"), indent=2)
PY
echo "measure-5-1b: done; results in $out"
