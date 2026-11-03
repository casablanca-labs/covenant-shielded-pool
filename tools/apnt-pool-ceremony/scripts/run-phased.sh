#!/usr/bin/env bash
# Runs a simulated-single-party ceremony (zero-value tests only) with every
# phase in its own process, then the standalone verifier with both
# out-of-band anchors (and the circuit anchor when --expect-r1cs-sha256 is
# given), and measures each phase: wall time and peak memory
# (/usr/bin/time -l), the process's sampled RSS, available memory, swap, and
# the disk the ceremony and work directories use afterwards.
#
# usage: scripts/run-phased.sh OUT-ROOT \
#          --ptau F --ptau-pin P --ptau-source S --r1cs F --label L \
#          --ceremony-id ID --contributions N --beacon HEX --beacon-source S \
#          [--expect-r1cs-sha256 H] [--min-available-gib G] [--rss-trip-gib G] \
#          [--stop-after init|contribute|seal]
#          [--min-disk-gib G]
#        scripts/run-phased.sh OUT-ROOT --resume-seal \
#          --ptau F --ptau-pin P --r1cs F --contributions N --beacon HEX \
#          --beacon-source S [--expect-r1cs-sha256 H] [memory flags]
#        scripts/run-phased.sh OUT-ROOT --verify-only CEREMONY-DIR \
#          --ptau F --ptau-pin P --r1cs F --beacon HEX \
#          [--expect-r1cs-sha256 H] [memory flags]
#
# --stop-after contribute then --resume-seal splits a run in two, so that a
# pre-announced beacon (a future block hash) becomes known only after the
# last contribution: the second invocation seals and verifies the same
# OUT-ROOT with the binaries the first built. It refuses unless the checkout
# is at the first invocation's commit with a clean tools/apnt-pool-ceremony,
# the running harness and every scripts/*.sh (the 5.1c wrapper included)
# have the digests the first invocation recorded, it was invoked through the
# same wrapper (RUN_PHASED_WRAPPER, or none), and the binaries, R1CS and
# phase-1 pin are unchanged.
# --verify-only runs only the standalone verifier, with both anchors and the
# same guards, on an existing sealed ceremony directory (which it only reads),
# e.g. to re-verify a task 5.1c ceremony later.
#
# OUT-ROOT must be new or empty and outside any git repository. It receives
#   ceremony/  the published ceremony directory (transcript, contribution
#              states, keys, key metadata)
#   work/      the coordinator's state between phases; removed after VALID
#   results/   <phase>.time, <phase>.samples.tsv, <phase>.stdout,
#              <phase>.stderr, <phase>.summary.json, run.json, summary.json
#   bin/       the binaries built for this run from the committed tree
#   SIMULATED-SINGLE-PARTY-ZERO-VALUE.txt   the fixed notice
#
# Phases: init (phase-1 import and gnark's Phase2.Initialize), contribute-NN
# (one automated contribution each), seal (phase-1 re-import, beacon, keys),
# verify (apnt-pool-ceremony-verify --expect-phase1-pin --expect-beacon
# --json, plus --expect-r1cs-sha256 when given, so the verifier checks the
# circuit file itself and its report records anchors.r1cs=true; ENG-460).
# The run fails unless the verifier exits 0 and reports VALID; exit 3
# (CONSISTENT-UNANCHORED) is a failure.
#
# Before every phase it refuses unless the available memory (free + inactive
# + speculative pages) is at least --min-available-gib (default 20), no other
# prover or ceremony process runs, the SP1 exclusive marker and
# ~/proof-scratch/.prover.lock are absent; it holds the machine-wide prover
# lock for the whole run and writes ~/proof-scratch/.prover.lock while it
# runs, and unless OUT-ROOT's file system has --min-disk-gib free (default
# 10). A phase is killed if its RSS passes --rss-trip-gib (default 12) or
# swap grows more than 4 GiB over the phase's baseline, sampled every 2 s.
# GOMAXPROCS (default 4), GOMEMLIMIT, GOGC and GODEBUG pass through to every
# phase and are recorded; with GODEBUG=gctrace=1 each phase's summary also
# carries the Go heap at its largest and the largest live heap after a GC.
set -euo pipefail

# Bash reads a script while it runs it, so an edit to this file, or a checkout
# that changes it, during a run of several hours would change the running
# code (it has: ENG-331). Run from a private copy; the build below is from the
# committed tree and lands in OUT-ROOT/bin.
if [[ -z ${RUN_PHASED_SELF:-} ]]; then
	self_copy="$(/usr/bin/mktemp -t run-phased)"
	/bin/cp "$0" "$self_copy"
	RUN_PHASED_SELF=$self_copy RUN_PHASED_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)" \
		exec /bin/bash "$self_copy" "$@"
fi

readonly SAMPLE_SECONDS=2
# Shared with tools/apnt-pool-action-circuit/scripts/measure-5-1b.sh and the
# SP1 runners.
readonly SHARED_PROVER_LOCK="/private/tmp/apnt-gnark-r2-proof-$UID.lock"
readonly SP1_EXCLUSIVE_MARKER="/private/tmp/bch-cloak-sp1-prover-exclusive-v1"
readonly PROVER_MARKER="$HOME/proof-scratch/.prover.lock"
readonly NOTICE="SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY. The project ran every contribution and could have kept the randomness, so it can forge proofs under these keys. These keys must never guard value."

out=""
marker_owned=false
die() {
	echo "run-phased: refusing: $*" >&2
	[[ -z $out ]] || echo "run-phased: outputs so far: $out" >&2
	exit 1
}
cleanup() {
	rm -f "$RUN_PHASED_SELF"
	if $marker_owned && [[ -f $PROVER_MARKER ]] && grep -q "^pid $$\$" "$PROVER_MARKER" 2>/dev/null; then
		rm -f "$PROVER_MARKER"
	fi
}
trap cleanup EXIT

[[ $# -ge 1 ]] || { sed -n '2,62p' "$0" >&2; exit 2; }
out_arg=$1
shift
ptau="" pin="" ptau_source="" r1cs="" label="" ceremony_id="" contributions="" beacon="" beacon_source=""
expect_r1cs="" min_gib=20 rss_gib=12 stop_after="" verify_only="" resume=false disk_gib=10
while [[ $# -gt 0 ]]; do
	if [[ $1 == --resume-seal ]]; then
		resume=true
		shift
		continue
	fi
	[[ $# -ge 2 ]] || die "flag $1 needs a value"
	case $1 in
	--ptau) ptau=$2 ;;
	--ptau-pin) pin=$2 ;;
	--ptau-source) ptau_source=$2 ;;
	--r1cs) r1cs=$2 ;;
	--label) label=$2 ;;
	--ceremony-id) ceremony_id=$2 ;;
	--contributions) contributions=$2 ;;
	--beacon) beacon=$2 ;;
	--beacon-source) beacon_source=$2 ;;
	--expect-r1cs-sha256) expect_r1cs=$2 ;;
	--min-available-gib) min_gib=$2 ;;
	--rss-trip-gib) rss_gib=$2 ;;
	--stop-after) stop_after=$2 ;;
	--verify-only) verify_only=$2 ;;
	--min-disk-gib) disk_gib=$2 ;;
	*) die "unknown flag $1" ;;
	esac
	shift 2
done
needed=(ptau pin ptau_source r1cs label ceremony_id contributions beacon beacon_source)
# A run that stops before sealing does not need the beacon yet.
[[ $stop_after != init && $stop_after != contribute ]] || needed=(ptau pin ptau_source r1cs label ceremony_id contributions)
if $resume; then
	[[ -z $verify_only && -z $stop_after ]] || die "--resume-seal takes neither --verify-only nor --stop-after"
	needed=(ptau pin r1cs contributions beacon beacon_source)
fi
if [[ -n $verify_only ]]; then
	needed=(ptau pin r1cs beacon)
	[[ -f $verify_only/transcript.json ]] || die "--verify-only $verify_only holds no transcript.json"
	verify_only="$(cd "$verify_only" && pwd -P)"
	contributions=0
fi
for v in "${needed[@]}"; do
	[[ -n ${!v} ]] || die "--${v//_/-} is required"
done
[[ -n $verify_only || $contributions =~ ^[1-9][0-9]?$ ]] || die "--contributions must be 1-99"
[[ $min_gib =~ ^[0-9]+$ && $rss_gib =~ ^[1-9][0-9]*$ && $disk_gib =~ ^[0-9]+$ ]] || die "--min-available-gib, --rss-trip-gib and --min-disk-gib are whole GiB"
[[ -z $expect_r1cs || $expect_r1cs =~ ^[0-9a-f]{64}$ ]] || die "--expect-r1cs-sha256 is 64 lowercase hex characters"
[[ -z $stop_after || $stop_after =~ ^(init|contribute|seal)$ ]] || die "--stop-after is init, contribute or seal"
[[ -f $ptau && -f $r1cs ]] || die "--ptau and --r1cs must be files"
ptau="$(cd "$(dirname "$ptau")" && pwd -P)/$(basename "$ptau")"
r1cs="$(cd "$(dirname "$r1cs")" && pwd -P)/$(basename "$r1cs")"
procs=${GOMAXPROCS:-4}
readonly MIN_AVAILABLE_BYTES=$((min_gib * 1024 * 1024 * 1024))
readonly RSS_TRIP_BYTES=$((rss_gib * 1024 * 1024 * 1024))
readonly SWAP_GROWTH_TRIP_BYTES=$((4 * 1024 * 1024 * 1024))
readonly MIN_DISK_KIB=$((disk_gib * 1024 * 1024))

here=$RUN_PHASED_HERE
repo="$(git -C "$here" rev-parse --show-toplevel)"

# The shell source a run executes: this harness as it runs (the private
# copy), every scripts/*.sh on disk, and the wrapper that invoked it, if
# any. A wrapper (run-5-1c.sh) sets RUN_PHASED_WRAPPER to its own path; it
# must be one of this tool's scripts. Printed as one JSON object; start
# records it in run.json and --resume-seal requires it unchanged.
wrapper=${RUN_PHASED_WRAPPER:-}
if [[ -n $wrapper ]]; then
	wrapper="$(cd "$(dirname "$wrapper")" && pwd -P)/$(basename "$wrapper")"
	[[ $(dirname "$wrapper") == "$here/scripts" && -f $wrapper ]] || die "RUN_PHASED_WRAPPER $wrapper is not one of $here/scripts"
fi
source_digests() {
	/usr/bin/python3 - "$RUN_PHASED_SELF" "$here/scripts" "$wrapper" <<'PY'
import hashlib, json, os, sys
running, scripts, wrapper = sys.argv[1:4]
def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()
print(json.dumps({
    "runningHarnessSha256": sha(running),
    "scripts": {f"scripts/{n}": sha(os.path.join(scripts, n)) for n in sorted(os.listdir(scripts)) if n.endswith(".sh")},
    "invokedVia": f"scripts/{os.path.basename(wrapper)}" if wrapper else "",
}, sort_keys=True))
PY
}

# ---- output root ----
if $resume; then
	[[ -d $out_arg && -f $out_arg/results/run.json && -f $out_arg/ceremony/transcript.json && -f $out_arg/work/work.json ]] ||
		die "--resume-seal needs an OUT-ROOT left by --stop-after contribute"
	out="$(cd "$out_arg" && pwd -P)"
else
	created=false
	if [[ -e $out_arg || -L $out_arg ]]; then
		[[ -d $out_arg && ! -L $out_arg ]] || die "$out_arg is not a directory"
		[[ -z "$(ls -A "$out_arg")" ]] || die "$out_arg is not empty; a ceremony is never overwritten"
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
fi
ceremony="$out/ceremony"
[[ -z $verify_only ]] || ceremony=$verify_only
work="$out/work"
results="$out/results"
if ! $resume; then
	mkdir "$results" "$out/bin"
	/bin/cp "$RUN_PHASED_SELF" "$results/run-phased.sh"
	printf '%s\n' "$NOTICE" "Provenance: simulated-single-party. Label: $label. Ceremony id: $ceremony_id." >"$out/SIMULATED-SINGLE-PARTY-ZERO-VALUE.txt"

fi

# ---- source state: build only from the committed tree; seal only with the start's ----
dirty="$(git -C "$repo" status --porcelain -- tools/apnt-pool-ceremony)"
[[ -z $dirty ]] || die "uncommitted changes in tools/apnt-pool-ceremony:
$dirty"
head_commit="$(git -C "$repo" rev-parse HEAD)"
source_now="$(source_digests)" || die "could not digest the shell source"
if $resume; then
	RESUME_HEAD=$head_commit RESUME_SOURCE=$source_now /usr/bin/python3 - "$results/run.json" <<'PY' || die "the checkout or shell source differs from the start's; see above"
import json, os, sys
run = json.load(open(sys.argv[1]))
started, now = run.get("source"), json.loads(os.environ["RESUME_SOURCE"])
bad = []
if run.get("headCommit") != os.environ["RESUME_HEAD"]:
    bad.append(f"HEAD is {os.environ['RESUME_HEAD']}, the start ran at {run.get('headCommit')}")
if started is None:
    bad.append("the start recorded no shell source (a run-phased.sh older than ENG-418)")
elif now != started:
    for key in ("runningHarnessSha256", "invokedVia"):
        if now[key] != started[key]:
            bad.append(f"{key}: now {now[key]!r}, at start {started[key]!r}")
    for name in sorted(set(now["scripts"]) | set(started["scripts"])):
        if now["scripts"].get(name) != started["scripts"].get(name):
            bad.append(f"{name}: now {now['scripts'].get(name)}, at start {started['scripts'].get(name)}")
for b in bad:
    print(f"run-phased: resume-seal: {b}", file=sys.stderr)
sys.exit(1 if bad else 0)
PY
elif [[ $(/usr/bin/python3 -c 'import json,sys; print(json.loads(sys.argv[1])["runningHarnessSha256"])' "$source_now") != \
	"$(/usr/bin/shasum -a 256 "$here/scripts/run-phased.sh" | cut -d' ' -f1)" ]]; then
	die "the running harness is not the committed scripts/run-phased.sh"
fi

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

# Resident bytes of the ceremony processes (at most one runs at a time).
phase_rss_bytes() {
	/bin/ps -axo rss=,comm= | /usr/bin/awk '
		{ exe = $0; sub(/^ *[0-9]+ +/, "", exe); sub(/^.*\//, "", exe) }
		exe == "apnt-pool-ceremony" || exe == "apnt-pool-ceremony-verify" { kib += $1 }
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
	[[ -z $others ]] || die "$phase: another prover or ceremony process is running:
$others"
	[[ ! -e $SP1_EXCLUSIVE_MARKER && ! -L $SP1_EXCLUSIVE_MARKER ]] || die "$phase: the SP1 exclusive marker $SP1_EXCLUSIVE_MARKER is present"
	if [[ -e $PROVER_MARKER ]] && ! grep -q "^pid $$\$" "$PROVER_MARKER" 2>/dev/null; then
		die "$phase: $PROVER_MARKER is present and not this run's:
$(cat "$PROVER_MARKER" 2>/dev/null)"
	fi
	avail="$(available_bytes)" || die "$phase: vm_stat unreadable"
	((avail >= MIN_AVAILABLE_BYTES)) || die "$phase: $avail bytes available (free + inactive + speculative), below the floor of $MIN_AVAILABLE_BYTES"
	local disk
	disk="$(/bin/df -k "$out" | /usr/bin/awk 'NR == 2 { print $4 }')" || die "$phase: df unreadable"
	((disk >= MIN_DISK_KIB)) || die "$phase: $disk KiB free on the output file system, below the floor of $MIN_DISK_KIB KiB"
}

# ---- locks ----
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
require_quiet_machine "start"
mkdir -p "$(dirname "$PROVER_MARKER")"
(
	set -o noclobber
	printf 'pid %s\nscript %s\nout %s\nstarted %s\n' "$$" "$0" "$out" "$(/bin/date)" >"$PROVER_MARKER"
) 2>/dev/null || die "could not create $PROVER_MARKER"
marker_owned=true

# ---- build ----
cer="$out/bin/apnt-pool-ceremony"
ver="$out/bin/apnt-pool-ceremony-verify"
r1cs_sha="$(/usr/bin/shasum -a 256 "$r1cs" | cut -d' ' -f1)"
[[ -z $expect_r1cs || $r1cs_sha == "$expect_r1cs" ]] || die "R1CS sha256 $r1cs_sha, expected $expect_r1cs"
if $resume; then
	# The binaries the first invocation built, unchanged since.
	/usr/bin/python3 - "$results/run.json" "$cer" "$ver" "$r1cs_sha" "$pin" <<'PY' || die "the binaries, R1CS or phase-1 pin differ from the first invocation's"
import hashlib, json, os, sys
run = json.load(open(sys.argv[1]))
for path in sys.argv[2:4]:
    if hashlib.sha256(open(path, "rb").read()).hexdigest() != run["binaries"][os.path.basename(path)]:
        sys.exit(1)
if run["r1csSha256"] != sys.argv[4] or run["ptauPin"] != sys.argv[5]:
    sys.exit(1)
PY
	RESUME_BEACON=$beacon RESUME_BEACON_SOURCE=$beacon_source RESUME_PROCS=$procs RESUME_HEAD=$head_commit RESUME_SOURCE=$source_now \
		/usr/bin/python3 - "$results/resume.json" <<'PY'
import json, os, subprocess, sys
e = os.environ
json.dump({"resumedUtc": subprocess.run(["/bin/date", "-u", "+%Y-%m-%dT%H:%M:%SZ"], capture_output=True, text=True).stdout.strip(),
           "headCommit": e["RESUME_HEAD"], "source": json.loads(e["RESUME_SOURCE"]),
           "beacon": e["RESUME_BEACON"], "beaconSource": e["RESUME_BEACON_SOURCE"],
           "env": {"GOMAXPROCS": e["RESUME_PROCS"], "GOMEMLIMIT": e.get("GOMEMLIMIT", ""), "GOGC": e.get("GOGC", ""),
                   "GODEBUG": e.get("GODEBUG", "")}}, open(sys.argv[1], "w"), indent=2)
PY
else
	(cd "$here" && GOPROXY=off GOFLAGS=-mod=readonly GODEBUG= go build -o "$out/bin/" ./cmd/...)
	[[ -x $cer && -x $ver ]] || die "the build produced no binaries"

RUN_NOTICE=$NOTICE RUN_HEAD=$head_commit RUN_SOURCE=$source_now RUN_REPO=$repo RUN_OUT=$out RUN_LABEL=$label RUN_ID=$ceremony_id \
	RUN_CONTRIBUTIONS=$contributions RUN_VERIFY_ONLY=$verify_only RUN_R1CS=$r1cs RUN_R1CS_SHA=$r1cs_sha RUN_PTAU=$ptau RUN_PIN=$pin \
	RUN_BEACON=$beacon RUN_BEACON_SOURCE=$beacon_source RUN_CER=$cer RUN_VER=$ver RUN_PROCS=$procs \
	RUN_MIN=$MIN_AVAILABLE_BYTES RUN_RSS=$RSS_TRIP_BYTES RUN_SWAP=$SWAP_GROWTH_TRIP_BYTES RUN_SAMPLE=$SAMPLE_SECONDS \
	/usr/bin/python3 - "$results/run.json" <<'PY'
import json, os, subprocess, sys
e = os.environ
def sh(*a):
    return subprocess.run(a, capture_output=True, text=True).stdout.strip()
json.dump({
    "provenance": "simulated-single-party",
    "zeroValueOnly": True,
    "notice": e["RUN_NOTICE"],
    "script": "tools/apnt-pool-ceremony/scripts/run-phased.sh",
    "scriptSha256": sh("/usr/bin/shasum", "-a", "256", e["RUN_PHASED_SELF"]).split()[0],
    "startedUtc": sh("/bin/date", "-u", "+%Y-%m-%dT%H:%M:%SZ"),
    "headCommit": e["RUN_HEAD"], "source": json.loads(e["RUN_SOURCE"]), "repo": e["RUN_REPO"], "outRoot": e["RUN_OUT"],
    "label": e["RUN_LABEL"], "ceremonyId": e["RUN_ID"], "contributions": int(e["RUN_CONTRIBUTIONS"]),
    "verifyOnly": e["RUN_VERIFY_ONLY"],
    "r1cs": e["RUN_R1CS"], "r1csSha256": e["RUN_R1CS_SHA"], "ptau": e["RUN_PTAU"], "ptauPin": e["RUN_PIN"],
    "beacon": e["RUN_BEACON"], "beaconSource": e["RUN_BEACON_SOURCE"],
    "binaries": {os.path.basename(e[k]): sh("/usr/bin/shasum", "-a", "256", e[k]).split()[0] for k in ("RUN_CER", "RUN_VER")},
    "goVersion": sh("go", "version"),
    "env": {"GOMAXPROCS": e["RUN_PROCS"], "GOMEMLIMIT": e.get("GOMEMLIMIT", ""), "GOGC": e.get("GOGC", ""),
            "GODEBUG": e.get("GODEBUG", "")},
    "hwMemsizeBytes": int(sh("/usr/sbin/sysctl", "-n", "hw.memsize")),
    "cpu": sh("/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"),
    "ncpu": int(sh("/usr/sbin/sysctl", "-n", "hw.ncpu")),
    "os": sh("/usr/bin/sw_vers", "-productVersion"),
    "thresholds": {"minAvailableBytes": int(e["RUN_MIN"]), "rssTripBytes": int(e["RUN_RSS"]),
                   "swapGrowthTripBytes": int(e["RUN_SWAP"]), "sampleSeconds": int(e["RUN_SAMPLE"])},
}, open(sys.argv[1], "w"), indent=2)
PY

fi

# ---- phases ----
sample() { # samples-file -> prints "swap avail rss"
	local swap avail rss
	swap="$(swap_used_bytes)" || swap=-1
	avail="$(available_bytes)" || avail=-1
	rss="$(phase_rss_bytes)" || rss=-1
	printf '%s\t%s\t%s\t%s\n' "$(/bin/date +%s)" "$swap" "$avail" "$rss" >>"$1"
	echo "$swap $avail $rss"
}

phases=()
run_phase() { # name binary args...
	local phase=$1 bin=$2
	shift 2
	require_quiet_machine "$phase"
	phases+=("$phase")
	local samples="$results/$phase.samples.tsv" swap0 status=0 tripped="" pid swap avail rss n=0
	printf 'epoch_s\tswap_used_bytes\tavailable_bytes\tphase_rss_bytes\n' >"$samples"
	swap0="$(swap_used_bytes)" || die "$phase: vm.swapusage unreadable"
	sample "$samples" >/dev/null
	echo "run-phased: $phase started $(/bin/date)"
	GOMAXPROCS=$procs /usr/bin/caffeinate -i /usr/bin/time -l -o "$results/$phase.time" \
		/usr/bin/nice -n 10 "$bin" "$@" >"$results/$phase.stdout" 2>"$results/$phase.stderr" &
	pid=$!
	while kill -0 "$pid" 2>/dev/null; do
		sleep 1
		n=$((n + 1))
		((n % SAMPLE_SECONDS == 0)) || continue
		read -r swap avail rss <<<"$(sample "$samples")"
		if ((swap >= 0 && swap - swap0 > SWAP_GROWTH_TRIP_BYTES)); then
			tripped="swap grew $((swap - swap0)) bytes over its baseline $swap0"
		elif ((rss > RSS_TRIP_BYTES)); then
			tripped="phase RSS $rss bytes over the trip of $RSS_TRIP_BYTES"
		fi
		if [[ -n $tripped ]]; then
			/usr/bin/pkill -TERM -x "$(basename "$bin")" || true
			break
		fi
	done
	wait "$pid" || status=$?
	sample "$samples" >/dev/null
	local disk_ceremony disk_work
	disk_ceremony="$(/usr/bin/du -sk "$ceremony" 2>/dev/null | cut -f1)" || disk_ceremony=0
	disk_work="$(/usr/bin/du -sk "$work" 2>/dev/null | cut -f1)" || disk_work=0
	/usr/bin/python3 - "$results" "$phase" "$status" "$swap0" "$tripped" "${disk_ceremony:-0}" "${disk_work:-0}" <<'PY'
import json, os, re, sys
results, phase, status, swap0, tripped = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
disk_ceremony, disk_work = int(sys.argv[6]) * 1024, int(sys.argv[7]) * 1024
rows = [l.rstrip("\n").split("\t") for l in open(f"{results}/{phase}.samples.tsv")][1:]
swaps = [int(r[1]) for r in rows if int(r[1]) >= 0]
avails = [int(r[2]) for r in rows if int(r[2]) >= 0]
rss = [int(r[3]) for r in rows if int(r[3]) >= 0]
s = {"phase": phase, "exitStatus": status, "tripped": tripped or None, "samples": len(rows),
     "swapBaselineBytes": swap0, "swapMaxBytes": max(swaps), "swapGrowthMaxBytes": max(swaps) - swap0,
     "availableMinBytes": min(avails), "sampledRSSMaxBytes": max(rss),
     "diskCeremonyBytes": disk_ceremony, "diskWorkBytes": disk_work}
t = open(f"{results}/{phase}.time").read() if os.path.exists(f"{results}/{phase}.time") else ""
for key, pat, conv in (("timeRealSeconds", r"([\d.]+) real", float),
                       ("timeMaxRSSBytes", r"(\d+)\s+maximum resident set size", int),
                       ("timePeakMemoryFootprintBytes", r"(\d+)\s+peak memory footprint", int)):
    m = re.search(pat, t)
    s[key] = conv(m.group(1)) if m else None
# GODEBUG=gctrace=1 lines: "gc N @Ts P%: ... A->B->C MB, D MB goal, ..."
heap = [tuple(int(x) for x in m.groups()) for m in
        re.finditer(r"(\d+)->(\d+)->(\d+) MB, \d+ MB goal", open(f"{results}/{phase}.stderr").read())]
if heap:
    s["gcTraceHeapMaxMB"] = max(max(a, b) for a, b, _ in heap)
    s["gcTraceLiveMaxMB"] = max(c for _, _, c in heap)
    s["gcTraceCycles"] = len(heap)
try:
    j = json.load(open(f"{results}/{phase}.stdout"))
    s["stageSeconds"] = j.get("seconds")
    if "verdict" in j:
        s["verdict"] = j["verdict"]
except Exception as e:
    s["stdoutJSON"] = f"unreadable: {e}"
json.dump(s, open(f"{results}/{phase}.summary.json", "w"), indent=2)
PY
	echo "run-phased: $phase ended $(/bin/date) with status $status"
	[[ -z $tripped ]] || die "$phase killed: $tripped"
	((status == 0)) || die "$phase exited with status $status; see $results/$phase.stderr"
}

finish() {
	/usr/bin/python3 - "$results" "${phases[@]}" <<'PY'
import json, sys
r = sys.argv[1]
json.dump({"run": json.load(open(f"{r}/run.json")),
           "phases": [json.load(open(f"{r}/{p}.summary.json")) for p in sys.argv[2:]]},
          open(f"{r}/summary.json", "w"), indent=2)
PY
}

if $resume; then
	# The phases the first invocation ran, in order, for summary.json.
	phases=(init)
	for ((i = 1; i <= contributions; i++)); do
		f="$(printf 'contribute-%02d' "$i")"
		[[ -f $results/$f.summary.json ]] || die "the first invocation left no $f summary; the transcript must hold $contributions contributions"
		phases+=("$f")
	done
	run_phase seal "$cer" rerun --phase seal --ptau "$ptau" --ptau-pin "$pin" --out "$ceremony" --work "$work" \
		--contributions "$contributions" --beacon "$beacon" --beacon-source "$beacon_source"
elif [[ -z $verify_only ]]; then
	run_phase init "$cer" rerun --phase init --ptau "$ptau" --ptau-pin "$pin" --ptau-source "$ptau_source" \
		--r1cs "$r1cs" --label "$label" --out "$ceremony" --work "$work" --ceremony-id "$ceremony_id"
	[[ $stop_after != init ]] || { finish; echo "run-phased: stopped after init; results in $out"; exit 0; }
	for ((i = 1; i <= contributions; i++)); do
		run_phase "$(printf 'contribute-%02d' "$i")" "$cer" rerun --phase contribute --out "$ceremony" --work "$work"
	done
	[[ $stop_after != contribute ]] || { finish; echo "run-phased: stopped after the contributions; results in $out"; exit 0; }
	run_phase seal "$cer" rerun --phase seal --ptau "$ptau" --ptau-pin "$pin" --out "$ceremony" --work "$work" \
		--contributions "$contributions" --beacon "$beacon" --beacon-source "$beacon_source"
	[[ $stop_after != seal ]] || { finish; echo "run-phased: stopped after seal; results in $out"; exit 0; }
fi

# The standalone verifier with both anchors, and the circuit anchor when the
# operator gave one: the check above is this harness's, and the verifier
# makes its own and records it (anchors.r1cs, ENG-460). Exit 0 and verdict
# VALID only; exit 3 (CONSISTENT-UNANCHORED) or anything else fails the run.
verify_args=(--transcript "$ceremony/transcript.json" --ptau "$ptau" --r1cs "$r1cs"
	--expect-phase1-pin "$pin" --expect-beacon "$beacon")
[[ -z $expect_r1cs ]] || verify_args+=(--expect-r1cs-sha256 "$expect_r1cs")
run_phase verify "$ver" "${verify_args[@]}" --json
finish
verdict="$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("verdict", ""))' "$results/verify.stdout" 2>/dev/null || true)"
[[ $verdict == VALID ]] || die "the standalone verifier did not report VALID (verdict '$verdict'); see $results/verify.stdout"
rm -rf "$work"
echo "run-phased: VALID; $NOTICE"
echo "run-phased: results in $out"
