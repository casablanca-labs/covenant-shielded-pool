#!/usr/bin/env bash
# ENG-424: proving-key load cases and a wallet prove, one process per case,
# serially, under nice and caffeinate -i, holding the machine-wide prover lock
# and writing the prover marker for the whole run. RESEARCH PROTOTYPE — NOT
# REVIEWED. The keys are zero-value test keys.
#
# usage: scripts/measure-pk-load.sh OUT-DIR PLAN [GOMAXPROCS]
#
# PLAN has one case per line (blank lines and # comments ignored):
#   NAME  FLOOR-GIB  CACHE  EXPECT  COMMAND ARGS...
# CACHE is cold (evict every file named by --key, --r1cs and --vk from the
# page cache first, recorded as NAME.evict-N.json), warm (read each of them once
# first, recorded as NAME.warm-N.json) or asis. EXPECT is ok; fail (the case
# must exit 1, for any reason); or refuse-STAGE for a negative control: the
# case must exit 1 with that pkload stage (pin, open, size, read, digest,
# decode) in its result. Otherwise the run stops. COMMAND ARGS are
# pool-pk-load's; check-live exercises the live gates without key work.
# The script appends OUT-DIR/results/NAME.json. Arguments
# cannot contain white space.
#
# OUT-DIR must be new or empty and outside any git repository. It receives
# bin/ (the pool-pk-load binary built for this run) and results/: per case
# NAME.json, NAME.time (/usr/bin/time -l), NAME.samples.tsv (1 s),
# NAME.stderr, NAME.summary.json; run.json and summary.json.
#
# Before each resource case it refuses unless FLOOR-GIB is available (free +
# inactive + speculative). Child action proves require at least 17 GiB.
# Streamed hashing, residency, eviction and check-live have no proving memory
# floor or memory-admission wait: they neither decode/load a proving key nor
# prove. Inventory, locks and monitoring remain required for every case.
# This harness has no aggregate entry; aggregate runners retain their 20 GiB floor.
# A case is killed if swap grows more than 8 GiB over its baseline or its RSS
# passes 24 GiB. GOMAXPROCS defaults to 4.
set -euo pipefail

readonly PRIVATE_RUNNER_GENERATION=2 # Fixed production generation; no environment/argv selector.
# E1's cwd is the checkout anchor. Caller SELF/HERE/Git/preload variables
# cannot select code or bypass admission. A pre-inherited FD8 is refused.
for runner_environment_name in ${!GIT_@} ${!DYLD_@} ${!LD_@}; do unset "$runner_environment_name"; done
unset NODE_OPTIONS NODE_PATH
repo="$(/usr/bin/git rev-parse --show-toplevel 2>/dev/null)" || exit 1
[[ $(pwd -P) == "$repo" ]] || exit 1
installation="$repo/tools/pool-action-modules/private-runner-installation.py"
/usr/bin/git -C "$repo" show HEAD:tools/pool-action-modules/private-runner-installation.py 2>/dev/null | /usr/bin/cmp -s - "$installation" || exit 1
if /usr/bin/python3 "$installation" --continuation "$0" "$@" 2>/dev/null; then
 MEASURE_PK_LOAD_SELF=$0
 MEASURE_PK_LOAD_HERE="$repo/tools/apnt-pool-action-circuit"
else
 if { true <&8; } 2>/dev/null; then exec 8<&-; exit 1; fi
 { exec 9>&-; } 2>/dev/null || true
 [[ $# == 3 && $3 == 4 ]] || exit 1
 [[ -d $repo/.git && ! -L $repo/.git ]] || exit 1
 [[ $(/usr/bin/git -C "$repo" branch --show-current 2>/dev/null) == main ]] || exit 1
 [[ -z $(/usr/bin/git -C "$repo" status --porcelain 2>/dev/null) ]] || exit 1
 /usr/bin/git -C "$repo" show HEAD:tools/apnt-pool-action-circuit/scripts/measure-pk-load.sh 2>/dev/null | /usr/bin/cmp -s - "$0" || exit 1
 self_copy="$(/usr/bin/mktemp /private/tmp/measure-pk-load.XXXXXXXX)" || exit 1
 /bin/cp "$0" "$self_copy" || exit 1
 # Installation verification precedes the fixed Node entry; no original PLAN
 # is opened here. Only the checked trampoline can create a continuation.
 /usr/bin/python3 "$installation" --bootstrap "$self_copy" 2>/dev/null || { /bin/rm -f "$self_copy"; exit 1; }
 trusted_node="$(/usr/bin/python3 "$installation" --node-path "$repo" 2>/dev/null)" || { /bin/rm -f "$self_copy"; exit 1; }
 exec "$trusted_node" "$repo/tools/pool-action-modules/private-runner-bootstrap.mjs" "$self_copy" "$@"
fi
plan_lines=()
while IFS= read -r runner_snapshot_line <&8; do plan_lines+=("$runner_snapshot_line"); done
exec 8<&-

readonly SAMPLE_SECONDS=1
# Shared with scripts/measure-5-1b.sh, tools/apnt-pool-ceremony/scripts/run-phased.sh
# and the SP1 runners.
readonly SHARED_PROVER_LOCK="/private/tmp/apnt-gnark-r2-proof-$UID.lock"
readonly SP1_EXCLUSIVE_MARKER="/private/tmp/bch-cloak-sp1-prover-exclusive-v1"
readonly PROVER_MARKER="$HOME/proof-scratch/.prover.lock"
readonly SWAP_GROWTH_TRIP_BYTES=$((8 * 1024 * 1024 * 1024))
readonly RSS_TRIP_BYTES=$((24 * 1024 * 1024 * 1024))

out=""
marker_owned=false
has_live=false
die() {
	if $has_live; then
  case "$*" in
   live-plan-memory-floor|live-plan-memory-unavailable|live-plan-main-checkout|live-plan-other-prover|live-plan-sp1-marker|live-plan-prover-marker|live-plan-prover-inventory-ps|live-plan-prover-inventory-awk|live-plan-prover-inventory-pipeline|live-plan-prover-inventory-sigpipe) echo "measure-pk-load: $*" >&2 ;;
   *) ;;
  esac
 else
  echo "measure-pk-load: refusing: $*" >&2
  [[ -z $out ]] || echo "measure-pk-load: outputs so far: $out" >&2
 fi
	exit 1
}
cleanup() {
	local cleanup_status=0
	rm -f "$MEASURE_PK_LOAD_SELF" || cleanup_status=1
	if $marker_owned && [[ -f $PROVER_MARKER ]] && grep -q "^pid $$\$" "$PROVER_MARKER" 2>/dev/null; then
		rm -f "$PROVER_MARKER" || cleanup_status=1
	fi
	return "$cleanup_status"
}
trap cleanup EXIT

if [[ $# -lt 2 || $# -gt 3 ]]; then
	echo "usage: $0 OUT-DIR PLAN [GOMAXPROCS]" >&2
	exit 2
fi
out_arg=$1
plan=$2
procs=${3:-4}
if /usr/bin/grep -Eq '(^|[[:space:]])--?request([=[:space:]]|$)' < <(printf '%s\n' "${plan_lines[@]}"); then has_live=true; fi
plan_source() {
 printf '%s\n' "${plan_lines[@]}"
}
# ---- private diagnostic boundary ----
# Catch shell, Python, build and cleanup failures, including failures before
# any result exists. Only a closed exit diagnostic retains terminal access.
# Match the entire byte stream, including its newline: a safe code with any
# extra text is unclassified. Drain unknown streams with bounded memory; only
# the mapped code reaches the disposable file, never the original stderr.
# Empty stderr identifies only missing diagnostic output, not a guard or cause.
# bridge-refused is emitted only by the separate scratch diagnostic entry.
private_runner_diagnostics() {
 /usr/bin/python3 -I -c '
import sys
codes = {
 b"": "no-diagnostic",
 b"live-request-result-write\n": "live-request-result-write",
 b"live-request-main-checkout-required\n": "live-request-main-checkout-required",
 b"live-request-harness-required\n": "live-request-harness-required",
 b"live-request-prover-lock-required\n": "live-request-prover-lock-required",
 b"live-request-bridge-refused\n": "live-request-bridge-refused",
 b"live-request-process-list-unavailable\n": "live-request-process-list-unavailable",
 b"live-request-other-prover\n": "live-request-other-prover",
 b"live-request-memory-unavailable\n": "live-request-memory-unavailable",
 b"live-request-monitor-unavailable\n": "live-request-monitor-unavailable",
 b"live-request-memory-floor\n": "live-request-memory-floor",
 b"live-request-swap-trip\n": "live-request-swap-trip",
 b"live-request-rss-trip\n": "live-request-rss-trip",
 b"measure-pk-load: live-plan-memory-floor\n": "live-plan-memory-floor",
 b"measure-pk-load: live-plan-memory-unavailable\n": "live-plan-memory-unavailable",
 b"measure-pk-load: live-plan-other-prover\n": "live-plan-other-prover",
 b"measure-pk-load: live-plan-sp1-marker\n": "live-plan-sp1-marker",
 b"measure-pk-load: live-plan-prover-marker\n": "live-plan-prover-marker",
 b"measure-pk-load: live-plan-main-checkout\n": "live-plan-main-checkout",
 b"measure-pk-load: live-plan-prover-inventory-ps\n": "live-plan-prover-inventory-ps",
 b"measure-pk-load: live-plan-prover-inventory-awk\n": "live-plan-prover-inventory-awk",
 b"measure-pk-load: live-plan-prover-inventory-pipeline\n": "live-plan-prover-inventory-pipeline",
 b"measure-pk-load: live-plan-prover-inventory-sigpipe\n": "live-plan-prover-inventory-sigpipe",
}
limit = max(map(len, codes))
raw = sys.stdin.buffer.read(limit + 1)
while sys.stdin.buffer.read(8192):
 pass
print(codes.get(raw, "unclassified"))
'
}
private_runner_diagnostic_file=""
private_runner_diagnostic_pid=""
private_runner_diagnostic_connected=false
private_runner_finish() {
 local status=$? reason=unclassified
 cleanup || status=1
 # Release the pipe and reap its reader even after a failed writer/cleanup.
 exec 2>/dev/null
 if [[ -n $private_runner_diagnostic_pid ]]; then
  if ! $private_runner_diagnostic_connected; then /bin/kill -TERM "$private_runner_diagnostic_pid" || true; fi
  wait "$private_runner_diagnostic_pid" || status=1
  IFS= read -r reason <"$private_runner_diagnostic_file" || status=1
 fi
 if [[ -n $private_runner_diagnostic_file ]]; then
  /bin/rm -f "$private_runner_diagnostic_file" || status=1
  /bin/rm -f "$private_runner_diagnostic_file.stream" || status=1
  /bin/rmdir "${private_runner_diagnostic_file%/*}" || status=1
 fi
 case "$reason" in
  no-diagnostic|live-request-result-write|live-request-main-checkout-required|live-request-harness-required|live-request-prover-lock-required|live-request-bridge-refused|live-request-process-list-unavailable|live-request-other-prover|live-request-memory-unavailable|live-request-monitor-unavailable|live-request-memory-floor|live-request-swap-trip|live-request-rss-trip|live-plan-memory-floor|live-plan-memory-unavailable|live-plan-other-prover|live-plan-sp1-marker|live-plan-prover-marker|live-plan-main-checkout|live-plan-prover-inventory-ps|live-plan-prover-inventory-awk|live-plan-prover-inventory-pipeline|live-plan-prover-inventory-sigpipe) ;;
  *) reason=unclassified ;;
 esac
 if ((status != 0)); then
  printf 'measure-pk-load: live-plan-refused reason=%s\n' "$reason" >&7
  exit 1
 fi
}
if [[ $PRIVATE_RUNNER_GENERATION == 2 ]] && $has_live; then
 exec 7>&2
 exec >/dev/null 2>&1
 trap private_runner_finish EXIT
 private_runner_diagnostic_file="$(/usr/bin/mktemp -d /private/tmp/measure-pk-load-reason.XXXXXXXX)" || exit 1
 private_runner_diagnostic_file="$private_runner_diagnostic_file/reason"
 /usr/bin/mkfifo -m 600 "$private_runner_diagnostic_file.stream" || exit 1
 # A background job is waitable on the host's Bash 3.2; an anonymous process
 # substitution is not. The private FIFO never stores the original stream.
 private_runner_diagnostics <"$private_runner_diagnostic_file.stream" >"$private_runner_diagnostic_file" 7>&- &
 private_runner_diagnostic_pid=$!
 exec 2>"$private_runner_diagnostic_file.stream"
 private_runner_diagnostic_connected=true
fi
# ---- end private diagnostic boundary ----
[[ $procs =~ ^[1-9][0-9]?$ ]] || die "GOMAXPROCS must be 1-99, got $procs"

here=$MEASURE_PK_LOAD_HERE

# ---- the plan, checked before anything runs ----
requires_proving_admission() {
	case "$1" in load|derive|roundtrip|prove) return 0 ;; *) return 1 ;; esac
}
names=()
has_prove=false
has_resource_work=false
while read -r line; do
	[[ -z ${line// /} || $line == \#* ]] && continue
	read -r name floor cache expect cmd _ <<<"$line"
 if $has_live; then
  [[ $cmd == prove || $cmd == check-live ]] || die "mixed live and measurement plan"
  [[ $line =~ (^|[[:space:]])--?request([=[:space:]]|$) ]] || die "live plan requires live cases"
  read -r -a words <<<"$line"
  request_arg=""
  for ((j=0; j<${#words[@]}; j++)); do
   case "${words[$j]}" in
    --request|-request) request_arg=${words[$((j+1))]:-} ;;
    --request=*|-request=*) request_arg=${words[$j]#*=} ;;
   esac
   [[ -z $request_arg || $name != "${request_arg##*/}" ]] || die "request aliases case name"
  done
 fi
	[[ $name =~ ^[a-z0-9][a-z0-9.-]*$ ]] || die "plan: bad case name '$name'"
	[[ $floor =~ ^[1-9][0-9]?$ ]] || die "plan: $name: floor '$floor' is not whole GiB"
	[[ $cache == cold || $cache == warm || $cache == asis ]] || die "plan: $name: cache '$cache'"
	[[ $expect =~ ^(ok|fail|refuse-(pin|open|size|read|digest|decode))$ ]] || die "plan: $name: expect '$expect'"
	[[ $cmd =~ ^(sha256|residency|evict|load|derive|roundtrip|prove|check-live)$ ]] || die "plan: $name: command '$cmd'"
	[[ $cmd != check-live || $cache == asis ]] || die "check-live requires cache asis"
	# Derive admission from the captured operation, never an env/CLI override.
	if requires_proving_admission "$cmd"; then has_resource_work=true; fi
	if [[ $cmd == prove || $cmd == check-live ]]; then
		has_prove=true
	fi
	if [[ $cmd == prove ]]; then
		((floor >= 17)) || die "live-plan-memory-floor"
	fi
	for n in "${names[@]+"${names[@]}"}"; do [[ $n != "$name" ]] || die "plan: $name twice"; done
	names+=("$name")
done < <(plan_source)
if [[ $PRIVATE_RUNNER_GENERATION == 2 ]] && $has_live; then ((${#names[@]} == 1)) || die "live plan case count"; fi
((${#names[@]} > 0)) || die "the plan has no cases"

# Proving (including live requests) stays in the clean main checkout. These
# checks precede output creation, key cache reads, the build and all phases.
if $has_prove; then
	[[ -d $repo/.git && ! -L $repo/.git ]] || die "live-plan-main-checkout"
	[[ $(git -C "$repo" branch --show-current) == main ]] || die "live-plan-main-checkout"
	[[ -z $(git -C "$repo" status --porcelain) ]] || die "live-plan-main-checkout"
fi

# ---- output directory ----
created=false
if [[ -e $out_arg || -L $out_arg ]]; then
	[[ -d $out_arg && ! -L $out_arg ]] || die "$out_arg is not a directory"
	[[ -z "$(ls -A "$out_arg")" ]] || die "$out_arg is not empty; a measurement is never overwritten"
else
	mkdir -p "$out_arg" 2>/dev/null || die "cannot create output directory"
	created=true
fi
resolved="$(cd "$out_arg" && pwd -P)"
if git -C "$resolved" rev-parse --git-dir >/dev/null 2>&1; then
	$created && rmdir "$resolved"
	die "$resolved is inside a git repository; outputs live outside the repository"
fi
out=$resolved
results="$out/results"
mkdir "$results" "$out/bin"
# Plans are private inputs: even aliases in unrelated flags/comments can name
# the live request. Never copy any plan text into the result directory.
printf '%s\n' 'Plan arguments withheld (private input).' >"$results/plan.txt"

dirty="$(git -C "$repo" status --porcelain -- tools/apnt-pool-action-circuit)"
[[ -z $dirty ]] || die "uncommitted changes in the tool:
$dirty"
head_commit="$(git -C "$repo" rev-parse HEAD)"

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

runner_process_scan() {
 # The checked installation owns this non-setuid reader. Every inventory
 # stays fresh inside the continuation, under fd9; no cached quiet result.
 "$repo/tools/pool-action-modules/dist/private-runner-process" "$@"
}

phase_rss_bytes() {
	runner_process_scan -axo rss=,comm= | /usr/bin/awk '
		{ exe = $0; sub(/^ *[0-9]+ +/, "", exe); sub(/^.*\//, "", exe) }
		exe == "pool-pk-load" { found = 1; kib += $1 }
		END { if (found) printf "%.0f\n", kib * 1024; else print "not measured" }'
}

other_provers() {
	local -a inventory_status
	# Capture both members before errexit can abort the command substitution.
	# A failed inventory is never an empty inventory, even with partial output.
	if runner_process_scan -axo pid=,comm= | /usr/bin/awk -v self="$$" '
		{ exe = $0; sub(/^ *[0-9]+ +/, "", exe); sub(/^.*\//, "", exe) }
		$1 == self { next }
		exe == "pool-pk-load" || exe == "pool-action-circuit" || exe == "apnt-pool-action-circuit.test" { print; next }
		exe ~ /^apnt-pool-ceremony/ { print; next }
		exe ~ /^(cargo-prove|sp1-prover|sp1_core)(-|$)/ { print; next }
		exe ~ /^apnt-.*-(runner|prover)(-[[:alnum:]_.-]+)?$/ { print; next }
		exe ~ /(^|[-_])(prove|prover)([-_]|$)/ { print; next }
		exe ~ /^(r2-run|r3-run|relation-r2-run|apnt-successor-child-circuits(\.test)?|apnt-child-circuits-cost(\.test)?)$/ { print; next }'; then
		return 0
	else
		inventory_status=("${PIPESTATUS[@]}")
		# Fixed internal statuses; never forward process names or raw errors.
		((inventory_status[0] != 141)) || return 73
		if ((inventory_status[0] != 0)); then
			((inventory_status[1] == 0)) || return 72
			return 70
		fi
		return 71
	fi
}

require_runner_exclusivity() {
	local phase=$1 others inventory_status=0
	others="$(other_provers 2>/dev/null)" || inventory_status=$?
	case $inventory_status in
		0) ;;
		70) die live-plan-prover-inventory-ps ;;
		71) die live-plan-prover-inventory-awk ;;
		72) die live-plan-prover-inventory-pipeline ;;
		73) die live-plan-prover-inventory-sigpipe ;;
		*) die live-plan-prover-inventory-pipeline ;;
	esac
	[[ -z $others ]] || { $has_live && die live-plan-other-prover; die "$phase: another prover is running:
$others"; }
	[[ ! -e $SP1_EXCLUSIVE_MARKER && ! -L $SP1_EXCLUSIVE_MARKER ]] || { $has_live && die live-plan-sp1-marker; die "$phase: the SP1 exclusive marker $SP1_EXCLUSIVE_MARKER is present"; }
	if [[ -e $PROVER_MARKER ]] && ! grep -q "^pid $$\$" "$PROVER_MARKER" 2>/dev/null; then
		$has_live && die live-plan-prover-marker
		die "$phase: $PROVER_MARKER is present and not this run's:
$(cat "$PROVER_MARKER" 2>/dev/null)"
	fi
}

require_quiet_machine() {
	local phase=$1 floor_bytes=$2 avail
	require_runner_exclusivity "$phase"
	avail="$(available_bytes)" || { $has_live && die live-plan-memory-unavailable; die "$phase: vm_stat unreadable"; }
	((avail >= floor_bytes)) || { $has_live && die live-plan-memory-floor; die "$phase: $avail bytes available (free + inactive + speculative), below the floor of $floor_bytes"; }
}

# ---- locks: fd 9 flock, then the marker, as run-phased.sh ----
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
if $has_resource_work; then
	require_quiet_machine "start" $((12 * 1024 * 1024 * 1024))
else
	require_runner_exclusivity "start"
fi
mkdir -p "$(dirname "$PROVER_MARKER")"
(
	set -o noclobber
 if [[ $PRIVATE_RUNNER_GENERATION == 2 ]] && $has_live; then
  printf 'pid %s\n' "$$" >"$PROVER_MARKER"
 else
  printf 'pid %s\nscript %s\nout %s\nstarted %s\n' "$$" "$0" "$out" "$(/bin/date)" >"$PROVER_MARKER"
 fi
) 2>/dev/null || die "could not create $PROVER_MARKER"
marker_owned=true

# ---- build (fresh, into this run's bin/) ----
(cd "$here" && GOPROXY=off GOENV=off GOFLAGS= /opt/homebrew/bin/go build -mod=readonly -tags= -o "$out/bin/" ./cmd/pool-pk-load)
bin="$out/bin/pool-pk-load"
[[ -x $bin ]] || die "the build produced no binary"

/usr/bin/python3 - "$results/run.json" "$repo" "$out" "$has_live" "$bin" <<PY
import json, subprocess, sys
def sh(*a):
    return subprocess.run(a, capture_output=True, text=True).stdout.strip()
json.dump({
    "notice": "research prototype — not reviewed (ENG-424); the keys are zero-value test keys",
    "script": "tools/apnt-pool-action-circuit/scripts/measure-pk-load.sh",
    "startedUtc": sh("/bin/date", "-u", "+%Y-%m-%dT%H:%M:%SZ"),
    "gomaxprocs": $procs,
    "repo": None if sys.argv[4] == "true" else sys.argv[2],
    "headCommit": "$head_commit",
    "outDir": None if sys.argv[4] == "true" else sys.argv[3],
    "binarySha256": sh("/usr/bin/shasum", "-a", "256", sys.argv[5]).split()[0],
    "goVersion": sh("go", "version"),
    "hwMemsizeBytes": int(sh("/usr/sbin/sysctl", "-n", "hw.memsize")),
    "cpu": sh("/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"),
    "ncpu": int(sh("/usr/sbin/sysctl", "-n", "hw.ncpu")),
    "os": sh("/usr/bin/sw_vers", "-productVersion"),
    "thresholds": {"swapGrowthTripBytes": $SWAP_GROWTH_TRIP_BYTES, "rssTripBytes": $RSS_TRIP_BYTES, "sampleSeconds": $SAMPLE_SECONDS},
}, open(sys.argv[1], "w"), indent=2)
PY

# ---- cases ----
sample() {
	local swap avail rss
	swap="$(swap_used_bytes)" || swap=-1
	avail="$(available_bytes)" || avail=-1
	rss="$(phase_rss_bytes)" || rss=-1
	printf '%s\t%s\t%s\t%s\n' "$(/bin/date +%s)" "$swap" "$avail" "$rss" >>"$1"
	echo "$swap $avail $rss"
}

inputs_of() { # args... -> the values after --key, --r1cs and --vk, one per line
	while [[ $# -gt 0 ]]; do
		if [[ $1 == --key || $1 == --r1cs || $1 == --vk ]]; then
			echo "$2"
			shift
		fi
		shift
	done
}

run_case() {
	local name=$1 floor=$2 cache=$3 expect=$4
	shift 4
	if [[ $1 == prove || $1 == check-live ]]; then
		if [[ $1 == prove ]]; then
			((floor >= 17)) || die "$name: proving requires at least 17 GiB"
		fi
		[[ -d $repo/.git && ! -L $repo/.git && $(git -C "$repo" branch --show-current) == main && -z $(git -C "$repo" status --porcelain) ]] ||
			{ $has_live && die live-plan-main-checkout; die "$name: proving requires the clean main checkout on main"; }
	fi
	if requires_proving_admission "$1"; then
		require_quiet_machine "$name" $((floor * 1024 * 1024 * 1024))
	else
		require_runner_exclusivity "$name"
	fi
	# Admit private input before even a warm-cache read of the multi-GB keys.
	# The prove process admits its own snapshot again and retains that witness.
	local arg live=false
	for arg in "$@"; do [[ $arg == --request || $arg == --request=* || $arg == -request || $arg == -request=* ]] && live=true; done
	if [[ $1 == prove || $1 == check-live ]] && $live; then
  POOL_PK_LOAD_HARNESS_PID=$$ "$bin" admit-request "${@:2}" "$results/$name.admission.json" || die "$name: live request admission failed"
	fi
	local inputs=() f i=0
	while read -r f; do inputs+=("$f"); done < <(inputs_of "$@")
	if ! $live && [[ $cache != asis ]]; then
		((${#inputs[@]} > 0)) || die "$name: $cache needs --key, --r1cs or --vk"
		for f in "${inputs[@]}"; do
			i=$((i + 1))
			if [[ $cache == cold ]]; then
				"$bin" evict --key "$f" "$results/$name.evict-$i.json" || die "$name: evict $f failed"
			else
				GOMAXPROCS=$procs "$bin" sha256 --key "$f" "$results/$name.warm-$i.json" || die "$name: warm-up read of $f failed"
			fi
		done
	fi
	# Live cache work belongs to the admitted child snapshot, under its own
 # memory gate and monitor. Shell pre-admission is not a snapshot handoff.
 if $live && [[ $1 == prove ]]; then set -- "$@" --live-cache "$cache"; fi
 local samples="$results/$name.samples.tsv" swap0 status=0 tripped="" pid swap avail rss
	printf 'epoch_s\tswap_used_bytes\tavailable_bytes\tphase_rss_bytes\n' >"$samples"
	swap0="$(swap_used_bytes)" || die "$name: vm.swapusage unreadable"
	sample "$samples" >/dev/null
	echo "measure-pk-load: $name ($cache) started $(/bin/date)"
 # ---- native diagnostic routing ----
 if [[ $PRIVATE_RUNNER_GENERATION == 2 ]] && $live; then
  POOL_PK_LOAD_HARNESS_PID=$$ GOMAXPROCS=$procs /usr/bin/caffeinate -i /usr/bin/time -l -o "$results/$name.time" \
   /usr/bin/nice -n 10 "$bin" "$@" "$results/$name.json" &
 else
  POOL_PK_LOAD_HARNESS_PID=$$ GOMAXPROCS=$procs /usr/bin/caffeinate -i /usr/bin/time -l -o "$results/$name.time" \
   /usr/bin/nice -n 10 "$bin" "$@" "$results/$name.json" 2>"$results/$name.stderr" &
 fi
 # ---- end native diagnostic routing ----
	pid=$!
	while kill -0 "$pid" 2>/dev/null; do
		sleep "$SAMPLE_SECONDS"
		read -r swap avail rss <<<"$(sample "$samples")"
		if [[ $rss == 'not measured' ]] || ((swap < 0 || rss < 0 || avail < 0)); then
   tripped="resource monitor unavailable"
  elif ((swap - swap0 > SWAP_GROWTH_TRIP_BYTES)); then
			tripped="swap grew $((swap - swap0)) bytes over its baseline $swap0"
		elif ((rss > RSS_TRIP_BYTES)); then
			tripped="case RSS $rss bytes"
		fi
		if [[ -n $tripped ]]; then
			/usr/bin/pkill -TERM -x pool-pk-load || true
			break
		fi
	done
	wait "$pid" || status=$?
	sample "$samples" >/dev/null
	local result_status=0
	/usr/bin/python3 - "$results" "$name" "$cache" "$status" "$swap0" "$tripped" "$expect" "$live" "$repo" "$PRIVATE_RUNNER_GENERATION" <<'PY' || result_status=$?
import json, os, re, sys, importlib.util
results, name, cache, status, swap0, tripped, expect = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), sys.argv[6], sys.argv[7]
live, repo = sys.argv[8] == "true", sys.argv[9]
if live and sys.argv[10] == "2":
    spec = importlib.util.spec_from_file_location("private_runner_result", f"{repo}/tools/pool-action-modules/private-runner-result.py")
    parser = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(parser)
        native_result = parser.read_live_result(f"{results}/{name}.json")
    except Exception:
        sys.exit(1)
rows = [l.rstrip("\n").split("\t") for l in open(f"{results}/{name}.samples.tsv")][1:]
swaps = [int(r[1]) for r in rows if int(r[1]) >= 0]
avails = [int(r[2]) for r in rows if int(r[2]) >= 0]
rss = [int(r[3]) for r in rows if int(r[3]) >= 0]
s = {"case": name, "cache": cache, "expect": expect, "exitStatus": status, "tripped": tripped or None, "samples": len(rows),
     "swapBaselineBytes": swap0, "swapGrowthMaxBytes": max(swaps) - swap0, "availableMinBytes": min(avails), "sampledRSSMaxBytes": max(rss)}
tf = f"{results}/{name}.time"
if os.path.exists(tf) and os.path.getsize(tf):
    t = open(tf).read()
    real = re.search(r"([\d.]+) real", t)
    mrss = re.search(r"(\d+)\s+maximum resident set size", t)
    foot = re.search(r"(\d+)\s+peak memory footprint", t)
    s["timeRealSeconds"] = float(real.group(1)) if real else None
    s["timeMaxRSSBytes"] = int(mrss.group(1)) if mrss else None
    s["timePeakMemoryFootprintBytes"] = int(foot.group(1)) if foot else None
import glob
s["evicted"] = []
for ef in sorted(glob.glob(f"{results}/{name}.evict-*.json")):
    e = json.load(open(ef))
    s["evicted"].append({"file": e["key"], "residentBefore": e["residencyAtStart"]["residentPages"],
                         "residentAfter": e["residencyAfter"]["residentPages"], "pages": e["residencyAfter"]["pages"]})
jf = f"{results}/{name}.json"
if (live and sys.argv[10] == "2") or os.path.exists(jf):
    j = native_result if live and sys.argv[10] == "2" else json.load(open(jf))
    s["residencyAtStart"] = (j.get("residencyAtStart") or {}).get("fraction")
    s["r1csResidencyAtStart"] = (j.get("r1csResidencyAtStart") or {}).get("fraction")
    s["processWallSeconds"] = j.get("processWallSeconds")
    s["processMaxRSSBytes"] = j.get("processMaxRSSBytes")
    s["error"] = j.get("error")
    s["errorStage"] = j.get("errorStage")
    s["steps"] = {p["name"]: {"seconds": p["seconds"], "maxRSSBytesAtEnd": p["maxRSSBytesAtEnd"]} for p in (j.get("phases") or [])}
json.dump(s, open(f"{results}/{name}.summary.json", "w"), indent=2)
PY
	(( result_status == 0 )) || die "native result refused"
	echo "measure-pk-load: $name ended $(/bin/date) with status $status"
	[[ -z $tripped ]] || die "$name killed: $tripped"
	if [[ $expect == ok ]]; then
		((status == 0)) || die "$name exited with status $status; see $results/$name.stderr"
	else
		local stage
		if [[ $PRIVATE_RUNNER_GENERATION == 2 ]] && $live; then
   stage="$(/usr/bin/python3 "$repo/tools/pool-action-modules/private-runner-result.py" "$results/$name.json" 2>/dev/null)" || die "native result refused"
  else
   stage="$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("errorStage") or "")' "$results/$name.json")"
  fi
		((status == 1)) && [[ $expect == fail || refuse-$stage == "$expect" ]] ||
			die "$name: expected $expect, got status $status stage '$stage'"
		echo "measure-pk-load: $name failed (stage '$stage'), as expected"
	fi
}

# The plan is read on fd 3 so that nothing a case runs can consume it.
while read -r line <&3; do
	[[ -z ${line// /} || $line == \#* ]] && continue
	# shellcheck disable=SC2086
	run_case $line
done 3< <(plan_source)

/usr/bin/python3 - "$results" "${names[@]}" <<'PY'
import json, sys
r = sys.argv[1]
json.dump({"run": json.load(open(f"{r}/run.json")),
           "cases": [json.load(open(f"{r}/{n}.summary.json")) for n in sys.argv[2:]]},
          open(f"{r}/summary.json", "w"), indent=2)
PY
if $has_live; then echo "measure-pk-load: done (live result paths withheld)"; else echo "measure-pk-load: done; results in $out"; fi
