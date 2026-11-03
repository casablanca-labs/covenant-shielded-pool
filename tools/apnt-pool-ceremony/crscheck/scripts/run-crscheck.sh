#!/usr/bin/env bash
# RESEARCH PROTOTYPE, NOT REVIEWED (ARCH-238, run R-393).
#
# run-crscheck.sh OUT-DIR BINARY [CRSCHECK-ARG...]
#
# Runs the crscheck BINARY once, measured, under the machine-wide prover lock
# (with-prover-lock.sh, floor MIN_AVAILABLE_GIB, default 12): GOMAXPROCS=4,
# GOMEMLIMIT=9GiB, nice 10, caffeinate -i, /usr/bin/time -l. Every 2 s it
# appends epoch, swap used, available memory (free + inactive + speculative)
# and the check's RSS to OUT-DIR/samples.tsv, and kills the check if its RSS
# passes RSS_TRIP_GIB (default 12) or available memory falls below 4 GiB or
# swap grows by more than 2 GiB. The check's stdout, stderr and time output
# go to OUT-DIR; OUT-DIR/summary.json records the measurements.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

if [[ ${1:-} != --inner ]]; then
	[[ $# -ge 2 ]] || { sed -n '2,14p' "$0" >&2; exit 2; }
	out=$1
	mkdir -p "$out"
	[[ -z "$(ls -A "$out")" ]] || { echo "run-crscheck: $out is not empty" >&2; exit 2; }
	exec "$here/with-prover-lock.sh" "${MIN_AVAILABLE_GIB:-12}" -- \
		/usr/bin/caffeinate -i /bin/bash "$0" --inner "$@"
fi
shift
out=$1 bin=$2
shift 2
rss_trip=$((${RSS_TRIP_GIB:-12} * 1073741824))
floor=$((4 * 1073741824))

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
		{ for (i = 1; i <= NF; i++) if ($i == "used") {
			v = $(i + 2); u = substr(v, length(v), 1); a = substr(v, 1, length(v) - 1) + 0
			m = u == "K" ? 1024 : u == "M" ? 1048576 : u == "G" ? 1073741824 : 0
			printf "%.0f\n", a * m } }'
}
rss_of() { /bin/ps -o rss= -p "$1" 2>/dev/null | /usr/bin/awk '{ printf "%.0f\n", $1 * 1024 }'; }

swap0="$(swap_used_bytes)"
printf 'epoch_s\tswap_used_bytes\tavailable_bytes\tcheck_rss_bytes\n' >"$out/samples.tsv"
printf '%s\n' "$bin $*" >"$out/command.txt"
start=$(/bin/date +%s)
env GOMAXPROCS=4 GOMEMLIMIT=9GiB /usr/bin/nice -n 10 /usr/bin/time -l "$bin" "$@" \
	>"$out/stdout.txt" 2>"$out/stderr.txt" &
tpid=$!
tripped=""
while kill -0 "$tpid" 2>/dev/null; do
	cpid="$(/usr/bin/pgrep -P "$tpid" | head -1 || true)"
	rss=0
	[[ -z $cpid ]] || rss="$(rss_of "$cpid" || echo 0)"
	avail="$(available_bytes || echo -1)"
	swap="$(swap_used_bytes || echo -1)"
	printf '%s\t%s\t%s\t%s\n' "$(/bin/date +%s)" "$swap" "$avail" "${rss:-0}" >>"$out/samples.tsv"
	if ((${rss:-0} > rss_trip)); then tripped="rss $rss"; fi
	if ((avail >= 0 && avail < floor)); then tripped="available $avail"; fi
	if ((swap >= 0 && swap - swap0 > 2147483648)); then tripped="swap growth $((swap - swap0))"; fi
	if [[ -n $tripped ]]; then
		echo "run-crscheck: TRIPPED ($tripped); killing" >&2
		[[ -z $cpid ]] || kill "$cpid" 2>/dev/null || true
		break
	fi
	sleep 2
done
status=0
wait "$tpid" || status=$?
end=$(/bin/date +%s)
/usr/bin/python3 - "$out" "$status" "$((end - start))" "$tripped" <<'PY'
import json, re, sys
out, status, wall, tripped = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
rows = [l.rstrip("\n").split("\t") for l in open(f"{out}/samples.tsv")][1:]
err = open(f"{out}/stderr.txt").read()
def grab(pat):
    m = re.search(pat, err)
    return int(m.group(1)) if m else None
s = {
    "exitStatus": status, "wallSeconds": wall, "tripped": tripped or None, "samples": len(rows),
    "timeMaxRSSBytes": grab(r"(\d+)\s+maximum resident set size"),
    "timePeakMemoryFootprintBytes": grab(r"(\d+)\s+peak memory footprint"),
    "sampledRSSMaxBytes": max((int(r[3]) for r in rows), default=None),
    "availableMinBytes": min((int(r[2]) for r in rows if int(r[2]) >= 0), default=None),
    "swapUsedMinBytes": min((int(r[1]) for r in rows if int(r[1]) >= 0), default=None),
    "swapUsedMaxBytes": max((int(r[1]) for r in rows if int(r[1]) >= 0), default=None),
}
m = re.search(r"([\d.]+) real\s+([\d.]+) user\s+([\d.]+) sys", err)
if m:
    s["timeReal"], s["timeUser"], s["timeSys"] = map(float, m.groups())
json.dump(s, open(f"{out}/summary.json", "w"), indent=2)
print(json.dumps(s, indent=2))
PY
exit "$status"
