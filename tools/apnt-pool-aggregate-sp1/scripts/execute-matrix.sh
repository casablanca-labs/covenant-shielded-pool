#!/usr/bin/env bash
# ENG-421 (task 5.4 slice 1): build the pool aggregate guest three times
# (default, DEVELOPMENT ZERO-VALUE test profile, and the labelled Chipnet
# build, ENG-510) and execute every runner case, one case per fresh runner
# process, serially. Execute only: nothing here proves; the runner's execute
# command has no proving path.
#
# usage: scripts/execute-matrix.sh OUT-DIR
#        scripts/execute-matrix.sh --canonical CANONICAL-DIR OUT-DIR
#
# OUT-DIR must be new; it receives elf/, cases/<case>.json, cases/<case>.log,
# build logs and run.txt. Without --canonical the ELFs are built in whatever
# checkout runs this script: their digests are measurements, never pins.
# With --canonical (ENG-510) nothing is built but the runner: CANONICAL-DIR
# holds the canonical builds of tools/sp1-canonical-guest-build
# (apnt-pool-aggregate-program-chipnet-zero-value-rev3 and
# apnt-pool-aggregate-program), the Chipnet ELF must equal this checkout's pin
# (canonical-build/chipnet-zero-value-rev3-canonical-build-v1.json: SHA-256
# and length) and the default ELF the record's default build, and only the
# chipnet and default cases run.
#
# Before the builds and before every case it refuses while
# ~/proof-scratch/.prover.lock or the SP1 exclusive marker exists, while a
# known prover process runs, or below 16 GiB available (free + inactive +
# speculative), and it holds the shared prover flock for the whole run.
set -euo pipefail

readonly MIN_AVAILABLE_BYTES=$((16 * 1024 * 1024 * 1024))
readonly SHARED_PROVER_LOCK="/private/tmp/apnt-gnark-r2-proof-$UID.lock"
readonly SP1_EXCLUSIVE_MARKER="/private/tmp/bch-cloak-sp1-prover-exclusive-v1"
readonly SCRATCH_PROVER_LOCK="$HOME/proof-scratch/.prover.lock"

die() { echo "execute-matrix: refusing: $*" >&2; exit 1; }
canonical=""
if [[ ${1:-} == --canonical ]]; then
	[[ $# -eq 3 ]] || { echo "usage: $0 [--canonical CANONICAL-DIR] OUT-DIR" >&2; exit 2; }
	canonical=$2
	shift 2
fi
[[ $# -eq 1 ]] || { echo "usage: $0 [--canonical CANONICAL-DIR] OUT-DIR" >&2; exit 2; }
out=$1
[[ ! -e $out ]] || die "$out already exists"
here="$(cd "$(dirname "$0")/.." && pwd -P)"
repo="$(git -C "$here" rev-parse --show-toplevel)"

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
		exe == "gnark-reference" || exe == "pool-action-circuit" || exe == "apnt-pool-action-circuit.test" { print; next }
		exe ~ /^apnt-pool-ceremony/ { print; next }
		exe ~ /^(cargo-prove|sp1-prover|sp1_core)(-|$)/ { print; next }
		exe == "apnt-pool-aggregate-runner" { next }
		exe ~ /^apnt-.*-(runner|prover)(-[[:alnum:]_.-]+)?$/ { print; next }
		exe ~ /^(r2-run|r3-run|relation-r2-run|apnt-successor-child-circuits(\.test)?|apnt-child-circuits-cost(\.test)?)$/ { print; next }'
}
require_quiet_machine() {
	local phase=$1 others avail
	[[ ! -e $SCRATCH_PROVER_LOCK && ! -L $SCRATCH_PROVER_LOCK ]] || die "$phase: $SCRATCH_PROVER_LOCK exists"
	[[ ! -e $SP1_EXCLUSIVE_MARKER && ! -L $SP1_EXCLUSIVE_MARKER ]] || die "$phase: the SP1 exclusive marker is present"
	others="$(other_provers)"
	[[ -z $others ]] || die "$phase: another prover is running:
$others"
	avail="$(available_bytes)" || die "$phase: vm_stat unreadable"
	((avail >= MIN_AVAILABLE_BYTES)) || die "$phase: $avail bytes available, below $MIN_AVAILABLE_BYTES"
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
((lock_status == 0)) || die "the shared prover lock is held (status $lock_status)"

require_quiet_machine build
mkdir -p "$out/elf" "$out/cases"
export RAYON_NUM_THREADS=4 CARGO_BUILD_JOBS=4
{
	echo "headCommit $(git -C "$repo" rev-parse HEAD)"
	echo "dirty $(git -C "$repo" status --porcelain -- tools/apnt-pool-aggregate-sp1 | wc -l | tr -d ' ')"
	echo "started $(/bin/date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "cargoProve $("$HOME/.sp1/bin/cargo-prove" prove --version 2>&1 | head -1)"
} >"$out/run.txt"

record="$here/canonical-build/chipnet-zero-value-rev3-canonical-build-v1.json"
pinned() { /usr/bin/python3 -B -c 'import json,sys; r=json.load(open(sys.argv[1])); x=r[sys.argv[2]]; print(x["guestElfSha256"], x["guestElfBytes"])' "$record" "$1"; }
if [[ -n $canonical ]]; then
	echo "canonical $canonical" >>"$out/run.txt"
	for pair in "record apnt-pool-aggregate-program-chipnet-zero-value-rev3 pool-aggregate-chipnet" \
		"defaultBuild apnt-pool-aggregate-program pool-aggregate-default"; do
		read -r key src dst <<<"$pair"
		f="$canonical/$src"
		[[ -f $f && ! -L $f ]] || die "no canonical ELF $f"
		read -r want_sha want_bytes <<<"$(pinned "$key")"
		[[ "$(shasum -a 256 "$f" | cut -c1-64)" == "$want_sha" && "$(wc -c <"$f" | tr -d ' ')" == "$want_bytes" ]] ||
			die "$f is not the pinned canonical $key ELF"
		cp "$f" "$out/elf/$dst"
	done
else
	cd "$here/program"
	/usr/bin/nice -n 10 "$HOME/.sp1/bin/cargo-prove" prove build --locked --elf-name pool-aggregate-default \
		--output-directory "$out/elf" >"$out/build-default.log" 2>&1
	/usr/bin/nice -n 10 "$HOME/.sp1/bin/cargo-prove" prove build --locked --features development-zero-value-test-profile \
		--elf-name pool-aggregate-development --output-directory "$out/elf" >"$out/build-development.log" 2>&1
	cd "$here/program-chipnet-zero-value-rev3"
	/usr/bin/nice -n 10 "$HOME/.sp1/bin/cargo-prove" prove build --locked --elf-name pool-aggregate-chipnet \
		--output-directory "$out/elf" >"$out/build-chipnet.log" 2>&1
fi
cd "$here"
/usr/bin/nice -n 10 cargo build --offline --locked --release -p apnt-pool-aggregate-runner >"$out/build-runner.log" 2>&1
runner="$here/target/release/apnt-pool-aggregate-runner"
[[ -x $runner ]] || die "no runner binary"
builds="default development chipnet"
[[ -z $canonical ]] || builds="default chipnet"
for b in $builds; do
	[[ -s "$out/elf/pool-aggregate-$b" ]] || die "missing ELF pool-aggregate-$b"
done
shasum -a 256 "$out/elf/"* >"$out/elf/SHA256SUMS"

"$runner" list | while read -r case build; do
	if [[ " $builds " == *" $build "* ]]; then echo "$case $build"; fi
done >"$out/cases.txt"
status=0
while read -r case build; do
	require_quiet_machine "$case"
	elf="$out/elf/pool-aggregate-$build"
	echo "execute-matrix: $case ($build) $(/bin/date)"
	/usr/bin/nice -n 10 "$runner" execute --case "$case" --elf "$elf" "$out/cases/$case.json" \
		</dev/null >"$out/cases/$case.log" 2>&1 || { status=1; echo "execute-matrix: $case FAILED" >&2; }
done <"$out/cases.txt"
echo "finished $(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) status $status" >>"$out/run.txt"
exit "$status"
