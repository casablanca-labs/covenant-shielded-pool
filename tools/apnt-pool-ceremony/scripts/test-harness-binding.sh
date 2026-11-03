#!/usr/bin/env bash
# Tests that run-phased.sh --resume-seal (run-5-1c.sh seal) runs only with the
# shell source its start recorded (ENG-418). Everything happens in one sparse
# scratch clone of this repository at HEAD, on the committed test circuit
# with the INSECURE toy phase-1 fixture, so it needs no real phase-1 file and
# little memory. Each case runs a fresh start (init, one contribution), makes
# one change to the clone, and resumes:
#
#   control             no change: seal and the anchored verifier, VALID
#   dirty-harness       run-phased.sh edited, uncommitted (REV-182's case)
#   dirty-other         README.md edited, uncommitted: only the clean-tree
#                       guard can see it
#   committed-other     README.md changed and committed: only the HEAD guard
#   hidden-harness      run-phased.sh edited behind git update-index
#                       --assume-unchanged: HEAD and git status unchanged,
#                       only the digest guard can see it
#   hidden-wrapper      the same for run-5-1c.sh
#   wrapper-mismatch    started through RUN_PHASED_WRAPPER, resumed without
#
# Each change leaves the binaries, the R1CS and the phase-1 pin as they were.
# Then each guard's witness: the clone's harness with that one guard
# disabled (committed in the clone) must let its isolating case through.
#
# usage: scripts/test-harness-binding.sh SCRATCH-DIR   (new or empty; outside
#        any git repository). Exit 0 only if every case and witness passes.
# It holds the machine-wide prover lock through run-phased.sh, one run at a
# time, and needs 2 GiB available.
set -euo pipefail

[[ $# -eq 1 ]] || { sed -n '2,27p' "$0" >&2; exit 2; }
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
repo="$(git -C "$here" rev-parse --show-toplevel)"
[[ -z "$(git -C "$repo" status --porcelain -- tools/apnt-pool-ceremony)" ]] ||
	{ echo "test-harness-binding: commit tools/apnt-pool-ceremony first; the clone tests HEAD" >&2; exit 1; }
head="$(git -C "$repo" rev-parse HEAD)"
mkdir -p "$1"
S="$(cd "$1" && pwd -P)"
[[ -z "$(ls -A "$S")" ]] || { echo "test-harness-binding: $S is not empty" >&2; exit 1; }
! git -C "$S" rev-parse --git-dir >/dev/null 2>&1 || { echo "test-harness-binding: $S is inside a git repository" >&2; exit 1; }

C="$S/clone"
T="$C/tools/apnt-pool-ceremony"
git clone --quiet --shared --no-checkout "$repo" "$C"
git -C "$C" sparse-checkout set --cone tools/apnt-pool-ceremony
git -C "$C" checkout --quiet --detach "$head"
g() { git -C "$C" -c user.name=test-harness-binding -c user.email=test@invalid -c core.hooksPath=/dev/null "$@"; }

# Fixtures: the committed test circuit (a commitment, 256-point domain) and
# the INSECURE toy phase-1 file for its domain.
(cd "$T" && GOPROXY=off go build -o "$S/tool/" ./cmd/...)
"$S/tool/apnt-pool-ceremony" compile-test-circuit --circuit committed --size 100 --out "$S/c100.r1cs" >/dev/null
"$S/tool/apnt-pool-ceremony" write-toy-ptau --power 8 --out "$S/toy8.ptau" >"$S/toy8.json" 2>/dev/null
pin="$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha256"])' "$S/toy8.json")"
beacon=a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00
flags=(--ptau "$S/toy8.ptau" --ptau-pin "$pin" --r1cs "$S/c100.r1cs" --min-available-gib 2 --min-disk-gib 1)
export GOMAXPROCS=4

reset_clone() { # back to HEAD, flags cleared
	g update-index --no-assume-unchanged tools/apnt-pool-ceremony/scripts/run-phased.sh tools/apnt-pool-ceremony/scripts/run-5-1c.sh
	g checkout --quiet --detach --force "$head"
	g reset --quiet --hard "$head"
}
hide_edit() { # edit a script with git told to ignore it; git status and HEAD stay as they were
	g update-index --assume-unchanged "tools/apnt-pool-ceremony/scripts/$1"
	printf '\n# hidden edit by test-harness-binding\n' >>"$T/scripts/$1"
	if [[ -n "$(g status --porcelain)" ]]; then
		echo "FAIL hidden edit of $1 shows in git status; the case would not isolate the digest guard"
		failures=$((failures + 1))
	fi
}
start() { # name [env...]
	local name=$1
	shift
	env "$@" "$T/scripts/run-phased.sh" "$S/out-$name" "${flags[@]}" --ptau-source "toy INSECURE fixture" \
		--label c100 --ceremony-id "binding-$name" --contributions 1 --stop-after contribute >"$S/$name.start.log" 2>&1
}
resume() { # name [env...] -> exit status
	local name=$1
	shift
	set +e
	env "$@" "$T/scripts/run-phased.sh" "$S/out-$name" --resume-seal "${flags[@]}" --contributions 1 \
		--beacon "$beacon" --beacon-source "fixed test beacon" >"$S/$name.seal.log" 2>&1
	local st=$?
	set -e
	return $st
}

failures=0
report() { # verdict name want got
	[[ $1 == PASS ]] || failures=$((failures + 1))
	printf '%-4s %-34s want %-7s got exit %s: %s\n' "$1" "$2" "$3" "$4" \
		"$(grep -hE 'run-phased: (resume-seal: |refusing|VALID)' "$S/$2.seal.log" | head -3 | tr '\n' ' ' | cut -c1-230)"
}
# case name want(refused|VALID) change-command [start-env...]
case_() {
	local name=$1 want=$2 change=$3
	shift 3
	reset_clone
	start "$name" "$@" || { echo "FAIL $name: start failed, see $S/$name.start.log"; failures=$((failures + 1)); return; }
	eval "$change"
	local st=0
	resume "$name" || st=$?
	local got=refused
	((st == 0)) && grep -q '^run-phased: VALID' "$S/$name.seal.log" && got=VALID
	local verdict=FAIL
	[[ $got == "$want" ]] && verdict=PASS
	report "$verdict" "$name" "$want" "$st"
}

case_ control VALID ":"
case_ dirty-harness refused "printf '\n# uncommitted edit\n' >>'$T/scripts/run-phased.sh'"
case_ dirty-other refused "printf '\nuncommitted edit\n' >>'$T/README.md'"
case_ committed-other refused "printf '\ncommitted edit\n' >>'$T/README.md'; g commit --quiet -am 'test: README edit'"
case_ hidden-harness refused "hide_edit run-phased.sh"
case_ hidden-wrapper refused "hide_edit run-5-1c.sh"
case_ wrapper-mismatch refused ":" "RUN_PHASED_WRAPPER=$T/scripts/run-5-1c.sh"

# Witnesses: disable one guard in the clone's harness, commit it there (so
# start and resume both run the mutated harness from a clean tree), and rerun
# the case only that guard catches. It must now get through.
witness() { # name case-change original replacement
	local name=$1 change=$2 original=$3 replacement=$4
	reset_clone
	/usr/bin/python3 - "$T/scripts/run-phased.sh" "$original" "$replacement" <<'PY'
import sys
p, old, new = sys.argv[1:4]
s = open(p).read()
if s.count(old) != 1:
    sys.exit(f"witness: original text found {s.count(old)} times")
open(p, "w").write(s.replace(old, new))
PY
	g commit --quiet -am "test: witness $name"
	start "$name" || { echo "FAIL $name: start failed, see $S/$name.start.log"; failures=$((failures + 1)); return; }
	eval "$change"
	local st=0
	resume "$name" || st=$?
	local got=refused
	((st == 0)) && grep -q '^run-phased: VALID' "$S/$name.seal.log" && got=VALID
	local verdict=FAIL
	[[ $got == VALID ]] && verdict=PASS
	report "$verdict" "$name" VALID "$st"
}
witness witness-clean-tree "printf '\nuncommitted edit\n' >>'$T/README.md'" \
	'dirty="$(git -C "$repo" status --porcelain -- tools/apnt-pool-ceremony)"' 'dirty=""'
witness witness-head "printf '\ncommitted edit\n' >>'$T/README.md'; g commit --quiet -am 'test: README edit'" \
	'if run.get("headCommit") != os.environ["RESUME_HEAD"]:' 'if False:'
witness witness-digests "hide_edit run-phased.sh" \
	'elif now != started:' 'elif False:'
reset_clone

echo "test-harness-binding: $failures failure(s); logs in $S"
((failures == 0))
