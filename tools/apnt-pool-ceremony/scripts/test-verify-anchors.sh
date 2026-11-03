#!/usr/bin/env bash
# Tests that run-phased.sh hands the standalone verifier all three anchors
# when it is given --expect-r1cs-sha256 (ENG-460): the phase-1 pin, the
# beacon and the R1CS digest. Everything happens in one sparse scratch clone
# of this repository at HEAD, on the committed test circuit with the INSECURE
# toy phase-1 fixture, so it needs no real phase-1 file and little memory.
#
#   anchored     a full toy run (init, one contribution, seal, verify) with
#                --expect-r1cs-sha256: VALID, and the verifier's report
#                records anchors phase1Pin, beacon and r1cs all true
#   replay       the run's verifier binary with the harness's arguments and
#                the right digest: exit 0, VALID, anchors.r1cs true
#   wrong-r1cs   the same with one hex digit of the digest changed: the
#                verifier refuses (exit 1, R1CS_UNEXPECTED). run-phased.sh
#                itself dies on a wrong digest before any phase, so this is
#                the verifier's own check, which the anchor exists for
#   unanchored   --verify-only without --expect-r1cs-sha256: VALID with
#                anchors.r1cs false (the flag stays optional)
#   witness      the clone's harness with the ENG-460 line removed
#                (committed in the clone), --verify-only with the flag: the
#                anchored check must now fail, anchors.r1cs false
#
# usage: scripts/test-verify-anchors.sh SCRATCH-DIR   (new or empty; outside
#        any git repository). Exit 0 only if every case passes.
# It holds the machine-wide prover lock through run-phased.sh, one run at a
# time, and needs 2 GiB available.
set -euo pipefail

[[ $# -eq 1 ]] || { sed -n '2,26p' "$0" >&2; exit 2; }
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
repo="$(git -C "$here" rev-parse --show-toplevel)"
[[ -z "$(git -C "$repo" status --porcelain -- tools/apnt-pool-ceremony)" ]] ||
	{ echo "test-verify-anchors: commit tools/apnt-pool-ceremony first; the clone tests HEAD" >&2; exit 1; }
head="$(git -C "$repo" rev-parse HEAD)"
mkdir -p "$1"
S="$(cd "$1" && pwd -P)"
[[ -z "$(ls -A "$S")" ]] || { echo "test-verify-anchors: $S is not empty" >&2; exit 1; }
! git -C "$S" rev-parse --git-dir >/dev/null 2>&1 || { echo "test-verify-anchors: $S is inside a git repository" >&2; exit 1; }

C="$S/clone"
T="$C/tools/apnt-pool-ceremony"
git clone --quiet --shared --no-checkout "$repo" "$C"
git -C "$C" sparse-checkout set --cone tools/apnt-pool-ceremony
git -C "$C" checkout --quiet --detach "$head"
g() { git -C "$C" -c user.name=test-verify-anchors -c user.email=test@invalid -c core.hooksPath=/dev/null "$@"; }

(cd "$T" && GOPROXY=off go build -o "$S/tool/" ./cmd/...)
"$S/tool/apnt-pool-ceremony" compile-test-circuit --circuit committed --size 100 --out "$S/c100.r1cs" >/dev/null
"$S/tool/apnt-pool-ceremony" write-toy-ptau --power 8 --out "$S/toy8.ptau" >"$S/toy8.json" 2>/dev/null
pin="$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha256"])' "$S/toy8.json")"
r1cs_sha="$(/usr/bin/shasum -a 256 "$S/c100.r1cs" | cut -d' ' -f1)"
# One hex digit changed, so the wrong digest is still well-formed.
wrong_sha="$(/usr/bin/python3 -c 'import sys; h = sys.argv[1]; print(h[:-1] + ("0" if h[-1] != "0" else "1"))' "$r1cs_sha")"
beacon=a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00
flags=(--ptau "$S/toy8.ptau" --ptau-pin "$pin" --r1cs "$S/c100.r1cs" --min-available-gib 2 --min-disk-gib 1)
export GOMAXPROCS=4

failures=0
result() { # PASS|FAIL name detail
	[[ $1 == PASS ]] || failures=$((failures + 1))
	printf '%-4s %-12s %s\n' "$1" "$2" "$3"
}
# anchors FILE -> "verdict phase1Pin beacon r1cs", or the verdict and code of a refusal
anchors() {
	/usr/bin/python3 - "$1" <<'PY'
import json, sys
try:
    r = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"unreadable {e}")
    sys.exit(0)
a = r.get("anchors") or {}
print(r.get("verdict"), a.get("phase1Pin"), a.get("beacon"), a.get("r1cs"), r.get("code", ""))
PY
}

# anchored: the full toy run with the R1CS anchor.
st=0
"$T/scripts/run-phased.sh" "$S/out-anchored" "${flags[@]}" --ptau-source "toy INSECURE fixture" --label c100 \
	--ceremony-id anchors-anchored --contributions 1 --beacon "$beacon" --beacon-source "fixed test beacon" \
	--expect-r1cs-sha256 "$r1cs_sha" >"$S/anchored.log" 2>&1 || st=$?
got="$(anchors "$S/out-anchored/results/verify.stdout")"
if ((st == 0)) && grep -q '^run-phased: VALID' "$S/anchored.log" && [[ $got == "VALID True True True " ]]; then
	result PASS anchored "exit 0; verdict and anchors: $got"
else
	result FAIL anchored "exit $st; verdict and anchors: $got; see $S/anchored.log"
fi

# replay and wrong-r1cs: the run's own verifier binary, the harness's arguments.
ver="$S/out-anchored/bin/apnt-pool-ceremony-verify"
vargs=(--transcript "$S/out-anchored/ceremony/transcript.json" --ptau "$S/toy8.ptau" --r1cs "$S/c100.r1cs"
	--expect-phase1-pin "$pin" --expect-beacon "$beacon")
st=0
"$ver" "${vargs[@]}" --expect-r1cs-sha256 "$r1cs_sha" --json >"$S/replay.json" 2>"$S/replay.stderr" || st=$?
got="$(anchors "$S/replay.json")"
if ((st == 0)) && [[ $got == "VALID True True True " ]]; then
	result PASS replay "exit 0; verdict and anchors: $got"
else
	result FAIL replay "exit $st; verdict and anchors: $got"
fi
st=0
"$ver" "${vargs[@]}" --expect-r1cs-sha256 "$wrong_sha" --json >"$S/wrong-r1cs.json" 2>"$S/wrong-r1cs.stderr" || st=$?
got="$(anchors "$S/wrong-r1cs.json")"
if ((st == 1)) && [[ $got == "REFUSED None None None R1CS_UNEXPECTED" ]]; then
	result PASS wrong-r1cs "exit 1; $got"
else
	result FAIL wrong-r1cs "exit $st; $got; see $S/wrong-r1cs.stderr"
fi

# unanchored: the flag stays optional.
st=0
"$T/scripts/run-phased.sh" "$S/out-unanchored" --verify-only "$S/out-anchored/ceremony" "${flags[@]}" \
	--beacon "$beacon" >"$S/unanchored.log" 2>&1 || st=$?
got="$(anchors "$S/out-unanchored/results/verify.stdout")"
if ((st == 0)) && [[ $got == "VALID True True False " ]]; then
	result PASS unanchored "exit 0; verdict and anchors: $got"
else
	result FAIL unanchored "exit $st; verdict and anchors: $got; see $S/unanchored.log"
fi

# witness: without ENG-460's line the anchored check must fail.
/usr/bin/python3 - "$T/scripts/run-phased.sh" <<'PY'
import sys
p = sys.argv[1]
old = '[[ -z $expect_r1cs ]] || verify_args+=(--expect-r1cs-sha256 "$expect_r1cs")'
s = open(p).read()
if s.count(old) != 1:
    sys.exit(f"witness: original text found {s.count(old)} times")
open(p, "w").write(s.replace(old, ":"))
PY
g commit --quiet -am "test: witness without ENG-460"
st=0
"$T/scripts/run-phased.sh" "$S/out-witness" --verify-only "$S/out-anchored/ceremony" "${flags[@]}" \
	--beacon "$beacon" --expect-r1cs-sha256 "$r1cs_sha" >"$S/witness.log" 2>&1 || st=$?
got="$(anchors "$S/out-witness/results/verify.stdout")"
if ((st == 0)) && [[ $got == "VALID True True False " ]]; then
	result PASS witness "the anchored check fires without ENG-460: $got"
else
	result FAIL witness "exit $st; verdict and anchors: $got; see $S/witness.log"
fi
g checkout --quiet --detach --force "$head"

echo "test-verify-anchors: $failures failure(s); logs in $S"
((failures == 0))
