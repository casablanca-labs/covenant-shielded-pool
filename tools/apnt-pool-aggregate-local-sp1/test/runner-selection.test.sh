#!/usr/bin/env bash
# Pin-selection controls only: no guest execution, setup, prove, Docker, or chain contact.
# usage: runner-selection.test.sh CANONICAL-LOCAL-ELF CANONICAL-CHIPNET-ELF NEW-SCRATCH
set -euo pipefail
[[ $# -eq 3 && -f $1 && -f $2 && ! -e $3 ]] || { echo "usage: $0 LOCAL-ELF CHIPNET-ELF NEW-SCRATCH" >&2; exit 2; }
root="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
runner="$root/tools/apnt-pool-aggregate-sp1/scripts/aggregate-proof-runner.sh"
mkdir -p "$3"
scratch="$(cd "$3" && pwd -P)"
printf '{}\n' >"$scratch/local-input.json"
token=--operator-authorized-one-aggregate-proof

expect_refusal() {
  local name=$1 code=$2; shift 2
  local output rc=0
  output="$("$@" 2>&1)" || rc=$?
  [[ $rc -eq 1 && $output == *"error=$code"* ]] || { echo "FAIL $name: exit=$rc output=$output" >&2; exit 1; }
  echo "PASS $name $code"
}

"$runner" dry-run live-b1 "$root" "$1" --network local --live-input "$scratch/local-input.json" --selector-control-only >"$scratch/local.selection"
"$runner" dry-run b1 "$root" "$2" --selector-control-only >"$scratch/chipnet.selection"
/usr/bin/grep -q '^network=local$' "$scratch/local.selection"
/usr/bin/grep -q '^network=chipnet$' "$scratch/chipnet.selection"
/usr/bin/grep -q '^label=LOCAL 0x99 - SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY$' "$scratch/local.selection"
echo "PASS distinct pinned selections"

expect_refusal local-elf-under-chipnet elf-length-mismatch "$runner" dry-run b1 "$root" "$1"
expect_refusal chipnet-elf-under-local elf-length-mismatch "$runner" dry-run live-b1 "$root" "$2" --network local --live-input "$scratch/local-input.json"
head -c 16 "$1" >"$scratch/short-local.elf"
expect_refusal local-wrong-length elf-length-mismatch "$runner" dry-run live-b1 "$root" "$scratch/short-local.elf" --network local --live-input "$scratch/local-input.json"
expect_refusal local-requires-live-b1 pool-local-live-b1-required "$runner" dry-run b1 "$root" "$1" --network local
expect_refusal worktree-prove checkout-is-not-on-main "$runner" prove live-b1 "$root" "$1" "$scratch/proof.json" "$token" --network local --live-input "$scratch/local-input.json"
[[ ! -e $scratch/proof.json ]] || { echo "FAIL proof output exists" >&2; exit 1; }
