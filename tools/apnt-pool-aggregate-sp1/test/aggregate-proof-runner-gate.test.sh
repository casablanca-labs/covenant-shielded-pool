#!/usr/bin/env bash
# ENG-510: the refusals of scripts/aggregate-proof-runner.sh, each executed for real. Every case
# refuses before a runner is built, a marker is created or a prover starts; no case proves.
#
# usage: test/aggregate-proof-runner-gate.test.sh CANONICAL-CHIPNET-ELF SCRATCH-DIR
#
# SCRATCH-DIR must be new; it receives a shared clone of this checkout (for the guest-input
# case) and wrong ELFs. The shared-lock case holds the machine-wide prover flock for a few
# seconds, so run it when no prover is running.
set -euo pipefail
[[ $# -eq 2 ]] || { echo "usage: $0 CANONICAL-CHIPNET-ELF SCRATCH-DIR" >&2; exit 2; }
elf="$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")"
scratch=$2
[[ ! -e $scratch ]] || { echo "$scratch exists" >&2; exit 2; }
here="$(cd "$(dirname "$0")/.." && pwd -P)"
root="$(git -C "$here" rev-parse --show-toplevel)"
harness="$here/scripts/aggregate-proof-runner.sh"
token=--operator-authorized-one-aggregate-proof
mkdir -p "$scratch/out"
scratch="$(cd "$scratch" && pwd -P)"
pass=0

expect() { # expect NAME EXIT-CODE ERROR-SUBSTRING -- command...
	local name=$1 want_exit=$2 want=$3
	shift 4
	local got=0 err
	err="$("$@" 2>&1 >/dev/null)" || got=$?
	if [[ $got -ne $want_exit || $err != *"$want"* ]]; then
		echo "FAIL $name: exit $got (want $want_exit), stderr: $err" >&2
		exit 1
	fi
	[[ ! -e /private/tmp/bch-cloak-sp1-prover-exclusive-v1 ]] || { echo "FAIL $name left the SP1 marker" >&2; exit 1; }
	pass=$((pass + 1))
	echo "ok $name"
}

expect usage 2 usage -- "$harness"
expect unknown-mode 2 usage -- "$harness" execute b1 "$root" "$elf"
expect batch-b16 1 error=batch-must-be-b1-or-b17-or-live-bN -- "$harness" dry-run b16 "$root" "$elf"
expect live-missing-input 1 error=pool-live-input-required -- "$harness" dry-run live-b1 "$root" "$elf"
expect live-missing-file 1 error=pool-live-input-file -- "$harness" dry-run live-b1 "$root" "$elf" --live-input "$scratch/missing.json"
expect fixture-with-live-file 1 error=pool-live-input-requires-live-batch -- "$harness" dry-run b1 "$root" "$elf" --live-input "$scratch/missing.json"
expect live-prove-without-token 2 usage -- "$harness" prove live-b1 "$root" "$elf" "$scratch/out/proof.json" --live-input "$scratch/missing.json"
expect prove-without-token 2 usage -- "$harness" prove b1 "$root" "$elf" "$scratch/out/proof.json"
expect prove-wrong-token 2 usage -- "$harness" prove b1 "$root" "$elf" "$scratch/out/proof.json" --yes
head -c 16 "$elf" >"$scratch/short.elf"
expect elf-length 1 error=elf-length-mismatch -- "$harness" dry-run b1 "$root" "$scratch/short.elf"
cp "$elf" "$scratch/flipped.elf"
printf '\x00' | dd of="$scratch/flipped.elf" bs=1 seek=4096 conv=notrunc 2>/dev/null
cmp -s "$elf" "$scratch/flipped.elf" && printf '\x01' | dd of="$scratch/flipped.elf" bs=1 seek=4096 conv=notrunc 2>/dev/null
expect elf-digest 1 error=elf-digest-mismatch -- "$harness" dry-run b1 "$root" "$scratch/flipped.elf"
ln -s "$elf" "$scratch/link.elf"
expect elf-symlink 1 error=elf-is-not-a-regular-file -- "$harness" dry-run b1 "$root" "$scratch/link.elf"
expect live-input-symlink 1 error=pool-live-input-file -- "$harness" dry-run live-b1 "$root" "$elf" --live-input "$scratch/link.elf"
printf '{}\n' >"$scratch/live.json"
# A checkout whose guest inputs differ from the pin (one comment line in the guest source).
git clone -q --shared --no-checkout "$root" "$scratch/clone"
git -C "$scratch/clone" checkout -q --detach "$(git -C "$root" rev-parse HEAD)"
echo "// ENG-510 gate test: a changed guest input" >>"$scratch/clone/tools/apnt-pool-aggregate-sp1/program/src/main.rs"
expect guest-inputs 1 error=checkout-guest-inputs-are-not-the-pinned-ones -- "$harness" dry-run b1 "$scratch/clone" "$elf"
# prove refuses anything but the clean main checkout on main (the clone is detached; this
# checkout is on a lane branch or is a worktree).
git -C "$scratch/clone" checkout -q -- tools/apnt-pool-aggregate-sp1/program/src/main.rs
expect prove-detached 1 error=checkout-is-not-on-main -- "$harness" prove b1 "$scratch/clone" "$elf" "$scratch/out/proof.json" "$token"
expect live-prove-detached 1 error=checkout-is-not-on-main -- "$harness" prove live-b1 "$scratch/clone" "$elf" "$scratch/out/proof.json" "$token" --live-input "$scratch/live.json"
git -C "$scratch/clone" checkout -q -B main
echo scratch >"$scratch/clone/untracked-file"
expect prove-dirty 1 error=checkout-is-not-clean -- "$harness" prove b1 "$scratch/clone" "$elf" "$scratch/out/proof.json" "$token"
rm "$scratch/clone/untracked-file"
touch "$scratch/out/exists.json"
expect prove-output-exists 1 error=output-already-exists -- "$harness" prove b1 "$scratch/clone" "$elf" "$scratch/out/exists.json" "$token"
expect prove-output-in-checkout 1 error=output-inside-the-checkout -- "$harness" prove b1 "$scratch/clone" "$elf" "$scratch/clone/proof.json" "$token"
touch "$scratch/out/SHA256SUMS"
expect prove-sums-exist 1 error=output-directory-already-has-SHA256SUMS -- "$harness" prove b1 "$scratch/clone" "$elf" "$scratch/out/proof.json" "$token"
rm "$scratch/out/SHA256SUMS"
# The shared prover lock, held by another process: refused before any build.
/usr/bin/python3 -B -c '
import fcntl, os, sys, time
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
open(sys.argv[2], "w").close()
time.sleep(20)' "/private/tmp/apnt-gnark-r2-proof-$UID.lock" "$scratch/locked" &
holder=$!
for _ in $(seq 1 50); do [[ -e $scratch/locked ]] && break; sleep 0.1; done
expect shared-lock-held 1 error=shared-prover-lock-held -- "$harness" dry-run b1 "$root" "$elf"
kill "$holder" 2>/dev/null || true
wait "$holder" 2>/dev/null || true
[[ ! -e $HOME/proof-scratch/.prover.lock ]] || { echo "FAIL a case left ~/proof-scratch/.prover.lock" >&2; exit 1; }
echo "aggregate-proof-runner gate: $pass refusals PASS"
