#!/usr/bin/env bash
# Task 5.1c: the simulated single-party phase-2 ceremony of the pool action
# circuit, for Chipnet. SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY:
# the project runs every contribution and could keep the randomness, so it
# can forge proofs under these keys (operator decision on ARCH-141,
# 2026-09-24). Mainnet needs a permissionless multi-party ceremony.
#
# usage: scripts/run-5-1c.sh start  OUT-ROOT R1CS EXPECTED-R1CS-SHA256
#        scripts/run-5-1c.sh seal   OUT-ROOT R1CS EXPECTED-R1CS-SHA256 BEACON-HEX BEACON-SOURCE
#        scripts/run-5-1c.sh verify NEW-OUT-ROOT R1CS EXPECTED-R1CS-SHA256 CEREMONY-DIR BEACON-HEX
#
#   OUT-ROOT              start: new or empty, outside any git repository,
#                         e.g. ~/proof-scratch/pool-5-1c-<date>; seal: the
#                         same directory
#   R1CS                  the pool action circuit's R1CS (gnark v0.16.3,
#                         (*cs.R1CS).WriteTo)
#   EXPECTED-R1CS-SHA256  its SHA-256 from the circuit tool's manifest; any
#                         other file is refused
#   BEACON-HEX            the pre-announced public beacon, lowercase hex,
#                         32-255 bytes: the hash of a Chipnet block at a
#                         height announced before `start`, in display order
#   BEACON-SOURCE         height, byte order, where and when it was announced
#
# start runs init and three automated contributions and stops. seal, once
# the announced block exists, runs seal and then the standalone verifier with
# both anchors (--expect-phase1-pin and --expect-beacon, ENG-350) and the
# circuit anchor (--expect-r1cs-sha256 EXPECTED-R1CS-SHA256, ENG-460). Each phase
# is its own process (scripts/run-phased.sh). Only verifier exit 0 with
# verdict VALID passes; exit 3 (CONSISTENT-UNANCHORED) or anything else fails.
# verify re-runs the anchored verifier alone on a sealed ceremony directory,
# writing its report under NEW-OUT-ROOT. Everything is written under the
# output roots; the transcript, key metadata and a notice file carry the
# simulated-single-party zero-value label.
#
# Memory and disk: every phase refuses to start unless MIN_AVAILABLE_GIB is
# available, MIN_DISK_GIB is free and no prover or ceremony process runs; the
# run holds the machine-wide prover lock and ~/proof-scratch/.prover.lock, and
# a phase whose RSS passes RSS_TRIP_GIB is killed. GOMEMLIMIT keeps the Go
# heap near its live size. The values come from the ENG-331 measurements
# (private historical record ENG-331); the README's 5.1c
# section gives the expected time and memory per phase.
#
# Go runtime settings are the measured plan's, whatever the environment
# holds: GOMEMLIMIT=13GiB, GOMAXPROCS=4, GOGC and GODEBUG unset (the Go
# default collector under the limit). The one override is tighten-only:
# RUN_5_1C_GOMAXPROCS=1, 2 or 3 runs with fewer threads (slower, never more
# memory); any other value is refused. seal must run through this wrapper at
# the start's commit with this wrapper and the harness unchanged
# (run-phased.sh --resume-seal checks their digests).
set -euo pipefail

readonly PTAU="$HOME/proof-scratch/ptau/ppot_0080_23.ptau"
readonly PTAU_PIN="sha256:05085994c8aa34e4925585202e178e09fb8acc04e9565311751e8a04dec81cb1"
readonly PTAU_SOURCE="PSE Perpetual Powers of Tau, contribution 0080 plus beacon, prepared, ppot_0080_23.ptau (https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_23.ptau)"
readonly LABEL="apnt-pool-action-circuit"
readonly CONTRIBUTIONS=3
readonly MIN_AVAILABLE_GIB=20
readonly RSS_TRIP_GIB=18
readonly MIN_DISK_GIB=20
readonly GO_MEMORY_LIMIT=13GiB

usage() {
	sed -n '2,49p' "$0" >&2
	exit 2
}
[[ $# -ge 4 ]] || usage
mode=$1 out=$2 r1cs=$3 expect=$4
shift 4
[[ $expect =~ ^[0-9a-f]{64}$ ]] || { echo "run-5-1c: EXPECTED-R1CS-SHA256 must be 64 lowercase hex characters" >&2; exit 2; }
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
common=(--ptau "$PTAU" --ptau-pin "$PTAU_PIN" --r1cs "$r1cs" --expect-r1cs-sha256 "$expect"
	--min-available-gib "$MIN_AVAILABLE_GIB" --rss-trip-gib "$RSS_TRIP_GIB" --min-disk-gib "$MIN_DISK_GIB")
procs=4
if [[ -n ${RUN_5_1C_GOMAXPROCS:-} ]]; then
	[[ $RUN_5_1C_GOMAXPROCS =~ ^[1-4]$ ]] || { echo "run-5-1c: RUN_5_1C_GOMAXPROCS may only lower GOMAXPROCS to 1-4, got '$RUN_5_1C_GOMAXPROCS'" >&2; exit 2; }
	procs=$RUN_5_1C_GOMAXPROCS
fi
unset GOGC GODEBUG
export GOMAXPROCS=$procs GOMEMLIMIT=$GO_MEMORY_LIMIT RUN_PHASED_WRAPPER="$here/run-5-1c.sh"

case $mode in
start)
	[[ $# -eq 0 ]] || usage
	exec "$here/run-phased.sh" "$out" "${common[@]}" --ptau-source "$PTAU_SOURCE" --label "$LABEL" \
		--ceremony-id "chipnet-pool-action-5.1c-$(/bin/date -u +%Y%m%dT%H%M%SZ)" \
		--contributions "$CONTRIBUTIONS" --stop-after contribute
	;;
seal)
	[[ $# -eq 2 ]] || usage
	beacon=$1 beacon_source=$2
	[[ $beacon =~ ^([0-9a-f]{2}){32,255}$ ]] || { echo "run-5-1c: BEACON-HEX must be 32-255 bytes of lowercase hex" >&2; exit 2; }
	[[ -n $beacon_source ]] || { echo "run-5-1c: BEACON-SOURCE is required" >&2; exit 2; }
	exec "$here/run-phased.sh" "$out" --resume-seal "${common[@]}" --contributions "$CONTRIBUTIONS" \
		--beacon "$beacon" --beacon-source "$beacon_source"
	;;
verify)
	[[ $# -eq 2 ]] || usage
	ceremony=$1 beacon=$2
	exec "$here/run-phased.sh" "$out" --verify-only "$ceremony" "${common[@]}" --beacon "$beacon"
	;;
*) usage ;;
esac
