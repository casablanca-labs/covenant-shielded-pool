#!/usr/bin/env bash
# ENG-514, ENG-517 abort test: plays scripts/aggregate-proof-runner.sh's prove path around the
# sourced supervision library - the same claim, marker, launch, keeper, supervision, reap and
# release code - with every claim under CASE-DIR, CASE-DIR/docker/docker (the fake CLI) as
# DOCKER_BIN, the two memory measurements read from CASE-DIR/fake, and runner-stub.sh as the
# prover. Only the measurements are replaced; the run's process listing behind the RSS figure
# still executes. It proves nothing and never names the machine-wide lock or markers.
# STUB-MODE admission runs only the prove admission's container check against the fake daemon.
#
# usage: driver.sh LIBRARY CASE-DIR STUB-MODE
set -euo pipefail
umask 077
[[ $# -eq 3 ]] || { echo "usage: $0 LIBRARY CASE-DIR STUB-MODE" >&2; exit 2; }
library=$1
case_dir="$(cd "$2" && pwd -P)"
stub_mode=$3
fixtures="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

readonly SHARED_PROVER_LOCK="$case_dir/claims/shared.lock"
readonly SP1_EXCLUSIVE_MARKER="$case_dir/claims/sp1-exclusive"
readonly SCRATCH_PROVER_LOCK="$case_dir/claims/scratch-marker/prover.lock"
readonly DOCKER_BIN="$case_dir/docker/docker"
readonly POLL_SECONDS=1
readonly TRIP_RSS_KIB=$((30 * 1024 * 1024))
readonly SWAP_GROWTH_TRIP_BYTES=$((16 * 1024 * 1024 * 1024))
readonly REAP_TERM_SECONDS=2
readonly REAP_KILL_SECONDS=5
readonly DOCKER_CALL_SECONDS=10
# shellcheck source=../../scripts/prover-supervision.sh
source "$library"

eval "real_$(declare -f prover_rss_kib)"
prover_rss_kib() { real_prover_rss_kib >/dev/null || return 1; cat "$case_dir/fake/rss-kib"; }
swap_used_bytes() { cat "$case_dir/fake/swap-bytes"; }

if [[ $stub_mode == admission ]]; then
	require_no_prover_containers
	echo "driver: admission passed"
	exit 0
fi
claim_shared_prover_lock
create_prover_markers b1 "$case_dir/proof.json"
: >"$case_dir/claimed"
swap_baseline="$(swap_used_bytes)"
prover_launch "$case_dir/run" "$case_dir" "$fixtures/runner-stub.sh" "$case_dir" "$stub_mode"
prover_supervise "$case_dir/memory.tsv"
echo "driver: the prover exited 0"
