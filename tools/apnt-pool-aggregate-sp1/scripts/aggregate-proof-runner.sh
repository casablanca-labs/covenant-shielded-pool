#!/usr/bin/env bash
# ENG-510 (task 5.4 slice 2a writes it; slice 2b runs it): the gated harness for ONE SP1
# Groth16 proof of the pool aggregate's labelled Chipnet build (SIMULATED SINGLE-PARTY SETUP -
# ZERO-VALUE TEST ONLY) over a v5 statement: b1 (REL1, settleable) or b17 (the cost).
#
# usage: scripts/aggregate-proof-runner.sh dry-run b1|b17 CHECKOUT-ROOT CANONICAL-ELF
#        scripts/aggregate-proof-runner.sh prove   b1|b17 CHECKOUT-ROOT CANONICAL-ELF OUTPUT \
#            --operator-authorized-one-aggregate-proof
#        For a live batch, replace b1|b17 with live-bN and append --live-input FILE.
#        Append --network local for the separate local 0x99 zero-value guest (live-bN only).
#        Omitted --network means the original Chipnet path.
#
# Gates, in order (a refusal prints error=CODE and exits 1; nothing is built or proved first):
#   - the batch is b1, b17 or live-bN (local requires live-bN and a regular input file);
#     the ELF is a regular file equal to the selected network's pin (SHA-256 and length);
#   - the checkout's guest inputs match that pin; the selector anchors the pin and graph bytes;
#   - prove only: the checkout is the main checkout on branch main and clean; OUTPUT does not
#     exist, its directory does and lies outside the checkout; Docker answers with at least
#     20 GiB of VM memory (SP1's Groth16 wrap runs gnark in Docker and needs about 14 GB);
#   - no known prover process runs, the SP1 exclusive marker and ~/proof-scratch/.prover.lock
#     are absent, and this script takes the machine-wide shared prover flock (fd 9) for its
#     whole run;
#   - prove only: at least 20 GiB available (free + inactive + speculative), measured again
#     after the fresh runner build, immediately before the prover starts;
#   - prove only: no container labelled by a prover run and none of SP1's gnark image exists,
#     in any state (running, created, exited), and SP1_GNARK_IMAGE is unset.
# Then (prove) it creates the SP1 exclusive marker and ~/proof-scratch/.prover.lock, builds a
# fresh --locked release runner with the `prove` feature outside the checkout, loads the SP1
# 6.3.1 M1 memory profile (tools/apnt-pool-aggregate-sp1/scripts/memory-measure.py env m1; default
# sharding does not fit 48 GB), and runs the prover under nice, as its own session under a keeper
# (scripts/prover-processes.py) that holds it unreaped until the release, with two
# trips sampled every 5 s: the run's host RSS reaching 30 GiB, and swap growing more than 16 GiB
# over its baseline (macOS swaps a few GB during the gnark wrap regardless of free memory). On
# success it requires exactly one setup and one prove call, annotates the evidence with the
# memory record and writes SHA256SUMS beside it.
# On every exit - success, refusal, prover failure, a trip, HUP, INT or TERM - the EXIT trap in
# scripts/prover-supervision.sh (ENG-514, ENG-517; see its header) reaps the prover's whole run:
# TERM to every process of it (the group only through the keeper; each pid only after a fresh
# identity check), a bounded wait, KILL; once a listing confirms no process of it is left, it
# removes every gnark wrap or labelled container in any state and confirms none is left. Only
# then are the markers removed and the flock closed.
# Unconfirmed, the markers stay and the script exits 3 (error=prover-reap-unconfirmed). The
# markers are removed only if this run created them; a SIGKILL leaves them, and a stale marker
# blocks, never admits.
# dry-run takes the same locks and checks, builds the same runner, and executes the guest
# (light client; no setup, no prove), printing the admission it would face.
# The runner admits live inputs through the core encoder and verifier before any SDK step.
set -euo pipefail
umask 077

readonly ADMISSION_BYTES=$((20 * 1024 * 1024 * 1024))
readonly DOCKER_MIN_BYTES=$((20 * 1024 * 1024 * 1024))
readonly TRIP_RSS_KIB=$((30 * 1024 * 1024))
readonly SWAP_GROWTH_TRIP_BYTES=$((16 * 1024 * 1024 * 1024))
readonly POLL_SECONDS=5
readonly REAP_TERM_SECONDS=15
readonly REAP_KILL_SECONDS=30
readonly DOCKER_CALL_SECONDS=30
readonly SHARED_PROVER_LOCK="/private/tmp/apnt-gnark-r2-proof-$UID.lock"
readonly SP1_EXCLUSIVE_MARKER="/private/tmp/bch-cloak-sp1-prover-exclusive-v1"
readonly SCRATCH_PROVER_LOCK="$HOME/proof-scratch/.prover.lock"
readonly TOKEN="--operator-authorized-one-aggregate-proof"
readonly CARGO_BIN="$HOME/.cargo/bin/cargo"
readonly NODE_BIN="/opt/homebrew/bin/node"
readonly PROTOC_BIN="/opt/homebrew/bin/protoc"
readonly GO_BIN="/opt/homebrew/bin/go"
readonly DOCKER_BIN="/usr/local/bin/docker"

# fail, the claims, the prover's supervision and the EXIT, HUP, INT and TERM traps.
# shellcheck source=prover-supervision.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/prover-supervision.sh"

usage() {
	echo "usage: $0 dry-run b1|b17 CHECKOUT-ROOT CANONICAL-ELF" >&2
	echo "       $0 prove b1|b17 CHECKOUT-ROOT CANONICAL-ELF OUTPUT $TOKEN" >&2
	echo "       live-bN (1 <= N <= 65535): same arguments, with --live-input FILE appended; --network local|chipnet is optional" >&2
	exit 2
}

mode=${1:-}
case "$mode" in
dry-run) [[ $# -ge 4 ]] || usage; first_option=5 ;;
prove) [[ $# -ge 6 && $6 == "$TOKEN" ]] || usage; first_option=7 ;;
*) usage ;;
esac
batch=$2
live_batch=false
if [[ $batch == live-b* ]]; then
	count=${batch#live-b}
	[[ $count =~ ^[1-9][0-9]{0,4}$ && $count -le 65535 ]] || fail "pool-live-batch-selector"
	live_batch=true
else
	[[ $batch == b1 || $batch == b17 ]] || fail "batch-must-be-b1-or-b17-or-live-bN"
fi
network=chipnet
network_seen=false
live_input=
selector_control=false
args=("$@")
for ((i=first_option-1; i<${#args[@]}; i++)); do
	case "${args[i]}" in
	--network)
		[[ $network_seen == false && $((i+1)) -lt ${#args[@]} ]] || usage
		network=${args[++i]}; network_seen=true ;;
	--live-input)
		[[ -z $live_input && $((i+1)) -lt ${#args[@]} ]] || usage
		live_input=${args[++i]} ;;
	--selector-control-only)
		[[ $mode == dry-run && $selector_control == false ]] || usage
		selector_control=true ;;
	*) usage ;;
	esac
done
[[ $network == chipnet || $network == local ]] || fail "pool-network-unsupported"
[[ $network != local || $live_batch == true ]] || fail "pool-local-live-batch-required"
live_args=()
if [[ $live_batch == true ]]; then
	[[ -n $live_input ]] || fail "pool-live-input-required"
	[[ -f $live_input && ! -L $live_input ]] || fail "pool-live-input-file"
	live_input="$(cd "$(dirname "$live_input")" && pwd -P)/$(basename "$live_input")"
	live_args=(--live-input "$live_input")
else
	[[ -z $live_input ]] || fail "pool-live-input-requires-live-batch"
fi
[[ -d $3 && ! -L $3 ]] || fail "checkout-root-is-not-a-directory"
root="$(cd "$3" && pwd -P)"
elf=$4
workspace="$root/tools/apnt-pool-aggregate-sp1"
if [[ $network == local ]]; then
	record="$root/tools/apnt-pool-aggregate-local-sp1/canonical-build/local-zero-value-canonical-build-v1.json"
	input_module="./tools/apnt-pool-aggregate-local-sp1/canonical-build/guest-inputs.mjs"
	input_function=localGuestInputsInWorkingTree
	pin_label="LOCAL 0x99 - SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY"
else
	record="$workspace/canonical-build/chipnet-zero-value-rev3-canonical-build-v1.json"
	input_module="./tools/apnt-pool-aggregate-sp1/canonical-build/guest-inputs.mjs"
	input_function=guestInputsInWorkingTree
	pin_label="SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY"
fi
[[ -f $record ]] || fail "pin-record-missing"

# ---- the ELF and the checkout's guest inputs are the pin's ----
pins="$(/usr/bin/python3 -B -c '
import json, sys
r = json.load(open(sys.argv[1]))
assert r["label"] == sys.argv[2]
x = r["record"]
print(x["guestElfSha256"], x["guestElfBytes"], x["programVkeyHash"], x["guestInputs"]["sha256"])' "$record" "$pin_label")" || fail "pin-record-unreadable"
read -r pin_sha pin_bytes pin_vkey pin_inputs <<<"$pins"
[[ -f $elf && ! -L $elf ]] || fail "elf-is-not-a-regular-file"
[[ "$(/usr/bin/stat -f %z "$elf")" == "$pin_bytes" ]] || fail "elf-length-mismatch"
[[ "$(/usr/bin/shasum -a 256 "$elf" | cut -c1-64)" == "$pin_sha" ]] || fail "elf-digest-mismatch"
elf="$(cd "$(dirname "$elf")" && pwd -P)/$(basename "$elf")"
[[ -x $NODE_BIN ]] || fail "node-unavailable"
# The network selector anchors the exact pin and verifier graph bytes. The
# record's own fields alone cannot authorize a substituted pin file.
(cd "$root" && "$NODE_BIN" --input-type=module -e '
import { getPinnedPoolAggregateBuildSelection } from "./tools/apnt-pool-aggregate-local-sp1/canonical-build/identity-policy.mjs";
const [network, sha, length, vkey] = process.argv.slice(1);
const p = getPinnedPoolAggregateBuildSelection(network);
if (p.guestElfSha256 !== sha || p.guestElfBytes !== Number(length) ||
    p.programVkeyHash !== vkey || p.network !== network) process.exit(1);
' "$network" "$pin_sha" "$pin_bytes" "$pin_vkey" 9>&-) || fail "pin-selection-mismatch"
inputs="$(cd "$root" && "$NODE_BIN" --input-type=module -e '
const m = await import(process.argv[2]);
console.log(m[process.argv[3]](process.argv[1]).sha256);' "$root" "$input_module" "$input_function" 9>&-)" || fail "guest-inputs-unreadable"
[[ $inputs == "$pin_inputs" ]] || fail "checkout-guest-inputs-are-not-the-pinned-ones" \
	"rebuild canonically and re-pin, or check out the pinned sources; never edit the pin to match"
if [[ $selector_control == true ]]; then
	printf '%s\n' "network=$network" "pin_record=$record" "elf_sha256=$pin_sha" "elf_bytes=$pin_bytes" \
		"program_vkey_pinned=$pin_vkey" "guest_inputs_sha256=$inputs" "label=$pin_label"
	exit 0
fi

# ---- prove only: the clean main checkout, the output, Docker ----
if [[ $mode == prove ]]; then
	output=$5
	[[ "$(git -C "$root" symbolic-ref --quiet --short HEAD 2>/dev/null 9>&-)" == main ]] || fail "checkout-is-not-on-main"
	[[ -z "$(git -C "$root" status --porcelain --untracked-files=normal 2>/dev/null 9>&-)" ]] || fail "checkout-is-not-clean"
	[[ "$(git -C "$root" rev-parse --git-dir 9>&-)" == .git ]] || fail "checkout-is-a-worktree-not-the-main-checkout"
	[[ ! -e $output && ! -L $output ]] || fail "output-already-exists"
	outdir="$(cd "$(dirname "$output")" 2>/dev/null && pwd -P)" || fail "output-directory-missing"
	case "$outdir/" in "$root"/*) fail "output-inside-the-checkout" ;; esac
	output="$outdir/$(basename "$output")"
	counts="$output.call-counts.json"
	[[ ! -e $counts ]] || fail "call-count-sidecar-already-exists"
	[[ ! -e $outdir/SHA256SUMS ]] || fail "output-directory-already-has-SHA256SUMS" "give each proof its own new directory"
	[[ -x $DOCKER_BIN ]] || fail "docker-cli-unavailable"
	docker_bytes="$("$DOCKER_BIN" info --format '{{.MemTotal}}' 2>/dev/null 9>&-)" || fail "docker-daemon-unavailable" "start Docker Desktop"
	[[ $docker_bytes =~ ^[0-9]+$ ]] && ((docker_bytes >= DOCKER_MIN_BYTES)) ||
		fail "docker-vm-memory-below-20-gib" "raise Docker Desktop's memory to at least 24 GiB: the Groth16 wrap needs about 14 GB"
fi

# ---- one prover ----
available_bytes() {
	/usr/bin/vm_stat | /usr/bin/awk '
		NR == 1 && match($0, /page size of [0-9]+ bytes/) { v = substr($0, RSTART, RLENGTH); gsub(/[^0-9]/, "", v); page = v + 0 }
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
		exe ~ /^apnt-.*-(runner|prover)(-[[:alnum:]_.-]+)?$/ { print; next }
		exe ~ /^(r2-run|r3-run|relation-r2-run|apnt-successor-child-circuits(\.test)?|apnt-child-circuits-cost(\.test)?)$/ { print; next }'
}
require_quiet_machine() {
	local others
	[[ ! -e $SP1_EXCLUSIVE_MARKER && ! -L $SP1_EXCLUSIVE_MARKER ]] ||
		fail "sp1-exclusive-marker-present" "remove $SP1_EXCLUSIVE_MARKER only after confirming the pid in its owner file is not running"
	[[ ! -e $SCRATCH_PROVER_LOCK && ! -L $SCRATCH_PROVER_LOCK ]] ||
		fail "scratch-prover-marker-present" "remove $SCRATCH_PROVER_LOCK only after confirming the pid in it is not running"
	others="$(other_provers)"
	[[ -z $others ]] || fail "another-prover-is-running: $(echo $others)"
}
require_quiet_machine
claim_shared_prover_lock
available="$(available_bytes)" || fail "vm-stat-unreadable"
swap_baseline="$(swap_used_bytes)" || fail "swap-unreadable"

if [[ $mode == prove ]]; then
	((available >= ADMISSION_BYTES)) || fail "20-gib-admission-refused ($available bytes available)"
	require_no_prover_containers
	create_prover_markers "$batch" "$output"
fi

# ---- a fresh --locked release runner with the prove feature, outside the checkout ----
[[ -x $CARGO_BIN && -x $PROTOC_BIN && -x $GO_BIN ]] || fail "build-tools-unavailable"
build_dir="$(/usr/bin/mktemp -d /private/tmp/pool-aggregate-prover-build.XXXXXX)"
mkdir "$build_dir/host-tools"
ln -s "$PROTOC_BIN" "$build_dir/host-tools/protoc"
ln -s "$GO_BIN" "$build_dir/host-tools/go"
if ! (cd "$workspace" && PROTOC="$build_dir/host-tools/protoc" PATH="$build_dir/host-tools:$PATH" CARGO_BUILD_JOBS=4 \
	/usr/bin/nice -n 10 "$CARGO_BIN" build --locked --offline --release --features prove -p apnt-pool-aggregate-runner \
	--target-dir "$build_dir/target" >"$build_dir/build.log" 2>&1) 9>&-; then
	tail -20 "$build_dir/build.log" >&2
	fail "runner-build-failed"
fi
runner="$build_dir/target/release/apnt-pool-aggregate-runner"
[[ -x $runner ]] || fail "runner-missing"
runner_sha="$(/usr/bin/shasum -a 256 "$runner" | cut -c1-64)"

if [[ $mode == dry-run ]]; then
	out="$(cd "$workspace" && RAYON_NUM_THREADS=4 /usr/bin/nice -n 10 "$runner" proof-dry-run --network "$network" --batch "$batch" --canonical-elf "$elf" ${live_args[@]+"${live_args[@]}"})" ||
		fail "runner-dry-run-failed"
	available="$(available_bytes)" || fail "vm-stat-unreadable"
	/usr/bin/python3 -B - "$out" <<'PY' || fail "dry-run-output-mismatch"
import json, sys
p = json.loads(sys.argv[1])
assert p["schema"] == "apnt-pool-aggregate-proof-dry-run-v1" and p["exitCode"] == 0 and p["committedHex"] == p["runBind32"]
assert p["setupCallCount"] == 0 and p["proveCallCount"] == 0 and p["proofConstructed"] is False
PY
	docker_bytes="$("$DOCKER_BIN" info --format '{{.MemTotal}}' 2>/dev/null 9>&- || echo unavailable)"
	printf '%s\n' "schema=apnt-pool-aggregate-proof-harness-dry-run-v1" "network=$network" "batch=$batch" "checkout_root=$root" \
		"elf_sha256=$pin_sha" "elf_bytes=$pin_bytes" "program_vkey_pinned=$pin_vkey" "guest_inputs_sha256=$inputs" \
		"available_memory_bytes=$available" "admission_required_bytes=$ADMISSION_BYTES" \
		"admission_passed=$([[ $available -ge $ADMISSION_BYTES ]] && echo true || echo false)" \
		"docker_vm_memory_bytes=$docker_bytes" "swap_used_bytes_baseline=$swap_baseline" \
		"swap_growth_trip_bytes=$SWAP_GROWTH_TRIP_BYTES" "rss_trip_kib=$TRIP_RSS_KIB" \
		"shared_prover_lock_held=true" "exclusive_marker_created=false" "runner_build=fresh-locked-release-prove-feature" \
		"runner_sha256=$runner_sha" "runner_dry_run=$out"
	exit 0
fi

# ---- prove: M1 profile, one prover, trips ----
m1="$root/tools/apnt-pool-aggregate-sp1/scripts/memory-measure.py"
[[ -f $m1 ]] || fail "m1-profile-source-missing"
m1_env="$(/usr/bin/python3 -B "$m1" env m1 9>&-)" || fail "m1-profile-unavailable"
eval "$m1_env"
others="$(other_provers)"
[[ -z $others ]] || fail "another-prover-is-running-after-build: $(echo $others)"
available="$(available_bytes)" || fail "vm-stat-unreadable"
((available >= ADMISSION_BYTES)) || fail "20-gib-admission-refused-after-build ($available bytes available)"
swap_baseline="$(swap_used_bytes)" || fail "swap-unreadable"
prover_launch "$build_dir/run" "$workspace" /usr/bin/nice -n 10 "$runner" prove-groth16 --network "$network" --batch "$batch" --canonical-elf "$elf" \
	--output "$output" --call-count-output "$counts" ${live_args[@]+"${live_args[@]}"}
prover_supervise "$output.memory.tsv"
/usr/bin/python3 -B - "$counts" <<'PY' || fail "call-counts-unexpected"
import json, sys
c = json.load(open(sys.argv[1]))
assert c["schema"] == "apnt-pool-aggregate-sdk-call-counts-v1" and c["setupCallCount"] == 1 and c["proveCallCount"] == 1
PY
/usr/bin/python3 -B - "$output" "$swap_baseline" "$swap_peak" "$rss_peak_kib" "$((SECONDS - started))" "$runner_sha" "$(git -C "$root" rev-parse HEAD 9>&-)" <<'PY' || fail "evidence-annotation-failed"
import json, os, sys
path = sys.argv[1]
p = json.load(open(path))
for k in ("harness",):
    assert k not in p
p["harness"] = {"script": "tools/apnt-pool-aggregate-sp1/scripts/aggregate-proof-runner.sh", "checkoutHead": sys.argv[7],
    "swapUsedBytesBaseline": int(sys.argv[2]), "swapUsedBytesPeak": int(sys.argv[3]), "swapGrowthTripBytes": 16 * 1024**3,
    "processTreePeakRssKib": int(sys.argv[4]), "rssTripKib": 30 * 1024**2, "wallSeconds": int(sys.argv[5]),
    "runnerSha256": sys.argv[6], "memoryProfile": "SP1 6.3.1 M1 (tools/apnt-pool-aggregate-sp1/scripts/memory-measure.py env m1)",
    "note": "RSS is the run's host processes (its process group, run-tagged processes and their descendants); the Groth16 wrap's gnark runs in Docker's VM and is not in it"}
tmp = path + ".tmp"
with open(tmp, "x") as f:
    json.dump(p, f, indent=2); f.write("\n"); f.flush(); os.fsync(f.fileno())
os.replace(tmp, path)
PY
(cd "$(dirname "$output")" && /usr/bin/shasum -a 256 "$(basename "$output")" >SHA256SUMS)
echo "proved batch=$batch output=$output wall_seconds=$((SECONDS - started)) rss_peak_kib=$rss_peak_kib swap_growth_bytes=$((swap_peak - swap_baseline))"
