#!/usr/bin/env bash
set -euo pipefail

# Explicit metadata follows completed semantic controls; ordinary output and
# descendants are suppressed by the native adapter. No value/path is emitted.
POOL_NATIVE_ASSERTIONS=0
native_assertion() {
  POOL_NATIVE_ASSERTIONS=$((POOL_NATIVE_ASSERTIONS + 1))
  if [ "${POOL_NATIVE_METADATA:-}" = 1 ]; then
    printf 'ok %s - %s\n' "$POOL_NATIVE_ASSERTIONS" "$1" >&3
  fi
}
native_assertions_done() {
  if [ "${POOL_NATIVE_METADATA:-}" = 1 ]; then
    printf '1..%s\n' "$POOL_NATIVE_ASSERTIONS" >&3
  fi
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SOURCE_BUILDER="$(cd "$SCRIPT_DIR/.." && pwd -P)/canonical-guest-build.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/private/tmp}/apnt-canonical-builder-host-tools-test.XXXXXX")"
TEST_ROOT="$(cd "$TEST_ROOT" && pwd -P)"
trap 'rm -rf "$TEST_ROOT"' EXIT

CHECKOUT="$TEST_ROOT/checkout"
FIXED="$TEST_ROOT/fixed"
TEMP_PARENT="$TEST_ROOT/temp"
OUTPUT="$TEST_ROOT/output"
FIXTURE_BUILDER="$TEST_ROOT/canonical-guest-build.sh"
mkdir -p \
  "$CHECKOUT/tools/apnt-private-note-transition-v2-sp1/program" \
  "$FIXED" "$TEMP_PARENT" "$OUTPUT"

cat > "$FIXED/protoc" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
cat > "$FIXED/go" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
cat > "$FIXED/cargo-prove" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
STUB_ROOT="$(cd "$(dirname "$0")" && pwd -P)"
HOST_TOOLS="${PATH%%:*}"
{
  echo "path=$PATH"
  echo "host-tools=$HOST_TOOLS"
  echo "mode=$(/usr/bin/stat -f '%Lp' "$HOST_TOOLS")"
  echo "protoc=$(/usr/bin/readlink "$HOST_TOOLS/protoc")"
  echo "go=$(/usr/bin/readlink "$HOST_TOOLS/go")"
  for entry in "$HOST_TOOLS"/*; do
    echo "entry=$(/usr/bin/basename "$entry")"
  done
  for argument in "$@"; do
    echo "arg=$argument"
  done
} >> "$STUB_ROOT/invocations.log"

if [ -e "$STUB_ROOT/fail" ]; then
  exit 91
fi
if [ -e "$STUB_ROOT/signal-parent" ]; then
  /bin/kill -TERM "$PPID"
  exit 94
fi

output=""
elf=""
workspace=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-directory)
      output="$2"
      shift 2
      ;;
    --elf-name)
      elf="$2"
      shift 2
      ;;
    --workspace-directory)
      workspace="$2"
      shift 2
      ;;
    *) shift ;;
  esac
done
[ -n "$output" ] && [ -n "$elf" ]
if [ -e "$STUB_ROOT/offline" ]; then
  image=ghcr.io/succinctlabs/sp1@sha256:0942a27dbe8e38f4b14f3732e779df4027b17bde93e9fbc9e8c773c15eb63400
  docker run --rm --platform linux/amd64 --entrypoint '' \
    -e RUSTUP_TOOLCHAIN=succinct "$image" rustc --version
  docker run --rm --platform linux/amd64 \
    -v "$workspace:/root/program" \
    -v sp1-cargo-registry:/root/.cargo/registry -v sp1-cargo-git:/root/.cargo/git \
    -w /root/program/tools/apnt-pool-aggregate-sp1/program-chipnet-zero-value-rev3 \
    -e CARGO_TARGET_DIR=/root/program/tools/apnt-pool-aggregate-sp1/target/elf-compilation/docker \
    -e RUSTUP_TOOLCHAIN=succinct -e RUSTC_BOOTSTRAP=1 \
    -e CARGO_ENCODED_RUSTFLAGS=fixture -e RUSTC=/root/toolchain/bin/rustc \
    -e CFLAGS_riscv32im_succinct_zkvm_elf=-D__ILP32__ --entrypoint '' \
    "$image" cargo build --release --target riscv64im-succinct-zkvm-elf \
    -p "$elf" --bin "$elf" --locked
fi
/bin/mkdir -p "$output"
printf 'fixture-elf\n' > "$output/$elf"
STUB
chmod 700 "$FIXED/protoc" "$FIXED/go" "$FIXED/cargo-prove"

/usr/bin/sed \
  -e "s|^TRUSTED_CARGO_PROVE=.*|TRUSTED_CARGO_PROVE=\"$FIXED/cargo-prove\"|" \
  -e "s|^TRUSTED_PROTOC=.*|TRUSTED_PROTOC=\"$FIXED/protoc\"|" \
  -e "s|^TRUSTED_GO=.*|TRUSTED_GO=\"$FIXED/go\"|" \
  -e "s|^TRUSTED_DOCKER=.*|TRUSTED_DOCKER=\"$FIXED/docker\"|" \
  -e 's|^TRUSTED_PATH=.*|TRUSTED_PATH="/usr/bin:/bin"|' \
  "$SOURCE_BUILDER" > "$FIXTURE_BUILDER"
chmod 700 "$FIXTURE_BUILDER"

find "$CHECKOUT" -print | LC_ALL=C sort > "$TEST_ROOT/checkout-before"
TMPDIR="$TEMP_PARENT" \
  "$FIXTURE_BUILDER" "$CHECKOUT" transition-v2 "$OUTPUT/success" \
  > "$TEST_ROOT/success.stdout"
find "$CHECKOUT" -print | LC_ALL=C sort > "$TEST_ROOT/checkout-after"
/usr/bin/diff -u "$TEST_ROOT/checkout-before" "$TEST_ROOT/checkout-after"

grep -Fqx "mode=700" "$FIXED/invocations.log"
grep -Fqx "protoc=$FIXED/protoc" "$FIXED/invocations.log"
grep -Fqx "go=$FIXED/go" "$FIXED/invocations.log"
[ "$(grep -c '^entry=' "$FIXED/invocations.log")" -eq 2 ]
grep -Fqx 'entry=go' "$FIXED/invocations.log"
grep -Fqx 'entry=protoc' "$FIXED/invocations.log"
[ -f "$OUTPUT/success/apnt-private-note-transition-v2-sp1-program" ]

assert_no_setup_artifacts() {
  if find "$TEMP_PARENT" -maxdepth 1 \
      -name 'apnt-canonical-builder-host-tools.*' -print -quit \
      | grep -q .; then
    echo "canonical builder retained a host-tool setup directory" >&2
    exit 1
  fi
}
assert_no_setup_artifacts
native_assertion "host-tools/private-fixed-tools-and-checkout-preserved"

mv "$FIXED/go" "$FIXED/go.missing"
: > "$FIXED/invocations.log"
if TMPDIR="$TEMP_PARENT" \
    "$FIXTURE_BUILDER" "$CHECKOUT" transition-v2 "$OUTPUT/missing" \
    > "$TEST_ROOT/missing.stdout" 2> "$TEST_ROOT/missing.stderr"; then
  echo "canonical builder accepted a missing fixed host prerequisite" >&2
  exit 1
fi
grep -Fq 'fixed canonical builder host prerequisite is unavailable' \
  "$TEST_ROOT/missing.stderr"
[ ! -s "$FIXED/invocations.log" ]
assert_no_setup_artifacts
native_assertion "host-tools/missing-tool-refused-before-builder"
mv "$FIXED/go.missing" "$FIXED/go"

touch "$FIXED/fail"
: > "$FIXED/invocations.log"
if TMPDIR="$TEMP_PARENT" \
    "$FIXTURE_BUILDER" "$CHECKOUT" transition-v2 "$OUTPUT/failure" \
    > "$TEST_ROOT/failure.stdout" 2> "$TEST_ROOT/failure.stderr"; then
  echo "canonical builder accepted a failed cargo-prove command" >&2
  exit 1
fi
[ -s "$FIXED/invocations.log" ]
assert_no_setup_artifacts
native_assertion "host-tools/builder-failure-cleans"
rm "$FIXED/fail"

touch "$FIXED/signal-parent"
: > "$FIXED/invocations.log"
if TMPDIR="$TEMP_PARENT" \
    "$FIXTURE_BUILDER" "$CHECKOUT" transition-v2 "$OUTPUT/interrupted" \
    > "$TEST_ROOT/interrupted.stdout" 2> "$TEST_ROOT/interrupted.stderr"; then
  echo "canonical builder survived an interruption control" >&2
  exit 1
fi
[ -s "$FIXED/invocations.log" ]
assert_no_setup_artifacts
native_assertion "host-tools/interruption-cleans"
rm "$FIXED/signal-parent"

cat > "$FIXED/docker" <<'STUB'
#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd -P)"
for arg in "$@"; do printf '%s\n' "$arg"; done >> "$root/docker-arguments"
STUB
chmod 700 "$FIXED/docker"
touch "$FIXED/offline"
CACHE="$TEST_ROOT/cache"
mkdir -m 700 "$CACHE" "$CACHE/registry" "$CACHE/git"
mkdir -p "$CHECKOUT/tools/apnt-pool-aggregate-sp1/program-chipnet-zero-value-rev3"
TMPDIR="$TEMP_PARENT" "$FIXTURE_BUILDER" "$CHECKOUT" \
  pool-aggregate-chipnet-zero-value-rev3 "$OUTPUT/offline" --offline-cache "$CACHE" \
  > "$TEST_ROOT/offline.stdout" 2> "$TEST_ROOT/offline.stderr"
grep -Fqx "type=bind,src=$CACHE/registry,dst=/root/.cargo/registry" "$FIXED/docker-arguments"
grep -Fqx "type=bind,src=$CACHE/git,dst=/root/.cargo/git" "$FIXED/docker-arguments"
grep -Fqx "type=bind,src=$CHECKOUT,dst=/root/program" "$FIXED/docker-arguments"
[ "$(grep -Fc 'type=bind,' "$FIXED/docker-arguments")" -eq 3 ]
if grep -Eq ',dst=/root/\.cargo$' "$FIXED/docker-arguments"; then
  echo "offline cache hid the image compiler tools" >&2; exit 1
fi
[ "$(grep -Fc -- '--network=none' "$FIXED/docker-arguments")" -eq 2 ]
[ "$(grep -Fc -- '--pull=never' "$FIXED/docker-arguments")" -eq 2 ]
if grep -Fqx sp1-cargo-registry:/root/.cargo/registry "$FIXED/docker-arguments" \
    || grep -Fqx sp1-cargo-git:/root/.cargo/git "$FIXED/docker-arguments"; then
  echo "offline cache retained a shared volume" >&2; exit 1
fi
assert_no_setup_artifacts
native_assertion "host-tools/offline-cache-preserves-image-tools"

mv "$CACHE/registry" "$CACHE/registry-owned"
ln -s "$CACHE/registry-owned" "$CACHE/registry"
: > "$FIXED/invocations.log"
if TMPDIR="$TEMP_PARENT" "$FIXTURE_BUILDER" "$CHECKOUT" \
    pool-aggregate-chipnet-zero-value-rev3 "$OUTPUT/cache-link" --offline-cache "$CACHE" \
    > "$TEST_ROOT/cache-link.stdout" 2> "$TEST_ROOT/cache-link.stderr"; then
  echo "offline cache accepted a symlinked subtree" >&2; exit 1
fi
grep -Fq 'offline cache subtree is not a private owned physical directory' "$TEST_ROOT/cache-link.stderr"
[ ! -s "$FIXED/invocations.log" ]
rm "$CACHE/registry"
mv "$CACHE/registry-owned" "$CACHE/registry"
chmod 755 "$CACHE/git"
if TMPDIR="$TEMP_PARENT" "$FIXTURE_BUILDER" "$CHECKOUT" \
    pool-aggregate-chipnet-zero-value-rev3 "$OUTPUT/cache-mode" --offline-cache "$CACHE" \
    > "$TEST_ROOT/cache-mode.stdout" 2> "$TEST_ROOT/cache-mode.stderr"; then
  echo "offline cache accepted a nonprivate subtree" >&2; exit 1
fi
grep -Fq 'offline cache subtree is not a private owned physical directory' "$TEST_ROOT/cache-mode.stderr"
[ ! -s "$FIXED/invocations.log" ]
assert_no_setup_artifacts
native_assertion "host-tools/offline-cache-subtrees-refused-before-builder"

printf 'canonical builder ephemeral fixed host tools: PASS\n'

native_assertions_done
