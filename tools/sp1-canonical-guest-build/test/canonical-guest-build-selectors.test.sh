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

# Native account lookup; caller HOME/PATH never select trusted tools.
TRUSTED_ACCOUNT="$(/usr/bin/id -un)"
case "$TRUSTED_ACCOUNT" in ''|*[!A-Za-z0-9._-]*) exit 1 ;; esac
if [ -x /usr/bin/dscl ]; then
  TRUSTED_HOME="$(/usr/bin/dscl . -read "/Users/${TRUSTED_ACCOUNT}" NFSHomeDirectory | /usr/bin/sed -n 's/^NFSHomeDirectory: //p')"
else
  TRUSTED_HOME="$(/usr/bin/getent passwd "$TRUSTED_ACCOUNT" | /usr/bin/cut -d: -f6)"
fi
case "$TRUSTED_HOME" in /*) ;; *) exit 1 ;; esac
case "$TRUSTED_HOME" in *[[:space:]]*) exit 1 ;; esac
[ -d "$TRUSTED_HOME" ] || exit 1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
BUILDER="$(cd "$SCRIPT_DIR/.." && pwd -P)/canonical-guest-build.sh"
CHECKER="$(cd "$SCRIPT_DIR/.." && pwd -P)/check-recurrence-native-v0.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR%/}/apnt-canonical-builder-selectors.XXXXXX")"
TEST_ROOT="$(cd "$TEST_ROOT" && pwd -P)"
trap 'rm -rf "$TEST_ROOT"' EXIT

CHECKOUT="$TEST_ROOT/checkout"
DECOY_BIN="$TEST_ROOT/decoy-bin"
DECOY_MARKER="$TEST_ROOT/decoy-invoked"
LOG="$TEST_ROOT/selector-control.log"
mkdir -p "$CHECKOUT" "$DECOY_BIN"

cat > "$DECOY_BIN/cargo-prove" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
: "${CANONICAL_BUILDER_DECOY_MARKER:?}"
touch "$CANONICAL_BUILDER_DECOY_MARKER"
exit 97
STUB
cp "$DECOY_BIN/cargo-prove" "$DECOY_BIN/cargo"
cp "$DECOY_BIN/cargo-prove" "$DECOY_BIN/shasum"
chmod 700 "$DECOY_BIN/cargo-prove" "$DECOY_BIN/cargo" "$DECOY_BIN/shasum"

assert_log_line() {
  grep -Fqx -- "$1" "$LOG"
}

run_selector() {
  local key="$1"
  local workspace="$2"
  local package="$3"
  local binary="$4"
  local expected_output="$5"
  local expected_rustflag="$6"
  local program_subdir="${7:-program}"
  local output="$TEST_ROOT/output-$key"

  mkdir -p "$CHECKOUT/$workspace/$program_subdir" "$output"
  CANONICAL_BUILDER_DECOY_MARKER="$DECOY_MARKER" \
    HOME="$TEST_ROOT/forged-home" \
    PATH="$DECOY_BIN:/usr/bin:/bin" \
    RUSTFLAGS="--cfg=forged_ambient_rustflag" \
    /bin/bash "$BUILDER" "$CHECKOUT" "$key" "$output" \
      --selector-control-only > "$LOG"

  assert_log_line "selector-control-only=true"
  assert_log_line "trusted-executable=${TRUSTED_HOME}/.sp1/bin/cargo-prove"
  assert_log_line "trusted-path=${TRUSTED_HOME}/.sp1/bin:${TRUSTED_HOME}/.cargo/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
  assert_log_line "arg=prove"
  assert_log_line "arg=build"
  assert_log_line "arg=--docker"
  assert_log_line "arg=--locked"
  assert_log_line "arg=--workspace-directory"
  assert_log_line "arg=$CHECKOUT"
  assert_log_line "arg=-p"
  assert_log_line "arg=$package"
  assert_log_line "arg=--binaries"
  assert_log_line "arg=$binary"
  assert_log_line "arg=--output-directory"
  assert_log_line "arg=$output"
  assert_log_line "arg=--elf-name"
  assert_log_line "arg=$expected_output"
  assert_log_line "selected-package=$package"
  assert_log_line "selected-binary=$binary"
  assert_log_line "selected-output=$expected_output"
  [ "$(grep -c '^arg=--binaries$' "$LOG")" -eq 1 ]
  if [ "$expected_rustflag" = none ]; then
    [ "$(grep -c '^arg=--rustflags' "$LOG" || true)" -eq 0 ]
  else
    assert_log_line "arg=--rustflags=$expected_rustflag"
    [ "$(grep -c '^arg=--rustflags' "$LOG")" -eq 1 ]
  fi
  ! grep -Fq 'forged_ambient_rustflag' "$LOG"
  [ ! -e "$output/$expected_output" ]
  [ ! -e "$DECOY_MARKER" ]
  native_assertion "selector/$key/exact-trusted-command"
}

run_selector \
  transition \
  tools/apnt-private-note-transition-sp1 \
  apnt-private-note-transition-sp1-program \
  apnt-private-note-transition-sp1-program \
  apnt-private-note-transition-sp1-program \
  none
run_selector \
  transition-v1 \
  tools/apnt-private-note-transition-v1-sp1 \
  apnt-private-note-transition-v1-sp1-program \
  apnt-private-note-transition-v1-sp1-program \
  apnt-private-note-transition-v1-sp1-program \
  none
run_selector \
  transition-v2 \
  tools/apnt-private-note-transition-v2-sp1 \
  apnt-private-note-transition-v2-sp1-program \
  apnt-private-note-transition-v2-sp1-program \
  apnt-private-note-transition-v2-sp1-program \
  none
run_selector \
  recurrence-v0 \
  tools/apnt-private-note-transition-v2-sp1 \
  apnt-private-note-transition-v2-sp1-program \
  apnt-recurrence-native-private-transition-v0 \
  apnt-recurrence-native-private-transition-v0 \
  --cfg=apnt_recurrence_native_v0
run_selector \
  successor-aggregate-v3 \
  tools/apnt-successor-aggregate-sp1 \
  apnt-successor-aggregate-program \
  apnt-successor-aggregate-program \
  apnt-successor-aggregate-program \
  none
run_selector \
  pool-aggregate-default \
  tools/apnt-pool-aggregate-sp1 \
  apnt-pool-aggregate-program \
  apnt-pool-aggregate-program \
  apnt-pool-aggregate-program \
  none
run_selector \
  pool-aggregate-chipnet-zero-value-rev3 \
  tools/apnt-pool-aggregate-sp1 \
  apnt-pool-aggregate-program-chipnet-zero-value-rev3 \
  apnt-pool-aggregate-program-chipnet-zero-value-rev3 \
  apnt-pool-aggregate-program-chipnet-zero-value-rev3 \
  none \
  program-chipnet-zero-value-rev3
run_selector \
  pool-aggregate-local-zero-value \
  tools/apnt-pool-aggregate-local-sp1 \
  apnt-pool-aggregate-program-local-zero-value \
  apnt-pool-aggregate-program-local-zero-value \
  apnt-pool-aggregate-program-local-zero-value \
  none
# The Chipnet selector never resolves to the default program directory.
rm -rf "$CHECKOUT/tools/apnt-pool-aggregate-sp1/program-chipnet-zero-value-rev3"
if /bin/bash "$BUILDER" "$CHECKOUT" pool-aggregate-chipnet-zero-value-rev3 "$TEST_ROOT/rejected-pool" \
    --selector-control-only > /dev/null 2>&1; then
  echo "canonical builder resolved the Chipnet pool selector without its own program directory" >&2
  exit 1
fi

native_assertion "selector/chipnet/own-program-directory-required"

if /bin/bash "$BUILDER" "$CHECKOUT" recurrence-v0 "$TEST_ROOT/rejected" \
    --not-a-control > /dev/null 2>&1; then
  echo "canonical builder accepted an unknown fourth argument" >&2
  exit 1
fi

native_assertion "selector/unknown-argument-refused"

grep -Fq '"$TRUSTED_CARGO_PROVE" "${BUILD_ARGUMENTS[@]}"' "$BUILDER"
grep -Fq 'INITIAL_HEAD=' "$CHECKER"
grep -Fq 'INITIAL_TREE=' "$CHECKER"
grep -Fq 'FINAL_HEAD=' "$CHECKER"
grep -Fq 'FINAL_TREE=' "$CHECKER"
grep -Fq 'CARGO_TARGET_DIR="$PROBE_TARGET"' "$CHECKER"
grep -Fq 'checkoutRevalidatedAfterBuild: true' "$CHECKER"
grep -Fq 'preservedArtifact: path.basename(elfOutputPath)' "$CHECKER"
grep -Fq '"$TRUSTED_ENV" -i' "$CHECKER"
native_assertion "selector/checker-source-contract"

printf 'canonical guest selector mappings and trusted command control: PASS\n'

native_assertions_done
