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
SOURCE_CHECKER="$(cd "$SCRIPT_DIR/.." && pwd -P)/check-recurrence-native-v0.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/private/tmp}/apnt-recurrence-checker-test.XXXXXX")"
TEST_ROOT="$(cd "$TEST_ROOT" && pwd -P)"
trap 'rm -rf "$TEST_ROOT"' EXIT

REPOSITORY="$TEST_ROOT/repository"
FIXED="$TEST_ROOT/fixed"
TEMP_PARENT="$TEST_ROOT/temp"
OUTPUT_PARENT="$TEST_ROOT/outputs"
CONTROL="$TEST_ROOT/control"
CHECKER="$REPOSITORY/tools/sp1-canonical-guest-build/check-recurrence-native-v0.sh"
NODE="$(command -v node)"
mkdir -p \
  "$REPOSITORY/tools/sp1-canonical-guest-build/vkey-probe" \
  "$FIXED" "$TEMP_PARENT" "$OUTPUT_PARENT" "$CONTROL" \
  "$TEST_ROOT/isolated-home" "$TEST_ROOT/isolated-xdg"

cat > "$FIXED/protoc" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
cat > "$FIXED/go" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
cat > "$FIXED/cargo" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
STUB_ROOT="$(cd "$(dirname "$0")" && pwd -P)"
HOST_TOOLS="${PATH%%:*}"
{
  echo "host-tools=$HOST_TOOLS"
  echo "mode=$(/usr/bin/stat -f '%Lp' "$HOST_TOOLS")"
  echo "protoc=$(/usr/bin/readlink "$HOST_TOOLS/protoc")"
  echo "go=$(/usr/bin/readlink "$HOST_TOOLS/go")"
  for entry in "$HOST_TOOLS"/*; do
    echo "entry=$(/usr/bin/basename "$entry")"
  done
} >> "$STUB_ROOT/invocations.log"

if [ -e "$STUB_ROOT/fail" ]; then
  exit 92
fi
if [ -e "$STUB_ROOT/signal-parent" ]; then
  /bin/kill -TERM "$PPID"
  exit 94
fi

PROBE="$CARGO_TARGET_DIR/release/apnt-sp1-guest-identity-probe"
/bin/mkdir -p "$(/usr/bin/dirname "$PROBE")"
cat > "$PROBE" <<'PROBE'
#!/usr/bin/env bash
set -euo pipefail
recurrence_sha="$(/usr/bin/shasum -a 256 "$2" | /usr/bin/awk '{print $1}')"
recurrence_bytes="$(/usr/bin/wc -c < "$2" | /usr/bin/tr -d ' ')"
printf '{"path":"%s","guest_elf_sha256":"68e662d5991ef94fe6a8e42d7469a048dc4d0374ee04e2c0b641eb372ca590f0","guest_elf_bytes":1213056,"program_vkey_hash":"0063f9299d606362f251d7f5f2febcbe2da90cb7bf86a950df1ca7f1bd193fa8"}\n' "$1"
printf '{"path":"%s","guest_elf_sha256":"%s","guest_elf_bytes":%s,"program_vkey_hash":"1111111111111111111111111111111111111111111111111111111111111111"}\n' "$2" "$recurrence_sha" "$recurrence_bytes"
PROBE
chmod 700 "$PROBE"
STUB
chmod 700 "$FIXED/protoc" "$FIXED/go" "$FIXED/cargo"

cat > "$REPOSITORY/tools/sp1-canonical-guest-build/canonical-guest-build.sh" <<'BUILDER'
#!/usr/bin/env bash
set -euo pipefail
SP1_CANONICAL_IMAGE_DIGEST="sha256:0942a27dbe8e38f4b14f3732e779df4027b17bde93e9fbc9e8c773c15eb63400"
: "${CHECKER_TEST_CONTROL_ROOT:?}"
echo "$2" >> "$CHECKER_TEST_CONTROL_ROOT/builder.log"
/bin/mkdir -p "$3"
case "$2" in
  transition-v2)
    printf 'fixture-v2\n' > "$3/apnt-private-note-transition-v2-sp1-program"
    ;;
  recurrence-v0)
    printf 'fixture-recurrence\n' > "$3/apnt-recurrence-native-private-transition-v0"
    if [ -e "$CHECKER_TEST_CONTROL_ROOT/stage-claude" ]; then
      /usr/bin/git -C "$1" add -f CLAUDE.md
    fi
    ;;
  *) exit 93 ;;
esac
BUILDER
chmod 700 "$REPOSITORY/tools/sp1-canonical-guest-build/canonical-guest-build.sh"
: > "$REPOSITORY/tools/sp1-canonical-guest-build/vkey-probe/Cargo.toml"

/usr/bin/sed \
  -e "s|^TRUSTED_CARGO=.*|TRUSTED_CARGO=\"$FIXED/cargo\"|" \
  -e "s|^TRUSTED_NODE=.*|TRUSTED_NODE=\"$NODE\"|" \
  -e "s|^TRUSTED_PROTOC=.*|TRUSTED_PROTOC=\"$FIXED/protoc\"|" \
  -e "s|^TRUSTED_GO=.*|TRUSTED_GO=\"$FIXED/go\"|" \
  -e 's|^TRUSTED_PATH=.*|TRUSTED_PATH="/usr/bin:/bin"|' \
  "$SOURCE_CHECKER" > "$CHECKER"
chmod 700 "$CHECKER"

/usr/bin/git -C "$REPOSITORY" init -q -b main
/usr/bin/git -C "$REPOSITORY" config user.name fixture
/usr/bin/git -C "$REPOSITORY" config user.email fixture@example.invalid
/usr/bin/git -C "$REPOSITORY" add tools
/usr/bin/git -C "$REPOSITORY" commit -q -m fixture

assert_no_setup_artifacts() {
  if find "$TEMP_PARENT" -maxdepth 1 \
      \( -name 'apnt-recurrence-checker-host-tools.*' \
      -o -name 'apnt-recurrence-identity.*' \) \
      -print -quit | grep -q .; then
    echo "recurrence checker retained a temporary setup directory" >&2
    exit 1
  fi
}

run_checker() {
  local output="$1"
  shift
  TMPDIR="$TEMP_PARENT" CHECKER_TEST_CONTROL_ROOT="$CONTROL" "$@" \
    "$CHECKER" "$REPOSITORY" "$OUTPUT_PARENT/$output"
}

: > "$CONTROL/builder.log"
run_checker success env > "$TEST_ROOT/success.stdout"
[ "$(sed -n '$=' "$CONTROL/builder.log")" -eq 2 ]
[ -f "$OUTPUT_PARENT/success/recurrence-native-canonical-guest-identity-v0.json" ]
[ -f "$OUTPUT_PARENT/success/apnt-recurrence-native-private-transition-v0.canonical.elf" ]
grep -Fqx 'mode=700' "$FIXED/invocations.log"
grep -Fqx "protoc=$FIXED/protoc" "$FIXED/invocations.log"
grep -Fqx "go=$FIXED/go" "$FIXED/invocations.log"
[ "$(grep -c '^entry=' "$FIXED/invocations.log")" -eq 2 ]
assert_no_setup_artifacts
native_assertion "recurrence/private-tools-artifacts-and-cleanup"

mv "$FIXED/go" "$FIXED/go.missing"
: > "$CONTROL/builder.log"
if run_checker missing-tool env \
    > "$TEST_ROOT/missing.stdout" 2> "$TEST_ROOT/missing.stderr"; then
  echo "recurrence checker accepted a missing fixed host prerequisite" >&2
  exit 1
fi
grep -Fq 'canonical identity tooling is unavailable' "$TEST_ROOT/missing.stderr"
[ ! -s "$CONTROL/builder.log" ]
assert_no_setup_artifacts
native_assertion "recurrence/missing-tool-refused-before-build"
mv "$FIXED/go.missing" "$FIXED/go"

touch "$FIXED/fail"
: > "$CONTROL/builder.log"
if run_checker cargo-failure env \
    > "$TEST_ROOT/cargo-failure.stdout" 2> "$TEST_ROOT/cargo-failure.stderr"; then
  echo "recurrence checker accepted a failed VKey-probe build" >&2
  exit 1
fi
[ "$(sed -n '$=' "$CONTROL/builder.log")" -eq 2 ]
assert_no_setup_artifacts
native_assertion "recurrence/probe-build-failure-cleans"
rm "$FIXED/fail"

touch "$FIXED/signal-parent"
: > "$CONTROL/builder.log"
if run_checker cargo-interrupted env \
    > "$TEST_ROOT/cargo-interrupted.stdout" \
    2> "$TEST_ROOT/cargo-interrupted.stderr"; then
  echo "recurrence checker survived an interrupted VKey-probe build" >&2
  exit 1
fi
[ "$(sed -n '$=' "$CONTROL/builder.log")" -eq 2 ]
assert_no_setup_artifacts
native_assertion "recurrence/probe-interruption-cleans"
rm "$FIXED/signal-parent"

printf 'CLAUDE.md\n' > "$TEST_ROOT/global-ignore"
cat > "$TEST_ROOT/global.gitconfig" <<CONFIG
[core]
  excludesfile = $TEST_ROOT/global-ignore
CONFIG
printf 'must-not-enter-identity\n' > "$REPOSITORY/CLAUDE.md"
CLAUDE_BEFORE="$(/usr/bin/shasum -a 256 "$REPOSITORY/CLAUDE.md")"
: > "$CONTROL/builder.log"
run_checker ignored-claude env \
  HOME="$TEST_ROOT/isolated-home" \
  XDG_CONFIG_HOME="$TEST_ROOT/isolated-xdg" \
  GIT_CONFIG_GLOBAL="$TEST_ROOT/global.gitconfig" \
  > "$TEST_ROOT/ignored-claude.stdout"
[ "$CLAUDE_BEFORE" = "$(/usr/bin/shasum -a 256 "$REPOSITORY/CLAUDE.md")" ]
[ "$(sed -n '$=' "$CONTROL/builder.log")" -eq 2 ]
assert_no_setup_artifacts
native_assertion "recurrence/exact-ignored-file-preserved"

: > "$CONTROL/builder.log"
if run_checker unignored-claude env \
    HOME="$TEST_ROOT/isolated-home" \
    XDG_CONFIG_HOME="$TEST_ROOT/isolated-xdg" \
    GIT_CONFIG_GLOBAL=/dev/null \
    > "$TEST_ROOT/unignored.stdout" 2> "$TEST_ROOT/unignored.stderr"; then
  echo "recurrence checker accepted an unignored checkout-root CLAUDE.md" >&2
  exit 1
fi
grep -Fq 'checkout-root CLAUDE.md is not already ignored' \
  "$TEST_ROOT/unignored.stderr"
[ ! -s "$CONTROL/builder.log" ]
assert_no_setup_artifacts
native_assertion "recurrence/unignored-file-refused"

rm "$REPOSITORY/CLAUDE.md"
ln -s "$TEST_ROOT/global-ignore" "$REPOSITORY/CLAUDE.md"
: > "$CONTROL/builder.log"
if run_checker symlink-claude env \
    HOME="$TEST_ROOT/isolated-home" \
    XDG_CONFIG_HOME="$TEST_ROOT/isolated-xdg" \
    GIT_CONFIG_GLOBAL="$TEST_ROOT/global.gitconfig" \
    > "$TEST_ROOT/symlink.stdout" 2> "$TEST_ROOT/symlink.stderr"; then
  echo "recurrence checker accepted a symlink at checkout-root CLAUDE.md" >&2
  exit 1
fi
grep -Fq 'checkout-root CLAUDE.md is not one exact regular file' \
  "$TEST_ROOT/symlink.stderr"
[ ! -s "$CONTROL/builder.log" ]
assert_no_setup_artifacts
native_assertion "recurrence/symlink-refused"
rm "$REPOSITORY/CLAUDE.md"
printf 'must-not-enter-identity\n' > "$REPOSITORY/CLAUDE.md"

printf 'unexpected\n' > "$REPOSITORY/unexpected.txt"
: > "$CONTROL/builder.log"
if run_checker unexpected-dirty env \
    HOME="$TEST_ROOT/isolated-home" \
    XDG_CONFIG_HOME="$TEST_ROOT/isolated-xdg" \
    GIT_CONFIG_GLOBAL="$TEST_ROOT/global.gitconfig" \
    > "$TEST_ROOT/unexpected.stdout" 2> "$TEST_ROOT/unexpected.stderr"; then
  echo "recurrence checker accepted another dirty checkout path" >&2
  exit 1
fi
grep -Fq 'checker requires one exact clean canonical main checkout' \
  "$TEST_ROOT/unexpected.stderr"
[ ! -s "$CONTROL/builder.log" ]
assert_no_setup_artifacts
native_assertion "recurrence/other-dirty-path-refused"

rm "$REPOSITORY/unexpected.txt"
touch "$CONTROL/stage-claude"
: > "$CONTROL/builder.log"
if run_checker claude-status-changed env \
    HOME="$TEST_ROOT/isolated-home" \
    XDG_CONFIG_HOME="$TEST_ROOT/isolated-xdg" \
    GIT_CONFIG_GLOBAL="$TEST_ROOT/global.gitconfig" \
    > "$TEST_ROOT/claude-status-changed.stdout" \
    2> "$TEST_ROOT/claude-status-changed.stderr"; then
  echo "recurrence checker missed a staged ignored-root path" >&2
  exit 1
fi
grep -Fq 'canonical main identity or cleanliness changed during guest derivation' \
  "$TEST_ROOT/claude-status-changed.stderr"
[ "$(sed -n '$=' "$CONTROL/builder.log")" -eq 2 ]
assert_no_setup_artifacts
native_assertion "recurrence/midbuild-status-change-refused"

printf 'recurrence checker restrictive setup and ignored-root control: PASS\n'

native_assertions_done
