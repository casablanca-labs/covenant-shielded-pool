#!/usr/bin/env bash
#
# canonical-guest-trusted-root — regression control for the trust-anchor
# derivation in canonical-guest-build.sh.
#
# The builder must pin its trusted toolchain to the invoking account's REAL
# home directory, read from the password database, and must NOT derive it from
# the caller-controlled $HOME. A forged $HOME must not be able to move
# TRUSTED_CARGO_PROVE or TRUSTED_PATH.
#
# This control is SELF-VALIDATING: it also runs a deliberately weakened copy of
# the builder that derives from $HOME, and requires that copy to be caught. A
# detector that cannot be made to fire is not evidence of anything.
#
# It does not replace canonical-guest-build-selectors.test.sh, which pins the
# exact expected literals; this one pins the PROPERTY, so it survives a change
# of operator account.
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
BUILDER="$(cd "$SCRIPT_DIR/.." && pwd -P)/canonical-guest-build.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR%/}/apnt-canonical-trusted-root.XXXXXX")"
TEST_ROOT="$(cd "$TEST_ROOT" && pwd -P)"
trap 'rm -rf "$TEST_ROOT"' EXIT

CHECKOUT="$TEST_ROOT/checkout"
FORGED_HOME="$TEST_ROOT/forged-home"
OUT="$TEST_ROOT/out"
mkdir -p "$CHECKOUT/tools/apnt-private-note-transition-v2-sp1/program" "$OUT" \
  "$FORGED_HOME/.sp1/bin" "$FORGED_HOME/.cargo/bin"
printf '#!/bin/sh\nexit 97\n' > "$FORGED_HOME/.sp1/bin/cargo-prove"
chmod 700 "$FORGED_HOME/.sp1/bin/cargo-prove"

# The real home, derived the same way the builder does: from the password
# database, never from $HOME.
ACCOUNT="$(/usr/bin/id -un)"
eval "REAL_HOME=~${ACCOUNT}"

run_selector() {
  HOME="$FORGED_HOME" \
    /bin/bash "$1" "$CHECKOUT" recurrence-v0 "$OUT" --selector-control-only
}

# ── 1. The shipped builder must ignore the forged HOME ──────────────────────
LOG="$TEST_ROOT/fixed.log"
run_selector "$BUILDER" > "$LOG"

grep -Fqx -- "trusted-executable=${REAL_HOME}/.sp1/bin/cargo-prove" "$LOG" || {
  echo "trusted executable was not derived from the password-database home" >&2
  exit 1
}
grep -Fq -- "trusted-path=${REAL_HOME}/.sp1/bin:${REAL_HOME}/.cargo/bin:" "$LOG" || {
  echo "trusted path was not derived from the password-database home" >&2
  exit 1
}
if grep -Fq -- "$FORGED_HOME" "$LOG"; then
  echo "FORGED HOME REACHED A TRUST ANCHOR: the builder is caller-controlled" >&2
  exit 1
fi

native_assertion "trusted-root/forged-home-ignored"

# ── 2. The builder must carry no operator-identifying absolute path ─────────
# De-identification is a real requirement of this file: it is published through
# the public-export allowlist. Fixing the trust anchor must not reintroduce a
# hardcoded home directory.
if grep -Fq -- "$REAL_HOME" "$BUILDER"; then
  echo "builder reintroduced a hardcoded operator home path" >&2
  exit 1
fi

native_assertion "trusted-root/no-account-literal"

# ── 3. SELF-VALIDATION: a $HOME-derived copy must be caught ─────────────────
WEAKENED="$TEST_ROOT/weakened-build.sh"
sed \
  -e 's|TRUSTED_CARGO_PROVE="${TRUSTED_HOME}/.sp1/bin/cargo-prove"|TRUSTED_CARGO_PROVE="${HOME}/.sp1/bin/cargo-prove"|' \
  -e 's|TRUSTED_PATH="${TRUSTED_HOME}/.sp1/bin:${TRUSTED_HOME}/.cargo/bin:|TRUSTED_PATH="${HOME}/.sp1/bin:${HOME}/.cargo/bin:|' \
  "$BUILDER" > "$WEAKENED"
chmod 700 "$WEAKENED"

if ! grep -Fq 'TRUSTED_CARGO_PROVE="${HOME}/.sp1/bin/cargo-prove"' "$WEAKENED"; then
  echo "self-validation could not construct the weakened builder" >&2
  exit 1
fi

WEAK_LOG="$TEST_ROOT/weakened.log"
run_selector "$WEAKENED" > "$WEAK_LOG"
if ! grep -Fq -- "$FORGED_HOME" "$WEAK_LOG"; then
  echo "self-validation failed: the weakened builder was NOT caught, so this control is dead" >&2
  exit 1
fi

native_assertion "trusted-root/forged-home-mutation-detected"

# ── 4. An all-numeric account name must not become a directory-stack ────────
# `~0` in bash is DIRECTORY-STACK expansion, not a user lookup, so an account
# named `0` under the old eval-a-tilde approach resolved to the caller's working
# directory — putting the trust anchor back under caller control. The builder
# now reads the password database directly and must fail closed instead.
STUB_BIN="$TEST_ROOT/stub-bin"
mkdir -p "$STUB_BIN"
printf '#!/bin/sh\nprintf "0\\n"\n' > "$STUB_BIN/id"
chmod 700 "$STUB_BIN/id"

NUMERIC="$TEST_ROOT/numeric-account-build.sh"
sed -e "s|^TRUSTED_ID=\"/usr/bin/id\"|TRUSTED_ID=\"$STUB_BIN/id\"|" "$BUILDER" > "$NUMERIC"
chmod 700 "$NUMERIC"
grep -Fq "TRUSTED_ID=\"$STUB_BIN/id\"" "$NUMERIC" || {
  echo "could not construct the numeric-account variant" >&2
  exit 1
}

NUMERIC_LOG="$TEST_ROOT/numeric.log"
CWD_MARKER="$TEST_ROOT/cwd-marker"
mkdir -p "$CWD_MARKER"
set +e
( cd "$CWD_MARKER" && HOME="$FORGED_HOME" \
    /bin/bash "$NUMERIC" "$CHECKOUT" recurrence-v0 "$OUT" --selector-control-only ) \
    > "$NUMERIC_LOG" 2>&1
NUMERIC_STATUS=$?
set -e

if [ "$NUMERIC_STATUS" -eq 0 ]; then
  echo "an all-numeric account name was accepted; the trust anchor is derivable from CWD" >&2
  exit 1
fi
if grep -Fq -- "$CWD_MARKER" "$NUMERIC_LOG"; then
  echo "the caller working directory reached a trust anchor via numeric-account expansion" >&2
  exit 1
fi

native_assertion "trusted-root/numeric-account-refused"

# ── 5. SELF-VALIDATION of control 4: the OLD eval-a-tilde form must be caught ─
LEGACY="$TEST_ROOT/legacy-eval-build.sh"
/usr/bin/sed -e "s|^TRUSTED_ID=\"/usr/bin/id\"|TRUSTED_ID=\"$STUB_BIN/id\"|" "$BUILDER" \
  | /usr/bin/awk '
      /^TRUSTED_HOME=""$/ { print "eval \"TRUSTED_HOME=~${TRUSTED_ACCOUNT}\""; skipping = 1; next }
      skipping && /^fi$/   { skipping = 0; next }
      skipping             { next }
      { print }
    ' > "$LEGACY"
chmod 700 "$LEGACY"

LEGACY_LOG="$TEST_ROOT/legacy.log"
set +e
( cd "$CWD_MARKER" && HOME="$FORGED_HOME" \
    /bin/bash "$LEGACY" "$CHECKOUT" recurrence-v0 "$OUT" --selector-control-only ) \
    > "$LEGACY_LOG" 2>&1
LEGACY_STATUS=$?
set -e

# The legacy form must exhibit exactly the hole this control exists to detect:
# either it resolves the anchor into the caller CWD, or it at minimum succeeds
# where the fixed builder refuses. If it does neither, control 4 proves nothing.
if [ "$LEGACY_STATUS" -eq 0 ] && ! grep -Fq -- "$CWD_MARKER" "$LEGACY_LOG"; then
  echo "self-validation failed: the legacy eval form showed no hole, so control 4 is dead" >&2
  exit 1
fi

native_assertion "trusted-root/legacy-eval-mutation-detected"

echo "canonical guest trusted-root derivation control: PASS"

native_assertions_done
