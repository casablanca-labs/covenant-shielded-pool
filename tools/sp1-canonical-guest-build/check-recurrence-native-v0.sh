#!/usr/bin/env bash
# Build the frozen Relation V2 control and additive recurrence guest from one
# clean canonical main checkout, then derive setup-only public identities and
# preserve the exact canonical recurrence ELF. This script never constructs a
# proof.
set -euo pipefail

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

TRUSTED_ENV="/usr/bin/env"
TRUSTED_GIT="/usr/bin/git"
TRUSTED_CARGO="${TRUSTED_HOME}/.cargo/bin/cargo"
TRUSTED_NODE="${TRUSTED_HOME}/.nvm/versions/node/v20.19.4/bin/node"
TRUSTED_PROTOC="/opt/homebrew/bin/protoc"
TRUSTED_GO="/opt/homebrew/bin/go"
TRUSTED_PATH="${TRUSTED_HOME}/.sp1/bin:${TRUSTED_HOME}/.cargo/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
ALLOW_IGNORED_ROOT_CLAUDE=false
CHECKER_HOST_TOOLS_DIR=""
CHECKER_HOST_TOOLS_PARENT=""

usage() {
  echo "usage: $0 <clean-canonical-main-checkout> <fresh-identity-output-directory>" >&2
  exit 2
}

trusted_git() {
  local checkout="$1"
  shift
  "$TRUSTED_ENV" -i PATH="/usr/bin:/bin" LC_ALL=C LANG=C \
    TMPDIR="${TMPDIR:-/private/tmp}" \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 \
    "$TRUSTED_GIT" --no-replace-objects -C "$checkout" "$@"
}

operator_ignores_root_claude() {
  "$TRUSTED_GIT" -C "$1" check-ignore --quiet -- CLAUDE.md
}

root_claude_is_allowable() {
  [ -f "$1/CLAUDE.md" ] && [ ! -L "$1/CLAUDE.md" ] \
    && operator_ignores_root_claude "$1"
}

trusted_status() {
  local checkout="$1"
  if [ "$ALLOW_IGNORED_ROOT_CLAUDE" = true ]; then
    if ! root_claude_is_allowable "$checkout"; then
      printf 'checkout-root CLAUDE.md lost its ignored-untracked status\n'
      return 0
    fi
    trusted_git "$checkout" status --porcelain=v1 --untracked-files=all \
      -- . ':(top,exclude)CLAUDE.md'
  else
    trusted_git "$checkout" status --porcelain=v1 --untracked-files=all
  fi
}

cleanup_checker_host_tools() {
  if [ -n "$CHECKER_HOST_TOOLS_DIR" ]; then
    case "$CHECKER_HOST_TOOLS_DIR" in
      "$CHECKER_HOST_TOOLS_PARENT"/apnt-recurrence-checker-host-tools.*)
        /bin/rm -rf -- "$CHECKER_HOST_TOOLS_DIR"
        ;;
      *)
        echo "refusing to remove unexpected recurrence checker host-tool path" >&2
        ;;
    esac
    CHECKER_HOST_TOOLS_DIR=""
  fi
}

prepare_checker_host_tools() {
  CHECKER_HOST_TOOLS_PARENT="$(cd "${TMPDIR:-/private/tmp}" && pwd -P)"
  CHECKER_HOST_TOOLS_DIR="$(/usr/bin/mktemp -d \
    "$CHECKER_HOST_TOOLS_PARENT/apnt-recurrence-checker-host-tools.XXXXXX")"
  CHECKER_HOST_TOOLS_DIR="$(cd "$CHECKER_HOST_TOOLS_DIR" && pwd -P)"
  /bin/chmod 700 "$CHECKER_HOST_TOOLS_DIR"
  /bin/ln -s "$TRUSTED_PROTOC" "$CHECKER_HOST_TOOLS_DIR/protoc"
  /bin/ln -s "$TRUSTED_GO" "$CHECKER_HOST_TOOLS_DIR/go"
}

[ "$#" -eq 2 ] || usage
CHECKOUT_ROOT="$(cd "$1" && pwd -P)"
OUTPUT_PARENT="$(cd "$(/usr/bin/dirname "$2")" && pwd -P)"
OUTPUT_BASENAME="$(/usr/bin/basename "$2")"
[ -n "$OUTPUT_BASENAME" ] && [ "$OUTPUT_BASENAME" != "." ] \
  && [ "$OUTPUT_BASENAME" != ".." ] || usage
OUTPUT_DIR="$OUTPUT_PARENT/$OUTPUT_BASENAME"

if [ -e "$CHECKOUT_ROOT/CLAUDE.md" ] || [ -L "$CHECKOUT_ROOT/CLAUDE.md" ]; then
  if [ ! -f "$CHECKOUT_ROOT/CLAUDE.md" ] \
      || [ -L "$CHECKOUT_ROOT/CLAUDE.md" ]; then
    echo "checkout-root CLAUDE.md is not one exact regular file" >&2
    exit 1
  elif operator_ignores_root_claude "$CHECKOUT_ROOT"; then
    ALLOW_IGNORED_ROOT_CLAUDE=true
  else
    echo "checkout-root CLAUDE.md is not already ignored" >&2
    exit 1
  fi
fi

if [ -e "$OUTPUT_DIR" ] || [ -L "$OUTPUT_DIR" ]; then
  echo "identity output directory already exists" >&2
  exit 1
fi
case "$OUTPUT_DIR" in
  "$CHECKOUT_ROOT"|"$CHECKOUT_ROOT"/*)
    echo "identity output directory must be outside the canonical checkout" >&2
    exit 1
    ;;
esac
if trusted_git "$OUTPUT_PARENT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "identity output directory must be outside every Git worktree" >&2
  exit 1
fi

REPOSITORY_ROOT="$(trusted_git "$CHECKOUT_ROOT" rev-parse --show-toplevel)"
REPOSITORY_ROOT="$(cd "$REPOSITORY_ROOT" && pwd -P)"
INITIAL_HEAD="$(trusted_git "$CHECKOUT_ROOT" rev-parse HEAD)"
INITIAL_TREE="$(trusted_git "$CHECKOUT_ROOT" rev-parse 'HEAD^{tree}')"
INITIAL_BRANCH="$(trusted_git "$CHECKOUT_ROOT" symbolic-ref --quiet --short HEAD)"
INITIAL_MAIN_HEAD="$(trusted_git "$CHECKOUT_ROOT" rev-parse refs/heads/main)"
INITIAL_STATUS="$(trusted_status "$CHECKOUT_ROOT")"
if [ "$REPOSITORY_ROOT" != "$CHECKOUT_ROOT" ] \
  || [ "$INITIAL_BRANCH" != "main" ] \
  || [ "$INITIAL_HEAD" != "$INITIAL_MAIN_HEAD" ] \
  || [ -n "$INITIAL_STATUS" ]; then
  echo "checker requires one exact clean canonical main checkout" >&2
  exit 1
fi

BUILDER="$CHECKOUT_ROOT/tools/sp1-canonical-guest-build/canonical-guest-build.sh"
PROBE_MANIFEST="$CHECKOUT_ROOT/tools/sp1-canonical-guest-build/vkey-probe/Cargo.toml"
[ -f "$BUILDER" ] && [ ! -L "$BUILDER" ] && [ -x "$BUILDER" ] \
  && [ -f "$PROBE_MANIFEST" ] && [ ! -L "$PROBE_MANIFEST" ] \
  && [ -x "$TRUSTED_ENV" ] && [ -x "$TRUSTED_GIT" ] \
  && [ -x "$TRUSTED_CARGO" ] && [ -x "$TRUSTED_NODE" ] \
  && [ -x "$TRUSTED_PROTOC" ] && [ -x "$TRUSTED_GO" ] || {
    echo "canonical identity tooling is unavailable" >&2
    exit 1
  }

IMAGE_DIGEST="sha256:0942a27dbe8e38f4b14f3732e779df4027b17bde93e9fbc9e8c773c15eb63400"
/usr/bin/grep -Fqx "SP1_CANONICAL_IMAGE_DIGEST=\"$IMAGE_DIGEST\"" "$BUILDER" || {
  echo "canonical builder image identity changed" >&2
  exit 1
}

umask 077
/bin/mkdir "$OUTPUT_DIR"
/bin/chmod 700 "$OUTPUT_DIR"
BUILD_PARENT="$(cd "${TMPDIR:-/private/tmp}" && pwd -P)"
BUILD_ROOT="$(/usr/bin/mktemp -d "$BUILD_PARENT/apnt-recurrence-identity.XXXXXX")"
BUILD_ROOT="$(cd "$BUILD_ROOT" && pwd -P)"
cleanup() {
  cleanup_checker_host_tools
  case "$BUILD_ROOT" in
    "$BUILD_PARENT"/apnt-recurrence-identity.*) /bin/rm -rf -- "$BUILD_ROOT" ;;
  esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

V2_BUILD="$BUILD_ROOT/transition-v2"
RECURRENCE_BUILD="$BUILD_ROOT/recurrence-v0"
PROBE_TARGET="$BUILD_ROOT/vkey-probe-target"
/bin/mkdir "$V2_BUILD" "$RECURRENCE_BUILD" "$PROBE_TARGET"
"$BUILDER" "$CHECKOUT_ROOT" transition-v2 "$V2_BUILD"
"$BUILDER" "$CHECKOUT_ROOT" recurrence-v0 "$RECURRENCE_BUILD"

prepare_checker_host_tools
"$TRUSTED_ENV" -i \
  HOME="${TRUSTED_HOME}" \
  CARGO_HOME="${TRUSTED_HOME}/.cargo" \
  RUSTUP_HOME="${TRUSTED_HOME}/.rustup" \
  SP1_HOME="${TRUSTED_HOME}/.sp1" \
  CARGO_TARGET_DIR="$PROBE_TARGET" \
  PATH="$CHECKER_HOST_TOOLS_DIR:$TRUSTED_PATH" \
  LC_ALL=C \
  "$TRUSTED_CARGO" build --release --locked --manifest-path "$PROBE_MANIFEST"
cleanup_checker_host_tools
PROBE="$PROBE_TARGET/release/apnt-sp1-guest-identity-probe"
[ -f "$PROBE" ] && [ ! -L "$PROBE" ] && [ -x "$PROBE" ] || {
  echo "setup-only VKey probe is unavailable" >&2
  exit 1
}

V2_ELF="$V2_BUILD/apnt-private-note-transition-v2-sp1-program"
RECURRENCE_ELF="$RECURRENCE_BUILD/apnt-recurrence-native-private-transition-v0"
[ -f "$V2_ELF" ] && [ ! -L "$V2_ELF" ] \
  && [ -f "$RECURRENCE_ELF" ] && [ ! -L "$RECURRENCE_ELF" ] || {
    echo "canonical guest build did not return regular ELF files" >&2
    exit 1
  }

IDENTITIES="$BUILD_ROOT/identities.ndjson"
"$TRUSTED_ENV" -i \
  HOME="${TRUSTED_HOME}" \
  SP1_HOME="${TRUSTED_HOME}/.sp1" \
  PATH="$TRUSTED_PATH" \
  LC_ALL=C \
  "$PROBE" "$V2_ELF" "$RECURRENCE_ELF" > "$IDENTITIES"

FINAL_HEAD="$(trusted_git "$CHECKOUT_ROOT" rev-parse HEAD)"
FINAL_TREE="$(trusted_git "$CHECKOUT_ROOT" rev-parse 'HEAD^{tree}')"
FINAL_BRANCH="$(trusted_git "$CHECKOUT_ROOT" symbolic-ref --quiet --short HEAD)"
FINAL_MAIN_HEAD="$(trusted_git "$CHECKOUT_ROOT" rev-parse refs/heads/main)"
FINAL_STATUS="$(trusted_status "$CHECKOUT_ROOT")"
if [ "$FINAL_HEAD" != "$INITIAL_HEAD" ] \
  || [ "$FINAL_TREE" != "$INITIAL_TREE" ] \
  || [ "$FINAL_BRANCH" != "$INITIAL_BRANCH" ] \
  || [ "$FINAL_MAIN_HEAD" != "$INITIAL_MAIN_HEAD" ] \
  || [ -n "$FINAL_STATUS" ]; then
  echo "canonical main identity or cleanliness changed during guest derivation" >&2
  exit 1
fi

BUILDER_SHA256="$(/usr/bin/shasum -a 256 "$BUILDER" | /usr/bin/awk '{print $1}')"
IDENTITY_OUTPUT="$OUTPUT_DIR/recurrence-native-canonical-guest-identity-v0.json"
ELF_OUTPUT="$OUTPUT_DIR/apnt-recurrence-native-private-transition-v0.canonical.elf"

"$TRUSTED_ENV" -i PATH="/usr/bin:/bin" LC_ALL=C \
  "$TRUSTED_NODE" - "$IDENTITIES" "$IDENTITY_OUTPUT" "$RECURRENCE_ELF" \
  "$ELF_OUTPUT" "$INITIAL_HEAD" "$INITIAL_TREE" "$BUILDER_SHA256" \
  "$IMAGE_DIGEST" <<'NODE'
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const [identitiesPath, outputPath, recurrenceElfPath, elfOutputPath, head, tree,
  builderSha256, imageDigest] = process.argv.slice(2);
const lines = fs.readFileSync(identitiesPath, "utf8").trim().split("\n");
if (lines.length !== 2) throw new Error("expected exactly two canonical guest identities");
const [relationV2, recurrence] = lines.map((line) => JSON.parse(line));
const hex32 = /^[0-9a-f]{64}$/u;
for (const identity of [relationV2, recurrence]) {
  if (!hex32.test(identity.guest_elf_sha256)
      || !Number.isSafeInteger(identity.guest_elf_bytes)
      || identity.guest_elf_bytes <= 0
      || !hex32.test(identity.program_vkey_hash)) {
    throw new Error("canonical guest probe returned an invalid public identity");
  }
}
if (path.basename(relationV2.path) !== "apnt-private-note-transition-v2-sp1-program"
    || path.basename(recurrence.path)
      !== "apnt-recurrence-native-private-transition-v0") {
  throw new Error("canonical selector output names changed");
}
const frozen = {
  guest_elf_sha256: "68e662d5991ef94fe6a8e42d7469a048dc4d0374ee04e2c0b641eb372ca590f0",
  guest_elf_bytes: 1213056,
  program_vkey_hash: "0063f9299d606362f251d7f5f2febcbe2da90cb7bf86a950df1ca7f1bd193fa8",
};
for (const [field, expected] of Object.entries(frozen)) {
  if (relationV2[field] !== expected) {
    throw new Error("BLOCKED: RECURRENCE-SHARED-LIB-MOVES-RELATION-V2-GUEST");
  }
}

const recurrenceElfMetadata = fs.lstatSync(recurrenceElfPath);
const recurrenceElf = fs.readFileSync(recurrenceElfPath);
const recurrenceElfSha256 = crypto.createHash("sha256").update(recurrenceElf).digest("hex");
if (recurrenceElfMetadata.isSymbolicLink() || !recurrenceElfMetadata.isFile()
    || recurrenceElf.length !== recurrence.guest_elf_bytes
    || recurrenceElfSha256 !== recurrence.guest_elf_sha256) {
  throw new Error("canonical recurrence ELF changed after setup-only identity derivation");
}
fs.copyFileSync(recurrenceElfPath, elfOutputPath, fs.constants.COPYFILE_EXCL);
fs.chmodSync(elfOutputPath, 0o600);

const evidence = {
  version: 0,
  codec: "APNTRCI0",
  classification: "public-safe canonical recurrence guest identity candidate",
  canonicalMainHead: head,
  canonicalMainTree: tree,
  checkoutRevalidatedAfterBuild: true,
  builder: {
    path: "tools/sp1-canonical-guest-build/canonical-guest-build.sh",
    sha256: builderSha256,
    imageDigest,
    lockedDependencies: true,
    repositoryRootWorkspaceDirectory: true,
    explicitBinarySelection: true,
    trustedAbsoluteExecutables: true,
    allowlistedEnvironment: true,
  },
  relationV2FrozenControl: {
    selector: "transition-v2",
    package: "apnt-private-note-transition-v2-sp1-program",
    binary: "apnt-private-note-transition-v2-sp1-program",
    guestElfSha256: relationV2.guest_elf_sha256,
    guestElfBytes: relationV2.guest_elf_bytes,
    programVkeyHash: relationV2.program_vkey_hash,
    matchedFrozenIdentity: true,
  },
  recurrenceNativeCandidate: {
    selector: "recurrence-v0",
    package: "apnt-private-note-transition-v2-sp1-program",
    binary: "apnt-recurrence-native-private-transition-v0",
    guestElfSha256: recurrence.guest_elf_sha256,
    guestElfBytes: recurrence.guest_elf_bytes,
    programVkeyHash: recurrence.program_vkey_hash,
    preservedArtifact: path.basename(elfOutputPath),
  },
  setupOnly: true,
  proofConstructed: false,
  proofVerified: false,
  cashVmExecuted: false,
  chainIncluded: false,
  walletAccepted: false,
  walletSpendable: false,
  privacyClaimed: false,
  anonymityClaimed: false,
  economicViabilityClaimed: false,
};
fs.writeFileSync(outputPath, `${JSON.stringify(evidence, null, 2)}\n`, {
  flag: "wx",
  mode: 0o600,
});
NODE

/bin/chmod 600 "$IDENTITY_OUTPUT" "$ELF_OUTPUT"
echo "recurrence-native canonical guest identity control: PASS"
echo "identity record: $IDENTITY_OUTPUT"
echo "canonical recurrence ELF: $ELF_OUTPUT"
