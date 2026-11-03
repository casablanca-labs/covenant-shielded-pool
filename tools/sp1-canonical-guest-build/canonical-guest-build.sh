#!/usr/bin/env bash
#
# canonical-guest-build.sh — the ONE sanctioned way to build a pinnable SP1
# guest ELF for this repository.
#
# WHY THIS EXISTS
# ---------------
# A guest ELF built the ordinary way is a function of the absolute path of the
# checkout it was built in. Two separate mechanisms cause that, and both are
# measured, not assumed (see README.md for the experiment and its controls):
#
#   1. Cargo's `-Cmetadata` (the crate disambiguator). Cargo normally strips the
#      workspace prefix from a path dependency so the hash is relocatable. When
#      the dependency lies OUTSIDE the Cargo workspace root that `strip_prefix`
#      fails and Cargo falls back to hashing the ABSOLUTE path. The SP1
#      workspaces here are rooted at `tools/…-sp1` while their parity crates are
#      sibling directories at `tools/…-rust-parity` — outside the root. So every
#      disambiguator, and transitively every downstream crate's disambiguator,
#      moves when the checkout moves.
#
#   2. Literal path strings in the ELF. The guest ELFs carry the absolute source
#      paths of the out-of-workspace parity crates (panic-location strings), plus
#      absolute `~/.cargo/registry` and `~/.sp1/toolchains` paths. Those strings
#      change LENGTH with the path, which is why byte length moves too.
#
# `--remap-path-prefix` fixes NEITHER. It cannot rewrite a `-Cmetadata` value
# Cargo already computed (measured: identical metadata with and without it), and
# it never reaches the build anyway because `sp1-build` SETS rather than appends
# `CARGO_ENCODED_RUSTFLAGS`, so ambient `RUSTFLAGS` is discarded.
#
# WHAT THIS DOES INSTEAD
# ----------------------
# It builds inside a digest-pinned container where the checkout is bind-mounted
# at a FIXED path, `/root/program`. Every absolute path that feeds either
# mechanism — the workspace root, the out-of-workspace parity crates, the cargo
# registry, the toolchain — becomes the same string no matter where the host
# checkout lives. The host path stops being an input.
#
# The `--workspace-directory` must be the REPO ROOT, not the SP1 workspace root.
# `sp1-build` mounts exactly that one directory; pointing it at `tools/…-sp1`
# would leave the sibling parity crates outside the mount and the build would
# fail to resolve them.
#
# WHAT WOULD BREAK IT
# -------------------
#   * Changing SP1_CANONICAL_IMAGE_DIGEST. The image carries the rustc that
#     compiles the guest; a different image is a different program.
#   * Passing a different --workspace-directory, or moving any selected SP1
#     workspace or parity crate to a different depth under the repo root. The
#     in-container path is derived from the path relative to the repo root, so
#     the RELATIVE layout is now load-bearing even though the absolute one is
#     not.
#   * Dropping `--locked`, which would let dependency resolution drift.
#   * Activating a Cargo feature. Cargo mixes enabled features into the same
#     `-Cmetadata` hash, so a feature change moves every disambiguator.
#   * Renaming the repo-root directory itself does NOT break it — that is the
#     whole point — but renaming `tools/…` does.
#
# USAGE
#   canonical-guest-build.sh <checkout-root> <guest-key> <output-dir>
#   canonical-guest-build.sh <checkout-root> <guest-key> <output-dir> --selector-control-only
#   canonical-guest-build.sh <checkout-root> pool-aggregate-chipnet-zero-value-rev3 <output-dir> --offline-cache <private-cache>
#
#   guest-key ∈ transition | transition-v1 | transition-v2 | recurrence-v0 | import-v1 | import-v2 | import-v4 | import-v6 | successor-aggregate-v3 | pool-aggregate-default | pool-aggregate-chipnet-zero-value-rev3 | pool-aggregate-local-zero-value | sp1-fanout-research
#
set -euo pipefail

# ── The canonical environment. Pinned by immutable digest, never by a mutable
# ── tag: `v6.3.1` can be repointed at new bytes, `@sha256:…` cannot.
SP1_CANONICAL_IMAGE_DIGEST="sha256:0942a27dbe8e38f4b14f3732e779df4027b17bde93e9fbc9e8c773c15eb63400"
SP1_CANONICAL_IMAGE="ghcr.io/succinctlabs/sp1@${SP1_CANONICAL_IMAGE_DIGEST}"
TRUSTED_ENV="/usr/bin/env"
TRUSTED_ID="/usr/bin/id"
TRUSTED_DSCL="/usr/bin/dscl"
TRUSTED_GETENT="/usr/bin/getent"
TRUSTED_SED="/usr/bin/sed"
TRUSTED_HEAD="/usr/bin/head"
TRUSTED_CUT="/usr/bin/cut"
# Trusted host tools are pinned to the invoking account's REAL home directory,
# read from the password database via the effective UID.
#
# Deliberately NOT `$HOME`. `$HOME` is caller-controlled, so deriving a trust
# anchor from it lets a forged environment relocate the trusted toolchain — an
# honest run under a different HOME (sudo, another account, a CI or agent
# context) would silently build with a different `cargo-prove` instead of
# failing closed. The password database is not settable by the caller.
#
# This still carries no operator-identifying absolute path, so the
# de-identification that motivated moving off the hardcoded literal is
# preserved.
#
# The home directory is read DIRECTLY from the password database. It is
# deliberately NOT obtained by `eval`-ing a tilde expression: in bash, `~N` for
# an all-numeric N is DIRECTORY-STACK expansion, not a user lookup, so an
# account literally named `0` would expand to the caller's working directory and
# put the trust anchor back under caller control. The account name is only ever
# a lookup key here, never shell syntax, and no `eval` is involved.
TRUSTED_ACCOUNT="$("$TRUSTED_ID" -un)"
case "$TRUSTED_ACCOUNT" in
  ''|*[!A-Za-z0-9._-]*)
    echo "refusing to derive a trusted root from an unexpected account name" >&2
    exit 1
    ;;
esac
TRUSTED_HOME=""
TRUSTED_PASSWD_RECORD=""
if [ -x "$TRUSTED_DSCL" ]; then
  TRUSTED_PASSWD_RECORD="$("$TRUSTED_DSCL" . -read "/Users/${TRUSTED_ACCOUNT}" \
    NFSHomeDirectory 2>/dev/null || true)"
  TRUSTED_HOME="$(printf '%s\n' "$TRUSTED_PASSWD_RECORD" \
    | "$TRUSTED_SED" -n 's/^NFSHomeDirectory: //p' | "$TRUSTED_HEAD" -n 1 || true)"
elif [ -x "$TRUSTED_GETENT" ]; then
  TRUSTED_PASSWD_RECORD="$("$TRUSTED_GETENT" passwd "$TRUSTED_ACCOUNT" 2>/dev/null || true)"
  TRUSTED_HOME="$(printf '%s\n' "$TRUSTED_PASSWD_RECORD" \
    | "$TRUSTED_HEAD" -n 1 | "$TRUSTED_CUT" -d: -f6 || true)"
fi
[ -n "$TRUSTED_HOME" ] || {
  echo "trusted home directory could not be read from the password database" >&2
  exit 1
}
case "$TRUSTED_HOME" in
  /*) ;;
  *)
    echo "trusted home directory did not resolve to an absolute path" >&2
    exit 1
    ;;
esac
[ -d "$TRUSTED_HOME" ] || {
  echo "trusted home directory is unavailable" >&2
  exit 1
}
TRUSTED_CARGO_PROVE="${TRUSTED_HOME}/.sp1/bin/cargo-prove"
TRUSTED_PROTOC="/opt/homebrew/bin/protoc"
TRUSTED_GO="/opt/homebrew/bin/go"
TRUSTED_PATH="${TRUSTED_HOME}/.sp1/bin:${TRUSTED_HOME}/.cargo/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
HOST_TOOLS_DIR=""
HOST_TOOLS_PARENT=""

cleanup_host_tools() {
  if [ -n "$HOST_TOOLS_DIR" ]; then
    case "$HOST_TOOLS_DIR" in
      "$HOST_TOOLS_PARENT"/apnt-canonical-builder-host-tools.*)
        /bin/rm -rf -- "$HOST_TOOLS_DIR"
        ;;
      *)
        echo "refusing to remove unexpected canonical builder host-tool path" >&2
        ;;
    esac
    HOST_TOOLS_DIR=""
  fi
}

trap cleanup_host_tools EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

prepare_host_tools() {
  [ -x "$TRUSTED_PROTOC" ] && [ -x "$TRUSTED_GO" ] || {
    echo "fixed canonical builder host prerequisite is unavailable" >&2
    return 1
  }

  HOST_TOOLS_PARENT="$(cd "${TMPDIR:-/private/tmp}" && pwd -P)"
  HOST_TOOLS_DIR="$(/usr/bin/mktemp -d \
    "$HOST_TOOLS_PARENT/apnt-canonical-builder-host-tools.XXXXXX")"
  HOST_TOOLS_DIR="$(cd "$HOST_TOOLS_DIR" && pwd -P)"
  /bin/chmod 700 "$HOST_TOOLS_DIR"
  /bin/ln -s "$TRUSTED_PROTOC" "$HOST_TOOLS_DIR/protoc"
  /bin/ln -s "$TRUSTED_GO" "$HOST_TOOLS_DIR/go"
  if [ -n "$OFFLINE_CACHE" ]; then
    prepare_offline_docker
  fi
}

# The same trusted cargo-prove still constructs every compiler invocation.
# This private shim closes only Docker transport and cache arguments. It is
# embedded here so a restored public clone has no withheld helper dependency.
prepare_offline_docker() {
  [ -x "$TRUSTED_DOCKER" ] || { echo "fixed offline Docker executable unavailable" >&2; return 1; }
  {
    printf '#!/bin/bash\nset -euo pipefail\n'
    printf 'docker=%q\ncheckout=%q\ncache=%q\nimage=%q\n' \
      "$TRUSTED_DOCKER" "$CHECKOUT_ROOT" "$OFFLINE_CACHE" "$SP1_CANONICAL_IMAGE"
    /bin/cat <<'OFFLINE_DOCKER'
refuse() { echo "canonical offline Docker arguments refused" >&2; exit 2; }
if [ "$#" -eq 1 ] && [ "$1" = info ]; then exec "$docker" "$@"; fi
[ "$#" -gt 1 ] && [ "$1" = run ] || refuse
shift
flags=(); volumes=(); variables=()
rm_seen=false; platform=false; entrypoint=false; interactive=false; workdir=false
while [ "$#" -gt 0 ] && [ "$1" != "$image" ]; do
  key="$1"; shift
  case "$key" in
    --rm) [ "$rm_seen" = false ] || refuse; rm_seen=true; flags+=(--rm); continue ;;
    -i) [ "$interactive" = false ] || refuse; interactive=true; flags+=(-i); continue ;;
  esac
  [ "$#" -gt 0 ] || refuse
  value="$1"; shift
  case "$key" in
    -v) volumes+=("$value"); continue ;;
    --platform) [ "$platform" = false ] && [ "$value" = linux/amd64 ] || refuse; platform=true ;;
    --entrypoint) [ "$entrypoint" = false ] && [ -z "$value" ] || refuse; entrypoint=true ;;
    -w)
      [ "$workdir" = false ] && [ "$value" = /root/program/tools/apnt-pool-aggregate-sp1/program-chipnet-zero-value-rev3 ] || refuse
      workdir=true ;;
    -e)
      case "$value" in *=*) ;; *) refuse ;; esac
      name="${value%%=*}"
      for previous in "${variables[@]+${variables[@]}}"; do [ "$name" != "$previous" ] || refuse; done
      case "$name" in
        CARGO_TARGET_DIR) case "$value" in CARGO_TARGET_DIR=/root/program/*) ;; *) refuse ;; esac
          case "$value" in */../*|*/..) refuse ;; esac ;;
        RUSTUP_TOOLCHAIN) [ "$value" = RUSTUP_TOOLCHAIN=succinct ] || refuse ;;
        RUSTC_BOOTSTRAP|CARGO_ENCODED_RUSTFLAGS|RUSTC|CFLAGS_riscv32im_succinct_zkvm_elf) ;;
        *) refuse ;;
      esac
      variables+=("$name") ;;
    *) refuse ;;
  esac
  flags+=("$key" "$value")
done
[ "$#" -gt 0 ] && [ "$1" = "$image" ] && [ "$rm_seen" = true ] && [ "$platform" = true ] && [ "$entrypoint" = true ] || refuse
shift
probe=false
if [ "$#" -eq 2 ] && [ "$1" = rustc ] && [ "$2" = --version ]; then probe=true; fi
if [ "$#" -eq 3 ] && [ "$1" = rustc ] && [ "$2" = --print ] && [ "$3" = sysroot ]; then probe=true; fi
if [ "$probe" = true ]; then
  [ "${#volumes[@]}" -eq 0 ] && [ "${#variables[@]}" -eq 1 ] && [ "${variables[0]}" = RUSTUP_TOOLCHAIN ] && [ "$workdir" = false ] || refuse
else
  guest=apnt-pool-aggregate-program-chipnet-zero-value-rev3
  expected=(cargo build --release --target riscv64im-succinct-zkvm-elf -p "$guest" --bin "$guest" --locked)
  [ "$#" -eq "${#expected[@]}" ] && [ "$workdir" = true ] && [ "${#variables[@]}" -eq 6 ] || refuse
  index=0
  for arg in "$@"; do [ "$arg" = "${expected[$index]}" ] || refuse; index=$((index+1)); done
  [ "${#volumes[@]}" -eq 1 ] || [ "${#volumes[@]}" -eq 3 ] || refuse
  [ "${volumes[0]}" = "$checkout:/root/program" ] || refuse
  if [ "${#volumes[@]}" -eq 3 ]; then
    [ "${volumes[1]}" = sp1-cargo-registry:/root/.cargo/registry ] && [ "${volumes[2]}" = sp1-cargo-git:/root/.cargo/git ] || refuse
  fi
  # Preserve the image's /root/.cargo/bin compiler tools. Mounting the cache
  # root here hides cargo itself; only resolver state belongs to the cache.
  flags+=(--mount "type=bind,src=$checkout,dst=/root/program"
    --mount "type=bind,src=$cache/registry,dst=/root/.cargo/registry"
    --mount "type=bind,src=$cache/git,dst=/root/.cargo/git")
fi
exec "$docker" run --network=none --pull=never "${flags[@]}" \
  -e CARGO_NET_OFFLINE=true -e RUSTUP_OFFLINE=1 -e CARGO_NET_GIT_FETCH_WITH_CLI=false "$image" "$@"
OFFLINE_DOCKER
  } > "$HOST_TOOLS_DIR/docker"
  /bin/chmod 700 "$HOST_TOOLS_DIR/docker"
}

usage() {
  echo "usage: $0 <checkout-root> <guest-key> <output-dir>" >&2
  echo "       $0 <checkout-root> <guest-key> <output-dir> --selector-control-only" >&2
  echo "       $0 <checkout-root> pool-aggregate-chipnet-zero-value-rev3 <output-dir> --offline-cache <private-cache>" >&2
  echo "  guest-key ∈ transition | transition-v1 | transition-v2 | recurrence-v0 | import-v1 | import-v2 | import-v4 | import-v6 | successor-aggregate-v3 | pool-aggregate-default | pool-aggregate-chipnet-zero-value-rev3 | pool-aggregate-local-zero-value | sp1-fanout-research" >&2
  exit 2
}

[ "$#" -eq 3 ] || { [ "$#" -eq 4 ] && [ "$4" = "--selector-control-only" ]; } || { [ "$#" -eq 5 ] && [ "$4" = "--offline-cache" ]; } || usage
CHECKOUT_ROOT="$1"
GUEST_KEY="$2"
OUT_DIR="$3"
SELECTOR_CONTROL_ONLY=false
OFFLINE_CACHE=""
TRUSTED_DOCKER="/Applications/Docker.app/Contents/Resources/bin/docker"
if [ "$#" -eq 4 ]; then SELECTOR_CONTROL_ONLY=true; fi
if [ "$#" -eq 5 ]; then
  [ "$GUEST_KEY" = pool-aggregate-chipnet-zero-value-rev3 ] || usage
  OFFLINE_CACHE="$5"
  # No symlink aliases, shared writable cache, shell fragment or mount syntax.
  case "$OFFLINE_CACHE" in /*) ;; *) usage ;; esac
  case "$OFFLINE_CACHE" in *[!A-Za-z0-9_./-]*|*'/../'*|*'/./'*) usage ;; esac
  [ -d "$OFFLINE_CACHE" ] && [ ! -L "$OFFLINE_CACHE" ] \
    && [ "$(cd "$OFFLINE_CACHE" && pwd -P)" = "$OFFLINE_CACHE" ] \
    && [ "$(/usr/bin/stat -f '%u:%Lp' "$OFFLINE_CACHE")" = "$(/usr/bin/id -u):700" ] || {
      echo "offline cache is not a private owned physical directory" >&2; exit 1;
    }
  for cache_part in registry git; do
    cache_directory="$OFFLINE_CACHE/$cache_part"
    [ -d "$cache_directory" ] && [ ! -L "$cache_directory" ] \
      && [ "$(cd "$cache_directory" && pwd -P)" = "$cache_directory" ] \
      && [ "$(/usr/bin/stat -f '%u:%Lp' "$cache_directory")" = "$(/usr/bin/id -u):700" ] || {
        echo "offline cache subtree is not a private owned physical directory" >&2; exit 1;
      }
  done
fi

# ── Guest table: workspace, program directory, Cargo package, exact binary,
# ── and exact output. The explicit binary is load-bearing now that one package
# ── owns both the frozen Relation V2 guest and the additive recurrence guest.
EXTRA_RUSTFLAG=""
BUILD_RESOURCE_ENV=()
case "$GUEST_KEY" in
  transition)
    SP1_WS="tools/apnt-private-note-transition-sp1"
    PROGRAM_SUBDIR="program"
    PACKAGE="apnt-private-note-transition-sp1-program"
    BINARY="$PACKAGE"
    OUTPUT="$BINARY"
    ;;
  transition-v1)
    SP1_WS="tools/apnt-private-note-transition-v1-sp1"
    PROGRAM_SUBDIR="program"
    PACKAGE="apnt-private-note-transition-v1-sp1-program"
    BINARY="$PACKAGE"
    OUTPUT="$BINARY"
    ;;
  transition-v2)
    SP1_WS="tools/apnt-private-note-transition-v2-sp1"
    PROGRAM_SUBDIR="program"
    PACKAGE="apnt-private-note-transition-v2-sp1-program"
    BINARY="$PACKAGE"
    OUTPUT="$BINARY"
    ;;
  recurrence-v0)
    SP1_WS="tools/apnt-private-note-transition-v2-sp1"
    PROGRAM_SUBDIR="program"
    PACKAGE="apnt-private-note-transition-v2-sp1-program"
    BINARY="apnt-recurrence-native-private-transition-v0"
    OUTPUT="$BINARY"
    EXTRA_RUSTFLAG="--cfg=apnt_recurrence_native_v0"
    ;;
  import-v1)
    SP1_WS="tools/apnt-import-created-note-sp1"
    PROGRAM_SUBDIR="program"
    PACKAGE="apnt-import-created-note-sp1-program"
    BINARY="$PACKAGE"
    OUTPUT="$BINARY"
    ;;
  import-v2)
    SP1_WS="tools/apnt-import-created-note-sp1"
    PROGRAM_SUBDIR="program-v2"
    PACKAGE="apnt-import-created-note-sp1-program-v2"
    BINARY="$PACKAGE"
    OUTPUT="$BINARY"
    ;;
  import-v4)
    SP1_WS="tools/apnt-import-created-note-sp1"
    PROGRAM_SUBDIR="program-v4"
    PACKAGE="apnt-import-created-note-sp1-program-v4"
    BINARY="$PACKAGE"
    OUTPUT="$BINARY"
    ;;
  import-v6)
    SP1_WS="tools/apnt-import-created-note-v6-sp1"
    PROGRAM_SUBDIR="program"
    PACKAGE="apnt-import-created-note-v6-sp1-program"
    BINARY="$PACKAGE"
    OUTPUT="$BINARY"
    ;;
  successor-aggregate-v3)
    SP1_WS="tools/apnt-successor-aggregate-sp1"
    PROGRAM_SUBDIR="program"
    PACKAGE="apnt-successor-aggregate-program"
    BINARY="$PACKAGE"
    OUTPUT="$BINARY"
    ;;
  pool-aggregate-default)
    # The pool aggregate guest's default build: an empty profile allowlist.
    SP1_WS="tools/apnt-pool-aggregate-sp1"
    PROGRAM_SUBDIR="program"
    PACKAGE="apnt-pool-aggregate-program"
    BINARY="$PACKAGE"
    OUTPUT="$BINARY"
    ;;
  pool-aggregate-chipnet-zero-value-rev3)
    # The labelled Chipnet build: the same guest source compiled by its own
    # package, whose allowlist is exactly registry entry 1 revision 3's
    # Chipnet vp. SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY.
    SP1_WS="tools/apnt-pool-aggregate-sp1"
    PROGRAM_SUBDIR="program-chipnet-zero-value-rev3"
    PACKAGE="apnt-pool-aggregate-program-chipnet-zero-value-rev3"
    BINARY="$PACKAGE"
    OUTPUT="$BINARY"
    ;;
  pool-aggregate-local-zero-value)
    # Separate workspace and source; no Chipnet guest input is changed.
    SP1_WS="tools/apnt-pool-aggregate-local-sp1"
    PROGRAM_SUBDIR="program"
    PACKAGE="apnt-pool-aggregate-program-local-zero-value"
    BINARY="$PACKAGE"
    OUTPUT="$BINARY"
    BUILD_RESOURCE_ENV=(RAYON_NUM_THREADS=4 CARGO_BUILD_JOBS=4)
    ;;
  sp1-fanout-research)
    # Additive, internal research only. No existing selector or pin changes.
    SP1_WS="tools/sp1-fanout-research"
    PROGRAM_SUBDIR="program"
    PACKAGE="apnt-sp1-fanout-research-program"
    BINARY="$PACKAGE"
    OUTPUT="$BINARY"
    BUILD_RESOURCE_ENV=(RAYON_NUM_THREADS=4 CARGO_BUILD_JOBS=4)
    ;;
  *) usage ;;
esac

# `sp1-build` canonicalizes both the workspace directory and the program
# directory and then requires one to be a prefix of the other. A checkout
# reached through a symlink (notably anything under macOS `/tmp`, which is a
# symlink to `/private/tmp`) makes that prefix test fail. Canonicalize here so
# the failure is a clear message rather than sp1-build's bare `exit 1`.
CHECKOUT_ROOT="$(cd "$CHECKOUT_ROOT" && pwd -P)"
if [ -n "$OFFLINE_CACHE" ]; then
  case "$CHECKOUT_ROOT" in *[!A-Za-z0-9_./-]*) usage ;; esac
  case "$OFFLINE_CACHE/" in "$CHECKOUT_ROOT/"*) usage ;; esac
  case "$CHECKOUT_ROOT/" in "$OFFLINE_CACHE/"*) usage ;; esac
fi
PROGRAM_DIR="$CHECKOUT_ROOT/$SP1_WS/$PROGRAM_SUBDIR"
[ -d "$PROGRAM_DIR" ] || { echo "no such program directory: $PROGRAM_DIR" >&2; exit 1; }

/bin/mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd -P)"

[ -x "$TRUSTED_ENV" ] && [ -x "$TRUSTED_CARGO_PROVE" ] || {
  echo "trusted canonical SP1 builder executable is unavailable" >&2
  exit 1
}

echo "── canonical guest build ────────────────────────────────────────────"
echo "  guest          : $GUEST_KEY ($PACKAGE / $BINARY)"
echo "  checkout root  : $CHECKOUT_ROOT  (host path length ${#CHECKOUT_ROOT})"
echo "  mounted at     : /root/program   (fixed, in-container)"
echo "  image          : $SP1_CANONICAL_IMAGE"
echo "  output         : $OUT_DIR/$OUTPUT"
echo "─────────────────────────────────────────────────────────────────────"

cd "$PROGRAM_DIR"
BUILD_ARGUMENTS=(
  prove
  build
  --docker
  --locked
  --workspace-directory "$CHECKOUT_ROOT"
  -p "$PACKAGE"
  --binaries "$BINARY"
  --output-directory "$OUT_DIR"
  --elf-name "$OUTPUT"
)
if [ -n "$EXTRA_RUSTFLAG" ]; then
  BUILD_ARGUMENTS+=("--rustflags=$EXTRA_RUSTFLAG")
fi

if [ "$SELECTOR_CONTROL_ONLY" = true ]; then
  echo "selector-control-only=true"
  echo "trusted-executable=$TRUSTED_CARGO_PROVE"
  echo "trusted-path=$TRUSTED_PATH"
  for argument in "${BUILD_ARGUMENTS[@]}"; do
    echo "arg=$argument"
  done
  echo "selected-package=$PACKAGE"
  echo "selected-binary=$BINARY"
  echo "selected-output=$OUTPUT"
  exit 0
fi

umask 077
prepare_host_tools
CANONICAL_CARGO_HOME="${TRUSTED_HOME}/.cargo"
OFFLINE_ENV=()
if [ -n "$OFFLINE_CACHE" ]; then
  CANONICAL_CARGO_HOME="$OFFLINE_CACHE"
  /bin/mkdir -m 700 "$HOST_TOOLS_DIR/docker-config"
  OFFLINE_ENV=(CARGO_NET_OFFLINE=true CARGO_NET_GIT_FETCH_WITH_CLI=false RUSTUP_OFFLINE=1
    DOCKER_HOST="unix://${TRUSTED_HOME}/.docker/run/docker.sock" DOCKER_CONFIG="$HOST_TOOLS_DIR/docker-config")
fi
"$TRUSTED_ENV" -i \
  HOME="${TRUSTED_HOME}" \
  CARGO_HOME="$CANONICAL_CARGO_HOME" \
  RUSTUP_HOME="${TRUSTED_HOME}/.rustup" \
  SP1_HOME="${TRUSTED_HOME}/.sp1" \
  PATH="$HOST_TOOLS_DIR:$TRUSTED_PATH" \
  LC_ALL=C \
  SP1_DOCKER_IMAGE="$SP1_CANONICAL_IMAGE" \
  "${OFFLINE_ENV[@]+${OFFLINE_ENV[@]}}" \
  "${BUILD_RESOURCE_ENV[@]}" \
  "$TRUSTED_CARGO_PROVE" "${BUILD_ARGUMENTS[@]}"
cleanup_host_tools

echo
echo "built: $OUT_DIR/$OUTPUT"
/usr/bin/shasum -a 256 "$OUT_DIR/$OUTPUT"
/usr/bin/wc -c < "$OUT_DIR/$OUTPUT" | /usr/bin/tr -d ' ' | /usr/bin/sed 's/^/bytes: /'
