# Build, dependency acquisition and validation

These instructions apply to Covenant Shielded Pool v0.5.0 and replace the retired private P2 workshop procedure. Use the public sources below; no private cache, signed admission packet or private development checkout is part of this developer path. Historical qualification metadata is not a fresh build or consumer-test receipt.

All setup references are disclosed simulated, single-party, zero-value test material, for Chipnet only. Building source does not authenticate setup material or qualify production use. Preserve locks, cryptographic relations, vectors, signatures and proof/verifier anchors. A mismatch must be investigated, never repinned to pass. These commands construct no proof, generate no key and move no funds.

## Toolchains and public sources

The measured reference environment is macOS arm64; other hosts are not validated by that evidence. Install native linker prerequisites first (Xcode Command Line Tools on macOS). The canonical guest wrapper additionally requires the fixed macOS paths described below.

| Tool or dependency | Version used or required | Public acquisition |
| --- | --- | --- |
| Node.js | 20.19.4, measured cutover runtime | [Versioned distribution and checksums](https://nodejs.org/dist/v20.19.4/). `.nvmrc` retains 22.22.3, unverified here; select 20.19.4 explicitly. |
| pnpm | 9.0.0 | `npm install --global pnpm@9.0.0`; [official guide](https://pnpm.io/installation#using-npm). |
| JavaScript dependencies | TypeScript 5.9.3, Vitest 2.1.9, libauth 3.1.0-next.8, noble curves 1.9.7, types/node 25.8.0 | `pnpm-lock.yaml` and the committed Vitest patch; frozen installation below. |
| Go | 1.26.5 reference compiler; modules declare minimum 1.25.7 | [Official archived downloads and checksums](https://go.dev/dl/). Select the matching OS/architecture and put its `bin` on PATH. Use `GOTOOLCHAIN=local`. |
| Rust / Cargo | rustc 1.97.0 / cargo 1.97.0 | Install [rustup](https://rust-lang.org/tools/install/), then `rustup toolchain install 1.97.0 --profile minimal`. Select it as shown below. |
| Protocol Buffers compiler | protoc 36.1 | [Upstream v36.1 release](https://github.com/protocolbuffers/protobuf/releases/tag/v36.1), matching host archive. Put `protoc` on PATH. |
| Bash for the canonical wrapper | 5.3.9; macOS system Bash 3.2 is unsupported | [GNU Bash 5.3 distribution](https://ftp.gnu.org/gnu/bash/bash-5.3.tar.gz) with [upstream patches bash53-001 through bash53-009](https://ftp.gnu.org/gnu/bash/bash-5.3-patches/). Verify the upstream signatures and put the installed Bash before `/bin` on PATH. |
| Go modules | gnark 0.16.3, gnark-crypto 0.21.0 and committed transitive selection | Public Go proxy/checksum database; each module's `go.mod` and `go.sum`. |
| Rust crates | SP1 SDK exactly 6.3.1; other crates and patched Git revisions from each Cargo.lock | crates.io and public Git repositories in the manifests; `cargo fetch --locked` below. |
| Canonical guest builder | SP1 CLI 6.3.1; measured string `cargo-prove sp1 (8252c29 2026-06-25T11:48:19.318567000Z)` | [Upstream v6.3.1 release](https://github.com/succinctlabs/sp1/releases/tag/v6.3.1) and [installation guide](https://docs.succinct.xyz/docs/sp1/getting-started/install). Install the versioned release, not the current default. |
| Guest container | `ghcr.io/succinctlabs/sp1@sha256:0942a27dbe8e38f4b14f3732e779df4027b17bde93e9fbc9e8c773c15eb63400` | Pull this exact digest with Docker; the image pins guest rustc. Docker CLI reference: 29.5.3; a running engine is also required. |

Verify upstream checksums/signatures where supplied. Matching versions alone does not authenticate every installed byte. Historical workshop metadata has been removed from this public source tree; it does not establish portable installation or current qualification.

## JavaScript bootstrap and checks

From the repository root, with Node 20.19.4 and pnpm 9.0.0 on PATH:

```sh
node scripts/rehearsal-check.mjs
```

This executes the existing commands in order, stopping at the first failure:

```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm build
pnpm typecheck
pnpm test:identities
pnpm test:rehearsal
pnpm test:build-metadata
```

The existing test selection, single worker and limits remain unchanged. The identities group is also included in the rehearsal group. Later steps after a failure are unrun; use the individual command to diagnose a failed step. Node 22.22.3 is accepted to preserve the legacy declaration, but is unverified here. An accepted version is not a passing check. The helper resolves the checkout from its own location, so it can be launched from any directory.

## Four native host builds

First install/select the versions above. Put rustup proxies before any unrelated system Rust installation:

```sh
export PATH="$HOME/.cargo/bin:$PATH"
export RUSTUP_TOOLCHAIN=1.97.0
go version
rustc --version
cargo --version
protoc --version
node scripts/rehearsal-check.mjs fetch-native
node scripts/rehearsal-check.mjs native-builds
```

`fetch-native` is explicit public network acquisition: the two Go modules use the public Go proxy and checksum database; the aggregate workspace and identity probe use `cargo fetch --locked`. Go acquisition runs in fresh temporary copies of only the module manifests/sums and requires them to remain byte-identical. Source sums are never rewritten. Cargo preserves its committed checksums and Git revisions. Missing packages, checksum failures and changed locks are failures, not reasons to use a private cache.

`native-builds` checks versions, then uses `GOTOOLCHAIN=local`, `GOFLAGS=-mod=readonly`, `GOPROXY=off`, `GOSUMDB=off`, and `CARGO_NET_OFFLINE=true`. It never auto-installs a compiler. Outputs and the Go compiler cache go in a fresh temporary directory printed by the helper, outside the checkout. Retain it for inspection or remove only that owned directory when finished. It runs these four existing recipes:

```sh
# OUT is the fresh output directory created by the helper.
go -C tools/apnt-pool-action-circuit build -trimpath -buildvcs=false \
  -o "$OUT/action/" ./cmd/pool-action-circuit ./cmd/pool-pk-load
go -C tools/apnt-pool-ceremony build -trimpath -buildvcs=false \
  -o "$OUT/ceremony/" ./cmd/apnt-pool-ceremony-verify ./cmd/apnt-pool-ceremony-recheck
cargo build --offline --locked --manifest-path tools/apnt-pool-aggregate-sp1/Cargo.toml \
  -p apnt-pool-aggregate-runner --target-dir "$OUT/aggregate"
cargo build --offline --locked --release \
  --manifest-path tools/sp1-canonical-guest-build/vkey-probe/Cargo.toml --target-dir "$OUT/vkey"
```

The aggregate runner's default build has no `prove` feature. The identity probe is built but not executed by `native-builds`. Compiler success does not demonstrate fixture consumption, verifier acceptance, guest equality or setup soundness.

## Canonical Chipnet guest reproduction

Use only the shipped `pool-aggregate-chipnet-zero-value-rev3` selector for this comparison. The wrapper retains historical selectors whose sources may be absent; they are outside this recipe. Its README explains the mount/path rationale. The unchanged wrapper resolves the real account home and requires that account's `.sp1/bin/cargo-prove`, plus `/opt/homebrew/bin/go` and `/opt/homebrew/bin/protoc`. Alternate PATH or HOME does not relocate trusted tools. A host lacking these prerequisites is unsupported by this wrapper; do not edit it or its anchors to compensate.

Install the CLI from the versioned upstream release into the real account's `.sp1/bin`, verify the measured CLI string above, and have a running Docker engine. Acquire the pinned image explicitly:

```sh
docker pull ghcr.io/succinctlabs/sp1@sha256:0942a27dbe8e38f4b14f3732e779df4027b17bde93e9fbc9e8c773c15eb63400
```

The ordinary wrapper can acquire public container dependencies and uses the upstream builder's Cargo volumes. Host `fetch-native` does not populate container caches. This is an online developer recipe, not a claim of sealed offline execution. The optional `--offline-cache` transport requires a separately qualified cache and is not needed here.

From a clean committed checkout, build at two independent clone paths. Use Bash 5.3.9 explicitly: the macOS system shell cannot expand the wrapper's empty arrays correctly and can return zero without producing an ELF. Require the actual outputs as well as exit codes. Preserve the root mount, digest, locked dependencies and exact binary. These commands build guests and derive identities with SP1 `setup()` only; they do not prove:

```sh
case "$(bash --version)" in
  *'version 5.3.9'*) ;;
  *) echo 'Bash 5.3.9 must be first on PATH.' >&2; exit 1 ;;
esac
REPRO="$(mktemp -d "${TMPDIR:-/tmp}/csp-guest-repro.XXXXXX")"
git clone --no-hardlinks . "$REPRO/short"
git clone --no-hardlinks . "$REPRO/a-much-longer-independent-checkout"
for arm in short a-much-longer-independent-checkout; do
  bash "$REPRO/$arm/tools/sp1-canonical-guest-build/canonical-guest-build.sh" \
    "$REPRO/$arm" pool-aggregate-chipnet-zero-value-rev3 "$REPRO/$arm-output" || exit 1
  test -s "$REPRO/$arm-output/apnt-pool-aggregate-program-chipnet-zero-value-rev3" || exit 1
done
cmp "$REPRO/short-output/apnt-pool-aggregate-program-chipnet-zero-value-rev3" \
    "$REPRO/a-much-longer-independent-checkout-output/apnt-pool-aggregate-program-chipnet-zero-value-rev3" || exit 1
# Set PROBE to the binary under native-builds' printed output directory.
PROBE="/absolute/path/to/printed-output/vkey/release/apnt-sp1-guest-identity-probe"
"$PROBE" "$REPRO/short-output/apnt-pool-aggregate-program-chipnet-zero-value-rev3" \
  "$REPRO/a-much-longer-independent-checkout-output/apnt-pool-aggregate-program-chipnet-zero-value-rev3" \
  > "$REPRO/identities.jsonl" || exit 1
node --input-type=module - "$REPRO/identities.jsonl" <<'JS'
import { readFileSync } from 'node:fs';
const identities = readFileSync(process.argv[2], 'utf8').trim().split('\n').map(line => JSON.parse(line));
const { record } = JSON.parse(readFileSync('tools/apnt-pool-aggregate-sp1/canonical-build/chipnet-zero-value-rev3-canonical-build-v1.json', 'utf8'));
if (identities.length !== 2 || identities.some(identity =>
    identity.guest_elf_sha256 !== record.guestElfSha256 ||
    identity.guest_elf_bytes !== record.guestElfBytes ||
    identity.program_vkey_hash !== record.programVkeyHash)) {
  throw new Error('Canonical ELF/hash/length/VKey mismatch; stop without repinning.');
}
console.log('Two-clone ELF bytes, length and setup-only VKey match the existing Chipnet record.');
JS
```

Retain the source commit, tool versions, both build exit codes, `cmp` exit and comparison exit. Missing tools/inputs, failed builds or mismatches leave equality unverified. Never substitute the local-zero-value selector or update a pin. Keep the temporary output for inspection; remove only the directory these commands created when finished.

## Coverage and remaining limits

The v0.5.0 cutover producer recorded successful JavaScript commands and four host builds. It recorded three input-dependent Go groups failing and four Rust consumer groups plus two-clone guest equality unrun. These are historical results, not new passes from this guide. Separate public validation-input work owns missing fixtures/recipes/runtime bridge closure. Do not fetch private donor material to fill a gap or describe full native validation as complete before those consumers have passing evidence.

Canonical guest reproduction remains unverified: the system-Bash trial produced no ELF, and the corrected Bash 5.3.9 recipe still needs a successful two-clone run. A zero build exit alone is insufficient evidence.

The helper selects no native tests, full-release tier, live wallet, relay, chain or proof workload. Final release validation remains separate. Missing inputs and excluded/skipped tests stay explicit. A successful bootstrap does not certify privacy, production setup or spendability.
