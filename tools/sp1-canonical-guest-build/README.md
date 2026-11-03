> Historical paths below use illustrative public substitutions. Recorded path lengths and byte sizes describe the original experiments, not the substituted path strings.

# Canonical SP1 guest build environment

A guest ELF built the ordinary way is a **function of the absolute path of the
checkout it was built in**. Its SHA-256, its byte length, and the program VKey
derived from it all move when the checkout moves. That has already cost real
work: the transition guest was pinned from inside a git worktree
(`b852785f…` / 986,496) and that value is unreachable from the main checkout.

This directory holds the environment that removes the host path from the
inputs, plus the evidence that it does.

Everything here is **build and `setup()` only**. No proof is constructed
anywhere in this directory.

---

## The canonical build command

```sh
tools/sp1-canonical-guest-build/canonical-guest-build.sh \
    <checkout-root> <guest-key> <output-dir>
```

`guest-key ∈ transition | transition-v1 | transition-v2 | recurrence-v0 | import-v1 | import-v2 | import-v4 | import-v6 | successor-aggregate-v3 | pool-aggregate-default | pool-aggregate-chipnet-zero-value-rev3 | pool-aggregate-local-zero-value`.
`transition-v1` is the additive secure-transition guest; `transition` remains
the frozen V0 guest and is never reinterpreted by that selector.
`transition-v2` is the additive Relation V2 guest; it does not reinterpret
either existing transition selector. `import-v6` selects the
canonical-APNTPIV6-only Relation V6 guest. `successor-aggregate-v3` selects
the default-feature aggregate guest that commits APNTAGV3 after child
verification, private-global validation, and successor-settlement binding; it
never enables the test-only child-stub feature.
`pool-aggregate-default` selects the pool aggregate guest's default build
(an empty profile allowlist); `pool-aggregate-chipnet-zero-value-rev3`
selects the labelled Chipnet build of the same guest source, a separate
package (`program-chipnet-zero-value-rev3`) whose allowlist is exactly
registry entry 1 revision 3's Chipnet vp (SIMULATED SINGLE-PARTY SETUP -
ZERO-VALUE TEST ONLY; its pins are in
`tools/apnt-pool-aggregate-sp1/canonical-build/`). Neither passes a Cargo
feature on the command line: the Chipnet package enables its core feature
itself.
`pool-aggregate-local-zero-value` selects a separate workspace and source
under `tools/apnt-pool-aggregate-local-sp1/`. Its own entry passes exactly
revision 3's recorded action VP profile to the unchanged aggregate core and
carries a local 0x99 zero-value label. It does not modify the Chipnet guest
input set. No Cargo feature is passed for this selector. Its canonical command
additionally sets `RAYON_NUM_THREADS=4` and `CARGO_BUILD_JOBS=4` in the clean
environment; existing selectors retain their original environment.
`recurrence-v0` selects the additive
`apnt-recurrence-native-private-transition-v0` binary from the same Cargo
package as `transition-v2`; the two selectors never rely on Cargo's implicit
binary choice.

which is the following allowlisted empty-environment invocation, with the
fresh directory and selector-specific optional argument shown as explicit
placeholders:

```sh
cd "<checkout-root>/tools/<sp1-workspace>/<program-dir>"
/usr/bin/env -i \
  HOME=/example/home \
  CARGO_HOME=/example/home/.cargo \
  RUSTUP_HOME=/example/home/.rustup \
  SP1_HOME=/example/home/.sp1 \
  PATH=<fresh-builder-host-tools-dir>:/example/home/.sp1/bin:/example/home/.cargo/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin \
  LC_ALL=C \
  SP1_DOCKER_IMAGE=ghcr.io/succinctlabs/sp1@sha256:0942a27dbe8e38f4b14f3732e779df4027b17bde93e9fbc9e8c773c15eb63400 \
  /example/home/.sp1/bin/cargo-prove prove build \
  --docker \
  --locked \
  --workspace-directory "<checkout-root>" \
  -p "<program-package>" \
  --binaries "<exact-program-binary>" \
  --output-directory "<output-dir>" \
  --elf-name "<exact-output-name>" \
  [--rustflags=--cfg=apnt_recurrence_native_v0]
```

The bracketed argument is present exactly once for `recurrence-v0` and absent
for every other selector, including `transition-v2`. It is a selector-local
packaging cfg, not a feature or program-identity claim. Inherited
`RUSTFLAGS` is outside the empty environment and cannot reach either guest.

Three parts of that are load-bearing and none are defaults:

* **The executable and environment are fixed.** Inherited `PATH`, Cargo,
  Rust, Git, Docker, Node, and wrapper variables cannot select a different
  builder. The selector-only test mode prints this exact command without
  entering a build and is never used by the canonical identity checker. For
  the real `cargo-prove` window, the wrapper also requires the already-installed
  `/opt/homebrew/bin/protoc` and `/opt/homebrew/bin/go`, exposes only links to
  those two fixed paths through a fresh mode-0700 temporary PATH directory,
  and removes that directory on success, failure, or interruption. It never
  installs, copies, or persists a host-tool bridge.
* **`--workspace-directory` is the REPO ROOT**, not the SP1 workspace root.
  `sp1-build` bind-mounts exactly that one directory at the fixed in-container
  path `/root/program`. The selected SP1 workspaces are rooted at
  `tools/…-sp1` while their parity crates are siblings at
  `tools/…-rust-parity`; pointing the flag at the SP1 workspace would leave
  those crates outside the mount.
* **`SP1_DOCKER_IMAGE` pins by immutable digest**, not by the `--tag v6.3.1`
  default. A tag can be repointed at new bytes; a digest cannot. The image
  carries the `rustc` that compiles the guest, so the image *is* part of the
  program's identity.
* **`--locked`** stops dependency resolution drifting, and stops a build from
  rewriting a tracked `Cargo.lock` in someone else's checkout.
* **`--binaries` names one exact target.** This is mandatory for every selector,
  including packages that currently have only one binary. In particular,
  `transition-v2` and `recurrence-v0` select different binaries from the same
  package and produce differently named outputs.

### Recurrence-native frozen-control checker

After the reviewed recurrence source/selector precursor is integrated, and
only from the clean canonical `main` checkout under the managed `sp1-prover`
resource lease, run:

```sh
tools/sp1-canonical-guest-build/check-recurrence-native-v0.sh \
  <clean-canonical-main-checkout> \
  <fresh-restrictive-non-worktree-output-directory>
```

The checker builds `transition-v2` and `recurrence-v0` through the immutable
container boundary, derives both VKeys with the existing setup-only probe, and
first requires Relation V2 to remain exactly SHA-256
`68e662d5991ef94fe6a8e42d7469a048dc4d0374ee04e2c0b641eb372ca590f0`,
1,213,056 bytes, and program VKey
`0063f9299d606362f251d7f5f2febcbe2da90cb7bf86a950df1ca7f1bd193fa8`.
Any mismatch stops with
`BLOCKED: RECURRENCE-SHARED-LIB-MOVES-RELATION-V2-GUEST`; it is never a reason
to edit the old pin. The checker freezes and revalidates the canonical-main
HEAD, tree, branch, ref, and cleanliness across both builds and a fresh
out-of-checkout probe-target build. Only after that control passes does it
create a mode-0600 public recurrence identity candidate record and preserve
the exact mode-0600 canonical recurrence ELF beside it for later reviewed
proof routing. It executes `setup()` only: no proof, CashVM, chain, wallet,
privacy, anonymity, spendability, or economic claim follows from either file.

The checker independently creates and cleans its own mode-0700 links to the
same fixed `protoc` and Go executables for only the VKey-probe Cargo build; it
does not depend on the builder's temporary directory. Missing or non-executable
fixed tools reject before a guest build or identity record. Clean-checkout
validation may disregard only checkout-root `CLAUDE.md`, and only when the
invoking Git configuration already classifies that exact name as ignored. The
checker never reads it or changes any ignore file, and every other dirty path
still rejects.

### What breaks it

* Changing the image digest — a different compiler is a different program.
* Moving any selected SP1 workspace or parity crate to a different depth under
  the repo root. The absolute host path stops mattering; the **relative**
  layout under the repo root becomes load-bearing instead.
* Dropping `--locked`.
* Activating a Cargo feature — Cargo mixes enabled features into the same
  `-Cmetadata` hash, so a feature change moves every disambiguator.
* Reaching the checkout through a symlink. `command/docker.rs` canonicalizes the
  `--workspace-directory` you pass, but then prefix-tests it against
  `program_metadata.workspace_root`, which comes from `cargo metadata`
  un-canonicalized. Under macOS `/tmp` (a symlink to `/private/tmp`) the two
  disagree and `sp1-build` exits 1 with only a "must be a parent" message. The
  wrapper resolves the root with `pwd -P` up front so this cannot happen
  silently.
* Renaming the repo-root directory does **not** break it. That is the point.

---

## Why the host path leaks in the first place

Two independent mechanisms, both measured here rather than assumed.

### 1. Cargo's `-Cmetadata` (the crate disambiguator)

`rustc`'s `StableCrateId` hashes the crate name, every `-Cmetadata` value, the
crate kind and the rustc version — **not** a source path. `-Cmetadata` is
generated by *Cargo*, which mixes in package identity and enabled features.
Cargo normally strips the workspace prefix from a path dependency so the hash is
relocatable — but **when the dependency lies outside the Cargo workspace root
that `strip_prefix` fails and Cargo hashes the absolute path instead**.

That is exactly this repo's shape. Reproduced minimally, with a negative
control, at two roots differing in both length and content:

| crate | position | `-Cmetadata` at root A | `-Cmetadata` at root B |
|---|---|---|---|
| `inside_dep` | path dep **inside** workspace root | `75d63e9ff1ea1c00` | `75d63e9ff1ea1c00` — **same** |
| `outside_dep` | path dep **outside** workspace root | `949a4646ba6691d1` | `808d7b8fa321a64d` — **differs** |
| `member` | workspace member depending on both | `41ecdabfdd7e54a4` | `86b4df5e4a315b5c` — **differs** |

The `inside_dep` row is the control: it shows the difference is caused by the
crate's position relative to the workspace root, not by the roots differing.
The `member` row shows the contamination propagates downstream to every crate
that depends on an out-of-workspace crate.

**`--remap-path-prefix` does not fix this.** Re-running the same experiment with
`RUSTFLAGS=--remap-path-prefix=<root>=/canonical` produced *byte-identical
`-Cmetadata` values* — it cannot rewrite a hash Cargo already computed. It also
would not reach an SP1 guest build anyway: `sp1-build` **sets** rather than
appends `CARGO_ENCODED_RUSTFLAGS` (`command/local.rs`, `command/docker.rs`), so
ambient `RUSTFLAGS` is discarded. The only supported channel is `BuildArgs
.rustflags`, which is appended in `command/utils.rs::get_rust_compiler_flags` —
and it still cannot touch `-Cmetadata`.

### 2. Literal absolute paths embedded in the ELF

This one is not in the `-Cmetadata` story at all, and it is why byte *length*
moves too. A non-canonical guest ELF contains the absolute source paths of the
out-of-workspace parity crates (panic-location strings), plus absolute
`~/.cargo/registry`, `~/.cargo/git` and toolchain paths:

```
/example/checkouts/covenant-shielded-pool/tools/apnt-import-created-note-rust-parity/src/relation.rs
/example/home/.cargo/registry/src/index.crates.io-.../libcrux-ml-kem-0.0.10/src/vector/portable/sampling.rs
```

Measured on `import-v1`, non-canonical local builds of the same commit:

| host checkout path | length | ELF bytes |
|---|---:|---:|
| `/example/short` | 14 | 839,920 |
| `/example/checkouts/covenant-shielded-pool` | 41 | 839,984 |
| `<agent worktree>` | 83 | 840,192 |

That is **not** a clean "≈4.7 bytes per character": the measured slopes are
2.37, 4.95 and 3.94 B/char over the three intervals. The ELF carries 4 copies of
the checkout root, and 4 × 69 = 276 ≈ the 272-byte spread from 14 → 83, with the
residue explained by section alignment. Length is a step function of path
length, not a linear one — so **never infer an expected length from a path-length
delta.**

### What the container fixes

Both. Every absolute path that feeds either mechanism — workspace root,
out-of-workspace parity crates, cargo registry, cargo git checkouts, toolchain —
becomes the same string regardless of where the host checkout lives. Measured on
all four canonical ELFs:

* occurrences of `/example/home` (historical host-home pattern): **0**
* occurrences of `/root/program`: 3–5
* occurrences of `/root/.cargo`: 14–29

---

## Result: path independence

Same commit (`cbb8d38`), four host checkout paths of four different lengths,
built through the canonical environment.

| arm | host checkout path | length |
|---|---|---:|
| `cq` | `/example/short` | 14 |
| `main` | `/example/checkouts/covenant-shielded-pool` | 41 |
| `arm3` | `/example/checkouts/third-arm-with-a-deliberately-long-name` | 67 |
| `wt` | `<agent worktree>` | 83 |

All four arms produced **byte-identical** ELFs and identical VKeys for all four
guests. The values are in `CANDIDATES.md`.

Four controls make that result mean something:

* **Same-path determinism control.** Both container target directories were
  deleted and arm `cq` rebuilt from scratch — 145 crates recompiled for the
  transition and import-v1 graphs — producing identical digests. So "the arms
  agree" is not "the build did not re-run".
* **Second determinism control, on the other arm.** The same wipe-and-rebuild
  was repeated on arm `wt` (145 / 145 / 77 / 26 crates recompiled), reproducing
  identical digests. So `wt`'s agreement with `cq` is not artifact reuse either.
* **Negative control.** The *same two* arms were built **without** the canonical
  environment (plain `cargo prove build`). They disagreed, in digest, in length
  and in VKey. So "the arms agree" is not vacuously true of these paths.
* **Control on the digest pin itself.** Pointing `SP1_DOCKER_IMAGE` at a
  well-formed but nonexistent digest makes the build **fail** (`failed to
  resolve reference … not found`). So the pin is honoured by `sp1-build` rather
  than being decorative while the mutable `:v6.3.1` tag is silently used.

| import-v1 build | ELF SHA-256 | bytes | program VKey |
|---|---|---:|---|
| canonical, arm `cq` (len 14) | `5b69827e…c32e60` | 839,464 | `00c29abe…47c7b6` |
| canonical, arm `wt` (len 83) | `5b69827e…c32e60` | 839,464 | `00c29abe…47c7b6` |
| **non-canonical**, arm `cq` | `4a55fddd…be7424d`* | 839,920 | `0007a744…9b28bd` |
| **non-canonical**, arm `wt` | `babeabac…d46847` | 840,192 | `00202b25…079144` |

\* full values in `CANDIDATES.md`.

---

## The single-Cargo-workspace alternative

Assessed, **not implemented**. One workspace containing every guest and every
local parity crate would let Cargo express all package paths relative to a
single root, killing mechanism 1 at the source.

**Blast radius is small in files and large in consequences.**

Files: no directory has to move. It is one new root manifest, three existing
workspace roots dissolved (`apnt-import-created-note-sp1` 9 manifests,
`apnt-private-note-transition-sp1` 5, `apnt-sp1-notecommitment-verifier` 4),
three standalone packages absorbed (both `…-rust-parity` crates and
`apnt-prover-backend-v0`), and five `Cargo.lock` files collapsed to one.

Consequences — **two measured blockers**, both of which change every pinned
guest ELF:

1. **The two SP1 workspaces carry different `[patch.crates-io]` tables.**
   `transition` patches `k256` to `sp1-patches/elliptic-curves`; `import` does
   not. A workspace has exactly one patch table. `k256 v0.13.4` is in the import
   guest's compiled graph today (it appears in the build log), so merging would
   put a *different, SP1-accelerated* `k256` into the import guests.
2. **Shared dependencies resolve to different versions.** `import` locks
   `aes 0.9.1`, `transition` locks `aes 0.9.2` — semver-compatible, so a single
   lockfile unifies them and changes the import guests' dependency graph.
   (Visible in the ELFs: the canonical import ELFs embed `aes-0.9.1` paths, the
   canonical transition ELF embeds `aes-0.9.2`.)

So the reorganisation does not avoid a re-pin; it **forces a strictly larger
one** — every import guest changes for reasons unrelated to paths.

One further limit, **predicted from the string evidence but not measured**: a
single workspace would make the ELF independent of the *checkout* path, but the
14–29 embedded `~/.cargo/registry` paths per ELF come from crates outside any
workspace and stay absolute. They vary with `CARGO_HOME`/`$HOME`, so the
artifact would still not reproduce across machines or users. The container
removes that too.

---

## `vkey-probe`

Each pinned prover `include_elf!`s its own guest, so none of them can report the
identity of an ELF built somewhere else — which is exactly what a
path-independence check needs. `vkey-probe` reads a guest ELF **from a path** and
prints its SHA-256, byte length and program VKey as JSON.

It calls `apnt-prover-backend-v0::program_identity`, the repo's existing
reviewed wrapper around SP1 `setup()`, rather than opening a second route to the
SP1 client. `setup()` derives a verifying key and constructs no proof.

```sh
cargo build --release --manifest-path tools/sp1-canonical-guest-build/vkey-probe/Cargo.toml
tools/sp1-canonical-guest-build/vkey-probe/target/release/apnt-sp1-guest-identity-probe <elf>...
```

Roughly 17 s per ELF.

For separately briefed offline qualification, rebuild this utility from its
unchanged source with `--offline --locked --release` and a fresh isolated
`--target-dir`. Supply a private copy of the measured lock-selected Cargo cache
and its required Go FFI dependencies through the qualified host transport.
Retain the resulting executable's path, SHA-256 and length with the producer
evidence. An earlier passing build receipt does not establish that a temporary
binary still exists. Missing binaries must be rebuilt before guest comparison;
they never authorize repinning or substituting a different identity utility.

The existing Chipnet wrapper also accepts an opt-in offline transport:

```text
canonical-guest-build.sh CHECKOUT pool-aggregate-chipnet-zero-value-rev3 OUT --offline-cache PRIVATE_CACHE
```

The three positional arguments, trusted builder and guest anchors are unchanged.
The cache must be a fresh private owned physical directory. The embedded Docker
shim admits only the expected compiler probes and exact guest Cargo command,
uses `--network=none --pull=never`, replaces shared Cargo volumes with the cache's
private physical `registry` and `git` subdirectories and selects an empty private
Docker configuration at the unchanged local socket. It preserves the image's
`/root/.cargo/bin` tools; mounting a cache over `/root/.cargo` hides `cargo`.
This interface supplies transport controls; complete installation/cache
qualification and two independent ELF/length/VKey comparisons remain separate
producer obligations. It grants no proving, setup generation or publication.
