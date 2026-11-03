# Third-party notices

This source repository licenses its original code under the MIT License in
`LICENSE` (Copyright (c) 2026 Casablanca Labs). Dependencies
retain their own terms; the project license does not replace them.

`THIRD_PARTY_NOTICES.json` is the complete versioned inventory: 110 JavaScript
packages, 590 external Rust package/source identities (including five Git
patches), and 21 Go module versions. The Go set includes 14 versions selected in
`go.mod` and seven additional versions recorded in `go.sum` for test/tool closure.
`selectedBy` distinguishes those sets. Optional platform packages, build and test
dependencies, and all three Rust lockfiles are included. Lock membership and
each retained notice ID are recorded for every package; identical texts are
deduplicated by SHA256 in `THIRD_PARTY_NOTICES.txt`.

This inventory describes source dependencies recorded in these locks. It does
not assert which optional crates/features/platforms are linked into an executable.
Dependency archives, toolchains, installed directories and compiled binaries are
not vendored here. Anyone distributing those artifacts must retain the notices
applicable to that artifact and meet its upstream terms, including source terms.
In particular, MPL-2.0 packages (Lightning CSS, dynasm and dynasmrt), Apache notices,
Unicode terms, and bundled upstream notices keep their original scope. No
upstream work is relicensed MIT by this repository.

## Retained text sources

Texts come from the exact cached/published package versions, nested license and
notice files, and root licenses at the published crate VCS revisions where the
archive omitted them. Missing public archives were fetched from npm/crates.io
and verified against their lockfile integrity/checksum before extracting only
package metadata and notices. No dependency scripts or builds ran to collect them.
JavaScript platform packages that declare MIT but omit license files reference
their matching esbuild or Rollup version's retained distribution notice. The
winapi platform support crates reference the shared winapi-rs project notices
from winapi 0.3.9, as identified in their inventory entries.

Some published packages provide a license declaration without a standalone
license file. For those, the inventory marks `declarationOnly`, and the bundle
retains the actual package declaration, available README license sections and
source copyright/SPDX attribution lines. No copyright holder or year is guessed.
Their upstream package/source links remain in the inventory. These entries are:

- `async-scoped@0.9.0`
- `deepsize_derive2@0.1.0`
- `eventsource-stream@0.2.3`
- `impl-trait-for-tuples@0.2.3`
- `mti@1.1.1`
- `r-efi@5.3.0`
- `r-efi@6.0.0`
- `rrs-succinct@0.2.0`
- `stackback@0.0.2`
- `struct-reflection-derive@0.1.0`
- `struct-reflection@0.1.0`
- `tracing-forest@0.1.6`
- `typeid_prefix@1.2.1`
- `typeid_suffix@1.3.0`

## Local and Git patches

`patches/vitest-2.1.9.patch` changes Vitest 2.1.9 exit handling when
`teardownTimeout` is zero: it waits for close and preserves the explicit force
exit. This is a local modification, not an upstream release. Vitest's MIT notice
is retained under its package entry. Its patch and the pnpm patch hash are
unchanged by this licensing update.

The Rust patches below retain the locked upstream revisions and terms. No
dependency version, patch, lockfile, cryptographic relation or trust anchor is
changed by these notices.

| Package | Version | Locked source | Declared terms |
| --- | --- | --- | --- |
| ecdsa | 0.16.9 | `git+https://github.com/sp1-patches/signatures?tag=sp1-skip-verify-on-recovery#1880299a48fe7ef249edaa616fd411239fb5daf1` | Apache-2.0 OR MIT |
| k256 | 0.13.4 | `git+https://github.com/sp1-patches/elliptic-curves?tag=patch-k256-13.4-sp1-6.0.0#476243d31d3ffd9d882d0e5da1f6adaa2a204b62` | Apache-2.0 OR MIT |
| rfc6979 | 0.4.0 | `git+https://github.com/sp1-patches/signatures?tag=sp1-skip-verify-on-recovery#1880299a48fe7ef249edaa616fd411239fb5daf1` | Apache-2.0 OR MIT |
| sha2 | 0.10.9 | `git+https://github.com/sp1-patches/RustCrypto-hashes?tag=patch-sha2-0.10.9-sp1-6.0.0#e48b656ebc806117554bb33c2f8687e4637e37ff` | MIT OR Apache-2.0 |
| substrate-bn-succinct-rs | 0.6.0 | `git+https://github.com/sp1-patches/bn?tag=patch-0.6.0-sp1-6.2.0#af2ee646c36ad80a44a15b91db0a2b648b517b44` | MIT OR Apache-2.0 |

## Updating the inventory

Read all entries in `pnpm-lock.yaml`, all external `(name, version, source)`
identities in the three `Cargo.lock` files, and all `(module, version)` pairs in
the three `go.sum` files (deduplicating `/go.mod` checksum lines). Keep membership
of each lock and Go `go.mod` selection. Retain actual upstream license, notice,
copyright and attribution files, including nested bundled notices, without
editing their bodies. When an archive has no standalone file, use its published
VCS revision or retain its declaration and available attribution explicitly.
Reconcile every package with its notice IDs and recompute lock/text hashes.
Refresh this inventory when the dependency locks or shipped artifact scope change.
