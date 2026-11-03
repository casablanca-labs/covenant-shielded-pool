# Covenant Shielded Pool

Covenant Shielded Pool is a shielded pool built with covenants that runs under current Bitcoin Cash rules with no consensus change. The intent is public review, then eventual adoption into consensus by Bitcoin Cash nodes through the community CHIP process and node implementations. No adoption or activation date is promised.

v0.5.0 is the current source baseline. Development happens in a private working repository. Selected source and evidence follow here by milestone, with the harness at Milestone 3.

Start with [how the pool works](docs/how-the-pool-works.md), the [overview](docs/overview.md), [acceptance criteria](docs/acceptance-criteria.md), and [release contract and evidence map](docs/release-contract.md). The [protocol specification and full original/published digests](docs/spec/README.md) state the frozen requirements. The [threat model](docs/threat-model.md) states the privacy and custody limits. [Shared pools and reference-pool recognition](docs/shared-pools-and-recognition.md) includes a documentation-only draft for comment. [Earlier phases](docs/phase-1-and-2-closeout.md) records their approved close-out. These documents describe requirements and remaining work; their presence does not complete a milestone or establish publication for comment.

This source includes the canonical host relation, statements, trees, frontiers, ranges, transaction codec, genesis and settlement history, covenant sources, and selected Go and Rust proof and verifier tools. Source presence does not establish that the APNT shielded pool target is implemented or that a private transfer is ready for use.

The setup is disclosed, simulated, single-party zero-value test material. Chipnet only. These tests do not certify production setup, anonymity or proof soundness. Wallets retain their secrets, spending authority and acceptance decisions. Relay acceptance, chain inclusion, wallet acceptance and spendability are separate facts.

## Check the release identities

Some frozen data and source files were relabelled for publication: local build paths, internal folder labels and record IDs were replaced with neutral labels. Their file fingerprints changed and are listed beside the frozen originals; their cryptographic identities (circuit ID, verifying key, aggregate program, verifier graph and covenant bytecode) did not.

After installing the declared Node and pnpm versions and running `pnpm install --frozen-lockfile --ignore-scripts`, use:

```sh
pnpm check:identities
```

This non-proving command builds the JavaScript host and prints PASS/FAIL for each identity in [identity-manifest.json](identity-manifest.json): the circuit ID (the published revision-3 serialized R1CS digest and size), the action verifying key and its derived profile, the reassembled reference verdict-factory covenant bytecode, and the aggregate ELF digest and program VKey recorded in the pinned canonical build and verifier graph. Each entry names its source of truth. Wrong-profile and wrong-network controls must fail their selection checks; the command reports PASS when each expected refusal occurs. Other selected profiles and networks are rejected.

Rebuilding the guest from published source does not yet reproduce the recorded guest inputs (Chipnet: three Cargo manifests and core/src/tests.rs differ; local: the original source commit is unavailable). `pnpm check:identities` verifies published bytes, not a rebuild.

The verifying key is checked against its published bytes and cannot be re-derived from the simulated setup. No setup or proof is run. Circuit compilation, hashing actual R1CS/ELF files, deriving the aggregate program VKey, installed-runtime checks and setup qualification remain explicitly UNRUN by this command. A metadata match does not establish these runtime facts or a live transfer. `pnpm test:release-identities` exercises identity mutations and CLI refusals after the build; `pnpm test:identities` retains the reference covenant checks.

## Build and check

Use Node **20.19.4** and pnpm **9.0.0**. Node 20.19.4 is the runtime used by the recorded successful JavaScript checks on macOS arm64. The retained `.nvmrc` declares 22.22.3; that version has not been validated here. Select 20.19.4 explicitly rather than using an unqualified `nvm use`.

Install Node from its [versioned distribution](https://nodejs.org/dist/v20.19.4/) and verify its published checksums, then install the exact pnpm version using [pnpm's npm installation method](https://pnpm.io/installation#using-npm):

```sh
node --version                 # v20.19.4
npm install --global pnpm@9.0.0
git clone https://github.com/casablanca-labs/covenant-shielded-pool.git
cd covenant-shielded-pool
node scripts/rehearsal-check.mjs
```

No private package registry or private development checkout is needed for the JavaScript command. It installs from the frozen lockfile with lifecycle scripts disabled, then runs `pnpm build`, `pnpm typecheck`, `pnpm test:identities`, `pnpm test:rehearsal`, and `pnpm test:build-metadata`, stopping at the first failure. The existing Vitest file selection, single worker and limits remain unchanged; the identities group is also included in the rehearsal group. To diagnose or rerun a failed step, use that individual command. A successful run covers these declared JavaScript checks only.

[Proof and verifier material acquisition](docs/rehearsal/proof-material-acquisition.md) gives public toolchain sources, exact versions, separate dependency acquisition and offline native host builds, and the canonical two-clone guest comparison. Native input-dependent tests and guest equality need their own evidence. Some retained consumers still lack public inputs or runtime bridges. Missing, excluded or unrun coverage is never a pass or a reason to weaken a check. Do not start a prover as part of these commands.

Real secrets, keys, seeds, private witnesses, wallet files, openings and local operational state do not belong in this repository. Cryptography, signatures, frozen vectors and proof trust anchors must not be changed to pass validation.

Publication and consensus adoption remain separate decisions. The final open-source release is intended to be complete under MIT, with no withheld validation dependency.

Package names and a frozen domain tag keep the earlier working name `bch-cloak` until a later release.
