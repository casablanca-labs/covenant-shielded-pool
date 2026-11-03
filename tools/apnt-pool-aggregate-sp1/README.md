# Pool aggregate program (SP1), task 5.4 slice 1

The gated runner also accepts a [live single-action input](LIVE-INPUT.md)
(`live-b1`, ENG-559), verified under the existing pinned Chipnet key before
any SP1 step. That adapter was added without changing the guest or pins.

The APNT shielded pool v1 aggregate program: it verifies `B` action proofs
(proof-system registry entry 1 revision 3, gnark Groth16 on BN254 with the
BSB22 commitment, one hashed public input over a 314-byte record) against a
verifying key `vp`, assembles the statement `S` and commits
`runBind32 = SHA-256(S)` as its only public output (ENG-421; revision 2,
ENG-437; revision 3, pad16, ENG-454).

**Revision 3 status (ENG-454, ENG-486).** The core takes 314-byte records
(`RECORD_BYTES`, the amounts at 258). Its accepted runs are under registry
entry 1 revision 3's recorded Chipnet vp (ENG-446), with an action proof of
each of the 18 host positives made under that vp's ceremony proving key
(ENG-486; `fixtures/simulated-ceremony-zero-value-rev3/`). **SIMULATED
SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY**: the project could forge proofs
under those keys, so an accepted run shows the construction and its cost,
never validity. The refusals that are only meaningful beside an accepted run
(a tampered record, swapped proofs, a proof under a δ-rescaled key) run on
them too. Revision 2's frozen fixtures stay as that revision's record and
still carry the verifier's revision-2 differential tests.

Slice 1 is the guest's core and its execution cost. Slice 2a (ENG-510,
below) adds the labelled Chipnet build, its canonical build and pins, and
the gated proving harness slice 2b runs. There is still **no proof of the
aggregate** (see "Not yet").

## Relation

`core/` is the relation, shared by the guest and the host tests; the host
semantics (`packages/protocol-runtime`) are canonical.

1. Parse the input: `u32le(len(vp)) ‖ vp ‖ deployment_id ‖ u16le(B) ‖ (A_k ‖ π_k) × B`
   (`pool-aggregate-input`).
2. `profile_id = SHA-256("APNT-POOL-v1:profile" ‖ u16le(1) ‖ u64le(len(vp)) ‖ vp)`
   over the `vp` the children are verified under, refused unless it is in the
   compiled allowlist, before `vp` is parsed
   (`pool-aggregate-profile-not-allowlisted`). A prover can supply a key, but
   never one the program was not compiled with.
3. Parse `vp` with registry entry 1's topology (revisions 2 and 3): 528 bytes,
   `|K| = 3`, one commitment committing no public input. A revision-1 key
   (13,168 bytes) is refused here even if allowlisted.
4. Assemble `S` with every check of `encodeAPNTPoolStatementV1`, in its order
   and with its failure codes: `1 ≤ B ≤ 65,535`, 314-byte records, the strict
   record decode (`rk` points, amounts, the `wlock_hash` rule), ascending `ad`
   order with equal digests refused, no nullifier or commitment twice.
5. Verify every child: the BSB22 knowledge pairing, then the Groth16 pairing
   with its one public input `x = int_be(SHA-256(A_k)) mod r`, computed here
   from the record placed in `S` and never taken from the prover
   (`core/src/groth16.rs` has the equations). `x` matches the host's
   `deriveAPNTPoolActionPublicInputV1` on its 23 vectors (every quotient
   `⌊int_be(d)/r⌋` from 0 to 5).
6. Commit `SHA-256(S)`: the settlement covenant checks `SHA-256(S)` against
   the verdict token's commitment (`apnt_pool_settlement_v1.casm` check 1;
   design.md, "Settlement and the proof verdict").

**Allowlist.** The default build's allowlist is empty. The labelled Chipnet
build (`program-chipnet-zero-value-rev3/`, ENG-510) allowlists exactly
revision 3's recorded Chipnet vp; the core's `chipnet-zero-value-rev3-profile`
feature compiles it, and the development feature and it refuse to compile
together. The `development-zero-value-test-profile` feature compiles in three
ids: revision 3's recorded Chipnet vp (`ea3d52d7…`; SIMULATED SINGLE-PARTY
SETUP - ZERO-VALUE TEST ONLY), which carries the accepted runs, and two
development ids of revision 2 that carry refusal cases only: the revision-2
action circuit's own development key (`b41bf776…`, R1CS `25d3f54d…`, with one
proof, of REL1's 396-byte record) and a STAND-IN key of the same public shape
(`f324e6aa…`) whose 17 proofs prove only `x = int_be(SHA-256(A)) mod r` for
their 396-byte records. All three are forgeable (the revision-2 keys are
`DEVELOPMENT ZERO-VALUE — toxic waste not destroyed; forgeable; never for
value`); no canonical build enables the feature. Each build keeps its label
in its ELF (`profile::COMPILED_BUILD_LABEL`), and the runner refuses to run a
case on an ELF that does not carry that case's build label.

**Where it refuses what gnark accepts.** A proof point at infinity. gnark
decodes one and `Verify` then refuses it (every such case in
`gnark-reference-v2.json`); refusing at decode never admits a proof gnark
refuses.

## Slice 2a: the labelled Chipnet build, its canonical pins and the proving harness (ENG-510, R-468)

**The build.** `program-chipnet-zero-value-rev3/` is its own package and
binary (`apnt-pool-aggregate-program-chipnet-zero-value-rev3`) compiling the
same source as `program/` with the core's `chipnet-zero-value-rev3-profile`
feature: its compiled allowlist is exactly `ea3d52d7…`, registry entry 1
revision 3's Chipnet zero-value vp (528 B, SHA-256 `35c2bdb2…`). It is a
distinct program with its own key, and its name, Cargo metadata and ELF carry
the label **SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY; never
mainnet, never value**. The default build's allowlist stays empty.

**The pins** (`canonical-build/chipnet-zero-value-rev3-canonical-build-v1.json`,
held to its sources by `canonical-build.test.ts`): built by
`tools/sp1-canonical-guest-build` (`pool-aggregate-chipnet-zero-value-rev3`;
`--workspace-directory` the repository root; image pinned by digest) from two
checkout paths of 56 and 105 characters, byte-identical:

| build | ELF SHA-256 | bytes | SP1 program key |
|---|---|---:|---|
| Chipnet (pinned) | `46092a6935692fb202ed995d49e90a9f5e46eb3f107d56eb0f491dea9e7ce601` | 443,800 | `00a69d739feae9fecf1ad3db30a73f967912fda951c849e374492f1a14fd7fed` |
| default (control) | `875d1658f168359ae43a35ad1795e623b13f0dfefb1cec4733ee5cac7c7e6aa2` | 127,848 | `006d0956bffbd2bc2729c0eea170a37f147bcf7a0493ddc0da15896614c8781a` |

The program keys come from SP1 `setup()` alone (the `vkey-probe`; about 17 s
and 7.8 GB peak each); no proof was constructed. The pins hold only while the
guest's compiled inputs (the workspace manifest and lock, `core/`, `program/`,
`program-chipnet-zero-value-rev3/`) are byte for byte the source commit's;
`canonical-build.test.ts` fails otherwise. **Controls, recorded in the pin
record:** a plain (non-container) build also agrees across those two checkout
paths, because this workspace has no dependency outside its Cargo root and its
ELF embeds no checkout path; two-path agreement alone therefore does not show
what the container adds for this guest. A plain build with another
`CARGO_HOME` does move (29 embedded host-home source paths), and the canonical
ELF embeds no host path: the container is what makes it independent of the
host home and compiler.

**Execute only, canonical ELFs** (`scripts/execute-matrix.sh --canonical`,
which refuses any Chipnet ELF but the pinned one; 2026-09-27, `1db3399b`,
clean; SP1 6.3.1 light client; under the prover flock): all 15 cases met their
expectations. The Chipnet build accepted B = 1 (6,902,618 instructions,
223 MiB) and B = 17 (75,793,376, 1,580 MiB) and the three v5 statements
(below), each committing exactly the host's `runBind32`; it refused the
pairing negatives (a tampered record, swapped proofs, a proof under the
δ-rescaled key, a replaced knowledge proof, a second stand-in Setup's proof)
with their codes, and refused at the allowlist the revision-2 action circuit's
key, the revision-2 stand-in key, a second stand-in key and the δ-rescaled
Chipnet key, each with a proof that verifies under it (14,335 instructions).
The default build refused the Chipnet vp at the allowlist. Every refusal
exited non-zero and committed nothing.

**v5 run vectors** (`fixtures/pool-aggregate-statement-vectors-v5.json`): the
same records under the current no-meter Chipnet deployment id (`d4853408…`),
the id the shipped settlement covenant checks `S` against. v4's id
(`9e7af816…`) carries the retired meter category, so no current settlement
covenant can settle a v4 statement. B = 1 (REL1) and B = 16 can be settled;
B = 17 exceeds the settlement input's 10,000-byte limit and is kept for the
aggregate's cost. Slice 2b proves v5 B = 1 and B = 17.

**The proving harness** (`scripts/aggregate-proof-runner.sh`, written here,
run by slice 2b; `src/prove.rs`, the runner's `prove` feature). `dry-run`
builds a fresh `--locked` runner with the feature and executes the guest;
`prove` makes one SP1 setup and one Groth16 proof (the wrap through SP1
6.3.1's Docker gnark image) of the pinned ELF over v5 B = 1 or B = 17, from
the clean main checkout on `main` only, under one prover (the shared flock,
the SP1 exclusive marker and `~/proof-scratch/.prover.lock`), a 20 GiB floor
measured again just before the prover starts, a Docker VM of at least 20 GiB,
the SP1 6.3.1 M1 memory profile, and two trips: 30 GiB of the run's host RSS
and 16 GiB of swap growth. `test/aggregate-proof-runner-gate.test.sh` executes
its 15 refusals; none builds or proves.

**Abort and release** (ENG-514, ENG-517, `scripts/prover-supervision.sh`,
sourced by the harness, and `scripts/prover-processes.py`). A keeper forks
the prover as its own session, with a run tag in its environment and
`scripts/docker-shim/docker` first on its PATH, which labels SP1's
`docker run` for the Groth16 wrap. The keeper holds the prover unreaped until
the release, so its process group's id cannot be reused, and it alone signals
that group; any other process of the run is signalled only after a fresh
check that its pid still has the start time and executable recorded for it.
On every exit (success, refusal, prover failure, trip, HUP/INT/TERM) the
harness TERMs the run, waits, KILLs what is left, and confirms by a listing
that no process of it is left. Only then does it remove every gnark wrap or
labelled container in any state (`docker ps --all`, `docker rm --force`) and
confirm that none is left. Measured on Docker 29.5.3 with a sleep container:
killing `docker run` does not stop its container, and a container killed
while `created` was `running` 3 s later (6 of 6), because its start was
already in flight. Removing it at once left nothing (8 of 8). Only then are
the markers removed and the flock closed; otherwise the markers stay and it
exits 3 (`error=prover-reap-unconfirmed`), within the reap's bounds, whatever
survives. `test/aggregate-proof-runner-abort.test.sh` executes that path against
a harmless stub tree, a fake Docker CLI and a fake daemon that answers late,
with a flock observer, eleven negative controls that must fail, and no proving.

## Files

| Path | What |
|---|---|
| `core/` | the relation (`no_std`); `src/tests.rs` the host tests |
| `program/` | the SP1 guest; a refusal prints `apnt-pool-aggregate-refusal: CODE` and panics |
| `program-chipnet-zero-value-rev3/` | the labelled Chipnet build: the same guest source, allowlist exactly the Chipnet zero-value vp (ENG-510) |
| `canonical-build/` | the Chipnet build's pin record, its ELF SHA256SUMS and `guest-inputs.mjs` (the compiled inputs' digest); `canonical-build.test.ts` holds the record to its sources |
| `fixtures/pool-aggregate-statement-vectors-v5.json` | the host's accepted runs under the current no-meter Chipnet deployment id: what slice 2b proves |
| `scripts/aggregate-proof-runner.sh`, `runner/src/prove.rs` | the gated proving harness and the runner's `prove` feature (slice 2b runs them); `test/aggregate-proof-runner-gate.test.sh` its refusals |
| `scripts/prover-supervision.sh`, `scripts/prover-processes.py`, `scripts/docker-shim/docker` | the harness's claims, prover keeper and session, trips, reap and ordered release, the run's membership and identity-checked signals, and the shim that labels the wrap's container (ENG-514, ENG-517); `test/aggregate-proof-runner-abort.test.sh` and `test/aggregate-proof-runner-abort/` its abort path |
| `runner/` | execute-only runner, one case per process; its proving path exists only with the `prove` feature |
| `gnark-reference/` | gnark v0.16.3's side: `prove-batch` (development proofs), `transform` (a proof under a different `vp`), `reference` (decoded points, commitment wires, verdicts, including `x` reduced other ways) |
| `pool-aggregate-vectors.test.ts` | the TypeScript host writes the extra positive (`pool-aggregate-batch-corpus-v2.json`) and the revision-3 codec statement vectors (v3), and pins revision 2's frozen files by SHA-256 |
| `fixtures/simulated-ceremony-zero-value-rev3/` | revision 3 (ENG-486): the action proofs of all 18 host positives under the Chipnet ceremony keys (`proofs/`, SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY), the prove run's records, the δ-rescaled pair (`transform/`) and gnark's revision-3 reference dump; the vp itself is the registry's (`chipnetZeroValueVp`) |
| `fixtures/pool-aggregate-statement-vectors-v4.json` | the host's accepted runs at revision 3 under the recorded vp's profile id: B = 1, 2, 4, 16, 17 and 18 |
| `fixtures/` | host vectors; revision 2's, frozen: `pool-aggregate-batch-corpus-v1.json` and its label, the codec vectors v1 (396-byte records) and the run vectors v2, and `development-zero-value-rev2/`: the action circuit's development key and REL1 proof (`action/`), the stand-in keys and proofs (`standin/`), the δ-rescaled pair (`transform/`), gnark's reference dump; `development-zero-value/vk.bin`: the superseded task-5.1b revision-1 key, kept only as the codec vectors' profile id |
| `scripts/prove-dev-batch.sh` | the gated prover (proving), under development keys or, with `--ceremony R1CS`, the Chipnet ceremony keys; `test/prove-dev-batch-lock.test.sh` tests its locks without proving |
| `scripts/execute-matrix.sh` | builds both ELFs and the runner, executes every case |
| `measurements/execute-only-20260924.json` | revision 1's 16 cases' execution results (a worktree build: measurements, not pins) |

## Fixture disclosure

- `fixtures/development-zero-value-rev2/`: development keys and the proofs
  made under them (`PARAMETERS-LABEL.txt`: DEVELOPMENT ZERO-VALUE — toxic
  waste not destroyed; forgeable; never for value). `action/PROVENANCE.txt`
  and `standin/PROVENANCE.txt` say where each came from: ARCH-235's gated
  development Setup of the circuit this module verifies, and its stand-in
  Setups (R-386, commits `d4113a35` and `1dc710a6`), copied unchanged. No Setup
  ran in ENG-437.
- `fixtures/development-zero-value/vk.bin`: the task-5.1b key of revision 1.
  Its batch proofs, reference dump and transform pair were deleted with their
  consumers in ENG-437; they remain at `d18c51f1`.
- `fixtures/pool-aggregate-batch-corpus-v1.json` (revision 2) and
  `-v2.json` (revision 3) each hold one full action witness whose
  secret-format fields (nullifier key, `ρ`, `rcm` of the inputs, recovery tag
  and key, `α`, membership path) are **synthetic, deterministic, zero-value
  development values** derived from public labels. They are not wallet
  material and not guest input; their consumers are the codec vectors and
  `gnark-reference prove-batch`. Each adjacent `.LABEL.txt` says so and names
  its file's SHA-256, which the vector test checks. v1's bytes are fixed: the
  recorded revision-2 development proof was proven from them. v2's are fixed
  likewise: its entry's revision-3 ceremony proof was proven from them.
- `fixtures/simulated-ceremony-zero-value-rev3/` (ENG-486): action proofs made
  under the Chipnet simulated single-party ceremony's proving key
  (`PARAMETERS-LABEL.txt`: SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST
  ONLY). The project ran every contribution and could have kept the
  randomness, so it can forge proofs under these keys; they never guard value.
  `PROVENANCE.txt` says how they were made. No Setup ran.

## Commands

```sh
# host vectors (APNT_POOL_AGGREGATE_WRITE_VECTORS=1 rewrites them)
pnpm exec vitest run tools/apnt-pool-aggregate-sp1/pool-aggregate-vectors.test.ts

# the relation's host tests (optimised: native pairings are slow in debug)
cd tools/apnt-pool-aggregate-sp1
CARGO_BUILD_JOBS=2 nice cargo test --offline --release -p apnt-pool-aggregate-core -- --test-threads=1
cargo test --offline --release -p apnt-pool-aggregate-core --features development-zero-value-test-profile compiled_allowlist

# gnark's reference side (no proving; reference peaked at 13.2 GB RSS in
# 6.5 s, ENG-437, from gnark decoding the mutated keys: run it under the
# prover lock). Revision 3's dump (ENG-486), with the recorded vp as vk.bin:
go build -o BIN ./gnark-reference
D=fixtures/simulated-ceremony-zero-value-rev3
BIN transform --vk vk.bin --proof $D/proofs/rel1-real-real-deposit-withdrawal.proof.bin --record-hex HEX OUT-DIR
BIN reference --vk vk.bin --alt-vk $D/transform/alt-vk.bin --alt-proof $D/transform/alt-proof.bin --batch $D/proofs \
  --corpus ../../packages/protocol-runtime/test-vectors/apnt-pool-v1-action-circuit-vectors.json \
  --corpus fixtures/pool-aggregate-batch-corpus-v2.json OUT.json
# Since revision 3 it takes 314-byte records, so it cannot regenerate revision
# 2's frozen dump; these are the commands that wrote it, at ENG-437's commit.
D=fixtures/development-zero-value-rev2
BIN transform --vk $D/standin/key-a/vk.bin --proof $D/standin/proofs-a/rel1-real-real-deposit-withdrawal.proof.bin \
  --record-hex HEX OUT-DIR
BIN reference --vk $D/standin/key-a/vk.bin --alt-vk $D/transform/alt-vk.bin --alt-proof $D/transform/alt-proof.bin \
  --batch $D/standin/proofs-a --action-vk $D/action/vk.bin \
  --action-proof $D/action/rel1-real-real-deposit-withdrawal.proof.bin \
  --corpus ../../packages/protocol-runtime/test-vectors/apnt-pool-v1-action-circuit-vectors.json \
  --corpus fixtures/pool-aggregate-batch-corpus-v1.json OUT.json

# proving, gated (the shared prover flock, then the ~/proof-scratch/.prover.lock
# marker as run-phased.sh writes it; 20 GiB floor; RSS and swap trips):
# development keys, or the Chipnet ceremony keys (ENG-486)
scripts/prove-dev-batch.sh KEYS-DIR OUT-DIR ENTRY[,ENTRY...]
scripts/prove-dev-batch.sh --ceremony R1CS CEREMONY-DIR OUT-DIR ENTRY[,ENTRY...]
# its lock and marker protocol, on a scratch clone with stub locks and prover
test/prove-dev-batch-lock.test.sh SCRATCH-DIR

# execute only: the three ELFs, the runner, every case (prover lock, 16 GiB floor)
scripts/execute-matrix.sh OUT-DIR
# execute only on the canonical ELFs (the Chipnet one must equal the pin): the Chipnet and default cases
scripts/execute-matrix.sh --canonical CANONICAL-DIR OUT-DIR

# the canonical builds (ENG-510), from any checkout; compare with canonical-build/*.SHA256SUMS
tools/sp1-canonical-guest-build/canonical-guest-build.sh REPO pool-aggregate-chipnet-zero-value-rev3 OUT-DIR
tools/sp1-canonical-guest-build/canonical-guest-build.sh REPO pool-aggregate-default OUT-DIR
pnpm exec vitest run tools/apnt-pool-aggregate-sp1/canonical-build.test.ts
cargo test --offline --release -p apnt-pool-aggregate-core --features chipnet-zero-value-rev3-profile

# the proving harness (slice 2b; see its header): dry-run executes only; prove needs the main checkout
scripts/aggregate-proof-runner.sh dry-run b1|b17 REPO CANONICAL-CHIPNET-ELF
test/aggregate-proof-runner-gate.test.sh CANONICAL-CHIPNET-ELF SCRATCH-DIR
test/aggregate-proof-runner-abort.test.sh SCRATCH-DIR
cargo test --offline --release -p apnt-pool-aggregate-runner --features prove
```

An ELF built outside the main checkout is path-dependent (AGENTS.md, "Build
artifacts are path-dependent"): `execute-matrix.sh` records its digest as a
measurement, never a pin.

## Measured, execute only, revision 3 under the Chipnet ceremony keys (2026-09-26, `8797aa75`, lane worktree build; ENG-486)

SP1 6.3.1 light client, both ELFs built by `scripts/execute-matrix.sh`, one
case per process, under the prover flock; no proof was constructed. All 22
cases met their expectations: the six positives, under the registry's
recorded Chipnet vp (SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY),
committed the host's `runBind32` (v4 run vectors), and the 16 negatives
refused with their codes, committing nothing, among them a tampered record,
swapped proofs and a δ-rescaled key beside those accepted runs. The record is
in `private historical record ENG-446` (a
worktree build: measurements, not pins).

| B | instructions | gas | child verification | runner peak RSS |
|---:|---:|---:|---:|---:|
| 1 | 6,902,747 | 7,425,492 | 4,281,472 | 223 MiB |
| 2 | 11,205,140 | 12,099,511 | 8,566,000 | 308 MiB |
| 4 | 19,820,406 | 21,456,700 | 17,145,492 | 480 MiB |
| 16 | 71,487,238 | 77,575,594 | 68,585,430 | 1,488 MiB |
| 17 | 75,793,841 | 82,252,998 | 72,871,906 | 1,576 MiB |
| 18 | 80,101,485 | 86,931,470 | 77,161,305 | 1,660 MiB |

About 4.31 M instructions per action (slope B = 1 → 18: 4,305,808) and 2.60 M
fixed (2,596,939), of which parsing the 528-byte `vp` is 2,584,373 and
`profile_id` 5,812: the same cost as revision 2's stand-in key, as a child's
cost depends on the key's shape. The guest input at B = 1 is 1,076 bytes.

## Executed, revision 3 (2026-09-26, lane `lane/pool-pad16` worktree build; ENG-454)

SP1 6.3.1 light client, both ELFs built by `scripts/execute-matrix.sh` from
the revision-3 core, one case per process, under the prover flock; no proof
was constructed. All 13 cases met their expectations: each exited non-zero,
committed nothing and printed exactly its expected refusal, among them a
revision-2 proof refused at the pairing over the same action's 314-byte record
and a 396-byte record refused by the input framing. No case was accepted then:
no revision-3 proof existed before ENG-486. The record is in
`private historical record ENG-454`
(a worktree build: measurements, not pins).

## Measured, execute only, revision 2 (2026-09-25, `c2c626b2`, lane worktree build; ENG-437)

SP1 6.3.1 light client, development-profile ELF, one case per process, under
the prover flock; no proof was constructed. All 20 cases met their
expectations: the six positives committed the host's `runBind32` (v2 run
vectors) and the 14 negatives refused with their codes, committing nothing.
The record is in
`private historical record ENG-437`
and `execute-summary.json` (a worktree build: measurements, not pins).

| B | instructions | gas | child verification | runner peak RSS |
|---:|---:|---:|---:|---:|
| 1 (stand-in) | 6,909,218 | 7,433,874 | 4,287,163 | 228 MiB |
| 1 (the action circuit's own proof) | 6,910,703 | 7,435,228 | 4,288,650 | 223 MiB |
| 2 | 11,213,340 | 12,111,473 | 8,572,542 | 310 MiB |
| 4 | 19,823,315 | 21,468,896 | 17,144,407 | 476 MiB |
| 16 | 71,495,118 | 77,622,415 | 68,576,895 | 1,494 MiB |
| 17 | 75,802,716 | 82,303,776 | 72,864,277 | 1,580 MiB |

About 4.31 M instructions per action (slope B = 1 → 17: 4,305,844) and
2.60 M fixed (2,603,374), against revision 1's 4.50 M and 3.39 M below. Parsing
the 528-byte `vp` (3 G1 and 5 G2 decompressions) is 2,584,349 of the fixed
part and `profile_id` 5,799; the guest input at B = 1 is 1,158 bytes. The
action circuit's own child costs 1,487 instructions (0.035%) more than a
stand-in child on the same record, consistent with scalar-dependent
double-and-add over different key points and commitment wires (R), not with a
cost of the circuit behind the key.

## Measured, execute only, revision 1 (2026-09-24, `d878c4d7`, lane worktree build; history)

The ENG-421 slice-1 guest with 396 byte-sized public inputs, before ENG-437.

SP1 6.3.1 light client, development-profile ELF, one case per process; no
proof was constructed. From `measurements/execute-only-20260924.json`:

| B | instructions | gas | child verification | runner peak RSS |
|---:|---:|---:|---:|---:|
| 1 | 7,899,831 | 8,448,762 | 4,490,811 | 235 MiB |
| 2 | 12,402,959 | 13,276,255 | 8,975,183 | 323 MiB |
| 4 | 21,407,868 | 22,930,676 | 17,941,956 | 490 MiB |
| 16 | 75,473,201 | 80,887,098 | 71,767,818 | 1,519 MiB |
| 17 | 79,978,766 | 85,717,094 | 76,253,154 | 1,605 MiB |

About 4.50 M instructions per action and 3.39 M fixed, of which parsing `vp`
(398 G1 and 5 G2 decompressions with the G2 subgroup checks) is 3.31 M.
Every negative exits non-zero, commits nothing and names its refusal code.

## Not yet

- an SP1 proof of the aggregate (core, compress, Groth16 wrap) and its
  measured time and memory: slice 2b, with the harness above;
- a real proof through the one-transaction verifier (regenerated for the
  pinned key in `tools/pool-onetx-verifier-prototype/pool-key/`) and its
  verdict into the settlement covenant: slice 2b
  (`pool-key-real-proof.test.ts`);
- the verifier-factory binding at genesis (ARCH-193);
- these tools in a validation gate.
