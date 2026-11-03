# apnt-pool-ceremony

Groth16 (gnark v0.16.3, BN254) phase-2 ceremony tooling for the APNT shielded
pool: a pinned Powers of Tau import, a sequential coordinator, a contributor
command, a standalone transcript verifier, and a one-command simulated re-run.
Item ENG-300, under ARCH-141.

**Simulated ceremonies are zero-value tests only.** In a
`simulated-single-party` ceremony the project runs every contribution. It
could keep the randomness and forge proofs under the keys. A Chipnet pool on
such keys is an explicitly labelled zero-value test. Its testers are told the
project could forge proofs. Mainnet requires a permissionless multi-party
ceremony for any setup-backed proof system, and the proof-system spec's
HUM-51/52 requirement still applies (the frozen APNT shielded pool v1 specification,
settlement-custody spec, "No setup holder guards pooled value").

Tested on small test circuits and measured on action-shaped test circuits
up to 2^22 (ENG-331). No Setup of the pool action circuit has been run with
this tool; task 5.1c is that run (see below).

## Why here, and why Go

The tool lives beside the pool action circuit (`tools/apnt-pool-action-circuit`)
and uses the same gnark v0.16.3 and gnark-crypto v0.21.0 (ENG-367, the fix for
gnark advisory GHSA-3mvx-pp85-pm65). Phase 2 is gnark's own
`backend/groth16/bn254/mpcsetup`, so the keys come from the library the action
circuit compiles with. There is no second implementation of the setup
mathematics. `TestToolRecordMatchesGoMod` (here) and
`TestGnarkVersionsMatchGoMod` (in the circuit module) fail unless both modules'
`go.mod` require exactly the versions the transcript's tool record names. The
verifier refuses a transcript whose tool record differs from its own, so a
transcript made on another gnark does not verify. The seal-era gnark tools
(`tools/apnt-child-circuits-cost`, `tools/apnt-successor-child-circuits`) stay
on v0.15.0; this tool no longer shares their versions.

## Commands

```sh
go build -o bin/ ./cmd/...

# One command after an R1CS change: phase 2, seal, anchored re-verify by the
# standalone verifier (not an independent implementation; see below). All
# phases in one process; <out>.work holds the coordinator's state between
# them and is removed once the ceremony verifies.
bin/apnt-pool-ceremony rerun \
  --ptau ppot_0080_23.ptau --ptau-pin sha256:<hex> \
  --ptau-source "PSE Perpetual Powers of Tau, contribution 0080, prepared" \
  --r1cs action.r1cs --label <circuit label> --out <new empty dir> \
  --ceremony-id <id> [--contributions 3] \
  --beacon <hex, ≥ 32 bytes> --beacon-source "<what it is and its byte order>"

# The same, one phase per process (see "Phases and processes").
bin/apnt-pool-ceremony rerun --phase init --ptau F --ptau-pin P --ptau-source S \
  --r1cs F --label L --out <new empty dir> --work <new empty dir> --ceremony-id ID
bin/apnt-pool-ceremony rerun --phase contribute --out D --work W   # once per contribution
bin/apnt-pool-ceremony rerun --phase seal --ptau F --ptau-pin P --out D --work W \
  --contributions N --beacon HEX --beacon-source S
bin/apnt-pool-ceremony-verify --transcript D/transcript.json --ptau F --r1cs F \
  --expect-phase1-pin P --expect-beacon HEX --json

# All of that under the prover lock, a memory floor and RSS/swap trips, with
# per-phase measurements; and the pinned task 5.1c run built on it.
scripts/run-phased.sh OUT-ROOT --ptau F --ptau-pin P --ptau-source S --r1cs F \
  --label L --ceremony-id ID --contributions N --beacon HEX --beacon-source S
scripts/run-5-1c.sh start OUT-ROOT R1CS EXPECTED-R1CS-SHA256        # init, contributions
scripts/run-5-1c.sh seal OUT-ROOT R1CS EXPECTED-R1CS-SHA256 BEACON-HEX BEACON-SOURCE

# Standalone verifier. VALID (exit 0) needs both out-of-band anchors;
# without either the verdict is CONSISTENT-UNANCHORED (exit 3). A release
# gate also passes --expect-r1cs-sha256, the circuit's digest from the
# proof-system record; without it the circuit is whatever the transcript
# names (see "Which entry points anchor the circuit").
bin/apnt-pool-ceremony-verify --transcript <dir>/transcript.json \
  --ptau <file> --r1cs <file> --expect-phase1-pin P --expect-beacon HEX \
  [--expect-r1cs-sha256 HEX] [--json]

# The ENG-440 checks alone, on a ceremony sealed and verified before them:
# the phase-1 import with its non-degeneracy checks, the Randomize-hint mask
# location and the BSB22 mask check on the published proving key. Not a
# ceremony verification (see below).
bin/apnt-pool-ceremony-recheck --transcript <dir>/transcript.json --ptau <file> \
  --r1cs <file> --expect-phase1-pin P --expect-r1cs-sha256 HEX \
  --expect-proving-key-sha256 HEX

# A remote contributor answers a challenge message file.
bin/apnt-pool-ceremony contribute --challenge in.bin --out out.bin --id <name>

# Phase-1 utilities.
bin/apnt-pool-ceremony phase1-probe --url <.ptau URL>   # sampled evidence only (or --file F)
bin/apnt-pool-ceremony phase1-import --ptau F --ptau-pin P --domain N
bin/apnt-pool-ceremony hash --file F
bin/apnt-pool-ceremony compile-test-circuit --circuit cubic|chain|committed --size N --out F
# A test circuit with a reference R1CS's per-constraint shape (wires, terms per
# side by coefficient class and size, commitment bases), N constraints.
bin/apnt-pool-ceremony compile-test-circuit --circuit shaped --size N --like REF.r1cs --out F
bin/apnt-pool-ceremony describe-r1cs --r1cs F   # digest and shape
bin/apnt-pool-ceremony write-toy-ptau --power P --out F   # INSECURE test fixture
```

`rerun` refuses a non-empty output directory, so an earlier ceremony is never
overwritten. It can only produce `simulated-single-party` transcripts. The
provenance is a constant in the `rerun` package, not a flag.

## Phases and processes

A re-run is four phases. Each can run as its own process, so no process
holds more than its own step needs, and they pass their results on disk:

| phase | does | reads | writes |
| --- | --- | --- | --- |
| `init` | pinned phase-1 import for the R1CS's domain; gnark's `Phase2.Initialize` | `.ptau`, R1CS | open `transcript.json` (ceremony dir); initial state and evaluations (work dir) |
| `contribute` | one automated contribution, verified and recorded | transcript, latest state | `phase2-NNNN.bin`, transcript |
| `seal` | pinned phase-1 re-import, checked against the transcript; seal with the beacon | `.ptau`, transcript, latest state, evaluations | `proving.key`, `verifying.key`, `keys.meta.json`, sealed transcript |
| verify | the standalone verifier's replay, anchored | `.ptau`, R1CS, ceremony dir | its report |

The work directory is the coordinator's own state between phases:
`work.json`, the initial state `phase2-0000.bin`, and `evaluations.bin`
(gnark's `Phase2Evaluations`, which gnark does not serialize; raw points).
`work.json` binds it to one ceremony (id, root challenge, R1CS, phase-1
parameters, initial-state digest) and records each file's SHA-256 and
length. Every phase refuses a work directory from another ceremony or a file
whose digest differs (`WORK_MISMATCH`), and reads the evaluations twice, as
the importer reads a `.ptau` file: hash first, decode second.

The work directory is not part of the transcript. The standalone verifier
never reads it: it re-derives the initial state and the evaluations from the
`.ptau` file and the R1CS. A work file edited and re-bound to `work.json`
passes the coordinator and yields keys the verifier refuses
(`TestEditedEvaluationsAreCaughtByTheVerifier`, `SEALED_KEY_MISMATCH`). It
can stall a ceremony, not make one verify.

`seal` and the verifier seal with `transcript.SealCommons`: only [α]₁ (with
the domain's length), [β]₁ and [β]₂, which is all gnark v0.16.3's
`Phase2.Seal` reads, so the τ vectors can be freed first. Nothing is replaced
by another value; if `Seal` read anything left out, it would panic, not seal
other keys. The helper is shared by both sides, so the verifier could not
see a defect in it; `TestSealCommonsSealsTheSameKeys` compares it with
gnark's seal on the full parameters (mutation M26). Both sides stream the
keys through SHA-256 rather than buffer them.

## Verifier verdicts and boundary

The verifier's exit status and verdict are:

| exit | verdict | meaning |
| --- | --- | --- |
| 0 | `VALID` | every check passed, and the transcript's phase-1 pin and beacon equal the `--expect-phase1-pin` and `--expect-beacon` values the caller trusts out of band |
| 3 | `CONSISTENT-UNANCHORED` | every check passed, but at least one anchor was not supplied; the report names the missing ones |
| 1 | `REFUSED` | a check failed; the stable failure code is printed |
| 2 | — | usage error |

`CONSISTENT-UNANCHORED` says only that the transcript is consistent with the
pin and beacon it names itself. Anyone can build such a transcript on a
phase-1 file and beacon of their choosing, so it is not an authoritative
verdict. In Go, `Report.Authoritative()` is true only for an anchored
`VALID`. `rerun` always supplies both anchors, the pin and beacon it was given.

**What a report is bound to (ENG-443, after REV-198).** Besides the fields
it checked, the report carries:

- `transcriptSha256`: the SHA-256 of exactly the transcript bytes the verifier
  read, hashed and parsed from one read. A report names one transcript file.
  The other fields leave some parts of a transcript unreported: the phase-1
  `source` and `file`, which are not checked either, and the phase-2 root
  challenge, which is checked. Without this field, one report would fit every
  transcript that agrees on the reported fields.
- `verifierBuild`: the binary that ran the verifier, from the build records Go
  embeds in it, as `status`, `reason`, `module`, `vcsRevision`, `vcsModified`,
  `gnark` and `gnarkCrypto`. The status is `verified` only if the records name
  this module, unreplaced gnark v0.16.3 and gnark-crypto v0.21.0, a VCS
  revision and `vcs.modified=false`. Otherwise it is `unverified`, with the
  first missing or wrong record as `reason`, and absent records stay empty,
  never guessed.

  Go records no VCS revision in a binary built inside a git worktree (where
  `.git` is a file), in a copy without `.git`, or in a `go test` binary; all of
  these report `unverified`. A build from a clean clone of a commit reports
  `verified` with that commit (`scripts/test-verifier-build-identity.sh`).
  `verified` is the binary's own record, not an authentication of it.

Both fields are additive; existing fields and verdicts are unchanged. A
consumer that binds an archived report must compare `transcriptSha256` with
the transcript it releases and decide which `verifierBuild` it accepts.

Decide on the exit status, or on the JSON `verdict` field, and never on a text
search of the output. As a second line of defence, the complete output of an
exit-3 run (text or JSON, stdout and stderr) never contains the substring
`VALID`, even when the transcript's own freeform fields say it. The ceremony
id, circuit label, contributor ids and beacon source are chosen by the
transcript's author, so each occurrence is written `VAL\u0049D`. In JSON that
is a string escape, and a decoder reads back the transcript's exact value.
Exit-1 output carries no such guarantee: several stable codes contain
`INVALID` (for example `BEACON_INVALID`), and refusal details can quote the
transcript.

The verifier imports no coordinator, contributor or `rerun` package
(`TestVerifierIsIndependentOfTheCoordinator`), and replays the ceremony from
its public inputs rather than trusting coordinator output. It is not an
independent implementation, though. It shares the `ptau` importer and the
`transcript` package (root challenge, initial state, shape guard, state,
message and JSON decoding) with the coordinator, and both use gnark's
`mpcsetup` phase 2. A defect in those shared paths is common to both sides and
the verifier would not catch it.

## What is checked

- **Phase 1** (`ptau`): a `phase1-probe` pass is **sampled evidence, not
  importer acceptance**, and every probe report says so in its `scope` field.
  The probe applies the importer's own version check (only version 1) and
  section-table rule (each required section at most once, the header before
  every point section), and it checks section sizes. It reads only the
  header, the section table and a few sampled points, so the importer can
  still refuse a file the probe passed, for a point the probe did not read.
  Only `phase1-import` establishes acceptance. On import, the whole `.ptau`
  file is hashed and compared with the pin before anything in it is parsed.
  It is hashed again while it is parsed, in case it changes between the two
  passes. Every point is checked: canonical coordinates, not infinity, on the
  curve, and in the subgroup. The vectors must be geometric with one common τ
  (gnark-crypto's `SameRatioMany`, the check `Phase1.Verify` ends with), and
  `[β]₁` must match `[β]₂`. The parameters are truncated to the circuit's
  domain N. Two values that pass all of that are then refused
  (`ptau.CheckNonDegenerate`, ENG-440 after ARCH-238): τ a root of unity of
  the domain, `[τᴺ]₁ = [τ⁰]₁` (`PHASE1_TAU_IN_DOMAIN`), which makes
  t(τ) = 0, every Z element O and soundness fail; and β = −1,
  `[β]₁ = −[1]₁` (`PHASE1_BETA_MINUS_ONE`). With either, the basis element
  of the random mask gnark's `Commit` adds, (β+1)·Lₖ(τ), is O (unless τ is
  exactly ωᵏ), so every proof's BSB22 commitment is a fixed function of the
  committed private values while the proofs still verify. Both values lie
  in phase 1 and γ = 1 in gnark's phase 2, so no phase-2 contribution can
  repair them. The importer does **not** read the file's contribution history
  (section 7) or its Lagrange sections (12–15); gnark's `Phase2.Initialize`
  computes its own Lagrange bases from the τ powers, so sections 12–15 never
  reach the keys.

  **The PSE `ppot_0080_23.ptau` file (ENG-331).** What is and is not
  established, with the evidence in
  `private historical record ENG-331`:

  - Its pin, SHA-256 `05085994…1cb1` (BLAKE2b-512 `952221e6…aca6`), is the
    project's own digest of its download. PSE publishes no digest for the
    prepared files. The file's S3 multipart ETag equals the one PSE's bucket
    serves, so the pin names the bucket's current object; that is not a
    publisher attestation.
  - It carries the contribution history `snarkjs powersoftau verify` needs:
    section 7 holds 62 records with their public keys (58 imported
    Perpetual Powers of Tau contributions, 0078–0080, and the beacon, whose
    hash equals the randao value the PSE README publishes, 2^31 iterations).
    Section 7 is byte-identical in `ppot_0080_14`, `_18` and `_23`.
  - The challenge hashes of records 58–61 equal, in full, the challenge and
    new-challenge BLAKE2b hashes in the published 0078, 0079 and 0080
    attestations. The attestations' own signatures were not checked.
  - `tauG1[1]`, `tauG2[1]`, `alphaTauG1[0]`, `betaTauG1[0]` and `betaG2` of
    the 2^23 file equal the last record's values byte for byte (the equality
    checks `snarkjs powersoftau verify` makes).
  - `snarkjs powersoftau verify` (snarkjs 0.7.6) accepts `ppot_0080_18.ptau`
    ("Powers of Tau Ok!", 2,204 s, 4.2 GiB RSS): every record's proofs of
    knowledge, the beacon's derivation and the challenge chain of the same
    section-7 bytes, plus that file's powers and Lagrange sections. The
    response hashes it prints for records 59–61 equal the 0078–0080
    attestations'.
  - The importer accepts the whole 2^23 file at domain 2^23 (140 s, 9.8 GiB
    RSS under `GOMEMLIMIT=10GiB`): every point of sections 2–6, the common
    ratio and β. Its phase-1 parameters digest is `b0e96f58…dc2b`.
  - Together these establish what `snarkjs powersoftau verify` would about
    sections 2–6 of the 2^23 file: they are the powers of the verified
    chain's final τ, α and β.
  - Not verified: `snarkjs powersoftau verify` on the 2^23 file itself, so
    its Lagrange sections 12–15 are unchecked (unused, see above). It would
    take ≈ 40–55 min and ≈ 6–10 GiB (estimated): ≈ 36.5 min of it is fixed
    in any PSE 0080 file (the 2^28 initial challenge hash and the beacon's
    2^31 iterations). snarkjs itself skips the final response-hash check on
    a truncated file, and 1-of-N honesty is an assumption no check can
    establish.
- **Phase 2** (`coordinator`, `verifier`): the initial state is gnark's
  deterministic `Phase2.Initialize`, plus a root challenge placed in its
  `Challenge` field:

  ```text
  SHA-256("APNT-POOL-v1:ceremony-root" ‖ lp(format) ‖ lp(ceremonyId) ‖
          lp(provenance) ‖ commonsSha256 ‖ r1csSha256)
  ```

  gnark hashes that field into the state, so every contribution's proofs of
  knowledge descend from the root. A contribution is accepted only if all of
  the following hold:
  - the message header matches the ceremony, the next index and the latest
    state's digest;
  - its length prefixes equal the previous state's, a resource guard that runs
    before gnark's decoder allocates;
  - it decodes canonically;
  - its internal challenge is the previous state's SHA-256;
  - gnark's `Phase2.Verify` passes (δ and σ proofs of knowledge, and update
    consistency).

  A refused contribution changes nothing.
- **Seal and keys**: `Phase2.Seal` with the beacon. The proving key is written
  with `WriteRawTo` and the verifying key with `WriteTo`. The verifier re-seals
  and requires that the published digests and the key files both equal the
  re-derived keys. Before that it refuses a re-derived key whose basis
  element for a commitment's random mask is O (`COMMITMENT_MASK_ZERO`).

  **How the mask is identified** (`transcript.LocateCommitmentMasks`).
  gnark v0.16.3's `Commit` appends to every commitment the output of its
  `Randomize` hint, called with no input, and adds the constraint
  mask·1 = mask. From the R1CS alone, before the phase-1 import, the verifier
  requires:
  - the constraint shape, found by ARCH-238's rule, not by index: a committed
    private wire w with a constraint whose L = {w: 1}, R = {wire 0: 1} and
    O = {w: 1};
  - the provenance (IMPL-28, after REV-197): w is the sole output of exactly
    one hint instruction, and that instruction calls hint id
    `transcript.RandomizeHintID` (`0x69c66a53`, the FNV-32a of
    `github.com/consensys/gnark/internal/hints.Randomize`) with no input and
    one output. The R1CS's hint-name record for that id must be present and
    name `Randomize`. `TestRandomizeHintIDIsPinned` fails if gnark's id,
    name, registration or `Commit` call changes;
  - the schedule (IMPL-31, after REV-200). gnark's solver runs only the
    instructions the R1CS's `Levels` lists, level by level, and the file
    supplies `Levels`. The verifier replays gnark's builder
    (`System.AddInstruction`, each blueprint's `UpdateInstructionTree`, on
    fresh blueprint state) over the R1CS's instructions and requires `Levels`
    to equal the result. Every instruction is then scheduled exactly once, in
    gnark's dependency order. A second instruction setting a wire makes the
    replay fail for every blueprint the verifier admits. The sparse (PLONK)
    blueprints are not admitted: an R1CS file can carry one, though gnark's
    R1CS builder never emits one, and a sparse Mul or Add writes its output
    unconditionally while its walk treats an already-set output as an input,
    so the replay would not see it set the mask a second time (REV-205). The
    verifier refuses any R1CS that carries one (IMPL-32). It also requires
    each mask's `Randomize` instruction to sit in a level strictly before
    every other instruction whose walk references the mask wire.

  The refusals are:
  - `COMMITMENT_MASK_MISSING`: a commitment without a mask-shaped committed
    wire, or with a committed-wire layout the basis order cannot be read from;
  - `COMMITMENT_MASK_NOT_RANDOMIZED`: a mask-shaped committed wire without
    that provenance (an ordinary secret input, REV-197's counterexample;
    another hint's output; `Randomize` with an input or two outputs), a
    missing or wrong hint-name record, or a mask referenced in or before its
    `Randomize` instruction's level;
  - `R1CS_SCHEDULE_INVALID`: `Levels` that differ from the replayed schedule,
    such as REV-200's counterexample (the `Randomize` call left out of
    `Levels` and an R1C x·1 = mask run first), instructions whose replay
    sets a wire twice, or a sparse (PLONK) blueprint.

  **What this establishes** [R, source: gnark v0.16.3 `constraint/bn254/solver.go`
  `run()` and `set()`; M: the tests named].
  - For an R1CS that passes, gnark v0.16.3's solver with its default hint
    registry runs each located mask's `Randomize` call in a level before
    every other instruction whose walk references the mask. Any other setter
    of the mask then panics the solver. So a proof it completes carries a
    mask drawn with `crypto/rand`.
  - A walk is what an instruction's `UpdateInstructionTree` reports, and it
    is not every read. gnark's lookup blueprint walks each table entry only
    in the first query that covers it, so a later query can read the mask
    through its table in `Randomize`'s level, before `Randomize` runs, and
    read it unset. The blueprint also caches entry values on the first query
    it executes, so every query over that table then reads 0 for the mask,
    even one walked after `Randomize`. The verifier accepts such a file; the
    queries' outputs are 0 and the mask is still random
    (`TestRev205LookupReadBeforeRandomizeLeavesTheMaskRandom`).
    Two proofs of one witness on an accepted, gnark-compiled circuit carry
    different commitments (`TestRev200HonestMaskIsFreshPerProof`).
  - Each mask's basis element is not O, so the mask reaches the proof's
    commitment. In a circuit compiled by gnark v0.16.3 the mask appears in no
    other constraint, so that element is (β+1)·Lₖ(τ), and the phase-1 checks
    already exclude O [R]. The basis check is the backstop; the hand-built
    toy `fixture.MaskCancelledR1CS` reaches it on a non-degenerate phase 1.
  - The real 5.1c action R1CS (`a042b497…`) passes the schedule check: its
    `Levels` equal the replay [M, IMPL-31 evidence].

  **What it does not establish.**
  - **That the mask is random for a circuit file nobody anchored.** An
    unanchored VALID does not certify mask randomness. The argument above
    reads gnark v0.16.3's solver and blueprints, and the tests cover the
    constructions found so far (REV-197, REV-200). A circuit file from an
    untrusted source could use gnark behaviour this reading misses. The
    control for an untrusted circuit file is the R1CS anchor
    (`--expect-r1cs-sha256`, `Inputs.ExpectedR1CSSHA256`): the digest of a
    circuit the project reviewed and compiled with gnark.
  - That the circuit is the intended one. The mask checks vouch for the
    R1CS the transcript names. Only the anchor ties it to the reviewed
    circuit.
  - That a prover uses gnark v0.16.3's default registry. A prover that
    overrides the `Randomize` id (gnark's `solver.OverrideHint`) or runs
    another gnark is outside this check.
  - That every structural change to gnark's `Commit` fails closed. Only a
    change that drops the constraint shape, the `Randomize` provenance or the
    schedule order is refused. A change that keeps all three, but alters how
    the mask enters the proof, is caught only by the pin test above, and only
    when this module moves to that gnark.
  - Anything about soundness.

  The action-shaped test circuits (`testcircuits.Shaped`) carry one mask per
  commitment built as gnark's `Commit` builds it: a fresh `Randomize` hint
  output, committed last, with its constraint.

  **Which entry points anchor the circuit.**
  - `verifier.Verify` and `apnt-pool-ceremony-verify` refuse a transcript for
    another circuit (`R1CS_UNEXPECTED`) only when given
    `Inputs.ExpectedR1CSSHA256` or `--expect-r1cs-sha256`. The report's
    `anchors.r1cs` records whether it was given; the VALID verdict does not
    depend on it, so existing callers keep their verdicts.
  - `apnt-pool-ceremony-recheck` requires `--expect-r1cs-sha256`.
  - `scripts/run-5-1c.sh` requires `EXPECTED-R1CS-SHA256` and passes it to
    `scripts/run-phased.sh`, which checks the R1CS file against it in the
    shell before any phase and, since ENG-460, passes it to the verifier as
    `--expect-r1cs-sha256`. The verifier checks the file against it itself
    and requires the transcript's digest to equal the file's, so a 5.1c
    VALID is for the expected circuit and its report records
    `anchors.r1cs: true`. The 5.1c runs before ENG-460, revision 2's
    included, checked the file only in the shell, and their reports read
    `anchors.r1cs: false`.
  - `scripts/run-phased.sh` run directly checks the file, and anchors the
    verifier, only when given `--expect-r1cs-sha256`, which is empty by
    default. Without it, its VALID is for whatever circuit it was given and
    `anchors.r1cs` reads false.
  - `scripts/test-verify-anchors.sh` runs `run-phased.sh` on a toy ceremony
    and requires the verifier's report to record all three anchors, and the
    verifier to refuse the same invocation with a wrong R1CS digest.
  - `rerun` takes no expectation.
- **Labels**: the transcript, `keys.meta.json` and the verifier's report carry
  `provenance`, `zeroValueOnly` and a fixed notice. A permissionless
  multi-party ceremony refuses `automated-local` contributions. Because the
  label is in the root, a simulated transcript cannot be relabelled
  multi-party, even with every other field made consistent. The chain breaks
  (`TestFullyConsistentRelabelRefused`; mutation M9b shows that nothing else
  stops it). The label is a bound claim about the ceremony's process. It does
  not prove that any contributor was honest: anyone can run "remote"
  contributors themselves. Under 1-of-N honesty, each contributor relies on
  its own contribution. It can find that contribution's state digest in the
  verifier's report.

The transcript, `keys.meta.json` and contribution message headers are decoded
strictly: unknown fields and anything but whitespace after the one JSON value
are refused (`TRANSCRIPT_FORMAT`, `KEY_METADATA_MALFORMED`,
`MESSAGE_MALFORMED`).

Every refusal carries a stable code (`failure/failure.go`). The tests assert
codes. `scripts/mutation-witness.py` disables checks one at a time in a scratch
copy and requires the tests to fail.

## Task 5.1c: the action circuit's simulated ceremony

`scripts/run-5-1c.sh` runs task 5.1c on `scripts/run-phased.sh`, with the
pinned `ppot_0080_23.ptau` and fixed limits. It is two invocations, so that
the beacon, the hash of a Chipnet block at a height announced before the
start, is known only after the last contribution:

```sh
# 1. Announce a future Chipnet block height H. Then:
scripts/run-5-1c.sh start ~/proof-scratch/pool-5-1c-<date> \
  ~/proof-scratch/pool-5-1b-v0163/keys/circuit.r1cs \
  a042b49793563e5bbd5d335b84e04aa29d01789e96db97ceabbe7a7d39fcd392
# 2. Once block H exists, with its hash in display order:
scripts/run-5-1c.sh seal ~/proof-scratch/pool-5-1c-<date> \
  ~/proof-scratch/pool-5-1b-v0163/keys/circuit.r1cs \
  a042b49793563e5bbd5d335b84e04aa29d01789e96db97ceabbe7a7d39fcd392 \
  <block H hash hex> "Chipnet block H hash, display order, announced <where, when>"
```

Replace the R1CS path and digest with the current action circuit's (its
tool's manifest) after any circuit change. `seal` ends with the standalone
verifier given both anchors and the R1CS anchor, and passes only on exit 0
with verdict `VALID`.
`run-5-1c.sh verify NEW-OUT-ROOT R1CS DIGEST CEREMONY-DIR BEACON` re-runs that
verifier alone later.

Every phase runs with `GOMEMLIMIT=13GiB` and `GOMAXPROCS=4`, with `GOGC`
and `GODEBUG` unset, whatever the calling environment holds: the settings
the estimates below were measured with. The only override is
`RUN_5_1C_GOMAXPROCS=1`, `2` or `3` (fewer threads: slower, never more
memory); any other value is refused. Every phase refuses to start unless
20 GiB of memory is available and 20 GiB of disk is free, and is killed if
its RSS passes 18 GiB. The run holds the machine-wide prover lock and
`~/proof-scratch/.prover.lock`.

`seal` runs only with the shell source `start` ran with (ENG-418): the
checkout must be at the start's commit with a clean `tools/apnt-pool-ceremony`,
the running harness and every `scripts/*.sh`, `run-5-1c.sh` included, must
have the digests `start` recorded in `results/run.json`, `seal` must come
through the same wrapper, and the binaries, R1CS and phase-1 pin must be
unchanged. `scripts/test-harness-binding.sh` tests each of these guards
with a negative, a firing control and a witness.

Expected at 2^23 (**E**; from runs of action-shaped test circuits at 2^20,
2^21 and 2^22 on an Apple M5 Pro with `GOMAXPROCS=4`, extrapolated per
domain doubling, plus the measured extra memory of the action circuit's
R1CS; archive `ENG-331-CEREMONY-RERUN-PREP-20260924.md`):

| phase | wall time | memory with `GOMEMLIMIT=13GiB` | memory with the Go default (for comparison) |
| --- | --- | --- | --- |
| init | 1.6–1.8 h | footprint ≈ 13 GiB, RSS ≤ ≈ 16 GiB | RSS 19.1–22.6 GiB |
| contribute, each of 3 | 3.4–3.7 min | under the limit | RSS 7.8–8.7 GiB |
| seal | 4.7–5.1 min | footprint ≤ ≈ 13 GiB | RSS 16.7–18.3 GiB |
| verify | 1.7–1.9 h | footprint ≈ 13 GiB, RSS ≤ ≈ 16 GiB | RSS 17.7–19.4 GiB |
| whole run | 3.6–3.9 h, plus the wait for block H | | |

Disk: 6.0–6.6 GiB after seal, of which the work directory (≈ 2.4–2.7 GiB) is
removed after `VALID`.

The limit costs no measured time at 2^21 (init 1,366 s against 1,375 s,
verify 1,433 s against 1,426 s at 3 GiB). Under it the footprint stays at
the limit and the RSS 1.20–1.23 times higher: on macOS the RSS counts
freed pages the Go runtime has returned but the kernel has not yet
reclaimed. If the true live heap at 2^23 exceeded 13 GiB, the Go garbage
collector would run continuously (it caps itself at half the CPU) and the
phase would slow rather than grow; the RSS trip still bounds it.

## Message format

Local automated contributors and remote contributors exchange the same bytes:

```text
"APNTCRM1" ‖ u32le(len(header)) ‖ header JSON ‖ gnark Phase2.WriteTo state
```

The header carries the type (`challenge` or `contribution`), the ceremony id,
the provenance, the index, the previous and new state digests, and the
contributor record. There is no network transport yet. A remote ceremony would
move these files over any channel, and the coordinator verifies whatever
arrives.

## Prior work

- `worldcoin/ptau-deserializer` (MIT): read for the `.ptau` layout and the
  Montgomery limb encoding. No code taken. It targets gnark v0.13 and writes
  gnark's then-private phase-1 fields through `reflect`/`unsafe`. gnark v0.15
  and later export `SrsCommons` and `Phase2.Initialize` takes it directly, so this
  tool needs no such workaround.
- snarkjs (GPL-3.0): the `.ptau` format definition. No code taken.
- `succinctlabs/semaphore-gnark-11` and `worldcoin/semaphore-mtb-setup`
  (Apache-2.0): read for the ceremony flow, namely per-index contribution
  hashes for contributor attestation and a coordinator that verifies before it
  accepts. No code taken. semaphore-gnark-11 builds on a gnark fork
  (`p4u/gnark`), not on the pinned v0.16.3.

## Tests

```sh
GOMAXPROCS=4 go test ./...
# The real-file tests run when a Perpetual Powers of Tau file is supplied:
APNT_CEREMONY_PPOT=ppot_0080_08.ptau APNT_CEREMONY_PPOT_PIN=sha256:<hex> go test ./ptau ./rerun
python3 scripts/mutation-witness.py
scripts/measure-rerun.sh <ppot-dir> <out-dir>   # the one-process rerun
scripts/run-phased.sh OUT-ROOT ...               # one process per phase, measured
scripts/test-harness-binding.sh SCRATCH-DIR     # seal's binding to the start's shell source
scripts/test-verifier-build-identity.sh SCRATCH-DIR  # verifierBuild: worktree build vs clean clone
scripts/test-verify-anchors.sh SCRATCH-DIR      # run-phased.sh hands the verifier all three anchors
```

Large files, meaning `.ptau` inputs, phase-2 states and keys, are never
committed. They are referenced by digest.
