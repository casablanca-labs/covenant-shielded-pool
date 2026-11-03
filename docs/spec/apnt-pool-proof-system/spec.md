# apnt-pool-proof-system

## ADDED Requirements

### Requirement: The child proof system is a profile parameter

The action proof system MUST be selected by a profile parameter. Its
proof-system id and verifier parameters MUST be bound into the aggregate
statement as the 32-byte

```text
profile_id = SHA-256("APNT-POOL-v1:profile" ‖ u16le(system_id) ‖ u64le(len(vp)) ‖ vp)
```

- `system_id` MUST come from this registry: 1 is gnark Groth16 on BN254, 2 is
  Halo 2 with IPA on the Pasta curves. 3 is reserved for Binius64 and is not
  listed until a registry entry names its verifier and its `vp` serialization
  with a parity vector. Until then 3 is invalid, like 0 and every unlisted
  value: the host derivation and the aggregate program MUST refuse it.
  Reserving it keeps the id for Binius64; activating it changes only the
  registry, the host list and the aggregate program.
- `vp` MUST be the complete byte string the aggregate program verifies children
  against, in the one serialization the registry entry names. The entry MUST
  pin that serialization by library version, with a parity vector, before the
  child circuit's first compile.
- The aggregate program MUST compute `profile_id` from the `vp` it actually
  uses, and MUST accept only ids compiled into it. It MUST NOT take a
  `profile_id` or `vp` from prover input unchecked.

No relation or covenant MAY hard-code a single proof system.

#### Scenario: Switching the child system

- **WHEN** a new child system is allowlisted
- **THEN** only the profile, its verifier parameters and the aggregate program
  MAY change; the note statement, the action record and covenants MUST NOT

#### Scenario: Prover supplies the verifying key

- **WHEN** an aggregate program accepts a child verifying key from its prover
  input and writes its digest into `S` without checking it against the
  compiled allowlist
- **THEN** it MUST be rejected, because a prover could verify children under a
  key of its own

#### Scenario: Unregistered system id

- **WHEN** a `profile_id` preimage uses `system_id` 0 or an unlisted value
- **THEN** the aggregate program MUST refuse it

#### Scenario: Reserved system id before its registry entry

- **WHEN** a `profile_id` preimage uses `system_id` 3 before a registry entry
  names the Binius64 verifier and its `vp` serialization with a parity vector
- **THEN** the host derivation and the aggregate program MUST refuse it

### Requirement: Registry entry 1 is gnark Groth16 on BN254

Registry entry 1 MUST be:

- **system**: `system_id = 1`, gnark Groth16 on BN254, pinned at gnark
  v0.16.3 and gnark-crypto v0.21.0;
- **`vp`**: the verifying key's gnark v0.16.3 compressed serialization,
  `(*groth16/bn254.VerifyingKey).WriteTo`, byte for byte. In order:
  - `[α]1 ‖ [β]1 ‖ [β]2 ‖ [γ]2 ‖ [δ]1 ‖ [δ]2`;
  - `u32be(|K|) ‖ K[0..|K|−1]`;
  - `PublicAndCommitmentCommitted` as `u32be(outer)` followed by, for each,
    `u32be(inner) ‖ u64be(index)…`;
  - `u32be(|CommitmentKeys|)` followed by, for each, `G ‖ GSigmaNeg`.

  G1 points are 32-byte and G2 points 64-byte compressed, with gnark-crypto's
  flag bits. For the pool action circuit `|K| = 1 + 1 + 1` (one public input
  and one BSB22 commitment, committing no public input), and `vp` is 528
  bytes;
- **public input**: one BN254 scalar, `x = int_be(SHA-256(A)) mod r`: SHA-256
  over the 314 bytes of the action record `A` with no domain tag, the digest
  read big-endian, reduced mod the BN254 scalar field order `r`. The
  aggregate program, and every other verifier, MUST compute `x` from the `A`
  it holds and MUST NOT take `x`, or an integer for it, from prover input;
- **verification**: gnark v0.16.3 `groth16/bn254` `Verify` with its BSB22
  commitment extension. That is the Pedersen knowledge check under the
  commitment keys; the commitment wire hashed to the scalar field with
  `expand_message_xmd(SHA-256)`, domain `bsb22-commitment`, 48 bytes; then the
  Groth16 pairing check.

This is revision 3 of registry entry 1 (pad16: HUM-84, ENG-454): the circuit
derives each output's `rcm` from `K` and `ρ` and proves the 16-byte pad
packet, over the 314-byte record, with R1CS SHA-256 `7c32a8f6…`. Revision 2
(HUM-80) took the same one hashed public input over the 396-byte record with
the 57-byte AES-256-GCM packet (R1CS `25d3f54d…`); revision 3 keeps its `vp`
topology, and a revision-2 key MUST NOT be allowlisted or accepted as a
revision-3 `vp`. Revision 1 took the 396 bytes of `A` as 396 public scalars
(`|K| = 398`, a 13,168-byte `vp`); it was revised before any `vp` was
allowlisted, and a revision-1 key MUST NOT be allowlisted or accepted as a
`vp`.

Current implementation: registry entry 1 revision 3 is the shipped action
circuit (`tools/apnt-pool-action-circuit/registry.go:77-86`). Its recorded
zero-value Chipnet `vp` is from the completed ENG-483 simulated single-party
task-5.1c re-run (`tools/apnt-pool-action-circuit/registry.go:88-100`,
`tools/apnt-pool-action-circuit/registry.go:129-132`, `tasks.md:562-576`).
The project could forge proofs under it; it MUST guard only explicitly
labelled zero-value tests. Recording it does not allowlist it, establish fund
security or demonstrate a 16 GB fit.

The host, the circuit tooling and the aggregate program MUST agree on this
entry, and on `x` for every record, through shared vectors. A serialization shape vector, which is not a
verifying key, MAY pin the layout before Setup. Its `profile_id` MUST NOT be
allowlisted. Every setup, including every re-run of a simulated setup, yields a
new `vp` and so a new `profile_id`.

Beside each allowlisted `vp`, the registry entry and the pinned deployment
artifact MUST record its setup's provenance:

- the SHA-256 of the sealed ceremony transcript file;
- the provenance label, `simulated-single-party` or
  `permissionless-multi-party`.

A deployed `profile_id` MUST so be traceable to its ceremony and label.

M1 status under ARCH-679: the requirement that each allowlisted vp have its sealed transcript SHA-256 and enumerated provenance recorded in the pinned deployment artifact remains normative and explicitly UNMET in closed artifact revisions 1 and 2. The registry records a transcript digest and a simulated-setup warning, but that warning is not the enumerated simulated-single-party label and registry data is not an artifact field. Neither this status nor the current transitive pins satisfy the deployed-profile refusal scenario. The freeze records the unmet requirement and acceptance obligation, with no value-bearing or production authorization. ARCH-703 is folded into ARCH-679. The operator retains, pre-mainnet, the choice among a new artifact revision, authenticated manifest or amended normative transitive binding, and signs off on the M1 freeze with this gap presented. No choice is made here. Tester disclosure that the project can forge proofs and move pooled Chipnet coins remains mandatory for every deployment; keys from this setup MUST NOT guard mainnet value.


#### Scenario: vp in another serialization

- **WHEN** an aggregate program verifies children under a verifying key read or
  written in any serialization other than registry entry 1's
- **THEN** its computed `profile_id` MUST NOT match, and it MUST be refused

#### Scenario: Public input built from prover data

- **WHEN** an aggregate program takes the public input `x` from prover input
  instead of computing it from `A`, or computes it any other way (the digest
  read little-endian, truncated in place of reduced mod `r`, or hashed over
  other bytes than the 314 of `A`)
- **THEN** it MUST be rejected

#### Scenario: Record and public input disagree

- **WHEN** an action proof's public input is the `x` of one record while the
  relation it proves holds for another
- **THEN** the proof MUST NOT verify for the first record, because the circuit
  binds `x` to the record bytes its relation reads

#### Scenario: Revision-1 key

- **WHEN** a verifying key of registry entry 1 revision 1 (396 public scalars,
  13,168 bytes) is offered as a `vp`, even with its `profile_id` allowlisted
- **THEN** the aggregate program MUST refuse it

#### Scenario: Shape vector allowlisted

- **WHEN** the `profile_id` of the serialization shape vector appears in an
  allowlist
- **THEN** it MUST be refused, because no Setup produced that key

#### Scenario: Deployed profile without setup provenance

- **WHEN** a deployment artifact or registry entry lists a `vp` without its
  transcript digest and provenance label
- **THEN** the deployment MUST be refused

M1 status under ARCH-679: the requirement that each allowlisted vp have its sealed transcript SHA-256 and enumerated provenance recorded in the pinned deployment artifact remains normative and explicitly UNMET in closed artifact revisions 1 and 2. The registry records a transcript digest and a simulated-setup warning, but that warning is not the enumerated simulated-single-party label and registry data is not an artifact field. Neither this status nor the current transitive pins satisfy the deployed-profile refusal scenario. The freeze records the unmet requirement and acceptance obligation, with no value-bearing or production authorization. ARCH-703 is folded into ARCH-679. The operator retains, pre-mainnet, the choice among a new artifact revision, authenticated manifest or amended normative transitive binding, and signs off on the M1 freeze with this gap presented. No choice is made here. Tester disclosure that the project can forge proofs and move pooled Chipnet coins remains mandatory for every deployment; keys from this setup MUST NOT guard mainnet value.


### Requirement: Published proofs carry an explicit zero-knowledge condition

The privacy claims retain their complete existing adversary, assumption and exclusion statements. Registry/profile/key identity, fresh honest prover randomness and CRS well-formedness for each setup-backed layer are distinct conditions. The action CRS checker and release gate exist; the complete claims-check implementation and failing controls required by PS:205–228 are not found in the inspected code. Action CRS evidence supplies no wrapper CRS or wrapper zero-knowledge evidence. Where evidence is unestablished the precondition remains explicitly unestablished. Simulated setup leaves the project able to forge proofs and move pooled research coins; honest-prover privacy conditions do not repair that soundness failure. No production privacy or fund-security certification follows.


Action proofs and any aggregate or wrapper proofs accompanying the three
object-hiding claims of `apnt-pool-privacy-model`, "Pool privacy claims carry
their conditions", MUST be zero knowledge of their private witnesses under
their named proof profiles. The claim is conditioned on the prescribed prover
and fresh, independent cryptographic randomness, and on a well-formed CRS for
each setup-backed layer. Zero knowledge means the proof discloses no private
witness information beyond its public statement; it does not hide that
statement, signatures, tags, funding, timing or deductions from those data.

For registry entry 1 revision 3, the grounding is gnark v0.16.3's Groth16
BN254 prover with its randomized BSB22 commitment extension, and ARCH-238's
CRS analysis and checker (`tools/apnt-pool-ceremony/crscheck/README.md`,
"What it checks" and "The release gate"). The condition includes the
Groth16 prover's fresh randomizers and the committed-wire mask generated
by the pinned solver's default `Randomize` hint. It does not cover an
overridden hint, omitted randomization or another prover implementation.
The complete proving key, verifying key, R1CS and phase-1 parameters MUST
have checked CRS well-formedness, including nondegenerate queries and mask
randomization/provenance, with the check evidence bound to their exact
digests and checker/prover versions. The existing CRS release gate's
`RELEASE-OK` evidence supplies that binding for this entry; a bare key pin,
ceremony label or transcript verification alone does not. A new key or
profile cannot inherit another key's check evidence.

An aggregate/wrapper layer MUST state its own zero-knowledge assumptions,
randomization and setup/CRS evidence separately; checking the action CRS
establishes no such property for that layer. Where the evidence for any
layer is absent, the claims MUST remain explicitly conditional with that
precondition not established, never reported as verified zero knowledge.
This requirement records conditions of the existing construction, not a
claim that this specification amendment ran any proof or CRS check.

Setup trust MUST be disclosed separately from CRS well-formedness. The
current project-run simulated single-party action setup leaves the project
able to forge proofs, so soundness and fund security against it are not
established and its deployments remain labelled zero-value tests. A
well-formed checked CRS can support zero knowledge of an honest prover's
witness even when the setup party knows the trapdoor; this does not repair
soundness. The analysis, checker and release-gate evidence are conditional
grounds for prover privacy, not a production-privacy certification. "No
setup holder guards pooled value" in `apnt-pool-settlement-custody` and the
mainnet gates continue to govern.

#### Scenario: A key pin is substituted for a CRS check

- **WHEN** a profile's privacy statement cites only a key digest or verified
  ceremony transcript as establishing zero knowledge
- **THEN** the claims check MUST refuse that assertion and require
  well-formedness evidence bound to the exact key, R1CS, phase-1 parameters
  and checker/prover versions
- **AND** controls omitting a required digest, using another key's report or
  removing mask randomization/provenance MUST fail

#### Scenario: Child CRS evidence is applied to a wrapper

- **WHEN** a report uses the action CRS check to establish aggregate or
  wrapper zero knowledge, or the wrapper's evidence is missing
- **THEN** the claims check MUST refuse the established-property assertion
  and keep that layer's zero-knowledge precondition explicitly unestablished

#### Scenario: Simulated setup conflates privacy with custody

- **WHEN** a privacy statement uses checked CRS well-formedness to claim that
  the project cannot forge under the simulated single-party setup, or uses
  the forgeability disclosure alone to assert witness leakage
- **THEN** the claims check MUST refuse either inference and retain both the
  conditioned zero-knowledge property and the zero-value/forgeability warning

### Requirement: Every child system carries the invalid-curve delegate-theft negative

Every child proof system, gnark now and Halo 2 or any later one, MUST carry a
named negative for this attack. A delegate holds the witness (`ak`, `nk`, `α`,
not `ask`) and keeps `SEC1c(ak)`, and so the owner tag, `cm` and `nf`. It
supplies an off-curve `y` with the same parity, chosen so that the addition
`ak + α·G` lands on the `x` of `r·G` for an `r` it knows. `rk` then decodes to
`±r·G`, a key the delegate can sign for.

- The production circuit MUST refuse that witness.
- A build with only the on-curve check removed MUST accept it, which shows
  the check is load-bearing.
- A control with the true `y` MUST be refused.

The host corpus cannot carry this negative, because the host takes `ak` as 33
`SEC1c` bytes, so each child system MUST carry its own.

#### Scenario: Circuit without the on-curve check

- **WHEN** a child circuit takes `ak` as coordinates and does not constrain it
  to the curve
- **THEN** the attack witness MUST satisfy it, and the named negative MUST fail
  on that build

#### Scenario: Child system added without the negative

- **WHEN** a new child proof system is proposed for the registry without its own
  invalid-curve delegate-theft negative
- **THEN** its circuit slice MUST NOT be accepted until it carries one

### Requirement: SHA-256 is the only hash

Every in-circuit and in-script hash MUST be domain-separated SHA-256 except for the following existing canonical constructions: (1) x = int_be(SHA-256(A)) mod r; (2) runBind32 = SHA-256(S); (3) the SHA-256 commitment to the canonical ordered statement leaf list; (4) wlock_hash = SHA-256(withdrawal locking bytecode); (5) the verdict factory's SP1 public-values digest, SHA-256(C_0 ‖ … ‖ C_{M−1}) with its top three bits cleared, where the C_j are the ordered runBind32 values; (6) the BCH-defined hashes used by the pool scripts: P2SH32 HASH256(redeem), OP_CHECKSIG's transaction-signature digest HASH256(BCH signing serialization for the signature's sighash type), OP_CHECKDATASIG's SHA-256 of its 32-byte message, and the native BCH EC-Schnorr challenge SHA-256(R.x ‖ SEC1c(P) ‖ h), where h is the opcode's message hash; (7) the verifier graph's OP_SHA256 of the next input's locking bytecode, compared with a pinned digest (inputs 0, 1, 4, 7, 8 and 9 of both pinned graphs); and (8) the verifier graph's OP_SHA256 of the GLV split table (input 1 of both pinned graphs). In the inbox refund branch, OP_CHECKSIG verifies h = HASH256(the BCH signing serialization); the shipped wallet uses sighash type 0x61 (SIGHASH_ALL | SIGHASH_UTXOS). For APNT authorization, the opcode message m = SHA-256("APNT-POOL-v1:dt-auth" ‖ ad ‖ dt_0 ‖ dt_1) is domain-tagged; OP_CHECKDATASIG computes h = SHA-256(m), which the BCH signature verifies. The transaction-signature digest, OP_CHECKDATASIG's extra SHA-256 and the BCH challenge are untagged BCH constructions, not additional APNT tags. All the listed constructions retain their exact prescribed preimages, digest transformations and bytes. Every other protocol hash retains the domain-separation MUST. Any additional untagged protocol hash requires an operator decision; these exceptions grant no such authority. A prime-field hash MUST NOT be adopted without an operator decision recording its effect on script verification and on Binius64 adoption.

#### Scenario: Poseidon proposed to cut constraints

- **WHEN** a slice replaces SHA-256 with a prime-field hash in the action circuit
- **THEN** it MUST stop and report instead of proceeding

### Requirement: Proving is local and within consumer hardware

The shipped child route is gnark Groth16 revision 3 with simulated single-party research keys. Native wallet proof launch is unimplemented and is not deferred by the cited fit-engineering decision. Consumer fit remains an unfulfilled target. Phase 3 measures and discloses complete proving/workflow cost, including key load, machine/key/profile identity, peak host and VM memory, swap growth and wall time; engineering a fit is deferred with no fix promised. Prior measurement/operator exceptions do not establish a 16 GiB fit or repeal the original pre-Setup stop rule. No historical figure is represented as a new measurement.


Each wallet MUST be able to prove its own complete action locally on a 16 GB
consumer machine.

- **"16 GB fit"** means that the complete action proof — the full relation of
  `apnt-pool-note-statement`, with its proving key loaded — completes on a
  machine with 16 GiB of physical memory, or under a hard 16 GiB memory
  limit, with:
  - peak resident memory ≤ 12 GiB;
  - swap growth ≤ 1 GiB.
- The profile MUST state that measured peak memory and the whole-process wall
  time, including key load, for each allowlisted child system.
- The number is unmeasured today. Until it is measured, no document MAY present
  an estimate, an interpolation or a partial circuit's count as a fit.
- A child system that misses the fit MUST NOT proceed to Setup, ceremony or
  deployment. The slice MUST stop and report the number to the operator.

Delegation MAY be offered only as an explicitly labelled privacy disclosure. It
MUST be described as disclosing the witness to the prover, and it MUST NOT
carry spend authority.

#### Scenario: Delegation described as private

- **WHEN** documentation describes delegated proving as hiding the witness from
  the prover
- **THEN** it MUST be corrected

#### Scenario: Estimate cited as a fit

- **WHEN** a document cites the 8–14 GB estimate, or the compiled E5 counts of a
  simplified circuit, as showing that the action fits 16 GB
- **THEN** it MUST be corrected to say the complete action's memory is
  unmeasured

#### Scenario: Complete action misses the fit

- **WHEN** the measured complete action proof exceeds 12 GiB peak RSS or grows
  swap by more than 1 GiB on the 16 GB reference
- **THEN** no Setup or ceremony for that system MUST proceed, and the number
  MUST go to the operator

### Requirement: Host semantics lead

A deterministic host implementation of the action relation MUST exist and be
reviewed before any circuit is compiled against it. Circuit and aggregate
parity MUST be demonstrated on shared vectors with non-palindromic values. An
SP1 guest panic MUST be detected by its exit code.

#### Scenario: Circuit written before host semantics

- **WHEN** a circuit slice starts before the host relation passes review
- **THEN** it MUST be blocked

### Requirement: The Chipnet setup route is decided by a comparable gate

The shipped child route is gnark Groth16 revision 3 with simulated single-party research keys. Native wallet proof launch is unimplemented and is not deferred by the cited fit-engineering decision. Consumer fit remains an unfulfilled target. Phase 3 measures and discloses complete proving/workflow cost, including key load, machine/key/profile identity, peak host and VM memory, swap growth and wall time; engineering a fit is deferred with no fix promised. Prior measurement/operator exceptions do not establish a 16 GiB fit or repeal the original pre-Setup stop rule. No historical figure is represented as a new measurement.


Before any action-circuit Setup, a time-boxed comparison memo MUST weigh Halo 2
children verified in the SP1 aggregate against a permissionless per-circuit
ceremony. It MUST recommend one Chipnet route as a yes/no to the operator, and
MUST NOT presume either answer.

For both routes, the memo MUST contain:

- the complete action proof's peak memory and wall time under "16 GB fit";
- aggregate proving time and peak memory for a batch of at least two children,
  including child verification inside SP1 and the SP1 wrapper;
- a pessimistic engineering estimate to the Chipnet MVP milestone, the first
  funded Chipnet pool settlement with wallet acceptance;
- the trust statement.

For the ceremony route it MUST also contain a ceremony plan and cost covering:

- the phase-1 source;
- phase 2 per circuit;
- transcript verification;
- the coordinator;
- contribution memory and time;
- the target number of contributors;
- the calendar duration;
- that every circuit change voids phase 2.

Where a quantity is not measured, the memo MUST declare an uncertainty band
built from measured components, and MUST apply the stop rules to the band's
pessimistic end.

Stop rules, with `T_H2` and `T_C` the pessimistic time-to-MVP of the Halo 2 and
ceremony routes:

- a route that misses "16 GB fit" MUST NOT be recommended;
- if `T_H2 ≥ 1.8 · T_C`, the memo MUST recommend the ceremony route;
- if `T_H2 ≤ 1.25 · T_C` and both routes fit, it MUST recommend Halo 2 first;
- otherwise it MUST present both, and the operator decides;
- if a band straddles a threshold, it MUST return "undecidable within the time
  box" and name the deciding measurement.

The operator sets the time box when authorizing the memo. Until the operator
adopts a route, development parameters MUST appear only in explicitly labelled
zero-value tests.

#### Scenario: Setup without the gate

- **WHEN** a slice runs an action-circuit Setup for a funded Chipnet pool
  before the operator has adopted a route from the gate
- **THEN** it MUST stop and report

#### Scenario: One verification extrapolated to a batch

- **WHEN** the memo's Halo 2 aggregate figure is extrapolated from a single IPA
  verification without a measured multi-child aggregate or a declared band
- **THEN** the memo MUST NOT make a recommendation on it

#### Scenario: Halo 2 roughly doubles time to MVP

- **WHEN** `T_H2 ≥ 1.8 · T_C` at the pessimistic ends
- **THEN** the memo MUST recommend the ceremony route for Chipnet

#### Scenario: Band straddles a threshold

- **WHEN** an uncertainty band crosses a stop-rule threshold
- **THEN** the memo MUST return "undecidable within the time box" with the
  deciding measurement, and MUST NOT choose

### Requirement: Mainnet needs setup-free proving or two proof systems

Before any mainnet value, the pool MUST have either a setup-free end-to-end
proof pipeline or two independent proof systems verified per batch. The choice
between them MUST follow measurement of both.

#### Scenario: Mainnet deployment on one setup-backed system

- **WHEN** a mainnet deployment relies on a single proof system that needs a
  trusted setup
- **THEN** it MUST be refused
