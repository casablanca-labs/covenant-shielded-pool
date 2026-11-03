# apnt-pool-note-statement

## ADDED Requirements

### Requirement: Pool notes are commitments, not tokens

A pool note MUST exist on chain only as a domain-separated SHA-256 commitment,
plus a 16-byte packet that pads its value:

```text
cm = SHA-256("APNT-POOL-v1:cm" ‖ u64le(v) ‖ O ‖ ρ ‖ rcm ‖ tag)
```

Here `O = SHA-256("APNT-POOL-v1:owner" ‖ SEC1c(ak) ‖ nkc)`, with the
nullifier-key commitment `nkc = SHA-256("APNT-POOL-v1:nkc" ‖ nk)`, and
`tag = SHA-256("APNT-POOL-v1:rt" ‖ K)`. An output's `rcm` MUST be
`SHA-256("APNT-POOL-v1:rcm" ‖ K ‖ ρ)`, from its own `K` and `ρ` (registry
entry 1 revision 3, pad16); a spent note presents the `rcm` its creating
action derived. No token, category, locking script or
other on-chain field MAY identify a note's owner or value. Pooled BCH MUST be
held in token-free pool coins, and no pool coin is associated with any note.

#### Scenario: A note is represented by a token

- **WHEN** a design or implementation represents a private note or its value as
  a CashToken amount or NFT held by, or transferable to, its owner
- **THEN** it MUST be rejected as an architecture regression, because token
  holdings and transfers are public

### Requirement: Canonical encodings are fixed

The host relation, every circuit, the aggregate program and every covenant MUST
use the canonical encodings of `design.md` ("Canonical encodings") byte for
byte:

- values, deposits, withdrawals and fees as `u64le` in `[0, MAX_MONEY]`;
- the pairwise prefix-free ASCII domain tags `APNT-POOL-v1:<name>`;
- points as 33-byte SEC1 compressed;
- the 314-byte action record `A` with its field order and offsets
  (`design.md`, "Action record `A`"): `anchor` at 0, `nf_0` at 32, `nf_1` at
  64, `rk_0` at 96, `rk_1` at 129, `cm_0` at 162, `cm_1` at 194, the 16-byte
  `packet_0` at 226 and `packet_1` at 242, `deposit` at 258, `withdrawal` at
  266, `fee` at 274 and `wlock_hash` at 282;
- the authorization digest
  `ad = SHA-256("APNT-POOL-v1:action-auth" ‖ deployment_id ‖ A)`;
- the 8-byte discovery tag `dt_j` of each output `j ∈ {0, 1}`, outside `A`
  and `S`, and the tag-authorization message
  `m = SHA-256("APNT-POOL-v1:dt-auth" ‖ ad ‖ dt_0 ‖ dt_1)`
  (`apnt-pool-settlement-custody`, "Every output carries a bound
  discovery-tag slot");
- the v1 change and dummy discovery-tag derivation
  `dt = SHA-256("APNT-POOL-v1:dtag" ‖ F ‖ role)[0:8]`, the first 8 bytes of
  the digest, with `F` the output's 32-byte fill key and `role` one byte,
  `0x00` in v1. A payment output's tag is the recipient's FF1 encoding of the
  invoice id, a wallet derivation outside the host (`apnt-pool-receive-recovery`,
  "Every output's discovery tag follows the v1 fill rules");
- the statement
  `S = "APNT-POOL-v1:statement" ‖ deployment_id ‖ profile_id ‖ u16le(B) ‖ A_1 ‖ … ‖ A_B`,
  with records in strictly ascending byte-lexicographic `ad` order (each `ad`
  compared as 32 bytes from the first byte, equivalently as a big-endian
  integer, never as a little-endian integer) and no repeated nullifier or
  commitment. Every field is fixed length: the 22-byte tag, `deployment_id` at
  offset 22, `profile_id` at 54, `u16le(B)` at 86, and record `A_k` at
  `88 + 314·(k − 1)`. `|S|` MUST equal `88 + 314·B` with `B ≥ 1`, and any other
  length MUST be refused;
- the profile id, 32 bytes:
  `profile_id = SHA-256("APNT-POOL-v1:profile" ‖ u16le(system_id) ‖ u64le(len(vp)) ‖ vp)`,
  with `system_id` and `vp` as `apnt-pool-proof-system` defines;
- the output commitment randomness `rcm = SHA-256("APNT-POOL-v1:rcm" ‖ K ‖ ρ)`;
- the packet digest `d = SHA-256("APNT-POOL-v1:pad" ‖ K ‖ ρ ‖ cm)` and the
  16-byte packet `(u64le(v) ⊕ d[0..8)) ‖ d[8..16)`. The tag
  `APNT-POOL-v1:pk` of revision 2's AES-256-GCM packet key is retired and
  MUST NOT be reused.

Shared parity vectors MUST use non-palindromic values.

#### Scenario: A field is encoded differently

- **WHEN** an implementation reorders, pads, length-prefixes or changes the
  byte order of any field of `A`, `ad` or `S`
- **THEN** it MUST fail the shared parity vectors, and it MUST NOT be adopted

#### Scenario: Statement parsed at a shifted offset

- **WHEN** a statement carries a `profile_id` of any length other than 32 bytes,
  or a byte more or fewer than `88 + 314·B`
- **THEN** the host, the aggregate program and the settlement covenant MUST
  refuse it

#### Scenario: Statement with a repeated record or nullifier

- **WHEN** an aggregate statement lists two equal records, records out of
  ascending `ad` order, or one nullifier or commitment twice
- **THEN** the aggregate program MUST reject it

#### Scenario: Records ordered by little-endian ad

- **WHEN** a statement holds X1's two records (ENG-262), whose `ad` values
  over the 314-byte records are
  `9bc47dc11967d7b53790a7119b19829b7bbe22b89125d0a52ad66467cd5c1cab` and
  `fc92b1655d5dd3acc08435a7d38f2ae84b3e9cacef569903d0a5709d86606c50`, in the
  order of `ad` read as little-endian integers, the `fc92b165…` record first
- **THEN** the host, the aggregate program and the settlement covenant MUST
  refuse it, because byte-lexicographic order puts the `9bc47dc1…` record
  first. (Over revision 2's 396-byte records the pair's `ad` values were
  `923b121b…` and `3c91c29d…`, and the two orders ran the other way.)

### Requirement: The host input boundary

Untrusted pool data MUST enter the host semantics only as bytes, through the
strict decoders of the canonical encodings. In-process object inputs come from
trusted code, and the host MUST still canonicalize them defensively. Every
exported host entry point MUST first take a structured clone of its arguments,
and MUST then validate the clone's shape with intrinsic operations only, never
by calling a method of the input.

- Anything the structured clone cannot copy MUST be refused with one stable
  boundary code. That includes a proxy, a function, a symbol, and an accessor
  that throws, whatever the thrown value looks like.
- A host result MUST be a function of the clone's canonical bytes and values,
  never of an input's methods, accessors or prototype.
- A host result MUST report a failure code only from a check the host itself
  made after the clone.
- The package interface MUST NOT export the host's error class or its internal
  helpers.

#### Scenario: Input whose behaviour disagrees with its contents

- **WHEN** an in-process caller passes an object whose methods, accessors or
  prototype report something other than its contents, such as an overriding
  subclass, a getter that answers differently on its second read, or a proxy
  that misreports an array's length
- **THEN** the host MUST answer from the cloned contents or refuse with the
  boundary code, and MUST NOT accept a transition the contents do not support

#### Scenario: Caller-thrown failure

- **WHEN** caller code throws while the host clones its input, including an
  error built to look like a host error
- **THEN** the host MUST report the boundary code, not a code the caller chose

### Requirement: Nullifiers are owner-secret and unique by construction

A note's nullifier MUST be `nf = SHA-256("APNT-POOL-v1:nf" ‖ nk ‖ ρ ‖ cm)`,
where `nk` is known only to the note's owner. For each action:

- output `j` MUST take `ρ_out_j = nf_in_j`, for `j ∈ {0, 1}`;
- the two input nullifiers MUST differ;
- every input nullifier, real or dummy, MUST be inserted into the nullifier
  range records by the settlement.

No other assignment of `ρ` is allowed.

#### Scenario: Payer tries to predict the recipient's nullifier

- **WHEN** a payer holds everything it legitimately learned when creating a
  note: `v`, `O`, `ρ`, `rcm`, `tag`, `K`, `cm` and the packet
- **THEN** it MUST NOT be able to compute that note's `nf`

#### Scenario: A holder of the nullifier-key commitment tries to compute a nullifier

- **WHEN** a party also holds the note's `nkc` and `ak`, enough to form its
  owner tag `O`, but not `nk`
- **THEN** it MUST NOT be able to compute that note's `nf`, because `nf` takes
  `nk`, a SHA-256 preimage of `nkc`
- **AND** the action relation MUST refuse a record whose `nf` is
  `SHA-256("APNT-POOL-v1:nf" ‖ nkc ‖ ρ ‖ cm)`, the nullifier a build that fed
  `nkc` into `nf` would accept

#### Scenario: The commitment presented in place of the nullifier key

- **WHEN** a witness presents a note's `nkc` where its `nk` is required, with
  a record whose `nf` is computed from that `nkc`
- **THEN** the action relation MUST refuse it, because the owner tag it
  derives is over `SHA-256("APNT-POOL-v1:nkc" ‖ nkc)`, not over the note's
  `nkc`

#### Scenario: Faerie gold inside one action

- **WHEN** an action's two outputs both take `ρ` equal to the same input
  nullifier and repeat every other commitment field, producing two equal
  leaves
- **THEN** the action relation MUST reject it, because output 1's `ρ` must equal
  input 1's nullifier and the two input nullifiers must differ

#### Scenario: Faerie gold across actions through a reused dummy

- **WHEN** two actions reuse one dummy input note, and so one dummy nullifier,
  to give outputs the same `ρ` and identical commitments
- **THEN** the second settlement MUST fail, because the dummy nullifier was
  inserted into the range records by the first

#### Scenario: One note in both input slots

- **WHEN** an action names the same input note in both slots
- **THEN** the relation MUST reject it

### Requirement: Dummy notes are complete and indistinguishable

Unused slots MUST be filled with dummy notes of value zero, built as follows.

- **Dummy input.** It has `ask_d ∈ [1, n_G − 1]`, `nk_d`, `ρ_d`, `rcm_d` and
  `K_d` that no one without the wallet's seed can predict: fresh randomness,
  or values derived from the seed. Its `O`, `tag`, `cm` and `nf` are derived
  as for any note. It publishes a re-randomized `rk_d` with a valid owner
  signature. Its nullifier is inserted like any other.
- **Dummy output.** It pays `v = 0` to an owner and `K` that are unpredictable
  in the same sense, with `ρ` given by the index rule and `rcm` derived from
  that `K` and `ρ`. It carries a correct 16-byte packet and a discovery tag
  filled by the v1 fill rules from a key
  bound to its own `ρ`, so a reused counter never repeats it by construction;
  two such 8-byte tags remain equal by accident with probability about
  `2^-64` per pair (`apnt-pool-privacy-model`).
- **Membership.** It MUST be enforced for every input with `v ≠ 0`, and only
  those inputs are exempt from it.
- **Determinism.** Where an action must be rebuildable after restore, its dummy
  values MUST be derived from the seed and a per-action counter, by the dummy
  layout of `design.md` ("Dummy notes"). Within one live wallet store, a
  wallet MUST NOT allocate one counter to two different actions, and a retry
  MUST keep its counter. Across a restore, reuse is improbable but not
  impossible (see the restore contract in apnt-pool-receive-recovery). A
  counter reused for two different actions repeats a dummy nullifier. The
  range records refuse it, which is a liveness failure, not a safety one.

Real and dummy slots MUST be indistinguishable on chain.

#### Scenario: Dummy input claims value

- **WHEN** an input with `v ≠ 0` has no membership path in the tree under the
  action's anchor
- **THEN** the relation MUST reject the action

#### Scenario: Dummy nullifier left out of the range records

- **WHEN** a design settles an action while inserting only the nullifiers of
  real inputs
- **THEN** it MUST be rejected, because it lets `ρ` repeat across actions and it
  makes dummy slots visible

#### Scenario: Retried action rebuilds its dummies

- **WHEN** a wallet that derives its dummies from the seed retries an action
  under the same per-action counter
- **THEN** it MUST reproduce the same dummy values, and so the same dummy
  nullifiers

#### Scenario: Dummy slot visible on chain

- **WHEN** a dummy slot differs from a real one in any published field length,
  signature presence, packet length, discovery-tag presence or distribution,
  or range insertion
- **THEN** it MUST be treated as a privacy defect

### Requirement: Actions are fixed-shape and self-contained

Every pool state change MUST be an action with exactly two input slots and two
output slots. Each action MUST prove the following by itself, about its
314-byte record `A`, with one public input
`x = int_be(SHA-256(A)) mod r` that the circuit binds to the record bytes it
reads (`apnt-pool-proof-system`, registry entry 1):

- membership at depth 32 under `anchor` for each input with `v ≠ 0`;
- nullifier derivation, with distinct input nullifiers;
- ownership and `rk` derivation for each input slot (see "Spend authority stays
  with the owner");
- the `ρ` index rule;
- that every note value, `deposit`, `withdrawal` and `fee` lies in
  `[0, MAX_MONEY]`;
- exact balance over the integers:
  `Σ v_in + deposit = Σ v_out + withdrawal + fee`;
- for both outputs, that `cm_j` commits an `rcm` derived as
  `SHA-256("APNT-POOL-v1:rcm" ‖ K ‖ ρ_out_j)` from the same `K` whose `tag`
  is in `cm_j`, and that `packet_j = (u64le(v_j) ⊕ d_j[0..8)) ‖ d_j[8..16)`
  with `d_j = SHA-256("APNT-POOL-v1:pad" ‖ K ‖ ρ_out_j ‖ cm_j)`, as decided
  by the proof-system requirement. The packet has no MAC: this proof, the
  owners' signatures and the statement hash are its integrity, so a wallet
  MUST open only packets of settled, proven actions.

The anchor is proved only as the root the membership path reaches. That it is
an authentic root is checked by the settlement covenant
(`apnt-pool-settlement-custody`), not by the proof.

No requirement MAY constrain two actions jointly.

#### Scenario: Balance off by one

- **WHEN** an action's inputs, outputs, deposit, withdrawal and fee do not
  balance exactly
- **THEN** the relation MUST reject the action

#### Scenario: Value wraps the field

- **WHEN** an action balances only modulo the proof system's field, for example
  with an output value above `MAX_MONEY` that acts as a negative number
- **THEN** the relation MUST reject it through the range checks

#### Scenario: Cross-action equation introduced

- **WHEN** a proposed change makes one action's validity depend on another
  action's private values
- **THEN** it MUST be rejected, because it reintroduces a need to pool private
  inputs

### Requirement: Spend authority stays with the owner

Every input slot, real or dummy, MUST be authorized with BCH's native
EC-Schnorr signature. That scheme is the 2019-05-15 BCH construction: challenge
`SHA-256(R.x ‖ SEC1c(P) ‖ m)`, 33-byte compressed keys, and no BIP-340 tagged
hash or x-only key.

- The signature is under the slot's re-randomized key
  `rk = SEC1c(ak + α·G)`, formed with a fresh `α` per spend. The owner signs
  with `rsk = (ask + α) mod n_G`, which MUST be nonzero.
- The signed message is `SHA-256(m)` of the action's tag-authorization
  message `m = SHA-256("APNT-POOL-v1:dt-auth" ‖ ad ‖ dt_0 ‖ dt_1)`, which
  commits the authorization digest `ad`, and so the whole record `A`, and the
  action's two discovery tags (operator decision HUM-75, 2026-09-24).
- The pool settlement covenant MUST recompute `ad` from the record bytes of the
  opened statement, and `m` from `ad` and the record's tags as carried in
  input 0. It MUST check each slot with `OP_CHECKDATASIGVERIFY(sig, m, rk)`.
- The action MUST prove, for each slot, that:
  - `ak` is a valid curve point, not the point at infinity;
  - the input note's owner tag is `O = SHA-256("APNT-POOL-v1:owner" ‖ SEC1c(ak) ‖ nkc)`,
    with `nkc = SHA-256("APNT-POOL-v1:nkc" ‖ nk)` computed from the same `nk`
    as the slot's nullifier;
  - `α ∈ [0, n_G)`;
  - the public `rk` equals `SEC1c(ak + α·G)`, not the point at infinity.

Signatures MUST NOT appear in `ad`, in `m`, in `S` or in any proof input.
Discovery tags MUST NOT appear in `A`, in `S` or in any proof input. No witness
or request given to a prover, aggregator or relay MAY contain `ask` or `rsk`.

#### Scenario: BIP-340 signature presented

- **WHEN** a slot carries a BIP-340 signature by `rsk` over the same digest
- **THEN** BCH script MUST reject it, and no specification MAY describe pool
  authorization as BIP-340

#### Scenario: Two spends under one invoice

- **WHEN** two notes received under one invoice are spent in different actions
- **THEN** their revealed keys MUST differ and MUST NOT be linkable without
  the owner's secrets

#### Scenario: Delegated prover attempts a spend

- **WHEN** a prover holds a complete action witness, including `ak`, `nk` and
  `α`, but not `ask`
- **THEN** it MUST NOT be able to produce a signature that script accepts under
  `rk`

#### Scenario: Aggregator redirects a withdrawal after signing

- **WHEN** an aggregator obtains a statement committing a record whose
  withdrawal amount or `wlock_hash` differs from what the owner signed, and
  presents the owner's signatures
- **THEN** the settlement covenant MUST reject it, because the recomputed `ad`,
  and so `m`, no longer matches the signatures

#### Scenario: Aggregator rewrites a discovery tag after signing

- **WHEN** an aggregator or relay replaces, swaps or strips a discovery tag of
  a signed action and presents the owner's signatures
- **THEN** the settlement covenant MUST reject it, because the recomputed `m`
  no longer matches the signatures

#### Scenario: Signature inside its own digest

- **WHEN** a design has the owner sign a statement or digest that contains the
  signatures themselves
- **THEN** it MUST be rejected as unconstructible and recursive

### Requirement: What the owner signs is what the verdict commits

The child proof's public input MUST be `x = int_be(SHA-256(A)) mod r` of the
action record `A`, and the aggregate program MUST compute it from the `A` it
places in `S`, never take it from the prover. The aggregate program MUST place
each verified child's `A` in `S` verbatim, and the proof verdict MUST commit
`SHA-256(S)`. The record inside the owner-signed
`m` (through `ad`), the proved record and the covenant-enforced record MUST
therefore be one byte string. The discovery tags `m` also binds are outside
the proof and the verdict; the owner signatures alone bind them.

#### Scenario: Aggregate program alters a record

- **WHEN** an aggregate statement carries a record that differs in any byte from
  the record whose `x` the verified child's proof binds
- **THEN** the aggregate program MUST reject it, and the settlement covenant
  MUST refuse the owner signatures over the altered record
