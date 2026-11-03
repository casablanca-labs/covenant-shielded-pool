# apnt-pool-settlement-custody

## ADDED Requirements

### Requirement: Pool state changes only under the settlement authority

A transaction has the settlement authority when its input 0 is under the pool
settlement lock and carries a token of the pool's verdict category with no
capability. Pool coins, root copies and range records MUST be spendable only
under it. The verifier ladder MUST emit its terminal proof
verdict only under the pool settlement lock. A verdict-category token with a
capability, or under any other lock, MUST NOT authorize any pool state change.

#### Scenario: Pool coin drained without a verdict

- **WHEN** a transaction spends a pool coin without an authentic verdict
- **THEN** the covenant MUST reject it

#### Scenario: Verdict-category token of the wrong kind at input 0

- **WHEN** a transaction puts a verifier-factory token, or a verdict-category
  token under a lock other than the pool settlement lock, at input 0 and spends
  a pool coin, root copy or range record
- **THEN** that pool covenant MUST reject it

### Requirement: The settlement covenant checks an exact list

The pool settlement covenant, the verdict's lock at input 0, MUST check all of
the following, and MUST bind statement values, not input outpoints:

1. **Statement.** `SHA-256(S)` equals the verdict's commitment; `S` starts with
   the statement tag; its `deployment_id` equals the covenant's own constant;
   `|S| = 88 + 314·B` with `B ≥ 1`.
2. **Signatures.** Both owner signatures of every record, over the
   tag-authorization message `m` recomputed in script from `ad` and the
   record's two discovery tags, as in "Every output carries a bound
   discovery-tag slot".
3. **Anchors.** As in "Every anchor is an authentic root spent in the same
   settlement".
4. **Nullifiers.** The one-to-one insertion of `apnt-pool-nullifier-range-records`,
   at inputs `C+1 … C+2B`, with each record's splits at fixed outputs
   `M+1+C+2j` and `M+1+C+2j+1`.
5. **Withdrawals.** As in "Withdrawals map one to one onto indexed outputs".
6. **Pending batch.** Output 0 is under the batch's pending lock,
   `P2SH32(<H_cm> OP_DROP ‖ PCODE)` with `H_cm` the SHA-256 of `S`'s leaves
   `cm_{1,0} ‖ cm_{1,1} ‖ … ‖ cm_{B,1}` computed from `S` in statement order,
   carries the input-0 verdict token unchanged (verdict category, no
   capability, commitment `SHA-256(S)`) and holds at least the fold bounty
   `P_fold`. No other output carries the verdict category.
7. **Pool coins.** `Σ pool out = Σ pool in + Σ deposit − Σ withdrawal − Σ fee`,
   where `Σ pool in` runs over every input under the pool-coin lock, and
   `Σ pool out` over every output under that lock at an index above the
   withdrawal outputs. Each such output MUST be token-free.

The pool has no deposit cap and no meter (ARCH-196; operator decision
2026-09-24, reversing decision 0.4), so the list has no eighth check.

The covenant MAY take unauthenticated index hints from its unlocking data only
if it checks every hinted fact, so that a wrong hint can refuse a settlement
but never admit one.

The covenant MUST refuse any spend of its own lock at an input other than
input 0. It MUST NOT embed the range-record, root-copy or pool-coin lock, each of
which embeds it: it identifies root copies by the root category with no
capability and range records by the range category with the minting
capability at their fixed input positions, and it derives the pool-coin lock
and the range record's code from its own lock and category.

#### Scenario: Settlement lock spent at a later input

- **WHEN** a verdict under the settlement lock is spent at an input other than
  0, for example at input 2 of a fold or beside another settlement's verdict
- **THEN** the covenant MUST reject it, so the verdict is never burned without
  its settlement

#### Scenario: Withdrawal redirected

- **WHEN** a settlement changes a withdrawal's value or lock from the statement
- **THEN** the covenant MUST reject it

#### Scenario: Owner signature missing

- **WHEN** a settlement carries an authentic verdict but lacks a valid owner
  signature for any slot of any record
- **THEN** the covenant MUST reject it

#### Scenario: Statement of another deployment

- **WHEN** a verdict commits a statement whose `deployment_id` is not the
  covenant's own
- **THEN** the covenant MUST reject the settlement

#### Scenario: Statement of the wrong length

- **WHEN** a verdict commits a statement whose length is not `88 + 314·B`
- **THEN** the covenant MUST reject the settlement

#### Scenario: Pending output with another commitment

- **WHEN** a settlement's output 0 carries a verdict-category token whose
  commitment is not `SHA-256(S)`, or another output carries the verdict
  category
- **THEN** the covenant MUST reject it

#### Scenario: Pool coin left out of the sum

- **WHEN** a settlement spends a pool coin that a hinted or partial sum would
  not count, and pays its value elsewhere
- **THEN** the covenant MUST reject it, because `Σ pool in` covers every
  pool-coin input

### Requirement: Every output carries a bound discovery-tag slot

Current implementation: ENG-390 implements this slot. The settlement parses
144 bytes per record and verifies owner signatures over `m`
(`packages/protocol-runtime/src/cashassembly/apnt_pool_settlement_v1.casm:239-255`);
the host derives `m` (`packages/protocol-runtime/src/apnt_pool_action_record_v1.ts:177-182`),
and the task record marks the slot done with REV-178 PASS (`tasks.md:213-219`).
Wallet fill and scanning components now exist; the capped fallback and absent
targeted/deep-scan commands remain the limits recorded in the dated M1
reconciliation. This slot proves neither honest tag fill nor payment ownership.

Every output slot of every action, real or dummy, MUST carry an 8-byte
discovery tag `dt_j`, `j ∈ {0, 1}` (operator decision HUM-75, 2026-09-24).
The tags travel outside `A` and outside `S`, with the owner signatures:

- **Carriage.** Input 0's unlocking bytecode is `<S> <sigs>`. The second push
  MUST carry, for each record `k = 1..B` in statement order,
  `sig_{k,0} ‖ sig_{k,1} ‖ dt_{k,0} ‖ dt_{k,1}`: 144 bytes per record. The
  covenant MUST refuse a push of any length other than exactly `144·B` bytes,
  so no party can strip, truncate or append a tag. `dt_{k,j}` belongs to
  output `j` of record `k`, whose `cm_j` and `packet_j` are in `A_k`.
- **Binding.** For each record the covenant MUST recompute `ad_k` from the
  record bytes, then
  `m_k = SHA-256("APNT-POOL-v1:dt-auth" ‖ ad_k ‖ dt_{k,0} ‖ dt_{k,1})`, and
  MUST check each slot with `OP_CHECKDATASIGVERIFY(sig_{k,s}, m_k, rk_{k,s})`.
  The owners sign `SHA-256(m_k)` in place of `SHA-256(ad_k)`
  (`apnt-pool-note-statement`, "Spend authority stays with the owner"). Only
  the owners who sign an action can choose its tags.
- **Order.** Records MUST stay in strictly ascending byte-lexicographic `ad`
  order. The tags and `m` MUST NOT influence statement order.
- **Unchanged.** `A`, `S`, `|S| = 88 + 314·B`, the verdict's commitment
  `SHA-256(S)`, the aggregate program and the fold MUST stay as specified;
  no covenant but the settlement reads `S`. The action circuit's only
  public input is `x = int_be(SHA-256(A)) mod r`, a function of the 314-byte
  record `A` alone (`apnt-pool-proof-system`, registry entry 1). So no tag
  reaches the circuit, its R1CS or its Setup, and none of them changes.
- **No fill check.** The covenant checks that the owners signed each tag, not
  what the tag contains. No circuit or covenant checks a tag against its
  output's `K`. The fill rules are wallet rules
  (`apnt-pool-receive-recovery`, "Every output's discovery tag follows the v1
  fill rules"). A tag is therefore an unauthenticated hint: a signer may write
  any 8 bytes on its own outputs, a copy of another output's public tag
  included, and nothing on chain shows that a tag belongs to its output.
  The binding stops a party that did not sign an action from changing its
  tags; it does not make a tag evidence of payment.

#### Scenario: Flipped tag bit

- **WHEN** a settlement carries valid owner signatures but one bit of any
  `dt_{k,j}` differs from what the owners signed
- **THEN** the covenant MUST reject it at input 0

#### Scenario: Tags swapped within a record

- **WHEN** a settlement carries record `k`'s two tags in the order
  `dt_{k,1} ‖ dt_{k,0}`
- **THEN** the covenant MUST reject it

#### Scenario: Tags swapped across records

- **WHEN** a settlement carries record `k`'s tags in record `k'`'s place and
  record `k'`'s in record `k`'s, with every signature where it was
- **THEN** the covenant MUST reject it

#### Scenario: Tag stripped or appended

- **WHEN** a settlement's signature push omits the last record's tags, omits
  any other tag bytes, carries only the `2B` signatures, or carries one byte
  more than `144·B`
- **THEN** the covenant MUST reject it

#### Scenario: Unbound tag accepted

- **WHEN** a covenant variant reads the tag bytes but checks the signatures
  over `ad_k`, not `m_k`
- **THEN** the test suite MUST include that variant as the firing control of
  the tag negatives and MUST show that it accepts the flipped-tag settlement
  the covenant refuses, and such a build MUST NOT be adopted

#### Scenario: Records in ascending `ad` order, descending `m` order

- **WHEN** a statement holds two records in strictly ascending `ad` order
  whose `m` values are in descending order
- **THEN** the host, the aggregate program and the covenant MUST accept its
  order, and a build that orders records by `m` or by tag MUST fail this test

#### Scenario: Tag placed in the record or the statement

- **WHEN** a proposed implementation puts a discovery tag into `A`, into `S`
  or into the action circuit's public input
- **THEN** it MUST be rejected, because it changes `A`, `S`, the circuit and
  its Setup

### Requirement: Every anchor is an authentic root spent in the same settlement

For every record `k` of `S`, the settlement covenant MUST check that
`A_k.anchor` equals the 32-byte commitment of a root copy that the same
transaction spends: an input whose token is of the root category with no
capability. Such tokens exist only under the root-copy lock, which recreates
each one (genesis audit, then the tree-update and root-copy covenants), so the
covenant identifies copies by that category rather than by the lock, which it
cannot embed. The spent root copies MUST be
exactly one per distinct anchor of `S`: no two MAY carry the same root, and each
MUST carry some record's anchor. Actions in one settlement MAY use different
anchors. The rule applies to every record, including one whose inputs are both
dummies.

#### Scenario: Sound proof under a fabricated anchor

- **WHEN** an action proves membership and balance of a note under a root the
  prover built itself, with a sound proof and valid owner signatures, and the
  settlement spends and recreates an authentic root copy of a different root
- **THEN** the covenant MUST reject the settlement

#### Scenario: Copy of a forged category

- **WHEN** an action's anchor is carried by an immutable token of a category
  other than the pool's root category, even under the root-copy lock
- **THEN** the covenant MUST reject the settlement

#### Scenario: Tree-update token offered as a copy

- **WHEN** a settlement offers a root-category token with a capability, such as
  the tree update's, as the copy for an anchor
- **THEN** the covenant MUST reject it

#### Scenario: Actions with different anchors

- **WHEN** a batch contains actions anchored to two different authentic roots,
  and the settlement spends one copy of each
- **THEN** the anchor check MUST pass, with no action re-proved

#### Scenario: Two anchors, one copy

- **WHEN** a statement uses two distinct anchors and the settlement spends a
  copy of only one
- **THEN** the covenant MUST reject it

#### Scenario: Extra or duplicate copy

- **WHEN** a settlement spends a root copy whose root no record uses, or two
  copies of one root
- **THEN** the covenant MUST reject it

### Requirement: Withdrawals map one to one onto indexed outputs

Let `r_1 < … < r_M` be the statement positions of the records with
`withdrawal > 0`. For `j = 1..M`, the settlement covenant MUST check that
output `j` is token-free, carries exactly `withdrawal_{r_j}` satoshis, and has
`SHA-256(locking bytecode) = wlock_hash_{r_j}`. Distinct records therefore map
to distinct outputs, and no output discharges two withdrawals. Output 0 is the
pending-batch output. An output at index `1..M` MUST NOT also count as a pool
coin.

#### Scenario: Two equal withdrawals share one output

- **WHEN** two signed records each withdraw the same value to the same locking
  bytecode, and the settlement creates one such output and pays the second
  amount elsewhere
- **THEN** the covenant MUST reject it

#### Scenario: Withdrawals out of statement order

- **WHEN** two withdrawal outputs appear in an order other than their records'
  statement order
- **THEN** the covenant MUST reject the settlement

#### Scenario: Withdrawal output carries a token

- **WHEN** a withdrawal output carries any token
- **THEN** the covenant MUST reject the settlement

### Requirement: Deposits enter through a record-keyed pool inbox

A deposit's BCH MUST enter the pool through its deployment's pool inbox, not
through depositor inputs signed inside the settlement (operator decision
HUM-104, 2026-09-27). For deployment Δ and action record `A`:

```text
D(A)   = A.cm_0 ‖ A.packet_0 ‖ u64le(A.deposit) ‖ A.rk_0      (89 bytes)
L_Δ(A) = P2SH32(push(D(A)) ‖ CODE_Δ)
```

`push(D(A))` MUST be the minimal push. `CODE_Δ` MUST be fixed per deployment.
It MUST embed Δ's settlement locking bytecode, its verdict category, the
refund delay `T_refund = 1,008` blocks and its own redeem length, and MUST
take no parameter from a wallet, funder or aggregator. Artifact revision 2
pins it ("The deployment artifact pins the inbox code in a closed
revision"). A record therefore has exactly one inbox lock per deployment.

An inbox output MUST be spendable in exactly two ways:

1. **Settlement.** All of the following hold:
   - input 0 carries Δ's settlement authority;
   - input 0's first unlocking push is `S`, and `SHA-256(S)` is input 0's
     token commitment;
   - for the hinted `k`, `0 ≤ k < B`, record `k` of `S` carries `D`'s `cm_0`,
     `packet_0`, `deposit` and `rk_0`;
   - the executing redeem is exactly `push(D) ‖ CODE_Δ`, checked by its
     length and by its HASH256 against this input's P2SH32 hash;
   - this input carries no token and holds exactly `W`, the record's deposit;
   - no other input of the transaction has this input's locking bytecode.
2. **Refund.** After a relative lock of `T_refund` blocks, a signature by
   `rk_0`'s key, with no public key pushed. The VM checks only the input's
   sequence number. BIP68 relative-lock maturity is the node's rule, and the
   local simulation ledger MUST enforce it as well.

The inbox MUST NOT change the action record, the statement `S`, the
settlement covenant, the pool-coin covenant, the action circuit or its keys.
It reads four fields every 314-byte record already carries, and `S` as input
0 already pushes it, `|S| = 88 + 314·B`. Every covenant negative below MUST
be executed in both BCH 2026 VMs with a firing control that removes the
check responsible and shows the attack accepted. Where checks overlap, the
smallest removal set that admits it MUST be recorded. The maturity negative
is the ledger's, with its own control.

Current implementation: `packages/protocol-runtime/src/apnt_pool_inbox_covenant_v1.ts`
ships the record-keyed inbox covenant (ENG-528). The local ledger enforces
BIP68 maturity in its refund test. Wallet inbox funding/refund and aggregator inbox admission/carry-through
exist. The migration host remains in its older hashed form; no certified live
run is claimed here. The settlement covenant still cannot prove that a deposit record was
funded by its canonical inbox input (`design.md`, "Deposit inbox").

#### Scenario: Statement without the deposit record

- **WHEN** a settlement's statement does not contain the record whose fields
  the inbox's `D` carries
- **THEN** the inbox MUST reject its spend

#### Scenario: Forged statement or foreign settlement at input 0

- **WHEN** input 0 is not under Δ's settlement lock, carries no verdict token
  or a self-minted one, or pushes a statement whose SHA-256 is not its token's
  commitment, or belongs to another deployment's settlement
- **THEN** the inbox MUST reject its spend

#### Scenario: One lock funded twice

- **WHEN** two or more inputs of one transaction are under one inbox lock
- **THEN** each of them MUST be rejected, and the firing control MUST show that
  with the uniqueness check removed the settlement is accepted and the second
  `W` reaches the assembler's payout

#### Scenario: Second inbox for one record under another key

- **WHEN** an inbox whose `D` carries a different `rk_0` is offered to fund a
  record, beside the record's own inbox or instead of it
- **THEN** it MUST be rejected at its own input, and its value MUST stay
  refundable only by the key its `D` names

#### Scenario: Inbox with the wrong value or a token

- **WHEN** an inbox holds other than exactly the record's deposit, or carries a
  token
- **THEN** the settlement branch MUST reject it, and only `rk_0`'s refund MAY
  move it, carrying any token back

#### Scenario: Wrapped or re-encoded redeem

- **WHEN** a lock commits `D` and `CODE_Δ` inside any other redeem: with a
  prefix or a suffix, with `D` split across pushes joined by `OP_CAT`, behind
  an `OP_CODESEPARATOR`, or with a non-minimal push of `D`
- **THEN** the settlement branch MUST NOT run from it. The length and hash
  checks refuse the first four, and the VM's minimal-push rule the last

#### Scenario: Record already settled

- **WHEN** a second canonical inbox of a record is offered to a later
  settlement of that record
- **THEN** the settlement covenant MUST reject it at input 0, because the
  record's nullifiers are already inserted, and that inbox MUST stay
  refundable only by `rk_0`'s key

#### Scenario: Depositor's fields under another signer

- **WHEN** a record carries a depositor's `cm_0`, `packet_0`, deposit and
  `rk_0`, but its slot-0 signature is by another key
- **THEN** the settlement covenant MUST reject it at input 0

#### Scenario: Refund before the delay or by another key

- **WHEN** a refund spends an inbox at a sequence below 1,008, or is signed by
  any key other than `rk_0`'s
- **THEN** it MUST be rejected

#### Scenario: Refund before BIP68 maturity

- **WHEN** a refund at sequence 1,008 spends an inbox funded fewer than 1,008
  blocks earlier
- **THEN** the local simulation ledger MUST refuse it, and its firing control
  MUST show it accepted with the ledger rule removed. A test that checks only
  the sequence number MUST NOT be presented as this negative

#### Scenario: Rebuild with the depositor offline

- **WHEN** a settlement containing a funded deposit is rebuilt after
  contention spent one of its copies, records or pool coins
- **THEN** the rebuilt settlement MUST spend the same inbox input with the
  same unlocking, and MUST need no new signature from the depositor

### Requirement: The inbox guarantee and its limit are stated exactly

Every description of the inbox MUST state its guarantee as follows, and no
more. In any one transaction, at most one input running Δ's pinned inbox code
can release value into a settlement for a given record. The record settles in
at most one transaction. An output under the record's canonical lock, holding
exactly `W` and no token, can go only to one of two places:

- a settlement of a statement containing the record, which also requires the
  record's slot-0 signature under `rk_0` and pool coins growing by its
  deposit;
- `rk_0`'s key, after `T_refund`.

It MUST also state what no inbox rule can prevent: any other input, under any
other script, can join a settlement and add its own value, and that script
alone governs the value. A lookalike inbox can settle a record, value sent to
a lookalike may be stolen, and a trial settlement cannot tell a canonical
inbox from a trap.

Custody of an honest depositor's `W` rests on the pinned code and on a
wallet that funds only the lock it computed itself
(`apnt-pool-receive-recovery`, "A wallet funds a deposit inbox only after its
pre-funding binding"). It MUST NOT be described as resting on aggregator
checks. Custody of pooled value still rests on proof soundness ("Custody
rests on proof soundness, stated plainly").

#### Scenario: Lookalike beside the canonical inbox

- **WHEN** a third party funds a lookalike that keeps the canonical settlement
  branch with another refund rule, and it settles the depositor's record beside
  the canonical inbox
- **THEN** a test MUST show that every depositor output is byte-identical to
  the canonical-only settlement and that the payout rises by exactly the
  lookalike's value less its own input bytes

#### Scenario: Chain described as refusing lookalikes

- **WHEN** a document says the chain refuses any second inbox for a record, or
  that a lookalike can take nothing from any depositor
- **THEN** it MUST be corrected: the chain refuses a second input running the
  pinned code, a lookalike can take value sent to it, and the wallet's binding
  is what keeps an honest wallet from sending value there

### Requirement: The deployment artifact pins the inbox code in a closed revision

A deployment that takes deposits MUST pin its inbox code through artifact
revision 2, an explicit revision separate from the pool version and from the
proof-system registry revision:

- revision 2 is closed: every revision-1 field, `artifactRevision: 2`, and a
  seventh covenant entry `inbox` with exactly three fields. They are
  `codeBytecode`, the code `CODE_Δ` alone; `codeSha256`, exactly 32 bytes,
  `SHA-256(CODE_Δ)`; and `refundDelayBlocks`, fixed at 1,008. Any other field,
  type, length or delay MUST be refused as `pool-genesis-artifact`;
- the existing genesis validator MUST dispatch the two revisions explicitly
  and keep every existing check. For revision 2 it MUST build the inbox code
  with the reviewed builder from that artifact's audited verdict category and
  settlement lock and the fixed delay, and require the artifact's code and
  hash to equal the built code and its SHA-256. A mismatch is
  `pool-genesis-covenant`; a builder or source failure keeps the `pool-shape`
  distinction;
- a successful revision-2 audit MUST return a detached validated inbox result
  holding the builder-derived code, hash and delay. A revision-1 audit
  returns no inbox result and MUST NOT authorize inbox funding;
- no `P2SH32(CODE_Δ)` is a fundable lock: every inbox lock is record-specific;
- revision 2 adds new vectors. No committed vector corpus or digest, and not
  the `deployment_id` derivation, changes.

There MUST be no second genesis validator and no caller-supplied acceptance
object. Passing the audit is not chain validation: the wallet's own chain
read comes first.

Artifact revisions 1 and 2 are the closed genesis/inbox schemas. Successful audit establishes their defined fields and shipped covenant equality from supplied transaction bytes; chain authentication remains the reader’s separate obligation. Neither schema contains vp, the required provenance enum or the sealed transcript digest. The inbox revision-2 requirement and prohibition on caller-supplied acceptance remain unchanged. At M1, the deployment-artifact provenance requirement is explicitly UNMET with no value-bearing authorization, under ARCH-679 as detailed in E05. Recording that gap at freeze does not choose or implement its binding.


Current implementation: ENG-528 ships the closed seventh `inbox` artifact
entry in revision 2. The genesis audit compares its code and hash with the
reviewed inbox builder, then returns a detached validated inbox result.
ENG-591 ships revision-carrying settlement and tree history replay on main.
Revision 1 remains readable but cannot authorize inbox funding; wallet inbox
funding and aggregator inbox admission now exist; the migration-host change
remains target work.

#### Scenario: Replacement inbox code with its hash recomputed

- **WHEN** a revision-2 artifact carries inbox code other than the reviewed
  build for its own audited parameters, with a matching hash
- **THEN** the genesis validator MUST refuse it with `pool-genesis-covenant`

#### Scenario: Replacement inbox code under the canonical hash

- **WHEN** a revision-2 artifact carries other inbox code beside the canonical
  code's hash
- **THEN** the genesis validator MUST refuse it

#### Scenario: Revision-1 artifact offered for a deposit

- **WHEN** a wallet is asked to fund an inbox for a deployment whose artifact
  is revision 1
- **THEN** the audit MUST return no inbox result and the wallet MUST refuse
  before any funding signature

#### Scenario: Other refund delay or unknown field

- **WHEN** a revision-2 artifact carries a refund delay other than 1,008, or
  any field not listed
- **THEN** the genesis validator MUST refuse it with `pool-genesis-artifact`

### Requirement: Deposit admission protects liveness, not custody

An aggregator MUST admit a deposit action only when all of the following hold
in its own chain view:

- its selected deployment and inbox code are bound through the genesis audit
  and the reviewed build;
- the inbox output is confirmed, with at least `c_inbox` confirmations, and
  is unspent;
- its lock equals the lock recomputed from the record and `CODE_Δ`;
- it holds exactly `W` and no token;
- it is the only inbox admitted for the record;
- the action's authorization is valid;
- at least `M_refund` blocks of its refund lock remain.

It MUST NOT admit an inbox because a trial settlement passes. Its intake MUST
take only the public record, proof, owner signatures, discovery tags and the
inbox outpoint, and MUST NOT ask for refund authority. It MUST carry the
inbox input unchanged through every rebuild and MUST NOT ask a depositor for
another signature. These rules protect liveness and third parties. The
aggregator is untrusted, and no custody claim MAY rest on them.

#### Scenario: Trial settlement taken as admission

- **WHEN** an intake admits an inbox because a trial settlement of its record
  passes
- **THEN** the build MUST be rejected, and a negative test MUST show that a
  lookalike whose own key spends it at sequence 0 passes that trial

#### Scenario: Unconfirmed inbox or short refund margin

- **WHEN** an offered inbox is unconfirmed, or has fewer than `M_refund` blocks
  of refund lock left
- **THEN** the aggregator MUST NOT admit it

#### Scenario: Intake asks for refund authority

- **WHEN** an intake message format carries or requests `rsk_0`, `ask_d`, a
  seed or any other refund or spend authority
- **THEN** it MUST be rejected

### Requirement: Depositor inputs signed inside a settlement are not a v1 deposit path

A v1 wallet MUST NOT deposit by signing its own funding input inside a
settlement; that is HUM-104's rejected alternative. The settlement covenant
places no rule on such inputs and cannot refuse them. Deposits in the
ARCH-267 local simulation and Chipnet smoke (8.1 L2 and 8.2) MUST use the
record-keyed inbox (operator decision ARCH-289/ARCH-292, 2026-09-27). The wallet inbox path is implemented; the former statement that smoke waits for that path to be built is historical. The V1 and V2 self-deposit build and sign APIs remain exported as guarded compatibility surfaces. They are prohibited, non-v1 evidence and MUST NOT be used to satisfy v1 deposit, ladder or smoke acceptance. A v1 wallet MUST NOT sign its own depositor funding input inside settlement; the current settlement module refuses that route. Neither 0x41 nor the later 0x61 hardening authorizes an interim alternative to the record-keyed inbox. This status correction retires no export and changes no frozen signer contract. The proposed
`SIGHASH_ALL|SIGHASH_UTXOS` (`0x61`), statement-binding and exact-value
checks (ENG-531) neither make that signer compliant nor authorize an interim
depositor-input deposit path.

#### Scenario: Plain SIGHASH_ALL and a lying assembler

- **WHEN** the superseded depositor-input flow signs over UTXO data that the
  assembler misstates
- **THEN** a test MUST show that a plain `SIGHASH_ALL` signature settles a
  statement without the depositor's record, sending its `W` to the payout,
  while the `0x61` signature is refused

#### Scenario: Anyone-can-pay signing to survive rebuilds

- **WHEN** a flow signs its deposit input `SIGHASH_SINGLE|SIGHASH_ANYONECANPAY`
  or `SIGHASH_NONE|SIGHASH_ANYONECANPAY` so that the signature survives a
  rebuild
- **THEN** it MUST be rejected, because the assembler can then move the
  deposit into a settlement of a statement without it

### Requirement: Custody rests on proof soundness, stated plainly

The privacy claims retain their complete existing adversary, assumption and exclusion statements. Registry/profile/key identity, fresh honest prover randomness and CRS well-formedness for each setup-backed layer are distinct conditions. The action CRS checker and release gate exist; the complete claims-check implementation and failing controls required by PS:205–228 are not found in the inspected code. Action CRS evidence supplies no wrapper CRS or wrapper zero-knowledge evidence. Where evidence is unestablished the precondition remains explicitly unestablished. Simulated setup leaves the project able to forge proofs and move pooled research coins; honest-prover privacy conditions do not repair that soundness failure. No production privacy or fund-security certification follows.


Every description of the pool MUST state that custody of all pooled BCH rests
on the soundness of the proof pipeline: circuits, aggregate program, wrapper,
on-chain verifier and any setup. It rests too on the settlement covenant
binding every proved statement value to chain state. It MUST NOT describe the
pool as protected by per-note owner signatures. The owner signatures stop a prover, relay or
aggregator from spending without the owner. They do not stop a forged proof.

The only bound is pool-coin conservation: covenants cannot pay out more BCH
than the pool coins hold. The pool has no deposit cap and no meter (ARCH-196,
operator decision 2026-09-24), so nothing bounds how much BCH is pooled or how
much of it one unsound proof could reach. Documentation MUST state that a
counterfeit note from an unsound proof can withdraw other depositors' BCH, up
to everything the pool holds.

A withdrawal MAY name the pool-coin lock as its destination. Its BCH is then
paid into a pool coin that no note commits: it adds to what the pool holds and
no owner can withdraw it as a note, though, like any pooled BCH, a counterfeit
note could.

#### Scenario: Claim without the condition

- **WHEN** a report or publication describes pooled funds as safe without naming
  proof soundness and the setup posture
- **THEN** it MUST be corrected

#### Scenario: Exposure described as capped

- **WHEN** a document says pooled value or a depositor's exposure is capped or
  metered
- **THEN** it MUST be corrected: the pool has no cap, and a counterfeit note
  can reach everything pooled

#### Scenario: Withdrawal to the pool-coin lock

- **WHEN** a settlement's record withdraws to the pool-coin lock
- **THEN** the covenant MUST accept it like any other withdrawal, the output
  MUST NOT count toward `Σ pool out`, and the withdrawn BCH MUST remain under
  the pool-coin lock as an unowned pool coin

### Requirement: No setup holder guards pooled value

A development or single-party setup MUST NOT guard any pooled value beyond an
explicitly labelled zero-value test. Pooled value MUST require one of the
following, as the operator decides:

- a permissionless ceremony. Anyone may contribute, and anyone can verify its
  public transcript and their own contribution's inclusion. Its soundness
  assumption is stated as at least one honest contribution whose randomness was
  destroyed (1-of-N honest), in phase 1 and in phase 2;
- a no-setup proof pipeline.

A contributor's being outside the project MUST NOT be presented as the
assumption.

A Chipnet deployment MAY take its keys from a project-run simulated
single-party ceremony (operator decision on ARCH-141, 2026-09-24). It uses the
same coordinator, transcript format and verifier as a permissionless ceremony,
but the project runs every contribution, so the project holds the setup's
randomness and could forge proofs that move pooled coins. Every such
deployment is an explicitly labelled zero-value test:

- its transcript, its key metadata and its pinned deployment artifact MUST
  carry the provenance label `simulated-single-party`. A permissionless
  ceremony's outputs carry `permissionless-multi-party`. The transcript
  verifier MUST report the label. The deployment artifact and the proof-system
  registry entry MUST also record, beside `vp`, the SHA-256 of the sealed
  transcript file, so a deployed `profile_id` traces to its ceremony;
- the label MUST be bound into the phase-2 challenge chain, so that
  contributions made under `simulated-single-party` never verify under
  `permissionless-multi-party`, however the rest of the transcript is edited;
- testers MUST be told, before they deposit, that the project could forge
  proofs under these keys and move every pooled Chipnet coin;
- its keys MUST NOT guard mainnet value.

M1 status under ARCH-679: the requirement that each allowlisted vp have its sealed transcript SHA-256 and enumerated provenance recorded in the pinned deployment artifact remains normative and explicitly UNMET in closed artifact revisions 1 and 2. The registry records a transcript digest and a simulated-setup warning, but that warning is not the enumerated simulated-single-party label and registry data is not an artifact field. Neither this status nor the current transitive pins satisfy the deployed-profile refusal scenario. The freeze records the unmet requirement and acceptance obligation, with no value-bearing or production authorization. ARCH-703 is folded into ARCH-679. The operator retains, pre-mainnet, the choice among a new artifact revision, authenticated manifest or amended normative transitive binding, and signs off on the M1 freeze with this gap presented. No choice is made here. Tester disclosure that the project can forge proofs and move pooled Chipnet coins remains mandatory for every deployment; keys from this setup MUST NOT guard mainnet value.


A mainnet deployment is never a zero-value test. Before any mainnet value,
every setup-backed proof system the pool verifies MUST come from a
permissionless multi-party ceremony. A setup-free pipeline needs no ceremony.
This does not relax "Mainnet needs setup-free proving or two proof systems"
(HUM-51/52), which still applies, nor "A scoped soundness audit of the action
circuit gates value".

#### Scenario: Development parameters in a funded pool

- **WHEN** a pool deployment that is not an explicitly labelled zero-value
  test uses development or simulated single-party proving parameters
- **THEN** the deployment MUST be refused as custodial

#### Scenario: Chipnet deployment under a simulated ceremony

- **WHEN** a Chipnet pool deployment's keys come from a simulated single-party
  ceremony
- **THEN** its transcript, key metadata and deployment artifact MUST be
  labelled `simulated-single-party`, and its tester-facing documentation MUST
  say that the project could forge proofs

M1 status under ARCH-679: the requirement that each allowlisted vp have its sealed transcript SHA-256 and enumerated provenance recorded in the pinned deployment artifact remains normative and explicitly UNMET in closed artifact revisions 1 and 2. The registry records a transcript digest and a simulated-setup warning, but that warning is not the enumerated simulated-single-party label and registry data is not an artifact field. Neither this status nor the current transitive pins satisfy the deployed-profile refusal scenario. The freeze records the unmet requirement and acceptance obligation, with no value-bearing or production authorization. ARCH-703 is folded into ARCH-679. The operator retains, pre-mainnet, the choice among a new artifact revision, authenticated manifest or amended normative transitive binding, and signs off on the M1 freeze with this gap presented. No choice is made here. Tester disclosure that the project can forge proofs and move pooled Chipnet coins remains mandatory for every deployment; keys from this setup MUST NOT guard mainnet value.


#### Scenario: Simulated transcript relabelled as multi-party

- **WHEN** a transcript whose contributions were made under
  `simulated-single-party` is presented as `permissionless-multi-party`, with
  every other field, including its key metadata, made consistent
- **THEN** the transcript verifier MUST refuse it

#### Scenario: Simulated keys offered for mainnet

- **WHEN** a mainnet deployment uses keys whose transcript is
  `simulated-single-party`
- **THEN** the deployment MUST be refused as custodial

#### Scenario: Outside contributor offered as the guarantee

- **WHEN** a document says the setup is safe because at least one contributor
  was outside the project
- **THEN** it MUST be corrected to the 1-of-N honest assumption, with the
  permissionless contribution route that lets any party rely on its own
  contribution

### Requirement: A scoped soundness audit of the action circuit gates value

A scoped soundness audit of the action circuit MUST have passed before any
value-bearing pool deployment and before the permissionless mainnet ceremony
starts (operator decision HUM-71, option C, 2026-09-24). It is not required
before the Chipnet simulated-ceremony Setup, whose deployments are explicitly
labelled zero-value tests. The gate sits beside the permissionless ceremony and
"Mainnet needs setup-free proving or two proof systems" (HUM-51/52); none of
the three relaxes another.

#### Scenario: Value-bearing deployment before the audit

- **WHEN** a pool deployment that is not an explicitly labelled zero-value test
  is proposed before the action circuit's scoped soundness audit has passed
- **THEN** it MUST be refused

#### Scenario: Mainnet ceremony before the audit

- **WHEN** the permissionless mainnet ceremony is scheduled before the action
  circuit's scoped soundness audit has passed
- **THEN** it MUST NOT start

#### Scenario: Chipnet Setup before the audit

- **WHEN** the Chipnet simulated-ceremony Setup runs before the audit, for a
  deployment labelled as a zero-value test
- **THEN** it MAY proceed

### Requirement: No authority can pause, veto or redirect

The pool MUST NOT include a guardian, pause, veto, sequencer or any key that can
stop, reorder or redirect settlements. Aggregators MAY decline to include an
action, but MUST NOT be able to prevent another party from settling it.

#### Scenario: Aggregator refuses an action

- **WHEN** an aggregator declines a user's action
- **THEN** the user MUST be able to hand the same action, with the same proof
  and signatures, to another aggregator or aggregate it on its own hardware
