# apnt-pool-nullifier-range-records

## ADDED Requirements

### Requirement: Nullifier freshness is enforced by range records

The pool MUST enforce nullifier freshness with nullifier range records.

- A range record is a keyless covenant UTXO carrying a minting NFT of the
  pool's range category and fungible amount zero.
- A nullifier's range key is `κ(nf) = 2·int_le(nf) + 1`, an odd integer.
- Endpoints are integers in `[0, 2^257]`. Each is encoded as 33-byte unsigned
  little-endian, giving 66-byte record data `lo‖hi`, carried in the record's
  own lock `P2SH32(push(lo‖hi) ‖ OP_DROP ‖ CODE)`, where `CODE` is the
  deployment's record code. The record's token commitment MUST be empty.
- A record asserts that no inserted key `k` satisfies `lo < k < hi`.

Inserting `nf` MUST:

- spend the single record with `lo < κ(nf) < hi`;
- create exactly the records `(lo, κ(nf))` and `(κ(nf), hi)`, each under its
  own record lock for its own data, each with the minting capability, an
  empty commitment, amount zero and the deployment's record value.

#### Scenario: Double spend

- **WHEN** a settlement tries to insert a nullifier whose key is already a range
  boundary
- **THEN** no record contains it, and the settlement MUST fail

#### Scenario: Nullifier at a sentinel value

- **WHEN** a nullifier equals 0, `2^256 − 1`, or a value whose key neighbours a
  genesis boundary
- **THEN** exactly one record MUST contain its key before insertion and none
  after, because genesis boundaries are even and keys are odd

#### Scenario: Extra range record minted

- **WHEN** an insertion creates any range-category output other than the two
  split records
- **THEN** the covenant MUST reject it

#### Scenario: Record re-locked

- **WHEN** an insertion places a split record under any lock other than its
  own data's record lock
- **THEN** the covenant MUST reject it

### Requirement: Only a proof verdict listing the nullifier may insert it

An insertion MUST require the settlement authority of
`apnt-pool-settlement-custody`: the pool's proof verdict at input 0, under the
pool settlement lock, whose committed statement lists the inserted nullifier.
Every nullifier the statement lists MUST be inserted, dummy nullifiers
included. Every insertion check MUST run in the settlement covenant at input
0; a record's own code MUST accept being spent only under the settlement
authority.

The `2B` nullifiers of a statement and the range-record inputs of its
settlement MUST correspond one to one: each record input splits at the key of
exactly one statement nullifier, and every statement nullifier is inserted by
exactly one record input.

A record splits at one key per transaction. Statement assembly MUST therefore
check, before aggregate proving, that the statement's keys lie in pairwise
distinct current records. A wallet MUST draw each dummy nullifier so that its
key avoids the record of the action's other input key, and MUST put two real
inputs whose keys share a record in separate actions.

#### Scenario: Front-running to freeze a victim

- **WHEN** an attacker spends a range record with a self-made authority listing
  a victim's nullifier
- **THEN** the covenant MUST reject it for a wrong authority category

#### Scenario: Skipped nullifier

- **WHEN** a settlement omits the insertion of a nullifier its statement lists
- **THEN** the settlement MUST fail

#### Scenario: Two statement keys in one record

- **WHEN** an aggregator assembling a statement finds two of its keys inside one
  current range record
- **THEN** it MUST leave one of the two actions to a later batch before
  aggregate proving, because the settlement could not insert both

#### Scenario: Concurrent split after assembly

- **WHEN** another settlement splits a record after a statement was assembled
  with its keys in distinct records
- **THEN** the keys MUST still lie in distinct records, because a split only
  refines the partition

### Requirement: Genesis is exact and its whole category supply is audited

Each pool category — verdict, range and root; the pool has no meter
(ARCH-196) — MUST be
created in exactly one genesis transaction, the one that spends outpoint
`(category, 0)`. That transaction MUST create exactly the category outputs of
`design.md` ("Genesis") and nothing else of that category:

- for the range category, `G = 2^g` records with `1 ≤ g ≤ 9`, record `i`
  covering `(i·2^(257−g), (i+1)·2^(257−g))`, under its own record lock, with
  minting capability, an empty commitment and amount zero. `g ≥ 1` because
  every action inserts two
  nullifiers into two distinct records: a single-record genesis could never
  settle a first action;
- no other lock, capability, commitment or fungible amount.

The pinned deployment artifact MUST record:

- the network and pool version;
- every category id, in both wire and display order;
- every genesis txid;
- every covenant's redeem bytecode and lock, the pool-coin covenant included;
- `g`, `K`, the dust values and the fold bounty `P_fold`;
- under artifact revision 2, the deposit inbox's code, its SHA-256 and the
  fixed refund delay (`apnt-pool-settlement-custody`, "The deployment
  artifact pins the inbox code in a closed revision").

Artifact revisions 1 and 2 are the closed genesis/inbox schemas. Successful audit establishes their defined fields and shipped covenant equality from supplied transaction bytes; chain authentication remains the reader’s separate obligation. Neither schema contains vp, the required provenance enum or the sealed transcript digest. The inbox revision-2 requirement and prohibition on caller-supplied acceptance remain unchanged. At M1, the deployment-artifact provenance requirement is explicitly UNMET with no value-bearing authorization, under ARCH-679 as detailed in E05. Recording that gap at freeze does not choose or implement its binding.


Before trusting range status, a wallet MUST, from its own chain read:

- fetch each genesis transaction and check its confirmation depth;
- check that it spends `(category, 0)`;
- compare **every** output carrying the category with the artifact,
  recognising range outputs by their locks, which MUST be the `2^g` grid
  records' own locks;
- check every covenant's bytecode against the reviewed build and its lock
  hash, and, under revision 2, the inbox code against the reviewed inbox
  build for the same audited parameters.

Every covenant holding a minting or mutable capability of a pool category MUST:

- count every output of that category in any transaction that spends it,
  itself or, for a range record, through the settlement covenant its code
  requires at input 0;
- permit only its specified transitions;
- never send such a capability to another lock.

Covenants MUST compare categories in wire order. OP_UTXOTOKENCATEGORY and
OP_OUTPUTTOKENCATEGORY return the category reversed from display order,
followed by `0x01` for mutable or `0x02` for minting.

A property test MUST check that random valid insertion sequences from a
partitioned genesis never produce overlapping or uncovered ranges. That test
MUST use a seeded pair of overlapping records, which allows a double
insertion, as its firing control.

#### Scenario: Overlapping genesis

- **WHEN** a genesis contains two overlapping range records
- **THEN** genesis validation MUST refuse the deployment

#### Scenario: Single-record genesis

- **WHEN** a deployment artifact specifies `g = 0`, one range record covering
  the whole key space
- **THEN** genesis validation MUST refuse the deployment, because no action's
  two nullifiers can lie in two distinct records, so no settlement could ever
  split the record

#### Scenario: Hidden minting record outside the advertised set

- **WHEN** a genesis transaction creates the advertised records plus a further
  range-category minting NFT, for example under a deployer's key or under the
  record lock of overlapping data
- **THEN** the wallet's full category-output audit MUST refuse the deployment,
  even though the advertised records alone match the artifact

#### Scenario: Capability leaves the covenant later

- **WHEN** a transaction spending a range record sends a range-category minting
  or mutable token to any lock other than a record lock for the split data
- **THEN** the covenant MUST reject it

#### Scenario: Category byte order confused

- **WHEN** a covenant constant or a test fixture uses a category in display
  order where wire order is required
- **THEN** a test with a non-palindromic category MUST fail

### Requirement: Every check is shown to be load-bearing or recorded as overlapped

For each covenant check, tests MUST run in both the consensus and standard
2026 VMs with non-palindromic outpoints, categories and nullifier values.

- **Where a distinguishing attack exists**, a test MUST ablate that check alone
  and observe the attack succeed.
- **Where other guards also refuse the attack**, the test MUST record which
  guards refuse it when the check alone is ablated, and the smallest ablation
  that lets it pass. Examples are Opus E1's missing-authority (S1) and layout
  (S5) cases.

No check MAY be removed or weakened because its single ablation shows no
effect.

#### Scenario: Check removed

- **WHEN** a single check with a distinguishing attack is removed from the
  covenant
- **THEN** its named attack MUST pass in both VMs, proving the check matters

#### Scenario: Overlapping guards

- **WHEN** a single check is removed and its attack is still refused by another
  guard
- **THEN** the test MUST record the overlap and the guard pair, and the check
  MUST stay in the covenant

### Requirement: Contention costs a rebuild, not a proof

A settlement that loses a race for a range record MUST be re-assemblable
against the new records without a new proof or new owner signatures, because
the verdict and the signatures bind statement values, not input outpoints.

#### Scenario: Concurrent split

- **WHEN** a range record a pending settlement intended to spend is split by
  another settlement first
- **THEN** the pending settlement MUST be rebuildable against the resulting
  record with the same verdict and signatures
