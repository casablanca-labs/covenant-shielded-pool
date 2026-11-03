# apnt-pool-note-tree

## ADDED Requirements

### Requirement: Roots are carried by interchangeable root copies

The note-tree root MUST be carried by `K ≥ 2` root copies. A root copy is a
keyless covenant UTXO with an immutable NFT of the pool's root category whose
32-byte commitment is the root. A settlement that uses a copy MUST recreate it
exactly: same lock, category and commitment, and value not reduced. Only a
transaction with the settlement authority of `apnt-pool-settlement-custody`
MAY spend a copy.

A root authenticates membership only through the settlement's anchor check:
every action's anchor MUST equal the root of a copy spent in the same
settlement, one copy per distinct anchor (`apnt-pool-settlement-custody`). Old
copies are never destroyed, so every folded root stays usable as an anchor.

#### Scenario: Two spends in one period

- **WHEN** two settlements use the same root concurrently
- **THEN** they MUST be able to use different copies with no shared input

#### Scenario: Griefing a root copy

- **WHEN** a transaction without the settlement authority spends a root copy
- **THEN** the covenant MUST reject it

#### Scenario: Membership under a root no copy carries

- **WHEN** an action's anchor is a root that no root copy carries, such as a
  tree the prover built itself
- **THEN** every settlement that includes it MUST be refused

### Requirement: The note tree is a depth-32 SHA-256 incremental Merkle tree

The note tree MUST have these parameters:

- depth 32;
- leaves are output commitments;
- the empty leaf is 32 zero bytes;
- `node(l, r) = SHA-256("APNT-POOL-v1:node" ‖ l ‖ r)`;
- capacity is `2^32 − 1` leaves.

Its state MUST be a leaf count `n` and a frontier `F` of 32 entries of 32 bytes,
updated and rooted by the `append` and `root` procedures of `design.md`.

The tree update's token commitment MUST be `u64le(n) ‖ H_F ‖ root`, with
`H_F = SHA-256("APNT-POOL-v1:frontier" ‖ u64le(n) ‖ F)`.

A settled batch's leaves MUST be appended in statement order: `cm_0`, then
`cm_1`, of each record in turn.

The empty frontier MUST be `n = 0` with `F = 0^1024`, every `F_h` equal to
the empty leaf. Its hash is
`H_F(empty) = c7ca2937937715ce2c099dbba659474356271f8f0516b9181f61f00dfa462363`
and its root is
`Z_32 = bbe056523758e93a054eaa2840428f3ece539fb79fe16ce919ebd23898abfc4b`, so
the genesis tree update's commitment MUST be `u64le(0) ‖ H_F(empty) ‖ Z_32`.

`F_h` MUST keep what `append` last wrote at level `h`, including entries that
no root reads any more, and `H_F` MUST cover them. The canonical frontier is
exactly what `append` produces from the empty frontier. No implementation MAY
clear, zero or replace a stale entry.

#### Scenario: Genesis frontier

- **WHEN** a genesis or a wallet starts the tree from entries `F_h = Z_h`, or
  from any frontier other than `F = 0^1024` with `n = 0`
- **THEN** its `H_F` differs from `H_F(empty)`, and the genesis audit and the
  tree update MUST refuse it

#### Scenario: Stale frontier entry cleared

- **WHEN** a tree update pushes a frontier in which a stale entry has been
  cleared, which leaves the root unchanged
- **THEN** its `H_F` no longer matches the committed one, and the covenant MUST
  refuse it, even where folding from the cleared frontier would give the honest
  next state

#### Scenario: Tree full

- **WHEN** an append would make `n` exceed `2^32 − 1`
- **THEN** the tree update MUST refuse it, and value moves only by migration

#### Scenario: Reference parity

- **WHEN** the frontier procedures are implemented in the host, a circuit or a
  covenant
- **THEN** they MUST match a naive full-tree computation on shared vectors that
  cover carries through every level

### Requirement: The tree update recomputes the frontier in script

A single tree-update UTXO MUST hold the root category's minting capability and
the committed frontier. It MUST be spent only in a transaction that:

- has the pending batch verdict at input 1: an input under a pending-batch
  lock, whose redeem carries the batch's `H_cm`, and whose token is of the
  verdict category with no capability;
- pushes the batch's `64·B` bytes of leaves, not the statement;
- checks `H_F` against its own commitment and the SHA-256 of the pushed
  leaves against `H_cm`;
- appends the batch's commitments in script, refusing to pass capacity;
- recomputes the new root in script;
- creates exactly one tree update with the new commitment and `K` immutable root
  copies of the new root;
- burns the pending verdict.

No other output MAY carry the root or verdict category.

The tree update MUST NOT require any signature, and MUST NOT be touched by
individual spends. The proof MUST NOT be trusted to attest the new root.

#### Scenario: Anyone folds

- **WHEN** any party holds an authentic pending batch verdict and the batch's
  statement, from which it takes the leaves
- **THEN** it MUST be able to build the tree update without a key or permission

#### Scenario: Forged batch folded

- **WHEN** a tree update consumes a pending output not produced by an authentic
  settlement
- **THEN** the covenant MUST reject it

#### Scenario: Fabricated root

- **WHEN** a tree update mints root copies whose root is not the SHA-256 append
  of the settled commitments to the committed frontier
- **THEN** the covenant MUST reject it

#### Scenario: Tampered frontier or leaf count

- **WHEN** the pushed frontier or leaf count does not hash to the tree update's
  committed `H_F`
- **THEN** the covenant MUST reject it

#### Scenario: Batch folded twice

- **WHEN** a batch's pending verdict has already been folded
- **THEN** no second fold of that batch MUST be possible, because the fold burns
  the pending verdict

### Requirement: Root authentication uses SHA-256

The tree frontier and every root MUST be computed with domain-separated
SHA-256. Design question D1 is resolved in favour of script recomputation. Any
change to that MUST follow a reviewed measurement and an operator decision.

#### Scenario: Circuit-friendly hash proposed for the tree

- **WHEN** a slice proposes a prime-field hash for the note tree
- **THEN** it MUST first be recorded as an operator decision, stating its effect
  on script verification and on future Binius64 adoption
