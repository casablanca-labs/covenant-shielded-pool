# apnt-pool-versioning-migration

## ADDED Requirements

### Requirement: Every pool deployment is versioned

Every domain tag, category, statement and verifier binding of a pool deployment
MUST carry a pool version, through its tags and its `deployment_id`. A
deployment MUST NOT accept statements, verdicts or records of another version
except through the specified migration shape.

#### Scenario: Old verdict used in a new pool

- **WHEN** a settlement in pool version n+1 presents a verdict of version n
- **THEN** it MUST be rejected

### Requirement: A migration path exists before deployment

Before any pool accepts value, its specification MUST define the migration
shape of `design.md` ("Versioning and migration") and test it locally, with
the one Chipnet exception below. Moving
value `W` from pool `n` to pool `n+1` takes two steps.

**Step 1.** An ordinary pool-`n` action whose inputs are the owner's pool-`n`
notes, with `withdrawal = W`. Its `wlock_hash` is the SHA-256 of pool `n+1`'s
deposit inbox lock for step 2's record `A_new` (operator decision HUM-104,
2026-09-27; `apnt-pool-settlement-custody`, "Deposits enter through a
record-keyed pool inbox"):

```text
D(A_new)     = cm_new ‖ packet_new ‖ u64le(W) ‖ rk_0      (89 bytes)
wlock_hash   = SHA-256(P2SH32(push(D(A_new)) ‖ CODE_{n+1}))
```

`rk_0` is step 2's slot-0 re-randomized key, which the owner derives from
the seed and the migration counter. The deployment is bound by
`CODE_{n+1}`, which embeds pool `n+1`'s settlement lock and verdict
category. The owner's signatures over pool `n`'s `m`, which commits its
`ad`, therefore bind the new note and its refund key
(`apnt-pool-settlement-custody`, discovery-tag slot). Settlement check 5
makes step 1's withdrawal output token-free, of exactly `W`, under that lock.

Before signing step 1, the owner MUST apply the wallet's pre-funding binding
to pool `n+1` (`apnt-pool-receive-recovery`, "A wallet funds a deposit inbox
only after its pre-funding binding"). It selects pool `n+1`'s deployment and
establishes its genesis from its own chain read and the genesis validator. It
takes `CODE_{n+1}` from the reviewed inbox build bound to that deployment, and
derives `A_new` and its `rk_0` itself. It then checks its own step-1 record's
`wlock_hash` and `withdrawal` against that lock and `W`.

Current implementation: the shipped migration host still commits step 1 to
the hashed form
`h = SHA-256("APNT-POOL-v1:migrate" ‖ deployment_id_{n+1} ‖ cm_new ‖ SHA-256(packet_new) ‖ u64le(W))`,
over a 104-byte preimage after the tag, with `wlock_hash` the hash of the
inbox lock built from `h` and no `rk_0`. The migration host change (ENG-538)
MUST move to the 89-byte `D`, add an `rk_0` check with its own failure code,
and retire the `migrate` tag without reusing it. Its new revision MUST
supersede the two committed `reference.inbox` frontier vectors, the host's
migration tests of the 104-byte preimage and the boundary test's 104-byte
cases, and MUST NOT edit any of them in place.

**Step 2.** A pool-`n+1` deposit action with two dummy inputs and
`deposit = W`. Its output 0 is `cm_new`, with `v = W − fee_{n+1}` and
`packet_new` under the owner's change keys for its `ρ_out_0`, the nullifier of
its dummy input 0 (`apnt-pool-receive-recovery`); its output 1 is a dummy,
with `ρ_out_1` the nullifier of its dummy input 1. It consumes step 1's
withdrawal output as its inbox.

That inbox is pool `n+1`'s deposit inbox, with its guarantee and its limit
(`apnt-pool-settlement-custody`, "The inbox guarantee and its limit are
stated exactly"). It MUST release its value only into a pool-`n+1` settlement
whose statement carries `A_new`, or to `rk_0`'s key after the 1,008-block
refund delay, so value does not strand when pool `n+1` cannot settle it. A
refunded migration's value leaves as transparent BCH, and its migration
counter MUST be retired like any refunded deposit's.

The following MUST hold:

- the step-2 dummy values are derived from the seed and a migration counter,
  so the step can be rebuilt after restore;
- the step-2 outputs carry discovery tags by the v1 fill rules
  (`apnt-pool-receive-recovery`, "Every output's discovery tag follows the v1
  fill rules"): output 0's is `dt(K_ρ, 0x00)` for its change key `K_ρ` of
  `ρ_out_0`, and output 1's is `dt(K_dt(ρ_out_1), 0x00)` with
  `K_dt(ρ_out_1) = SHA-256("APNT-POOL-v1:wallet-dummy-dt" ‖ D ‖ ρ_out_1)`, where
  `D` is the builder's dummy root. Output 1's tag MUST NOT be `dt(K_d, 0x00)`
  for the counter-derived dummy output key `K_d` (the dummy layout's field 18),
  nor any other value determined by the migration counter alone: a counter
  reused for another action whose slot-1 input is a different real note
  repeats `K_d` across two outputs that both settle (REV-186 H1-R377-1). The
  tags are bound by the step-2 action's owner signatures like any action's; the
  inbox data `D` does not include them;
- each pool's fee is paid in that pool;
- the old pool keeps a withdrawal path for the life of its covenants.

**Chipnet exception (operator decision, 2026-09-24, on ARCH-140; narrowed by
HUM-104, 2026-09-27).** HUM-104 makes the inbox covenant (task 3.6) the
deposit inbox, v1's only deposit path, so a genesis without it takes no
deposits. The first Chipnet pool genesis MUST therefore carry the deposit
inbox: its code pinned through artifact revision 2 with the genesis inbox
check, and the local ledger's BIP68 rule tested. It MAY proceed without the
locally tested migration action (task 7.1) and the migration host change.
That deployment is an explicitly labelled zero-value test
(`apnt-pool-settlement-custody`, "No setup holder guards pooled value"), and
its tester-facing documentation MUST say that it has no tested migration
path to a successor pool. The exception covers only that first Chipnet
genesis. The deposit inbox, with its negatives, and the tested migration
action remain required before any value-bearing deployment. This narrowing
is a consequence of HUM-104, not a separate operator decision.

The canonical inbox and local two-pool covenant composition exist. The exported migration host still implements the older hashed preimage without the record-keyed refund key, not the specified two-step wallet/host migration path. The record-keyed target and pre-funding genesis binding remain required. VM’s exception covers only the first labelled zero-value Chipnet genesis. The record, including ENG-694 and its successors, was not searched for the Chipnet genesis count. A count is [not found] in the named report, plan and source inputs inspected for this reconciliation and remains NOT VERIFIED; this report cannot identify any new deployment as covered or widen that exception. No current end-to-end migration is demonstrated. Before relying on the exception, bind an authorized deployment-count record; do not infer a count from source or test fixtures.


#### Scenario: First Chipnet genesis without the migration action

- **WHEN** the first Chipnet pool genesis is proposed, with the deposit inbox
  pinned, before the migration action is tested, as an explicitly labelled
  zero-value test
- **THEN** it MAY proceed, and its tester-facing documentation MUST say that
  the deployment has no tested migration path

#### Scenario: Chipnet genesis without the deposit inbox

- **WHEN** a Chipnet pool genesis that is to take deposits is proposed before
  the deposit inbox and artifact revision 2 exist
- **THEN** it MUST NOT proceed on the 2026-09-24 exception, which no longer
  covers the inbox

#### Scenario: Value-bearing deployment without the inbox

- **WHEN** a pool deployment that is not an explicitly labelled zero-value
  test is proposed before the deposit inbox, with its negatives, and the
  locally tested migration action exist
- **THEN** it MUST be refused

#### Scenario: Exception stretched to a later deployment

- **WHEN** a later Chipnet deployment, or any deployment described as covered
  by the first Chipnet genesis's exception, is proposed without the tested
  migration action
- **THEN** it MUST NOT proceed on that exception; it needs the migration
  action or a new operator decision

#### Scenario: Step 1 toward a lock the owner did not compute

- **WHEN** a migration's step 1 would withdraw to a lock that is not the
  owner's own `L_{n+1}(A_new)`, whether from a supplied successor record, a
  supplied successor artifact or code, another `rk_0`, or another `W`
- **THEN** the owner's wallet MUST refuse before signing step 1

#### Scenario: Migration inbox refunded

- **WHEN** pool `n+1` does not settle a migration's step 2 and the 1,008-block
  refund delay has matured
- **THEN** the owner MUST be able to refund the inbox with `rk_0`'s key,
  derived from its seed and migration counter, and MUST retire that counter

#### Scenario: Migration dummy tag under a reused counter

- **WHEN** a store reuses a step-2 action's migration counter for a later
  action whose input slots hold real notes, the slot-1 note differing from the
  step-2 dummy input 1, and whose output 1 is a dummy, so that the two actions
  insert distinct nullifiers and both settle with distinct `ρ_out_1`
- **THEN** their output-1 tags MUST differ, up to the accidental 64-bit
  collision residual, and a retry of step 2 from the stored action MUST
  reproduce its tags. A negative test MUST show that a build filling migration
  output 1 with `dt(K_d, 0x00)` from the dummy layout's field 18 repeats the tag
  across the two, and the build MUST be rejected

#### Scenario: Soundness bug found after deployment

- **WHEN** a soundness bug is found in a deployed pool version
- **THEN** users MUST be able to migrate or withdraw without any party holding
  an upgrade key

#### Scenario: Inbox diverted

- **WHEN** a transaction spends a migration inbox into anything other than a
  pool-`n+1` settlement of a statement carrying `A_new`, with its `cm_new`,
  `packet_new`, deposit `W` and `rk_0`, or other than by `rk_0`'s refund after
  the delay
- **THEN** the inbox covenant MUST reject it, including a duplicate inbox, an
  inbox holding other than `W` or a token, and a forged first push at input 0

#### Scenario: Migration completed by another party

- **WHEN** step 1 has confirmed and the owner is offline
- **THEN** any party holding the step-2 action MUST be able to settle it, and
  only the committed note MUST result

### Requirement: The limit of migrating out of an unsound pool is disclosed

Documentation MUST state the limit. If a pool's proof system is unsound,
counterfeit notes can withdraw or migrate pooled BCH ahead of honest users.
The retained withdrawal path therefore cannot guarantee that enough BCH remains
to honour honest notes, which are paid first-come-first-served from what
remains. Migration repairs no loss. The withdrawal path works only while
someone can still produce that pool's proofs.

#### Scenario: Migration described as a rescue

- **WHEN** a document says users can always recover their full balance by
  migrating out of an unsound pool
- **THEN** it MUST be corrected

### Requirement: Legacy successor notes leave by exit

Notes of the seal-cell successor profile MUST enter the pool by exit to
transparent BCH followed by a deposit, and every multi-cell exit MUST disclose that it
publishes the note's cell partition through common-input ownership. A one-cell
exit's disclosure MUST say that it publishes no multi-cell partition. The seal-era legacy test note is permanently
unspendable and MUST NOT be described as migratable.

#### Scenario: Legacy note migration claimed

- **WHEN** any document describes the seal-era legacy test note as migratable or
  spendable
- **THEN** it MUST be corrected
