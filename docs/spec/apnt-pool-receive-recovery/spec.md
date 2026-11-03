# apnt-pool-receive-recovery

## ADDED Requirements

The wallet copies payment invoice tags and derives change/dummy tags from their own rho-bound keys. Routine decoding and wallet-owned scan/acceptance components exist; wallet inbox funding/refund and aggregator inbox admission/carry-through exist. This is source status, not a certified live run. The fallback is the capped blind prefix in E08; targeted rescan and extended per-epoch deep scan remain absent. The migration host is still in its older hashed form. Fresh restore and restored-wallet refund are deferred Phase 3 exercises. Covenant tag slots check owner authorization, not honest tag fill or payment ownership. Legacy self-deposit exports remain prohibited v1 evidence as E24 records.
Key derivation and issuance alone are not recovery or spendability.

### Requirement: Receiving does not require the recipient online

A payer MUST be able to create a recipient's note from a sealed per-payment
invoice while the recipient is offline. The invoice MUST be exactly
`(v, O_I, K_I, dt_I, payment id, E_I)` for the invoice id `I` of "Invoice ids
pair a random epoch with a sequential index", with:

- `v ∈ [0, MAX_MONEY]`;
- `dt_I` the invoice's 8-byte payment tag and the payment id its 16-byte
  value, both from "Tags and payment ids encode the invoice id";
- `E_I` the invoice's expiry height, an unsigned 32-bit block height with
  `t_I + 1 ≤ E_I ≤ t_I + T` (see "The per-epoch window scan follows the V1
  window").

It MUST NOT contain the spend key `ak_I`, the nullifier key `nk_I`, the spend
secret `ask_I`, the invoice id `I`, its epoch or its index, or any reusable
address. Nothing from the invoice MAY appear on chain except `dt_I`, which the
payer writes, unchanged, into its payment output's discovery-tag slot ("Every
output's discovery tag follows the v1 fill rules"). The invoice carries the
recipient-issued tag by operator decision HUM-77 (2026-09-24).

`E_I` is payer-visible timing metadata, and MUST be disclosed as such wherever
the invoice's contents are described. It adds no chain bytes, reveals no key
and links no two invoices, but it gives the payer the invoice's exact expiry
height and, with the profile's public `T`, a range of at most `T` heights for
the recipient's anchor-confirmed read at issue.

#### Scenario: Recipient offline at payment time

- **WHEN** the recipient is offline during the payer's action and its settlement
- **THEN** the payment MUST still settle, and the recipient MUST be able to find
  it later

#### Scenario: Key material in the invoice

- **WHEN** a byte scan of an issued invoice looks for `ak_I`, `nk_I`, `ask_I`
  or the eight bytes of `I`
- **THEN** it MUST find none, and the scan MUST fire on a control invoice that
  contains one

#### Scenario: Expiry described as revealing nothing

- **WHEN** documentation says an invoice tells the payer nothing about the
  recipient's timing
- **THEN** it MUST be corrected to name `E_I` as payer-visible timing metadata

#### Scenario: Invoice expiry outside its bounds

- **WHEN** a wallet is asked to issue an invoice whose `E_I` is at most `t_I` or
  above `t_I + T`, or a payer receives an invoice with no `E_I`
- **THEN** the wallet MUST refuse to issue it, and the payer MUST refuse to pay
  it

The issuer MUST check t_I + 1 <= E_I <= t_I + T against its own confirmed scan height and refuse issuance outside it. The payer MUST refuse an invoice without E_I, validate its unsigned-height encoding and refuse begin at or above E_I. The six-field invoice carries no authenticated issuer height t_I, so no payer verification of that hidden issuance-time bound is asserted. Payer-visible expiry timing metadata MUST remain disclosed. This clarifies the paired clauses; it adds no invoice field or payer obligation.


#### Scenario: Invoice without its tag or payment id

- **WHEN** a payer receives an invoice without an 8-byte `dt_I`, or with a
  payment id that is not 16 bytes
- **THEN** it MUST refuse to pay it and MUST NOT derive a tag of its own

### Requirement: Wallet keys derive from the seed along fixed paths

The wallet MUST derive its pool keys from its 32-byte seed and the pool
deployment's 32-byte `deployment_id` as follows. `b` is the branch byte
(`0x00` invoice, `0x01` change), `I` an 8-byte invoice id ("Invoice ids pair a
random epoch with a sequential index"), `ρ` a change output's own 32-byte `ρ`,
and `a` a one-byte rejection attempt. `kr_0`, `nr_0`, `τ_0`, `ask_0` and `ak_0`
are the branch values for `b = 0x00`, and `kr_c`, `nr_c`, `τ_c`, `ask_c` and
`ak_c` those for `b = 0x01`. The per-invoice-id lines replace the earlier
per-index ones (operator decision HUM-77, 2026-09-24):

```text
R_seed = SHA-256("APNT-POOL-v1:wallet-root"       ‖ seed32)
R     = SHA-256("APNT-POOL-v1:wallet-deployment"  ‖ R_seed ‖ deployment_id)
ask_b = scalar("APNT-POOL-v1:wallet-branch-ask"    ‖ R ‖ b ‖ a)
τ_b   = SHA-256("APNT-POOL-v1:wallet-branch-tweak" ‖ R ‖ b)
nr_b  = SHA-256("APNT-POOL-v1:wallet-branch-nk"    ‖ R ‖ b)
kr_b  = SHA-256("APNT-POOL-v1:wallet-branch-k"     ‖ R ‖ b)

invoice branch (b = 0x00) only, per invoice id I:
tw_I  = scalar("APNT-POOL-v1:wallet-epoch-tweak"   ‖ τ_0 ‖ SEC1c(ak_0) ‖ I ‖ a)
ask_I = (ask_0 + tw_I) mod n_G,   ak_I = ak_0 + tw_I·G
nk_I  = SHA-256("APNT-POOL-v1:wallet-epoch-nk"     ‖ nr_0 ‖ I)
K_I   = SHA-256("APNT-POOL-v1:wallet-epoch-k"      ‖ kr_0 ‖ I)
k_dt  = SHA-256("APNT-POOL-v1:wallet-dtag-key"     ‖ kr_0)
k_pid = SHA-256("APNT-POOL-v1:wallet-epoch-pid"    ‖ R)

change branch (b = 0x01) only, per change output with public ρ:
t_ρ   = scalar("APNT-POOL-v1:wallet-rho-tweak"     ‖ τ_c ‖ SEC1c(ak_c) ‖ ρ ‖ a)
ask_ρ = (ask_c + t_ρ) mod n_G,   ak_ρ = ak_c + t_ρ·G
nk_ρ  = SHA-256("APNT-POOL-v1:wallet-rho-nk"       ‖ nr_c ‖ ρ)
K_ρ   = SHA-256("APNT-POOL-v1:wallet-rho-k"        ‖ kr_c ‖ ρ)
```

- `R` is per deployment. Every other wallet derivation MUST take this `R`:
  the branch values, `k_pid` and the dummy root. (An output's `rcm` is not a
  wallet derivation: it is `SHA-256("APNT-POOL-v1:rcm" ‖ K ‖ ρ)`, which the
  relation derives, `apnt-pool-note-statement`.) A
  wallet so has independent keys, tags, payment ids, dummies, action counters
  and viewing keys in each deployment, and nothing derived in one deployment
  repeats in another. `R_seed` MUST NOT leave the wallet.
- `O_I` and `tag_I` follow from `ak_I`, `nk_I` and `K_I` by the host's note
  encodings.
- `k_dt` derives from `kr_0`, so the incoming viewing tier derives it. `k_pid`
  derives from `R`, and MUST NOT leave the wallet.
- `scalar(·)` MUST take the first `a = 0, 1, …` whose digest, read as a
  big-endian integer, lies in `[1, n_G − 1]`.
- A zero `ask_I` or `ask_ρ` MUST be refused.
- Each tag MUST take one fixed input length.
- The `wallet-epoch-*` and `wallet-dtag-key` derivations MUST NOT be applied
  to the change branch, and the `wallet-rho-*` derivations MUST NOT be applied
  to the invoice branch.
- The wallet's seventeen `APNT-POOL-v1:wallet-*` tags (`wallet-root`,
  `wallet-deployment`, `wallet-branch-ask`, `wallet-branch-tweak`,
  `wallet-branch-nk`, `wallet-branch-k`, `wallet-epoch-tweak`,
  `wallet-epoch-nk`, `wallet-epoch-k`, `wallet-dtag-key`, `wallet-epoch-pid`,
  `wallet-rho-tweak`, `wallet-rho-nk`, `wallet-rho-k`,
  `wallet-dummy-seed`, `wallet-dummy-field` and `wallet-dummy-dt`) and the
  host's sixteen pool tags, `APNT-POOL-v1:dtag`, `APNT-POOL-v1:dt-auth`,
  `APNT-POOL-v1:rcm` and `APNT-POOL-v1:pad` included, MUST be distinct and
  pairwise prefix-free.
- The four retired invoice-index tags, `wallet-index-tweak`,
  `wallet-index-nk`, `wallet-index-k` and `wallet-payment-id`, and
  `wallet-output-rcm`, retired by pad16 (HUM-84, ENG-454), MUST NOT be used
  to derive any value of a v1 wallet.

Per-invoice and per-output spend keys are an additive tweak of their branch key
(operator decision HUM-67). This MUST be disclosed wherever viewing keys are
described: a full viewing key together with any one leaked `ask_I` or `ask_ρ`
yields that branch's `ask_b` in that deployment, and so every spend key of that
branch there, as with a BIP-32 extended public key. No `ask_I`, `ask_ρ`,
`ask_b` or `rsk` MAY leave the wallet.

#### Scenario: Spend key and tweak agree

- **WHEN** a wallet derives `ask_I` and `ak_I` for an invoice id, or `ask_ρ`
  and `ak_ρ` for a change output
- **THEN** `ask·G` MUST equal `ak`, and a build that leaves `tw_I` or `t_ρ` out
  of the spend key MUST fail that check

#### Scenario: One seed in two deployments

- **WHEN** one seed uses the same invoice id, the same change `ρ`, and the same
  action counter and dummy slot in two deployments
- **THEN** their `K`, `nk`, `ak`, `O`, payment tag `dt_I`, payment id, dummy
  nullifier and discovery tags MUST all differ, a witness from one deployment
  MUST open no packet and yield no nullifier of the other, and a negative test
  MUST show that a build omitting `deployment_id` repeats them, tags and
  payment ids included, and opens the other deployment's packet

#### Scenario: Wallet tag collides with a host tag

- **WHEN** a wallet tag is a prefix of another wallet or host tag, or equal to
  one
- **THEN** the tag-set test MUST fail, and it MUST be shown to fire on
  `APNT-POOL-v1:wallet-epoch-key`, `APNT-POOL-v1:wallet-epoch`,
  `APNT-POOL-v1:wallet-dtag` and a duplicate

#### Scenario: Viewing key described without the branch disclosure

- **WHEN** documentation offers a full viewing key without stating that it,
  plus one leaked per-invoice or per-output spend key, exposes every spend key
  of that branch
- **THEN** it MUST be corrected

### Requirement: Change keys derive from each output's public ρ

Every change or self-transfer output MUST take `K_ρ`, `nk_ρ` and `ak_ρ` from
the change branch and that output's own `ρ` ("Wallet keys derive from the seed
along fixed paths"), with `O_ρ` and `tag_ρ` following by the host's note
encodings. Output `j` of an action has `ρ = nf_in_j`, public in the action's
record. The following MUST hold:

- the wallet MUST fix which input fills slot `j`, and so `ρ`, before it
  derives output `j`'s keys. A retry that keeps the same input in slot `j`
  MUST reproduce the keys; any other change of input or slot gives new keys;
- when `ask_ρ = 0`, the wallet MUST plan that output in the other slot or with
  other inputs;
- discovery MUST check each output exactly once for change, under `K_ρ` for
  that output's own `ρ`: by comparing `dt(K_ρ, 0x00)` with its discovery tag,
  or by one trial decryption of its packet ("Discovery decodes tags locally,
  with the per-epoch window as fallback"). Every change note's key is a
  function of the wallet's change root and public data of its own record, so
  the one-trial scan finds every change note whatever its settlement delay,
  retries, restores or action counter, and the tag check finds every correctly
  tagged one;
- the change branch has no index, no epoch, no gap constant, no in-flight
  allocation and no restore handling. `G_chg`, the change gap rule and change
  allocation are retired;
- no output the wallet plans for itself uses invoice-branch material. The
  disclosed gap-closing output, the one earlier exception, is retired with gap
  closing (HUM-77).

Within one deployment every nullifier is inserted once, so at most one
settled output has a given `ρ`; with the per-deployment `R`, no change note of
another deployment shares its keys. Candidate actions are different. Every
change output the wallet plans in slot `j` over the same input in slot `j`, in
one deployment, has the same `ρ` and so the same `K_ρ`, `nk_ρ` and `ak_ρ`: this
set of candidate outputs is that change output's **`ρ` family**, and at most
one member settles. The keys bind the family, not one candidate; the packet
digest still binds each member's own `cm`, so no digest pads two different
plaintexts.

A change output's witness therefore discloses its whole `ρ` family. Its holder
can derive every member's packet digest from `K_ρ` and that member's public
`cm`, open the packet, learn `v`, derive `rcm`, and compute the nullifier from
`nk_ρ`. That
includes the member that settles, which can be a later candidate than the one
it saw. It discloses no change output with another `ρ`, and nothing of another
deployment. The wallet MUST present the delegation of an action as disclosing
the `ρ` family of each of its change outputs. A wallet that must keep a later
candidate's change from an earlier candidate's delegate MUST give that change
output another `ρ`, by moving it to the other slot or choosing another input.

#### Scenario: Change of a withheld action

- **WHEN** an aggregator withholds a signed action of the wallet and settles it
  hundreds of blocks later
- **THEN** the one-trial-per-packet scan and the tag check MUST each find its
  change, and a negative test MUST show that change under an indexed key,
  scanned with the invoice window, loses a withheld change note

#### Scenario: Change keyed on the action counter

- **WHEN** a build derives change keys from the per-action counter, or from any
  value that is not public in the output's own record, instead of from `ρ`
- **THEN** the negative test MUST show the `ρ` scan loses those notes, withheld
  ones included, and the build MUST be rejected

#### Scenario: Change key without the secret root

- **WHEN** a build derives a change `K` from `ρ` without `kr_c`
- **THEN** a party without the seed MUST be shown to decrypt its change, the
  negative test MUST fire, and the build MUST be rejected

#### Scenario: Witness opens its `ρ` family

- **WHEN** a prover-delegable witness for one candidate's change output is
  tried against a later candidate's change packet that keeps the same input in
  the same slot, with another value and `cm`
- **THEN** a test MUST show that it opens that packet and computes its
  nullifier, and the wallet's delegation disclosure MUST name the `ρ` family

#### Scenario: Witness tried outside its `ρ` family

- **WHEN** a prover-delegable witness for one change output is tried against a
  change packet with another `ρ`, or against any packet of another deployment
- **THEN** it MUST open none of them and MUST yield none of their nullifiers

### Requirement: Viewing tiers bind notes only at the full tier

The wallet MUST offer two viewing tiers, each for one deployment, and neither
MAY hold `ask_b`, any `ask_I` or `ask_ρ`, `k_pid`, `R_seed` or the seed:

- the **incoming** tier, `kr_b` of both branches. It derives every `K_I`,
  every `K_ρ`, `k_dt`, their recovery tags and their discovery tags, and so can
  decode discovery tags and decrypt packets. It cannot derive `O_I` or `O_ρ`.
  Its result MUST be labelled an **owner-unverified candidate**, and MUST NOT
  be treated as an opening or used as an input to acceptance. It cannot
  compute the routine scan's `u_e`, which counts only owner-verified openings,
  so no window scan of it MAY be described as finding every invoice note. Its
  decode finds every correctly tagged invoice candidate; its complete scan for
  mis-tagged invoice candidates is the per-epoch deep scan with `u_e` taken
  over candidates, in the epochs it has decoded. Its change-candidate scan is
  one trial per packet, and complete. Its decoded ids reveal every payment's
  epoch and index, and so when the wallet restored, started an issuing session
  or opened an epoch, and how many invoices each epoch issued. This MUST be
  disclosed wherever the incoming viewing key is described;
- the **full** tier, which adds `nr_b`, `τ_b` and `ak_b` of each branch. It
  derives `nk_I`, `ak_I`, `O_I`, `nk_ρ`, `ak_ρ` and `O_ρ`, MUST recheck `cm`
  under the wallet's own `O`, and computes nullifiers and the routine scan's
  `u_e`. Only its result, an **owner-verified opening**, MAY feed acceptance,
  and it is not itself acceptance. It cannot spend. Its holder can fund an
  owner-verified note to any invoice id, which burns that id when found and,
  above `h_e` in the wallet's current epoch, closes that epoch ("Invoice ids
  pair a random epoch with a sequential index"). It can also form invoices
  `(v, O_I, K_I, dt_I, payment id, E_I)` under the wallet's keys without the
  wallet, for ids it learns by decoding, including ids above `h_e` in the
  current epoch; a payer of such an invoice and a later payer of the same id
  from the wallet can read each other's packets. Both MUST be disclosed
  wherever the full viewing key is described.

The incoming tier MUST detect candidates with the host's packet detection,
which checks the packet's key check under `K` and the public `ρ` and `cm` and
returns the padded value, at most `MAX_MONEY`, as an owner-unverified
candidate, so that the host stays the only authority on the packet format.

#### Scenario: Foreign owner sealed under the wallet's key

- **WHEN** a payer holding `K_I` seals a note paying its own `O` under the
  wallet's `K_I`
- **THEN** the incoming tier MAY report it only as an owner-unverified
  candidate, and the full tier's `cm` recheck MUST refuse it

#### Scenario: Incoming tier described as detecting received notes

- **WHEN** documentation says the incoming viewing key detects or decrypts the
  wallet's received notes, without saying its results are owner-unverified, or
  says its window scan finds every invoice note
- **THEN** it MUST be corrected

#### Scenario: Incoming tier described without the epoch disclosure

- **WHEN** documentation offers the incoming viewing key without stating that
  its holder decodes every payment tag to its epoch and index, and so learns
  the wallet's restores, sessions, epoch openings and issuance per epoch
- **THEN** it MUST be corrected

#### Scenario: Full viewing key described without the issuer disclosure

- **WHEN** documentation offers the full viewing key without stating that its
  holder can fund notes to any invoice id and can form invoices under the
  wallet's keys whose ids the wallet may issue again
- **THEN** it MUST be corrected

### Requirement: Invoices are single use and change is private

The wallet MUST derive two independent seed branches:

- an invoice branch, per invoice id: `(ask_I, nk_I, K_I)` for invoice id `I`;
- a change branch, per output: `(ask_ρ, nk_ρ, K_ρ)` for a change output with
  public `ρ`.

It MUST issue an invoice id to at most one payment request and never issue it
again. The one disclosed exception is the epoch-collision residual of "Invoice
ids pair a random epoch with a sequential index", which no rule of a single
store can remove. Issuance follows that requirement. Every index at or below
`h_e` in an epoch of the store's table is issued or burned, and MUST NOT be
issued again. A request MAY name an invoice id:

- a named id in an epoch of the store's table, at an index at or below that
  epoch's `h_e`, MUST be refused as reuse;
- any other named id MUST be refused as out of order. That covers an id in the
  current epoch above `h_e + 1`, an id in a closed epoch or in an epoch not in
  the table, and any named id when the store must open an epoch before its
  next issuance;
- a fresh id MUST be issued only on a new request, which names no id or names
  exactly the next id of the current epoch when no epoch must be opened;
- a refusal MUST NOT substitute another id. A full index range in the current
  epoch opens a fresh epoch; it is never refused as exhaustion, wrapped, or
  answered with an existing id.

Every change or self-transfer output MUST use the change-branch keys for its
own `ρ`. No output the wallet plans for itself MAY use an invoice-branch key, a
payment tag, or any key a payer has received.

One wallet-allocated per-action counter MUST identify an action across all
its candidates and retries. It keys its dummies. (Until pad16 it also keyed
the `rcm` of every output the wallet planned; an output's `rcm` now derives
from its `K` and `ρ`.)

A retry MUST keep its counter, with one exception: once a deposit's inbox has
been refunded, its counter is retired, and a retry is a new action with a
fresh counter ("Deposits are tracked, restored and refunded by the wallet").

A second note under an already-paid invoice id, when a scan finds it, MUST be
accepted as funds and recorded as a reuse disclosure, and MUST NOT by itself
close or open an epoch. Its payers can read each other's packets, and its
discovery tag repeats on chain, publicly suggesting that the two payments pay
one recipient (`apnt-pool-privacy-model`).

#### Scenario: Payer traces the recipient through change

- **WHEN** a payer that holds `K_I` trial-decrypts every packet settled after
  its payment, including the recipient's later spends
- **THEN** it MUST decrypt none of the recipient's change or other outputs. The
  negative test MUST fire on a deliberately faulty build that encrypts change
  under `K_I`.

#### Scenario: Invoice id issued twice

- **WHEN** a wallet is asked to issue an invoice id it has already issued or
  burned
- **THEN** it MUST refuse the request as reuse, and MUST NOT substitute
  another id. A fresh id is issued only on a new request that names none

#### Scenario: Invoice id requested out of order

- **WHEN** a request names an id above `h_e + 1` in the current epoch, an id in
  a closed epoch or in an epoch the store did not open, or any id when the
  store must open an epoch first
- **THEN** the wallet MUST refuse it and issue nothing

#### Scenario: Own output under invoice material

- **WHEN** a build plans a change or self-transfer output under an
  invoice-branch `K_I`, or tags one with a payment tag
- **THEN** a test MUST show that the holder of that invoice opens it or
  recognizes it, and the build MUST be rejected

#### Scenario: Retry with a changed output value

- **WHEN** a retry of an action, under the same per-action counter and with the
  same inputs in the same slots, changes a wallet-planned output's value
- **THEN** the output keeps its `rcm` and its change keys, and its `cm`, and
  hence its packet digest, MUST change

### Requirement: Invoice ids pair a random epoch with a sequential index

An invoice id is `I = u40be(e) ‖ u24be(x)`, eight bytes: a 40-bit **epoch**
`e` and a 24-bit **index** `x`, each big-endian (operator decision HUM-77,
2026-09-24; ARCH-212, ARCH-222). An encoder MUST refuse `e ≥ 2^40` and
`x ≥ 2^24`, and no arithmetic MAY carry from one field into the other. One
encoding serves the keys, the payment tag and the payment id.

**Epoch table.** The store MUST keep an epoch table: for each epoch `e` it has
opened or learned, the routine scan's `u_e` ("Discovery decodes tags locally,
with the per-epoch window as fallback"), `h_e`, the highest index in `e`
issued or burned, and a status, current or closed. The following MUST hold:

- at most one epoch is current, and only an epoch this store opened is ever
  current;
- a current epoch has `h_e ≥ 0`: no committed state holds a current epoch
  with no issued or burned index;
- for every epoch, `−1 ≤ u_e ≤ h_e ≤ 2^24 − 1`. `h_e` never falls, entries are
  never removed, and a closed epoch never becomes current again;
- every owner-verified find `(e, x)`, by any scan, adds `e` to the table,
  closed if it is new, and sets `h_e := max(h_e, x)` in the transition that
  records the note, before the note is reported: the no-reissue barrier.

The store's **known set** is the set of epochs in its table: every epoch it
opened, every epoch of an owner-verified find in any scan, and every epoch a
restore source held.

**When an epoch opens.** The store MUST open a fresh epoch as part of an
issuance, instead of issuing in its current epoch, when any of these holds:

1. it has no current epoch: its first issuance, every issuance after a
   restore, and every issuance after its current epoch closed;
2. the **session rule**: the issuing process did not itself commit the store's
   current state continuously since it last opened an epoch. The process
   holds in memory the revision and state digest of the last state it
   committed, and whether every intervening transition it made read a state
   it had itself committed. A transition reading any other state breaks
   continuity; later commits do not restore it. Only opening a fresh epoch
   restores continuity. The process MUST open a fresh epoch if it has no
   remembered state, the revision or digest differs, or continuity was
   broken, even if it subsequently committed the state now in the store.
   This covers a new process, a store changed underneath the process, and a
   copy or rollback of the store's files, one at the same revision included
   (`packages/reference-wallet/src/apnt_pool_wallet_store_v1.ts:84-102, 325-340, 468-475`);
3. the next index `h_e + 1` exceeds `u_e + G_inv`: the window is full;
4. the next index exceeds `2^24 − 1`.

An owner-verified find in the current epoch at an index above its `h_e` MUST
close that epoch in the transition that records the find, so the next
issuance opens a fresh one. A second payment to an issued index MUST NOT by
itself close or open an epoch.

**How an epoch opens.** Opening an epoch and releasing its first invoice MUST
be one reserve-then-commit transition ("Wallet pool state is a durable,
journaled store"). Inside that transition, after it has read the committed
state and while it holds the store's lock, the store MUST:

- require that its routine scan has run through the height `t_I` the issuance
  uses;
- draw `e` uniformly from `[0, 2^40)` with the operating system's
  cryptographically secure random generator, and draw again while `e` is in
  its known set;
- close its previous current epoch, record `e` as current with `u_e = −1` and
  `h_e = 0`, and commit;
- only then release invoice `(e, 0)`.

A draw that is not committed MUST be discarded and never used again. A crash
after the commit and before release burns `(e, 0)`, and the session rule makes
the next process open another epoch. An epoch MUST NOT be derived from the
seed, chain data, a counter, a clock, a store revision or any other value
another store could reproduce, and MUST NOT be chosen by a caller.

**Issuance in the current epoch.** When no epoch must open, the store issues
`x = h_e + 1` of its current epoch, which the gap rule bounds by
`x ≤ u_e + G_inv` for the `u_e` of its routine scan through `t_I`, and sets
`h_e := x` in the transition that releases the invoice.

**Stores of one seed.** Each device, each restore and each copy of a store's
files is a separate store, and every store of one seed in one deployment draws
its own epochs. A second device MUST be created by the restore command
("Restore recovers notes and issues from a fresh epoch"), which scans before
the store's first draw and moves its action counter. A copy of a store's files
made outside the restore command is covered by the session rule for invoice
ids, but its action counters can repeat the original's; a repeated counter is
the liveness failure disclosed in "Restore recovers notes and issues from a
fresh epoch". Stores learn each other's epochs only from owner-verified finds.
They MUST NOT be described as coordinating, or as never drawing one epoch.

**The epoch-collision residual.** Two stores of one seed hand out one id only
if two draws land on one epoch while neither drawing store knows the other's
epoch. Over every draw `d` of the seed in one deployment:

```text
P(an invoice id is handed to two payers through an epoch collision)
    ≤  Σ_d  V_d / (2^40 − M_d)
```

- `M_d` is the drawing store's known-set size at `d`. (`K_d` names the dummy
  output key elsewhere in this capability.)
- `V_d` counts every other draw by another store of the seed in the
  deployment that was made before `d`, or overlaps `d` in time (drawn and not
  yet committed or discarded), whose epoch the drawing store does not know at
  `d`, and that has released an invoice or can still release one. Another
  store is another device, a restore, a lost store, or a copied or rolled-back
  copy of this one. A discarded draw, and an epoch closed without releasing an
  invoice, can release none.
- Each pair of draws is counted once. Counting every pair of draws by
  different stores, with no credit for exclusion, gives a larger bound that
  holds for any schedule of the same draws.
- The bound assumes draws from independent, unrepeated generator states. A
  generator state cloned between devices is outside it.

A statement of this residual MUST use this counter. A counter of only the
epochs that other stores have already issued in is not an upper bound, and
MUST NOT be presented as one. An epoch open committed before its first
issuance escapes it, and so do two stores' draws that overlap in time
(REV-179 H1-1).

#### Scenario: Unpaid invoices at a loss

- **WHEN** a store issued `(e_0, 0)` through `(e_0, 29)`, the payments to
  indices 0 through 9 settled, the store was lost, the seed was restored, and
  indices 10 through 19 are paid after the restore
- **THEN** the restored store MUST issue from a fresh `e_1` outside its known
  set, the keys of its invoices MUST open no `e_0` packet, and a later
  seed-only restore MUST find every one of those payments. A negative test MUST
  show that resuming `e_0` above its highest found index hands out keys that
  open the late payments

#### Scenario: Two devices on one seed

- **WHEN** two stores of one seed, each created by the restore command, issue
  invoices concurrently with independent generators
- **THEN** each MUST issue only in epochs it drew, each MUST learn the other's
  epochs only from owner-verified finds, and they MUST share no invoice id
  outside the epoch-collision residual. A negative test MUST show that two
  stores starting one fixed epoch issue the same ids. A test, scenario or
  document that says two devices always draw distinct epochs MUST be corrected
  to state the residual

#### Scenario: Epoch opened without an invoice

- **WHEN** a build commits an epoch open in one transition and releases its
  first invoice in a later one, and a second store of the seed draws while the
  first holds that epoch unused
- **THEN** a test whose generator returns one value to both MUST show that
  both hand `(e, 0)` to a payer, and that a counter of issued epochs is 0 at
  the second draw while `V_d` is 1; the build MUST be rejected. The specified
  store MUST be shown never to commit a current epoch with `h_e = −1`

#### Scenario: Overlapping draws on two devices

- **WHEN** two stores' opening transitions overlap in time, each drawing
  before either commits
- **THEN** `V_d` MUST be 1 at the later draw, and a test whose generator
  returns one value to both MUST show that both hand `(e, 0)` to a payer while
  a counter of issued epochs counts 0

#### Scenario: Whole-store rollback

- **WHEN** a store's state and journal are replaced by an earlier consistent
  copy, one at the same revision with another digest included, and a new
  process opens them
- **THEN** its next issuance MUST open a fresh epoch outside every epoch of the
  copy, and a negative test MUST show that without the session rule the copy
  issues again every id handed out after the copy was made

#### Scenario: Rollback followed by an action commit

- **WHEN** the issuing process committed a later state, the state and journal
  are rolled back together to an earlier consistent copy, and the same
  process then commits an action transition against that copy
- **THEN** that action commit MUST NOT restore session continuity; the next
  invoice issuance MUST open a fresh epoch. A control that remembers only the
  last state this process committed MUST continue the copied epoch and show
  the invoice-id reuse the continuity rule prevents

#### Scenario: Crash around an epoch opening

- **WHEN** a process crashes after drawing an epoch and before its commit, or
  after the commit and before releasing `(e, 0)`
- **THEN** in the first case nothing MUST be recorded or released and the draw
  MUST NOT be used again; in the second, `(e, 0)` MUST never be released, and
  the next issuance MUST open another epoch

#### Scenario: Derived epochs

- **WHEN** a build derives an epoch from the seed, from chain data, from the
  number or the largest of its known epochs, from a counter or from a clock
- **THEN** a model with losses and restores MUST show reused ids, and the
  build MUST be rejected

#### Scenario: Small epoch space

- **WHEN** a test build uses a 4-, 6- or 8-bit epoch
- **THEN** its collisions MUST occur at the rate `Σ V_d / (2^b − M_d)`, the
  residual's control, and a build without exclusion MUST collide more

#### Scenario: Full window

- **WHEN** the next index of the current epoch would exceed `u_e + G_inv`
- **THEN** the issuance MUST open a fresh epoch and release its index 0, and a
  negative test MUST show that holding issuance refuses the request

#### Scenario: Index range used up

- **WHEN** the current epoch's `h_e` is `2^24 − 1`
- **THEN** the next issuance MUST open a fresh epoch, and MUST NOT wrap or
  refuse

#### Scenario: Gift above the mark

- **WHEN** a full-viewing-key holder funds `(e_cur, 2^24 − 1)` in the current
  epoch and a scan finds it
- **THEN** the find MUST set `h_e` to `2^24 − 1` and close the epoch, and the
  next invoice MUST come from a fresh epoch, with no block and no closing
  action

#### Scenario: Second payment to an issued index

- **WHEN** an issued index of the current epoch is paid twice
- **THEN** the epoch MUST stay current, and the next issuance MUST issue
  `h_e + 1` when the window allows it

### Requirement: Tags and payment ids encode the invoice id

The payment tag of invoice `I` MUST be
`dt_I = FF1-AES256.Encrypt(k_dt, T = "", X = I)`, eight bytes: FF1 as
specified in NIST SP 800-38G (the 2016 publication as updated 2016-08-04),
with:

- radix 256 and `n = 8` numerals, the eight bytes of `I` in order, so
  `u = v = 4`;
- the empty tweak and the 32-byte key `k_dt`, so AES-256;
- the rules of the second public draft of SP 800-38Gr1 (2025-02-03): only
  integer arithmetic, `b = ⌈BITLEN(256^4 − 1)/8⌉ = 4`, `d = 8`, ten rounds, and
  only the forward AES cipher.

Decoding MUST be `FF1-AES256.Decrypt` with the same parameters. FF1-AES256 is
the tag cipher by operator decision HUM-78 (2026-09-24), which accepts a
disclosed licensing risk. Voltage Security's letter of assurance for the FFX
mode offers licences on reasonable terms, not royalty-free, and patents on it
are listed as active until 2029. This is recorded as an operator decision, not
a legal opinion.

Current implementation limit (REV-270): constant-time FF1 execution has not
been established. The tag cipher is accepted for explicitly labelled
zero-value Chipnet tests only; ENG-583 blocks mainnet.

The payment id MUST be `pid_I = AES-256.Encrypt(k_pid, I ‖ 0^8)`, one 16-byte
block. A decoder MUST refuse a value that is not 16 bytes, or whose last eight
decrypted bytes are not all zero, and MUST report nothing else about it. That
test is probabilistic for values the wallet did not issue: a 16-byte value
that is not one of its payment ids, a random one or one with a flipped bit
included, passes with probability about `2^-64` and then decodes to some id.
A rescan under that id's key finds nothing unless a note under it exists, and
any find still passes the full-tier recheck and the barrier like any other. No
test or document MAY claim that every invalid 16-byte value is refused.

Keys MUST be kept apart:

- `k_dt` MUST be used only as the FF1 key of payment tags: never as an AES key
  for another purpose, a fill key of `dt(F, role)`, or an input to a packet
  digest or to another derivation;
- `k_pid` MUST be used only as the AES-256 key of payment ids;
- `K_I`, `k_dt`, `k_pid` and every packet digest derive under distinct
  domain tags;
- only the recipient encrypts under `k_dt` and `k_pid`, and only its own ids.

A tag has no check bits: every 8-byte string decodes to some id. A decoded id
is therefore a hint. Before the wallet records a note, raises `u_e` or `h_e`,
adds an epoch to its table, or offers a note to acceptance, it MUST derive
`K_I`, trial-decrypt the output's packet under it, and apply the full tier's
`cm` recheck under `O_I`.

An implementation MUST reproduce NIST's FF1 samples 1 to 9, the radix-2
FF1-AES256 vectors Zcash publishes for ZIP 32, and the repository's own T2
vectors. Those vectors MUST be generated in the repository and cross-checked
against an independent FF1 implementation. No vector produced by the ARCH-212
scratch code MAY be pinned.

#### Scenario: FF1 vectors

- **WHEN** the tag cipher's tests run
- **THEN** they MUST reproduce every listed vector, encrypt and decrypt, and
  MUST fire on a changed key bit, on nine rounds and on a wrong radix

#### Scenario: Byte order of the invoice id

- **WHEN** a test encodes `(e, x) = (0x3a5c91e207, 20)`
- **THEN** `I` MUST be `3a5c91e207000014`, and a build that writes either
  field little-endian, or feeds FF1 the reversed bytes, MUST fail the
  repository's T2 vectors

#### Scenario: Payment id refused

- **WHEN** a test gives the decoder a value that is not 16 bytes long, and
  16-byte values it constructs not to be this wallet's payment ids: one of its
  ids with a flipped bit, bytes from a fixed random seed, and another wallet's
  payment id
- **THEN** the decoder MUST refuse the wrong-length value always, and MUST
  refuse each constructed 16-byte value whose last eight decrypted bytes the
  test has confirmed are not all zero, reporting nothing else. The test MUST
  state that an arbitrary invalid 16-byte value is refused only except with
  probability about `2^-64`

#### Scenario: Tag with visible structure

- **WHEN** a build writes the epoch, the index or check bits into a payment
  tag in the clear, or encrypts the id with a keyed XOR or one Feistel round
- **THEN** the tag-linkage tests of `apnt-pool-privacy-model` MUST fire on it,
  and the build MUST be rejected

#### Scenario: Key used for two purposes

- **WHEN** a build uses `k_dt` or `k_pid` as any other key, or derives two of
  `K_I`, `k_dt` and `k_pid` under one domain tag
- **THEN** the key-derivation and tag-set tests MUST fail, and the build MUST
  be rejected

### Requirement: Packets have one fixed format

Every output, real or dummy, MUST carry a 16-byte packet (pad16, registry
entry 1 revision 3; HUM-84, ENG-454):

```text
d      = SHA-256("APNT-POOL-v1:pad" ‖ K ‖ ρ ‖ cm)
packet = (u64le(v) ⊕ d[0..8)) ‖ d[8..16)
```

where `cm` is that output's note commitment, whose `rcm` is
`SHA-256("APNT-POOL-v1:rcm" ‖ K ‖ ρ)`. The first 8 bytes pad the value; the
last 8 are a key check. Packets MUST travel on chain inside the statement.

The digest binds `cm`, which commits to `v`. So one `d` MUST never pad two
different values. This MUST hold across every candidate action a wallet
constructs, submits, retries or abandons, and across deployments, without
relying on the uniqueness of `ρ`, which holds only among settled actions. An
identical retry of an output MAY produce an identical packet, because its
equal `cm` already shows the equality. The recipient MUST be able to derive
`d` from its `K` and the public `ρ` and `cm`, recover `v`, derive `rcm`, and
rebuild `cm` under its own `O`.

The packet has no MAC. Its integrity is the action proof's, which enforces
it from the output's own `v`, `K`, `ρ` and `cm`, together with the owners'
signatures and the statement hash, so a wallet MUST open only packets of
settled, proven actions. The key check is a wrong-key trial filter (64 bits,
about 77 with `v ≤ MAX_MONEY`), not an ownership or authenticity check: only
the full tier's `cm` recheck under the wallet's own `O` yields an opening.

#### Scenario: Packet length depends on content

- **WHEN** a packet's length varies with value, memo or dummy status
- **THEN** it MUST be treated as a privacy defect

#### Scenario: Candidate retried with a changed output

- **WHEN** a wallet builds two candidate actions that spend the same input
  nullifier, so output `j` gets the same `ρ`, to the same `K`, with a different
  `v`, and an observer sees both packets
- **THEN** their digests MUST differ, and the XOR of the packets' padded
  values MUST NOT equal the XOR of the values

#### Scenario: Digest not bound to the plaintext

- **WHEN** an implementation derives the packet digest without `cm`, from `K`
  alone or from `K` and `ρ`, or otherwise lets one digest pad two different
  values
- **THEN** it MUST be rejected, and the candidate-retry negative MUST fire
  against it

### Requirement: Every output's discovery tag follows the v1 fill rules

Whoever builds an output MUST fill its 8-byte discovery-tag slot
(`apnt-pool-settlement-custody`, "Every output carries a bound discovery-tag
slot") by the v1 fill rules (operator decisions HUM-75 and HUM-77,
2026-09-24):

```text
dt(F, role) = SHA-256("APNT-POOL-v1:dtag" ‖ F ‖ role)[0:8]
K_dt(ρ)     = SHA-256("APNT-POOL-v1:wallet-dummy-dt" ‖ D ‖ ρ)
```

`F` is a 32-byte **fill key** and `role` one byte. `D` is the builder's dummy
root (`design.md`, "Dummy layout"), and `ρ` is always the output's own `ρ`:

| Output | Tag | Filled by |
|---|---|---|
| payment to invoice `I` | `dt_I`, copied unchanged from the invoice ("Tags and payment ids encode the invoice id") | the payer |
| change or self-transfer output | `dt(K_ρ, 0x00)`, with `K_ρ` the change key for its `ρ` | the change owner |
| dummy output | `dt(K_dt(ρ), 0x00)` | the action's builder |

The following MUST hold:

- `role` is `0x00`. No other role value exists in v1, and a wallet MUST NOT
  fill or match one. The gap-closing role `0x01` is retired with gap closing
  (HUM-77);
- a payer MUST copy the invoice's `dt_I` unchanged into its payment output and
  MUST NOT derive a payment tag of its own;
- a change or dummy tag MUST derive only from its fill key and `role` as in
  the table, and a payment tag only from the recipient's `k_dt` and the
  invoice id. No tag MAY derive from `v`, `cm`, the packet, `deployment_id`, a
  payment id, a paycode, a descriptor, a static key, an invoice index, epoch or
  action counter alone, or any per-wallet constant. Every fill key and `k_dt`
  derive from the per-deployment root `R`, so one seed's tags in two
  deployments differ;
- a wallet MUST NOT fill the tag of an output it plans for itself with a
  payment tag `dt_I`;
- **per-output uniqueness.** Every change and dummy fill key is a function of
  a wallet secret and the output's own `ρ`. Within one deployment at most one
  settled output has a given `ρ`, so no two settled change or dummy outputs
  share a fill key, whatever the wallet repeats, a counter reused after a
  restore included, and no wallet rule MAY make two of their tags equal.
  Payment tags of one wallet's distinct invoice ids differ exactly, because
  FF1 permutes 8-byte strings under one `k_dt`, and no id is issued twice
  outside the epoch-collision residual. In honest use only outputs paying one
  invoice share a tag by construction;
- **accidental collisions.** A change or dummy tag is a SHA-256 digest
  truncated to 64 bits, and tags under different keys (two recipients'
  payment tags, or a payment tag beside a change or dummy tag) are unrelated
  8-byte values. So two tags from different keys are equal by accident with
  probability about `2^-64` per pair, and among `n` tags of one deployment
  some two are equal with probability at most `n(n − 1)/2^65`: about
  `2.7·10^-8` at a million outputs, and about 0.39 at the tree's `2^32 − 1`
  leaves (X33). Such an equal pair is neither a repeated invoice nor evidence
  of one. Every statement of tag uniqueness in this capability holds up to
  this residual. A test that asserts distinct tags over a model chain MUST
  state that chain's accidental-collision probability, and a test of a banned
  repeat MUST use a construction that repeats by rule, not by chance;
- a retry or re-prove that keeps an output's invoice, or its fill key and
  `role`, keeps its tag. The members of a `ρ` family share one tag, and at most
  one of them settles;
- a tag is advisory and unauthenticated. A tag match, or a decoded id, is not
  an opening, a find or acceptance, and nothing checks that a tag belongs to
  its output. A wrong tag never makes a note another party's; it only makes
  routine decoding miss that note.

A later wallet profile MAY fill the same slot by another rule, with no chain
change. Any rule MUST keep per-output uniqueness for outputs a wallet plans
for itself: a dummy or self-transfer output's tag MUST NOT be determined by an
invoice id, an index or an action counter alone. Any rule MUST also name the
payment tag that a payer's duplicate check filters on ("A payer checks for a
prior payment before paying"); only that filter is fill-specific, and the
check's verification step is not.

#### Scenario: Payment, change and dummy tags

- **WHEN** a wallet builds an action whose outputs are a payment to an invoice
  and a change output, and another whose output 1 is a dummy
- **THEN** the payment's tag MUST equal the invoice's `dt_I` and decode to `I`
  under the recipient's `k_dt`, and every other tag MUST equal `dt(F, 0x00)`
  for that output's fill key; a test MUST recompute the change and dummy tags
  from the builder's own keys

#### Scenario: Static change tag

- **WHEN** a build tags every change output with one per-wallet value, or with
  any value that does not vary with each output's `K_ρ`
- **THEN** a test over one wallet's settled change outputs MUST show that the
  build's tags repeat and link those outputs, and the build MUST be rejected;
  no wallet rule MAY make two of its settled change outputs share a tag, and
  only the accidental 64-bit residual can

#### Scenario: Payment tag on an own output

- **WHEN** a build tags two outputs it plans for itself, such as two
  self-transfers aimed at one of its invoice ids, with the payment tag of one
  `(e, g)`
- **THEN** a test MUST show that the tag repeats across the two and equals a
  later payment's tag to `(e, g)`, and the build MUST be rejected (ARCH-219)

#### Scenario: Payer derives its own payment tag

- **WHEN** a payer fills a payment's tag with `dt(K_I, 0x00)`, or with any
  value other than the invoice's `dt_I`
- **THEN** a test MUST show that the recipient's routine decoding misses the
  payment while the targeted rescan and the per-epoch deep scan find it, and
  the payer MUST be rejected

#### Scenario: Dummy tag under a reused counter

- **WHEN** a restored wallet reuses an action counter for two actions whose
  inputs are all real, each with a dummy output in the same slot, so no dummy
  nullifier repeats and both settle
- **THEN** their dummy tags MUST differ, up to the accidental 64-bit residual,
  and a test MUST show that a build tagging dummy outputs `dt(K_d, 0x00)` from
  the dummy layout's field 18 repeats the tag across the two, and the build
  MUST be rejected. Migration step 2's dummy output 1 follows the same rule
  (`apnt-pool-versioning-migration`)

#### Scenario: Tag derived from public data

- **WHEN** a build derives a tag from `ρ`, `cm`, the packet or
  `deployment_id`, without a wallet secret or the recipient's `k_dt`
- **THEN** a test MUST show that an observer recomputes it from public data,
  and the build MUST be rejected

#### Scenario: Constant dummy tag

- **WHEN** a build fills dummy outputs' slots with zeros or any other constant
- **THEN** a test MUST show that dummy slots become distinguishable from real
  ones, and the build MUST be rejected as a privacy defect

#### Scenario: Retry keeps its tags

- **WHEN** a payer re-proves a payment after a stale anchor, keeping its
  invoice and its inputs in their slots
- **THEN** every output's tag MUST be unchanged

### Requirement: Invoices expire and payers honor the expiry

Phase 3 defers active cancellation, fresh-wallet restore, restored-wallet refund and the separate-machine exercise under Scope v2/v3 and plan section 5. Existing expiry/H_cancel refusals and created-home refund remain in scope. RR-10 is partial implementation, not wholly deferred. Seed restore code, counter jumps or retained-home refund do not demonstrate the deferred exercises. Full target cancellation, no-hold recovery, privacy conditions and failure states remain normative and unfulfilled where absent. Found or recovered notes are not thereby accepted or spendable; an unsigned release does not settle cancellation.


A payer MUST honor an invoice's expiry `E_I`, with `grace` and `L_settle` as
defined in "The per-epoch window scan follows the V1 window" and the cancel
height `H_cancel = E_I + grace − L_settle − 1`:

- it MUST refuse to begin an action paying invoice `I` once its chain tip is at
  or above `E_I`;
- it MAY re-prove and resubmit a payment it began before `E_I`, such as an
  anchor retry, only while its tip is below `H_cancel` and the payment has not
  been released under "Deadline refusal releases never-dispatched payments";
- if an unreleased payment is unsettled by the payer's own chain read at a tip
  at or above `H_cancel`, the payer MUST stop submitting it and MUST at once
  submit a cancelling action over the anonymizing network: any action that
  spends at least one of the payment's input notes. A payer that is online
  keeps its chain read current, so it cancels no later than at tip `H_cancel`;
  a payer that was offline cancels when it returns. Once the cancelling
  action settles, the range records refuse the payment's nullifier, so the
  payment can never settle. **At once** means that the payer begins the
  cancel at that tip and waits for nothing but what the cancel itself needs:
  it issues the cancel's own invoice, builds and proves the cancel, and
  submits it under the anchor policy of `apnt-pool-privacy-model` ("Anchors,
  staleness and submission windows follow a stated policy"), whose random
  delay and one attempt of up to `R_retry` re-proves `L_settle` covers;
- the cancelling action for still-reserved notes MUST pay a fresh own invoice
  issued privately for that cancellation, never an invoice handed to an
  outside payer or used by another
  action. It MUST spend exactly the still-reserved held notes. If it remains
  unsettled at its own `H_cancel`, the payer MUST re-prove that same journaled
  cancellation from the same notes and a current anchor, even after that
  height. It MUST NOT start a cancel of the cancel or a second cancellation
  of the original. This bounds the journal to the original payment and one
  cancellation; retries continue only until one action settles, and no
  unrelated action may reuse their reserved nullifiers. The exception for
  released notes is "Deadline refusal releases never-dispatched payments";
- when an attempt of the cancelling action ends after `R_retry` re-proves
  without a fresh-enough anchor, the payer MUST report it and MUST begin the
  next attempt of that same journaled cancellation at once. It MUST NOT
  submit the cancel with a stale anchor, and the ended attempt ends neither
  the cancellation nor the payment's tracking;
- the check of "A payer checks for a prior payment before paying" runs before
  each submission and re-prove of the cancelling action, as for any action
  that pays an invoice. For the cancellation's own invoice its decision is
  that requirement's own-invoice case: evidence is reported to the user and
  never pauses, stops or delays the cancel;
- the payer MUST decide the outcome from its own chain read of which action
  inserted that input's nullifier: **paid** when the payment settled below
  `E_I + grace`, **cancelled** when the cancelling action did, and **late**
  when the payment settled at or above `E_I + grace`. It MUST report a late
  payment to its user together with its payment id, for the recipient's
  targeted rescan should its routine scan miss the payment.

**A cancel fee ceiling and its headroom.** A payer MAY fix, before
`H_cancel`, the most it will pay as its cancelling action's fee, a **cancel
fee ceiling**, so that its cancel at `H_cancel` waits for no approval
(`add-apnt-pool-agentic-wallet-v1` fixes one when it plans a payment). A payer
that does MUST fix the ceiling at no less than `min(Σ v_in, ⌈h_cancel · f(p)⌉)`.
Here `Σ v_in` is the value of the payment's input notes, `f(p)` the fee the
payer's fee rule gives one action of the pool's fixed shape at the tip `p` at
which it fixes the ceiling, and `h_cancel ≥ 1` the wallet profile's **cancel
fee headroom**. `h_cancel` is measured, never chosen:

- the **observation series** is a recording on the deployment's network of
  one observation for each height `h` it records: the fee `f(h)` the payer's
  fee rule gives at `h`, and either `f_req(h)`, the least fee at which the
  aggregators the payer submits to admit one action of the pool's fixed shape
  submitted at `h` and settle it within `L_settle`, or **no finite fee**, when
  no fee they were offered did so. A height inside the recording with no
  observation is a gap;
- the **horizon** of a planning height `p` is every `h` with
  `p ≤ h ≤ p + T + grace − 1`. That span reaches `E_I + grace − 1`, the end of
  the cancel's settlement window, from any tip `p ≥ E_I − T`. The **planning
  subseries** is every `p` whose whole horizon the observation series
  records, so it ends `T + grace − 1` heights before the series does. A
  planning height whose horizon runs past the series or holds a gap is
  outside it. Its missing observations MUST NOT be filled by extrapolation, an
  inferred rate or any chosen value; only a longer recording brings it in;
- `h_cancel` MUST be at least the largest ratio `f_req(h) / f(p)` over every
  `p` of the planning subseries and every `h` of its horizon, each ratio
  computed exactly as a rational;
- the measurement MUST refuse, and state no value, when its planning
  subseries is empty; when the fee rule gives `f(p) = 0` at any planning
  height, where no ratio exists and no headroom multiplies a zero planning
  fee into a positive required fee; or when any planning height's horizon
  holds a no-finite-fee observation, where no ceiling buys settlement within
  `L_settle` and the observation is evidence against `L_settle` for task
  1.4's measurement, not a ratio. It MUST NOT drop such a planning height to
  state a value;
- the measurement MUST state its network, the heights its observation series
  records and its gaps, the heights of its planning subseries, the
  aggregators and fee rule it observed, how it observed `f_req`, every
  observation it refused on, with its height, and the largest ratio it
  found. Until that measurement exists, only labelled zero-value test
  profiles use a cancel fee ceiling, and each MUST state that its `h_cancel`
  is not measured.

A ceiling frees the cancel's submission from any wait for an approval. It
does not make the cancel settle. A required fee above the ceiling or above
`Σ v_in`, or a rise beyond what the measured series showed, makes an under-fee
cancel. A ceiling fixed at a tip below `E_I − T` lies outside the measured
span. One fixed from a planning fee `f(p) = 0` lies outside every
measurement, so outside a labelled zero-value test a payer MUST NOT fix a
ceiling at a tip at which its fee rule gives `f(p) = 0`.

**The honest cancel path, and what lies off it.** A signed action cannot be
revoked, so these rules bound only what honest payers do. They bound the
per-epoch window's coverage of mis-tagged payments only on the **honest
cancel path**: a cancelling action, when one is needed, that settles by
`H_cancel + L_settle = E_I + grace − 1`. On that path a withheld payment can
settle only before its cancel, so below `E_I + grace`, and the window finds it
whatever its tag. Decoding finds a correctly tagged payment whenever it
settles, on that path or off it. Off it, a withheld payment can settle at or
above `E_I + grace`, and is then late. Lateness alone does not make the window
miss it: the window can first miss a mis-tagged payment later, at a height
fixed by the invoice's `t_I` and by when `u_e` passes its index ("The
per-epoch window scan follows the V1 window"). Each of these causes breaks that
premise, and each is a residual disclosed under `apnt-pool-privacy-model`
"Residuals are disclosed":

- an **under-fee cancel**: a cancelling action whose fee is below what every
  aggregator it reaches requires, whether its payer capped the fee with a
  cancel fee ceiling or fees rose past what its fee rule gave. It may settle
  only once fees fall, or never, so no value of `L_settle` or `grace` covers
  it;
- a cancel whose first attempt runs out of anchor re-proves; its later
  attempts can settle after `H_cancel + L_settle`;
- a payer that is offline at `H_cancel`, cannot reach the anonymizing
  network, or whose store cannot yet issue the cancellation's own invoice
  because its scan is behind or a restore scan is pending;
- every submission path withholding or delaying the cancelling action as well
  as the payment;
- a reorganization that removes a block with `c_anchor` confirmations, which
  can move a payment to or above `E_I + grace` ("The per-epoch window scan
  follows the V1 window").

In each case the payer still decides the outcome from its own chain read and
reports a late payment with its payment id, so the recipient's targeted
rescan finds a mis-tagged late payment in any epoch. Without that payment id
only the per-epoch deep scan finds it, and only in an epoch the recipient
knows ("A targeted rescan and a per-epoch deep scan find mis-tagged
payments").

#### Scenario: Invoice expired at payment time

- **WHEN** a payer's chain tip is at or above `E_I` and it is asked to pay
  invoice `I`
- **THEN** it MUST refuse and build no action

#### Scenario: Payment withheld past the cancel height

- **WHEN** an aggregator withholds a payment, the payer's tip reaches
  `H_cancel` with the payment unsettled, and the payer's cancelling action
  settles by `H_cancel + L_settle`
- **THEN** the payer MUST submit a cancelling action, every payment that still
  settles MUST do so below `E_I + grace`, and the recipient's per-epoch window
  scan MUST find it whatever its tag. A negative test MUST show that without
  the cancel rule a withheld, mis-tagged payment settles at or above
  `E_I + grace` and the window scan misses it

#### Scenario: Under-fee cancel beside a withheld payment

- **WHEN** `E_I = 120`, `grace = 20` and `L_settle = 8`, so `H_cancel = 131`,
  with `T = 20` and `G_inv = 20`; the recipient's store opened epoch `e` by
  issuing `I = (e, 0)` with `t_I = 100`, so `E_I = t_I + T`; that store still
  holds `e`, is the only store of its seed that drew it, and sees only
  shallow reorganizations; a correctly tagged payment to its next invoice
  `(e, 1)` settles at height 105, so `u_e(s) = −1` below 105 and
  `u_e(s) = 1` from 105; an aggregator withholds a mis-tagged payment to `I`;
  the payer, online, on the anonymizing network and never short of a fresh
  anchor, submits its cancelling action at tip 131 at a fee below what every
  aggregator it reaches requires, and they refuse it for that fee alone; and
  the withheld payment is released and settles at height 150
- **THEN** until the payment settles the payer MUST keep re-proving the same
  journaled cancellation, and once it settles the payer MUST report it as
  late, with its payment id, and MUST NOT report it as paid or cancelled
- **AND** a test MUST show that the per-epoch window scan misses the payment
  at 150, where `W_e(150) = (u_e(110), u_e(149) + G_inv] = (1, 21]`, and that
  the targeted rescan with its payment id, and the per-epoch deep scan of
  `e`, each find it. Controls MUST show that the window finds the same
  payment when it settles at 140, the first late height, where
  `W_e(140) = (u_e(100), u_e(139) + G_inv] = (−1, 21]`, and the payer still
  reports it late; and when the payment to `(e, 1)` settles at 111 instead,
  so that `u_e(110) = −1`. Any text that states the window's coverage of
  withheld payments without the honest cancel path MUST be corrected

#### Scenario: Cancel fee ceiling from an unmeasured headroom

- **WHEN** a wallet profile outside a labelled zero-value test sets
  `h_cancel` without this requirement's measurement, or below the largest
  ratio that measurement found
- **THEN** it MUST be refused

#### Scenario: Headroom measured past its observations

- **WHEN** an observation series records every height from 100 to 150, with
  `T = 5` and `grace = 4`, and a measurement takes a ratio at a planning
  height above 142, or fills the observations above 150 by extrapolation, an
  inferred rate or any chosen value
- **THEN** the measurement MUST be refused. Its planning subseries is 100 to
  142, and a test MUST show that the 8 planning heights 143 to 150 need
  ratios at 36 pairs `(p, h)` with `h` from 151 to 158, which the series does
  not hold

#### Scenario: Zero planning fee or no finite fee in the headroom measurement

- **WHEN** the fee rule gives `f(p) = 0` at a height of the planning
  subseries, or a planning height's horizon holds a no-finite-fee
  observation
- **THEN** the measurement MUST state no value, and a measurement that drops
  that planning height, or treats the observation as a finite fee, to state
  one MUST be refused

#### Scenario: Resubmission after the cancel height

- **WHEN** a payer is asked to re-prove or resubmit a payment at or above
  `H_cancel`
- **THEN** it MUST refuse, and MUST cancel instead if the payment is unsettled

#### Scenario: Payment wins the race and settles late

- **WHEN** the payer's chain read shows its payment settled at or above
  `E_I + grace`
- **THEN** the payer MUST report it as late, with its payment id, and MUST NOT
  report it as paid or cancelled

### Requirement: Deadline refusal releases never-dispatched payments

Operator decision HUM-131 (2026-10-08) keeps no-hold restore and chain-decided
cancellation, and releases a deadline-refused, never-dispatched payment's
notes. This exception covers the executed owner-payment case in the labelled
zero-value harness profile reviewed by REV-594 MM-0; it does not release
module-CLI payments without an owner operation. Its rules follow
the project's internal design review (REV-594), section 5 MM-1 to
MM-7, and its disclosures follow that report's section 7. This is wallet
lifecycle policy, with no change to the action relation or chain validity.

**Refusal and release (REV-594 MM-1, MM-2).** Let `D` be the operation's
approved deadline (`approvalExpiry`), with `D ≤ E_I`. The wallet MUST commit a
deadline refusal when its own current verified chain observation reaches
`D`, the operation has a consumed approval bound to its executed intent, and
it is still before dispatch. The eligible states are `approved`,
`awaiting-proof`, `proving`, `proof-verified`, `waiting`, or `unknown` solely
with reason `wallet-approval-plan-changed`. The refusal reason MUST be
`pool-wallet-invoice-expired` at or above `E_I`, otherwise
`wallet-approval-expired`. The wallet MUST check on committing sync as well
as before import and hand-off; a missing proof or execution bundle MUST NOT
prevent refusal of an eligible operation.

Before release, the wallet MUST establish from its own private submission
state that no dispatch attempt names the operation, and, when its execution
bundle exists, no dispatch attempt names its action. A handed-off or attempted
payment, including `submitted` or `unknown` with
`pool-wallet-submit-reconciliation-required`, MUST stay reserved until the
wallet's own chain read resolves it. A deadline alone MUST NOT release it.
Release of such an unsettled payment at its cancel height is HUM-132, open
with the operator; this requirement grants no such release. Its existing
cancellation obligations in "Invoices expire and payers honor the expiry"
remain. Proof construction, export, import or verification without a dispatch
attempt MUST NOT by itself prevent this deadline release.

In the same durable store transition that refuses the operation, the wallet
MUST append a release fact if it holds that payment's built payer record with
an input-nullifier pair. The fact MUST bind the action counter, payment id,
deadline reason and observed height. The record MUST match the operation's
counter and all six invoice fields and MUST NOT be a designated cancellation
record. If no input pair was journaled, no release fact is added; refusal
ends the operation's reservation. A release fact MUST NOT edit or remove the
payer record, its input pair, build tag or build-MAC text.

**Reservations and retries (REV-594 MM-3, MM-4).** Only a validated release
fact in the wallet's own store, matched to a built non-cancellation payer
record, releases that record's reservation. No caller-supplied boolean,
height, path, message or acceptance claim MAY authorize release. An absent
release-fact collection means no releases. All payer-builder, P2 selection
and cancellation-overlap reservation checks MUST agree on this predicate;
partial activation MUST fail closed. An unreleased record that shares the
note's nullifier MUST still reserve it, and chain-observed spentness always
wins over release.

The released record MUST be retained for reconciliation and audit but MUST
NOT be retryable. The wallet MUST refuse to rebuild, re-prove, import,
resubmit or dispatch that payment, and MUST refuse to re-plan its invoice as
a way to resume it. A later payment spending a released note has its own
invoice, counter, deadline and cancel height. Shared nullifiers with a
released record MUST NOT turn it into a designated cancellation or grant it
that cancellation's retries beyond its own cancel height (MM-4b to MM-4d).

**Amount shielding on reuse (REV-594 MM-4f).** When a new payment selects a
note appearing in a released record, the wallet MUST fix that note in the
payment slot of the approved, bound intent: `paymentSlot = inputSlot`.
Change MUST take the other slot's fresh dummy nullifier as its `ρ`, so it
does not share a change-key `ρ` family with the released payment. A plan
that cannot meet this rule MUST be refused, rather than disclose the new
payment's change amount. Notes appearing in no released record keep the
existing random slot choice. This is a wallet planning constraint, not a
new input-to-output relation rule.

**Chain reconciliation (REV-594 MM-5, MM-6).** Any later action spending at
least one released input note is a cancelling action for the refused
payment, under the existing definition in "Invoices expire and payers honor
the expiry" (pre-delta `spec.md:933-934`). It need not pay the fresh own
invoice required for cancellation of still-reserved notes. Release itself
MUST NOT be reported as an on-chain cancellation: an exposed signed action
can still settle, and only the chain decides which shared-nullifier action
wins. From its own verified chain read, the wallet MUST attribute each
record's outcome to the settled action and whether it pays that record's
invoice, never to tags alone:

- if the refused payment wins, it MUST be recorded as executed, with payer
  outcome `paid` below `E_I + grace` or `late` at or above it; a late outcome
  MUST carry the payment id for the recipient's targeted rescan. A later
  payment that loses this race MUST be recorded as terminal `cancelled`;
- if the later payment wins, the refused payment's payer outcome MUST be
  `cancelled`; its operation remains refused, and the later payment is
  reconciled against its own invoice;
- the release fact MUST remain in either case. A chain-observed insertion
  makes the input spent regardless of release. If a reorganization removes
  the insertion, the fact remains, the refused payment stays non-retryable,
  and selection of the now-unspent note races any exposed action again.

**Restore (REV-594 MM-7).** "Restore recovers notes and issues from a fresh
epoch" MUST carry validated release facts together with retained payer
records. Seed-only restore MUST introduce no hold on found notes. Restore,
release and eligibility for selection alone MUST NOT be presented as chain
spendability, chain inclusion or wallet acceptance.

**Required disclosures (HUM-131; REV-594 section 7).** The wallet MUST show
these facts when it presents the refusal and before approval of a payment
reusing a released note:

- refusal stops this wallet, but does not revoke a signed action. A copy,
  including one retained from proof construction, can still be submitted.
  The chain settles at most one action spending the shared note. If the
  refused action wins, its recipient is paid despite refusal, the new
  payment fails, and paying the new recipient needs a fresh invoice. If the
  new action wins, the refused action cannot settle. A late winning payment
  may need the recipient's payment-id targeted rescan;
- anyone seeing both actions, such as a prover, aggregator or relay receiving
  both, sees their shared nullifier and learns that they share an input. This
  linkage alone reveals neither private amounts nor recipients; the payment
  slot rule above is mandatory to prevent disclosure of the new change.
  Public shape, counts, fees, timing and outside knowledge remain residuals;
- seed-only restore forgets unsettled payer records: found unspent notes are
  available without a hold, but their later spends race pre-loss actions in
  the same way. A reorganization can reopen this ordering race.

#### Scenario: Never-imported payment reaches its deadline

- **WHEN** an eligible executed operation reaches `D` in the wallet's current
  verified chain read, without any dispatch attempt, including a build-failed
  operation with no execution bundle
- **THEN** sync MUST refuse it and atomically release any matching built payer
  record; a new invoice MAY select its unspent note, while the released
  payment itself MUST remain non-retryable

#### Scenario: Dispatch attempt precedes the deadline

- **WHEN** a payment has an operation or action dispatch attempt, or is handed
  off, submitted or reconciliation-required, and its deadline passes
- **THEN** its notes MUST stay reserved; even at its cancel height this
  requirement MUST NOT release them under the pending HUM-132 decision

#### Scenario: Reuse cannot expose new change to an earlier prover

- **WHEN** a note in a refused payment's change slot is released and selected
  for a new payment
- **THEN** the approved new plan MUST put that note in its payment slot and
  use the fresh dummy's `ρ` for change; a test MUST show that the old change
  witness cannot open the new change packet, and that putting the note in
  both change slots exposes the new change amount and MUST be rejected

#### Scenario: Released payment cannot be resumed through a new plan

- **WHEN** a wallet is asked to rebuild, re-prove, import, resubmit or dispatch
  a released payment, or re-plan its invoice even while the invoice is valid
- **THEN** it MUST refuse without a new reservation, signature or dispatch;
  reuse by a different payment MUST keep that payment's own retry limits

#### Scenario: Refused payment wins the ordering race

- **WHEN** a refused payment settles before a later payment spending the same
  released note, below its late height or at or above it
- **THEN** the wallet MUST reconcile the refused payment as executed with
  `paid` or `late` respectively, and the losing later payment as terminal
  `cancelled`; it MUST keep the release fact and treat the input as spent

#### Scenario: Later payment wins the ordering race

- **WHEN** the wallet's own chain read shows a later action spending a
  released input without paying the refused record's invoice
- **THEN** the refused payment's payer outcome MUST be `cancelled`, its
  operation MUST stay refused and its record retained but non-retryable;
  the wallet MUST NOT infer any recipient's acceptance from this outcome

#### Scenario: Reorganization removes the winning insertion

- **WHEN** a reorganization removes the chain insertion that spent a released
  note
- **THEN** the wallet MUST keep the release fact, allow selection only if its
  own verified read shows the note unspent with no other reservation, keep
  the refused payment non-retryable, and disclose the renewed race

### Requirement: A payer checks for a prior payment before paying

A discovery tag is an unauthenticated hint: the covenant binds it to its
signers, never to its output's `K` (`apnt-pool-settlement-custody`). A tag
on chain is therefore never proof that an invoice was paid, and a payer MUST
NOT refuse, pause or cancel a payment on tag equality alone.

Before it begins an action paying invoice `I`, and again before each
resubmission or re-prove of that payment, a payer MUST run this check over its
own chain read. That read MUST be the complete pool-lock history of
`apnt-pool-privacy-model`, never a query keyed by the tag:

1. **Filter.** Find every settled output, other than its own payment's, whose
   discovery tag equals the invoice's `dt_I`, the payment tag the v1 fill
   rules name (ARCH-220, REV-174). Its own payment is the output in the
   settlement that inserted that payment's input nullifiers.
2. **Verify.** For each, open the packet under `K_I` with the output's public
   `ρ` and `cm`, and recheck `cm` under the invoice's `O_I` and
   `SHA-256("APNT-POOL-v1:rt" ‖ K_I)`, as the host opener does. Only an output
   that passes both is **evidence of a prior payment** to the invoice, and its
   opening gives its value `v'`.
3. **Decide.**
   - Evidence found, outside the own-invoice case below: the payer MUST NOT
     begin or resubmit the payment without its user's explicit choice. It
     MUST show the value `v'` and the height of each prior payment, and the
     disclosure that paying again repeats the invoice's tag on chain. Until
     the user chooses, it MUST stop submitting a pending payment. The expiry
     rules still apply: at `H_cancel` an unsettled payment is cancelled as
     they require.
   - No evidence: a tag match whose packet does not open under `K_I`, or opens
     and fails the recheck under `O_I`, is a copied tag, a foreign-owner packet,
     a recipient's repeated tag or a chance collision. The payer MUST proceed as
     if the match were absent. It MAY log a notice, and it MUST NOT treat the
     match as a payment.
   - **The own-invoice case.** When `I` is the fresh own invoice that a
     cancelling action pays ("Invoices expire and payers honor the expiry"),
     evidence found MUST NOT pause, stop or delay the cancelling action or any
     re-prove of it, and the payer MUST NOT wait for its user's choice. It
     MUST report the evidence to its user as a notice, with each output's
     value `v'` and height, the disclosure that the cancel's invoice output
     repeats that tag on chain, and the disclosure that only a holder of the
     wallet's seed or full viewing key, or another store of its seed that drew
     the same epoch, can create such evidence. That invoice was issued
     privately and handed to no one, and it pays no outside recipient, so
     there is no second payment to an outside recipient for the user to
     decide on. The expiry rules require that cancellation to be re-proved
     until one action settles, and a pause would let the holder of that
     material hold up the cancel and break the honest cancel path.

The filter MUST use the invoice's `dt_I`, never a tag the payer derives. The
check sees only settled, correctly tagged outputs. Two holders of one invoice
paying concurrently can both settle, a prior payment carrying a wrong tag is
not filtered, and a user who chooses to pay again repeats the tag; each of
these repeats the tag publicly (`apnt-pool-privacy-model`, "Discovery tags
disclose nothing beyond a repeated invoice"). So does a cancel that continues
past evidence on its own invoice. Any holder of the invoice can create
evidence by paying under `(O_I, K_I)` itself, even a value of 0. That note
does reach the recipient's `O_I`, and the user then decides, except in the
own-invoice case above, where the cancel continues and the user is told.

#### Scenario: Honest prior payment

- **WHEN** a payer is asked to pay invoice `I` and another settled output
  carrying `dt_I` opens under `K_I` and rechecks under `O_I`
- **THEN** it MUST show that payment's value and height and MUST NOT pay
  without its user's explicit choice

#### Scenario: Filter on a derived tag

- **WHEN** a payer's filter computes `dt(K_I, 0x00)`, or any tag other than the
  invoice's `dt_I`
- **THEN** a negative test MUST show that it misses an honest prior payment
  carrying `dt_I`, and the payer MUST be rejected

#### Scenario: Foreign-owner packet carrying the invoice's tag

- **WHEN** a holder of invoice `I` settles an output sealed under `K_I` to an
  owner other than `O_I`, carrying `dt_I`
- **THEN** the payer MUST proceed with the payment, and MUST NOT refuse, pause
  or cancel it. A test MUST show that a build refusing or cancelling on tag
  equality alone does so here

#### Scenario: Copied public tag

- **WHEN** any signer copies `dt_I` onto an output of its own under an
  unrelated `K`, or a recipient puts one tag into two of its invoices and the
  first is paid
- **THEN** the payer MUST proceed, and a test MUST show that a build refusing
  or cancelling on tag equality alone does so here

#### Scenario: Copied tag while a payment is pending

- **WHEN** a payer's own payment to invoice `I` is unsettled and a copied or
  foreign-owner output carrying `dt_I` settles
- **THEN** the payer MUST keep its payment's ordinary submission and expiry
  behaviour, and MUST NOT cancel because of that output

#### Scenario: Payer without its history pays again

- **WHEN** a payer that lost its payment records is asked again to pay an
  invoice it already paid, and the payment has settled
- **THEN** the check MUST find it as evidence and require the user's choice,
  and a negative test MUST show that a payer without the check settles a
  second payment carrying the same tag

#### Scenario: Zero-value prior payment by an invoice holder

- **WHEN** a holder of invoice `I` settles a note of value 0 under
  `(O_I, K_I)` with the invoice's tag
- **THEN** the check MUST report it as evidence with value 0, and the payer
  MUST leave the choice to its user rather than refusing on its own, unless
  `I` is a cancellation's own invoice

#### Scenario: Evidence on a cancellation's own invoice

- **WHEN** a payer's cancelling action is unsettled, and a settled output
  carrying the cancellation's own invoice's `dt_I` opens under its `K_I` and
  rechecks under its `O_I`, such as a value-0 note that a full-viewing-key
  holder settled to that invoice id
- **THEN** the payer MUST keep submitting and re-proving the same journaled
  cancellation without waiting for any choice, and MUST report the evidence
  to its user with each output's value and height and the disclosures of the
  own-invoice case
- **AND** a test MUST show that a build pausing the cancel on that evidence
  submits nothing while a withheld payment settles at or above `E_I + grace`

#### Scenario: Duplicate check by server query

- **WHEN** a payer asks a server whether `dt_I`, or any value derived from it,
  is on chain
- **THEN** it MUST be treated as a privacy defect

### Requirement: Recovery and spendability from seed plus chain

Current implementation at 705bd169: routine tag decoding and the change-key trial run over the verified read. The fallback uses, for each known epoch, the prefix from zero through current post-decode u_e plus G_inv, clipped to the index domain and capped at 4,096 ids in total. For a known epoch with monotone u_e over the compared history, below that cap it contains every per-height V1 window W_e(h); this source deduction does not certify implementation of the specified algorithm. The cap refuses before recording any scan finds, including routine decode finds, and also prevents P12 acceptance for that store. The shipped prefix therefore cannot satisfy the test at RR:1591–1596 requiring the window scan to miss the late payment that decoding finds. The payment-id decoder exists, but targeted rescan and user-selectable per-epoch deep-scan commands are absent. Wallet disclosure text names both commands, Ink release text directs the recipient to targeted rescan, and the host calls this prefix perEpochWindow; those are current-state disclosure gaps, not evidence of available recovery. The normative V1 window, deep scan, targeted rescan, disclosures and acceptance scenarios remain unfulfilled where absent; they are not weakened to match the prefix.


A wallet MUST be able to do all of the following from its seed and chain data
alone, with no roster, batch package or counterparty:

- discover its correctly tagged invoice notes by the decode scan of
  "Discovery decodes tags locally, with the per-epoch window as fallback", and
  its change notes by the tag check or by one trial decryption per packet
  under `K_ρ`;
- learn from those finds every epoch that holds one;
- discover mis-tagged invoice notes with the commands of "A targeted rescan
  and a per-epoch deep scan find mis-tagged payments", within their coverage;
- recover their openings, taking `ρ` from the creating action's nullifier and
  `cm` from its public record;
- rebuild their membership paths from the tree-update history;
- determine their spent status from the complete settlement-lock history,
  reading each settlement's inserted nullifiers.

Invoice issuance MUST follow this gap rule in every epoch, with the invoice gap
constant `G_inv`:

- `u_e` is the routine decode scan's `u_e` over heights at or below the
  anchor-confirmed height of a chain read made at or before the issue: the
  highest index with an owner-verified opening in epoch `e`, counted by that
  scan, in a settlement with at least `c_anchor` confirmations, or −1 if none;
- indices of one epoch are issued once each and in order, and the store MUST
  NOT issue in its current epoch an index above `u_e + G_inv`; it opens a
  fresh epoch instead ("Invoice ids pair a random epoch with a sequential
  index").

`G_inv` is a wallet-profile constant, 20 in the first wallet profile. A later
profile MAY raise it and MUST NOT lower it, and a restore MUST use the largest
value the wallet's profiles used.

Bounded gap closing (ARCH-210) is retired by operator decision HUM-77: a full
window opens a fresh epoch at index 0. A v1 wallet has no zero-value closing
action, closing record, acknowledgement or step bound, and MUST NOT plan an
output to one of its own invoice ids.

#### Scenario: Restore from seed

- **WHEN** a wallet is restored from its seed after receiving correctly tagged
  invoice notes in several epochs, late payments included, and change of
  withheld actions
- **THEN** it MUST recover every such note and its spendability, and learn
  every epoch that holds one, without contacting any other party

#### Scenario: Invoice index far beyond the window

- **WHEN** a wallet whose highest counted index in its current epoch is 1 is
  asked to issue index 1,000,000 of that epoch
- **THEN** it MUST refuse, and a negative test MUST show that a faulty build
  which issues it loses a mis-tagged payment to it under the default per-epoch
  deep scan

#### Scenario: Unpaid invoices fill the window

- **WHEN** the `G_inv` invoices issued in the current epoch after its last paid
  one are all unpaid
- **THEN** the next invoice MUST come from a fresh epoch, and a negative test
  MUST show that holding issuance refuses the request

#### Scenario: Gap-closing action requested

- **WHEN** a caller asks a v1 wallet to plan a zero-value output to one of its
  own invoice ids
- **THEN** the wallet MUST refuse

### Requirement: Discovery decodes tags locally, with the per-epoch window as fallback

Current implementation at 705bd169: routine tag decoding and the change-key trial run over the verified read. The fallback uses, for each known epoch, the prefix from zero through current post-decode u_e plus G_inv, clipped to the index domain and capped at 4,096 ids in total. For a known epoch with monotone u_e over the compared history, below that cap it contains every per-height V1 window W_e(h); this source deduction does not certify implementation of the specified algorithm. The cap refuses before recording any scan finds, including routine decode finds, and also prevents P12 acceptance for that store. The shipped prefix therefore cannot satisfy the test at RR:1591–1596 requiring the window scan to miss the late payment that decoding finds. The payment-id decoder exists, but targeted rescan and user-selectable per-epoch deep-scan commands are absent. Wallet disclosure text names both commands, Ink release text directs the recipient to targeted rescan, and the host calls this prefix perEpochWindow; those are current-state disclosure gaps, not evidence of available recovery. The normative V1 window, deep scan, targeted rescan, disclosures and acceptance scenarios remain unfulfilled where absent; they are not weakened to match the prefix.


A wallet's routine scan MUST decode discovery tags (operator decisions HUM-75
and HUM-77). For every output, in ascending height order from the
deployment's genesis, it MUST:

1. decode the output's tag to a candidate invoice id, by `FF1-AES256.Decrypt`
   under `k_dt` ("Tags and payment ids encode the invoice id");
2. derive `K_I` for that id and trial-decrypt the output's packet once;
3. on an opening, recheck `cm` under `O_I` at the full tier;
4. check the output for change under `K_ρ` for its own `ρ`, by comparing
   `dt(K_ρ, 0x00)` with its tag or by one trial decryption.

Only an owner-verified opening is a find, and it goes through wallet acceptance
like any other. Every find commits by the no-reissue barrier of "Invoice ids
pair a random epoch with a sequential index". The scan reads the complete
pool-lock histories that `apnt-pool-privacy-model` requires, the tags in each
settlement's input 0 included. Matching is local only: no tag, `k_dt`,
decoded id, table or value derived from them MAY be sent to any server, and v1
has no private information retrieval.

- **`u_e`.** `u_e(s)` is the highest index `x` for which the decode scan has
  found an owner-verified opening of `(e, x)` at a height `h' ≤ s` with
  `x ≤ u_e(h' − 1) + G_inv`, or −1 if none. Any other find, above that bound or
  by another scan, raises only `h_e`. `u_e` depends only on the seed, the chain
  and this rule, so a restore reproduces the live wallet's `u_e` in every
  epoch.
- **No table needed.** Decoding needs no table of expected tags and no bound on
  issued indices. A live store MAY keep a table of `dt_I` for the invoices it
  issued, as an accelerator. A restore, and every epoch the store did not
  open, rely on decoding. The T1 invoice table (`x_tab`, `G_scan`, `h_inv` and
  `t_inv`) is retired with T1's payment fill (HUM-77).
- **Cost.** One FF1 decryption, one `K_I` derivation and one trial decryption
  per output, whatever the wallet's volume or number of epochs, plus the
  change check.
- **Every hit rechecked.** A decoded id whose packet does not open, or opens
  and fails the recheck, MUST be ignored. It raises neither `u_e` nor `h_e`,
  adds no epoch, records no note and feeds no acceptance. An incoming-tier
  decode yields owner-unverified candidates only ("Viewing tiers bind notes
  only at the full tier").
- **Per-epoch window.** The per-epoch window scan ("The per-epoch window scan
  follows the V1 window") MAY run routinely beside decoding, and MUST be
  offered as the deep scan. Its finds raise `h_e` by the barrier and never
  `u_e`.

What decoding finds, and what it misses:

- it MUST find every correctly tagged owner-verified payment to any invoice id
  of the wallet, in any epoch and at any height: late payments, payments that
  re-settle after a deep reorganization at an index far above
  `u_e + G_inv`, and payments to epochs the store did not know included. Each
  such find teaches the store its epoch;
- it misses every mis-tagged payment. The per-epoch deep scan, the targeted
  rescan and the one-trial change scan try keys whatever the tag, so each MUST
  find a mis-tagged note within its own coverage exactly as it finds a
  correctly tagged one. A wallet MUST offer all three;
- a foreign output costs one trial decryption, and the recheck refuses a
  chance opening.

The wallet MUST disclose, in its user-facing text, at the end of every restore
and in `LIMITS.md`, that a payment whose payer wrote a wrong tag is missed by
routine decoding and by a seed-only restore. It stays the recipient's, and no
one else can spend it. Only the per-epoch deep scan, in an epoch the wallet
knows, or a targeted rescan with its payment id, in any epoch, finds it. An
epoch whose only payments carry wrong tags is unknown to a seed-only restore.
Until one of those commands finds the payment, the wallet does not hold it and
cannot spend it.

#### Scenario: Late payment found by decoding

- **WHEN** a correctly tagged payment to invoice `(e, x)` settles at or above
  `E_I + grace`, after `u_e` had passed `x`
- **THEN** decoding MUST find it, and a test MUST show that the per-epoch
  window scan misses it

#### Scenario: Mis-tagged payment

- **WHEN** a payer fills a payment's tag slot with random bytes
- **THEN** a test MUST show that decoding misses it, and that the per-epoch
  deep scan and the targeted rescan with its payment id each find it

#### Scenario: Payment after a deep reorganization

- **WHEN** a correctly tagged payment re-settles, after a reorganization that
  removed an anchor-confirmed block, at an index above `u_e(s − 1) + G_inv`
- **THEN** decoding MUST find it, MUST NOT raise `u_e`, and MUST raise `h_e` by
  the barrier

#### Scenario: Payment to an unknown epoch

- **WHEN** a seed-only restore meets a correctly tagged payment to an epoch it
  has no entry for
- **THEN** it MUST find the payment and add the epoch to its table, closed

#### Scenario: Decoded id without an opening

- **WHEN** an output's tag decodes to an id of the wallet, a copied tag
  included, but its packet does not open under that `K_I`, or opens and fails
  the full-tier recheck
- **THEN** nothing MUST be recorded, `u_e` and `h_e` MUST stay unchanged, no
  epoch MUST be added, and nothing MUST be offered to acceptance

#### Scenario: Restore agrees with the live wallet

- **WHEN** a wallet restored from its seed completes its decode scan
- **THEN** its `u_e` MUST equal the live decode scan's `u_e` in every epoch
  that holds a decode find

#### Scenario: Decoding sent to a server

- **WHEN** a wallet sends `k_dt`, a decoded id, a tag it expects, its tag
  table or its change roots to a server to find its outputs
- **THEN** it MUST be treated as a privacy defect, because a server without
  private information retrieval learns exactly which outputs pay the wallet

### Requirement: The per-epoch window scan follows the V1 window

Current implementation at 705bd169: routine tag decoding and the change-key trial run over the verified read. The fallback uses, for each known epoch, the prefix from zero through current post-decode u_e plus G_inv, clipped to the index domain and capped at 4,096 ids in total. For a known epoch with monotone u_e over the compared history, below that cap it contains every per-height V1 window W_e(h); this source deduction does not certify implementation of the specified algorithm. The cap refuses before recording any scan finds, including routine decode finds, and also prevents P12 acceptance for that store. The shipped prefix therefore cannot satisfy the test at RR:1591–1596 requiring the window scan to miss the late payment that decoding finds. The payment-id decoder exists, but targeted rescan and user-selectable per-epoch deep-scan commands are absent. Wallet disclosure text names both commands, Ink release text directs the recipient to targeted rescan, and the host calls this prefix perEpochWindow; those are current-state disclosure gaps, not evidence of available recovery. The normative V1 window, deep scan, targeted rescan, disclosures and acceptance scenarios remain unfulfilled where absent; they are not weakened to match the prefix.


The per-epoch window scan is the V1 window of operator decision HUM-70
(ARCH-198), applied to every epoch of the store's known set with that epoch's
`u_e`. It is the deep scan's base, and MAY run routinely beside decoding
("Discovery decodes tags locally, with the per-epoch window as fallback"). Its
definitions:

```text
height    a block height of the chain the wallet reads. A packet's height is
          that of the block holding the settlement transaction whose
          statement carries it
c_anchor  the confirmation depth: the tip block has 1 confirmation. A chain
          read with tip τ has anchor-confirmed height τ − c_anchor + 1. A
          shallow reorganization removes no block with c_anchor
          confirmations
t_I       the anchor-confirmed height through which the routine decode scan
          behind the store's u_e has run when the wallet issues invoice I
T         the invoice lifetime in blocks, T ≥ 1; t_I + 1 ≤ E_I ≤ t_I + T
L_settle  the settlement-lag bound in blocks: the most blocks between a
          payer's tip when it begins or resubmits an action and that
          action's height on an honest submission path, covering the
          randomized submission delay, up to R_retry anchor re-proves,
          aggregation, re-inclusion after a shallow reorganization and the
          payer's chain-view lag
grace     blocks, with grace ≥ 2·L_settle
G_inv     the invoice gap constant
u_e(s)    the routine decode scan's u_e for epoch e at heights ≤ s; −1 if
          none, and for every s below the deployment's genesis
W_e(h)    { x : u_e(h − T − grace) < x ≤ u_e(h − 1) + G_inv }
```

`W_e(h)` is HUM-70's `(u(h − T − grace), u(h) + G]` for one epoch, whose
`u(h)` counts heights below `h`. In this requirement `h` names a height, and
`h_e` an epoch's highest issued or burned index. Indices are integers in
`[0, 2^24 − 1]`; every scan upper bound MUST be clipped to that domain using
checked arithmetic before clipping, never wrapped. The following MUST hold:

- a window scan MUST process heights in ascending order from the deployment's
  genesis. For each height `h` and each epoch `e` it scans, it MUST compute
  `W_e(h)` before it tries any packet at `h`, and MUST try every packet at `h`
  under `K_(e, x)` for every `x ∈ W_e(h)`, whatever the packet's tag;
- **no-reissue barrier.** Every owner-verified note that any scan finds at
  `(e, x)`, whether decoding, the window scan, a targeted rescan or a deep
  scan, with or without `G_ext,e`, MUST set `h_e := max(h_e, x)` and add `e`
  to the table in the same store transition that records the note, and the
  note MUST NOT be reported or accepted before that transition commits. Every
  index at or below `h_e` in epoch `e` is issued or **burned**: it is never
  issued to a payer again. `h_e` MUST never fall within a retained store
  lineage or below any available restore source;
- a note found above `h_e` is one funded with the seed or a full viewing key
  to an id the wallet never issued, a payment to an id another store of the
  seed issued in a colliding epoch, or, after a restore, a payment in an epoch
  a lost store opened. The wallet MUST accept it as funds under "Acceptance
  stays with the wallet", record that it was found above `h_e`, and, in its
  current epoch, close that epoch;
- the wallet MUST issue invoice `(e, x)` only from a store whose routine
  decode scan has run through `t_I`, with `x ≤ u_e + G_inv`;
- on a reorganization every scan MUST discard every finding from the removed
  blocks, recompute `u_e` from the fork point in every epoch and scan the
  replacing blocks. `h_e` and the table are kept;
- the window scan MUST find every owner-verified payment to an issued invoice
  of a known epoch that settles below `E_I + grace`, whatever its tag,
  provided every reorganization since its issue was shallow. A reorganization
  removing a block with `c_anchor` confirmations is the disclosed residual of
  "A targeted rescan and a per-epoch deep scan find mis-tagged payments", and
  it can also move a payment to or above `E_I + grace`;
- a late payment is not missed for being late. Under the same premises every
  find that `u_e` counts at an index at or above `x` settles above `t_I`, so
  `u_e(s) < x` for every `s ≤ t_I`, and `W_e(h)` holds `x` at every height
  `h` with `t_I < h ≤ t_I + T + grace`, which includes `E_I + grace`. It
  can lose `x` only at a height `h` with `u_e(h − T − grace) ≥ x`, so no
  earlier than `t_I + T + grace + 1`. This bounds where a test can show a
  miss; it adds nothing to what the window is required to find. A test that
  requires the window to miss a late payment to a known epoch MUST settle the
  payment at such a height and state the history that raises `u_e` there,
  and MUST NOT rest the miss on an unknown epoch or a deep reorganization
  unless that residual is what it tests;
- `T`, `grace` and `G_inv` are wallet-profile constants. A later profile MAY
  raise them and MUST NOT lower them, every profile MUST satisfy
  `grace ≥ 2·L_settle`, and a scan MUST use the largest values any profile of
  the wallet used. Their values are set from task 1.4's measurements (D4);
  until then only labelled test profiles use them.

#### Scenario: Payment at the expiry edge

- **WHEN** invoice `(e, a)` is paid with a wrong tag at height `E_a + grace − 1`
  after a later invoice `(e, b)` of the same epoch was paid at once
- **THEN** the window scan MUST find it, and a negative test MUST show that a
  build with lower bound `u_e(h − T)`, without grace, misses it

#### Scenario: Window without lower slack

- **WHEN** a build scans only `(u_e(h − 1), u_e(h − 1) + G_inv]`
- **THEN** a negative test MUST show it loses mis-tagged honest notes paid at
  or below `u_e`, such as second payments and payments that settle out of
  index order

#### Scenario: Invoice issued at exactly `u_e + G_inv`

- **WHEN** an invoice issued at exactly `u_e + G_inv` is paid at once with a
  wrong tag
- **THEN** the window scan MUST find it, and a negative test MUST show that a
  build with upper bound `u_e(h − 1) + G_inv − 1` misses it

#### Scenario: Shallow reorganization at issue

- **WHEN** the wallet's chain read at issue ran `c_anchor − 1` blocks ahead of
  the chain that later holds the payments, the next invoice's payment settles
  just above the shared blocks, and invoice `I` is paid with a wrong tag at
  `E_I + grace − 1`
- **THEN** the window scan MUST find it, and a negative test with
  `c_anchor ≥ 3` MUST show that a build setting `t_I` to its tip, not its
  anchor-confirmed height, misses it

#### Scenario: Window scan agrees across restore

- **WHEN** a wallet restored from its seed completes its decode scan and then
  its window scan of a known epoch
- **THEN** for mis-tagged payments to issued invoices under the
  shallow-reorganization assumptions, a missed note MUST have an index at or
  below `u_e(h − 1)` for its height `h`. Notes funded above the window and
  payments after deep reorganizations are outside that claim

#### Scenario: Note to an unissued index

- **WHEN** a full-viewing-key holder funds an owner-verified, correctly tagged
  note to `(e, h_e + k)` with `h_e + k ≤ u_e + G_inv`
- **THEN** decoding MUST count it in `u_e`, the store MUST burn through it in
  the same transition, keeping `u_e ≤ h_e`, the wallet MUST accept it as funds
  and record where it was found, and a seed-only restore MUST reach the same
  `u_e`. Negative tests MUST show that a store raising `u_e` without burning
  breaks `u_e ≤ h_e`, and that a live wallet leaving such notes out of `u_e`
  makes a seed-only restore's `u_e` disagree with it

#### Scenario: Owner-unverified candidate in the window

- **WHEN** a packet under `K_(e, x)` opens but fails the full tier's `cm`
  recheck
- **THEN** neither `u_e` nor `h_e` MUST rise

#### Scenario: Finding removed by a reorganization

- **WHEN** a shallow reorganization removes a block holding a found note
- **THEN** every scan MUST drop that finding and recompute `u_e` from the fork
  point before it scans the replacing blocks, and `h_e` MUST stay

#### Scenario: Profile lowers a window constant

- **WHEN** a later wallet profile would lower `T`, `grace` or `G_inv`, or set
  `grace < 2·L_settle`
- **THEN** it MUST be refused

### Requirement: A targeted rescan and a per-epoch deep scan find mis-tagged payments

Current implementation at 705bd169: routine tag decoding and the change-key trial run over the verified read. The fallback uses, for each known epoch, the prefix from zero through current post-decode u_e plus G_inv, clipped to the index domain and capped at 4,096 ids in total. For a known epoch with monotone u_e over the compared history, below that cap it contains every per-height V1 window W_e(h); this source deduction does not certify implementation of the specified algorithm. The cap refuses before recording any scan finds, including routine decode finds, and also prevents P12 acceptance for that store. The shipped prefix therefore cannot satisfy the test at RR:1591–1596 requiring the window scan to miss the late payment that decoding finds. The payment-id decoder exists, but targeted rescan and user-selectable per-epoch deep-scan commands are absent. Wallet disclosure text names both commands, Ink release text directs the recipient to targeted rescan, and the host calls this prefix perEpochWindow; those are current-state disclosure gaps, not evidence of available recovery. The normative V1 window, deep scan, targeted rescan, disclosures and acceptance scenarios remain unfulfilled where absent; they are not weakened to match the prefix.


A payment is **mis-tagged** when its tag is not its invoice's `dt_I`; routine
decoding misses it. A payment to invoice `I` that settles at a height
`h ≥ E_I + grace` is **late**; decoding finds a correctly tagged late payment.
The wallet MUST offer two commands that try keys whatever the tag:

- **targeted rescan by payment id.** Given a payment id, the wallet MUST
  decode it to `I` ("Tags and payment ids encode the invoice id"), refusing an
  id that does not decode and reporting nothing else. It MUST then try `K_I`,
  and only `K_I`, once on every packet from the deployment's genesis to its
  tip. It MUST NOT skip packets at or below the invoice's `t_I`, a stored
  anchor, the height of the invoice's issue or any other height taken from
  the invoice's history. After a reorganization that removed an
  anchor-confirmed block, a replacement branch can hold the payment below
  every such height (REV-179 H1-2). It MAY try the heights above a stored
  `t_I` first and report a find there once its barrier commits; it completes
  only after it has tried every height. It works for any epoch, one the store
  does not know included, and a find adds that epoch to the table, closed;
- **per-epoch deep scan.** For each epoch `e` of the known set, the window
  scan with no lower bound: at each height `h` from the deployment's genesis
  it MUST try every `x` with `0 ≤ x ≤ u_e(h − 1) + G_inv + G_ext,e` on every
  packet, whatever its tag, with `u_e` from the routine decode scan.
  `G_ext,e ≥ 0` is an extension, 0 by default. A store that holds `h_e` MUST
  offer `G_ext,e = max(0, h_e − G_inv + 1)`, which covers every index at or
  below `h_e` at every height, because `u_e ≥ −1`. Every bound MUST be
  clipped to `2^24 − 1` using checked arithmetic before clipping, never
  wrapped.

A note either command finds MUST go through the full-tier recheck and wallet
acceptance like any other. It MUST NOT change `u_e` or the window, and it MUST
raise `h_e` and add its epoch by the no-reissue barrier.

After a reorganization that removed an anchor-confirmed block, a mis-tagged
payment to an issued index can settle at a height `s` with
`x > u_e(s − 1) + G_inv`. The default deep scan then misses it. The deep scan
with `G_ext,e` covering `h_e` finds it in an epoch whose `h_e` the store holds,
and the targeted rescan finds it in any epoch. A seed-only restore knows `h_e`
only from finds.

The wallet MUST disclose this residual in its user-facing text, at the end of
every restore and in `LIMITS.md`. A mis-tagged payment stays the recipient's,
and no one else can spend it, but routine decoding and a seed-only restore
miss it, and a note the wallet has not found is not spendable by the wallet
either. A targeted rescan with its payment id finds it at one trial decryption
per packet, in any epoch and at any height. Without the payment id only the
per-epoch deep scan finds it, only in an epoch the wallet knows, at a cost that
grows with the number of epochs; after a reorganization that removed an
anchor-confirmed block, only an extended deep scan does. An epoch whose only
payments are mis-tagged is unknown to a seed-only restore, and only a payment
id or a backup's table reaches it.

#### Scenario: Mis-tagged payment after restore

- **WHEN** a mis-tagged payment to `(e, x)` settled on time in an epoch the
  restored store knows
- **THEN** decoding MUST miss it, the targeted rescan with its payment id MUST
  find it with one trial decryption per packet, and the per-epoch deep scan
  MUST find it without the payment id

#### Scenario: Mis-tagged payment below the stored anchor after a deep reorganization

- **WHEN** invoice `(e, 20)` was issued after a decode scan through
  `t_I = 100` with `u_e = 0`, a reorganization removes every block above
  height 4, the index-0 payment included, the payer pays again on the
  replacement branch at height 95 with a wrong tag, and a store restored from
  a backup holding `t_I = 100` and `h_e = 20` runs the targeted rescan with
  that invoice's payment id
- **THEN** the rescan MUST find the payment at height 95. A negative test MUST
  show that a rescan starting above the stored `t_I` finds nothing, that the
  default per-epoch deep scan (`u_e = −1`, bound 19) misses index 20, and that
  `G_ext,e = 1` finds it (REV-179 H1-2)

#### Scenario: Epoch reached only through a payment id

- **WHEN** an epoch's only payment carries a wrong tag and the wallet is
  restored from its seed alone
- **THEN** decoding and the per-epoch deep scan MUST miss it, the targeted
  rescan with its payment id MUST find it, and the find MUST add the epoch to
  the table

#### Scenario: Unknown payment id

- **WHEN** a targeted rescan is given a value that does not decode: one that
  is not 16 bytes long, or a 16-byte value whose last eight decrypted bytes
  are not all zero, such as a test's chosen flipped-bit, fixed-random or
  foreign payment id
- **THEN** the wallet MUST refuse it and report nothing else. An invalid
  16-byte value that decodes by chance, with probability about `2^-64`, only
  makes the rescan try one wrong key, and nothing is recorded unless an
  owner-verified note under that key exists

#### Scenario: Rescan finding and the window

- **WHEN** a targeted rescan or a deep scan finds a note at `(e, x)`
- **THEN** `u_e` and the window MUST stay unchanged, `h_e` MUST become
  `max(h_e, x)`, and `e` MUST be in the table, in the transition that records
  the note

#### Scenario: Note found above the window

- **WHEN** a store with `u_e = −1`, `h_e = 0` and `G_inv = 20` in its current
  epoch runs a deep scan with `G_ext,e = 1` that finds an owner-verified,
  mis-tagged note funded with a full viewing key to the unissued `(e, 20)`
- **THEN** it MUST accept the note and record where it was found, set
  `h_e := 20`, close the epoch, and issue its next invoice from a fresh epoch.
  A negative test MUST show that a rule leaving `h_e` at 0 later issues
  `(e, 20)` to a payer who can open that note

#### Scenario: Find reported before its barrier commits

- **WHEN** a scan reports or accepts a found note before the transition that
  raises `h_e` commits, or a crash falls between the find and that commit
- **THEN** an implementation that reports first MUST be rejected; after a crash
  before the commit nothing is released, and running the scan again finds the
  note again

#### Scenario: Restore without the disclosure

- **WHEN** a restore completes without telling the user that mis-tagged
  payments need a targeted rescan or a deep scan
- **THEN** it MUST be corrected

### Requirement: Wallet pool state is a durable, journaled store

The wallet's pool state MUST live in a durable store, one per deployment.
Every transition that issues an invoice, opening an epoch when "Invoice ids
pair a random epoch with a sequential index" requires it, allocates an action
counter, begins a payment as a payer, records the routine scan's `u_e` or a
scan's find, or restores MUST be reserve-then-commit against that store:

1. it names the revision it last read;
2. it takes the store's exclusive lock, refusing if the lock is held;
3. it reads the journal and the state file. The state's revision MUST equal
   the journal's last revision, and the SHA-256 of the state's canonical text
   MUST equal that record's digest;
4. it refuses unless the revision equals the one it named;
5. it computes the next state, at revision + 1, and validates every persisted
   invariant;
6. it appends and flushes the journal record `{kind, revision, digest}`, then
   commits the state durably;
7. it releases the lock, and only then releases its result.

The journal record carries kind, revision and the digest of canonical state text. In the shipped journal JSON that digest is stored under the field named state. The journal append is flushed before durable state replacement, and output is released after the transition completes. Expanded payer-release/deposit/owner records are additional authenticated lifecycle state; the original small snapshot is not a complete current schema.


An issuance transition MUST take `t_I` from the wallet's own chain read. An
issuance that opens an epoch MUST draw the epoch inside the transition, after
step 3 and under the lock, and MUST commit the new epoch together with its
first issued index in step 6. The store holds no change state.

A process MUST hold in memory the revision and state digest of the last state
it committed to the store; they are the session rule's input, and MUST NOT be
read back from the store as evidence that the process committed them.

Every read and every commit MUST re-validate these persisted invariants:

- the epoch table of "Invoice ids pair a random epoch with a sequential
  index": for every epoch `−1 ≤ u_e ≤ h_e ≤ 2^24 − 1`, at most one current
  epoch, and a current epoch with `h_e ≥ 0`; the store records the
  anchor-confirmed height through which its routine decode scan has run;
- each payer record binds one allocated action counter to an exact copy of all
  six invoice fields `(v, O_I, K_I, dt_I, payment id, E_I)`, the payer's begin
  height below `E_I`, and the cancel and late heights fixed at begin; a counter
  carries at most one record;
- each deadline-release fact of "Deadline refusal releases never-dispatched
  payments" matches a retained built non-cancellation payer record by action
  counter and payment id, with at most one fact per counter and a valid
  deadline reason and observed height (REV-594 MM-2, MM-3);
- the state text is canonical.

Every transition MUST also keep, against the state it replaces: no epoch
removed, no `h_e` lowered, no closed epoch made current, no epoch made current
except by an issuance that opens it, no payer record removed or changed, and no
fall of the action counter. Release facts MUST be append-only: no fact removed
or changed, and a fact added only by the same transition that refuses the
matching eligible never-dispatched operation at its deadline (REV-594 MM-2).

Failures MUST be fail closed:

- a lock left by a crash keeps the store busy until an operator removes it;
- a crash between journal and state leaves every later read refusing until the
  restore command runs;
- a crash after commit and before release burns the reserved value, which
  MUST never be handed out again.

An epoch with `h_e > u_e + G_inv`, after a deep reorganization lowered `u_e` or
a find raised `h_e`, is valid and loads. The store MUST keep `h_e` and MUST NOT
lower it on reorganization, scan rollback or repair, and its next issuance
opens a fresh epoch. Scans, change planning, action counters and release still
work.

#### Scenario: Concurrent issuance

- **WHEN** two processes issue an invoice from the same read revision
- **THEN** at most one MUST succeed; the other MUST be refused as busy or stale,
  and no invoice id MUST be handed out twice

#### Scenario: Two processes in turn

- **WHEN** two processes of one store issue invoices in turn, each after the
  other has committed
- **THEN** each MUST open a fresh epoch at its first issuance after the other's
  commit, and no invoice id MUST be handed out twice

#### Scenario: State file rolled back alone

- **WHEN** the state file is replaced by an older copy, or edited to claim a
  newer revision, while the journal is intact
- **THEN** every read and transition MUST refuse it

#### Scenario: Crash between journal and state

- **WHEN** a transition's journal record is durable but its state commit is not
- **THEN** nothing MUST have been released, and the store MUST refuse until
  restored

#### Scenario: Current epoch without an issued index

- **WHEN** a transition would commit a state whose current epoch has no issued
  or burned index
- **THEN** the store MUST refuse it

#### Scenario: Window lowered by a deep reorganization

- **WHEN** a persisted state's current epoch has `h_e > u_e + G_inv`
- **THEN** it MUST load and keep `h_e`, and its next issuance MUST open a fresh
  epoch. A negative test MUST show that a store lowering `h_e` to
  `u_e + G_inv` issues an id it had already issued

### Requirement: Restore recovers notes and issues from a fresh epoch

Phase 3 defers active cancellation, fresh-wallet restore, restored-wallet refund and the separate-machine exercise under Scope v2/v3 and plan section 5. Existing expiry/H_cancel refusals and created-home refund remain in scope. RR-10 is partial implementation, not wholly deferred. Seed restore code, counter jumps or retained-home refund do not demonstrate the deferred exercises. Full target cancellation, no-hold recovery, privacy conditions and failure states remain normative and unfulfilled where absent. Found or recovered notes are not thereby accepted or spendable; an unsigned release does not settle cancellation.


Restoring the store from any backup or supplied seed MUST go through the
wallet's restore command. A restore recovers existing notes, learns the
seed's epochs, and **resumes invoice issuance under the same seed** from a
fresh epoch. Operator decision HUM-77 (2026-09-24) reverses HUM-74 option C:
a restored seed keeps issuing, with no second seed and no issuance hold.

The restore MUST:

- keep every epoch a source holds, the backup's table and the directory's own
  state when it is readable and bound to this wallet, each closed, with `h_e`
  the largest over the sources and `u_e = −1` until the restore scan
  recomputes it. From the seed alone the table starts empty;
- keep every payer record of every source, reconciled by action counter. A
  record several sources hold identically is kept once. A released record
  stays retained but non-retryable; an unreleased record keeps its existing
  retry and reservation rules. Two different records on one counter refuse
  the restore before any file changes (REV-177 H1-R367; HUM-131);
- carry the release facts of every source as a union by action counter and
  payment id, validate each against a retained built non-cancellation payer
  record, and refuse conflicting facts for one counter before any file
  changes. Dropping the owner-operation journal MUST NOT drop these facts
  or reserve the released notes again (REV-594 MM-7);
- use the largest window constants of the supplied and retained profiles;
- set `restore-scan-pending`, which refuses every invoice request until the
  routine decode scan and the change scan have run from the deployment's
  genesis and committed every find, each with its barrier and epoch, and
  `u_e` in every epoch. Only that scan clears it;
- advance the per-action counter by at least `2^32` plus a random offset, and
  refuse any new action below it;
- allocate, clear or skip nothing for change: its keys follow from `ρ`;
- present the mis-tagged-payment and epoch-collision disclosures, and offer
  the targeted rescan and the per-epoch deep scan. Nothing MAY hold recovery,
  acceptance checks or spending of found notes.

The first issuance after a restore opens a fresh epoch outside every epoch the
restore learned ("Invoice ids pair a random epoch with a sequential index").
There is no invoice issuance hold, remembered floor, acknowledgement or second
seed. Initializing a store for a supplied seed is a restore: its notes and
epochs must be scanned for before its first draw (ARCH-217, amended by
HUM-77). It holds no issuance once that scan has committed. A store for a seed
the wallet has just generated MAY start without the restore command.

An unpaid pre-loss invoice leaves no trace on chain, and no scan of seed plus
chain reveals it (ARCH-209). No restore issues in a pre-loss epoch, and its
fresh epoch equals a lost store's unknown epoch only through the
epoch-collision residual. Expiry does not revoke `K_I` or a signed action, and
nothing here relies on it.

The counter jump makes reuse of a pre-restore counter improbable, not
impossible. Repeated restores from one old backup draw from the same range.
Documentation MUST NOT claim that it categorically prevents counter reuse. A
reused counter repeats dummy nullifiers, which the range records refuse: a
liveness failure.

#### Scenario: Backup predates later payments

- **WHEN** a wallet backed up with epoch `e_0` at `u = 1` later saw `u = 10`,
  issued invoices up to `(e_0, 30)`, was lost, and is restored from that
  backup
- **THEN** the restore MUST keep `e_0` closed, MUST issue its first invoice
  from a fresh epoch, and MUST never issue a pre-loss id such as `(e_0, 22)`

#### Scenario: Restore never lowers the high-water mark

- **WHEN** a restore's source holds an epoch with `h_e > u_e + G_inv`
- **THEN** the restored `h_e` MUST be at least the source's

#### Scenario: Deep reorganization before a restore

- **WHEN** a reorganization deeper than `c_anchor` removes the index-0 payment
  that justified issuing through `(e_0, 20)`, the correctly tagged payment to
  `(e_0, 20)` then settles on time, and the seed is restored
- **THEN** the restore MUST decode the `(e_0, 20)` payment, MUST issue from a
  fresh epoch, and MUST NOT issue `(e_0, 20)`. A negative test MUST show that
  the pre-barrier rule issues `(e_0, 20)` again, whose key opens the payment
  (REV-163)

#### Scenario: No floor needed

- **WHEN** the lost store issued through `(e_0, 20)` with every invoice unpaid,
  and the user remembers only 19
- **THEN** the restore MUST ask for no floor, MUST issue from a fresh epoch,
  and MUST decode the payment to `(e_0, 20)` when it settles. A negative test
  MUST show that a floor-19 rule's key for index 20 opens that payment
  (REV-165)

#### Scenario: Paid-note discovery is not complete issuance history

- **WHEN** two pre-loss histories differ only in an unpaid invoice and have
  identical seed, backup and replacement-chain inputs to restore
- **THEN** both restores MUST issue only in fresh epochs they drew, and a
  negative test MUST show that a deterministic rule, the next index after the
  highest found or an epoch derived from the seed and chain, collides with the
  lost history in one of them (ARCH-209)

#### Scenario: Issuance before the restore scan completes

- **WHEN** an invoice is requested after a restore and before its decode and
  change scans from genesis have committed
- **THEN** the wallet MUST refuse; once they commit, the next request MUST be
  served from a fresh epoch with no other clearing step

#### Scenario: Supplied seed in an empty directory

- **WHEN** a store is initialized for a supplied seed
- **THEN** it MUST run the restore command's scans before its first draw, and
  MUST then issue from a fresh epoch

#### Scenario: Conflicting payer records

- **WHEN** two restore sources hold different payer records on one action
  counter
- **THEN** the restore MUST refuse before any file changes; identical records
  MUST be kept once, with released records non-retryable and all other records
  subject to their existing retry and reservation rules

#### Scenario: Older backup and retained release fact

- **WHEN** a backup predates a deadline release, but another readable source
  bound to the wallet holds the matching payer record and release fact
- **THEN** restore MUST carry that fact, retain the record as non-retryable,
  and allow a later payment to select its unspent note without requiring the
  dropped owner journal or the released payment's selection file

#### Scenario: Conflicting release facts

- **WHEN** restore sources disagree on a release fact for one action counter,
  or a fact has no matching retained built non-cancellation payer record
- **THEN** restore MUST refuse before any file changes

#### Scenario: Seed-only restore races pre-loss actions without a hold

- **WHEN** a seed-only restore has no retained payer records or release facts
  and finds a note whose pre-loss action is unsettled
- **THEN** the wallet MUST introduce no hold, disclose that a new spend races
  the pre-loss action, and reconcile spentness from its own verified chain
  read; recovery alone MUST NOT be reported as spendability

#### Scenario: Change after restore

- **WHEN** a wallet restored from its seed alone has change from actions that
  were withheld and settled after the restore began
- **THEN** the change scan MUST find every such note at one trial decryption
  per packet, with no change state in the store

### Requirement: A wallet funds a deposit inbox only after its pre-funding binding

A wallet deposits through the deployment's pool inbox
(`apnt-pool-settlement-custody`, "Deposits enter through a record-keyed pool
inbox"; operator decision HUM-104, 2026-09-27). Before any funding
signature it MUST do the following, in this order, and every refusal MUST
happen before the funding signer is invoked:

1. **Select the deployment.** The network and `deployment_id` come from the
   wallet's own state. No aggregator, invoice or relay message MAY select or
   change them. An external artifact is candidate data, and its network and
   id MUST equal the selection.
2. **Establish genesis from its own chain read.** From its own chain
   interface, not from caller-supplied transactions or a validity flag, the
   wallet establishes which transactions spend the category genesis
   outpoints, their bytes, their inclusion and their confirmation depth.
   Missing, conflicting or insufficient evidence MUST fail closed, and a
   reorganization MUST invalidate the cached context. It then audits those
   bytes with the existing genesis validator, requiring success and a
   returned `deployment_id` equal to its selection. The validator audits
   supplied bytes and is not a chain read.
3. **Take the inbox code from the reviewed build.** The inbox code and its
   hash MUST come from the reviewed inbox build shipped with the wallet, for
   the verdict category and settlement lock of that same audited deployment
   and the fixed delay. The artifact's inbox entry is only checked against
   it.
4. **Derive the record and the refund key itself.** The wallet reserves a
   fresh action counter in its store, then derives the deposit action from
   its seed, the selected deployment and that counter. Both inputs are
   dummies, output 0 is `W − fee` to its own change keys for
   `ρ_out_0 = nf_0`, output 1 is a dummy, and the tags follow the v1 fill
   rules. It computes the record, `rk_0`, packets, commitments, `ad` and the
   owner signatures locally. No external message MAY supply the record or its
   spend authority. On resuming a plan, it MUST re-derive the complete record
   and compare it byte for byte.
5. **Bind the authorization to the deployment.** The action's authorization
   digest and the statement header bind the action to the selected
   deployment. No field is added to the record, and no request MAY relabel
   it with a supplied `ad` or id.
6. **Check the actual funding output, then sign that snapshot.** Immediately
   before signing, it copies the unsigned funding transaction and its source
   outputs into the signing operation. At the plan's designated output index
   it requires the lock it computed from its own record and the reviewed
   code, byte for byte, a value of exactly `W`, and no token. It then signs
   that same snapshot with `SIGHASH_ALL|SIGHASH_UTXOS` (`0x61`). An
   asynchronous signer's returned transaction MUST be compared with the
   authorized snapshot before release.
7. **Fund once.** A plan and its lock MUST have at most one outstanding
   funding. After a crash or an uncertain broadcast, the wallet reconciles
   from its own chain read before funding anything new. A pending observation at
   its funding source before funding is confirmed, or at this plan's inbox
   lock, makes it wait: it MUST NOT sign funding or refund, or re-offer intake.
   Reconcile MUST report an attempt as pending for its inbox lock, or for its
   funding source while funding remains unconfirmed. A confirmed-funded
   attempt MUST be classified from its confirmed inbox history (ARCH-310).

#### Scenario: Own pending funding or inbox lock

- **WHEN** the wallet observes a pending transaction at its funding source before funding confirms, or at the plan's inbox lock
- **THEN** it MUST wait without signing funding or refund or re-offering intake, and reconciliation MUST report pending for the affected attempt

The seed, `ask_d` and `rsk_0 = ask_d + α_d` MUST NOT leave the wallet. After
funding confirms, the wallet submits only the public record, proof, owner
signatures, tags and inbox outpoint. It SHOULD fund each deposit from one of
its own seed-derived transparent addresses, one source per deposit, at the
standard fee: that is what lets a seed-only restore find an unsettled inbox.

A test MUST show every refusal below with zero funding-signer calls. For
each binding removed, the firing control MUST show exactly one signature and
a funding transaction that both BCH 2026 VMs accept. A composite removal
MUST be named as composite, not as evidence that each part fires alone.

#### Scenario: Forged self-consistent artifact

- **WHEN** a candidate artifact carries its own settlement covenant, inbox code
  and hash, all consistent with each other, and possibly a recomputed identity
- **THEN** the wallet MUST refuse before signing, by its deployment selection
  and its own genesis read and audit

#### Scenario: Another valid deployment

- **WHEN** the candidate is a genuine, validator-accepted deployment whose id
  differs from the wallet's selection
- **THEN** the wallet MUST refuse before signing

#### Scenario: Same-id genesis not from the wallet's own read

- **WHEN** a candidate supplies an alternate genesis transaction that the
  validator accepts under the selected id, but the wallet's own chain read
  shows other transactions
- **THEN** the wallet MUST refuse before signing, and the control that trusts
  the supplied bytes MUST sign

#### Scenario: Inbox code or hash not the reviewed build

- **WHEN** the artifact's inbox code differs from the reviewed build for the
  audited parameters, or its hash differs from that build's
- **THEN** the wallet MUST refuse before signing

#### Scenario: Supplied or altered record

- **WHEN** a record is supplied from outside the wallet, even byte-identical
  to its own, or the wallet's `cm_0`, `packet_0` and `W` arrive with another
  `rk_0`
- **THEN** the wallet MUST fund only the lock of the record it derived
  itself, and MUST refuse the other before signing. The control MUST show the
  other key refunding the funded inbox

#### Scenario: Funding output not exactly as planned

- **WHEN** the designated funding output holds `W + 1` or `W − 1` satoshis or
  a token, or the correct lock appears only at another output while a
  different lock sits at the designated index
- **THEN** the wallet MUST refuse before signing

#### Scenario: Transaction swapped after the check

- **WHEN** a signer checks one transaction and signs another
- **THEN** the build MUST be rejected; a test MUST show that the wallet's
  `0x61` signature over the checked snapshot fails when moved to any other
  body

#### Scenario: Second funding while one is outstanding

- **WHEN** a plan whose inbox is funded and unspent is funded again
- **THEN** the wallet MUST refuse, and a resubmission MUST reuse the existing
  outpoint and record

### Requirement: Deposits are tracked, restored and refunded by the wallet

Phase 3 defers active cancellation, fresh-wallet restore, restored-wallet refund and the separate-machine exercise under Scope v2/v3 and plan section 5. Existing expiry/H_cancel refusals and created-home refund remain in scope. RR-10 is partial implementation, not wholly deferred. Seed restore code, counter jumps or retained-home refund do not demonstrate the deferred exercises. Full target cancellation, no-hold recovery, privacy conditions and failure states remain normative and unfulfilled where absent. Found or recovered notes are not thereby accepted or spendable; an unsigned release does not settle cancellation.


The wallet's store MUST persist, by the reserve-then-commit transitions of
"Wallet pool state is a durable, journaled store", each deposit's counter
reservation, funding outpoint, observed settlement or refund, and counter
retirement. When the wallet observes a confirmed refund of an action's inbox,
that action's counter MUST be retired permanently. A retry is then a new
action with a fresh counter, so fresh dummies, `rk_0`, `cm_0`, packets and
lock. A restore MUST NOT reset this history or reuse an exposed counter.

The wallet MUST be able, from its seed and chain data:

- to find a settled deposit's note by the change scan;
- to re-derive an unsettled inbox's record and lock from the seed and the
  deposit counter, taking `W` from its own transparent history;
- to refund an unsettled inbox with `rk_0`'s key once the 1,008-block
  relative lock has matured.

An inbox funded from outside the seed keeps a recoverable refund key but not
a recoverable lock unless `W` is backed up, and the wallet MUST say so.

#### Scenario: Counter reused after a refund

- **WHEN** a wallet would fund again an action whose inbox it has refunded
- **THEN** it MUST refuse, and allocate a fresh counter for the retry. A
  negative test MUST show that reusing the counter rebuilds the identical
  record and lock, whose settlement puts the refunded `rk_0` and `cm_0` on
  chain a second time

#### Scenario: Refund before maturity

- **WHEN** a wallet refunds an inbox whose funding has fewer than 1,008
  confirmations
- **THEN** the local ledger MUST refuse it, and the wallet MUST NOT describe
  the refund as spendable before maturity

#### Scenario: Restore with an unsettled inbox

- **WHEN** a wallet is restored from its seed while one of its inboxes, funded
  from its own transparent address, is unsettled
- **THEN** it MUST find the inbox, recompute its lock, and be able to refund
  it after maturity or leave it for settlement, without contacting any other
  party

### Requirement: Wallet results are classed by where they may go

Every successful result of an exported pool-wallet function MUST carry its data
only under these parts:

- `walletPrivate`, which never leaves the wallet;
- `proverDelegable`, the relation's witness for one slot. It carries `ak`,
  `nk`, `α`, `K`, `v`, `rcm` and `ρ` by design, and MUST NOT carry `ask`,
  `rsk`, the seed or a wallet root. A change output's witness carries its
  `K_ρ`, `nk_ρ` and `ak_ρ`, which every member of its `ρ` family shares and no
  settled note outside that family shares;
- `viewDelegable`, a viewing key of one tier. It MUST NOT carry `ask`, `rsk`,
  `k_pid` or the seed. The incoming tier's `kr_b` yields `k_dt`, so its holder
  decodes tags and learns epochs ("Viewing tiers bind notes only at the full
  tier");
- `payerFacing`, an invoice, carrying its own `K_I`, `dt_I` and payment id. It
  MUST NOT carry any other secret, `I`, its epoch or its index;
- `public`, on-chain bytes, with no secret. An output's discovery tag is
  `public` from the moment its action is submitted.

The epoch table, invoice ids, epochs, indices, `k_pid`, and every tag the
wallet derives to match or check outputs are `walletPrivate`.

Handing a `proverDelegable` witness to a delegated prover discloses it, and MUST
be presented as an explicitly labelled privacy disclosure. A test MUST check
every exported function, with a firing control, and show that no spend
scalar, no seed, no invoice id and no epoch appears outside `walletPrivate`.

#### Scenario: Spend scalar in a delegable result

- **WHEN** any exported function returns `ask`, `rsk` or the seed in a part
  other than `walletPrivate`
- **THEN** the result-class test MUST fail

#### Scenario: Invoice id outside the wallet

- **WHEN** any exported function returns `I`, an epoch, the epoch table or
  `k_pid` in a part other than `walletPrivate`
- **THEN** the result-class test MUST fail

#### Scenario: Witness described as secret-free

- **WHEN** documentation says a prover witness carries no `nk`, `K` or `α`
- **THEN** it MUST be corrected to say the witness carries them by design and
  carries no spend authority

### Requirement: Acceptance stays with the wallet

A wallet MUST accept a received note only from its own chain read of the
settlement and of the tree update containing the note, together with an
owner-verified opening from the full viewing tier. It MUST NOT accept on an
aggregator's or payer's assertion, nor on an owner-unverified candidate.

#### Scenario: Aggregator asserts inclusion

- **WHEN** an aggregator reports a note as included but the wallet's chain read
  does not show it folded
- **THEN** the wallet MUST NOT accept it

#### Scenario: Candidate offered for acceptance

- **WHEN** an incoming-tier candidate, whose `cm` was not rechecked under the
  wallet's own `O_I`, is offered to acceptance
- **THEN** the wallet MUST NOT accept it

#### Scenario: Decoded discovery tag offered for acceptance

- **WHEN** an output whose discovery tag decodes to one of the wallet's invoice
  ids, or matches a tag the wallet expects, is offered to acceptance without an
  owner-verified opening
- **THEN** the wallet MUST NOT accept it
