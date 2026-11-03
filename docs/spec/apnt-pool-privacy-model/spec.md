# apnt-pool-privacy-model

## ADDED Requirements

### Requirement: Pool privacy claims carry their conditions

The privacy claims retain their complete existing adversary, assumption and exclusion statements. Registry/profile/key identity, fresh honest prover randomness and CRS well-formedness for each setup-backed layer are distinct conditions. The action CRS checker and release gate exist; the complete claims-check implementation and failing controls required by PS:205–228 are not found in the inspected code. Action CRS evidence supplies no wrapper CRS or wrapper zero-knowledge evidence. Where evidence is unestablished the precondition remains explicitly unestablished. Simulated setup leaves the project able to forge proofs and move pooled research coins; honest-prover privacy conditions do not repair that soundness failure. No production privacy or fund-security certification follows.


Pool privacy MUST be stated as follows, with conditions attached:

```text
payer          cannot compute the recipient's nullifier, recognize its
               re-randomized spend key, or decrypt its change; cannot tell
               which later spend is the recipient's among all notes folded
               before the root used -- CONDITIONAL ON single-use invoices, up
               to the disclosed epoch-collision residual, and the separate
               change branch
aggregator     sees public action records, proofs, signatures, discovery
               tags, a deposit's public inbox outpoint and network
               metadata only
participants   see public statements only; no cross-action equations exist
observers      see nullifiers, commitments, roots, re-randomized keys,
               signatures, packets, discovery tags, public deposits,
               withdrawals, fees and timing; equal discovery tags suggest
               outputs under one invoice's key and prove nothing, because
               any signer can copy a public tag and 8-byte tags also
               collide by accident, about 2^-64 per pair
anonymity set  every note folded before the root a spend uses -- CONDITIONAL
               ON actual pool usage; no set is claimed without measurement
custody        rests on proof soundness (see apnt-pool-settlement-custody)
```

The following are **cryptographic claims**, each with its adversary,
conditions and construction grounding. Their names identify claims for an
observer registry, not new wire fields or relation rules. They concern what
the named objects encode; they MUST NOT be presented as hiding deductions
from public boundary amounts, conservation, funding provenance, timing,
action grouping or outside knowledge ("Residuals are disclosed"). The shared
**condition `proof-zero-knowledge-v1`** applies to exactly
`commitment-hiding-v1`, `packet-hiding-v1` and
`signature-key-unlinkability-v1`: accompanying action and aggregate proofs
are zero knowledge of their private witnesses under their named profiles,
with fresh prover randomness and a well-formed, checked CRS for every
setup-backed layer. Its grounding is `apnt-pool-proof-system`, "Published
proofs carry an explicit zero-knowledge condition". The registry MUST retain
that condition, the CRS-check evidence binding and the setup-trust disclosure
beside each of the three claims. A transcript or key digest alone does not
establish CRS well-formedness. The current simulated single-party setup lets
the project forge proofs and break soundness; a well-formed CRS can still
support the conditioned zero-knowledge claim. Neither property establishes
the other, and no fund security or production privacy follows.

- **Claim `commitment-hiding-v1` — note commitments.** To a public-chain
  observer, or an honest-but-curious aggregator or relay receiving only the
  public action, proof, signatures and tags, `cm` computationally hides the
  private value and owner tag in its preimage and exposes no recipient
  identity through that encoding. **Conditions:** the adversary has neither
  the opening nor `K` or wallet/viewing material that derives it; `K` has
  secret, unpredictable 256-bit key material; the output uses the canonical
  `rcm = SHA-256("APNT-POOL-v1:rcm" ‖ K ‖ ρ)` and commitment, with the
  prescribed `ρ` index rule and domain separation. Settled outputs have
  distinct `ρ`; an identical candidate retry repeats its public commitment
  and is recognizable as such. The shared `proof-zero-knowledge-v1`
  condition (zero knowledge, well-formed checked CRS and disclosed setup
  trust) also applies. **Grounding and assumption:**
  `apnt-pool-note-statement` "Pool notes are commitments, not tokens" and
  "Nullifiers are owner-secret and unique by construction"; `design.md`,
  "Canonical encodings", "Note" and "Output `rcm` is derived (pad16)".
  Hiding rests on SHA-256 behaving as a pseudorandom function on secret-key
  inputs and as a random oracle for the salted commitment, not on collision
  resistance alone. A payer that made this note knows its opening; a
  delegated prover given it also knows it. This claim covers neither party
  for that note and does not promise that a boundary note's value cannot be
  inferred from public arithmetic.
- **Claim `packet-hiding-v1` — encrypted value packets.** To the same
  public-only adversaries without the target output's `K`, the fixed-length
  16-byte pad16 packet computationally hides `v`; it encodes no recipient
  identity, invoice id or input-to-output correspondence. **Conditions:**
  secret, unpredictable `K`, canonical
  `d = SHA-256("APNT-POOL-v1:pad" ‖ K ‖ ρ ‖ cm)` and
  `packet = (u64le(v) ⊕ d[0..8)) ‖ d[8..16)`, with the output's own `cm`
  included. One digest pads one plaintext, including across candidates
  sharing `K` and `ρ`: different values have different `cm` absent a hash
  collision; identical retries repeat both `cm` and packet. The shared
  `proof-zero-knowledge-v1` condition (zero knowledge, well-formed checked
  CRS and disclosed setup trust) also applies. **Grounding and
  assumption:** `apnt-pool-note-statement` "Canonical encodings are fixed" and
  "Actions are fixed-shape and self-contained"; `design.md`, "Canonical
  encodings", "Packet (pad16)". SHA-256 on the secret-key input must yield
  a pseudorandom digest whose revealed check half does not disclose its pad
  half, with collision resistance for the commitment binding. This is a
  computational pad, not information-theoretic encryption or an AEAD/MAC.
  The 64-bit key check is a trial filter, not acceptance. Only settled,
  proven actions may be opened; integrity comes from the relation, signatures
  and statement binding. An invoice holder, including a payer or interceptor,
  has `K_I` and can read every packet under that invoice's key. Payer hiding
  of the recipient's later change requires distinct single-use invoices
  (subject to the disclosed epoch-collision residual) and the separate
  `ρ`-derived change branch (`apnt-pool-receive-recovery`, "Invoices are
  single use and change is private", "Change keys derive from each output's
  public ρ" and "Packets have one fixed format"). Viewing-key holders and
  delegated provers given `K` are outside the claim for those packets.
- **Claim `signature-key-unlinkability-v1` — signatures and spend keys.**
  To a public-chain observer, a payer of the consumed note, or an
  honest-but-curious aggregator or relay holding only public submissions,
  a slot's BCH Schnorr signature under `rk` does not identify the underlying
  `ak` or link independently randomized spends to one underlying spend key.
  **Conditions:** each independent spend uses a fresh, secret, independently
  uniform `α` in the allowed scalar range, rejecting an infinity `rk` or zero
  `rsk`; secure Schnorr nonce generation under `rsk`, without nonce reuse or
  owner-specific metadata; neither `α`, spend secrets nor a witness that
  identifies `ak` is disclosed to that adversary. The shared
  `proof-zero-knowledge-v1` condition (zero knowledge, well-formed checked
  CRS and disclosed setup trust) also applies. **Grounding and assumption:**
  `rk = SEC1c(ak + α·G)` and `rsk = (ask + α) mod n_G` in
  `apnt-pool-note-statement` "Spend authority stays with the owner" and its
  "Two spends under one invoice" scenario; `design.md`, "Authorization".
  The claim rests on the independent additive masks and secure native BCH
  Schnorr over secp256k1 under the discrete-log assumption. The signature is
  public authorization, not encryption: it binds the public `rk` to the
  public action and discovery tags, and hides neither that association nor
  a withdrawal destination. The same signed candidate copied or retried is
  recognizable; negligible accidental key equality is not ruled out. A
  delegated prover holding `ak` and `α` can undo the mask and is outside this
  claim, even though it lacks spend authority. Fresh masks do not conceal
  repeated invoice tags or the other disclosed residuals.

**Conditions are not observations.** A chain-only observer cannot establish
key secrecy, mask freshness, invoice single use or the absence of private
disclosures. A claims registry MUST retain the adversary, all conditions,
grounding, assumptions and exclusions beside each claim and MUST label it
conditional, never measured hiding. A detector or statistical test is a
regression check, not a proof of cryptographic indistinguishability.

**Freeze boundary.** These claims document the existing construction for the
coming ARCH-267 freeze. They change no relation, statement, format or pin.
Operational rules below govern funding practice and disclosure, not consensus
validity. A claimed property requiring a construction or frozen-contract
change MUST be reported as blocked, not obtained by editing that contract.

The freeze records a dated status for each residual: public boundary arithmetic, shape, fees and timing; action grouping; root age; range/root-copy growth; invoice repeats, copies and collisions; invoice expiry timing; viewing-key compromise; rho-family disclosure; cloned-store/RNG risks; scan misses; cancellation assumptions; and funding ancestry. The wallet and Ink disclosures currently promise deep-scan or targeted-rescan recovery that the shipped command surface does not offer, while the host labels its capped prefix perEpochWindow. This is an unmet current disclosure obligation, not a reason to remove the target recovery commands or their required limits. LIMITS and the release README must carry the applicable limits with their actual implementation status. The bounded ancestry helper does not establish procedure-wide compliance, complete owner attribution, or the specified small-count/differencing policy. No achieved anonymity set is claimed.


#### Scenario: Commitment claim loses a condition

- **WHEN** a claims-registry test renders `commitment-hiding-v1` for a
  commitment, including a public deposit and a candidate retry
- **THEN** it MUST retain the public-only adversary, secret-opening and `K`
  conditions, the prescribed `ρ` rule and domain separation, SHA-256 hiding
  assumptions and the shared `proof-zero-knowledge-v1` condition, including
  action and aggregate zero knowledge, fresh prover randomness, well-formed
  checked CRS, evidence binding and setup-trust disclosure, construction
  citations, retry equality and public-arithmetic exclusions
- **AND** the text check MUST fail on each control that drops one of those
  conditions or exclusions, substitutes collision resistance alone, or says
  the creating payer cannot know the value

#### Scenario: Packet claim loses its key-holder exception

- **WHEN** a claims-registry test renders `packet-hiding-v1` for a packet
- **THEN** it MUST retain the public-only adversary without `K`, the canonical
  `cm`-bound pad and assumption, the invoice-holder and viewing/delegation
  exceptions, the single-use and separate-change conditions, and the
  distinction between a key check and acceptance, and the shared
  `proof-zero-knowledge-v1` condition, including action and aggregate zero
  knowledge, fresh prover randomness, well-formed checked CRS, evidence
  binding and setup-trust disclosure
- **AND** the text check MUST fail on each control omitting one of those
  conditions or claiming AEAD integrity, hidden retries or hiding from the
  invoice's payer

#### Scenario: Signature claim applied to a witness holder

- **WHEN** a claims-registry test renders `signature-key-unlinkability-v1`
- **THEN** it MUST retain the fresh secret mask and secure signing conditions,
  construction and assumption, public authorization and repeated-candidate
  exclusions, the delegated-witness exception, and the shared
  `proof-zero-knowledge-v1` condition, including action and aggregate zero
  knowledge, fresh prover randomness, well-formed checked CRS, evidence
  binding and setup-trust disclosure
- **AND** the text check MUST fail on controls dropping each condition or
  claiming key unlinkability against a prover holding `ak` and `α`; a model
  test MUST recover `ak` as `rk − α·G` when given `α`, and MUST detect repeated
  keys in a control that reuses one `α` for the same `ak`

#### Scenario: Packet candidate-reuse detector is validated

- **WHEN** a model test uses one `K` and `ρ` for two candidates with distinct
  values and their corresponding commitments
- **THEN** the canonical packets' value halves MUST NOT have XOR equal to the
  values' XOR in that fixture, and the same detector MUST fire on synthetic
  control packets derived without `cm`; identical retries MUST reproduce the
  same packet, and a holder of `K` MUST recover the value
- **AND** neither this finite fixture nor a byte-absence scan MAY be reported
  as proof of amount hiding

#### Scenario: Anonymity claimed on Chipnet

- **WHEN** a report claims an anonymity set from a Chipnet run with few notes or
  one operator
- **THEN** it MUST be corrected to describe the construction, not an achieved
  set

### Requirement: Residuals are disclosed

The following MUST be disclosed as public or residual:

- boundary deposit and withdrawal amounts;
- fees and timing;
- root age, reduced by the newest-root and staleness rules;
- action grouping of nullifiers and commitments;
- two permanent range records per action, dummies included, and `K` root
  copies per fold;
- network origin of submissions, reduced by the anonymizing-network default;
- a self-settled batch of one action as a thinner timing cohort;
- an invoice paid more than once: every payment to it carries the same
  discovery tag, so anyone can see that those outputs likely pay one
  recipient, though not who the recipient is, the amounts, or who paid
  (HUM-75). A signer can also copy any public tag onto its own output, and a
  recipient chooses the tags of payments to it and can repeat one across its
  invoices, so an equal pair of tags may be a copy or a repeat and never
  proves a shared invoice. Two unrelated outputs' 8-byte tags are also equal
  by accident with probability about `2^-64` per pair: at most
  `n(n − 1)/2^65` among `n` outputs of a deployment, about `2.7·10^-8` at a
  million and about 0.39 at the tree's `2^32 − 1` leaves;
- a deposit's funding (HUM-104; `apnt-pool-settlement-custody`, "Deposits
  enter through a record-keyed pool inbox"). The funding transaction is
  ordinary BCH, so its source addresses, change, `W` and time are public.
  When a settlement spends the inbox, its redeem publishes `D`, which links
  the funding outpoint publicly to the new note's `cm_0`, `packet_0` and
  `rk_0`, and through the funding transaction to the depositor's transparent
  source. The note's later spend publishes a nullifier, not `cm_0`. Under the
  design assumptions there is no direct public commitment-to-nullifier map;
  matching amounts, timing and a small pool can still correlate the deposit
  with a later withdrawal. No achieved anonymity set is claimed;
- a deposit's refund, which publishes the refund branch, the abandoned
  record's `D`, the `rk_0` signature and the refund's destination, all
  linked to the funding outpoint. After a refund anyone can re-fund that
  public lock at their own expense, so the abandoned `cm_0` and `rk_0`
  appear again; the wallet's fresh counter only stops the wallet itself
  from repeating them. An unsettled deposit waits 1,008 blocks, about a
  week, before it can be refunded;
- batch funding provenance, in three classes: **shared deposit/batch
  transparent ancestry** under `funding-ancestry-v1` (`D = 2`), including
  different outputs of one parent funding
  a deposit and the batch's verifier graph; **participant-funded batch**, in
  which a participant's transparent wallet supplies batch funding; and
  **aggregator coin chaining**, in which funding or change from one batch is
  spent to fund another batch. Ancestry through verifier-graph funding,
  verdict and settlement inputs can expose these relationships even when
  no source address bytes appear in the settlement. They link transparent
  funding to a batch, or batches to each other, not by themselves a hidden
  consumed note, its recipient or the individual output amounts. Combined
  with boundary amounts, conservation and outside attribution, they can
  narrow a cohort or allow conditional totals to be deduced; blanket amount
  or payer unlinkability MUST NOT be claimed;
- boundary correlation. A deposit and a later withdrawal of about the same
  amount, close in time, can be linked, and funding one deposit from several
  transparent addresses links those addresses. The wallet defaults of
  ARCH-278 reduce this and do not remove it. They are deposit to self only,
  one transparent source per deposit, the standard fee, an optional split
  into standard denominations with independent delays, and a warning before
  a withdrawal close to an amount deposited within about 144 blocks. A split
  helps only as far as other users deposit the same amounts in the same
  period.

<a id="funding-ancestry-v1"></a>

**Definition `funding-ancestry-v1` — bounded transaction ancestry.** A
procedure MUST declare its deployment, batch set and deposit set. A deposit
source coin is any input outpoint spent by the transaction funding that
deposit's inbox; the inbox output itself is not the source coin. A batch
graph coin is any input outpoint external to that graph spent to fund it,
including every input of a multi-input funding transaction. The
funding transactions and these outpoints MUST be resolved from public bytes,
not addresses or ownership labels.

For a coin `c`, depth 0 is the transaction that creates `c`. Depth `d` is
`d` hops back through transaction input parents. The node set is transactions
only, identified by txid; addresses and output indexes are not ancestor
nodes. Define `A_D(c)` as the set of those transactions reachable in at most
`D` hops, including depth 0. Follow every input parent, including parents
through pool settlements, and stop at coinbase transactions or the bound.
Deduplicate txids and use the shortest hop distance when a node is reached
by more than one path. Version 1 fixes `D = 2` on each side, not a sum of
the two distances. This checks the creating transaction, its parents and
its grandparents, covering immediate shared funding and short consolidation
paths while bounding reads. Unbounded ancestry eventually converges even for
otherwise unrelated coins; this rule makes no claim beyond `D`. The bound
is an operational policy, not a measured deanonymization threshold.

A batch graph coin `g` **shares a transparent ancestor** with a deposit
source coin `s` exactly when `A_D(g) ∩ A_D(s)` is nonempty. Two outputs of
one transaction therefore share depth 0, even at `D = 0`. A deposit/batch
pair is counted once if any graph coin of that batch shares with any source
coin of that deposit, regardless of how many coins or ancestors match.
Every graph coin MUST be compared with every source coin of every deposit
in the same declared procedure, not just deposits in that batch. For an
observer report the procedure comprises the batches settled in its declared
chain range and the deposits consumed by those batches. Deposit-source and
graph-funding ancestry reads MAY extend before that range. Refunds,
never-settled inboxes and deposits outside that set are outside this
measurement and MUST be disclosed as such.

**Operational rule — batch funding.** Before funding, the procedure's plan
MUST include every deposit source coin already used or planned for that
procedure. A batch funder MUST refuse a graph coin sharing an ancestor with
any of those sources under `funding-ancestry-v1`, and MUST refuse to certify
compliance if any required outpoint or parent through `D = 2` is missing.
Adding a deposit to the plan requires rechecking earlier graph funding;
a previous result is not compliance for the expanded procedure. A complete
check with no overlap MAY report only "no shared transaction ancestor within
`D = 2` for the declared procedure", never unrelated coins or unbounded
disjointness. Separate outputs, addresses or transactions alone do not
establish this result. Settlement compensation MAY fund a later graph only
if the same check passes; it has no exemption, and a shared ancestor within
`D` is a violation as well as a disclosed chaining residual. Chaining whose
shared deposit ancestry lies beyond `D` can pass and remains a residual.
This rule adds no covenant check and does not invalidate a settled action.

**Reporting rule — funding provenance.** Public reports MUST use counts by
the three classes, never per-user links, wallet labels, funding-to-user
pairings or likelihoods. They MUST state the chain range, ancestry depth and
coverage, unit and denominator of each count, and any unmeasured cases; an
unmeasured case MUST NOT be counted as zero. Shared ancestry counts use
deposit/batch pairs with denominator equal to the number of declared deposits
times the number of declared batches; participant-funding and chaining counts
use batches with denominator equal to the number of declared batches.
The classes can overlap and MUST NOT be added as disjoint populations.
Chain evidence can establish ancestry and funding locks, not who owns them
or whether an owner is a participant. A chain-only observer MUST report the
participant-funded class as not measurable when it has no chain-grounded
participant attribution; it MUST NOT import wallet files, run logs or private
labels to fill that gap. Shared-ancestry checks and counts MUST cite
`funding-ancestry-v1` and state `D = 2`, the procedure's batch/deposit sets
and whether every required parent was read. A partial read can prove a
found overlap but cannot prove its absence; counts with missing reads MUST
be labelled lower bounds with the unmeasured pairs stated.

Known participant-funding counts derived from private labels MUST stay in
private reports unless the publication rules permit a separate, labelled
operator statement for an isolated deployment. They MUST never enter the
chain-only observer's model. Such a public statement MUST use the observer's
same minimum-cohort parameter `N_min`, a positive integer whose value the
operator decides later, and MUST suppress the count while `N_min` is unset.
For a declared cohort of `b` batches and a private-label class count `c`,
publication requires both `c ≥ N_min` and `b − c ≥ N_min`; otherwise the
count, fraction, percentage and any equivalent total MUST be suppressed,
with only "suppressed by the small-count rule" shown. This includes zero
counts and all-batches counts, which can attribute individual batches by
elimination. Subcohorts, overlapping reports or totals MUST NOT be released
when differencing them reveals a suppressed count or a per-batch/private-user
label. Meeting the threshold permits only an aggregate disclosure, not
per-user links or ground truth about a deployment other users use.

These wallet-side limits MUST also be disclosed, in the wallet's user-facing
text and backup guidance and in `LIMITS.md`:

- invoice ids come from random 40-bit epochs that every store of a seed draws
  for itself, excluding the epochs it knows (HUM-77). A draw can still equal
  another store's epoch that the drawing store does not know: typically one
  whose invoices are all unpaid, or one another device is drawing at the same
  moment. Two payers then hold one invoice key and can read each other's
  packets. The probability is at most about `2^-40` for each pair of draws by
  different stores of the seed in which neither knows the other's epoch,
  summed over the seed's life in the deployment (`apnt-pool-receive-recovery`,
  "Invoice ids pair a random epoch with a sequential index"). Draws need the
  operating system's secure random generator. A device whose generator state
  is cloned, such as a restored virtual-machine snapshot, can repeat an epoch,
  and the bound does not cover it;
- restoring all wallet files together (state and journal) from an earlier
  copy, outside the restore command, is caught only by the session rule: the
  copy's next issuance opens a fresh epoch, so the copy reuses an invoice id
  only through the residual above. Its action counters can repeat the
  original's, which the range records refuse: a liveness failure. The restore
  command remains the only supported way to bring back an earlier copy;
- a full viewing key plus any one leaked per-invoice or per-output spend key
  yields every spend key of that branch;
- handing an action witness to a delegated prover discloses it, including the
  value, `rcm` and nullifier of every candidate in each change output's `ρ`
  family, the one that settles included;
- an invoice's expiry height `E_I` tells its payer when the invoice expires
  and bounds when the recipient issued it;
- a viewing-key holder decodes every payment tag to its epoch and index, and so
  learns when the wallet restored, started an issuing session or opened an
  epoch, and how many invoices each epoch issued;
- a recipient chooses the discovery tag of every payment to it. A malicious
  recipient can repeat a tag across its invoices or copy one from chain, and
  equal tags prove nothing;
- a payer that pays an invoice already paid, whether a second holder of a
  reused invoice, a payer skipping its duplicate check or a user who chooses
  to pay again after the check reports a verified prior payment, makes the
  repeated discovery tag above public. The check sees only settled, correctly
  tagged outputs, and a tag match that does not open under the invoice's keys
  never stops a payment;
- a payment whose payer wrote a wrong discovery tag is missed by routine
  decoding and by a seed-only restore. Only the per-epoch deep scan, in an
  epoch the wallet knows, or a targeted rescan with its payment id, in any
  epoch, finds it. An epoch whose only payments carry wrong tags is unknown to
  a seed-only restore;
- a full viewing key can fund notes to any invoice id, which burns those ids
  when found and, above the wallet's mark in its current epoch, closes that
  epoch. Its holder can also form invoices under the wallet's keys without the
  wallet, and a payer of such an invoice and a later payer of the same id from
  the wallet can read each other's packets. It can also settle a payment to
  the own invoice of one of the wallet's cancellations, whose id it can
  guess among the next indices of the wallet's current epoch. The cancel does
  not pause for that evidence, so the cancel's own invoice output then
  repeats that payment's discovery tag on chain (`apnt-pool-receive-recovery`,
  "A payer checks for a prior payment before paying");
- a payer's cancel keeps the recipient's per-epoch window complete only when
  it settles by `H_cancel + L_settle`. A cancel whose fee is below what the
  aggregators it reaches require (an **under-fee cancel**, whether its fee was
  capped in advance or fees rose), whose first anchor attempt runs out, whose
  payer was offline or without the anonymizing network at `H_cancel`, or
  which every submission path withholds, can settle later or never. A
  withheld payment can then settle at or above `E_I + grace` and is late.
  Decoding still finds it if it is correctly tagged. If it is mis-tagged, the
  per-epoch window can miss it, though not merely for being late, and then
  only the targeted rescan with the payment id its payer reports, or the
  per-epoch deep scan in an epoch the recipient knows, finds it
  (`apnt-pool-receive-recovery`, "Invoices expire and payers honor the
  expiry").

The freeze records a dated status for each residual: public boundary arithmetic, shape, fees and timing; action grouping; root age; range/root-copy growth; invoice repeats, copies and collisions; invoice expiry timing; viewing-key compromise; rho-family disclosure; cloned-store/RNG risks; scan misses; cancellation assumptions; and funding ancestry. The wallet and Ink disclosures currently promise deep-scan or targeted-rescan recovery that the shipped command surface does not offer, while the host labels its capped prefix perEpochWindow. This is an unmet current disclosure obligation, not a reason to remove the target recovery commands or their required limits. LIMITS and the release README must carry the applicable limits with their actual implementation status. The bounded ancestry helper does not establish procedure-wide compliance, complete owner attribution, or the specified small-count/differencing policy. No achieved anonymity set is claimed.


#### Scenario: Matching deposit and withdrawal

- **WHEN** a deposit of X and a later withdrawal of X occur close together
- **THEN** documentation MUST NOT claim they are unlinkable

#### Scenario: Deposit described as unlinked from its funding

- **WHEN** a document says a deposit's new note is unlinked from its funding
  transaction or its depositor's transparent addresses
- **THEN** it MUST be corrected: the settled inbox publishes `D`, linking the
  funding outpoint to the note's `cm_0`. Under the design assumptions there is
  no direct public map from `cm_0` to its later nullifier, but amount, timing
  and a small pool can correlate the deposit with a later withdrawal

#### Scenario: Refund described as private

- **WHEN** a document says an inbox refund reveals nothing
- **THEN** it MUST be corrected to state that the refund publishes the
  abandoned record's `D` and its destination, and that anyone can re-fund
  the public lock afterwards

#### Scenario: Shared parent hidden by separate funding outputs

- **WHEN** a model-chain fixture spends different outputs of one
  non-palindromic transparent parent to fund a deposit and a batch verifier
  graph, then follows the graph's verdict into settlement
- **THEN** `funding-ancestry-v1` MUST find the shared parent at depth 0 of
  both source coins; the provenance test MUST count that deposit/batch pair
  once and the funding-policy check MUST refuse it; the same detector MUST
  distinguish an unrelated-parent control and MUST fire when only address-byte searches
  would have missed the shared ancestor
- **AND** substituted wrong-parent, wrong-output-index and display-order
  bytes at a wire-order input MUST fail their outpoint checks

#### Scenario: Bounded ancestry has a complete and an incomplete control

- **WHEN** a synthetic procedure includes multi-input funding and one
  deposit source sharing an ancestor with a graph coin at depths 2 and 1,
  another pair sharing only at depth 3, and settlement compensation funding
  a later graph
- **THEN** the check MUST compare every source and graph coin, reject the
  within-bound match, exclude the depth-3-only match from the `D = 2` count,
  and test compensation by the same predicate, counting chaining separately
- **AND** a complete no-match control MUST permit only the stated bounded
  result; removing a required parent at depth 1 or 2 MUST refuse compliance,
  and adding a planned deposit with a match MUST invalidate a prior pass

#### Scenario: Participant funding and batch chaining disclosed

- **WHEN** a labelled private model fixture has one participant-funded batch
  and a later batch spending the earlier batch's aggregator change coin
- **THEN** its private disclosure test MUST report one batch in each
  applicable class,
  allowing overlap, and MUST fail on controls omitting either class or
  publishing the participant label or funding-to-user pair
- **AND** the chain-only projection with the private labels removed MUST
  still count the chaining and MUST mark participant attribution not
  measurable, failing a control that reports zero participant-funded batches
  merely because it cannot identify participants

#### Scenario: Private-label small counts are suppressed

- **WHEN** a permitted isolated-deployment statement has a private-label
  participant-funding count `c` out of `b` batches
- **THEN** publication MUST suppress it if `N_min` is unset, `c < N_min`
  or `b − c < N_min`, including 1 of 1 and 0 of 1; only a cohort satisfying
  both bounds MAY publish the aggregate under the other publication rules
- **AND** controls publishing a suppressed count as a fraction, percentage,
  complementary total, difference of subcohorts or per-batch label MUST fail;
  the chain-only observer MUST refuse all private-label inputs regardless
  of the threshold

#### Scenario: Incomplete ancestry described as unrelated

- **WHEN** a provenance report omits a required parent within `D = 2`, or
  describes a complete `D = 2` check as proving no ancestry at any depth
- **THEN** its coverage check MUST mark missing within-bound reads unmeasured
  and refuse compliance, and MUST fail the unbounded-disjointness control;
  a complete no-match check establishes only the named bounded rule for the
  declared procedure, leaving deeper ancestry unmeasured

#### Scenario: Whole-wallet rollback

- **WHEN** a wallet's state file and journal are restored together from an
  earlier copy outside the restore command
- **THEN** documentation MUST NOT claim the wallet detects the copy, and a test
  MUST show that the copy's next invoice comes from a fresh epoch, and that
  without the session rule the same invoice id is issued again

#### Scenario: Epoch-collision residual understated

- **WHEN** documentation states the epoch-collision residual as zero, says that
  two devices of one seed always draw distinct epochs, or bounds it by counting
  only the epochs other stores have already issued in
- **THEN** it MUST be corrected to the draw-based bound, which counts every
  pair of draws by different stores in which neither knows the other's epoch,
  overlapping draws and epochs opened before their first invoice included

### Requirement: Discovery tags disclose nothing beyond a repeated invoice

Every output's 8-byte discovery tag is public (operator decision HUM-75,
2026-09-24). Under the v1 fill rules (`apnt-pool-receive-recovery`; HUM-77) a
payment's tag is `FF1-AES256(k_dt, I)` of its invoice id under the
recipient's secret `k_dt`, and a change or dummy tag is `dt(F, 0x00)` of a
wallet secret bound to the output's own `ρ`. An honest tag MUST reveal nothing
but equality: which outputs pay one invoice. Every change and dummy fill key is
bound to the output's own `ρ`, so in honest use no wallet rule makes two
settled change or dummy outputs share a tag, even when a wallet reuses an
action counter after a restore, and the payment tags of one wallet's distinct
invoice ids differ exactly. The one exception by construction is payments:
every payment to one invoice carries its `dt_I`, so an invoice paid more than
once shows its tag once per payment. That repeat publicly suggests that those
payments pay one recipient. It reveals no identity, amount, payer, epoch or
index, and it MUST be disclosed as a residual.

Tags are 8 bytes, so uniqueness is not exact. Two tags under different keys
are equal by accident with probability about `2^-64` per pair, and some two of
`n` tags in a deployment with probability at most `n(n − 1)/2^65`: about
`2.7·10^-8` at a million outputs and about 0.39 at the tree's `2^32 − 1`
leaves (`apnt-pool-receive-recovery`, "Every output's discovery tag follows
the v1 fill rules"). Such an equal pair is neither a repeated invoice nor a
copy. The ban on repeats that a rule produces, from a counter, an invoice id
alone or a reused fill key, is unaffected, and so is this requirement's claim,
which concerns repeats by construction.

A tag is also unauthenticated. Nothing checks that a tag belongs to its
output, so any signer can copy a public tag onto its own output, and a
recipient can put one tag into several of its invoices. Equal tags therefore
never prove a shared invoice, and no party MAY treat them as proof of payment
or of linkage. A copied tag reveals nothing new about the output it copies,
and it costs a recipient whose ids it decodes to one failed trial.

Documentation of tags MUST state:

- a discovery tag is not a reusable recipient marker. A payment tag is a
  pseudorandom-permutation value of one secret invoice id under the
  recipient's secret; a change or dummy tag derives from a wallet secret and
  the output's own `ρ`. Every tag is fixed-length on every output, real or
  dummy, and pseudorandom to everyone who holds neither `k_dt` nor its fill
  key;
- payment, change and dummy tags are indistinguishable, none can be recomputed
  from public data, and none depends on the value;
- to everyone without `k_dt`, a payment tag reveals no epoch, index, restore,
  session, epoch opening or issuance volume, and two payment tags of one
  wallet are unrelated;
- a holder of an invoice, the payer or anyone who intercepted it, recognizes
  that invoice's payment by its tag, as it already could by trial decryption,
  and learns nothing about the recipient's other tags. A holder of the
  incoming viewing key decodes every payment tag to its epoch and index;
- equal tags may be a reused invoice, a recipient's repeat, a copy or an
  accidental 64-bit collision, and never prove any of them. Accidental equal
  pairs grow with the square of the number of outputs, about `2^-64` per pair;
- an aggregator or relay also sees the tags of candidates that never settle.
  Two candidates paying one invoice from different inputs share a tag, so that
  party can link them;
- the claim rests on FF1-AES256 as a pseudorandom permutation and SHA-256 as a
  pseudorandom function. FF1's provable bounds are loose beyond about `2^20`
  tags per key, and above that the claim rests on cryptanalysis. Statistical
  tests detect gross patterns, not every distinguisher.

#### Scenario: Tag classes compared

- **WHEN** a test compares the tags of payment outputs, across epochs,
  restores and devices, with those of change and dummy outputs of a model chain
- **THEN** it MUST find no difference between the classes at its stated power,
  and it MUST fire on zero-filled dummy slots, on counter-derived tags and on
  invoice ids written in the clear

#### Scenario: Tag predicted from public data

- **WHEN** functions of an output's public data (`ρ`, `cm`, the packet,
  `deployment_id`) are tried as predictors of its tag
- **THEN** they MUST recognize no honest output, and the test MUST fire on a
  build that derives tags from `ρ ‖ cm`

#### Scenario: Tag depends on the value

- **WHEN** tags are tested for dependence on their outputs' values
- **THEN** the test MUST find none, and MUST fire on a build that writes a
  value-bucket byte into the tag

#### Scenario: Epochs linked by tags

- **WHEN** a test compares the leading equal bits of two payment tags of one
  epoch, of two epochs of one wallet, and of two recipients
- **THEN** it MUST find no difference, and it MUST fire on tags that XOR the
  invoice id with a key, show the epoch in the clear, or use one Feistel round

#### Scenario: Restore visible in tags

- **WHEN** a test compares the tags of each epoch's first invoices with later
  ones, and the tags of adjacent payments
- **THEN** it MUST find no difference, and it MUST fire on unencrypted invoice
  ids and on the epoch in the clear

#### Scenario: Repeated tags on a model chain

- **WHEN** a model chain includes invoices paid twice and dummy outputs under
  an action counter reused after a restore
- **THEN** the set of repeated tags MUST equal exactly the tags of the
  invoices funded more than once, checked by identity and not by count, up to
  accidental collisions, whose probability for the chain's `n` outputs, at
  most `n(n − 1)/2^65`, the test MUST state; and the test MUST fire on a build
  with a static change tag and on a build tagging dummy outputs
  `dt(K_d, 0x00)`

#### Scenario: Payer holding one invoice

- **WHEN** each payer of a model chain matches its own invoice's tag against
  every output
- **THEN** each MUST find its own payment and no other output, and the test
  MUST fire on a build whose payment tag is the invoice id in the clear, in
  which a payer predicts the recipient's next tags

#### Scenario: Tag uniqueness described as exact

- **WHEN** documentation says that honest change or dummy tags never collide,
  that every equal pair of tags is a repeated invoice or a copy, or that unique
  `ρ` values give unique tags
- **THEN** it MUST be corrected to state the accidental 64-bit residual, about
  `2^-64` per pair and at most `n(n − 1)/2^65` over `n` outputs, beside the
  ban on repeats by rule

#### Scenario: Tags described as hiding repeats

- **WHEN** documentation says discovery tags hide that an invoice was paid
  twice, or presents tags without the invoice-repeat residual
- **THEN** it MUST be corrected

#### Scenario: Equal tags presented as proof

- **WHEN** documentation, a wallet or a payer treats two equal tags as proof
  that two outputs pay one invoice, or a tag on chain as proof that an invoice
  was paid
- **THEN** it MUST be corrected, because a signer can copy any public tag onto
  its own output and a recipient can repeat one

### Requirement: Submission reveals no more than network metadata

Public single-action intake, chain collection and selected anchor/window checks exist. Reference Tor handoff and self-settlement APIs refuse as not implemented. The host defaults to requiring an anonymizing adapter; supported zero-value direct mode is an explicit metadata disclosure with no automatic fallback. It does not satisfy privacy-default egress. No complete anonymized self-settlement liveness path or measured production anchor/window policy is claimed. The all-wallet-egress anonymizing requirement and prohibition on note-keyed/tag-keyed queries remain; PLAN section 5 supplies no egress waiver.


An aggregator MUST accept self-contained single actions. No submission format
MAY group a participant's actions by owner.

In the privacy-default configuration every network egress of the wallet MUST go
over an anonymizing network (Tor). That covers:

- action submission to any aggregator;
- broadcast of a settlement or tree update the wallet assembled itself;
- chain reads.

Chain reads MUST fetch every confirmed pool-lock transaction through the read's tip.
The pending report comes from the same response, adds no query, and is never
inclusion or acceptance evidence (ARCH-310). Reads MUST NOT be keyed by
a value only the wallet knows, such as its nullifier, commitment, leaf
position or a discovery tag it expects. A wallet MUST NOT send a discovery
tag, its tag table, `k_dt`, a decoded invoice id, or any value derived from
them to any server: a server
without private information retrieval would learn exactly which outputs pay
the wallet. v1 has no private information retrieval, and tag matching is
local.

#### Scenario: Default submission over clearnet

- **WHEN** a wallet in its privacy-default configuration submits an action to
  an aggregator over a direct connection from the user's address
- **THEN** it MUST be treated as a privacy defect

#### Scenario: Self-settlement broadcast over clearnet

- **WHEN** a wallet in its privacy-default configuration broadcasts a
  settlement it assembled directly to relay peers from the user's address
- **THEN** it MUST be treated as a privacy defect, because relay peers see the
  origin as an aggregator would

#### Scenario: Note-keyed chain query

- **WHEN** a wallet asks a server about a specific nullifier, commitment or leaf
  position of its own
- **THEN** it MUST be treated as a privacy defect

#### Scenario: Tag-keyed server lookup

- **WHEN** a wallet or payer asks a server which outputs carry a discovery tag
  it expects, or hands a server its tag table, `k_dt`, its change roots or
  `K_I`
- **THEN** it MUST be treated as a privacy defect

#### Scenario: Multi-action submission by one owner

- **WHEN** a submission format requires one message carrying several of one
  owner's actions
- **THEN** it MUST be rejected, because it groups actions by owner

### Requirement: Self-settlement is a liveness path with a stated resource cost

Public single-action intake, chain collection and selected anchor/window checks exist. Reference Tor handoff and self-settlement APIs refuse as not implemented. The host defaults to requiring an anonymizing adapter; supported zero-value direct mode is an explicit metadata disclosure with no automatic fallback. It does not satisfy privacy-default egress. No complete anonymized self-settlement liveness path or measured production anchor/window policy is claimed. The all-wallet-egress anonymizing requirement and prohibition on note-keyed/tag-keyed queries remain; PLAN section 5 supplies no egress waiver.


Self-settlement has three resource needs, and the design MUST state each:

- an aggregate proof over a batch containing the action;
- the on-chain ladder run for that batch;
- settlement assembly from the wallet's own chain read.

The 16 GB local-proving requirement covers only the action proof. The
aggregate prover's peak memory and time for pool children, including a batch
of one, MUST be measured before any wallet is described as able to
self-aggregate.

When aggregators decline, the user MUST be able to do either of the following
over the anonymizing network:

- hand its action to any other aggregator, including one on its own other
  hardware;
- aggregate it itself on hardware meeting the measured aggregate requirement.

#### Scenario: Self-aggregation claimed for a 16 GB wallet

- **WHEN** documentation says a 16 GB wallet can self-settle without a measured
  aggregate requirement that fits it
- **THEN** it MUST be corrected

#### Scenario: All known aggregators decline

- **WHEN** every aggregator a user knows declines its action
- **THEN** the user MUST be able to settle the same action, with the same proof
  and signatures, through another party or its own aggregation, with no
  permission from any aggregator

### Requirement: Anchors, staleness and submission windows follow a stated policy

Public single-action intake, chain collection and selected anchor/window checks exist. Reference Tor handoff and self-settlement APIs refuse as not implemented. The host defaults to requiring an anonymizing adapter; supported zero-value direct mode is an explicit metadata disclosure with no automatic fallback. It does not satisfy privacy-default egress. No complete anonymized self-settlement liveness path or measured production anchor/window policy is claimed. The all-wallet-egress anonymizing requirement and prohibition on note-keyed/tag-keyed queries remain; PLAN section 5 supplies no egress waiver.


The profile MUST fix these parameters from measured fold interval, proving time
and settlement time:

- `c_anchor`, the confirmation depth for anchors;
- `W_anchor`, the maximum anchor lag in folds;
- `T_window`, the random submission window;
- `R_retry`, the maximum re-proves;
- `P_fold`, the fold bounty.

The profile MUST satisfy `W_anchor · T_fold,median ≥ T_prove + T_window + T_settle`.

A wallet MUST:

- build each spend against the newest root it has verified with at least
  `c_anchor` confirmations;
- wait a uniform random delay in `[0, T_window]` before submitting;
- re-check the anchor immediately before submission;
- re-prove against the newest root if the anchor lags by more than `W_anchor`
  folds.

These steps form one **attempt**, and `R_retry` bounds the re-proves of one
attempt. After `R_retry` re-proves without a fresh-enough anchor, the wallet
MUST end that attempt and report it, and MUST NOT submit with a stale anchor.
Ending an attempt ends neither the action nor what the wallet still owes for
it. What follows is the action's own rule (`apnt-pool-receive-recovery`,
"Invoices expire and payers honor the expiry"):

- a payment MAY begin another attempt only as a resubmission that rule
  permits, below its `H_cancel`, and only after the check of "A payer checks
  for a prior payment before paying";
- a cancelling action MUST begin its next attempt at once: it re-proves the
  same journaled cancellation against the newest root, with a fresh random
  delay, and keeps doing so until one action settles. It MUST NOT submit with
  a stale anchor to settle sooner.

An ended attempt submits nothing, so it costs proving work and discloses
nothing on the network. `L_settle` covers one attempt. A cancel that needs a
second attempt can settle after `H_cancel + L_settle`, and the per-epoch
window's coverage of a withheld, mis-tagged payment then does not hold for
that payment, a residual that requirement discloses.

A wallet waiting on a received note MAY fold pending batches itself, and then
MUST fold every pending batch in order, not only its own.

Anchor lag is a privacy rule, not a validity rule. A settlement MUST accept any
authentic root as an anchor, spending one root copy per distinct anchor
(`apnt-pool-settlement-custody`). An aggregator MAY batch actions with
different anchors, and a wallet MUST NOT be required to re-prove because of the
anchors of other actions in its batch.

#### Scenario: Stale root chosen

- **WHEN** a wallet builds a spend against an older root although a newer
  verified root with `c_anchor` confirmations is available
- **THEN** the wallet MUST use the newest root instead

#### Scenario: Anchor goes stale during proving and the window

- **WHEN** more than `W_anchor` folds occur between construction and the end of
  the random window
- **THEN** the wallet MUST re-prove against the newest root before submitting

#### Scenario: Retries exhausted

- **WHEN** `R_retry` re-proves of one attempt have not produced a fresh-enough
  anchor
- **THEN** the wallet MUST end that attempt and report instead of submitting

#### Scenario: A cancel's attempt runs out

- **WHEN** an attempt of a cancelling action ends after `R_retry` re-proves
  without a fresh-enough anchor, while neither the payment nor the cancel has
  settled
- **THEN** the wallet MUST NOT submit it with a stale anchor, MUST report the
  ended attempt, and MUST begin the next attempt of the same journaled
  cancellation at once, with the same notes, slots, counter and own invoice
- **AND** a test MUST show that a wallet treating the ended attempt as the
  end of the cancel submits nothing more while a withheld payment settles at
  or above `E_I + grace`, and that a wallet submitting the stale-anchored
  proof is rejected

#### Scenario: Batch mixes anchors

- **WHEN** an aggregator's batch holds an action anchored to the newest root and
  another anchored one fold earlier
- **THEN** both MUST be able to settle together with one copy of each root,
  without either wallet re-proving

#### Scenario: Parameters that cannot converge

- **WHEN** measured proving time plus the window and settlement time exceed
  `W_anchor` times the median fold interval
- **THEN** the profile MUST be revised before deployment
