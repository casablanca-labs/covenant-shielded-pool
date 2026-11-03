# apnt-pool-operations-harness

## ADDED Requirements

Scope. The other eight pool capabilities specify what the pool is. This one
specifies the machinery that drives it:

- each role's entry points and holding boundary;
- the prove-to-settle pipeline and its hand-offs;
- the environments and the live-evidence boundary;
- the test harnesses;
- the proving discipline.

It is the specification that tasks.md section 8 (live validation) runs
against, and it covers MVP-PLAN items 5, 6 and 7. It adds no protocol rule.
Where it restates a custody, privacy or acceptance rule, it names the owning
requirement. On any conflict the owning requirement governs, and the conflict
is reported.

Current state. Every requirement ends with a measured state:

- **implemented**: the code is on main with deterministic tests that exercise
  it. This never means it has run on its live path;
- **partial**: part of it is on main, or it exists only on an unmerged lane,
  or it is on main but has never run on its live path;
- **missing**: no code on main or on any lane.

The states were measured on 2026-09-27 at main `47ba43b3` by reading the
files each state names. The lanes are cited at their heads that day:

- `pool-multiparty-sim`, head `c6ee3cfe` (historical-record);
- `pool-chipnet-smoke`, head `4b6c6d57` (historical-record, historical-record);
- `pool-inbox-spec`, head `bcd346a8` (historical-record);
- `pool-wallet-self-deposit`, head `8d18fc65` (historical-record, historical-record).

These labels are a historical snapshot, not a claim about later main. No tool
re-measures them automatically.

Delta on main, measured at `c9ef580e` on 2026-09-27: `eaf0847c` and
`74db13bd` added and tested wallet self-deposit construction, journalled
`0x41` signing and authenticated signing history; that depositor-input route
is superseded for v1 deposits. `30b86c22` through `a443986e` placed the P0
simulation harness, two-channel boundary, host precondition and reviewed P0
record on main, while its L2 deposit and other lifecycle steps remain
placeholders. `4f55c619` through `5da8e77c` placed the record-keyed inbox
covenant, revision-2 genesis code pin, local-VM and refund tests on main;
wallet inbox funding and aggregator inbox intake are still absent. `c9ef580e`
adopted the reviewed chain-io collector in the P0 simulation and tested its
loopback network refusal. None of these commits demonstrates an historical-record gate
pass, a live pool settlement or wallet acceptance on Chipnet.

The deposit hand-off belongs to the record-keyed inbox delta (historical-record,
operator decision historical-record). At the measured base `47ba43b3` that delta is on lane
`pool-inbox-spec`, not on main. This capability cites its requirements by name
and does not restate them.

### Requirement: Harness requirements defer to the protocol specs and carry a measured state

This capability MUST NOT introduce, relax or reinterpret any protocol, custody,
privacy or acceptance rule. Where a harness requirement touches one, it MUST
name the owning requirement.

A requirement's current state MUST be measured from the repository, from the
files it names, and never copied from a report, a brief or a task note:

- code that exists only on an unmerged lane MUST be reported as **partial**,
  with its branch and head;
- code on main that has never run on its live path MUST NOT be reported as
  live;
- a state MUST NOT be raised on the strength of a review of a different
  commit.

Historical state before the M1 reconciliation: **implemented** for this document. Every state below was
measured on 2026-09-27 as the preamble describes. No tool keeps them current.

Current state at 705bd169 is the source-status inventory OH-1 through OH-34 in the M1 R2 reconciliation, with the PS-5 and B9 scope corrections in R3. Source presence is not runtime acceptance. The 47ba43b3/c9ef580e states remain dated history. Current descriptions must include the implemented read/inbox/live-bN/factory/fold/broadcast/evidence stages and their stated limits. A changed source status never closes a task: each remaining gap retains the binding below and requires remeasurement under that item, or an explicit operator rescope. Deferred obligations keep their binding and scope authority. Do not append an undated contradictory snapshot or infer closure from a registry comment.


#### Scenario: Harness rule conflicts with an owning requirement

- **WHEN** a requirement here and a requirement of another pool capability
  disagree
- **THEN** the other capability's requirement governs, the disagreement MUST be
  reported to the orchestrator, and neither text MAY be edited silently to
  agree

#### Scenario: State copied from a report

- **WHEN** a requirement's state is taken from a report or brief without
  reading the named files at the stated commit
- **THEN** it MUST be corrected to the measured state, and the correction
  recorded

### Requirement: Each role has a declared holding boundary

Every role that operates the pool MUST expose only the operations and hold only
the material this table allows. The last column names where each rule is
owned; this table restates those rules and adds none.

| Role | Operations | May hold | Must never hold | Owning requirements |
|---|---|---|---|---|
| Wallet | create or restore its store; read the chain; issue invoices; build, sign and prove its own action; fund its own deposit inbox; submit; fold; accept; withdraw | its seed, wallet root, spend and nullifier keys, openings, witnesses, store and acceptance state | another party's secret, opening or witness; any caller-supplied inclusion, membership or acceptance assertion treated as evidence | `apnt-pool-note-statement` "Spend authority stays with the owner"; `apnt-pool-receive-recovery` "Wallet results are classed by where they may go" and "Acceptance stays with the wallet" |
| Aggregator | take public actions; select records, copies and coins; assemble and rebuild settlements; request the aggregate proof; run the verifier graph and factory; broadcast | public records, child proofs, owner signatures, discovery tags, inbox outpoints, its own chain read, keys for its own fee funding | any seed, `ask`, `rsk`, `nk`, opening, witness, invoice id, epoch or refund authority; any power to accept for a wallet, sequence users or stop another party's settlement | `apnt-pool-settlement-custody` "No authority can pause, veto or redirect"; `apnt-pool-privacy-model` "Submission reveals no more than network metadata"; historical-record "Deposit admission protects liveness, not custody" |
| Action prover | prove one action | the wallet itself. A delegate exists only under a labelled privacy disclosure, and then holds one slot's `proverDelegable` witness | `ask`, `rsk`, the seed or a wallet root | `apnt-pool-proof-system` "Proving is local and within consumer hardware"; `apnt-pool-receive-recovery` "Wallet results are classed by where they may go" |
| Aggregate prover | prove the aggregate of one statement, then wrap it | the deployment id, the statement's public records and their child proofs, and the pinned ELF, program key and allowlisted `vp` | any witness, opening or spend authority; a verifying key, public-input scalar, run binding or acceptance flag supplied by a requester | `apnt-pool-proof-system` "The child proof system is a profile parameter" |
| Deployer | build and broadcast the pool genesis and the verifier-graph funding; publish the deployment artifact | its bootstrap funding key and the public artifact | any wallet's seed or note material; any token or capability that outlives genesis outside the audited covenants | `apnt-pool-nullifier-range-records` "Genesis is exact and its whole category supply is audited"; `apnt-pool-settlement-custody` "No setup holder guards pooled value" |
| Chain server and message relay | answer reads; relay messages | network metadata: connection, query bytes, order and timing | no party MAY send it a query keyed on a value only one wallet knows (`nf`, `cm`, a leaf, an expected tag) | `apnt-pool-privacy-model` "Submission reveals no more than network metadata" |
| Test-harness operator | launch its own simulated parties, seed its own simulated wallets, run the ledger, transport and checker | seeds of its own simulated wallets, only as the disclosure checker's ground truth | an independent outside tester's seed, spend authority, opening or witness; a party's role: it MUST NOT pass any party another party's bytes except through the two channels | "The multi-party gate confines each party to two channels"; "The outside tester completes a wallet-owned Chipnet lifecycle" |

Historical state before the M1 reconciliation: **partial**.

- **Wallet.** The payer's signer is a private function of its journaled build
  (`packages/reference-wallet/src/apnt_pool_wallet_payer_v1.ts`). Result classes
  are tested (`packages/reference-wallet/test/apnt_pool_wallet_results_v1.test.ts`).
  The package exports only its root and one seal-era subpath. Task 4.1 records
  one open item here: some exports still return `ask` (historical-record).
- **Aggregator.** Intake takes public data only and refuses unknown outer
  fields (`packages/reference-aggregator/src/apnt_pool_intake_v1.ts`).
- **Aggregate prover.** The live input schema has no field for a witness, key,
  scalar or flag, and extra fields are refused
  (`tools/apnt-pool-aggregate-sp1/LIVE-INPUT.md`).
- **Deployer.** Exists only on lane `pool-chipnet-smoke`
  (`tools/pool-chipnet-smoke/deployment.mjs`). It keeps its funding key under
  the main checkout's `.local-live/`.
- **Test-harness operator.** The P0 launcher is on main at `c9ef580e`; its
  seed permission applies only to the operator's own simulated wallets, never
  to an independent tester.

#### Scenario: Aggregate prover offered a witness or a key

- **WHEN** a request to the aggregate prover carries a field for a witness,
  opening, verifying key, public-input scalar, run binding or acceptance flag
- **THEN** the prover MUST refuse it with a named cause before any SP1 step

#### Scenario: Intake asks for refund or spend authority

- **WHEN** an aggregator's intake format carries or requests `rsk`, `ask`, a
  seed, or refund authority for a deposit inbox
- **THEN** it MUST be rejected, as historical-record's "Intake asks for refund
  authority" scenario requires

#### Scenario: Aggregator result offered as acceptance

- **WHEN** a wallet is handed an aggregator's statement that a note was
  included or accepted
- **THEN** the wallet MUST NOT treat it as evidence, and acceptance MUST come
  from the wallet's own chain read

#### Scenario: Harness operator passes a hint

- **WHEN** the harness writes into a party's directory anything other than its
  allowlisted bootstrap files
- **THEN** the multi-party gate MUST fail

### Requirement: Role entry points are declared executables

Bins exist in pool-wallet-host, pool-wallet-ink and pool-aggregator-service; the reference wallet/aggregator remain libraries. The aggregator service bin is a local health/status/metrics daemon only, not an intake, scheduler, prover, assembler, broadcaster or settlement command. The development harness uses workspace siblings and external generator defaults. Complete install/reproduction from a fresh account with the generator absent remains unverified; the withdraw module is pending. Phase 3’s integration-library/cross-wallet deferral does not defer release install and reproduction instructions.


The pool wallet and the aggregator MUST each be reachable through a `bin`
entry declared in its package manifest. Every operation that "Each role has a
declared holding boundary" gives the wallet or the aggregator MUST be reachable
through declared entry points alone. That includes the fold, which any party
may run.

An entry point:

- MUST NOT contain or read an absolute filesystem path;
- MUST NOT load code or data from a sibling checkout, or from any path outside
  its installed package and the user's own data directory;
- MUST NOT need the external verifier-graph generator. The verifier-graph
  record, its variant map and the factory ship as committed, digest-pinned
  artifacts.

Each package README MUST state its hardware floor ("The hardware floor is
stated per role and kept apart from the development gate"). The tree MUST carry
MVP-PLAN item 5's `LIMITS.md`.

The acceptance test is MVP-PLAN item 5's gate. A fresh user account installs
from the candidate tree and invokes only declared `bin` entries, with the
external generator absent from its PATH. It then produces a valid pool
submission: its actions with their proofs, encrypted packets and
spend-authorization signatures.

The freeze records a dated status for each residual: public boundary arithmetic, shape, fees and timing; action grouping; root age; range/root-copy growth; invoice repeats, copies and collisions; invoice expiry timing; viewing-key compromise; rho-family disclosure; cloned-store/RNG risks; scan misses; cancellation assumptions; and funding ancestry. The wallet and Ink disclosures currently promise deep-scan or targeted-rescan recovery that the shipped command surface does not offer, while the host labels its capped prefix perEpochWindow. This is an unmet current disclosure obligation, not a reason to remove the target recovery commands or their required limits. LIMITS and the release README must carry the applicable limits with their actual implementation status. The bounded ancestry helper does not establish procedure-wide compliance, complete owner attribution, or the specified small-count/differencing policy. No achieved anonymity set is claimed.


Historical state before the M1 reconciliation: **missing**.

- **No `bin` entry.** None of the six package manifests declares one (measured
  over `packages/*/package.json`).
- **No pool commands.** `packages/reference-cli/src` has no pool command.
- **Generator dependency.** The graph record and variant map are committed
  (`tools/pool-onetx-verifier-prototype/pool-key/`). Regenerating them still
  goes through `tools/pool-onetx-verifier-prototype/scripts/setup-scratch.mjs`,
  whose defaults are absolute paths to external generator checkouts.
- **Absolute paths.** The smoke tool on its lane hard-codes the main checkout's
  path for its secrets directory. No pool module under `packages/*/src`
  contains a `machine-home/` path (measured; the only hit is a seal-era CashAssembly
  comment).
- **No `LIMITS.md`.** The tree has no such file.

#### Scenario: Entry point with an absolute path

- **WHEN** a built entry point contains or opens an absolute filesystem path
- **THEN** a test that scans every declared entry point and what it loads MUST
  fail

#### Scenario: External generator absent

- **WHEN** the item 5 gate runs with the external verifier-graph generator
  absent from PATH and from the filesystem
- **THEN** the declared entry points MUST still produce a valid pool submission

#### Scenario: Operation reachable only by repository path

- **WHEN** a role operation can be run only as `node tools/…`, `bash tools/…`
  or another repository path
- **THEN** MVP-PLAN item 5 MUST NOT be reported as met

### Requirement: The hardware floor is stated per role and kept apart from the development gate

The shipped child route is gnark Groth16 revision 3 with simulated single-party research keys. Native wallet proof launch is unimplemented and is not deferred by the cited fit-engineering decision. Consumer fit remains an unfulfilled target. Phase 3 measures and discloses complete proving/workflow cost, including key load, machine/key/profile identity, peak host and VM memory, swap growth and wall time; engineering a fit is deferred with no fix promised. Prior measurement/operator exceptions do not establish a 16 GiB fit or repeal the original pre-Setup stop rule. No historical figure is represented as a new measurement.


Bins exist in pool-wallet-host, pool-wallet-ink and pool-aggregator-service; the reference wallet/aggregator remain libraries. The aggregator service bin is a local health/status/metrics daemon only, not an intake, scheduler, prover, assembler, broadcaster or settlement command. The development harness uses workspace siblings and external generator defaults. Complete install/reproduction from a fresh account with the generator absent remains unverified; the withdraw module is pending. Phase 3’s integration-library/cross-wallet deferral does not defer release install and reproduction instructions.


Each role's README MUST state that role's hardware floor as follows.

- **Wallet.** The "16 GB fit" of `apnt-pool-proof-system`, "Proving is local
  and within consumer hardware", for its complete action proof with key load.
  The README MUST say whether the fit has been measured on a 16 GiB machine.
  Until it has, a measurement from a larger machine MUST NOT be presented as the
  fit.
- **Aggregate prover.** Its measured peak resident memory, swap growth and wall
  time per batch size, and the Docker VM memory its wrap needs, each stated
  with the machine it was measured on.
- **Development gate.** The gate of "One prover at a time behind a memory gate"
  protects the shared development machine. It MUST NOT be presented as a
  wallet's hardware floor, and a wallet's entry point MUST NOT inherit its
  admission floor.

Historical state before the M1 reconciliation: **partial**. What is measured, all on a 48 GiB development
machine:

- **Wallet action proof.** A cold prove on a fast-loaded 5.1c key takes
  22–23 s at 7.5 GiB, or 6.4 GiB with `GOMEMLIMIT=6GiB` (task 5.1b record,
  historical-record). That run predates revision 3's keys.
- **Aggregate proof, B = 1.** 931 s, 15.6 GB peak, swap growth 7.5 GB (task
  5.4 record).
- **Aggregate proof, B = 17.** 5,499 s, 22.3 GB peak, swap growth 1.9 GB (task
  5.4 record).
- **Docker.** The runner requires a Docker VM of at least 20 GiB
  (`tools/apnt-pool-aggregate-sp1/scripts/aggregate-proof-runner.sh`).

Nothing has been measured on a 16 GiB machine, and no README states a floor.

#### Scenario: Larger-machine figure cited as the fit

- **WHEN** a document cites an action-proof measurement from a machine with more
  than 16 GiB of memory as meeting the 16 GB fit
- **THEN** it MUST be corrected to say the fit is unmeasured on a 16 GiB machine

#### Scenario: Development floor applied to a wallet

- **WHEN** a wallet entry point refuses to prove on a 16 GiB machine because it
  applies the development gate's admission floor
- **THEN** the build MUST be rejected. The wallet's own admission rule belongs
  to its entry point and derives from the measured action peak

### Requirement: The prove-to-settle pipeline is a fixed sequence of hand-offs

The pool MUST be driven by these stages, in this order. Each stage consumes only
what the table names.

| Stage | Role | Consumes | Hands off |
|---|---|---|---|
| P1 chain read | wallet; aggregator | the deployment artifact; chain reads | verified, replayed history evidence |
| P2 action | wallet | its own P1; an invoice or a self-transfer; its seed | record `A`, child proof, two owner signatures over `m`, two discovery tags |
| P3 deposit | wallet | its own P1; historical-record's pre-funding binding | a confirmed inbox outpoint |
| P4 intake | aggregator | P2's public outputs, and P3's outpoint for a deposit | admitted public actions |
| P5 assembly | aggregator | P4; its own P1 | statement `S`; settlement template |
| P6 aggregate | aggregate prover | `S`'s records and child proofs; the deployment id | SP1 proof committing `SHA-256(S)` |
| P7 wrap | aggregate prover | P6 | Groth16 wrapper proof and its public values |
| P8 verifier graph | aggregator | P7; the pinned graph record and variant map | verifier-transaction inputs |
| P9 factory mint | aggregator | P8 | verdict token under the settlement lock |
| P10 settlement | aggregator | P5; P9 | settlement transaction |
| P11 fold | any party | the pending batch | tree update and new root copies |
| P12 acceptance | wallet | its own P1 after P10 and P11 | held, accepted, member, unspent and spendable status, each separate |

Rules:

- **Fixed choices travel as data.** A choice fixed at one stage MUST travel as
  data to every later stage. Examples are a record selection, a statement
  order, a variant choice and an anchor. No later stage MAY re-derive such a
  choice from a later artifact. historical-record shows why. The verifier graph's
  per-input variant was re-chosen by measuring the replay proof, so the graph's
  lockings no longer matched their pins. Resolving it cost a day.
- **Named refusals.** Every stage MUST refuse with a named, stable cause. It MUST
  NOT repair, substitute or re-select an input in order to proceed.
  `pool-harness-*` names below are stage-level harness results, not BCH
  consensus failure codes. The harness MUST preserve the owning component's
  specific refusal alongside the stage result when one exists.
- **Public hand-offs.** A hand-off between roles MUST carry public data only. P2's
  witness stays in the wallet unless it is delegated under a labelled
  disclosure.
- **No borrowed verification.** No stage MAY take a later stage's success as its
  own check. For example, it MUST NOT admit an inbox because a trial settlement
  passes (historical-record).
- **Separate results.** A stage's success is a structural or local result.
  Relay acceptance, chain inclusion and wallet acceptance are separate results
  ("Live evidence keeps three results apart").

Historical state before the M1 reconciliation: **partial**.

- **On main:** P1, P2 without a wallet-integrated proof, P4 and P5.
- **In `tools/`:** P6 and P7. P8 and P9 exist only as the labelled research
  prototype `tools/pool-onetx-verifier-prototype`.
- **At the measured base:** P3 was missing. At `c9ef580e` its covenant and
  local tests are on main, but wallet inbox funding and aggregator intake are
  missing.
- **Local VMs only:** P10, for B = 1.
- **P11:** the covenant only.
- **P12:** partial.

There is no end-to-end driver on main. The only composition is the historical-record
lifecycle on its lane, which runs at P0 with stand-ins.

#### Scenario: A later stage re-derives an earlier choice

- **WHEN** a stage recomputes a choice fixed at an earlier stage from a later
  artifact, for example a verifier-graph variant chosen from the replay proof
- **THEN** it MUST refuse, and a test with a firing control MUST show the refusal

#### Scenario: A stage repairs its input

- **WHEN** a stage meets an input that fails its checks and substitutes,
  re-selects or edits it to continue
- **THEN** the build MUST be rejected; the stage refuses with its named cause

### Requirement: Each stage and user action is an independently invokable module

Bins exist in pool-wallet-host, pool-wallet-ink and pool-aggregator-service; the reference wallet/aggregator remain libraries. The aggregator service bin is a local health/status/metrics daemon only, not an intake, scheduler, prover, assembler, broadcaster or settlement command. The development harness uses workspace siblings and external generator defaults. Complete install/reproduction from a fresh account with the generator absent remains unverified; the withdraw module is pending. Phase 3’s integration-library/cross-wallet deferral does not defer release install and reproduction instructions.


Each P-stage above, and each user action, MUST be its own module that can be
called alone. The user actions are wallet creation, invoice issue, recipient
scan, inbox refund and withdrawal. Scenarios MUST compose modules. A single
linear script MUST NOT be the only way to run a stage. The P1-P12 order stays a
data-dependency order, not a call order.

Each module MUST declare:

- its role and holding boundary ("Each role has a declared holding boundary");
- the typed artifacts it consumes and hands off. Each hand-off is sealed with a
  digest and bound to one network;
- whether it reads, builds, signs, proves or broadcasts. Only the broadcast
  module broadcasts, and only on the Chipnet backend behind an explicit flag;
- for a wallet-role module that spends, a named approval point. It fails closed
  until a per-payment approval or an operator-installed spending policy grants
  it;
- a local backend and a Chipnet backend, each ready, pending or not applicable.

A module whose requirement is unimplemented MUST refuse with a stable pending
code that names its blocker. It MUST NOT be a stand-in that passes. A scenario
MUST refuse a hand-off that is skipped, reordered, from the wrong producer, or
changed after it was produced. An agent-facing caller of a wallet-role module
MUST NOT receive a seed, spend key, opening or witness.

A hand-off's claim to come from a module MUST NOT stand in for that module
having run. A consumer MUST refuse a claim that names a module not ready on its
backend. It MUST re-verify or authenticate every module-produced input it
accepts. A labelled fixture MAY stand in for a module's hand-off only where the
call or scenario declares that substitution, and only on the local backend. A
wallet-role module MUST act only for the wallet that issued the handle it is
given. A named scenario MUST NOT report success until every one of its steps has
completed and its terminal hand-off exists.

Historical state before the M1 reconciliation: **partial**, measured against main `5e46e6e6`. The module
harness exists only on lane `pool-action-modules` (historical-record slice 1,
`tools/pool-action-modules/`). Five modules are ready on the local backend:
wallet creation, invoice issue, and the aggregator's P1, P4 and P5. Every other
module is pending with its blocker named.

#### Scenario: Pending module passes

- **WHEN** a module whose requirement is unimplemented returns success
- **THEN** the build MUST be rejected; the module refuses with its pending code

#### Scenario: Scenario skips a hand-off

- **WHEN** a scenario calls a module whose consumed artifact no earlier call
  produced, or a later call produced
- **THEN** the harness MUST refuse before calling that module

#### Scenario: Producer claim stands in for a pending stage

- **WHEN** a module is given an artifact that claims a producer module not
  ready on its backend
- **THEN** the module MUST refuse before it builds anything

#### Scenario: Named scenario ends early

- **WHEN** a scenario bearing a stage's name omits one of its steps or its
  terminal hand-off
- **THEN** the harness MUST refuse rather than report success

### Requirement: P1, chain reads are collected, verified and replayed by the reader

Each wallet and each aggregator MUST derive pool state only from chain evidence
that it has verified and replayed itself:

- **Collection.** `collectChainIoHistoryEvidenceV1` (`packages/chain-io/src/index.ts`)
  reads the complete confirmed histories through the read's tip of the locking bytecodes and genesis txids its
  caller names. A pool reader MUST name only the public pool locks and the
  deployment's genesis txids, never a note-keyed value. The collector does not
  enforce this; the reader does. Mempool entries after confirmed history MUST be
  checked against the full script status and returned separately as unauthenticated
  observations. They MUST NOT enter evidence, replay, acceptance or inclusion claims (historical-record).
- **Verification.** `verifyChainIoHistoryEvidenceV1`
  (`packages/chain-io/src/history_evidence_v1.ts`) checks headers, links, work
  and Merkle inclusion.
- **Replay.** `replayAPNTPoolSettlementHistoryV1`
  (`packages/protocol-runtime/src/apnt_pool_settlement_history_v1.ts`) audits the
  genesis against the deployment artifact with `validateAPNTPoolGenesisV1`, then
  replays settlements and folds.

A freshness claim MUST rest on a comparison with the reader's earlier evidence.
Without that comparison the reader has verified only the read it was given, and
MUST say so.

Named refusal causes:

- collection: `chain-io-history-collection-configuration`, `-network`,
  `-transport`, `-response`, `-limit`, `-truncated`, `-mempool`, `-height`,
  `-order`, `-header` and `-changed`; `-mempool` applies when a genesis
  Merkle proof reports height 0 or −1, whether or not the txid is listed as
  confirmed in a queried history. A genesis txid listed in a pending suffix
  is `-height` first; a pending entry before a confirmed entry is `-order`;
- verification: `chain-io-history-txid`, `-inclusion`, `-header-link`,
  `-header-work`, `-stale`, `-withheld`, `-duplicate`, `-checkpoint` and
  `-shape`;
- wallet: `pool-wallet-chain-evidence`, `pool-wallet-chain-stale` and
  `pool-wallet-deployment`;
- genesis: the `pool-genesis-*` causes of `validateAPNTPoolGenesisV1`.

Historical state before the M1 reconciliation: **partial**.

- **Collector.** On main (historical-record, fixed by historical-record; confirmed-only pending split per historical-record).
- **Readers.** The wallet (`packages/reference-wallet/src/apnt_pool_wallet_spent_v1.ts`)
  and the aggregator's locator
  (`packages/reference-aggregator/src/apnt_pool_live_records_v1.ts`) verify and
  replay evidence handed to them. Neither calls the collector itself.
- **Recorded limits** (task 4.2, historical-record): freshness is conditional, and history
  completeness is not proven.
- **Egress.** Anonymized egress for reads is missing (task 4.3).

#### Scenario: Unrelated pending pool transaction

- **WHEN** a transaction touching the settlement, tree-update or category-source lock is pending
- **THEN** an unrelated reader MUST receive confirmed history without that transaction in evidence

#### Scenario: Evidence with one altered transaction

- **WHEN** a reader is given history evidence in which any raw transaction was
  altered
- **THEN** it MUST refuse with `chain-io-history-txid`, and the wallet with
  `pool-wallet-chain-evidence`

#### Scenario: Read keyed on a note value

- **WHEN** a reader queries the chain server by a nullifier, commitment, leaf
  or expected discovery tag
- **THEN** the build MUST be rejected, as `apnt-pool-privacy-model` "Submission
  reveals no more than network metadata" requires

### Requirement: P2, the wallet builds, signs and proves its own action

The wallet MUST build its action from its own P1 evidence and its own seed. It
MUST sign only the action its own build released, and MUST prove it locally.

- **Inputs.** The anchor and membership paths from its own chain read; an
  invoice (`payerFacing`) or a self-transfer; its seed-derived keys.
- **Outputs.**
  - the 314-byte record `A`;
  - a child proof under registry entry 1 revision 3;
  - two owner signatures over `m`;
  - two discovery tags.

  The witness never leaves the wallet unless delegated under a labelled
  disclosure.
- **Pins checked.** The prover MUST refuse unless each of these equals its pin:
  - the registry `vp` and its derived `profile_id`
    (`tools/apnt-pool-action-circuit/registry.go`);
  - the proving key's size and SHA-256, raw or image
    (`tools/apnt-pool-action-circuit/pkload/pins.go`);
  - the R1CS digest.

  The wallet MUST check its own proof under the pinned verifying key before
  handing it off.
- **Named refusals.** The wallet's `pool-wallet-*` causes, among them:
  - `pool-wallet-anchor-stale`, `pool-wallet-invoice-expired` and
    `pool-wallet-invoice-reused`;
  - `pool-wallet-payment-conflict`, `pool-wallet-payment-cancel-height` and
    `pool-wallet-signature`;
  - the key loader's refusals of pin, open, size, read, digest and decode.

Historical state before the M1 reconciliation: **partial**.

- **On main.** The payer build and its private signer
  (`buildReferenceWalletAPNTPoolInvoicePaymentV1`,
  `packages/reference-wallet/src/apnt_pool_wallet_payer_v1.ts`; task 4.1).
- **No wallet-integrated prover.** No file under `packages/reference-wallet/src`
  refers to gnark or the key loader (measured). Action proofs exist only
  through the measurement commands `pool-pk-load prove` and
  `pool-action-circuit devprove` (`tools/apnt-pool-action-circuit/cmd/`). These
  prove a committed corpus witness, not a wallet's live witness (smoke
  blocker 2, `tools/pool-chipnet-smoke/RUNBOOK.md`).
- **Interim tags.** Discovery tags are interim random tags (historical-record).

#### Scenario: Proving key other than the pinned one

- **WHEN** the proving key's size or SHA-256 differs from its pin
- **THEN** the prover MUST refuse before decoding any of it

#### Scenario: Corpus witness reported as a live action

- **WHEN** a proof made from the committed corpus entry is offered as a wallet's
  live action
- **THEN** the pipeline MUST refuse it, and no report MAY describe it as live

### Requirement: P3, deposits hand off through the record-keyed inbox

A deposit's BCH MUST enter the pool through its deployment's record-keyed inbox,
as historical-record specifies. This capability does not restate those rules; it names
them:

- `apnt-pool-settlement-custody`:
  - "Deposits enter through a record-keyed pool inbox";
  - "The inbox guarantee and its limit are stated exactly";
  - "The deployment artifact pins the inbox code in a closed revision";
  - "Deposit admission protects liveness, not custody";
  - "Depositor inputs signed inside a settlement are not a v1 deposit path".
- `apnt-pool-receive-recovery`:
  - "A wallet funds a deposit inbox only after its pre-funding binding";
  - "Deposits are tracked, restored and refunded by the wallet".

The harness obligations are these:

- **Order.** Inbox funding (P3) MUST precede intake (P4). Intake MUST take the
  inbox outpoint and nothing that authorizes a refund.
- **Carry-through.** Assembly (P5) MUST carry the inbox input unchanged through
  every rebuild.
- **BIP68.** The local ledger MUST enforce BIP68 relative locks, so the refund
  path's maturity is tested locally.
- **Inbox only.** Task 8.1 L2 and task 8.2 MUST deposit only through the
  record-keyed inbox. A depositor input signed inside a settlement, whether
  `0x41` or `0x61`, MUST be refused as `pool-harness-p3-depositor-input-route`.
  An operator exception cannot turn either route into v1 deposit evidence.
- **Named refusals.** An unconfirmed inbox MUST yield
  `pool-harness-p3-inbox-unconfirmed`; a short refund margin MUST yield
  `pool-harness-p3-refund-margin`, preserving historical-record's owning refusal.


The module harness returns typed handoffs and retains owning component failures as owner causes. P3 retains pool-harness-p3-depositor-input-route. For P10, pool-harness-p10-bytes-changed, pool-harness-p10-broadcast-refused, pool-harness-p10-relay-accepted, pool-harness-p10-inclusion-unverified and pool-harness-p10-inclusion-verified are implemented by the live-evidence tools; the modules carry their refusal causes and successful result codes. The two specified local-VM aliases, pool-harness-p10-local-vm-accepted and pool-harness-p10-local-vm-refused, are absent from the inspected code, although construction checks both VMs. Other stage aliases must be mapped individually to their actual artifact/result schema and owning refusal; their absence is not a blanket claim about P10. Build, relay acceptance, inclusion and wallet acceptance remain separate. The missing aliases remain acceptance gaps until the operator resolves the frozen result-contract wording.

Historical state before the M1 reconciliation at base `47ba43b3`: **missing**. At main `c9ef580e`: **partial**.

- **Inbox.** The covenant, revision-2 genesis pin and local VM/refund tests are
  on main. Wallet inbox funding and aggregator inbox intake are missing
  (task 3.6, generalized by historical-record; historical-record and historical-record).
- **Old assembler path.** The assembler on main still models a
  depositor input re-signed after each rebuild (the `depositor-resign-required`
  state, `packages/reference-aggregator/src/apnt_pool_assembler_v1.ts`), but
  that path is superseded for v1 deposits.
- **Superseded plans, not fallback authority.** The historical-record L2 plan at
  `c6ee3cfe` and Chipnet smoke assumptions at `4b6c6d57` planned plain
  `SIGHASH_ALL` depositor inputs. The self-deposit implementation at
  `8d18fc65`, later on main through `eaf0847c` and `74db13bd`, signs `0x41`.
  historical-record described an interim `0x61` path. The operator ruled on
  2026-09-27 at 17:46 (historical-record, historical-record) that neither depositor-input route
  is permitted for task 8.1 L2 or 8.2. A deposit-taking Chipnet genesis still
  requires the inbox.

#### Scenario: Intake before inbox confirmation

- **WHEN** an intake receives a deposit action whose inbox is unconfirmed or
  whose refund margin is short
- **THEN** it MUST refuse with `pool-harness-p3-inbox-unconfirmed` or
  `pool-harness-p3-refund-margin`, as applicable, and MUST NOT admit the action
  (historical-record "Unconfirmed inbox or short refund margin")

#### Scenario: Harness run with a depositor input in the settlement

- **WHEN** task 8.1 L2 or 8.2 offers a deposit through a depositor input
  signed inside the settlement with either `0x41` or `0x61`
- **THEN** P3 MUST refuse with `pool-harness-p3-depositor-input-route`, and the
  run MUST NOT be cited as v1 deposit evidence

### Requirement: P4, intake checks public data under an installed verifier

The aggregator's intake MUST check only public data, and it MUST check the
action proof with a verifier that is installed and pinned, never supplied.

- **Inputs.** For each action: the record; its 144-byte authorization, which
  holds both owner signatures and both discovery tags; the withdrawal locking
  bytecode when it withdraws; and its child proof. For a deposit, also the
  inbox outpoint. The deployment is the aggregator's own, never the
  caller's.
- **Outputs.** An admitted public action.
- **Pins checked.** The native verifier pinned to registry entry 1 revision 3's
  `profile_id` (`POOL_INTAKE_PROFILE_V1`).
- **Checks.** Both signatures over `m`; anchor currency against the
  aggregator's own read; no inserted nullifier; distinct range records.
- **Named refusals:**
  - `pool-intake-shape`, `-record`, `-tag-placement`, `-owner-signature`;
  - `pool-intake-withdrawal-lock`, `-anchor-unavailable`, `-stale-anchor-policy`;
  - `pool-intake-nullifier-inserted-or-history-incomplete`, `pool-range-same-record`;
  - `pool-intake-duplicate-action`, `-action-proof`, `-verifier-unavailable`;
  - `pool-intake-profile`, `-snapshot`, `-deployment`.

Historical state before the M1 reconciliation: **partial**.

- **Single-action intake is on main**
  (`packages/reference-aggregator/src/apnt_pool_intake_v1.ts`, historical-record,
  historical-record; historical-record PASS).
- **Not implemented:**
  - the Tor hand-off and self-settlement both return
    `pool-aggregator-transport-not-implemented` (tasks 4.3 and 6.1);
  - deposit intake through the inbox (historical-record).

#### Scenario: Verifier supplied by the caller

- **WHEN** an intake call carries a verifier, verifying key or profile of its
  own
- **THEN** intake MUST refuse it and use only the installed, pinned verifier

#### Scenario: Unknown outer field

- **WHEN** an action message carries a field outside the intake schema
- **THEN** intake MUST refuse it with `pool-intake-shape` before reading any
  payload

### Requirement: P5, assembly selects at random and rebuilds without re-signing

The aggregator MUST assemble a settlement from admitted actions and its own
chain read.

- **Selection.** It MUST select range records, root copies and pool coins at
  random, taking one randomly chosen copy per distinct anchor.
- **Rebuild.** On contention it MUST rebuild while keeping every record's
  statement bytes and signatures unchanged.
- **Capacity.** It MUST refuse a batch that exceeds the measured standard
  capacity rather than truncate or split it silently.
- **Outputs.** Statement `S` in strictly ascending `ad` order and a settlement
  template.
- **Named refusals:** `pool-assembler-capacity`,
  `-insufficient-public-funding`, `-utxo`, `-layout`, `-statement-changed` and
  `-random-source`.

Historical state before the M1 reconciliation: **partial**.

- **On main.** Assembly and rebuild
  (`packages/reference-aggregator/src/apnt_pool_assembler_v1.ts`; task 6.1 part
  1).
- **Capacity, measured (historical-record).** With 900-sat pool coins, B = 17 is accepted
  at 95,295 transaction bytes. B = 18 and 19 are refused by the 100,000-byte
  standardness guard.
- **Open:** the locator for the two-lock history (historical-record); carrying the inbox
  input (P3).

#### Scenario: Rebuild changes a signed record

- **WHEN** a contention rebuild changes any record's bytes or the statement
  order that the owners signed
- **THEN** assembly MUST refuse with `pool-assembler-statement-changed`

#### Scenario: Selection from a caller's list

- **WHEN** a caller supplies which records, copies or coins to use
- **THEN** assembly MUST still draw its selection from its own random source
  over its own chain read, or refuse with `pool-assembler-random-source`

### Requirement: P6, the SP1 aggregate runs only the canonical, pinned program

The aggregate prover MUST prove only with the pinned program over one statement.

- **Pinned program.** The guest ELF MUST be built through
  `tools/sp1-canonical-guest-build` and MUST equal the pin record
  (`tools/apnt-pool-aggregate-sp1/canonical-build/chipnet-zero-value-rev3-canonical-build-v1.json`)
  in SHA-256 and length. The checkout's guest inputs MUST equal the pinned
  guest-inputs digest. The program key MUST be the pinned one.
- **Allowlist.** The guest MUST compute `profile_id` from the `vp` it uses, and
  MUST refuse any id outside its compiled allowlist before parsing a child.
- **Live versus fixture.**
  - Fixture batches (`b1`, `b17`) are named inputs and MUST NOT be reported as
    live.
  - A live input carries exactly the deployment id, `profile_id` and, for each
    action, its record and child proof. Extra fields are refused.
  - The host MUST verify each child under the pinned key before any SP1 client
    is constructed.
  - A supplied deployment id is a binding, not chain-authenticated evidence.
- **Named refusals:**
  - `batch-must-be-b1-or-b17-or-live-b1`, `elf-digest-mismatch`,
    `elf-length-mismatch`;
  - `checkout-guest-inputs-are-not-the-pinned-ones`, `pin-record-missing`;
  - `pool-live-batch-must-be-one`, `pool-aggregate-profile-not-allowlisted`;
  - `pool-record-length`, `-key`, `-amount`, `-withdrawal-lock`;
  - the core's `pool-aggregate-proof-*` causes;
  - the `pool-live-input-*` causes.


The module harness returns typed handoffs and retains owning component failures as owner causes. P3 retains pool-harness-p3-depositor-input-route. For P10, pool-harness-p10-bytes-changed, pool-harness-p10-broadcast-refused, pool-harness-p10-relay-accepted, pool-harness-p10-inclusion-unverified and pool-harness-p10-inclusion-verified are implemented by the live-evidence tools; the modules carry their refusal causes and successful result codes. The two specified local-VM aliases, pool-harness-p10-local-vm-accepted and pool-harness-p10-local-vm-refused, are absent from the inspected code, although construction checks both VMs. Other stage aliases must be mapped individually to their actual artifact/result schema and owning refusal; their absence is not a blanket claim about P10. Build, relay acceptance, inclusion and wallet acceptance remain separate. The missing aliases remain acceptance gaps until the operator resolves the frozen result-contract wording.

Historical state before the M1 reconciliation: **partial**.

- **Pinned build.** The canonical ELF is pinned and was byte-identical from
  three checkout paths (task 5.4 slice 2a).
- **Real fixture proofs.** B = 1 and B = 17 were proved from the main checkout
  (slice 2b).
- **Live input.** Live single-action admission is implemented (historical-record,
  `tools/apnt-pool-aggregate-sp1/runner/src/live.rs`) but has never run with a
  real live proof.
- **Missing:** live input for B ≥ 2. It is deferred to the historical-record gate
  (historical-record).

#### Scenario: Worktree-built ELF

- **WHEN** the runner is given an ELF built in a worktree, whose digest or length
  differs from the pin
- **THEN** it MUST refuse with `elf-digest-mismatch` or `elf-length-mismatch`,
  and the pin MUST NOT be edited to match

#### Scenario: Fixture batch reported as live

- **WHEN** evidence from `b1` or `b17` is offered for a live deployment's
  settlement
- **THEN** it MUST be refused, because its statement is not that deployment's

### Requirement: P7, the wrap runs under the proving discipline and leaves nothing behind

The Groth16 wrap of the SP1 proof MUST run inside the same gated process as P6.

- **Evidence.** The run MUST record the wrapper proof, its public values and
  their digests. It MUST also require exactly one setup call and one prove call.
- **Clean start.** The run MUST refuse to start while any wrap container exists
  in any state, or while an override of the wrap image is set.
- **Cleanup.** On every exit it MUST reap every wrap container and confirm none
  is left ("Prover process trees and containers are reaped").
- **Named refusals:** `prover-container-present`,
  `sp1-gnark-image-override-set`, `docker-daemon-unavailable`,
  `docker-vm-memory-below-20-gib`, `call-counts-unexpected` and
  `prover-reap-unconfirmed`.

Historical state before the M1 reconciliation: **partial**. The wrap runs inside
`tools/apnt-pool-aggregate-sp1/scripts/aggregate-proof-runner.sh` and did so
for the two real proofs of task 5.4 slice 2b. The restart of Docker between
wraps is not automated ("Prover process trees and containers are reaped").

#### Scenario: Leftover wrap container

- **WHEN** a wrap container from an earlier run exists in any state
- **THEN** the runner MUST refuse with `prover-container-present` before proving

### Requirement: P8, the verifier graph is replayed from its pinned record and variant map

The verifier graph MUST be regenerated only from its committed record and its
pinned per-input variant map. It MUST NOT be regenerated from the proof being
replayed.

- **Pins checked:**
  - the graph record, its root and its lockings digest
    (`tools/pool-onetx-verifier-prototype/pool-key/chipnet-zero-value-rev3-graph-v1.json`);
  - the variant map's SHA-256
    (`tools/pool-onetx-verifier-prototype/pool-key/chipnet-zero-value-rev3-graph-v1.variant-map.json`,
    checked by `tools/pool-onetx-verifier-prototype/scripts/variant-map.mjs`).

  The map MUST name the same graph root, lockings digest and cuts, and one
  variant per graph input.
- **Planning.** Planning, which is an explicit measurement mode, MUST refuse a
  variant that rejects the planning proof.
- **Replay.** A replay without the map MUST refuse.
- **Named refusals:** `VARIANT_MAP_ABSENT`, `VARIANT_MAP_DIGEST`,
  `VARIANT_MAP_SCHEMA`, `VARIANT_MAP_INPUT_COUNT`, `VARIANT_MAP_VARIANT`,
  `VARIANT_MAP_GRAPH` and `VARIANT_REJECTS_PLANNING_PROOF`.

Historical state before the M1 reconciliation: **partial**.

- **Implemented, as a research prototype.** historical-record is in the labelled research
  prototype `tools/pool-onetx-verifier-prototype` (historical-record PASS).
- **Measured.** Both real proofs pass every one of the 11 graph inputs in both
  VMs. The B = 1 verifier transaction is 96,886 bytes with the verdict gate
  (task 5.4 record).
- **Open.** Regeneration needs the external generator ("Role entry points are
  declared executables"). External review of the residue construction is
  outstanding (task 5.4).

#### Scenario: Variant re-chosen from the replay proof

- **WHEN** a replay selects any input's variant by measuring the proof being
  replayed
- **THEN** it MUST refuse, and the lockings MUST come from the pinned map

#### Scenario: Map edited to fit

- **WHEN** the variant map's bytes change and its digest pin is changed to match
- **THEN** that MUST be treated as a new graph record needing review, never as
  a replay fix

### Requirement: P9, the factory mints only the proven verdict

The verdict factory MUST be pinned to the graph root, the settlement lock, the
verdict category and SP1's recursion root. It MUST mint the verdict as a
verdict-category token with no capability, under the settlement lock, whose
commitment is `SHA-256(S)`. It MUST keep the factory token at its own lock. The
genesis audit MUST bind the factory covenant to a reviewed build, as it binds
the other pool covenants.

P9 MUST report `pool-harness-p9-verdict-minted` only after the factory's local
checks pass and the genesis audit binds it to a reviewed build. An unbound
factory MUST yield `pool-harness-p9-factory-unbound`; a factory negative MUST
yield the stable harness refusal
`pool-harness-p9-factory-refused` with the specific factory test or VM refusal
retained. The negatives are refused at the factory, not inferred from a later
settlement (`tools/pool-onetx-verifier-prototype/pool-key-verdict.test.ts`):

- a verdict for another statement;
- a verdict to an attacker or under the pending lock;
- a mutable or minting verdict;
- a foreign category;
- a verdict below the value floor;
- change replaced by a forged verdict;
- a factory token not returned, sent to an attacker, downgraded or given a
  commitment;
- a reduced factory value;
- a foreign minting token at the factory.


The module harness returns typed handoffs and retains owning component failures as owner causes. P3 retains pool-harness-p3-depositor-input-route. For P10, pool-harness-p10-bytes-changed, pool-harness-p10-broadcast-refused, pool-harness-p10-relay-accepted, pool-harness-p10-inclusion-unverified and pool-harness-p10-inclusion-verified are implemented by the live-evidence tools; the modules carry their refusal causes and successful result codes. The two specified local-VM aliases, pool-harness-p10-local-vm-accepted and pool-harness-p10-local-vm-refused, are absent from the inspected code, although construction checks both VMs. Other stage aliases must be mapped individually to their actual artifact/result schema and owning refusal; their absence is not a blanket claim about P10. Build, relay acceptance, inclusion and wallet acceptance remain separate. The missing aliases remain acceptance gaps until the operator resolves the frozen result-contract wording.

Historical state before the M1 reconciliation: **partial**.

- **Local VMs.** The pool-mode factory mints M = 1 to 8 verdicts in one run on
  a stub graph root. With the real graph, B = 1's verdict settles in the shipped
  settlement covenant in both local VMs (task 5.4 slice 2b).
- **Unbound in the genesis audit.** `validateAPNTPoolGenesisV1` checks the
  factory only as a P2SH32 lock of the artifact's own redeem bytecode, not
  against a reviewed build
  (`packages/protocol-runtime/src/apnt_pool_genesis_v1.ts`, historical-record). A closed
  verdict supply is still required before any Chipnet genesis (historical-record,
  historical-record; historical-record).

#### Scenario: Artifact carries a substitute factory

- **WHEN** a deployment artifact names a factory redeem other than the reviewed
  build for its graph and settlement lock
- **THEN** P9 MUST report `pool-harness-p9-factory-unbound` and retain the
  genesis audit's existing specific refusal. The audit now binds the factory to
  the shipped reviewed builder; the P9 alias obligation remains distinct under
  the frozen result-contract review

The module harness returns typed handoffs and retains owning component failures as owner causes. P3 retains pool-harness-p3-depositor-input-route. For P10, pool-harness-p10-bytes-changed, pool-harness-p10-broadcast-refused, pool-harness-p10-relay-accepted, pool-harness-p10-inclusion-unverified and pool-harness-p10-inclusion-verified are implemented by the live-evidence tools; the modules carry their refusal causes and successful result codes. The two specified local-VM aliases, pool-harness-p10-local-vm-accepted and pool-harness-p10-local-vm-refused, are absent from the inspected code, although construction checks both VMs. Other stage aliases must be mapped individually to their actual artifact/result schema and owning refusal; their absence is not a blanket claim about P10. Build, relay acceptance, inclusion and wallet acceptance remain separate. The missing aliases remain acceptance gaps until the operator resolves the frozen result-contract wording.


### Requirement: P10, settlement is checked in both local VMs, then broadcast raw once

The settlement transaction MUST pass both BCH 2026 VMs (standard and consensus)
locally before any broadcast. Local acceptance is a precondition and never
evidence of a live result.

- **Broadcast.** The exact reviewed bytes MUST go out once, as a raw Electrum
  `blockchain.transaction.broadcast`. A source change after review MUST NOT
  trigger a re-sign or rebroadcast unless the rebuild itself is reviewed.
- **Evidence.** Relay acceptance, inclusion and wallet acceptance MUST be
  recorded as separate results ("Live evidence keeps three results apart").
- **Stage results.** Both local VMs passing MUST be recorded as
  `pool-harness-p10-local-vm-accepted`; either VM rejecting MUST yield
  `pool-harness-p10-local-vm-refused` with that VM's cause. Changed reviewed
  bytes MUST yield `pool-harness-p10-bytes-changed`. A rejected raw broadcast
  MUST yield `pool-harness-p10-broadcast-refused`. A successful relay response
  MUST be recorded as `pool-harness-p10-relay-accepted` only. Inclusion MUST
  remain `pool-harness-p10-inclusion-unverified` until independent direct-RPC
  evidence supports `pool-harness-p10-inclusion-verified`. None of these
  results asserts P12 wallet acceptance.


The module harness returns typed handoffs and retains owning component failures as owner causes. P3 retains pool-harness-p3-depositor-input-route. For P10, pool-harness-p10-bytes-changed, pool-harness-p10-broadcast-refused, pool-harness-p10-relay-accepted, pool-harness-p10-inclusion-unverified and pool-harness-p10-inclusion-verified are implemented by the live-evidence tools; the modules carry their refusal causes and successful result codes. The two specified local-VM aliases, pool-harness-p10-local-vm-accepted and pool-harness-p10-local-vm-refused, are absent from the inspected code, although construction checks both VMs. Other stage aliases must be mapped individually to their actual artifact/result schema and owning refusal; their absence is not a blanket claim about P10. Build, relay acceptance, inclusion and wallet acceptance remain separate. The missing aliases remain acceptance gaps until the operator resolves the frozen result-contract wording.

Historical state before the M1 reconciliation: **partial**.

- **Local only.** B = 1 settles end to end in both local VMs, with a 3,049-byte
  settlement (task 5.4 slice 2b).
- **B = 17 does not settle.** Its corpus statement is unsettleable by
  construction, and a test asserts exactly those causes (historical-record).
- **No live path.** No pool broadcast tool exists. The smoke tool has none by
  design, and no settlement has touched a chain.

#### Scenario: Rebroadcast after a source change

- **WHEN** a source file changes after a settlement's bytes were reviewed
- **THEN** the operator MUST NOT re-sign or rebroadcast those bytes on that
  account alone

### Requirement: P11, the fold is permissionless and separate from spendability

Any party MUST be able to fold a pending batch through the tree update. Wallets
waiting on a received note MUST fold every pending batch in order, not only
their own. A note in a pending, unfolded batch MUST NOT be reported as a member
of the tree or as spendable.

P11 MUST report `pool-harness-p11-folded` only for a tree update and new root
copies verified from the folding party's own P1 evidence. A failed fold MUST
report `pool-harness-p11-fold-refused` with the underlying covenant or
chain-evidence cause. An included settlement without its fold MUST remain
`pool-harness-p11-pending-unfolded`; that status never means spendable.


The module harness returns typed handoffs and retains owning component failures as owner causes. P3 retains pool-harness-p3-depositor-input-route. For P10, pool-harness-p10-bytes-changed, pool-harness-p10-broadcast-refused, pool-harness-p10-relay-accepted, pool-harness-p10-inclusion-unverified and pool-harness-p10-inclusion-verified are implemented by the live-evidence tools; the modules carry their refusal causes and successful result codes. The two specified local-VM aliases, pool-harness-p10-local-vm-accepted and pool-harness-p10-local-vm-refused, are absent from the inspected code, although construction checks both VMs. Other stage aliases must be mapped individually to their actual artifact/result schema and owning refusal; their absence is not a blanket claim about P10. Build, relay acceptance, inclusion and wallet acceptance remain separate. The missing aliases remain acceptance gaps until the operator resolves the frozen result-contract wording.

Historical state before the M1 reconciliation: **partial**.

- **Covenants on main.** The tree-update and root-copy covenants
  (`packages/protocol-runtime/src/apnt_pool_tree_covenants_v1.ts`) and their
  local-VM tests
  (`packages/reference-aggregator/test/apnt_pool_tree_covenants_v1_local_vm.test.ts`).
- **Host fold on main.** Folding a statement into the frontier
  (`foldAPNTPoolStatementIntoFrontierV1`,
  `packages/protocol-runtime/src/apnt_pool_frontier_v1.ts`).
- **No fold-transaction builder.** None exists outside the tests, and there is
  no fold entry point. The smoke runbook lists the fold among its unimplemented
  steps (`tools/pool-chipnet-smoke/RUNBOOK.md`).
- **Unmeasured.** Fold latency is a task 1.4 measurement (D4).

#### Scenario: Pending batch reported as spendable

- **WHEN** a wallet reports a received note spendable before a tree update
  containing it is in its own chain read
- **THEN** P11 MUST report `pool-harness-p11-pending-unfolded`, the report MUST
  be corrected, and the wallet MUST NOT build a spend of it

### Requirement: P12, wallet acceptance comes from the wallet's own chain read

The wallet MUST decide acceptance, membership, spent status and spendability
only from its own P1 evidence and an owner-verified opening. It MUST keep these
states separate: held, accepted, folded member, unspent and spendable.
Recording, persistence and recovery MUST NOT be reported as any of them
(`apnt-pool-receive-recovery` "Acceptance stays with the wallet").

P12 MUST record `pool-harness-p12-wallet-status-recorded` with the wallet's
distinct held, accepted, folded member, unspent and spendable results only as
the wallet returns them from its own P1 read. An
invalid or injected read MUST yield `pool-harness-p12-chain-evidence-refused`
with the wallet's own refusal. A held or restored note without wallet
acceptance MUST be recorded as `pool-harness-p12-not-accepted`, never promoted
by the harness. These are harness results, not a substitute for the wallet's
acceptance decision.


The module harness returns typed handoffs and retains owning component failures as owner causes. P3 retains pool-harness-p3-depositor-input-route. For P10, pool-harness-p10-bytes-changed, pool-harness-p10-broadcast-refused, pool-harness-p10-relay-accepted, pool-harness-p10-inclusion-unverified and pool-harness-p10-inclusion-verified are implemented by the live-evidence tools; the modules carry their refusal causes and successful result codes. The two specified local-VM aliases, pool-harness-p10-local-vm-accepted and pool-harness-p10-local-vm-refused, are absent from the inspected code, although construction checks both VMs. Other stage aliases must be mapped individually to their actual artifact/result schema and owning refusal; their absence is not a blanket claim about P10. Build, relay acceptance, inclusion and wallet acceptance remain separate. The missing aliases remain acceptance gaps until the operator resolves the frozen result-contract wording.

Historical state before the M1 reconciliation: **partial**.

- **On main.** Held notes, current status, anchors and membership paths from the
  wallet's own verified read (`acceptReferenceWalletAPNTPoolNotesV1` and
  `readReferenceWalletAPNTPoolNoteStatusV1`,
  `packages/reference-wallet/src/apnt_pool_wallet_notes_v1.ts`; historical-record, historical-record
  PASS), with eight check-removal controls.
- **Recorded limits.** Freshness is conditional. History completeness is not
  proven. A repeated seed-only restore needs re-acceptance first. None of it
  has run against a live chain.

#### Scenario: Acceptance from an injected record

- **WHEN** the wallet is offered a note, path or acceptance flag that is not
  derived from its own verified read
- **THEN** the wallet MUST refuse, P12 MUST record
  `pool-harness-p12-chain-evidence-refused` with the wallet's cause, and no
  caller-supplied acceptance MAY exist in its interface

### Requirement: One local dual-VM ledger serves every local harness

Local end-to-end runs MUST use one local ledger implementation. It MUST:

- accept a transaction only when both libauth BCH 2026 VMs (standard and
  consensus) accept it;
- keep a UTXO set;
- enforce BIP68 relative locks, finality and coinbase maturity;
- check standard transaction size, unlocking size, dust and the relay fee
  under a stated policy, recorded beside each receipt;
- order blocks canonically;
- serve the Electrum-shaped read subset that `packages/chain-io` calls, so that
  wallets and aggregators read it through their real entry points.

A second, independent ledger for another harness MUST NOT be written. Local
ledger acceptance MUST NOT be cited as relay acceptance, inclusion or wallet
acceptance.

Historical state before the M1 reconciliation: **partial**.

- **The historical-record ledger.** It is on main in `pool-multiparty-sim`
  (`tools/pool-multiparty-sim/ledger/`), with dual VMs, BIP68, finality,
  coinbase maturity, canonical block order and the chain-io reads.
- **A second ledger.** The smoke tool on its lane carries its own `DualVmLedger`
  (`tools/pool-chipnet-smoke/deployment.mjs`). It has no heights or blocks and
  no BIP68 check. It does check standard transaction and unlocking sizes, dust
  and the relay fee. The historical-record ledger states that it runs no fee or mempool
  policy. So each ledger checks what the other lacks, and the one ledger needs
  both sets of checks.
- **Not imported.** The smoke runbook records that the historical-record ledger was not
  imported.
- **Main.** The historical-record ledger is on main; the separate smoke ledger remains
  on its lane. The single-ledger requirement is still unmet.

The module backend shares the multiparty local ledger, whose stated model excludes fee/mempool policy beyond the VMs; full required relay policy is not established. Selected proof digests are checked, not a universal complete-digest reuse scheduler. Both-order test examples exist, but complete current outpoint/category inventory, the required smoke assumption register and stress expectation/observation register are not found in the inspected scope. For every actual live result, exact-byte raw-RPC inclusion, wallet-owned acceptance, endpoint/time and operator/note-count disclosures remain separate obligations. Missing evidence is missing, not zero or a local-VM pass.


#### Scenario: Refund maturity tested on a ledger without BIP68

- **WHEN** an inbox refund's maturity negative runs on a ledger that does not
  enforce BIP68
- **THEN** the negative MUST NOT be counted, because the refund lock is the
  node's rule and the ledger must enforce it

#### Scenario: Local acceptance cited as live

- **WHEN** a report cites a transaction's acceptance by the local ledger as
  relay acceptance, inclusion or wallet acceptance
- **THEN** it MUST be corrected

### Requirement: Chipnet reads use the chain-io collector, broadcasts are raw, and nothing touches mainnet

On Chipnet:

- **Reads.** Pool reads by a wallet or aggregator MUST go through the chain-io
  collector and its verification ("P1, chain reads are collected, verified and
  replayed by the reader").
- **Broadcasts.** A broadcast MUST submit exact, reviewed raw bytes once, as a
  raw Electrum call, following the internal operations document.
- **No mainnet.** Every pool tool MUST refuse mainnet. Its network MUST be
  bound to Chipnet, or to regtest on a loopback address for local runs.
- **Funding.** Only the operator funds. A tool that needs funds MUST stop and
  state the exact request: network, address and amount.
- **Labels.** Every Chipnet deployment is a labelled zero-value test on
  simulated-ceremony keys (`apnt-pool-settlement-custody` "No setup holder
  guards pooled value"). A deployment publishes bytecode, so it needs the
  operator's release decision under the publication rule. Task 8.2's single
  smoke deployment is the operator's carve-out.

The Chipnet ladder is the lifecycle gate ledger; the local ledger supplies regression and firing negatives. Phase 3 M3 is several wallet processes on one machine with complete-workflow measurements and independent review. Every cited run must state the single operator and exact deployment tree note count; it demonstrates construction, not independent-user anonymity. Separate-machine/fresh-restore exercises are deferred and participation engineering is narrowed to spec/paper. M3 remains acceptance work; publication is the separate operator-go launch of repository and FundMe after the pre-launch cleanup gate. No current M3 pass or publication go is established by this reconciliation.


Historical state before the M1 reconciliation: **partial**.

- **Collector.** It refuses any network except Chipnet and loopback regtest
  (`collectChainIoHistoryEvidenceV1`).
- **Smoke tool.** Its lane binds its build to `chipnet` and has no broadcast
  command.
- **Missing:** a pool broadcast tool.

#### Scenario: Mainnet endpoint configured

- **WHEN** any pool tool is configured with a mainnet network or endpoint
- **THEN** it MUST refuse before any request, as the collector refuses with
  `chain-io-history-collection-network`

#### Scenario: Agent funds a wallet

- **WHEN** a run needs Chipnet funds
- **THEN** it MUST stop and surface the exact funding request to the operator,
  and never obtain funds itself

### Requirement: Live evidence keeps three results apart

Every live claim MUST record relay acceptance, chain inclusion and wallet
acceptance as three separate results. Each MUST be verified by direct RPC:

- **Endpoint.** The Chipnet server `chipnet.imaginary.cash`, port 50002, raw
  Electrum over TLS with certificate verification.
- **Independent client.** The client MUST be independent of this repository's
  chain client.
- **Raw bytes.** `blockchain.transaction.get` MUST return exactly the candidate
  bytes, and the recomputed txid MUST equal the request.
- **Inclusion.** It MUST be checked with `blockchain.transaction.get_merkle`
  against a header fetched on its own.
- **Unspent state.** An indexing disagreement MUST be cross-checked with
  `blockchain.utxo.get_info` or `blockchain.transaction.get` before any
  conclusion. One missing index result is not proof of absence.
- **Records.** Evidence MUST record the method, parameters, endpoint, UTC time,
  raw response and any error. Earlier observations MUST be kept, not
  overwritten, when a read is repeated after a reorganization.

The following MUST NOT stand in for any of the three results:

- local VM acceptance;
- an Electrum status string;
- a provider's assertion;
- a log re-read.

Every live report MUST also state:

- the note count of the deployment's tree;
- who operated those notes;
- that the run is not evidence of an achieved anonymity set.

Historical state before the M1 reconciliation: **partial**.

- **Specified.** The smoke runbook specifies the direct-RPC table
  (`tools/pool-chipnet-smoke/RUNBOOK.md`).
- **Implemented.** Only the fee-policy reader
  (`tools/pool-chipnet-smoke/read-policy.mjs`, lane only).
- **Missing.** No tool performs or archives the inclusion and unspent
  verification. The wallet side is P12's.

#### Scenario: Relay acceptance reported as inclusion

- **WHEN** a report treats a broadcast's accepted response as inclusion
- **THEN** it MUST be corrected, and inclusion verified by Merkle proof against
  an independently fetched header

#### Scenario: Single index miss taken as spent

- **WHEN** `blockchain.scripthash.listunspent` omits an expected output
- **THEN** the run MUST cross-check with `blockchain.utxo.get_info` or
  `blockchain.transaction.get` before it concludes anything

### Requirement: Every outpoint path is tested in both byte orders on non-palindromic txids

Every code path that reads, writes, compares or signs an outpoint or a token
category MUST have a test on non-palindromic identifiers. Each test MUST show:

- the wire form is the byte reverse of the display form;
- the wire form appears where the transaction or VM expects it;
- the display form appears where Electrum expects it;
- the other order is refused, or does not match, at each place.

An inventory MUST list every such path with its test. A path without a test is
a gap. Palindromic or repeated-byte identifiers MUST NOT be the only fixtures
of any such test. A live run MUST record both forms for each txid it cites.

Historical state before the M1 reconciliation: **partial**.

- **Both-ways tests exist** for the aggregator's located records and the raw
  inputs built from them
  (`packages/reference-aggregator/test/apnt_pool_chain_reads_v1.test.ts`), and
  for the wallet's anchor fold id
  (`packages/reference-wallet/test/apnt_pool_wallet_held_notes_v1.test.ts`).
- **Non-palindromic fixtures** cover genesis categories and outpoints
  (`packages/protocol-runtime/test/apnt_pool_genesis_v1.test.ts`).
- **Missing:** an inventory of every outpoint path. The smoke register's
  byte-order row is unexecuted live.

The module backend shares the multiparty local ledger, whose stated model excludes fee/mempool policy beyond the VMs; full required relay policy is not established. Selected proof digests are checked, not a universal complete-digest reuse scheduler. Both-order test examples exist, but complete current outpoint/category inventory, the required smoke assumption register and stress expectation/observation register are not found in the inspected scope. For every actual live result, exact-byte raw-RPC inclusion, wallet-owned acceptance, endpoint/time and operator/note-count disclosures remain separate obligations. Missing evidence is missing, not zero or a local-VM pass.


#### Scenario: Palindromic fixture only

- **WHEN** an outpoint path's only tests use all-zero or repeated-byte txids
- **THEN** it MUST be counted as untested, because such fixtures cannot tell
  the two orders apart

#### Scenario: Display order where wire order belongs

- **WHEN** a builder places a display-order txid in a transaction input
- **THEN** its test MUST fail, and the reversed form MUST be the one that passes

### Requirement: The multi-party gate confines each party to two channels

The Chipnet ladder is the lifecycle gate ledger; the local ledger supplies regression and firing negatives. Phase 3 M3 is several wallet processes on one machine with complete-workflow measurements and independent review. Every cited run must state the single operator and exact deployment tree note count; it demonstrates construction, not independent-user anonymity. Separate-machine/fresh-restore exercises are deferred and participation engineering is narrowed to spec/paper. M3 remains acceptance work; publication is the separate operator-go launch of repository and FundMe after the pre-launch cleanup gate. No current M3 pass or publication go is established by this reconciliation.


The local multi-party gate (historical-record, task 8.1) MUST run at least three
independently seeded wallets and one aggregator as separate OS processes that
share no files.

- **Channels.** A party MUST learn about another party only through the local
  ledger's read API or the simulated message transport.
- **Bootstrap.** Its other inputs MUST be its own allowlisted bootstrap and the
  frozen public directory.
- **Restore.** A restore MUST run in a new private directory from its seed,
  config and phase file, with ledger access only.
- **Transcripts.** Each server MUST seal every party's transcript, and the
  checker MUST recompute each transcript to its seal.
- **Lifecycle.** The run MUST execute the lifecycle L1 to L8 of
  the internal operations document, with each step's named
  negatives firing.
- **Gate-tier proofs.** Every action and aggregate proof MUST be real.

Passing the gate demonstrates construction properties only. The anonymity set is
degenerate: three wallets and one aggregator, all run by one operator on one
machine. Every citation of the gate MUST say so. Passing is condition (a) of the
publication rule, not a release.

Historical state before the M1 reconciliation: **partial**.

- **Where it is.** The P0 harness and its specification are on main through
  `a443986e` (`tools/pool-multiparty-sim/` and
  the internal operations document). Its party reads adopted
  the reviewed chain-io collector at `c9ef580e`.
- **What runs at P0.** The ledger, transport, sandboxed launcher, sealed
  transcripts and checker run. The P0 boundary passed historical-record; this is not
  an historical-record full-lifecycle pass.
- **Why it cannot pass.** L2, L3, L4, L7 and L8 are placeholders, and L5 and L6
  are partial. The invoice, the intake payload and the verdict are labelled
  stand-ins.
- **Review history.** historical-record and historical-record found P0 boundary defects; historical-record
  passed the corrected P0 slice, which landed on main. A clean gate host is
  still needed.

#### Scenario: Party reads another party's directory

- **WHEN** a party process reads another party's directory or the wallet's
  earlier directory during a restore
- **THEN** the sandbox MUST refuse it, and the gate MUST fail on the recorded
  refusal

#### Scenario: Gate cited without its limits

- **WHEN** the gate's result is cited without the degenerate anonymity set and
  the construction-only scope
- **THEN** the citation MUST be corrected

### Requirement: A disclosure control counts only when its payload is observed

The disclosure checker's result MUST count only with its firing controls. Each
firing control MUST be a separate full run, and its detectors MUST trip only
when its forbidden payload was observed at the receiving end. The observation
MUST be one of:

- the sender's and recipient's transcript records;
- the chain-server transcript record;
- the attempted operation and the kernel's refusal;
- the recipient's retained test marker.

Further rules:

- **Early exits.** A control that exits before its payload is sent MUST NOT
  count as fired.
- **Detector removal.** With a detector removed, its control MUST pass the
  checker. A detector whose removal changes nothing is a finding.
- **Incomplete evidence.** An assertion with an empty needle class or
  incomplete evidence is `not-evaluated`, and `not-evaluated` fails the gate.
- **Full report only.** The gate MUST judge only a full report, with no
  detector, encoding form or reference derivation removed.

Historical state before the M1 reconciliation: **partial**.

- **historical-record.** It found a control that exited before sending its payload
  counted as fired.
- **historical-record.** Its implementation is on main
  (`tools/pool-multiparty-sim/gate/control-witness.mjs`,
  `tools/pool-multiparty-sim/checker/disclosure-checker.mjs`), requires an
  execution witness. historical-record required a correction; historical-record passed the P0
  boundary slice after that correction.
- **Still to be written** (per the gate specification):
  - the payer-to-recipient batch-shape assertion;
  - a second, independent needle search;
  - narrower controls for the redundant ledger rules (historical-record F6).

#### Scenario: Control exits before sending

- **WHEN** a firing control's party exits before its transport send
- **THEN** the control MUST NOT count as fired, and the gate's meta-check MUST
  refuse to count it

#### Scenario: Detector that matters to nothing

- **WHEN** removing a detector leaves every control's result unchanged
- **THEN** the review MUST report it as a finding

### Requirement: The gate tier runs only on a clean host

A gate-tier run MUST refuse to count as evidence unless the operator has
declared both of these, and the launcher's census before, during and after the
run confirms them:

- an isolated host with no unrelated SysV IPC creators;
- a dedicated account.

The run MUST refuse on any of these:

- an unreadable census;
- a process from an unrelated interactive account;
- a census gap above 1000 ms.

A new SysV object MUST fail the gate on any host. The shared development machine
does not meet this precondition.

Historical state before the M1 reconciliation: **partial**.

- **The refusal.** Implemented on main in `pool-multiparty-sim`
  (`tools/pool-multiparty-sim/lib/host-precondition.mjs`), declared through
  `POOL_SIM_EXCLUSIVE_SYSV_HOST=1` and `POOL_SIM_DEDICATED_ACCOUNT=1`.
- **The host.** No clean host is identified. Task 8.1 needs one.

#### Scenario: Gate run on the development machine

- **WHEN** a gate-tier run executes on the shared development machine
- **THEN** its verdict MUST be `refused` for the host precondition, whatever
  its assertions report

### Requirement: Real proofs are reused only by digest

Every piece of real-proof evidence MUST record the digest set it was made under:

- the aggregate guest ELF and its SP1 program key, from the canonical build;
- the action circuit's R1CS and its proving and verifying keys;
- the verifier-graph record, its variant map and the factory pins;
- the proving harness scripts;
- the wrap image, by immutable digest;
- the statement, its public inputs and the proof bytes.

A run MUST re-prove a component only when a digest in its set differs from the
last real-proof evidence. Otherwise it MUST replay the recorded proof and
re-execute its verification. A replayed proof MUST NOT be trusted without that
re-verification. A proof made under a worktree-derived digest MUST NOT enter the
set.

Historical state before the M1 reconciliation: **missing**. The rule is specified
(the internal operations document, operator decision D2). No
code on main or on lane `pool-multiparty-sim` records or compares a digest set
for proof reuse (measured by search).

The module backend shares the multiparty local ledger, whose stated model excludes fee/mempool policy beyond the VMs; full required relay policy is not established. Selected proof digests are checked, not a universal complete-digest reuse scheduler. Both-order test examples exist, but complete current outpoint/category inventory, the required smoke assumption register and stress expectation/observation register are not found in the inspected scope. For every actual live result, exact-byte raw-RPC inclusion, wallet-owned acceptance, endpoint/time and operator/note-count disclosures remain separate obligations. Missing evidence is missing, not zero or a local-VM pass.


#### Scenario: Stale proof replayed after a key change

- **WHEN** the action proving key's digest differs from the one a recorded proof
  was made under
- **THEN** the run MUST re-prove that action and MUST NOT replay the old proof

#### Scenario: Replay without re-verification

- **WHEN** a recorded proof is replayed without re-executing its verification
- **THEN** the run MUST NOT count it

### Requirement: The Chipnet smoke harness runs against its assumption register

The Chipnet smoke run (task 8.2) MUST be driven by an assumption register
written before its implementation. The register
(`tools/pool-chipnet-smoke/ASSUMPTIONS.md`) covers:

- relay standardness and size limits;
- fees and dust;
- unconfirmed chains;
- CashTokens genesis;
- node-VM versus libauth agreement;
- Fulcrum indexing;
- byte order on real txids;
- confirmation and reorganization handling.

The run MUST record each row as confirmed or broken, with its observation, and
MUST name every row it did not execute.

- **Phases.** Phase 1 MUST NOT broadcast, prove or run Setup. Phase 2 MUST
  follow the runbook's order from the main checkout.
- **Secrets.** Keys, seeds and private witness files MUST live only under the
  main checkout's `.local-live/`, mode 0600, and MUST never be printed, logged,
  committed or archived.
- **Funding.** The funding request MUST be derived from the signed
  serializations it covers.
- **Scope.** The run is one operator's labelled zero-value construction test.
  It demonstrates no anonymity set.

Historical state before the M1 reconciliation: **partial**.

- **Where it is.** Lane `pool-chipnet-smoke` at `4b6c6d57`
  (`tools/pool-chipnet-smoke/`), not on main.
- **What is ready.** Bootstrap and genesis candidate building. The task 8.2
  record says its funding output is confirmed; this spec did not re-check it
  on chain.
- **Its three recorded blockers**, at its base `c884d7b2`:
  - aggregate input;
  - the wallet deposit and witness adapter;
  - chain-derived acceptance and fold membership.
- **Since that base, main gained** live single-action aggregate input
  (historical-record), the history collector (historical-record) and held-note status from the
  wallet's own read (historical-record). None of these is on the lane, and none has been
  composed into a smoke run.
- **The deposit row is superseded.** At `4b6c6d57` it plans a `SIGHASH_ALL`
  depositor input. The operator's 2026-09-27 ruling makes the record-keyed
  inbox mandatory for task 8.2 ("P3, deposits hand off through the
  record-keyed inbox").

The module backend shares the multiparty local ledger, whose stated model excludes fee/mempool policy beyond the VMs; full required relay policy is not established. Selected proof digests are checked, not a universal complete-digest reuse scheduler. Both-order test examples exist, but complete current outpoint/category inventory, the required smoke assumption register and stress expectation/observation register are not found in the inspected scope. For every actual live result, exact-byte raw-RPC inclusion, wallet-owned acceptance, endpoint/time and operator/note-count disclosures remain separate obligations. Missing evidence is missing, not zero or a local-VM pass.


#### Scenario: Assumption left unrecorded

- **WHEN** a smoke run ends with a register row neither confirmed nor broken and
  not named as unexecuted
- **THEN** the run's report MUST NOT be accepted

#### Scenario: Fixture replay offered as the smoke settlement

- **WHEN** the fixture B = 1 replay is offered in place of the smoke
  deployment's own settlement
- **THEN** it MUST be refused, because its deployment and statement are not
  that deployment's

### Requirement: The outside tester completes a wallet-owned Chipnet lifecycle

Phase 3 defers active cancellation, fresh-wallet restore, restored-wallet refund and the separate-machine exercise under Scope v2/v3 and plan section 5. Existing expiry/H_cancel refusals and created-home refund remain in scope. RR-10 is partial implementation, not wholly deferred. Seed restore code, counter jumps or retained-home refund do not demonstrate the deferred exercises. Full target cancellation, no-hold recovery, privacy conditions and failure states remain normative and unfulfilled where absent. Found or recovered notes are not thereby accepted or spendable; an unsigned release does not settle cancellation.


The Chipnet ladder is the lifecycle gate ledger; the local ledger supplies regression and firing negatives. Phase 3 M3 is several wallet processes on one machine with complete-workflow measurements and independent review. Every cited run must state the single operator and exact deployment tree note count; it demonstrates construction, not independent-user anonymity. Separate-machine/fresh-restore exercises are deferred and participation engineering is narrowed to spec/paper. M3 remains acceptance work; publication is the separate operator-go launch of repository and FundMe after the pre-launch cleanup gate. No current M3 pass or publication go is established by this reconciliation.


Task 8.3 and MVP-PLAN item 7 MUST be exercised by an independently operated
outside tester on their own machine, with wallets run by at least two
operators. The tester MUST receive a private note in one pool settlement,
restore that note from their seed and chain alone, spend the restored note
onward in a second settlement, and withdraw one note's value to transparent
BCH. Both settlements and the withdrawal MUST be included on Chipnet. The
tester's wallet alone MUST decide acceptance from its own verified chain read
(`apnt-pool-receive-recovery` "Acceptance stays with the wallet").

The tester MUST NOT receive an operator-provided secret, opening or witness.
The harness operator's seed permission for its own simulated wallets MUST NOT
extend to the tester's seed or spend authority. The operator's records MUST
NOT reveal the tester's amounts, notes or which actions belong to the tester
(`apnt-pool-privacy-model` "Submission reveals no more than network metadata").
The run MUST record direct-RPC inclusion separately from the tester wallet's
acceptance. It MUST disclose the deployment's note count and who operated
those notes; it MUST NOT claim an achieved anonymity set from the run.

Historical state before the M1 reconciliation: **missing**. No outside-tester 8.3 lifecycle or its evidence
exists on main at `c9ef580e`. The single-operator P0 simulation and the
one-operator Chipnet smoke run have different gates.

#### Scenario: Tester restore or spend uses operator material

- **WHEN** the tester restores or spends using an operator-provided seed,
  secret, opening or witness, or the operator's records expose the tester's
  amounts, notes or action ownership
- **THEN** task 8.3 MUST refuse the lifecycle as evidence, even if the
  transactions are included

#### Scenario: Included lifecycle without wallet-owned acceptance

- **WHEN** both settlements and the withdrawal are included but the tester's
  wallet has not accepted from its own verified chain read
- **THEN** task 8.3 MUST remain incomplete; inclusion MUST NOT be reported as
  wallet acceptance

### Requirement: A stress case states its expected outcome before it runs

Every case of the Chipnet stress and adversarial run (task 8.4) MUST record its
expected outcome before it executes. The record MUST be committed or archived
with its time. The cases include:

- B up to the measured standard limit;
- contention rebuilds;
- a reorganization across a settlement;
- the fee and relay edges of the verifier transaction;
- concurrent wallets;
- restore under load;
- an inbox refund race.

The observed result MUST be recorded against the expectation. A mismatch is a
finding. The expectation MUST NOT be edited after the run to agree.

Historical state before the M1 reconciliation: **missing**. Task 8.4 has not started. It needs task 8.2.

Phase 3 defers active cancellation, fresh-wallet restore, restored-wallet refund and the separate-machine exercise under Scope v2/v3 and plan section 5. Existing expiry/H_cancel refusals and created-home refund remain in scope. RR-10 is partial implementation, not wholly deferred. Seed restore code, counter jumps or retained-home refund do not demonstrate the deferred exercises. Full target cancellation, no-hold recovery, privacy conditions and failure states remain normative and unfulfilled where absent. Found or recovered notes are not thereby accepted or spendable; an unsigned release does not settle cancellation.


The module backend shares the multiparty local ledger, whose stated model excludes fee/mempool policy beyond the VMs; full required relay policy is not established. Selected proof digests are checked, not a universal complete-digest reuse scheduler. Both-order test examples exist, but complete current outpoint/category inventory, the required smoke assumption register and stress expectation/observation register are not found in the inspected scope. For every actual live result, exact-byte raw-RPC inclusion, wallet-owned acceptance, endpoint/time and operator/note-count disclosures remain separate obligations. Missing evidence is missing, not zero or a local-VM pass.


#### Scenario: Expectation written after the run

- **WHEN** a case's expected outcome is recorded after its run, or edited after
  its run
- **THEN** that case MUST be reported as having no stated expectation

### Requirement: Real proofs run only from the clean main checkout

A real action or aggregate proof, a Setup, or a ceremony step MUST run only from
the main checkout, on branch `main`, with a clean tree. A worktree MUST be
refused.

- **Where pins come from.** Every pinned digest, length or program key MUST be
  derived at the main checkout's path, or by `tools/sp1-canonical-guest-build`,
  which makes the result independent of the checkout path.
- **Refusals.** A pin refusal is information. The pin MUST NOT be edited to make
  a run succeed.
- **Authorization.** Every real proof, Setup or ceremony needs explicit operator
  authorization.

Historical state before the M1 reconciliation: **partial**.

- **Aggregate runner.** It enforces the rule with
  `checkout-is-a-worktree-not-the-main-checkout`, `checkout-is-not-on-main` and
  `checkout-is-not-clean`
  (`tools/apnt-pool-aggregate-sp1/scripts/aggregate-proof-runner.sh`).
- **Action measurement scripts.** `measure-5-1b.sh` records whether it ran in
  the main checkout but does not refuse a worktree. `measure-pk-load.sh` does
  not check (`tools/apnt-pool-action-circuit/scripts/`).
- **No wallet prover** exists to hold to the rule.

The aggregate runner and key-load child-prove harness enforce clean main for proving. The older measurement script records main-checkout status rather than universally refusing a worktree. The operator’s 2026-10-07 historical-record admission policy is 17 GiB for child proves, 20 GiB for B=1–2 aggregates, and at least 20 GiB for larger batches until measured; this is development admission, not consumer fit. The older measurement script and key-load harness permit caller-selected GOMAXPROCS from 1 to 99, so an unconditional four-worker cap is not implemented there. Supervised reap/claim release exists; Docker restart remains an operator step, not a newly verified automated hop. Aggregate memory profiling is pool-owned. This records the existing policy and source differences; it does not grant a new floor, thread cap or gate bypass.


#### Scenario: Proof from a lane worktree

- **WHEN** a real proof is started from a lane worktree
- **THEN** the harness MUST refuse before building or proving anything

#### Scenario: Pin refusal fixed by editing the pin

- **WHEN** a digest refusal is resolved by changing the pinned value
- **THEN** the change MUST be rejected, and the refusal reported as a measurement

### Requirement: One prover at a time behind a memory gate

On the development machine every real prover MUST:

- **Lock.** Take the machine-wide prover lock (`flock`) for its whole run, and
  refuse while another known prover runs or while any prover marker exists. A
  stale marker blocks and never admits.
- **Memory.** Refuse unless about 20 GiB is available, measured as free,
  inactive and speculative pages from `vm_stat`. It MUST measure again
  immediately before the prover starts.
- **Swap.** Gate on swap growth from the run's own baseline, never on used
  swap, and stop the run on a stated swap-growth or RSS trip.
- **Threads.** Cap parallelism with `RAYON_NUM_THREADS=4`,
  `CARGO_BUILD_JOBS=4` and gnark `GOMAXPROCS=4`, and run under `nice`.
- **Interrupts.** Re-check memory before any retry.

Action proving MUST NOT overlap aggregate proving.

Historical state before the M1 reconciliation: **partial**.

- **Aggregate runner.** 20 GiB admission, measured again after the runner
  build, with a 30 GiB RSS trip and a 16 GiB swap-growth trip, under the shared
  lock
  (`tools/apnt-pool-aggregate-sp1/scripts/aggregate-proof-runner.sh`).
- **Action measurement.** `measure-5-1b.sh` has the same 20 GiB floor and trips
  under the same lock. `measure-pk-load.sh` takes the same lock, but reads its
  floor per case from its plan in whole GiB, and trips at 8 GiB of swap growth
  or 24 GiB of RSS (`tools/apnt-pool-action-circuit/scripts/`). A plan can
  therefore run a real prove below the 20 GiB floor.
- **Not covered.** A wallet's own prover is outside this gate ("The hardware
  floor is stated per role and kept apart from the development gate").

The aggregate runner and key-load child-prove harness enforce clean main for proving. The older measurement script records main-checkout status rather than universally refusing a worktree. The operator’s 2026-10-07 historical-record admission policy is 17 GiB for child proves, 20 GiB for B=1–2 aggregates, and at least 20 GiB for larger batches until measured; this is development admission, not consumer fit. The older measurement script and key-load harness permit caller-selected GOMAXPROCS from 1 to 99, so an unconditional four-worker cap is not implemented there. Supervised reap/claim release exists; Docker restart remains an operator step, not a newly verified automated hop. Aggregate memory profiling is pool-owned. This records the existing policy and source differences; it does not grant a new floor, thread cap or gate bypass.


#### Scenario: Second prover while one runs

- **WHEN** a prover starts while the machine-wide lock is held
- **THEN** it MUST refuse, never queue or wait

#### Scenario: Admission on used swap

- **WHEN** a gate admits or refuses on the machine's used swap, not the
  run's swap growth
- **THEN** the gate MUST be corrected, because macOS never shrinks its swap file

### Requirement: Prover process trees and containers are reaped

Every exit of a prover run MUST reap the prover's whole process tree and every
wrap container, in any state. That covers success, refusal, prover failure, a
trip and a signal. Only after a listing confirms that none is left MAY the run
remove its markers and release its lock. An unconfirmed reap MUST keep the
markers, which blocks later runs, and exit with `prover-reap-unconfirmed`.

The Docker VM keeps memory after a wrap. Docker MUST therefore be restarted
between wraps, and between an action proof and an aggregate proof, and memory
MUST be measured again after the restart.

Historical state before the M1 reconciliation: **partial**.

- **Reaping.** Implemented in `tools/apnt-pool-aggregate-sp1/scripts/prover-supervision.sh`
  (historical-record, historical-record).
- **Docker restart.** Not automated. No pool proving script restarts Docker
  (measured by search). It is an operator step in the smoke runbook, and the
  runner checks only the VM's configured size.

The aggregate runner and key-load child-prove harness enforce clean main for proving. The older measurement script records main-checkout status rather than universally refusing a worktree. The operator’s 2026-10-07 historical-record admission policy is 17 GiB for child proves, 20 GiB for B=1–2 aggregates, and at least 20 GiB for larger batches until measured; this is development admission, not consumer fit. The older measurement script and key-load harness permit caller-selected GOMAXPROCS from 1 to 99, so an unconditional four-worker cap is not implemented there. Supervised reap/claim release exists; Docker restart remains an operator step, not a newly verified automated hop. Aggregate memory profiling is pool-owned. This records the existing policy and source differences; it does not grant a new floor, thread cap or gate bypass.


#### Scenario: Wrap after a wrap without a restart

- **WHEN** a second wrap is started without a Docker restart since the first
- **THEN** the run MUST refuse, or the harness MUST restart Docker and measure
  memory again before proving

#### Scenario: Reap unconfirmed

- **WHEN** the reaper cannot confirm that no prover process or container is left
- **THEN** it MUST leave the markers in place and exit with
  `prover-reap-unconfirmed`

### Requirement: Pool tooling depends on no seal-era package

No pool harness, prover script or entry point MAY load code or data from a
seal-era package or tool that is scheduled for retirement. Anything it needs
from such a package MUST first move to a pool-owned location, so that a
retirement lane cannot break the pool.

Historical state before the M1 reconciliation: **missing**. The aggregate runner loads SP1's M1 memory profile
from `tools/apnt-successor-aggregate-sp1/memory-measure.py`
(`tools/apnt-pool-aggregate-sp1/scripts/aggregate-proof-runner.sh`). That is a
seal-era tool.

The aggregate runner and key-load child-prove harness enforce clean main for proving. The older measurement script records main-checkout status rather than universally refusing a worktree. The operator’s 2026-10-07 historical-record admission policy is 17 GiB for child proves, 20 GiB for B=1–2 aggregates, and at least 20 GiB for larger batches until measured; this is development admission, not consumer fit. The older measurement script and key-load harness permit caller-selected GOMAXPROCS from 1 to 99, so an unconditional four-worker cap is not implemented there. Supervised reap/claim release exists; Docker restart remains an operator step, not a newly verified automated hop. Aggregate memory profiling is pool-owned. This records the existing policy and source differences; it does not grant a new floor, thread cap or gate bypass.


#### Scenario: Retirement lane deletes a pool dependency

- **WHEN** a seal retirement lane deletes a file that a pool proving script loads
- **THEN** the pool's own tests MUST fail on the retirement lane before it can
  be promoted

### Requirement: Harness gaps are closed under named tasks

Each gap below MUST close under the task or item named, or be re-scoped by the
operator. Closing a gap MUST re-measure the requirement it belongs to. The
table starts from the `47ba43b3` snapshot and incorporates the measured
`c9ef580e` delta above.

| Gap | Requirement | Task or item |
|---|---|---|
| Complete installed role executables, LIMITS and per-role hardware/reproduction evidence; bins alone are insufficient | "Role entry points are declared executables"; "The hardware floor is stated per role and kept apart from the development gate" | MVP-PLAN item 5; task 7.2 |
| Complete verifier-graph regeneration without external absolute-path defaults | "Role entry points are declared executables"; P8 | MVP-PLAN item 5; task 5.4 |
| Wallet-local native prove path; live witness adapter exists but does not close the launcher | P2 | task 5.1b's wallet integration (historical-record); task 8.2 blocker 2 |
| Inbox implementation is present; complete current inbox lifecycle/negatives remain evidence obligations; direct depositor-input routes stay prohibited | P3 | task 3.6 as generalized by historical-record; task 6.1 (historical-record, historical-record); inbox-only deposits before tasks 8.1 L2 and 8.2 |
| Live-bN admission exists; complete current aggregate/lifecycle proof evidence is not established here | P6 | task 5.4; tasks 8.1 and 8.2 |
| Factory audit binding exists (historical-record); verifier construction/reproduction/acceptance evidence remains distinct | P8; P9 | task 5.4 (historical-record, historical-record, historical-record); before task 7.3 and task 8.2 |
| Anonymizing reads/submission and integrated self-settlement absent | P1; P4 | tasks 4.3 and 6.1 |
| Current two-lock locator/assembly evidence must be carried with the implemented source, not presumed from the old row | P5 | task 6.1 (historical-record) |
| Explicit fold builder exists; automatic waiting-wallet fold/liveness integration remains qualified | P11 | task 6.1; task 8.2 |
| Broadcast and direct-RPC tools exist; missing local-VM aliases and current bound live acceptance evidence remain | P10; "Live evidence keeps three results apart" | task 8.2 |
| Shared local backend exists; complete fee/dust/size/relay model remains unestablished | "One local dual-VM ledger serves every local harness" | tasks 8.1 and 8.2 |
| Complete both-byte-order outpoint/category path inventory absent | "Every outpoint path is tested in both byte orders on non-palindromic txids" | task 8.1; task 8.2 live |
| Complete current gate-tier lifecycle/firing controls, independent review and clean-host evidence not supplied here | the three gate requirements | task 8.1 |
| Universal complete-digest proof reuse scheduler absent beyond selected digest checks | "Real proofs are reused only by digest" | task 8.1 |
| Required current smoke assumptions/observation register absent | "The Chipnet smoke harness runs against its assumption register" | task 8.2 |
| Outside/independent-operator lifecycle target unfulfilled; Phase 3 separate-machine/restore exercise deferred with scope authority, not erased | "The outside tester completes a wallet-owned Chipnet lifecycle" | task 8.3; MVP-PLAN item 7 |
| Current stress expectation/observation register absent; restore/refund subcases separately deferred | "A stress case states its expected outcome before it runs" | task 8.4 |
| Universal clean-main coverage, worker cap and automated restart remain qualified; 17 GiB child floor has existing authority | "Real proofs run only from the clean main checkout"; "One prover at a time behind a memory gate"; "Prover process trees and containers are reaped" | task 5.4; task 8.1's proving window |
| Specific aggregate seal-era memory dependency is removed; package-wide retirement/dependency evidence remains scoped | "Pool tooling depends on no seal-era package" | seal retirement (task 0.9), before that package's lane |
| Interim tag-fill claim is historical; no complete cross-role export/detector closure follows from that correction | "Each role has a declared holding boundary"; P2 | task 4.1 (historical-record, historical-record) |
| Measured anchor/window/fold policy remains open | P1; P11 | task 1.4 (D4) |
| Most modules exist; withdraw and complete user-action coverage remain pending | "Each stage and user action is an independently invokable module" | tasks 8.1 and 8.2 (historical-record) |
| Full targeted/deep-scan command coverage and truthful current disclosure remain missing | "A targeted rescan and a per-epoch deep scan find mis-tagged payments"; "Residuals are disclosed" | task 4.2; disclosure task 7.2; existing historical-record proposal |
| Deployment provenance binding explicitly UNMET at M1; operator choice pre-mainnet | "Registry entry 1 is gnark Groth16 on BN254" (provenance); "No setup holder guards pooled value" | historical-record; historical-record folded into it |

#### Scenario: Gap closed without re-measuring

- **WHEN** a gap is reported closed without re-measuring its requirement's
  current state at the closing commit
- **THEN** the closure MUST NOT be recorded
