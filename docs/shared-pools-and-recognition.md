# Shared pools, competing pools and reference-pool recognition

Draft for comment. This is analysis and a documentation proposal, with no provider-integration or other engineering commitment. Comments belong in the thread on the [Bitcoin Cash Research forum](https://bitcoincashresearch.org).

Zero-value research only. The action setup is simulated and run by the project, so the project could forge proofs and take pooled backing. Recognizing the intended deployment does not remove that exposure or the separate external wrapper-setup dependency.

## Shared participation and competing deployments

Joining one verified deployment means using its note tree, nullifier-state lineage, covenant backing and proof stack. Root copies expose the same authenticated root; they are not separate pools. Different products can share that history while retaining separate wallet secrets, interfaces and service providers. No account, shared user key, identity enrollment or delegated custody is needed to join.

A spend's structural candidate set is bounded by the notes folded before the root it actually uses. Unfolded outputs do not belong to that set. Tree leaves include dummy slots and spent history; a leaf count is not a count of independent users or achieved anonymity. An older root narrows the bound. Separate deployments running the same source do not combine their trees or users.

| Choice | Shared material | Consequence |
| --- | --- | --- |
| Another product uses the same authenticated deployment and history | Same tree, category state, backing and setup exposure | Same structural candidate set; compatible, independent participation still needs evidence |
| A byte-identical complete artifact and genesis are mirrored | Description of the same chain objects | Same pool once history is authenticated; another URL or rebroadcast adds no users or anonymity |
| The same construction/verifier uses fresh categories and genesis | Code and possibly proof parameters | Different deployment with an empty initial tree; no inherited notes, backing, users or achieved privacy |
| A different key, circuit, aggregate program or covenant is used | Possibly design and build methods | Needs its own reviewed bindings; changed verifier/covenant bytes are unsupported by this release, without implying invalidity under every possible release |
| A different aggregator, relay or chain endpoint serves the same verified history | Same pool objects | Service choice alone does not select another pool; wallet verification and privacy requirements remain |

Current Chipnet verifier support uses the pinned simulated proof stack. A new genesis need not inherently require a new ceremony, but reusing the stack also reuses its setup exposure. A matching profile or empty root alone cannot identify a deployment. Migration is a public boundary between pools, does not merge their histories, and cannot recover backing already stolen from an unsound predecessor. No runnable migration demonstration is claimed here.

## Wallet and provider participation

Shared compatible activity can improve the structural candidate set and may spread aggregation, verification and folding costs over more actions. Those are incentives and cost hypotheses, not measured prices, throughput or privacy. Delays, contention, failures and service margins can outweigh nominal scale benefits.

Wallets, merchants and services choose whether to use the same deployment. Provider competition can concern reliability, fees, turnaround and metadata handling without moving users to a different tree. An aggregator's refusal must not become custody or a protocol veto; practical fallback has its own proof and chain resources. No interoperable provider market or maintained integration library is delivered by this analysis.

Adoption does not prove soundness, honest setup, independent users or careful wallet behavior. A safer successor may justify fragmentation. Optional amount shielding, identity-based admission and custodial shortcuts are not acceptable ways to compete. Identity/linkage and amount shielding remain required together.

The covenant construction uses current BCH rules. A possible future native pool is separate research; no consensus activation, exact native design or automatic migration of existing histories is promised. Native verification alone does not decide whether products share one tree.

## What sharing a tree does not hide

Public transaction shapes, action/batch counts, nullifier/commitment grouping, fees, deposits, exits, funding ancestry, timing, retries and root age remain correlators. Repeated invoice tags can be recognized, but copied tags and collisions mean equality is not proof of common ownership. Invoice holders and participants know their own payments. A known payment/change builder can reveal the companion output's planned change role without revealing its amount or later spend key.

The planned Phase 3 several-wallet run is on one machine under one operator, with zero-value coins and simulated setup. Its exact wallet count, root/height, folded leaf count, real/dummy/spent census and ownership boundary must come from that run. They are not measured by this document; no historical slot count substitutes for them. See the [threat model](threat-model.md).

## Recognition draft for comment

“Reference” means the deployment a product or user explicitly selected as its default. It is not a consensus title, endorsement by an aggregator, or proof that other products chose it. A wallet's existing selection cannot silently change because of an invoice, endpoint or recommendation.

The proposal below is a verification description, not an implemented feature, new artifact format, operator command or runnable screen. A hash authenticates no recommendation if the expected hash arrives with the substituted bytes. Initial software/default selection remains a supply-chain and social-choice boundary.

### Keep the identities distinct

| Identity | What it identifies | What it does not establish |
| --- | --- | --- |
| Pool semantic version | Statement and encoding contract | Unique deployment or implementation conformance |
| Deployment identifier | Domain, network and category tuple using canonical host semantics, including the retained zero meter slot | Every genesis byte, parameter, proof key or social endorsement |
| Category identifiers and genesis transaction IDs | Distinct category-genesis and transaction roles, with explicit wire/display order | Inclusion or confirmations from a supplied claim alone |
| Covenant code and locking bytecode | Exact parameterized deployed rules; P2SH32 uses HASH256 of redeem code | A generic source hash does not identify every lock; SHA-256 code metadata is a different check |
| Proof profile | System and exact canonical verifier parameters, under the aggregate allowlist and verifier path | Same pool, correct setup, honest erasure or sound circuit |
| Complete release/deployment record digest | Proposed binding of a versioned canonical record and all required dependencies | No complete canonical artifact encoding or such binding is selected by this draft |

The provenance requirement remains unmet: current deployment-artifact fields and transitive source/program/factory pins do not establish the required artifact-carried transcript digest and provenance label. A warning string or profile hash is not that evidence. A new artifact revision, an authenticated enclosing manifest, or an amended normative transitive binding remains a separate pre-mainnet choice. This document chooses none and changes no frozen hash preimage, schema or pin.

### Proposed checks

1. Fix the intended network, deployment, complete selected artifact, genesis references and checkpoint from reviewed local configuration before accepting candidate data. Preserve an existing wallet's choice.
2. Use the owning canonical helpers to check the record, category byte order, dependency bytes and supported parameters. A future complete-record digest first needs one chosen, versioned canonical encoding; do not introduce a second hash/codec or silently add fields to a closed schema.
3. Obtain authenticated raw genesis transactions, inclusion and sufficient confirmations on the selected network. Supplied transaction IDs and a server's validity flag are not independent chain evidence. Reorganizations invalidate cached context.
4. Audit the entire category supply and confinement, empty initial tree, range/root/factory state and exact parameterized covenant locks against reviewed builds. A trial payment cannot authenticate a deposit inbox.
5. Connect the actual verifier-parameter bytes to the child/profile, aggregate, verifier and factory bindings, and obtain/check public setup and CRS evidence for every setup-backed layer. Matching an identity does not prove soundness or close the provenance gap.
6. Keep recognition separate from payment acceptance. Before funding, derive and check the actual record-specific canonical inbox locally. Later receipt acceptance, recording, persistence and spendability still require the wallet's own evidence and policy.

Required public dependency bytes must be obtainable; a digest cannot replace them. If required material or chain evidence is missing, the result is unverified/unavailable. A distributor can authenticate a recommendation without gaining a spend key or authority to rewrite an existing wallet's selection. No mandatory registry, lookup server, membership credential or online approval is proposed. A protocol proof-system registry is a system/encoding table and allowlist, not a wallet-identity or deployment-election service. Optional transport identifiers never become reusable recipient markers or pool identity.

### Open questions for comment

1. Phase 3's runs use one Chipnet deployment, named in the repository. Should it also serve as the reference for other products? That is not selected here.
2. What single canonical encoding should bind a complete deployment record, and how should its proof-system provenance be bound?
3. How should a new product authenticate its initial default and later recommendations without a mandatory project server?
4. Which proof/setup bytes and independently checkable evidence must be available before a product trusts a deployment?
5. What chain-currentness and confirmation policy should apply to recognition and later use?
6. How should each run report the root-specific note counts, wallet counts and who operated all notes?
7. What compatibility, deprecation and migration policy should apply when several products use the pool?

None is closed by this draft. The [acceptance criteria](acceptance-criteria.md) keep publication for comment and implementation separate.
