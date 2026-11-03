# Covenant Shielded Pool overview

Covenant Shielded Pool is a shielded pool built with covenants that runs under current Bitcoin Cash rules with no consensus change. The intent is public review, then eventual adoption into consensus by Bitcoin Cash nodes through the community CHIP process and node implementations. No adoption or activation date is promised.

This research release supports zero-value BCH Chipnet use. The protocol's specification name is APNT shielded pool v1. It is a target contract: source presence, a specification requirement and a successful live workflow are different evidence.

## Construction and custody

Earlier designs associated each private note with particular backing outputs, allowing someone who knew those outputs to recognize a later spend. This construction separates a note from any particular backing coin. Notes commit to private values and ownership; token-free pool coins hold interchangeable backing, with authenticated note-tree and nullifier history.

Identity/linkage shielding and amount shielding are required together by default. Private input-to-output correspondence, ownership assignments, change ownership and nonreusable recipient material remain requirements. Aggregation is the normal path; direct self-settlement is an exit or fallback with extra resources and a thinner timing cohort. Wallets keep secrets, spending authority and their own acceptance decisions. An aggregator, prover, relay or deployment publisher gets no delegated spending authority.

Pooled-value custody rests on the soundness of the complete proof/verifier pipeline and its covenant binding. Owner signatures and BCH conservation do not stop counterfeit notes admitted by an unsound proof system. The simulated single-party action setup lets the project forge proofs and potentially withdraw all pooled backing. The external aggregate-proof wrapper is a separate setup dependency whose assurance is unverified here. See the [threat model](threat-model.md) and the released [custody specification](spec/apnt-pool-settlement-custody/spec.md).

## Supported environment and dependencies

Only zero-value Chipnet research is supported. The action setup is simulated and single-party. No mainnet or real-value use is authorized by this release. The planned several-wallet demonstration uses separate processes on one machine under one operator; it establishes no privacy among independent people or hostile processes sharing that user's operating-system identity.

The JavaScript baseline declares Node 20.19.4 and pnpm 9.0.0. The [README](../README.md#build-and-check) gives the existing no-proof check command, its coverage and the unverified legacy Node declaration. [Proof-material acquisition](rehearsal/proof-material-acquisition.md) gives the selected native toolchains and builds. A build or identity comparison is not a newly generated proof or a live lifecycle result.

External dependencies for the planned demonstration include a reachable Chipnet node and authenticated chain reads, operator-funded zero-value Chipnet coins, selected public proof/verification material and setup evidence, qualified native toolchains, one admitted prover on a machine with about 20 GB available memory, and a separate clean 16 GB machine for the released replay and local regressions. The 16 GB demonstration uses no coins and performs no proving. Machine availability, live endpoints and proving duration need actual evidence; this document reserves none of them.

Development happens in a private working repository. Selected source and evidence follow here by milestone, with the harness at Milestone 3. Each publication requires the required tests, secret and private-path checks and a publication decision.

Milestone numbers in the frozen specification predate the campaign's final milestones. The campaign and `phase3/README.md` give the current numbering. Commit hashes cited in the specification index, relabel ledger and export manifest refer to private development history that isn't in this repository.

## Wallet workflow across Milestones 2 to 4

1. Select and verify the intended network, deployment, genesis and proof stack before funding a locally derived canonical deposit inbox. A supplied address or trial settlement cannot authenticate a lookalike inbox.
2. Deposit, discover and open the intended received note, and accept it using the wallet's own authenticated settlement and fold evidence.
3. Construct and authorize a payment through the pool, from Alice to Bob, while keeping witnesses and spending secrets in the wallet's authority boundary. The current development harness's operator-run proving is not a private third-party proving service or wallet-launched native proving.
4. Bob reloads the received note and pays Charles, whose wallet accepts from its own read.
5. Exit through the supported wallet route. Record inclusion, acceptance, recording, persistence after normal reload, current spendability and actual spending separately.

Steps 1 to 3 are Milestone 2, step 4 is Milestone 3 and step 5 is Milestone 4. The workflow must use supported commands and interfaces without manual wallet-state edits, copied journals or imported acceptance. Expired invoices and invalid, duplicate and stale inputs must be refused at their own boundaries. The [acceptance criteria](acceptance-criteria.md) define the required controls. This document supplies no new live command and claims no completed M2 run.

## Current evidence and remaining work

| Area | Evidence in this source baseline | What remains |
| --- | --- | --- |
| Canonical semantics and custody | Protocol-runtime source, statements, tree/frontier/range helpers, transaction codec, genesis and covenant source; custody specification | Source presence does not certify host/circuit/verifier equivalence, proof soundness or a supported live lifecycle |
| Public checks | Existing JavaScript check command and selected native acquisition/build instructions | Only executed commands count; missing-input, excluded and unrun native coverage stay explicit |
| Frozen specification | [Specification index](spec/README.md): the proposal and nine capabilities, approved non-normative edits, complete original/published digests and changed-line list | Requirements are target text, not implementation claims |
| Release identities | [Identity manifest](../identity-manifest.json) and `pnpm check:identities`: public circuit metadata, published action verifying-key bytes and profile, reference covenant reassembly, aggregate digest/program VKey records and wrong-profile/wrong-network controls | Actual R1CS/ELF byte hashing and regeneration, program VKey derivation, installed-runtime checks and setup qualification remain unrun by this command |
| Wallet/aggregator/harness lifecycle | Development work and selected lower-level source | The private send at Milestone 2, the onward payment and harness at Milestone 3, and the exit and refusal controls at Milestone 4, each with its selected export; no complete wallet/aggregator/harness integration is supplied by these documents |
| Recording and independent replay | Requirements in the acceptance criteria | New three-wallet Chipnet run, safe recording, direct-RPC inclusion evidence and measurements at Milestone 3; verification utility and clean 16 GB replay at Milestone 4 |
| Release and recognition | These documents and the recognition proposal | Public posting for comment, final technical/limitations reports, commitment map, exact release artifacts and authorized publication |

The [release contract](release-contract.md) maps every milestone obligation to a path or explicit gap. It is the current index of delivery status; the frozen protocol requirements retain their meaning independently of that status.

## Scope and future research

Phase 3 does not promise a separately operated multi-machine experiment, seed-only recovery into a fresh wallet, active cancellation, maintained provider integrations, independently developed cross-wallet interoperability, or settling three or more funded payments in one batch. That batch is specified but not demonstrated. A normal wallet reload is not a fresh-wallet restore. Encrypted recovery remains required; deferred demonstrations do not authorize weakening it.

Consumer-hardware proving, consensus adoption through a CHIP and node implementations, a production ceremony and mainnet are future work. The 16 GB obligation is verification/replay and declared local regressions, with no proving. Shared-pool economics and provider participation are [analysis](shared-pools-and-recognition.md), with no new engineering commitment. Phase 1 and Phase 2 are [closed](phase-1-and-2-closeout.md).

The acceptance criteria describe the campaign scope and remaining work. These documents promise no launch date.
