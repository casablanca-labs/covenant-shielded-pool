# Acceptance criteria

This is the Phase 3 release contract and current delivery status at launch. Requirements say what must ship; they are not implementation claims. The [release evidence map](release-contract.md) links each obligation to a candidate artifact or explicit gap. These documents do not establish a live workflow.

## Milestone 1: release description and specification

| Requirement | Current status and evidence |
| --- | --- |
| Describe the construction, supported environment, dependencies and implementation gaps | [Overview](overview.md) and [how the pool works](how-the-pool-works.md) present; current source is a partial baseline |
| Publish the frozen protocol text with only approved non-normative edits and both full SHA-256 digests for each file | [Specification index](spec/README.md) present: all ten specification files, complete original/published digests and the changed-line list |
| Publish the threat model, retaining mandatory shielding, wallet authority, setup limits and broadcast authorization | [Threat model](threat-model.md) present; amended documentary analysis, no new independent PASS or live validation inferred |
| Publish shared/competing-pool and wallet-provider analysis and the first recognition draft for comment | [Draft](shared-pools-and-recognition.md) present, with seven open questions and the Bitcoin Cash Research forum as the comment venue; the thread link is added when posted |
| Identify completed work, remaining work and scope/dependency changes | This document and [evidence map](release-contract.md); Phase 1/2 [approved close-outs](phase-1-and-2-closeout.md) carried without reopening them |
| Ship release identity verification with wrong-profile and wrong-network controls | `pnpm check:identities` present; the [README](../README.md#check-the-release-identities) states its circuit, action verifying key and profile, reference covenant, aggregate digest and program VKey coverage, and what it leaves unrun |

The approved spec edits are non-normative: internal-document references become public descriptions and a named test-wallet reference is generalized. The spec owner must list every changed line and the complete original/published SHA-256 for each affected file. There are 14 approved lines in four files, plus three generic-literal lines requiring individual scan admissions. A change to a MUST/SHOULD/MAY, condition or outcome is forbidden under that allowance. Private record identifiers are private work-record labels, not protocol values. An abbreviated digest or older launch-copy draft cannot substitute for the later normative freeze.

## Milestone 2: a private send

A deposit, its receipt and a payment from Alice to Bob must complete on the declared environment using supported commands and wallet interfaces, without manual wallet-state edits, copied journals, synthetic wallet-home conversion or imported acceptance. Current status: in progress; no completed M2 run is evidenced by these documents. A later commit carries the M2 evidence and guide, under the [rules for every posted run](#rules-for-every-posted-run).

## Milestone 3: an onward payment

Bob reloads the received note and spends it to pay Charles, and Charles's wallet accepts from its own read, under the same rule on supported commands and manual edits.

| Requirement | Current status |
| --- | --- |
| In a new run, three separately generated wallet processes on one machine under one operator complete a deposit and both payments | Planned; no run or counts supplied by these documents |
| Verify network acceptance/inclusion for every submitted transaction and retain distinct wallet/lifecycle outcomes | Planned; direct-RPC evidence required |
| Post proving time, memory and fees as measured, with other recorded transaction/confirmation/spendability costs clearly labeled | Pending; a missing measurement is missing, never zero; no proving-performance target is added |

## Milestone 4: the exit and verifiable release

In the same run, Charles exits: a private note is paid out to an ordinary BCH address through the supported wallet route, and that payout is spent with Electron Cash, under the same rule on supported commands and manual edits.

Each refusal needs a valid control, an independently constructed invalid input reaching its own boundary, the exact code and evidence that no forbidden effect occurred. An earlier parse failure or generic wrapper error does not count. The following names are frozen from the development source for the refusal work; their presence is source evidence only, with execution controls still required:

| Boundary | Exact source-backed code | Required observation |
| --- | --- | --- |
| First payment build at or after invoice expiry | `pool-module-p2-invoice-expired` | Refuse before journal writes, signing or handoff; no broadcast |
| Invalid owner signature on an otherwise admissible action | `pool-intake-owner-signature` | Reach signature verification; a malformed record is not this negative control |
| Failed action-proof verification | `pool-intake-action-proof` | Reach the verifier with otherwise valid shape/profile; verifier unavailability is a different refusal |
| Repeated nullifier within one statement | `pool-statement-duplicate-nullifier` | Reach the statement's duplicate test; it does not prove rejection of a previously spent nullifier |
| Nullifier already inserted, or incomplete history at intake | `pool-intake-nullifier-inserted-or-history-incomplete` | Independently establish complete valid history and the spent nullifier; isolate replay from the code's other history-failure cause |
| Stale anchor under selected intake/settlement policy | `pool-intake-stale-anchor-policy` | Reach the actual age-policy test with valid authenticated history; an unavailable anchor is different |

The settlement harness can wrap an owner refusal as `pool-module-p10-settlement-refused`; retain its underlying cause as well. The prior-payment check is specified but not demonstrated in Phase 3. No runtime control is claimed from copying a code name into this table. The [source/evidence map](release-contract.md#refusal-source-boundaries) records the boundary distinctions and which sources are absent from this snapshot.

| Requirement | Current status |
| --- | --- |
| Publish a walk-through-and-verify utility that rechecks each published proof and transaction as the network did | Pending; Sage-themed read-only replay, no wallet actions or wallet-state changes |
| Reproduce the released replay plus declared local regressions on a clean 16 GB machine, using public repository inputs only | Pending; no coins, no fresh proof, no withheld validation dependency; never describe this as rerunning the live lifecycle |

The tagged release must contain installation/reproduction instructions, the complete identity verification tools, required test vectors, transaction references, safe recording/replay, limitations and versioned technical reports, and sufficient source/artifacts to check the claims under MIT without a withheld validation dependency. Each role's README states its hardware floor. Full re-proving is distinct from the 16 GB replay and requires about 20 GB available memory and actual proving admission.

The limitations report covers proof-dependent custody, no deposit cap, inability to rescue already stolen predecessor backing, two records per action, K root copies per fold, the thin one-action self-settlement timing cohort, irrevocable signed actions, public boundaries and shape/count/fee/timing correlation. It names both simulated action setup and external wrapper setup, with wrapper assurance unverified.

The technical report binds its exact release and supporting recording/replay/measurement artifacts. It explains the construction, payment/conservation rules, threat model, setup assumptions, exit, measured costs and remaining scaling questions, includes shared-pool/provider analysis without new engineering commitments, and identifies deferred demonstrations. Every result is labeled live run, local execution, model or external source. Three-or-more funded transfers in one batch remain specified but not demonstrated.

The final report maps every campaign commitment to its artifact and review result, retaining missing evidence and original verdicts honestly. Every export and the final tagged tree must be free of real secrets and private user data. Exact candidate/approval matching, real-secrets reconciliation and required fresh-clone, N1/restoration and pre/post-push validation remain with the publication owner. No source or document completion clears those prerequisites.

## Rules for every posted run

These apply to Milestones 2, 3 and 4.

| Requirement | Current status |
| --- | --- |
| Post transaction IDs and a safe recording once code is public, limited to that milestone's files | Pending real run and actual publication. No private values or payment links may be posted. One exception: ownership labels and payment links for the project's two demonstration runs may be published, before anyone else joins this deployment. Those notes are excluded from everyone else's anonymity sets. All secrets and private note amounts stay private; no other notes are labelled. |

Spending secrets must stay within the wallet. No witness, key, seed or opening may be a public evidence artifact, and no private payment link may be either, apart from the one exception above.

Run records separately state relay acceptance, authenticated direct-RPC chain inclusion, wallet acceptance, recording, persistence across a normal reload, current spendability and actual spending. A held note must state whether it is currently spendable and whether it was spent. Neither a txid nor an opened packet proves the later stages.

Every posting that cites a run carries four disclosures: one operator ran every wallet; coins are zero-value; setup was simulated so the project could forge proofs; the anonymity set is tiny. Also give the actual deployment/root, folded leaf count, wallet count and who operated all notes. Leaf count includes dummy/spent history and is only an upper bound on uncertainty.

## Later phases

This check belongs to later phases, along with hardening the pattern. For every declared output sink, plant synthetic private amounts and synthetic recovery material, show the detector rejects them, remove the detector in a scratch control and show the planted case then passes undetected, and show the corrected real output passes. Include literal and derived-digest carriers: hashing a small private tuple is not concealment.

| Required sink family | Current export's runtime coverage |
| --- | --- |
| Standard output and standard error | Uncovered by this document work |
| Inter-process replies and handoffs | Uncovered by this document work |
| Reports and support output | Uncovered by this document work |
| Error messages | Uncovered by this document work |
| Archives and recordings | Uncovered by this document work |
| Results view and replay output | Uncovered by this document work |

The runtime owner must replace each uncovered entry with exact source/run/control evidence or retain it as a gap. A document secret scan covers only selected document bytes, not those runtime sinks.

## Retained requirements and retired process

Retained: the M1–M4 deliverables above; truthful source/status distinctions; identities checked rather than described as reproduced by comparisons alone; M4 refusal controls and later-phase planted-leak controls; the postings for M2, M3 and M4, with measurements and disclosures; clean 16 GB no-proof replay at M4; role hardware floors, complete MIT source/inputs, limitations/technical reports, final commitment map and no-secret requirements. Known Major findings need their specific corrections and evidence before outward delivery/final release. One ordinary asynchronous source review remains; it is not a source-landing readiness gate.

Retired: fixed pre-main gate order, non-producer acceptance as a landing gate, independent validation-run review as a public precondition, protocol/harness/store freeze tags and freeze-preserving process, dated-one-commit-per-export, parity/exact-choice ceremony, and consumer-hardware wallet proving as Phase 3 acceptance. A static capture does not replace the real recording and verification utility. An outside cryptographic audit is not a new Phase 3 precondition; this does not remove the required clean-machine replay or safe-publication checks.

No launch date or campaign wording is selected here. Scope changes must be reflected in this contract and the next campaign update before the next export. An incomplete milestone cannot be labeled complete; actual revised outward wording remains a separate decision.
