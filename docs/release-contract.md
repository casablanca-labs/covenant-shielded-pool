# Release contract and evidence map

This map covers the Phase 3 M1–M4 deliverables and their current state at launch. “Present” means the named artifact exists here. “Gap” means the obligation remains undelivered or lacks the specified evidence. Requirements do not become implementation claims.

The baseline contains selected protocol/proof/verifier source. The release identity manifest covers published circuit metadata, action verifying-key bytes and profile, reference covenant bytecode and aggregate build identities. The frozen specification index preserves original/published digests. `export-manifest.json` remains the historical v0.5.0 composition record; it does not describe the inventory or validation of forward public edits. The [publication relabel ledger](../publication-relabel-ledger.json) records the public parent and exact old/new file fingerprints for this relabelling. The canonical publication target has no direct-public-parent forward-snapshot mode, so its historical origins were preserved. The [README](../README.md) names supported checks and their limits.

Some frozen data and source files were relabelled for publication: local build paths, internal folder labels and record IDs were replaced with neutral labels. Their file fingerprints changed and are listed beside the frozen originals; their cryptographic identities (circuit ID, verifying key, aggregate program, verifier graph and covenant bytecode) did not.

## Milestone requirements

| ID | Requirement | Candidate evidence | State and remaining work |
| --- | --- | --- | --- |
| M1-01 | Describe the construction and custody tradeoff | [Construction and custody](overview.md#construction-and-custody) | Present as target description; no full-pipeline soundness result |
| M1-02 | Supported environment, hardware and external dependencies | [Environment](overview.md#supported-environment-and-dependencies) | Present; live endpoint, machine and proving admission remain execution prerequisites |
| M1-03 | Publish the frozen protocol requirements and both digests | [Spec inventory](#frozen-specification-export) | Present: ten frozen files, 14 approved non-normative line edits and full original/published digests |
| M1-04 | Publish the amended threat model and authorization controls | [Threat model](threat-model.md) | Present; no new independent PASS inferred and no live guard execution claimed |
| M1-05 | Shared/competing pools and wallet-provider analysis | [Participation analysis](shared-pools-and-recognition.md#shared-participation-and-competing-deployments), [providers](shared-pools-and-recognition.md#wallet-and-provider-participation) | Present as analysis; no integration, adoption or achieved-anonymity claim |
| M1-06 | First reference-pool recognition draft for comment | [Recognition draft](shared-pools-and-recognition.md#recognition-draft-for-comment), [open questions](shared-pools-and-recognition.md#open-questions-for-comment) | Present with seven questions; the Bitcoin Cash Research forum is the comment venue, and the thread link is added when posted |
| M1-07 | Identify current work, dependencies and scope changes | [Current evidence](overview.md#current-evidence-and-remaining-work), [scope](overview.md#scope-and-future-research), [retained/retired split](acceptance-criteria.md#retained-requirements-and-retired-process) | Present; final campaign update and wording stay with their owner |
| M1-08 | Carry approved Phase 1/2 close-outs | [Close-out table](phase-1-and-2-closeout.md) | Present: operator-confirmed complete, with campaign/source links; no historical campaign reopened |
| M1-09 | Check complete release identities, including wrong-profile/network controls | [Current manifest](../identity-manifest.json), [current command](../package.json) | Implemented public-contract checks: `pnpm check:identities`; expected profile/network refusals. R1CS/ELF regeneration and actual file hashing, program VKey derivation, runtime and setup qualification remain unrun; identities are checked, not reproduced |
| M1-10 | Explain how the pool works | [How the pool works](how-the-pool-works.md) | Present as explanation; the specification remains the authority and the threat model gives the limits |
| M2-01 | Deposit and a private payment from Alice to Bob, without manual state edits | [M2 contract](acceptance-criteria.md#milestone-2-a-private-send) | Gap: the run's published transaction IDs, observer table, check command and recipient wallet report |
| M2-02 | Post this milestone's transaction IDs and record | [Posting obligation](acceptance-criteria.md#rules-for-every-posted-run) | Gap: actual publication, limited to this milestone's files; static illustration does not substitute |
| M2-03 | Publish the private send guide | [Phase 3 deliverables](../phase3/README.md#milestone-2-a-private-send-alice-pays-bob) | Gap: follows with this milestone |
| M2-04 | Keep inclusion, acceptance, recording, persistence, spendability and spending separate, at M2, M3 and M4 | [Lifecycle evidence](acceptance-criteria.md#rules-for-every-posted-run) | Contract present; distinct direct-RPC and wallet run observations remain |
| M3-01 | Bob reloads and pays Charles, and Charles accepts, in a new run of three separately generated wallets | [M3 contract](acceptance-criteria.md#milestone-3-an-onward-payment) | Gap: actual separate wallet processes/run; one operator, one machine |
| M3-02 | Post this milestone's transaction IDs and record | [Posting obligation](acceptance-criteria.md#rules-for-every-posted-run) | Gap: run, safe capture and actual publication, limited to this milestone's files; static illustration does not substitute |
| M3-03 | Publish measurements as recorded, missing fields as missing; restated in M4's technical report | [Measurement obligation](acceptance-criteria.md#milestone-3-an-onward-payment) | Gap: actual proving time, memory, fees and recorded lifecycle costs; no target or fabricated zero |
| M3-04 | Publish the onward payment guide, harness, commands and run directory | [Phase 3 deliverables](../phase3/README.md#milestone-3-an-onward-payment-bob-pays-charles) | Gap: follows with this milestone; the record discloses any part that ran another way |
| M3-05 | Four disclosures and actual anonymity-set bound, in any posting that cites a run | [Disclosures](acceptance-criteria.md#rules-for-every-posted-run), [threat limits](threat-model.md#residuals-and-evidence-limits) | Contract present; actual deployment/root/leaf/wallet/control census remains unmeasured |
| M4-01 | Tag the exact release with install/reproduction instructions and role hardware floors | [Release contents](acceptance-criteria.md#milestone-4-the-exit-and-verifiable-release), [baseline instructions](../README.md#build-and-check) | Baseline instructions present; full selected source, role floors and authorized final tag remain |
| M4-02 | Ship complete identity tools, vectors and sufficient public source/inputs | [Release contents](acceptance-criteria.md#milestone-4-the-exit-and-verifiable-release), [identity gap](#milestone-requirements) | Gap: full identity closure and all required validation dependencies under MIT; no withheld inputs |
| M4-03 | Transaction references, recording/replay and measured costs | [M4 contract](acceptance-criteria.md#milestone-4-the-exit-and-verifiable-release) | Gap: exact real-run artifacts and checked release bindings |
| M4-04 | Limitations report covers custody, setup, migration and correlation residuals | [Required report contents](acceptance-criteria.md#milestone-4-the-exit-and-verifiable-release), [threat analysis](threat-model.md) | Analysis present; versioned release limitations report still required |
| M4-05 | Versioned technical report tied to exact release and evidence | [Technical-report contract](acceptance-criteria.md#milestone-4-the-exit-and-verifiable-release) | Gap: actual report with design/conservation, setup, measurements, deferred work and result-origin labels |
| M4-06 | Every campaign commitment maps to artifact and review result | This map and [final-report contract](acceptance-criteria.md#milestone-4-the-exit-and-verifiable-release) | Requirement/status index present; final artifact/review results must replace remaining gaps without inventing verdicts |
| M4-07 | No secrets/private data in any export or tagged tree | [Release privacy obligation](acceptance-criteria.md#milestone-4-the-exit-and-verifiable-release) | Publication owner must reconcile exact composition and real secrets; selected-document scan is not whole-release clearance |
| M4-08 | Preserve actual publication conditions and correct known Majors | [Retained rules](acceptance-criteria.md#retained-requirements-and-retired-process) | Exact authorized candidate, required fresh-clone/N1/restoration and pre/post checks remain for each publication; no source-landing review gate |
| M4-09 | Charles exits: a private note paid out to an ordinary BCH address | [M4 contract](acceptance-criteria.md#milestone-4-the-exit-and-verifiable-release) | Gap: actual exit in the new run, with inclusion and spending recorded separately |
| M4-10 | Refuse first construction at/after invoice expiry before effects | [Refusal table](acceptance-criteria.md#milestone-4-the-exit-and-verifiable-release) | Exact code documented; valid/expiry controls and no journal/sign/handoff/broadcast evidence required |
| M4-11 | Refuse invalid, duplicate and stale inputs at their own boundaries | [Source boundaries](#refusal-source-boundaries), [required controls](acceptance-criteria.md#milestone-4-the-exit-and-verifiable-release) | Exact source names documented; independently constructed negatives, valid controls and counterfactuals remain |
| M4-12 | Post this milestone's transaction IDs and real recording | [Posting obligation](acceptance-criteria.md#rules-for-every-posted-run) | Gap: run, safe capture and actual publication, limited to this milestone's files; static illustration does not substitute |
| M4-13 | Publish read-only walk-through-and-verify replay | [Replay obligation](acceptance-criteria.md#milestone-4-the-exit-and-verifiable-release) | Gap: utility rechecking published proofs/transactions; no wallet actions or state mutation |
| M4-14 | Clean 16 GB replay plus declared local regressions using public inputs | [Clean-machine obligation](acceptance-criteria.md#milestone-4-the-exit-and-verifiable-release) | Gap: actual machine and run; no coins or proving, never a fresh live-lifecycle reproduction |
| M4-15 | Publish the exit guide | [Phase 3 deliverables](../phase3/README.md#milestone-4-the-exit-charles-pays-out-and-the-reference-release) | Gap: follows with this milestone |

## Later phases

| ID | Requirement | Candidate evidence | State and remaining work |
| --- | --- | --- | --- |
| Later-01 | Catch planted amount/recovery disclosures at every sink, including derived-digest carriers | [Sink inventory](acceptance-criteria.md#later-phases) | Every runtime sink remains uncovered by this doc work; detector-removal controls and corrected-output evidence required |

## Frozen specification export

The frozen contract is the later approved normative text, not an older public-layout draft. No requirement, signature, relation, vector or proof anchor may change merely to make an export/check pass. The [specification index](spec/README.md) supplies the full original/published digests and the approved changed-line locations, including the publication relabel ledger. These are documentary source bindings, not evidence that the protocol is fully implemented or that final export checks pass.

| Public specification | Current state |
| --- | --- |
| [Index, full digests and changed lines](spec/README.md) | Present |
| [Proposal](spec/proposal.md) | Frozen text with seven approved non-normative line edits |
| [Note statement](spec/apnt-pool-note-statement/spec.md) | Byte-identical to the frozen source |
| [Note tree](spec/apnt-pool-note-tree/spec.md) | Byte-identical to the frozen source |
| [Nullifier range records](spec/apnt-pool-nullifier-range-records/spec.md) | Byte-identical to the frozen source |
| [Settlement custody](spec/apnt-pool-settlement-custody/spec.md) | Retained byte-identical to the baseline and frozen source |
| [Proof system](spec/apnt-pool-proof-system/spec.md) | Byte-identical to the frozen source |
| [Privacy model](spec/apnt-pool-privacy-model/spec.md) | Byte-identical to the frozen source |
| [Receive recovery](spec/apnt-pool-receive-recovery/spec.md) | Frozen text with approved non-normative line edits |
| [Operations harness](spec/apnt-pool-operations-harness/spec.md) | Frozen text with approved non-normative line edits |
| [Versioning migration](spec/apnt-pool-versioning-migration/spec.md) | Frozen text with approved non-normative line edits |

The provenance requirement remains explicitly unmet, as explained in the [recognition draft](shared-pools-and-recognition.md#keep-the-identities-distinct). The public text cannot claim that transitive pins or an identity comparison close it. The design remains explanatory context; it must not overwrite or weaken normative requirements.

## Refusal source boundaries

The [acceptance table](acceptance-criteria.md#milestone-4-the-exit-and-verifiable-release) preserves exact existing source vocabulary. `apnt_pool_intake_v1.ts` defines and uses `pool-intake-owner-signature`, `pool-intake-action-proof` and `pool-intake-stale-anchor-policy`; its nullifier-history refusal deliberately covers both spent-nullifier and incomplete-history causes. The runtime refusal owner must isolate the intended cause with complete history and a verifying counterfactual.

In this snapshot, the [statement implementation](../packages/protocol-runtime/src/apnt_pool_statement_v1.ts) uses [the closed duplicate-nullifier code](../packages/protocol-runtime/src/apnt_pool_contract_v1.ts) for repeats within a statement. The development wallet-module expiry and aggregator/harness source are not included here; their exact source-backed names are documentation for a later export, not runnable candidate controls. The harness's generic settlement wrapper alone is insufficient evidence. A source name or a test title is never an executed negative result.

## Work beyond this document port

The specification source is present. The identity command checks the present public contracts; its unrun runtime observations and final validation remain explicit. The runtime owners supply each milestone's positive and refusal evidence. Recording, verification, live-run, clean replay and technical/release-report owners consume this same contract. The publication owner performs final composition, secret and private-path checks, required checks and actual authorized delivery.

These are existing responsibilities, not new process gates or extra engineering commitments. A missing clause/artifact stays a gap. Removing the recognition draft makes M1-06 unsatisfied even if the table row remains; a structural check is not independent semantic acceptance.
