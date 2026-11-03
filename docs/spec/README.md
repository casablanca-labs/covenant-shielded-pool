# Protocol specification

This directory holds the APNT shielded pool v1 specification, frozen on 21 October 2026. Requirements use MUST, SHOULD and MAY, and each capability states its scenarios as WHEN/THEN conditions that tests can check. The headings "ADDED Requirements" retain the project's specification format.

The specification describes the target protocol. It does not claim that every requirement is implemented. The [overview](../overview.md), [acceptance criteria](../acceptance-criteria.md) and [release contract and evidence map](../release-contract.md) distinguish current evidence, unmet requirements and remaining work. Local presence is not public publication or complete milestone delivery.

## Contents

| Document | What it specifies |
| --- | --- |
| [Proposal](proposal.md) | Why the pool replaced the earlier note-backing design, and the shape of the change |
| [Note statement](apnt-pool-note-statement/spec.md) | Notes, actions and the statement each action proves |
| [Note tree](apnt-pool-note-tree/spec.md) | The pool's note-commitment tree, its roots, and the interchangeable root copies that carry them on chain |
| [Nullifier range records](apnt-pool-nullifier-range-records/spec.md) | How spent notes are recorded on chain so none is spent twice |
| [Settlement and custody](apnt-pool-settlement-custody/spec.md) | The covenants that hold pooled value and enforce settlement |
| [Proof system](apnt-pool-proof-system/spec.md) | Proof systems, keys, setup and the aggregate proof |
| [Privacy model](apnt-pool-privacy-model/spec.md) | What the construction hides, under which conditions, and what stays public |
| [Receive and recovery](apnt-pool-receive-recovery/spec.md) | How wallets discover, accept, record and recover notes |
| [Operations harness](apnt-pool-operations-harness/spec.md) | The test harness that runs the pool's lifecycle on a local backend and on Chipnet |
| [Versioning and migration](apnt-pool-versioning-migration/spec.md) | How versions change and what migrates between them |

## How this text relates to the frozen original

The ten original files are the protocol change developed in a private working repository and frozen as `add-apnt-shielded-pool-v1` at commit `2464c811a60167791300bfc012db21cb78cdff11`, including its approved normative freeze. The launch-layout copy at `1065285520b63d710c66c809c11b9274ea7e89ed` contains the same ten original blobs. The explanatory design and task ledger are not part of this specification export.

The earlier export changed 14 approved non-normative lines in four files. The subsequent approved publication relabelling also changes the operations-harness machine-root example and historical record labels; its exact fingerprints and line inventory are recorded below. Internal-document citations become plain descriptions; a named legacy test note becomes the seal-era legacy test note. Every other byte was unchanged in that earlier export. Requirement language, frozen relations, vectors and proof trust anchors retain their meaning. The legacy note remains permanently unspendable and cannot be described as migratable. Identifiers such as `HUM-49`, `ARCH-140`, `ENG-1879` or `REV-594` are labels from the project's private work record, not public evidence links.

SHA-256 values cover each complete UTF-8 file, including its final newline. Equal original and published digests identify byte-identical files. The custody file already present in this repository is retained unchanged.

| File | SHA-256 of frozen original | SHA-256 of published file |
| --- | --- | --- |
| `proposal.md` | `34cb5de9b5f1c72fb1fc59f33b91443d675fce821d84588b892a2af82dfbf0b9` | `bee732e94cac3d0e3f6f30b324c2f232b47a3cdb8291ad2feee1eeae70db24de` |
| `apnt-pool-note-statement/spec.md` | `8f00c9557db608e2ac32e668d39f265f60bb98a21cab7745b383327e26a21e71` | `8f00c9557db608e2ac32e668d39f265f60bb98a21cab7745b383327e26a21e71` |
| `apnt-pool-note-tree/spec.md` | `eef0c19f8ce0304f8d3de6c05f4d6ae23fad9d471b0d63d880723941bbfb6711` | `eef0c19f8ce0304f8d3de6c05f4d6ae23fad9d471b0d63d880723941bbfb6711` |
| `apnt-pool-nullifier-range-records/spec.md` | `50afa5918618b0f198cc2dbce8f193134b99b68ec310a5fa6cb480e6a4ca01f6` | `50afa5918618b0f198cc2dbce8f193134b99b68ec310a5fa6cb480e6a4ca01f6` |
| `apnt-pool-settlement-custody/spec.md` | `8950abce7c5af13e87e758e9ea4a3cb323f39a60d7c8363141ef5ce11fd22670` | `8950abce7c5af13e87e758e9ea4a3cb323f39a60d7c8363141ef5ce11fd22670` |
| `apnt-pool-proof-system/spec.md` | `6b71f31916b488e316a5fa88e34791d72072e35d459f10bda03bba7afd08c220` | `6b71f31916b488e316a5fa88e34791d72072e35d459f10bda03bba7afd08c220` |
| `apnt-pool-privacy-model/spec.md` | `1899720799b95c1c4d5168298376f79f442ca5528abc38c5c7b960bc902aeb53` | `1899720799b95c1c4d5168298376f79f442ca5528abc38c5c7b960bc902aeb53` |
| `apnt-pool-receive-recovery/spec.md` | `d05e0a693358c92a125d27e2c355e61e58862385098e537fa44f17d6405cfae7` | `7c8ba878f391e115eb6688b1cfd5696e5b6b6ea906e8ce7149dbf760eafa253a` |
| `apnt-pool-operations-harness/spec.md` | `0c4c749b6b0eac1d929086aea4a7e3d71201132235f21ce3e549729bce314d85` | `1e604fa8808c4863dec69ea82182d4046d4c58526df9042e4e82f9fbe80bc5ba` |
| `apnt-pool-versioning-migration/spec.md` | `1d77a4da241c8cbe9f88a5c0259b6a1e997f21a65f2ef94fcde0f0329f784807` | `e73f228e9aafecdec00d20bb1bee6b8134a930701d1dea73d45c07d98bc5311e` |

## Every changed line

The earlier edits preserve line positions. The subsequent operations-harness relabelling also preserves line positions; its changed line numbers are listed in the ledger. The descriptions below identify each change without republishing the private document paths or the named test-note reference that the edits remove.

| File | Frozen/exported line | Approved edit |
| --- | --- | --- |
| `proposal.md` | 11 | Internal evidence citation replaced with a plain internal-evidence description; finding retained. |
| `proposal.md` | 12 | Internal evidence citation replaced with a plain internal-evidence description; finding retained. |
| `proposal.md` | 14 | Internal evidence citation replaced with a plain internal-evidence description; finding retained. |
| `proposal.md` | 20 | Internal evidence citation replaced with a plain internal-evidence description; finding retained. |
| `proposal.md` | 22 | Internal evidence citation replaced with a plain internal-evidence description; finding retained. |
| `proposal.md` | 26 | Internal evidence citation replaced with a plain internal-evidence description; finding retained. |
| `proposal.md` | 27 | Internal evidence citation replaced with a plain internal-evidence description; finding retained. |
| `apnt-pool-receive-recovery/spec.md` | 1151 | Private review-document citation replaced with the project's internal design review (REV-594); section references retained. |
| `apnt-pool-operations-harness/spec.md` | 1039 | Internal operations-document citation replaced with a plain description; surrounding rule retained. |
| `apnt-pool-operations-harness/spec.md` | 1185 | Internal operations-document citation replaced with a plain description; surrounding rule retained. |
| `apnt-pool-operations-harness/spec.md` | 1198 | Internal operations-document citation replaced with a plain description; surrounding rule retained. |
| `apnt-pool-operations-harness/spec.md` | 1320 | Internal operations-document citation replaced with a plain description; surrounding rule retained. |
| `apnt-pool-versioning-migration/spec.md` | 211 | Named test-note reference generalized to the seal-era legacy test note; permanent unspendability and correction requirement retained. |
| `apnt-pool-versioning-migration/spec.md` | 216 | Named test-note reference generalized to the seal-era legacy test note; permanent unspendability and correction requirement retained. |

## Publication relabelling

Some frozen data and source files were relabelled for publication: local build paths, internal folder labels and record IDs were replaced with neutral labels. Their file fingerprints changed and are listed beside the frozen originals; their cryptographic identities (circuit ID, verifying key, aggregate program, verifier graph and covenant bytecode) did not.

The [relabel ledger](../../publication-relabel-ledger.json) lists each of the 16 relabelled files, the original and published SHA-256, and the changed line numbers. The frozen-original specification digest column above remains unchanged. `export-manifest.json` remains the historical v0.5.0 record; the ledger binds this forward relabelling to its explicit committed public parent.

Rebuilding the guest from published source does not yet reproduce the recorded guest inputs (Chipnet: three Cargo manifests and core/src/tests.rs differ; local: the original source commit is unavailable). `pnpm check:identities` verifies published bytes, not a rebuild.
