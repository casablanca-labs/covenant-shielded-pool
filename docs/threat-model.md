# Threat model

This is the public documentary threat model for the Phase 3 research target. It preserves the amended analysis and its restored broadcast-authorization controls. It supplies no new test, audit, live-run or independent acceptance result. The [release contract](release-contract.md) distinguishes source present in this snapshot from requirements and missing evidence.

Zero-value Chipnet research only. The action setup is simulated and single-party. One project operator controls the planned wallet processes on one machine. Cryptographic hiding from public observers does not hide plaintexts from that operator or a process able to read the same owner context.

## Required protections and assumptions

Identity/linkage and amount shielding are mandatory together by default. Protected dimensions include payer-to-recipient and onward-spend linkage, private note values, input-to-output correspondence, private bundle assignments, change ownership and nonreusable recipient material. Public grouping and role-specific knowledge are not themselves hidden by that requirement.

The target depends on canonical host semantics, sound child/aggregate/verifier implementations, correct covenant execution, secret unpredictable wallet material, fresh proof randomness and well-formed checked parameters at every setup-backed layer. Commitments and packets do not conceal facts a party already knows or can deduce from public conservation. The pad16 packet is not an AEAD/MAC.

Wallets retain spending secrets, authorization and acceptance decisions. Public discovery is only a candidate: the wallet must reconstruct the commitment under its own owner tag and verify its own chain, settlement and fold evidence. Structural validity, semantic validity, proof verification, chain inclusion, wallet acceptance, recording, persistence, spendability and actual spending are distinct facts. Recovery is also distinct from spendability.

Owner signatures bind the exact deployment/action effect. Canonical relation checks bind ranges, ownership, membership, distinct nullifiers, output construction and integer balance. Settlement binds the statement and deployment, real roots/ranges, withdrawal values/locks and BCH conservation. The [custody specification](spec/apnt-pool-settlement-custody/spec.md) defines those requirements; these sentences are not evidence of a complete exercised pipeline.

## Payer

A payer knows its own input notes and values, the invoice and payment it constructs, its change and any recipient identity supplied by the business or delivery channel. It knows its private construction and public action grouping. No control can hide that payment from its creator or authenticate a human recipient from valid invoice bytes alone.

Invoice owner/recovery material lets its holder recognize/open payments to that invoice. It does not supply the recipient's spend authorization, nullifier key or wallet-wide identity. Under single-use derivation, separate change keys and the cryptographic assumptions, the payer should not identify the recipient's later consumed note merely by computing its nullifier. Reused invoices, copied tags, collisions, outside information and collusion weaken that boundary.

The payer can refuse or withhold payment, submit the wrong payment, disclose what it knows, or delay discovery with bad tags. Under sound proofs and intact wallet keys it cannot spend another owner's accepted note or redirect an already signed effect. Expiry policy does not revoke an existing signature; active cancellation is outside Phase 3.

## Recipient and invoice holder

The recipient learns the received value and output, surrounding public grouping, its own later spend construction and any payer identity supplied outside the chain. Its invoice alone does not reveal the payer's input/change values or map public nullifiers to historical leaves.

When the known two-output reference payment builder is used, an invoice holder recognizing its payment can identify the companion commitment as planned payer change, possibly zero. This reveals neither its amount nor its recovery/nullifier keys or later spend. Publication of the builder makes this workflow condition ordinary knowledge; privacy must not rely on hiding the source.

A recipient can disclose its own information, repeat tags, supply misleading commercial information or request payment to other invoice material. It cannot alter the exact signed action under the required signature and settlement bindings. A copied tag alone must not be treated as proof of a prior payment; a real opening and wallet policy are separate checks. The payer's prior-payment check is specified but not demonstrated in Phase 3.

The development harness uses operator-handled invoice files. Substitution can divert a payer-approved payment because cryptographic validity does not authenticate the intended human. Interception exposes the invoice's recognition/opening material. No authenticated isolated invoice-delivery path is established by that file interface.

## Aggregator

A public-interface aggregator sees public actions, authorization signatures/tags, child proofs, inbox outpoints, arrival/retry timing and proposed batch groupings, including abandoned candidates. It need not receive private witnesses, old consumed-note leaves, private owner assignments or output values. Public boundary amounts, fees and outside knowledge still permit deductions.

It can recognize retries, choose cohorts, censor, delay or relay an already authorized action. Under the required soundness and wallet boundaries, it cannot forge owner authority, redirect signed outputs, insert arbitrary victim nullifiers or mint legitimate private value. Aggregation is the default; direct self-settlement remains an exit/fallback with additional proving and chain resources, without unconditional liveness or unlinkability guarantees.

The development harness's Chipnet broadcast requires an explicit broadcast flag and approved intent, with settlement-specific approval. Chain I/O separately requires Chipnet and an explicit submission-policy flag. These authorization controls remain required; a coordinator handoff is neither proof generation nor broadcast. This document does not execute or certify a released harness path.

Network-origin linkability (IP/timing): “out of scope on Chipnet; revisit before mainnet”.

## Witness-bearing action prover

Phase 3's development path has operator-run proving on the same machine; it has no instantiated third-party delegated prover. The private request is wallet-owned, and wallet-launched native proving remains pending in that path. A label saying local proves only the intended same-machine scope, not that the wallet launches its own proof.

Hypothetical action delegation discloses the supplied witness: input values, ownership/nullifier material, randomness and membership paths, plus output values and owner/recovery material. It reveals that action's correspondence and assignments and may identify change from context. It is not zero knowledge to that prover. An aggregate prover given only public records and child proofs has the public aggregator view instead.

An output-only witness has value, owner tag, rho and recovery key K; it does not contain that output's nullifier key or spend key. Output K can open matching family packets and reveal their values/randomness, but computing later nullifiers needs additional nullifier-key material, such as a consuming input witness. A delegate or colluding delegates holding both creating and consuming witnesses can obtain the stronger family linkage. This distinction does not diminish the serious output-only disclosure.

No witness handoff grants spending authority. Canonical point/scalar validation, signature binding and relation checks remain necessary; labels are not transport confinement. This document supplies no selected-route witness-carrier audit, delegated-service implementation or consumer-device proving result.

## Chain observer

A chain observer sees public transaction bytes, action/nullifier/commitment grouping, tags, counts, fees, deposits and exits, root/fold history, timing and funding ancestry. It does not get a general mapping from a nullifier to an earlier leaf, private output ownership or note values merely from those public encodings, conditional on the stated assumptions. Known payments and all-but-known conservation arithmetic can nevertheless remove uncertainty.

Miners and network services can censor, delay, reorder or present incomplete/reorganized history within their capabilities. A supplied transaction ID or accepted relay response is not authenticated inclusion. Wallets must verify their selected network, checkpoint, currentness, confirmations, state history and spendability. No achieved-anonymity or censorship-resistance measurement is supplied here.

## Co-resident process under the same operating-system user

Owner-only file modes and local seals do not establish adversarial peer isolation among processes sharing the wallet owner's OS identity. Such a process may read accessible wallet state and invoices, correlate arguments, home directories, configuration and approval identifiers, or replace both a plan and its local authentication anchor. It can learn private values, correspondence, assignments, change derivations and stored identifiers without attacking commitment hiding.

Access to spend keys permits genuine unauthorized signing; replacing or deleting journals and recovery state can deny service or cause rollback/conflict. Held-descriptor owner/mode/path/inode checks and exact-byte snapshot seals protect their stated file boundary, not an anchor controlled by that same writer. A random context identifier is not a secret, capability or OS boundary.

No same-user isolation, complete process-carrier closure, constant-time JavaScript, guaranteed memory erasure or hostile-host protection is demonstrated. The ordinary file interface does not establish a deny-by-default no-invoice-file transport. A clean recording scan cannot settle this isolation question. A separate verified boundary or a separate explicit scope decision is still needed for any stronger claim; neither is supplied here.

## Pool copier or competing deployment

A copier can reuse public code and parameters, operate services, select a fresh genesis or advertise misleading reference claims. A new genesis has a different history and no inherited users, notes, backing or achieved privacy. Reusing the same setup reuses its exposure. Mirroring the complete authenticated original artifact/genesis describes the same pool.

The wallet's independently selected deployment and whole-genesis/covenant audit are essential. A shared profile, empty root, brand, endpoint or trial settlement is insufficient. A lookalike deposit script may steal funds sent to it even when an honest pool is otherwise sound. Reference recognition gives no publisher spend authority and does not replace payment acceptance. The [recognition draft](shared-pools-and-recognition.md#recognition-draft-for-comment) is analysis, not an implemented selection service.

## Project and setup holders

The project ran the simulated action setup and could retain the randomness needed to forge proofs, create counterfeit notes and withdraw up to all pooled backing. Victim signatures do not prevent attacker-owned counterfeit notes from being spent. Correct BCH conservation cannot distinguish those notes from legitimately backed ones. No Phase 3 protocol control stops such trapdoor-valid forgeries; zero-value labels restrict exposure rather than provide cryptographic protection.

The aggregate proof's external Groth16 wrapper has a separate setup dependency. A holder of its trapdoor, if one exists, could forge accepted verdicts with the same custody consequence. This does not assert that the project holds that trapdoor. Wrapper-specific assurance remains unverified; an action ceremony alone would leave the wrapper dependency intact.

Setup trapdoor possession alone is not evidence of decryption or a universal nullifier map for honest notes. Operating both wallets and the prover separately gives the project the private values and links in its own environment. Neither simulated-setup labels, source publication, reproducible builds nor pins establish production soundness/privacy or honest erasure.

## Residuals and evidence limits

| Surface | Remaining exposure |
| --- | --- |
| Shape, counts and grouping | Public action/batch structure, padded slots, append order, range-record growth and root-copy creation; known companion-change role |
| Fees and transparent boundary | Public boundary values and fees, funding ancestry and deductions from conservation; bounded ancestry policy is not unlimited funding independence |
| Timing and history | Retries, inclusion/fold delays, older roots and thin one-action self-settlement cohorts; authentic old roots can remain consensus-valid despite wallet policy |
| Tags and local context | Reused/copied/colliding tags, identical candidate retries, invoice files, shared-user state and observable process arguments |
| Hashes and reports | Unkeyed hashes of small private amount tuples can be dictionary oracles; omitting literal amounts does not establish privacy |
| Availability and recovery | No guaranteed time to settle, complete provider failover or rescue of backing already stolen; encrypted recovery and spendability remain distinct |

The required run census includes the exact deployment, root/height, folded leaf count and who operated all notes, including earlier activity. It is not measured by this document. Dummy and spent leaves and known ownership mean a structural bound is not achieved anonymity.

Separate-machine demonstration, fresh-wallet recovery, active cancellation, independent wallet interoperability and three-or-more funded transfers in one batch are outside Phase 3's demonstrated scope. The 16 GB demonstration is read-only replay and local regressions with no proving; full re-proving needs its separately admitted resources. No production security, mainnet readiness, global traffic anonymity, comprehensive cryptographic audit or equivalence to another privacy system is claimed.
