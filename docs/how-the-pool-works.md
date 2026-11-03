# How the pool works

The Covenant Shielded Pool lets wallets hold and pay private notes on Bitcoin Cash, using covenants and today's consensus rules. This page describes the design. The demonstrated workflow uses scripts for local proving. A deposit's own proof, settlement and fold precede a payment from its note. Hiding claims require the specification's cryptographic assumptions, secret wallet material, fresh randomness, single-use invoices and zero-knowledge proofs with well-formed setup parameters at every layer. The [specification](spec/README.md) is the authority, and the [threat model](threat-model.md) gives the limits per adversary. For what has actually run, and when, see [Phase 3 deliverables](../phase3/README.md).

This is zero-value research on Chipnet only. The action setup is simulated and run by the project, so the project could forge proofs. It must not protect real funds. This release makes no privacy claim.

## The main idea

Earlier designs tied each private note to particular backing coins. Someone who knew those coins could recognise when the note was spent. This design separates the two:

- A **note** is a private commitment to a value and an owner. Its contents stay in the owner's wallet.
- **Pool coins** are token-free BCH outputs that hold interchangeable backing. No pool coin belongs to any one note.
- The **note tree** records every note's commitment. Spending a note publishes a **nullifier**, which stops a second spend without saying which note was spent.

A payment proves that it consumes an authorised, unspent note and conserves value, without publicly identifying that note.

## Who does what

| Party | Does | Holds |
|---|---|---|
| Wallet | Creates its keys, reads the chain, issues invoices, builds, signs and proves its own actions, and decides for itself whether to accept a note | Its seed, spending secrets and private notes |
| Aggregator | Combines many actions into one batch, proves the batch and settles it on chain | Public action records and proofs only. No spending authority |
| Chain | Enforces the covenants and the on-chain proof check | Public transactions |

Aggregation is the normal path. A wallet can settle by itself as an exit or fallback, at extra cost and with a thinner crowd to hide in.

## The life of a payment

1. **Deposit.** A wallet funds its own one-time inbox coin from ordinary BCH. The deposit amount is public. If the deposit is never settled, the wallet can take the coin back after a 1,008-block delay.
2. **Invoice.** The recipient's wallet issues an invoice with an expiry and passes it to the payer privately.
3. **Action.** The payer's wallet reads the chain for itself, builds the action and proves it locally. The proof and the owner's signatures show that the note exists, that its owner authorised the spend and that value is conserved. The action carries nullifiers, new commitments, packets and discovery tags.
4. **Aggregation.** The aggregator checks the action and its proof, assembles a batch and produces one aggregate proof, then wraps it in a Groth16 proof small enough to check on chain.
5. **Verification.** Verifier transactions check the wrapped proof on chain. If it passes, a factory covenant mints a verdict token.
6. **Settlement.** A settlement transaction spends that verdict and applies the batch's nullifiers and backing changes.
7. **Fold.** A fold transaction adds the batch's new commitments to the note tree and publishes the new root.
8. **Acceptance.** The recipient's wallet reads the chain itself, finds candidates by discovery tag, reconstructs the note under its own keys, and checks the settlement and fold. Only then does it accept the note. An aggregator's reply can't do this for it.
9. **Exit.** To leave the pool, a wallet spends a note to an ordinary BCH address. The exit's destination, value and fee are public by design.

Being held, accepted, a member of the tree, unspent and spendable are separate facts, and the wallet records each one separately. So are a relay's acceptance, inclusion in a block and actual spending.

## What a chain observer sees

An observer sees public transaction bytes, nullifiers, commitments, roots, re-randomized keys, signatures, packets, discovery tags, deposits, exits, fees, counts, timing and funding ancestry.

From those public encodings alone, an observer doesn't get a general mapping from a nullifier to an earlier note, or a note's owner or value. That holds only under the stated assumptions. Known payments, conservation arithmetic, public deposits and exits, timing and small batches can all remove uncertainty. How much anonymity a pool gives depends on how many people use it: a spend's candidates are the notes folded before the root it uses, and anonymity becomes measurable as participants join.

## What custody rests on

Spending a note takes its owner's authorisation, and no aggregator, prover or relay gets spending authority. But the security of pooled funds rests on the soundness of the proofs and their enforcement, because owner signatures can't stop a counterfeit note admitted by an unsound proof system. Two setups matter here:

- The action setup is simulated and run by the project, so the project could forge proofs and take pooled backing.
- The aggregate proof's Groth16 wrapper relies on a separate setup from outside the project, which is a trust assumption of this release.

Mainnet use would need properly verified parameters from a permissionless ceremony, or a reviewed transparent replacement, together with wider security work.

## Read next

- [Overview](overview.md): construction, environment and status
- [Threat model](threat-model.md): what each party can and can't learn
- [Shared pools and reference-pool recognition](shared-pools-and-recognition.md): how several products could share one pool
- [Specification index](spec/README.md): the exact rules, with file digests
