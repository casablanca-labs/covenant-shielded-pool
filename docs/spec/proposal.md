# Change: Record the APNT shielded pool v1 as the target architecture

## Why

The successor profile backs each private note with its own BCH UTXOs, called
seal cells. The UTXO set then acts as the nullifier set for free. But a spend
must name the outpoints it consumes. Whoever learned those outpoints when the
note was created recognizes the spend from chain data alone. Today that is the
payer, who builds the recipient's cells.

- The channel was measured on Chipnet (internal evidence record).
- It survives seal v2 (internal evidence record).

The operator's revised goal (internal evidence record, 2026-09-23) makes
payer unlinkability, offline receive, and batch construction without private
inputs pooled in one place release-bar requirements.

Three studies closed the alternatives inside the seal-cell architecture:

- ARCH-135 (internal evidence record) found that batch
  construction needs one party to see every participant's private inputs.
- ARCH-137 (internal evidence record) found that the
  best per-note-cell fix still leaves the spend event visible. It caps the
  residual at a 1-in-2 guess and requires the recipient to be online. The
  operator rejected it.
- ARCH-140 (internal evidence record and
  internal evidence record, two independent reports)
  found two things:
  - A BCH shielded pool needs no single covenant UTXO that every spend
    touches. Nullifier freshness reduces to spending one named "range record"
    UTXO. This was executed in scratch covenants in both BCH 2026 VMs.
  - Every pool, on every chain, rests custody of pooled value on proof
    soundness.

On 2026-09-23 the operator accepted that trade (HUM-49 = yes). Proofs are
publicly verifiable by anyone.

## What Changes

This change records a new, versioned pool architecture as the target. It is
design and specification only: it changes no implementation, runs no prover,
touches no chain and edits no pin.

The target is APNT shielded pool v1. This M1 reconciliation records static source conformance at 705bd169 and distinguishes the protocol target, shipped research implementation, unverified acceptance evidence and explicit Phase 3 deferrals. The critical design review passed in round 3; passing it did not implement the pool. Host semantics, covenant builders, wallet discovery/acceptance components, inbox admission and modular harness stages now exist with the limits in this dated matrix. This is documentation, not implementation acceptance. The operations-harness capability belongs in the capability list. Earlier AEAD-in-circuit, T1-fill and Halo-2-first decisions remain only as dated history; pad16, T2 and the adopted zero-value ceremony route are the later recorded choices.


The Chipnet ladder is the lifecycle gate ledger; the local ledger supplies regression and firing negatives. Phase 3 M3 is several wallet processes on one machine with complete-workflow measurements and independent review. Every cited run must state the single operator and exact deployment tree note count; it demonstrates construction, not independent-user anonymity. Separate-machine/fresh-restore exercises are deferred and participation engineering is narrowed to spec/paper. M3 remains acceptance work; publication is the separate operator-go launch of repository and FundMe after the pre-launch cleanup gate. No current M3 pass or publication go is established by this reconciliation.


- **Notes.** A private note is a SHA-256 commitment in a pool note tree, plus
  an encrypted opening on chain. It is not a token, and nothing on chain names
  its owner. Pooled BCH sits in interchangeable token-free covenant UTXOs
  ("pool coins").
- **Actions.** Every spend, payment, deposit or withdrawal is one fixed-shape
  action (two in, two out, dummy-padded) with its own zero-knowledge proof. It
  proves membership, ownership, nullifier correctness and balance by itself,
  with every value range-checked, about one fixed 314-byte action record. Its
  one public input is that record's hash reduced into the proof's field,
  `x = int_be(SHA-256(A)) mod r`, which every verifier computes from the record
  itself (HUM-80). Nothing constrains two actions jointly. This removes the
  aggregate blinding sums and the pooled uniqueness check (ARCH-136).
- **Nullifiers.** `nf` is derived from a key only the note's owner holds, and
  from `ρ`. Output `j` of an action takes `ρ` equal to the nullifier of input
  `j` of the same action; the two input nullifiers differ, and every input
  nullifier, dummy ones included, is inserted. The chain enforces freshness
  through **nullifier range records**:
  - Each range record is a keyless covenant UTXO whose NFT states that no
    nullifier key strictly inside `(lo, hi)` has been used. A nullifier's key
    is `2·nf + 1`, so no key ever equals a genesis boundary.
  - Inserting `nf` spends the one record containing its key and creates the
    two halves.
  - Unrelated spends touch different records.
  - Genesis is audited over every output of each pool category, not only the
    advertised records.
- **Note tree.** The current root is carried by several identical **root
  copies**. A spend uses any one and recreates it. A **tree update** UTXO
  appends each settled batch to a depth-32 SHA-256 incremental Merkle frontier
  recomputed in script, and is touched once per batch, never per spend. Anyone
  may perform it.
- **Authorization.** The only thing that can change pool state is a **proof
  verdict**. That is the existing on-chain verifier's output NFT, committing
  the hash of the batch statement. Each input slot is also signed by its owner
  with BCH's native EC-Schnorr (not BIP-340), under a re-randomized key. The
  signed message covers the whole action record and the action's two
  discovery tags, and no signature. Script recomputes it from the committed
  statement and the tags, and checks each signature with
  `OP_CHECKDATASIGVERIFY`.
- **Settlement binds statements to chain state.** The settlement covenant
  checks an exact list. Every action's anchor must be the root of a root copy
  spent in the same settlement, one copy per distinct anchor. Each signed
  withdrawal is paid by its own indexed output. Every pool-coin input is
  counted in conservation, and the statement's deployment is pinned.
- **Receive and recovery.** The payer encrypts the note to the recipient's
  single-use per-payment key, so the recipient can be offline. The 16-byte
  pad16 packet uses `d = SHA-256("APNT-POOL-v1:pad" ‖ K ‖ ρ ‖ cm)` to pad
  the value and carry an 8-byte key-check suffix; output `rcm` derives from
  `K` and `ρ` (`packages/protocol-runtime/src/apnt_pool_note_v1.ts:33-37`).
  Binding the digest to `cm` separates different candidate plaintexts under
  reused `K, ρ`, up to SHA-256 collisions. The packet has no MAC: integrity
  needs a sound proof, owner signatures and wallet acceptance checks. Change
  uses a separate seed branch no payer ever sees, with keys derived from each output's public `ρ`, so it is
  found at one trial decryption per packet. Invoices carry an expiry height.
  An invoice id pairs a random 40-bit epoch, which each store draws for
  itself, with a sequential 24-bit index (HUM-77). A restored seed keeps
  issuing from a fresh epoch, with no issuance hold, second seed or gap
  closing. Its one residual is a disclosed epoch collision, about `2^-40` per
  pair of draws by different stores that do not know each other's epochs. The
  recipient discovers, recovers and checks spendability from its seed and
  chain data alone. The per-epoch window `(u_e(h − T − grace), u_e(h) + G]`
  (HUM-70) stays as the fallback for payments whose payer wrote a wrong tag,
  beside a targeted rescan by payment id from the deployment's genesis.
  A payer cancels a payment still unsettled at its cancel height, and
  re-proves that one cancellation until one of the two actions settles. The
  window's coverage of a withheld, mis-tagged payment holds only when that
  cancel settles within the settlement bound. An under-fee cancel, a cancel
  past its first anchor attempt, an offline payer and a withheld cancel are
  disclosed residuals, and the payer reports each late payment's id for the
  recipient's targeted rescan. Lateness alone does not make the window miss
  a payment; a miss needs a later height. A cancel fee ceiling fixed in
  advance uses a headroom measured over planning heights whose whole horizon
  was observed, which is not yet measured. Evidence of a prior payment
  to the cancel's own,
  privately issued invoice never pauses the cancel (2026-10-05, ARCH-316 to
  ARCH-319, ARCH-411).
- **Discovery tags (HUM-75, HUM-77).** Every output carries an 8-byte
  discovery tag, outside the action record and the proof, and bound by the
  owners' signatures. A payment's tag is the recipient's FF1-AES256 encoding of
  the invoice id, carried in the invoice and copied by the payer (HUM-78).
  Change and dummy tags derive from a wallet secret and the output's own `ρ`.
  The recipient decodes tags locally, which finds late payments and teaches a
  restore every epoch with a correctly tagged payment. No server is asked, and
  there is no private information retrieval.
  The window scan above stays as fallback and option, and still finds a
  payment whose payer wrote a wrong tag. One leak is public and disclosed: an
  invoice paid twice shows its tag twice. Every other tag is bound to its own
  output, so no other honest output repeats one. A tag is a hint, not proof:
  any signer can copy one, so a payer verifies a prior payment by opening it
  before acting. The circuit and its Setup do not change.
- **Custody and setup.** Custody of pooled value rests on proof soundness.
  - A development setup is disqualified for pooled value, because its holder
    could mint.
  - The first pool with value needs a permissionless ceremony whose assumption
    is 1-of-N honest contributions, or a no-setup pipeline. The Chipnet route
    is chosen by a gate that compares both routes on the same measurements,
    with numeric stop rules.
  - Before mainnet, the setup-free or two-independent-proof route is an
    operator decision.
  - There is no deposit cap (ARCH-196, operator decision 2026-09-24): custody
    of all pooled BCH rests on proof soundness, bounded only by pool-coin
    conservation, and a counterfeit note can withdraw other depositors' BCH.
  - A scoped soundness audit of the action circuit gates any value-bearing
    deployment and the permissionless mainnet ceremony (HUM-71, option C).
- **Proof system.** The child proof system stays a profile parameter. All
  in-circuit and in-script hashing is SHA-256. A prime-field hash is not
  adopted, which keeps a future Binius64 child adoptable. Whether a complete
  action proves within 16 GB is unmeasured. It is a gate before any Setup.

The shipped child route is gnark Groth16 revision 3 with simulated single-party research keys. Native wallet proof launch is unimplemented and is not deferred by the cited fit-engineering decision. Consumer fit remains an unfulfilled target. Phase 3 measures and discloses complete proving/workflow cost, including key load, machine/key/profile identity, peak host and VM memory, swap growth and wall time; engineering a fit is deferred with no fix promised. Prior measurement/operator exceptions do not establish a 16 GiB fit or repeal the original pre-Setup stop rule. No historical figure is represented as a new measurement.

- **Submission.** Every network egress of a privacy-default wallet, including
  self-settlement broadcast, goes over an anonymizing network. Anchors follow a
  stated staleness and retry policy. Its retry bound limits one attempt, and
  no action is ever submitted with a stale anchor.

Public single-action intake, chain collection and selected anchor/window checks exist. Reference Tor handoff and self-settlement APIs refuse as not implemented. The host defaults to requiring an anonymizing adapter; supported zero-value direct mode is an explicit metadata disclosure with no automatic fallback. It does not satisfy privacy-default egress. No complete anonymized self-settlement liveness path or measured production anchor/window policy is claimed. The all-wallet-egress anonymizing requirement and prohibition on note-keyed/tag-keyed queries remain; PLAN section 5 supplies no egress waiver.

- **Versioning.** Keyless covenants cannot be patched, so every pool deployment
  is versioned and a two-step migration shape to a successor pool is specified
  up front, with its limit for an unsound predecessor stated. The first
  Chipnet genesis that takes deposits needs the record-keyed deposit inbox,
  artifact revision 2 and its genesis inbox check. Only the locally tested
  migration action retains the first-genesis, labelled zero-value exception;
  no value-bearing deployment may use it.

The design was revised by ENG-262 on 2026-09-23 to close the findings of the
independent review REV-127 (verdict FAIL at `97717de0`). It was revised again
by ENG-268 the same day to close the round-2 review REV-129 (verdict FAIL at
`81ac241d`): anchor authenticity, one-to-one withdrawal outputs, the packet
key, the `profile_id` codec and the invoice gap rule. It has not yet passed a
review.

The preceding ENG-262/ENG-268 review narrative is dated history. The critical design review passed in round 3 (REV-131); that review implemented nothing. Current source status is the dated M1 reconciliation, with acceptance evidence kept separate.


**Retired from the privacy-default path** once this change passes design
review: seal cells, the owner co-signed seal (v1 and v2), the R2 relation's
cell and bundle coverage, and the private batch-wide equations. Retiring code
is a separate, later change; this change deletes nothing.

## Impact

The freeze records a dated status for each residual: public boundary arithmetic, shape, fees and timing; action grouping; root age; range/root-copy growth; invoice repeats, copies and collisions; invoice expiry timing; viewing-key compromise; rho-family disclosure; cloned-store/RNG risks; scan misses; cancellation assumptions; and funding ancestry. The wallet and Ink disclosures currently promise deep-scan or targeted-rescan recovery that the shipped command surface does not offer, while the host labels its capped prefix perEpochWindow. This is an unmet current disclosure obligation, not a reason to remove the target recovery commands or their required limits. LIMITS and the release README must carry the applicable limits with their actual implementation status. The bounded ancestry helper does not establish procedure-wide compliance, complete owner attribution, or the specified small-count/differencing policy. No achieved anonymity set is claimed.


- New capabilities:
  - `apnt-pool-note-statement`
  - `apnt-pool-nullifier-range-records`
  - `apnt-pool-note-tree`
  - `apnt-pool-settlement-custody`
  - `apnt-pool-receive-recovery`
  - `apnt-pool-privacy-model`
  - `apnt-pool-proof-system`
  - `apnt-pool-versioning-migration`
  - `apnt-pool-operations-harness`
- Supersedes, for the privacy-default path, the target architecture recorded in
  `add-apnt-successor-profile-v1`. That change stays active until a retirement
  change archives it, and its frozen artifacts are not edited.
- Affected code:
  - Pool implementation modules now exist in `protocol-runtime`,
    `reference-wallet` and `reference-aggregator`, with child-circuit, aggregate
    and modular-harness components. Source presence is not complete installed
    reproduction or runtime acceptance; the dated M1 status states the limits.
  - `chain-io`, the verifier ladder pattern, the recovery AEAD, the
    post-quantum invoice envelope and the build tooling carry over.
- Operator decisions, recorded 2026-09-23 (tasks.md section 0):
  - Chipnet setup (HUM-50): "Halo 2 first" as a time-boxed decision gate
    against a permissionless ceremony, not a commitment (task 5.0);
  - before mainnet (HUM-51/52): a setup-free pipeline or two independent proof
    systems per batch, chosen after both are measured;
  - pilot value cap through a keyless boundary meter UTXO: yes (HUM-53),
    reversed on 2026-09-24 (ARCH-196): the pool has no cap or meter;
  - AEAD inside the circuit: yes (HUM-54);
  - residuals (HUM-55): network origin and timing/root age reduced; the rest
    accepted and disclosed;
  - re-randomized spend keys: required in the first pool;
  - offline receive: required (HUM-58); proving is local on 16 GB hardware.
    Whether the complete action fits is unmeasured and gates Setup;
  - per-payment discovery tags: yes (HUM-75, 2026-09-24). The 8-byte slot and
    the T1 fill rule go in before the first Chipnet genesis, the minimal scan
    stays as fallback and option, there is no PIR in v1, and the
    invoice-repeat leak is accepted and disclosed. AGENTS.md's hard
    constraint now forbids *reusable* recipient markers on chain;
  - one seed keeps issuing after a restore: yes (HUM-77, 2026-09-24). T2's
    random invoice epochs and recipient-issued payment tags replace HUM-74
    option C's restore issuance hold and second seed, HUM-75's payment fill
    and bounded gap closing. The epoch-collision residual is disclosed;
  - FF1-AES256 as the tag cipher: yes (HUM-78, 2026-09-24), per SP 800-38G
    with the SP 800-38Gr1 draft's integer-only rule. The operator accepts the
    disclosed licensing risk; this is an operator decision, not a legal
    opinion. Current truth after REV-270: constant-time execution of the
    implemented FF1 is not established. It is accepted for explicitly
    labelled zero-value Chipnet tests only; ENG-583 blocks mainnet;
  - migration and deposit inbox: HUM-104 narrowed the 2026-09-24 exception.
    The first Chipnet genesis that takes deposits requires task 3.6's
    record-keyed inbox, artifact revision 2 and the genesis inbox check.
    Only the locally tested migration action (task 7.1) may be deferred for
    that explicitly labelled zero-value genesis. Both are required before
    any value-bearing deployment (ARCH-290, 2026-09-27).
