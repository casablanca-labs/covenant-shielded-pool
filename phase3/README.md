# Phase 3 deliverables

This folder tracks what Phase 3 of the Covenant Shielded Pool campaign promises, and how you can check each item yourself. Every row links to its evidence once it is done. At the final milestone, this table becomes the release's map from each promise to its evidence.

The release is for **zero-value research on Bitcoin Cash Chipnet only**. Its cryptographic setup is simulated and run by the project, so the project could forge proofs. It must not protect real funds.

## Milestone 1: The protocol

| Deliverable | Status | How you can check it | Evidence |
|---|---|---|---|
| Specification, threat model and acceptance criteria | Done | Open the specification index; it lists each file's digest | [Specification index](../docs/spec/README.md) |
| How the pool works | Done | Read it in the repository | [How the pool works](../docs/how-the-pool-works.md) |
| Release identity check | Done | Run `pnpm check:identities`. It reports the circuit ID, verifying key, covenant bytecode and aggregate program digest, and whether each matches. The verifying key is checked against its published bytes; it cannot be re-derived from the simulated setup | [Release identity check](../README.md#check-the-release-identities) |
| Shared-pool analysis and reference-pool recognition draft | Done | Read it in the repository | [Shared pools and reference-pool recognition](../docs/shared-pools-and-recognition.md) |
| Recognition draft open for comment | Planned | Comment on the Bitcoin Cash Research forum thread | Forum thread link, added when posted |

## Milestone 2: A private send, Alice pays Bob

| Deliverable | Status | How you can check it | Evidence |
|---|---|---|---|
| The run's deposit and payment on Chipnet | Planned | Open the transaction IDs, listed by public role, on a Chipnet explorer | — |
| What a chain observer sees | Planned | A table of each transaction's public fields by role. The decoded amount fields have declared public roles; the action records have no dedicated plaintext field for an internal note's amount. Proof, ciphertext and discovery-tag bytes are opaque to this check and listed only by length. One command rebuilds the table from public chain data and confirms each transaction's inclusion, with no coins, wallet or proving | — |
| The recipient wallet's report | Planned | Read it in the repository. It is the wallet's own report of acceptance, reload and spendability. The chain can't show this, by design | — |
| Private send guide | Planned | Read it in the repository | — |

## Milestone 3: An onward payment, Bob pays Charles

| Deliverable | Status | How you can check it | Evidence |
|---|---|---|---|
| The new run's transactions on Chipnet | Planned | The published transaction IDs, listed by public role | — |
| Run record and measurements (proving time, memory, fees) | Planned | Files in this repository, drawn from public chain data and recorded measurements | — |
| Onward payment guide | Planned | Read it in the repository | — |
| Harness, commands and run directory | Planned | Read them in this repository. The commands are the ones the run used, and the record discloses any part that ran another way. Running them on your own machine comes with the participation kit | — |
| Four disclosures: one operator, zero-value coins, simulated setup, tiny anonymity set | Planned | In the run record and the README | — |

## Milestone 4: The exit, Charles pays out, and the reference release

| Deliverable | Status | How you can check it | Evidence |
|---|---|---|---|
| Exit: a private note paid out to an ordinary BCH address on Chipnet | Planned | Open the transaction ID on a Chipnet explorer and see the payout | — |
| Validate script and refusals | Planned | Run it locally, with no coins or proving. It confirms each transaction is on Chipnet and shows the documented refusals for expired, invalid, duplicate and stale inputs | — |
| Replay and re-check | Planned | Run the replay on a 16 GB machine, with no coins or proving. It reports pass or fail for each recorded transaction and proof | — |
| Exit guide | Planned | Read it in the repository | — |
| Tagged release with installation and reproduction instructions | Planned | Follow the README on a clean 16 GB machine | — |
| Versioned technical report | Planned | Linked from the release tag | — |
| Limitations report | Planned | Linked from the release tag | — |
| Commitment map | Planned | This table, completed, with every promise linked to its evidence | — |

## After Milestone 4: a participation kit

| Deliverable | Status | How you can check it | Evidence |
|---|---|---|---|
| Scripts to run your own wallets on this pool with your own test BCH | Planned, once it has passed a test outside the development environment | Follow the kit. It needs an Apple silicon Mac with about 22 GiB free when proving, Docker and test BCH | — |

## Not part of Phase 3

These are planned for future funding rounds:

- more worked examples and reference reports for building on the pattern;
- payments between different people's wallets, on separate machines;
- measuring anonymity as participants join, and hardening the pattern;
- a wallet application;
- a single command that runs the whole workflow without an agent;
- restoring into a fresh wallet;
- actively cancelling a pending payment.

Settling three or more funded transfers in one batch is specified, and demonstrating it is for a later stage.

Adoption into consensus is decided by the community through the CHIP process. This release promises neither adoption nor a date.
