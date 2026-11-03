# Pool action circuit (gnark Groth16, BN254)

The APNT shielded pool v1 action relation (`design.md`, "Actions" 1–7) as a
gnark v0.16.3 circuit, for proof-system registry entry 1 (task 5.1a, ENG-318),
revision 3: one hashed public input (HUM-80, ENG-437) over the 314-byte record,
each output's `rcm` derived from its `K` and `ρ`, and the 16-byte SHA-256-pad
packet in place of AES-256-GCM (pad16, HUM-84, ENG-454).

The versions are gnark v0.16.3 and gnark-crypto v0.21.0 (ENG-367). v0.16.3
carries the fixes for gnark advisory GHSA-3mvx-pp85-pm65, which lists every
gnark release below v0.16.2 as affected. `registry.go` names
the versions, and `TestGnarkVersionsMatchGoMod` holds them equal to this
module's `go.mod` and to `tools/apnt-pool-ceremony`'s, so phase 2 and the
circuit use one gnark. A gnark change changes the R1CS digest: re-measure it
before any Setup.

The canonical relation is the host's
(`packages/protocol-runtime/src/apnt_pool_action_relation_v1.ts`). The circuit
matches it and never redefines it. Parity runs the host's own vectors
(`packages/protocol-runtime/test-vectors/apnt-pool-v1-action-circuit-vectors.json`,
built and checked by `packages/protocol-runtime/test/apnt_pool_action_circuit_corpus_v1.test.ts`)
through the compiled constraint system with gnark's R1CS solver.

**The root package runs no Setup and no proof, and writes no key.** Package
`devprove` (task 5.1b, ENG-299) does, under development parameters only:
gnark's `groth16.Setup` with its internal randomness, which nothing destroys.
Every file and result it writes carries the label
`DEVELOPMENT ZERO-VALUE — toxic waste not destroyed; forgeable; never for value`.
Those keys are forgeable. They never guard value, and their verifying key is
never allowlisted. The Chipnet keys come from the ceremony tooling
(`tools/apnt-pool-ceremony`). This module's tests run Setup and prove only on
a small test circuit.

## Relation

Public input: one BN254 scalar, `x = int_be(SHA-256(A)) mod r`: SHA-256 over
the 314 bytes of the action record `A` with no tag, the digest read big-endian,
reduced mod the BN254 scalar field order `r` (2 R1CS public variables with the
constant one). `PublicInput` computes it; it matches the host's
`deriveAPNTPoolActionPublicInputV1` on the host's vectors
(`packages/protocol-runtime/test-vectors/apnt-pool-v1-action-public-input-vectors.json`,
every quotient `⌊int_be(d)/r⌋` from 0 to 5). Every verifier derives `x` from
the `A` it holds and never takes it from a prover: the proof binds a field
element, and an integer spelling of it at least `r` names the same one
(parity case `x-as-unreduced-integer`).

Private witness: the record `A`, range-checked byte by byte exactly as when
it was public (clause `record-bytes`), and per input slot: `u64le(v)`, `ak` as
affine secp256k1 coordinates, `nk`, `ρ`, `rcm`, the note's recovery tag, `α`
and a depth-32 path.
Per output slot: `u64le(v)`, the owner tag `O`, `ρ` and `K`, and no `rcm`: the
circuit derives it (below). There is no field for `ask` or `rsk`
(`TestWitnessHasNoSpendAuthority`).

The output side (pad16, clauses `output-commitment` and `packet`):

```text
rcm_j    = SHA-256("APNT-POOL-v1:rcm" ‖ K ‖ ρ)            over the output's own K and ρ
cm_j     = SHA-256("APNT-POOL-v1:cm" ‖ u64le(v) ‖ O ‖ ρ ‖ rcm_j ‖ SHA-256("APNT-POOL-v1:rt" ‖ K))
d_j      = SHA-256("APNT-POOL-v1:pad" ‖ K ‖ ρ ‖ cm_j)
packet_j = (u64le(v) ⊕ d_j[0..8)) ‖ d_j[8..16)             16 bytes, no MAC
```

The packet has no MAC: its integrity is this clause, the record hash and the
owners' signatures; `d_j[8..16)` is a key check for a wallet's trial
decryption only. There is no AES in the circuit. Five test-only mutations
(`mutation-rcm-without-rho`, `-rcm-other-slot-rho`, `-packet-key-without-cm`,
`-pad-check-unbound`, `-pad-under-pk-tag`) are faulty builds the parity suite
shows admitting their own corpus negative and refusing an honest record.

An input's owner tag is `SHA-256("APNT-POOL-v1:owner" ‖ SEC1c(ak) ‖ nkc)`, with
`nkc = SHA-256("APNT-POOL-v1:nkc" ‖ nk)` computed from the same `nk` the
nullifier takes (ENG-329, clause `owner-tag-over-nkc`). The witness carries `nk`
only; `nkc` is never a witness field.

Every host check is a named clause in `circuit.go` (`Clauses`, with the host
failure code each serves in `ClauseHostCode`). The parity suite removes one
clause at a time and shows a named negative becoming satisfiable; negatives
that other clauses also refuse are recorded as overlaps, with the clause set
that admits them.

Clause `record-hash` (ENG-437) hashes the same record variables every other
clause reads, range-checks the 32 digest bytes and recomposes them big-endian
in the native field, where the sum is the digest reduced mod `r`; one equality
ties it to `x`. With it removed the circuit has 5,709,709 constraints (at
revision 2 it was exactly the revision-1 relation's 5,891,129), and `x` binds
nothing: parity shows a record
and `x` that disagree (`hash-of-other-record`), `x + 1` and a truncated `x`
becoming satisfiable. Its SHA-256 gadget range-checks the record bytes too, so
it overlaps `record-bytes`: the record's non-byte negatives stay refused with
either clause removed and become satisfiable only with both.

The compiled R1CS (`counts`: 5,918,922 constraints, domain 2^23, SHA-256
`7c32a8f691c8b3a60bd1c89364a9fc1a76b1a5fc576d21722eb4fc7f9155d31e`) is
byte-identical to ARCH-247's pad16 research prototype (lane
`lane/pool-packet-compress`, `46a238c6`, package `compactpacket`), whose parity
run it therefore shares; `TestRevision3R1CS` pins it. Revision 2's R1CS
(6,135,851 constraints, `25d3f54d…`) was byte-identical to ARCH-235's
prototype (`d4113a35`); its development Setup and prove, and its Chipnet
simulated-ceremony keys, are revision 2's and key nothing here.

## Commands

Check `vm_stat` first: at gnark v0.16.3 a compile peaks near 7 GB resident
(`counts` about 7.6 GB with serialization).

```sh
cd tools/apnt-pool-action-circuit
GOMAXPROCS=4 GOMEMLIMIT=6GiB nice go test -count=1 -timeout 60m .       # parity, mutations, registry (about 10 min, 8.1 GB)
GOMAXPROCS=4 nice go run ./cmd/pool-action-circuit counts OUT.json      # counts, domain, vp topology
GOMAXPROCS=4 nice go run ./cmd/pool-action-circuit attribute OUT.json   # constraints per clause
```

`POOL_ACTION_PARITY_RESULTS=FILE` makes `TestParity` write every case's
expected and observed result.

## Task 5.1b: the action proof under development parameters

Three commands, each in its own process so that each phase's peak RSS is its
own. `DIR` and `OUT.json` must lie outside any git work tree, and nothing is
overwritten.

```sh
pool-action-circuit devsetup  --expect-r1cs-sha256 HEX DIR OUT.json  # compile, refuse unless the R1CS digest is HEX, Setup
pool-action-circuit devprove  [--corpus FILE] DIR OUT.json           # load R1CS and pk (timed), prove, write the proof
pool-action-circuit devverify [--corpus FILE] DIR OUT.json           # verify; one flipped public input must be refused
```

- `devsetup` has no default digest. On a mismatch it writes nothing to `DIR`
  and runs no Setup.
- `devprove` and `devverify` refuse a `DIR` without the development label, and
  check every file they load against the manifest `devsetup` wrote.
- The witness is the corpus's reference positive
  `rel1-real-real-deposit-withdrawal`. It has two real inputs with membership
  paths, a deposit and a withdrawal.
- `devverify` rebuilds the public witness, `x` of that entry's record. It then
  verifies the same proof against `x` with its low bit flipped, which must be
  refused.

`scripts/measure-5-1b.sh OUT-DIR EXPECTED-R1CS-SHA256 [GOMAXPROCS]` runs the
three phases in series under `nice` and `caffeinate -i`, from a fresh build.
It refuses before each phase unless at least 20 GiB is available and no other
prover is running, and it holds the machine-wide prover lock. It samples swap
and RSS every 5 s and kills a phase on 16 GiB of swap growth or 30 GiB of RSS.
It writes `keys/`, `results/` and `bin/` under `OUT-DIR`. With
`DEVPROVE_TARGET=small` it runs the small test circuit instead, to test the
script; the floor is then 2 GiB. The environment can only tighten the
thresholds (`MEASURE_MIN_AVAILABLE_BYTES` raises the floor;
`MEASURE_RSS_TRIP_BYTES` and `MEASURE_SWAP_GROWTH_TRIP_BYTES` lower the trips).

```sh
GOMAXPROCS=4 nice go test -count=1 ./devprove/   # small test circuit only: Setup, prove, verify, refusals
```

## ENG-424: pinned-digest fast proving-key loading (research prototype — not reviewed)

Package `pkload` loads a proving key without gnark's per-point checks, and only
after the file's size (from fstat, before any read) and SHA-256 (over the bytes
read into memory the process owns) equal a pin. Nothing in the file is decoded
before both match: every decoder takes a `Verified`, which only `ReadVerified`
makes. Formats: the ceremony's raw encoding (gnark `UnsafeReadFrom`), gnark
`WriteDump`, and an image (`APNT-PK-IMAGE-v2`) whose point slices are views into
the verified buffer. The image header binds the writing build's point layout (a
fingerprint computed at run time) and its gnark and gnark-crypto versions, and
the reader refuses any other (`layout.go`). `Derive` makes the image once from
the raw key: it checks the raw pin first, then decodes those same bytes with
gnark's checked `ReadFrom`.

What the pin gives is byte identity with a known key: the raw digest is the one
the 5.1c transcript names (its verifier re-derives the key and hashes its
`WriteRawTo` encoding), and the image digest is what `Derive` makes from it.
Skipping the per-point checks relies on that identity only. It does not show the
key is a well-formed Groth16 CRS: zero knowledge under the pinned key also
depends on the ceremony verifier covering CRS well-formedness, which is open
(ARCH-238) and not claimed here.

`pins.go` pins revision 3's Chipnet zero-value files (`ChipnetZeroValueRevision3`,
SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY): the R1CS, raw key and
verifying key are the registry's values, and the image is what `Derive` made
from the raw key on this build's point layout (2,751,007,808 bytes, SHA-256
`eff8cdbd…`; two derivations byte-identical, R-466). Revision 2's keys were
never pinned here.

Command `pool-pk-load` measures the loaders and a wallet prove; it records a
proof only after it verifies under the pinned verifying key. Its streaming
no-pin cases are measurement-only baselines. `scripts/measure-pk-load.sh
OUT-DIR PLAN` runs a plan of cases, one process each, under the machine-wide
prover lock. Measurements and the trust design:
`private historical record ENG-424`; review REV-191 and its fixes:
`private historical record ENG-435`.

```sh
GOMAXPROCS=4 nice go test -count=1 ./pkload/ ./cmd/pool-pk-load/   # small test circuit only
```

## Live wallet request admission (ENG-575)

`pool-pk-load admit-request --request PRIVATE.json` consumes the wallet's
`proverDelegable.requestJson` file, using the same strict `CorpusWitness`
decoder and `CorpusEntry.Assignment` builder as corpus inputs. The outer wallet
result is not this file. The admitted `positive` names are `wallet-payment`
(deposit = withdrawal = 0), `wallet-inbox-deposit` (deposit > 0,
withdrawal = 0), and `wallet-withdrawal` (deposit = 0, withdrawal > 0).
The older `wallet-self-deposit` name remains admitted for its existing wallet
producer until that producer is retired. The withdrawal amount and lock hash
must obey the record rule. Unknown names/kinds and mismatched action shapes
fail closed. Admission checks shape and assignment only; the pinned relation
must solve before the result can count as a valid action.
The request is bounded to 1 MiB and decoded once per invocation; the prove
process retains its admitted witness through cache preparation and key loading,
without re-reading the file. The final request path component must be a regular
file, opened with `O_NOFOLLOW | O_NONBLOCK`; symlinks, FIFOs and devices refuse.
This is one bounded read through one descriptor and a retained decoded witness,
not an atomic filesystem snapshot during concurrent writes. Shell pre-admission
and child admission can see different files. The child's snapshot is the one
used, and malformed/symlink replacement refuses before child cache work. The shared decoder rejects unknown fields, trailing JSON and
input/output arrays whose length is not two.

Admission requires these existing pins, supplied explicitly using the normal
CLI flags (values in `pkload/pins.go`, never caller-chosen replacements):

```text
--format image --pin-bytes IMAGE_BYTES --pin-sha256 IMAGE_SHA256
--r1cs-bytes R1CS_BYTES --r1cs-sha256 R1CS_SHA256
--vk-bytes VK_BYTES --vk-sha256 VK_SHA256
--profile-id ea3d52d762f394b2959740126c3fb441165236696a02314a19498b48e2f1c1f2
```

`raw` with the existing raw-key pin is also supported. `dump`, missing pins,
other revisions/profiles, `--corpus` together with `--request`, and a live
request with `--target small` are refused. Named request failures are
`live-request-malformed`, `live-request-unknown-entry-kind` and
`live-request-pin-mismatch`; details that might echo private values are
withheld. `admit-request` writes an admission receipt outside the repository
and loads no key files. It checks assignment and pin **declarations**, not
the relation or the key files' contents. Its success is not host acceptance,
proof verification, chain validation or wallet acceptance.

### Private wallet construction and runner admission (inactive v2)

MIG01 RR stages this v2 contract; production remains v1 until C1. The new
supervisor CLI refuses while inactive. These target commands are not an
operator-ready path or proving authorization. Whole-runtime and kernel
controls belong to VR/C1; no genuine kernel positive is certified here.

At cutover, private requests run only through their owning foreground procedure. A
positively enrolled harness home creates a request route at the actual native
constructor. Its fixed handle-key-only PLAN writer then binds a new private
PLAN to that construction; writing a route grants no invocation authority.
With the public result/handle and reviewed key paths selected, the operator
uses these exact entry points on clean main:

```sh
node tools/pool-action-modules/harness-child-plan.mjs --payment "$payment" --wallet "$wallet" --wallet-home "$walletHome" --key "$pk" --r1cs "$r1cs" --vk "$vk" --plan "$plan" --kind invoice-payment --backend local
node tools/pool-action-modules/harness-private-runner.mjs "$out" "$plan" 4
```

Inbox-deposit uses `--kind inbox-deposit`. Host-provisioned payment homes
instead use `wallet-mvp-owner.mjs prepare RUN INSTANCE NETWORK`, followed by
`child-prove RUN INSTANCE NETWORK [ORDINAL]` and the separate owner `import`.
The owner connection remains attached throughout the fixed child. Raw Bash,
old redirected-stdout PLAN production and a retained input path do not admit
private acquisition. The ordinary direct Go entry also requires the genuine
runner before opening private input. Payment, inbox-deposit, self-deposit and
withdrawal reader labels share admission; a label is no construction writer.
No production withdrawal PLAN writer is supplied by MIG01.

The fixed committed public measurement selector is
`tools/apnt-pool-action-circuit/scripts/public-pk-load.plan`. Public measurement
may call Bash with that exact absolute path; an ad hoc public PLAN has no
supported bypass. Private PLANs, requests and wallet material stay outside
reports. Existing canonical registry/key pins remain unchanged. Child
proving and key-loading admission retain their memory floors (17 GiB for live
proving, measured as free + inactive + speculative, excluding purgeable);
aggregate runners retain 20 GiB. Pure `check-live` has no proving memory floor
or memory-admission wait.

The harness retains its exclusive machine lock, marker, other-prover
check, mode-aware memory gate, swap/RSS monitor, fresh build and nice/caffeinate wrapper.
The live CLI binds its current checkout to the absolute source checkout which
built it, checks clean `main`, authenticates the actual bash ancestor and its
script copy against the committed harness, and checks the inherited locked
descriptor and marker. Relocated or `-trimpath` builds fail closed. The CLI
independently checks competing provers, available memory and swap/RSS; it starts
its own fail-closed one-second monitor before any key work. PID, marker and lock
signals alone cannot skip those checks. Live cache preparation (`--live-cache`)
is performed only in this child after it admits its witness, under that guard.
The shell keeps its own checks and monitor as well.

`check-live --request PRIVATE.json` with the same pins, through a harness plan
with a whole-GiB floor field from 1 to 99, exercises admission without a proving
memory floor, then exits without cache work, key loading, Setup or proving.
For this mode the floor field is metadata; exclusivity, checkout, authentication
and swap/RSS checks still apply. This is a no-proof diagnostic;
it grants no permission to a later process. Tests inject samples only into Go
functions; the shipped CLI has no resource-check bypass switch. The unchanged fast loader checks actual file lengths and digests;
the proof is released only after verification and the flipped-public-input
control succeed. A low-level `--corpus` measurement invocation retains its
existing interface. It authenticates the exact bytes it decodes against the
canonical corpus committed at this build checkout's HEAD before claiming
`kind: committed-corpus`; caller paths and renamed entry labels cannot grant
that provenance. This authenticates source, not private semantic validity.

Receipts label the source `kind: live-request`. They contain no corpus
provenance, request digest/path, caller notes or witness bytes; live command
arguments and all key paths are omitted, aliases of the request in key/R1CS/VK
options are refused, and loader/verification errors are value-free. The harness
records a fixed notice instead of copying private plan text, omits live output
and checkout paths from run metadata, and uses value-free live diagnostics.
A live plan must contain only live prove/check-live cases; separate measurement
plans prevent a raw key-read case from disclosing an alias of a live input. Private requests
and original plans must never be copied into evidence. Keep the request
wallet-local and private. Delegation
would disclose private proving material and is never implied by admission.
These are simulated single-party Chipnet keys: the project can forge proofs,
and they are zero-value tests only. No live proof or Setup was executed for
this entry-point slice.

Focused no-Setup/no-proof checks (do **not** omit `-run`; other tests prove):

```sh
GOMAXPROCS=4 go test -p 1 -count=1 ./devprove ./cmd/pool-pk-load -run '^TestLive'
python3 scripts/test-prove-memory-floors.py  # synthetic 17/16 child and 20/19 aggregate gates; no prover
```

## What "unsatisfied" means

gnark's solver runs the honest hint functions; "unsatisfied" means the
constraints fail for those hint outputs. It does not prove that no choice of
the hinted internal variables satisfies them: that soundness rests on gnark's
gadgets (SHA-256, emulated secp256k1, lookups, range checks). "Satisfied" is
definitive.

`TestEmulatedMulCarryWrapProbe` is the one adversarial-hint regression so far
(ENG-324, ENG-367). On a small gadget circuit, not the action circuit, it
overrides gnark's emulated `mulHint` so that `Z ≡ X·Y + q (mod p)`, with the
carries recomputed mod q. gnark v0.15.0's solver accepted that; v0.16.3 must
refuse it at a constraint, and the test fails otherwise.

## Proof-system registry entry 1, revision 3

`registry.go` fixes `system_id = 1`, the `vp` serialization (gnark v0.16.3
`(*groth16/bn254.VerifyingKey).WriteTo`, compressed), the public-input rule
(`PublicInput`) and `profile_id`, and checks the Go `profile_id` against the
host's vectors. Revision 3 (pad16, ENG-454) keeps revision 2's topology, one
public input: `|K| = 3` and `len(vp) = 528`.

Its one recorded `vp` is the **Chipnet zero-value vp** (ENG-446): the verifying
key of the task-5.1c simulated single-party ceremony re-run on revision 3
(ENG-483; 528 bytes, SHA-256 `35c2bdb2…`, `profile_id` `ea3d52d7…`), with its
provenance (transcript `31def532…`, anchored verify VALID, CRS release gate
RELEASE-OK with report SHA-256 `54c07aea…`). **SIMULATED SINGLE-PARTY SETUP -
ZERO-VALUE TEST ONLY**: the project could forge proofs under it, so it never
guards value, and mainnet needs a permissionless multi-party ceremony.
`ChipnetZeroValueRevision3VP` returns it after checking its digest and
`profile_id`; `TestChipnetZeroValueRevision3VP` reads it with gnark's checked
reader and ties its shape to the compiled circuit's topology; the registry
vector file carries it as `chipnetZeroValueVp`. Recording it allowlists
nothing: the aggregate program's canonical allowlist is task 5.4 slice 2's.

The shape vector in
`packages/protocol-runtime/test-vectors/apnt-pool-v1-proof-system-registry-rev3-vectors.json`
is built from hash-to-curve points to pin the byte layout and length; it is
byte-identical to revision 2's, because the shape depends on the topology
alone. It is not a verifying key, and its `profile_id` must never be
allowlisted. Nor is a development-parameter verifying key from `devprove` a
`vp`: it never enters the registry.

Revision 2 (ENG-437; R1CS `25d3f54d…`, the 396-byte record and the 57-byte
AES-256-GCM packet) is superseded. Its vector file,
`apnt-pool-v1-proof-system-registry-rev2-vectors.json`, is kept byte for byte
(its SHA-256 is pinned by `TestRegistryRevision1IsSupersededUnchanged`), and
its Chipnet simulated-ceremony keys (task 5.1c re-run, ENG-445; vk SHA-256
`a82a7248…`) are zero-value test evidence for revision 2 and never a `vp` for
revision 3.

Revision 1 (396 public record bytes, `|K| = 398`, `len(vp) = 13,168`) was
revised before any `vp` was allowlisted anywhere. Its vector file,
`apnt-pool-v1-proof-system-registry-vectors.json`, stays unchanged as the
superseded revision's record, and `TestRegistryRevision1IsSupersededUnchanged`
still reproduces its shape vector and `profile_id` from its own topology. The
task-5.1c Chipnet keys (R1CS `a042b497…`) are for revision 1: superseded
evidence, never a `vp`.

The focused macOS no-proof controls exercise the real shell and stock runner in
a disposable clean-main fixture checkout with no keys. Run them outside an agent
Seatbelt sandbox, never alongside prover work, while the host test slot is free
or held by the caller:

```sh
python3 scripts/test-live-entry-no-proof.py /private/tmp/NEW-live-controls [--mutations]
```

The output directory must be new, absolute and outside Git. Component baselines
run on the exact source tree, whose production selectors are fixed at
generation 2 since C1; the runtime controls and, with `--mutations`, all 42
mutation groups run on the runtime entry's private test composition, which
production now carries (verified in place and committed empty, so the composed
tree is the source tree). Only `closed-summary.json`, written
once after every group is restored and every stage's process group is reaped,
is intended for review; the other files include synthetic private-input
fixtures. The positive command is `check-live`; negative `prove` invocations
must refuse before key work. No `Setup` or proof generation runs.

For MIG01 promotion, from the clean repository root on Node v22.22.3, the
supervisor uses this single validation command inside its admitted promotion
window (HUM-166 still applies):

```sh
node scripts/test-slot/test-slot.mjs run mig01-certification -- python3 tools/apnt-pool-action-circuit/scripts/mig01-certification.py /private/tmp/NEW-mig01-certification
```

It runs `validate:all-safe:steps` in order, expanding the modules gate and
replacing only its final runtime entry with the full restore/reservation
rollback oracle and `test-live-entry-no-proof.py NEW_ROOT --mutations`.
The driver includes the native inventory supplement, one full runtime baseline,
both registered-observer poison/restore controls, and all 42 mutation pairs.
Do not prepend the ordinary complete modules gate or the baseline-only driver:
that would repeat the runtime. Success is exit zero with `certification-record.json`
and the driver's `closed-summary.json`, after restoration and process reaping.
Those closed files contain fixed identifiers, counts, statuses and public code
or build digests. Raw reports, commands and observer diagnostics remain private.
This recipe does not merge, promote, activate v2, or authorize a runtime run.
## Portable native installation paths

The private runner selects Node 22.22.3 from the committed installation
configuration in `tools/pool-action-modules/lib/private-runner-installation.mjs`.
Its versioned location is relative to the home returned by the operating
system's account database. Caller `HOME`, `PATH` and executable arguments do
not select the trusted interpreter. The installation verifier still requires
clean canonical main, committed source, the installed graph receipt, and the
exact measured version before returning the executable to Go or the shell.
The public export alone is not an installed-runtime qualification receipt.

Offline frozen-oracle replay controls take the external fixture location from
`PRIVATE_RUNNER_FROZEN_ORACLES`; their existing exact SHA-256 and bound-oracle
checks remain mandatory. No fixture contents or local producer directories
are included here. Historical archive tags in verifier tooling identify Git
objects, rather than a required local directory.
