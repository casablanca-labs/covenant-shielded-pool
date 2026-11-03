import { bytesToHex, type Bytes32 } from "./bytes.js";
import {
  APNT_POOL_FAILURE_V1 as F,
  APNT_POOL_V1_MAX_MONEY_SATS,
  pool32,
  poolAnyBytes,
  poolArray,
  poolBoundary,
  poolConcat,
  poolEqual,
  poolFail,
  poolFailureCodeOf,
  poolRecord,
  poolRequire,
  poolSha256,
  type APNTPoolFailureV1,
} from "./apnt_pool_contract_v1.js";
import { deriveAPNTPoolDeploymentIdV1, type APNTPoolNetworkV1 } from "./apnt_pool_statement_v1.js";
import {
  apntPoolEmptyFrontierV1,
  deriveAPNTPoolFrontierRootV1,
  encodeAPNTPoolTreeUpdateCommitmentV1,
} from "./apnt_pool_frontier_v1.js";
import {
  APNT_POOL_V1_RANGE_GENESIS_MAXIMUM_LOG2,
  deriveAPNTPoolRangeGenesisRecordsV1,
  deriveAPNTPoolRangeRecordLockV1,
} from "./apnt_pool_range_record_v1.js";
import { buildAPNTPoolRangeRecordCovenantV1 } from "./apnt_pool_range_record_covenant_v1.js";
import { buildAPNTPoolInboxCovenantV1, APNT_POOL_V1_INBOX_REFUND_DELAY_BLOCKS, type APNTPoolInboxCovenantV1 } from "./apnt_pool_inbox_covenant_v1.js";
import { buildAPNTPoolSettlementCovenantsV1 } from "./apnt_pool_settlement_covenant_v1.js";
import { buildAPNTPoolNoteTreeCovenantsV1 } from "./apnt_pool_tree_covenants_v1.js";
import { buildAPNTPoolVerdictFactoryV1 } from "./apnt_pool_verdict_factory_v1.js";
import {
  APNT_POOL_V1_TOKEN_COMMITMENT_MAXIMUM_BYTES,
  poolDecodeTransaction,
  type APNTPoolTokenCapabilityV1,
  type APNTPoolTransactionOutputV1,
  type APNTPoolTransactionV1,
} from "./apnt_pool_transaction_v1.js";

/**
 * APNT shielded pool v1: the genesis validator (task 3.2; design.md,
 * "Genesis" and "Supply audit, then induction";
 * `apnt-pool-nullifier-range-records`, "Genesis is exact and its whole
 * category supply is audited").
 *
 * Given the pinned deployment artifact and the raw bytes of each genesis
 * transaction, it audits **every output of every pool category** in those
 * transactions, not only the advertised ones. In this order, refusing with the
 * first failing check's code:
 *
 * 1. the artifact's shape and values (`pool-genesis-artifact`), `g ≥ 1`
 *    (`pool-genesis-range-single-record`: every action inserts two nullifiers
 *    into two distinct records, so a one-record genesis could never settle),
 *    each category's display id the reverse of its wire id
 *    (`pool-genesis-category-order`), and its `deployment_id` the one derived
 *    from its network and wire-order categories (`pool-genesis-deployment`);
 * 2. each transaction strictly decodes, which refuses two inputs spending one
 *    outpoint (`pool-transaction`), and the ids of the
 *    transactions given are exactly the artifact's genesis ids
 *    (`pool-genesis-txid`);
 * 3. each category's genesis transaction spends outpoint `(category, 0)` in
 *    wire order (`pool-genesis-outpoint`; `pool-genesis-category-order` if it
 *    spends the display-order reading instead);
 * 4. every covenant lock is `OP_HASH256 <HASH256(redeem)> OP_EQUAL` of its
 *    redeem; the settlement and pool-coin locks are the shipped settlement
 *    covenants built with the artifact's network, categories, `K`, root-copy
 *    value, fold bounty `P_fold` and record value (ENG-270); the range
 *    covenant's redeem is the shipped range record's code CODE built with the
 *    artifact's verdict category and settlement lock (ARCH-245: each record
 *    sits under its own lock `P2SH32(push(lo‖hi) ‖ OP_DROP ‖ CODE)`, and none
 *    under the artifact's `P2SH32(CODE)`); the tree-update and root-copy locks
 *    are the shipped note-tree covenants built with its root and verdict
 *    categories, settlement lock, `K` and root-copy value (REV-151 H1-1); the
 *    artifact's locks are pairwise distinct, and none of their redeems is a
 *    pending-batch redeem `0x20 ‖ H_cm ‖ OP_DROP ‖ PCODE` for any `H_cm`
 *    (ENG-358, ARCH-245) or a record redeem for any data, all refused with
 *    `pool-genesis-covenant`;
 * 5. every output of every genesis transaction: none sits under the pool-coin
 *    lock, since genesis creates no pool coins (`pool-genesis-stray`); and of
 *    those carrying a pool category, none carries it in display order
 *    (`pool-genesis-category-order`); it sits in that category's own genesis
 *    transaction (`pool-genesis-stray`); a minting or mutable capability sits
 *    under that category's own covenant lock and no other: for the range
 *    category, one of the `2^g` genesis records' own locks
 *    (`pool-genesis-confinement`); it carries no fungible amount
 *    (`pool-genesis-amount`);
 * 6. per category, the outputs are exactly the artifact's and nothing else:
 *    - range: each a minting record (else `pool-genesis-stray`) under the lock
 *      of one of design.md's `2^g` records, with an empty commitment
 *      (`pool-genesis-range-record`) and the artifact's value
 *      (`pool-genesis-value`); no record twice (`pool-genesis-range-overlap`:
 *      two UTXOs of one record put every key of it in two records) and none
 *      missing (`pool-genesis-range-gap`);
 *    - root: one tree update (tree-update lock, minting, commitment
 *      `u64le(0) ‖ H_F(empty) ‖ root_empty`) and `K` root copies (copy lock,
 *      immutable, commitment `root_empty`); verdict: the artifact's
 *      verifier-factory tokens, under the factory lock. Anything else is
 *      `pool-genesis-stray`, a listed output with another value
 *      `pool-genesis-value`, and a listed output that is absent
 *      `pool-genesis-missing`.
 *
 * What the chain shows of a record (ARCH-245). A record's data is in its
 * redeem, so a genesis transaction shows only each record's lock hash. The
 * validator therefore identifies range outputs by matching their locks against
 * the `2^g` records design.md specifies; a record with any other data (an
 * overlapping, odd-bounded or unevenly split one) has a lock outside that set
 * and is refused as unconfined (step 5), or as stray if immutable (step 6).
 * `pool-genesis-range-boundary` (an odd endpoint) is therefore no longer
 * raised: an odd-bounded record is refused at step 5 instead.
 *
 * Why every capability counts. A stray minting range token outside the grid's
 * locks can mint any record, for example one over the whole key space, which
 * would let a nullifier be inserted twice. A stray immutable or mutable range
 * token can never serve as a record (the settlement requires minting records
 * at fixed positions and refuses the range category anywhere else), but the
 * audit still refuses it: the induction starts from exactly the listed supply.
 * A stray immutable verdict token under the settlement lock would be a
 * settlement authority for any statement. So no pool-category output outside
 * the artifact's exact list is accepted.
 *
 * What this is not. It does not fetch a transaction, check its confirmation
 * depth or that `(category, 0)` was spent only once: those are the wallet's
 * chain read. The settlement, pool-coin, range, tree-update and root-copy
 * covenants are compared against reviewed builds (the pending-batch redeem's
 * layout, which the settlement and the tree update embed, is derived from the
 * root category and has no artifact field); the verifier-factory covenant is
 * compared with the shipped pool-mode build bound to the pinned verifier graph
 * and SP1 recursion root. The genesis verdict supply is one empty-commitment
 * minting NFT at that factory. An immutable verdict cannot be a genesis output.
 * It sees the genesis transactions' outputs, not the tokens their inputs spend.
 * Passing it is not chain validation or wallet acceptance, and says nothing
 * about proof soundness.
 */

export type APNTPoolArtifactCategoryV1 = Readonly<{
  /** The category id in wire order: the genesis outpoint's txid as the transaction and the VM carry it. */
  wire32: Uint8Array;
  /** The same id in display order, recorded separately so a byte-order swap is visible. */
  display32: Uint8Array;
  /** The display-order id of the transaction that spends `(category, 0)`. */
  genesisTxidDisplay32: Uint8Array;
}>;

export type APNTPoolArtifactCovenantV1 = Readonly<{ redeemBytecode: Uint8Array; lockingBytecode: Uint8Array }>;

export type APNTPoolArtifactFactoryTokenV1 = Readonly<{
  capability: APNTPoolTokenCapabilityV1;
  commitment: Uint8Array;
  valueSats: bigint;
}>;

/**
 * The pinned deployment artifact (design.md, "Supply audit, then induction").
 * The pool has three categories and no meter or deposit cap (ARCH-196,
 * operator decision 2026-09-24); an artifact carrying any other field, the
 * retired meter's included, is refused with `pool-genesis-artifact`, as every
 * unknown field is. Its `deployment_id` is derived with `cat_meter` as 32
 * zero bytes, the canonical encoding's form for a deployment without a meter.
 */
export type APNTPoolDeploymentArtifactV1 = Readonly<{
  poolVersion: 1;
  /**
   * `local` is the zero-value-only local simulation deployment (ARCH-293). This audit binds the label only
   * through `deployment_id` and the covenants built from it; which chain the genesis was read from, and whether
   * an entry point may select this deployment at all, are the wallet's and the aggregator's checks.
   */
  network: APNTPoolNetworkV1;
  deploymentId32: Uint8Array;
  categories: Readonly<{
    verdict: APNTPoolArtifactCategoryV1;
    range: APNTPoolArtifactCategoryV1;
    root: APNTPoolArtifactCategoryV1;
  }>;
  covenants: Readonly<{
    settlement: APNTPoolArtifactCovenantV1;
    poolCoin: APNTPoolArtifactCovenantV1;
    range: APNTPoolArtifactCovenantV1;
    treeUpdate: APNTPoolArtifactCovenantV1;
    rootCopy: APNTPoolArtifactCovenantV1;
    verifierFactory: APNTPoolArtifactCovenantV1;
  }>;
  /** `g`: the genesis has `2^g` range records, `1 ≤ g ≤ 9`. */
  rangeGenesisLog2: number;
  /** `K ≥ 2` root copies. */
  rootCopyCount: number;
  /**
   * The satoshi value of each genesis output kind, from the deployment's dust policy, and the fold bounty
   * `P_fold` the settlement covenant requires of every pending output.
   */
  values: Readonly<{ rangeRecordSats: bigint; treeUpdateSats: bigint; rootCopySats: bigint; foldBountySats: bigint }>;
  /** Exactly one empty-commitment minting NFT under the shipped factory lock. */
  verifierFactoryTokens: readonly APNTPoolArtifactFactoryTokenV1[];
}>;

/** Revision 2 pins CODE metadata, not a fundable P2SH32(CODE) address. */
export type APNTPoolDeploymentArtifactV1Rev2 = Omit<APNTPoolDeploymentArtifactV1, "covenants"> & Readonly<{
  artifactRevision: 2;
  covenants: APNTPoolDeploymentArtifactV1["covenants"] & Readonly<{
    inbox: Readonly<{
      codeBytecode: Uint8Array;
      codeSha256: Uint8Array;
      refundDelayBlocks: typeof APNT_POOL_V1_INBOX_REFUND_DELAY_BLOCKS;
    }>;
  }>;
}>;

export type APNTPoolGenesisResultV1 =
  | Readonly<{
    valid: true;
    failureCode: null;
    deploymentId32: Bytes32;
    /** The audited genesis range records, ascending: the partition every later range state refines. */
    rangeRecords66: readonly Uint8Array[];
    /** Builder-derived CODE, or null for legacy revision 1. */
    inbox: APNTPoolInboxCovenantV1 | null;
  }>
  | Readonly<{ valid: false; failureCode: APNTPoolFailureV1; deploymentId32: null; rangeRecords66: null }>;

type CategoryName = "verdict" | "range" | "root";
type Category = { name: CategoryName; wire32: Bytes32; display32: Bytes32; genesisTxidDisplay32: Bytes32 };
type GridRecord = { data: Uint8Array; lock: Uint8Array };
type Covenant = { redeemBytecode: Uint8Array; lockingBytecode: Uint8Array };
type Expected = { lock: Uint8Array; capability: APNTPoolTokenCapabilityV1; commitment: Uint8Array; valueSats: bigint; remaining: number };
type Artifact = {
  revision: 1 | 2;
  inbox: { codeBytecode: Uint8Array; codeSha256: Bytes32; refundDelayBlocks: number } | null;
  network: APNTPoolNetworkV1;
  deploymentId32: Bytes32;
  categories: Category[];
  covenants: Map<string, Covenant>;
  log2: number;
  copies: number;
  values: { range: bigint; treeUpdate: bigint; rootCopy: bigint; foldBounty: bigint };
  factoryTokens: { capability: APNTPoolTokenCapabilityV1; commitment: Uint8Array; valueSats: bigint }[];
};

const CATEGORY_NAMES: readonly CategoryName[] = ["verdict", "range", "root"];
const COVENANT_NAMES = ["settlement", "poolCoin", "range", "treeUpdate", "rootCopy", "verifierFactory"] as const;
/** Which covenant lock a category's minting or mutable capability may sit under; for range, the grid records' own locks instead. */
const OWN_COVENANT: Readonly<Record<Exclude<CategoryName, "range">, (typeof COVENANT_NAMES)[number]>> = {
  verdict: "verifierFactory", root: "treeUpdate",
};
const CAPABILITIES: readonly string[] = ["none", "mutable", "minting"];
const MAXIMUM_REDEEM_BYTES = 10_000;
const MAXIMUM_FACTORY_TOKENS = 0xffff;
/**
 * `g ≥ 1` (REV-145 H1-1): every action inserts two nullifiers, which must lie in two distinct records
 * because a record splits at one key per transaction, so a `g = 0` genesis could never settle a first action.
 */
export const APNT_POOL_V1_RANGE_GENESIS_MINIMUM_LOG2 = 1;
const A = F.GENESIS_ARTIFACT;

const reversed = (bytes: Uint8Array): Uint8Array => bytes.slice().reverse();
const hash256 = (bytes: Uint8Array): Bytes32 => poolSha256(null, poolSha256(null, bytes));
const p2sh32 = (redeem: Uint8Array): Uint8Array => poolConcat(Uint8Array.of(0xaa, 0x20), hash256(redeem), Uint8Array.of(0x87));

function sats(value: unknown): bigint {
  poolRequire(typeof value === "bigint" && value >= 1n && value <= APNT_POOL_V1_MAX_MONEY_SATS, A);
  return value;
}

function categoryOf(name: CategoryName, value: unknown): Category {
  const input = poolRecord(value, ["wire32", "display32", "genesisTxidDisplay32"], A);
  return { name, wire32: pool32(input.wire32, A), display32: pool32(input.display32, A), genesisTxidDisplay32: pool32(input.genesisTxidDisplay32, A) };
}

function covenantOf(value: unknown): Covenant {
  const input = poolRecord(value, ["redeemBytecode", "lockingBytecode"], A);
  return { redeemBytecode: poolAnyBytes(input.redeemBytecode, A), lockingBytecode: poolAnyBytes(input.lockingBytecode, A) };
}

function artifactOf(value: unknown): Artifact {
  const revision = typeof value === "object" && value !== null && Object.hasOwn(value, "artifactRevision") ? 2 : 1;
  const input = poolRecord(value, [
    "poolVersion", "network", "deploymentId32", "categories", "covenants",
    "rangeGenesisLog2", "rootCopyCount", "values", "verifierFactoryTokens",
    ...(revision === 2 ? ["artifactRevision"] : []),
  ], A);
  poolRequire(input.poolVersion === 1, A);
  if (revision === 2) poolRequire(input.artifactRevision === 2, A);
  const network = input.network;
  poolRequire(network === "chipnet" || network === "mainnet" || network === "local", A);
  const covenantInput = poolRecord(input.covenants, revision === 2 ? [...COVENANT_NAMES, "inbox"] : COVENANT_NAMES, A);
  const covenants = new Map<string, Covenant>();
  for (const name of COVENANT_NAMES) covenants.set(name, covenantOf(covenantInput[name]));
  const inboxInput = revision === 2 ? poolRecord(covenantInput.inbox, ["codeBytecode", "codeSha256", "refundDelayBlocks"], A) : null;
  const inbox = inboxInput === null ? null : {
    codeBytecode: poolAnyBytes(inboxInput.codeBytecode, A),
    codeSha256: pool32(inboxInput.codeSha256, A),
    refundDelayBlocks: inboxInput.refundDelayBlocks as number,
  };
  if (inbox !== null) {
    poolRequire(inbox.codeBytecode.length >= 1 && inbox.codeBytecode.length <= 429, A);
    poolRequire(inbox.refundDelayBlocks === APNT_POOL_V1_INBOX_REFUND_DELAY_BLOCKS, A);
  }
  const log2 = input.rangeGenesisLog2;
  poolRequire(typeof log2 === "number" && Number.isSafeInteger(log2) && log2 >= 0 && log2 <= APNT_POOL_V1_RANGE_GENESIS_MAXIMUM_LOG2, A);
  poolRequire(log2 >= APNT_POOL_V1_RANGE_GENESIS_MINIMUM_LOG2, F.GENESIS_RANGE_SINGLE_RECORD);
  const categoryInput = poolRecord(input.categories, CATEGORY_NAMES, A);
  const categories: Category[] = CATEGORY_NAMES.map((name) => categoryOf(name, categoryInput[name]));
  const copies = input.rootCopyCount;
  poolRequire(typeof copies === "number" && Number.isSafeInteger(copies) && copies >= 2, A);
  const valueInput = poolRecord(input.values, ["rangeRecordSats", "treeUpdateSats", "rootCopySats", "foldBountySats"], A);
  const factoryTokens = poolArray(input.verifierFactoryTokens, MAXIMUM_FACTORY_TOKENS, A).map((entry) => {
    const token = poolRecord(entry, ["capability", "commitment", "valueSats"], A);
    poolRequire(typeof token.capability === "string" && CAPABILITIES.includes(token.capability), A);
    const commitment = poolAnyBytes(token.commitment, A);
    poolRequire(commitment.length <= APNT_POOL_V1_TOKEN_COMMITMENT_MAXIMUM_BYTES, A);
    return { capability: token.capability as APNTPoolTokenCapabilityV1, commitment, valueSats: sats(token.valueSats) };
  });
  poolRequire(factoryTokens.length === 1 && factoryTokens[0]!.capability === "minting" && factoryTokens[0]!.commitment.length === 0, A);
  return {
    revision,
    inbox,
    network,
    deploymentId32: pool32(input.deploymentId32, A),
    categories,
    covenants,
    log2,
    copies,
    values: {
      range: sats(valueInput.rangeRecordSats),
      treeUpdate: sats(valueInput.treeUpdateSats),
      rootCopy: sats(valueInput.rootCopySats),
      foldBounty: sats(valueInput.foldBountySats),
    },
    factoryTokens,
  };
}

const covenantLock = (artifact: Artifact, name: (typeof COVENANT_NAMES)[number]): Uint8Array => artifact.covenants.get(name)!.lockingBytecode;
const categoryNamed = (artifact: Artifact, name: CategoryName): Category | undefined => artifact.categories.find((category) => category.name === name);

/** Step 1 after the shape: byte order, distinctness and `deployment_id`. */
function checkIdentity(artifact: Artifact): void {
  for (const category of artifact.categories) poolRequire(poolEqual(category.display32, reversed(category.wire32)), F.GENESIS_CATEGORY_ORDER);
  const wires = new Set(artifact.categories.map((category) => bytesToHex(category.wire32)));
  poolRequire(wires.size === artifact.categories.length, A);
  const derived = deriveAPNTPoolDeploymentIdV1({
    network: artifact.network,
    verdictCategoryWire32: categoryNamed(artifact, "verdict")!.wire32,
    rangeCategoryWire32: categoryNamed(artifact, "range")!.wire32,
    rootCategoryWire32: categoryNamed(artifact, "root")!.wire32,
    meterCategoryWire32: null,
  });
  poolRequire(poolEqual(derived, artifact.deploymentId32), F.GENESIS_DEPLOYMENT);
}

/** Step 2: the transactions given are exactly the artifact's genesis transactions, each once. */
function transactionsOf(artifact: Artifact, value: unknown): Map<string, APNTPoolTransactionV1> {
  const expected = new Set(artifact.categories.map((category) => bytesToHex(category.genesisTxidDisplay32)));
  const raw = poolArray(value, CATEGORY_NAMES.length, F.GENESIS_TXID);
  const byTxid = new Map<string, APNTPoolTransactionV1>();
  for (const bytes of raw) {
    const transaction = poolDecodeTransaction(poolAnyBytes(bytes, F.TRANSACTION));
    const txid = bytesToHex(transaction.txidDisplay32);
    poolRequire(expected.has(txid) && !byTxid.has(txid), F.GENESIS_TXID);
    byTxid.set(txid, transaction);
  }
  poolRequire(byTxid.size === expected.size, F.GENESIS_TXID);
  return byTxid;
}

/** Step 3: each category's genesis transaction spends `(category, 0)`, wire order. */
function checkGenesisOutpoints(artifact: Artifact, byTxid: Map<string, APNTPoolTransactionV1>): void {
  for (const category of artifact.categories) {
    const inputs = byTxid.get(bytesToHex(category.genesisTxidDisplay32))!.inputs.filter((input) => input.outpointIndex === 0);
    if (inputs.some((input) => poolEqual(input.outpointTxidWire32, category.wire32))) continue;
    poolRequire(!inputs.some((input) => poolEqual(input.outpointTxidWire32, category.display32)), F.GENESIS_CATEGORY_ORDER);
    poolFail(F.GENESIS_OUTPOINT);
  }
}

/**
 * A reviewed build for the artifact's parameters, or `pool-genesis-covenant` if none exists: of the artifact's
 * values, only a `K` above a builder's bound, or a fold bounty not above `K × rootCopySats`, can cause a
 * parameter refusal. Any other builder failure (a source that cannot be read or compiled) is not a covenant
 * mismatch and is not reported as one (ENG-359).
 */
function reviewedBuild<T>(build: () => T): T {
  try {
    return build();
  } catch (error) {
    if (poolFailureCodeOf(error, F.SHAPE) !== F.COVENANT_PARAMETER) throw error;
    return poolFail(F.GENESIS_COVENANT);
  }
}

/** Whether `redeem` is `head ‖ any n bytes ‖ tail`. */
const hasShape = (redeem: Uint8Array, head: Uint8Array, n: number, tail: Uint8Array): boolean => redeem.length === head.length + n + tail.length
  && poolEqual(redeem.subarray(0, head.length), head) && poolEqual(redeem.subarray(head.length + n), tail);

/**
 * Step 4: P2SH32 locks of their redeems; the settlement, pool-coin, range code, tree-update and root-copy
 * redeems are the shipped covenants' builds; the artifact's locks are pairwise distinct, and no artifact redeem
 * is a pending-batch or record redeem of any digest or data. Without the builds, a genesis could put the root
 * minting NFT under any script (REV-151 H1-1), or a settlement lock that admits any verdict (ENG-270). Byte
 * equality of the redeems implies equality of the locks, checked first. Returns the pool-coin lock, whose
 * outputs genesis must not create, and the `2^g` genesis records with their own locks under the reviewed code.
 */
function checkCovenants(artifact: Artifact): { poolCoinLock: Uint8Array; grid: GridRecord[]; inbox: APNTPoolInboxCovenantV1 | null } {
  for (const covenant of artifact.covenants.values()) {
    poolRequire(covenant.redeemBytecode.length >= 1 && covenant.redeemBytecode.length <= MAXIMUM_REDEEM_BYTES, F.GENESIS_COVENANT);
    poolRequire(poolEqual(covenant.lockingBytecode, p2sh32(covenant.redeemBytecode)), F.GENESIS_COVENANT);
  }
  const redeemOf = (name: (typeof COVENANT_NAMES)[number]) => artifact.covenants.get(name)!.redeemBytecode;
  const settlement = reviewedBuild(() => buildAPNTPoolSettlementCovenantsV1({
    network: artifact.network,
    verdictCategoryWire32: categoryNamed(artifact, "verdict")!.wire32,
    rangeCategoryWire32: categoryNamed(artifact, "range")!.wire32,
    rootCategoryWire32: categoryNamed(artifact, "root")!.wire32,
    rootCopyCount: artifact.copies,
    rootCopySats: artifact.values.rootCopy,
    foldBountySats: artifact.values.foldBounty,
    recordValueSats: artifact.values.range,
  }));
  poolRequire(poolEqual(settlement.settlement.redeemBytecode, redeemOf("settlement")), F.GENESIS_COVENANT);
  poolRequire(poolEqual(settlement.poolCoin.redeemBytecode, redeemOf("poolCoin")), F.GENESIS_COVENANT);
  const inbox = artifact.inbox === null ? null : reviewedBuild(() => buildAPNTPoolInboxCovenantV1({
    verdictCategoryWire32: categoryNamed(artifact, "verdict")!.wire32,
    settlementLockingBytecode: covenantLock(artifact, "settlement"),
  }));
  if (inbox !== null) {
    poolRequire(poolEqual(inbox.codeBytecode, artifact.inbox!.codeBytecode), F.GENESIS_COVENANT);
    poolRequire(poolEqual(inbox.codeSha256, artifact.inbox!.codeSha256), F.GENESIS_COVENANT);
  }
  const range = reviewedBuild(() => buildAPNTPoolRangeRecordCovenantV1({
    verdictCategoryWire32: categoryNamed(artifact, "verdict")!.wire32,
    settlementLockingBytecode: covenantLock(artifact, "settlement"),
  }));
  poolRequire(poolEqual(range.codeBytecode, redeemOf("range")), F.GENESIS_COVENANT);
  const tree = reviewedBuild(() => buildAPNTPoolNoteTreeCovenantsV1({
    rootCategoryWire32: categoryNamed(artifact, "root")!.wire32,
    verdictCategoryWire32: categoryNamed(artifact, "verdict")!.wire32,
    settlementLockingBytecode: covenantLock(artifact, "settlement"),
    rootCopyCount: artifact.copies,
    rootCopySats: artifact.values.rootCopy,
  }));
  poolRequire(poolEqual(tree.treeUpdate.redeemBytecode, redeemOf("treeUpdate")), F.GENESIS_COVENANT);
  poolRequire(poolEqual(tree.rootCopy.redeemBytecode, redeemOf("rootCopy")), F.GENESIS_COVENANT);
  const factory = reviewedBuild(() => buildAPNTPoolVerdictFactoryV1({
    network: artifact.network,
    verdictCategoryWire32: categoryNamed(artifact, "verdict")!.wire32,
    settlementLockingBytecode: covenantLock(artifact, "settlement"),
  }));
  poolRequire(poolEqual(factory.redeemBytecode, redeemOf("verifierFactory")), F.GENESIS_COVENANT);
  const locks = new Set([...artifact.covenants.values()].map((covenant) => bytesToHex(covenant.lockingBytecode)));
  poolRequire(locks.size === artifact.covenants.size, F.GENESIS_COVENANT);
  // ENG-358 (REV-153 H3-1), under F1 (ARCH-245): each batch has its own pending lock, so a factory lock that is
  // any pending-batch lock would let a genesis token sit where a fold reads a settled verdict. Likewise no
  // artifact lock may be a record lock, where a settlement reads a record's data.
  const grid = deriveAPNTPoolRangeGenesisRecordsV1(artifact.log2).map((data) => ({
    data, lock: deriveAPNTPoolRangeRecordLockV1({ codeBytecode: range.codeBytecode, record66: data }).lockingBytecode,
  }));
  const record = deriveAPNTPoolRangeRecordLockV1({ codeBytecode: range.codeBytecode, record66: grid[0]!.data }).redeemBytecode;
  const recordHead = record.subarray(0, record.length - range.codeBytecode.length - 1 - 66);
  const recordTail = record.subarray(record.length - range.codeBytecode.length - 1);
  for (const covenant of artifact.covenants.values()) {
    poolRequire(!hasShape(covenant.redeemBytecode, tree.pendingBatch.head, 32, tree.pendingBatch.tail), F.GENESIS_COVENANT);
    poolRequire(!hasShape(covenant.redeemBytecode, recordHead, 66, recordTail), F.GENESIS_COVENANT);
  }
  return { poolCoinLock: settlement.poolCoin.lockingBytecode, grid, inbox };
}

type PoolOutput = APNTPoolTransactionOutputV1 & { token: NonNullable<APNTPoolTransactionOutputV1["token"]> & { nft: NonNullable<NonNullable<APNTPoolTransactionOutputV1["token"]>["nft"]> } };

/** Step 5: no pool coin, and every pool-category output of every genesis transaction, bucketed by category. */
function poolOutputsOf(artifact: Artifact, byTxid: Map<string, APNTPoolTransactionV1>, poolCoinLock: Uint8Array, grid: readonly GridRecord[]): Map<CategoryName, PoolOutput[]> {
  const buckets = new Map<CategoryName, PoolOutput[]>(artifact.categories.map((category) => [category.name, []]));
  const ownLocks = new Map<CategoryName, ReadonlySet<string>>(artifact.categories.map((category) => [category.name, category.name === "range"
    ? new Set(grid.map((record) => bytesToHex(record.lock)))
    : new Set([bytesToHex(covenantLock(artifact, OWN_COVENANT[category.name]))])]));
  for (const [txid, transaction] of byTxid) {
    for (const output of transaction.outputs) {
      // Genesis creates no pool coins (design.md, "Custody": genesis state is (cap, 0) and no pool coins).
      poolRequire(!poolEqual(output.lockingBytecode, poolCoinLock), F.GENESIS_STRAY);
      const token = output.token;
      if (token === null) continue;
      poolRequire(!artifact.categories.some((category) => poolEqual(token.categoryWire32, category.display32)), F.GENESIS_CATEGORY_ORDER);
      const category = artifact.categories.find((candidate) => poolEqual(token.categoryWire32, candidate.wire32));
      if (category === undefined) continue;
      poolRequire(bytesToHex(category.genesisTxidDisplay32) === txid, F.GENESIS_STRAY);
      poolRequire(token.nft === null || token.nft.capability === "none" || ownLocks.get(category.name)!.has(bytesToHex(output.lockingBytecode)), F.GENESIS_CONFINEMENT);
      poolRequire(token.amount === 0n, F.GENESIS_AMOUNT);
      buckets.get(category.name)!.push(output as PoolOutput);
    }
  }
  return buckets;
}

/**
 * Step 6, range: exactly design.md's `2^g` records, each once, identified by its own lock (step 5 already
 * refused every minting or mutable range token under another lock), each with an empty commitment and the
 * artifact's value. Two UTXOs of one record would overlap on every key of it; a missing record is a gap.
 */
function auditRange(artifact: Artifact, grid: readonly GridRecord[], outputs: readonly PoolOutput[]): readonly Uint8Array[] {
  const index = new Map(grid.map((record, i) => [bytesToHex(record.lock), i]));
  const seen = new Array<boolean>(grid.length).fill(false);
  for (const output of outputs) {
    const at = index.get(bytesToHex(output.lockingBytecode));
    poolRequire(output.token.nft.capability === "minting" && at !== undefined, F.GENESIS_STRAY);
    poolRequire(output.token.nft.commitment.length === 0, F.GENESIS_RANGE_RECORD);
    poolRequire(!seen[at], F.GENESIS_RANGE_OVERLAP);
    seen[at] = true;
    poolRequire(output.valueSats === artifact.values.range, F.GENESIS_VALUE);
  }
  poolRequire(seen.every(Boolean), F.GENESIS_RANGE_GAP);
  return grid.map((record) => record.data);
}

/** Step 6, root and verdict: the outputs are exactly the expected list. */
function auditExact(outputs: readonly PoolOutput[], expected: Expected[]): void {
  for (const output of outputs) {
    const nft = output.token.nft;
    const same = expected.filter((entry) => entry.remaining > 0 && entry.capability === nft.capability
      && poolEqual(entry.lock, output.lockingBytecode) && poolEqual(entry.commitment, nft.commitment));
    poolRequire(same.length > 0, F.GENESIS_STRAY);
    const match = same.find((entry) => entry.valueSats === output.valueSats);
    poolRequire(match !== undefined, F.GENESIS_VALUE);
    match.remaining -= 1;
  }
  poolRequire(expected.every((entry) => entry.remaining === 0), F.GENESIS_MISSING);
}

function expectedOf(artifact: Artifact, name: CategoryName): Expected[] {
  if (name === "root") {
    const empty = apntPoolEmptyFrontierV1();
    return [
      { lock: covenantLock(artifact, "treeUpdate"), capability: "minting", commitment: encodeAPNTPoolTreeUpdateCommitmentV1(empty), valueSats: artifact.values.treeUpdate, remaining: 1 },
      { lock: covenantLock(artifact, "rootCopy"), capability: "none", commitment: deriveAPNTPoolFrontierRootV1(empty), valueSats: artifact.values.rootCopy, remaining: artifact.copies },
    ];
  }
  const factoryLock = covenantLock(artifact, "verifierFactory");
  return artifact.factoryTokens.map((token) => ({ lock: factoryLock, ...token, remaining: 1 }));
}

/**
 * Audits a pool deployment's genesis against its pinned artifact: see the
 * module comment for every check and its code. `value` is
 * `{ artifact, genesisTransactions }`, the latter the raw bytes of each distinct
 * genesis transaction, in any order.
 */
export function validateAPNTPoolGenesisV1(value: unknown, requiredArtifactRevision: 1 | 2 = 1): APNTPoolGenesisResultV1 {
  try {
    const [clone] = poolBoundary([value]);
    const input = poolRecord(clone, ["artifact", "genesisTransactions"], F.SHAPE);
    const artifact = artifactOf(input.artifact);
    poolRequire(artifact.revision === requiredArtifactRevision, F.GENESIS_ARTIFACT);
    checkIdentity(artifact);
    const byTxid = transactionsOf(artifact, input.genesisTransactions);
    checkGenesisOutpoints(artifact, byTxid);
    const { poolCoinLock, grid, inbox } = checkCovenants(artifact);
    const buckets = poolOutputsOf(artifact, byTxid, poolCoinLock, grid);
    const rangeRecords66 = auditRange(artifact, grid, buckets.get("range")!);
    for (const name of ["root", "verdict"] as const) auditExact(buckets.get(name)!, expectedOf(artifact, name));
    return Object.freeze({
      valid: true,
      failureCode: null,
      deploymentId32: artifact.deploymentId32,
      rangeRecords66: Object.freeze(rangeRecords66.map((record) => record.slice())),
      inbox: inbox === null ? null : Object.freeze({ codeBytecode: inbox.codeBytecode.slice(), codeSha256: inbox.codeSha256.slice() as Bytes32, refundDelayBlocks: inbox.refundDelayBlocks }),
    });
  } catch (error) {
    return Object.freeze({ valid: false, failureCode: poolFailureCodeOf(error), deploymentId32: null, rangeRecords66: null });
  }
}
