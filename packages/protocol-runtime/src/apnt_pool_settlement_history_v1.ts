import { bytesToHex, type Bytes32 } from "./bytes.js";
import { type APNTPoolActionRecordFieldsV1 } from "./apnt_pool_action_record_v1.js";
import {
  APNT_POOL_FAILURE_V1 as F,
  APNT_POOL_V1_DISCOVERY_TAG_BYTES,
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
  poolU64le,
  type APNTPoolFailureV1,
} from "./apnt_pool_contract_v1.js";
import {
  APNT_POOL_V1_FRONTIER_BYTES,
  decodeAPNTPoolTreeUpdateCommitmentV1,
  evaluateAPNTPoolTreeUpdateV1,
} from "./apnt_pool_frontier_v1.js";
import { validateAPNTPoolGenesisV1, type APNTPoolDeploymentArtifactV1 } from "./apnt_pool_genesis_v1.js";
import {
  decodeAPNTPoolRangeRecordDataV1,
  deriveAPNTPoolRangeGenesisRecordsV1,
  deriveAPNTPoolRangeKeyV1,
  deriveAPNTPoolRangeRecordLockV1,
  splitAPNTPoolRangeRecordV1,
} from "./apnt_pool_range_record_v1.js";
import { decodeAPNTPoolStatementV1 } from "./apnt_pool_statement_v1.js";
import { poolDecodeTransaction, type APNTPoolTransactionV1 } from "./apnt_pool_transaction_v1.js";
import { deriveAPNTPoolPendingBatchLayoutV1, getAPNTPoolTreeCovenantSourceV1 } from "./apnt_pool_tree_covenants_v1.js";

/**
 * APNT shielded pool v1: what one settlement shows a reader of the settlement
 * lock's script-hash history (ARCH-245, ARCH-234 D2).
 *
 * Before D2 every range record sat under one range lock, and a wallet learned
 * whether its note was spent from that lock's history (design.md, "Nullifier
 * status"). Under D2 each record has its own lock, so that history no longer
 * exists. The settlement lock's history carries the same information: every
 * settlement spends a verdict under the settlement lock at input 0, pushes `S`
 * there, and inserts exactly `S`'s `2B` nullifiers (check 4). A wallet reads
 * the whole history, never querying by its own nullifier, and its note is
 * spent exactly when its nullifier is among some settlement's.
 *
 * Anyone can pay to the settlement lock, so a transaction in its history is
 * not necessarily a settlement, and one whose input 0 merely pushes the
 * settlement redeem last could be spending any bare script. This reader
 * therefore also requires what only the settlement covenant creates: output 0
 * carries a verdict-category token with no capability committing
 * `SHA-256(S)`, under the batch's pending lock `P2SH32(0x20 ‖ H_cm ‖ tail)`
 * with `H_cm` the SHA-256 of `S`'s leaves (check 6). A no-capability verdict
 * token leaves the settlement lock only through a settlement, which moves it
 * there and nowhere else (ARCH-190's interim stand-in factory, which can mint
 * one freely, is open and must be closed before this holds on chain).
 *
 * Refusals: `pool-settlement-spend` (input 0's unlocking bytecode is not
 * exactly the pushes `<S> <sigs> <settlement redeem>`), `pool-settlement-pending`
 * (output 0 is not `S`'s pending verdict), and `S`'s own strict-decode codes
 * (another deployment, a malformed statement).
 *
 * The discovery tags (ENG-712). `sigs` is, for each record in statement
 * order, `sig_{k,0} ‖ sig_{k,1} ‖ dt_{k,0} ‖ dt_{k,1}`, 144 bytes, and the
 * covenant's check 2 holds it to exactly `144·B` bytes and verifies both
 * signatures over the tags. A reading settlement returns each record's two
 * tags as `discoveryTags8`, or `null` when `sigs` is not `144·B` bytes, which
 * the covenant never lets through: the reader adds no refusal for it, so no
 * transaction reads differently from before. It checks no signature: a tag is
 * a wallet's hint, never evidence, and a wallet decoding it trial-opens the
 * output under the decoded id's own keys before it counts as a find.
 *
 * Host semantics only: it does not fetch a transaction, check its inclusion,
 * confirmation depth or a reorganization, and says nothing about proof
 * soundness. A nullifier it returns is inserted only once the transaction is
 * confirmed; recovery of a note is not its spendability.
 *
 * {@link replayAPNTPoolSettlementHistoryV1} (ENG-451) applies this reader to a
 * deployment's whole settlement-lock history, from its audited genesis, and
 * derives the pool's range state: every settled batch's nullifiers and actions,
 * and every live range record with the outpoint it sits at.
 */

export type APNTPoolSettledNullifiersResultV1 =
  | Readonly<{
    valid: true;
    failureCode: null;
    /** `SHA-256(S)`, the settled verdict's commitment. */
    statementCommitment32: Bytes32;
    /** The `2B` nullifiers the settlement inserted, in statement order. */
    nullifiers32: readonly Uint8Array[];
    /** `S`'s `B` action records, decoded, in statement order. */
    actions: readonly APNTPoolActionRecordFieldsV1[];
    /** Each record's `[dt_0, dt_1]` from input 0's signature push, in statement order; `null` if that push is not `144·B` bytes. */
    discoveryTags8: APNTPoolDiscoveryTagsV1 | null;
  }>
  | Readonly<{ valid: false; failureCode: APNTPoolFailureV1; statementCommitment32: null; nullifiers32: null; actions: null; discoveryTags8: null }>;

/** Each action's two 8-byte discovery tags, outputs 0 and 1, in statement order. */
export type APNTPoolDiscoveryTagsV1 = readonly (readonly [Uint8Array, Uint8Array])[];

/** One record's part of input 0's signature push: two 64-byte signatures, then its two tags. */
const AUTHORIZATION_BYTES = 2 * 64 + 2 * APNT_POOL_V1_DISCOVERY_TAG_BYTES;
const OP_PUSHDATA1 = 0x4c;
const OP_PUSHDATA2 = 0x4d;
const OP_PUSHDATA4 = 0x4e;
const MAXIMUM_REDEEM_BYTES = 10_000;

/** A push-only script's data pushes, minimally encoded; anything else is `pool-settlement-spend`. */
function pushesOf(script: Uint8Array): Uint8Array[] {
  const pushes: Uint8Array[] = [];
  let at = 0;
  while (at < script.length) {
    const opcode = script[at]!;
    let length: number;
    let header: number;
    if (opcode >= 0x01 && opcode <= 0x4b) { length = opcode; header = 1; }
    else if (opcode === OP_PUSHDATA1 && at + 1 < script.length) { length = script[at + 1]!; header = 2; poolRequire(length > 0x4b, F.SETTLEMENT_SPEND); }
    else if (opcode === OP_PUSHDATA2 && at + 2 < script.length) { length = script[at + 1]! | (script[at + 2]! << 8); header = 3; poolRequire(length > 0xff, F.SETTLEMENT_SPEND); }
    else if (opcode === OP_PUSHDATA4 && at + 4 < script.length) {
      length = (script[at + 1]! | (script[at + 2]! << 8) | (script[at + 3]! << 16) | (script[at + 4]! << 24)) >>> 0;
      header = 5;
      poolRequire(length > 0xffff, F.SETTLEMENT_SPEND);
    } else return poolFail(F.SETTLEMENT_SPEND);
    poolRequire(at + header + length <= script.length, F.SETTLEMENT_SPEND);
    pushes.push(script.slice(at + header, at + header + length));
    at += header + length;
  }
  return pushes;
}

const hash256 = (bytes: Uint8Array): Uint8Array => poolSha256(null, poolSha256(null, bytes));

/** Each record's two tags from a signature push of exactly `144·records` bytes, else `null`. */
function discoveryTagsOf(sigs: Uint8Array, records: number): APNTPoolDiscoveryTagsV1 | null {
  if (sigs.length !== AUTHORIZATION_BYTES * records) return null;
  return Object.freeze(Array.from({ length: records }, (_, k) => {
    const at = AUTHORIZATION_BYTES * k + 128;
    return Object.freeze([sigs.slice(at, at + APNT_POOL_V1_DISCOVERY_TAG_BYTES), sigs.slice(at + APNT_POOL_V1_DISCOVERY_TAG_BYTES, at + 2 * APNT_POOL_V1_DISCOVERY_TAG_BYTES)] as const);
  }));
}

/**
 * The nullifiers one settlement of this deployment inserted, from its raw
 * transaction: see the module comment. `value` is
 * `{ transaction, deploymentId32, verdictCategoryWire32, settlementRedeemBytecode, pendingBatchTailBytecode }`,
 * the last three the deployment's (the reviewed settlement redeem, and the
 * pending-batch redeem's tail `OP_DROP ‖ PCODE`).
 */
/** One canonical parse, shared by historical nullifier and exact-statement views.
 * This establishes neither inclusion nor proof validity. */
function parseSettlement(value: unknown) {
    const [clone] = poolBoundary([value]);
    const input = poolRecord(clone, ["transaction", "deploymentId32", "verdictCategoryWire32", "settlementRedeemBytecode", "pendingBatchTailBytecode"], F.SHAPE);
    const verdict = pool32(input.verdictCategoryWire32, F.SHAPE);
    const redeem = poolAnyBytes(input.settlementRedeemBytecode, F.SHAPE);
    poolRequire(redeem.length >= 1 && redeem.length <= MAXIMUM_REDEEM_BYTES, F.SHAPE);
    const tail = poolAnyBytes(input.pendingBatchTailBytecode, F.SHAPE);
    const transaction = poolDecodeTransaction(poolAnyBytes(input.transaction, F.TRANSACTION));
    const pushes = pushesOf(transaction.inputs[0]!.unlockingBytecode);
    poolRequire(pushes.length === 3 && poolEqual(pushes[2]!, redeem), F.SETTLEMENT_SPEND);
    const S = pushes[0]!;
    const decoded = decodeAPNTPoolStatementV1(S, input.deploymentId32);
    const commitment = poolSha256(null, S);
    const leaves = poolConcat(...decoded.fields.flatMap((fields) => fields.commitments32));
    const pendingLock = poolConcat(Uint8Array.of(0xaa, 0x20), hash256(poolConcat(Uint8Array.of(0x20), poolSha256(null, leaves), tail)), Uint8Array.of(0x87));
    const output = transaction.outputs[0];
    poolRequire(
      output !== undefined && output.token !== null && output.token.nft !== null
        && poolEqual(output.token.categoryWire32, verdict) && output.token.nft.capability === "none" && output.token.amount === 0n
        && poolEqual(output.token.nft.commitment, commitment) && poolEqual(output.lockingBytecode, pendingLock),
      F.SETTLEMENT_PENDING,
    );
    return { S, decoded, commitment, pushes };
}

export type APNTPoolSettlementStatementResultV1 =
  | Readonly<{ valid: true; failureCode: null; statement: Uint8Array; statementCommitment32: Bytes32; actions: readonly APNTPoolActionRecordFieldsV1[] }>
  | Readonly<{ valid: false; failureCode: APNTPoolFailureV1; statement: null; statementCommitment32: null; actions: null }>;

/** Exact bytes accepted by the canonical settlement parser, not a verified read. */
export function readAPNTPoolSettlementStatementV1(value: unknown): APNTPoolSettlementStatementResultV1 {
  try {
    const { S, decoded, commitment } = parseSettlement(value);
    return Object.freeze({ valid: true, failureCode: null, statement: S.slice(), statementCommitment32: commitment, actions: decoded.fields });
  } catch (error) {
    return Object.freeze({ valid: false, failureCode: poolFailureCodeOf(error), statement: null, statementCommitment32: null, actions: null });
  }
}

export function readAPNTPoolSettlementNullifiersV1(value: unknown): APNTPoolSettledNullifiersResultV1 {
  try {
    const { decoded, commitment, pushes } = parseSettlement(value);
    return Object.freeze({
      valid: true,
      failureCode: null,
      statementCommitment32: commitment,
      nullifiers32: Object.freeze(decoded.fields.flatMap((fields) => fields.nullifiers32.map((nf) => nf.slice()))),
      actions: decoded.fields,
      discoveryTags8: discoveryTagsOf(pushes[1]!, decoded.fields.length),
    });
  } catch (error) {
    return Object.freeze({ valid: false, failureCode: poolFailureCodeOf(error), statementCommitment32: null, nullifiers32: null, actions: null, discoveryTags8: null });
  }
}

// ---------------------------------------------------------------------------
// The whole settlement-lock history from genesis (ENG-451).
// ---------------------------------------------------------------------------

/** One transaction of a deployment's chain read: its raw bytes and its place in the chain. */
export type APNTPoolHistoryTransactionV1 = Readonly<{ transaction: Uint8Array; height: number; position: number }>;

/** An outpoint, with its transaction id in both byte orders. */
export type APNTPoolOutpointV1 = Readonly<{
  /** As a spending input carries it, and as `OP_OUTPOINTTXHASH` returns it. */
  txidWire32: Bytes32;
  /** As Electrum, explorers and Libauth's outpoint hash show it: the reverse. */
  txidDisplay32: Bytes32;
  index: number;
}>;

/** One settled batch: where it sits, what `S` it settled, and what it inserted. */
export type APNTPoolSettledBatchV1 = Readonly<{
  txidDisplay32: Bytes32;
  height: number;
  position: number;
  statementCommitment32: Bytes32;
  /** The `2B` nullifiers it inserted, in statement order. */
  nullifiers32: readonly Uint8Array[];
  /** `S`'s action records, decoded, in statement order. */
  actions: readonly APNTPoolActionRecordFieldsV1[];
  /** Each record's `[dt_0, dt_1]`, in statement order, or `null` (see {@link readAPNTPoolSettlementNullifiersV1}). */
  discoveryTags8: APNTPoolDiscoveryTagsV1 | null;
}>;

/** A live range record: its data, which only the history gives, and the outpoint it sits at. */
export type APNTPoolLiveRecordV1 = Readonly<{
  /** The record's data `lo ‖ hi`. */
  record66: Uint8Array;
  outpoint: APNTPoolOutpointV1;
  /** The height of the transaction that created it, a genesis transaction or a settlement. */
  createdHeight: number;
}>;

export type APNTPoolSettlementHistoryResultV1 =
  | Readonly<{
    valid: true;
    failureCode: null;
    /** The highest height among the deployment's genesis transactions. */
    genesisHeight: number;
    /** Every settlement, in replay order: by height, and within one block by dependency, then position. */
    settlements: readonly APNTPoolSettledBatchV1[];
    /** The live range records, ascending by `lo`: a partition of the key space. */
    liveRecords: readonly APNTPoolLiveRecordV1[];
    /** History transactions that pay the settlement lock without settling: ladder verdict outputs, lookalikes. */
    otherTransactionCount: number;
  }>
  | Readonly<{ valid: false; failureCode: APNTPoolFailureV1; genesisHeight: null; settlements: null; liveRecords: null; otherTransactionCount: null }>;

const MAXIMUM_HISTORY_TRANSACTIONS = 1 << 16;
const HEIGHT_MAXIMUM = 0xffff_ffff;
const CATEGORY_NAMES = ["verdict", "range", "root"] as const;

type HistoryEntry = { raw: Uint8Array; tx: APNTPoolTransactionV1; height: number; position: number };
type LiveRecord = { data: Uint8Array; lo: bigint; hi: bigint; outpoint: APNTPoolOutpointV1; createdHeight: number };
type SettlementEntry = {
  entry: HistoryEntry;
  commitment: Bytes32;
  nullifiers: readonly Uint8Array[];
  actions: readonly APNTPoolActionRecordFieldsV1[];
  discoveryTags: APNTPoolDiscoveryTagsV1 | null;
  /** `C`: distinct anchors, one root copy each. */
  copies: number;
  /** `M`: actions with a withdrawal. */
  withdrawals: number;
};

const outpointKey = (txidWire32: Uint8Array, index: number): string => `${bytesToHex(txidWire32)}:${String(index)}`;
const isHeight = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= HEIGHT_MAXIMUM;

/** A read's transactions, each decoded, with its height and position: `pool-shape` or `pool-transaction` otherwise. */
function historyEntriesOf(value: unknown): HistoryEntry[] {
  return poolArray(value, MAXIMUM_HISTORY_TRANSACTIONS, F.SHAPE).map((item) => {
    const fields = poolRecord(item, ["transaction", "height", "position"], F.SHAPE);
    poolRequire(isHeight(fields.height) && isHeight(fields.position), F.SHAPE);
    const raw = poolAnyBytes(fields.transaction, F.TRANSACTION);
    return { raw, tx: poolDecodeTransaction(raw), height: fields.height, position: fields.position };
  });
}

/** The artifact's genesis ids, display hex, or none when it is unreadable (the genesis validator then refuses it). */
function genesisTxidsOf(artifact: unknown): ReadonlySet<string> {
  try {
    const categories = (artifact as APNTPoolDeploymentArtifactV1).categories;
    return new Set(CATEGORY_NAMES.map((name) => bytesToHex(pool32(categories[name].genesisTxidDisplay32, F.SHAPE))));
  } catch {
    return new Set();
  }
}

function liveRecordOf(data: Uint8Array, tx: APNTPoolTransactionV1, index: number, createdHeight: number): LiveRecord {
  const { lo, hi } = decodeAPNTPoolRangeRecordDataV1(data);
  return { data, lo, hi, outpoint: Object.freeze({ txidWire32: tx.txidWire32, txidDisplay32: tx.txidDisplay32, index }), createdHeight };
}

/**
 * The pool's range state from a deployment's audited genesis and the complete
 * history of its settlement lock (ENG-451; design.md, "Nullifier status" and
 * "Supply audit, then induction"). `value` is `{ artifact, transactions }`:
 * the pinned deployment artifact, and every transaction of one chain read
 * (the deployment's genesis transactions and every confirmed transaction in
 * the settlement lock's script-hash history), each with its block height and
 * its position in that block, in any order.
 * `requiredArtifactRevision` selects the exact genesis artifact revision to
 * audit (default `1`); pass `2` for inbox deployments. It is a second
 * argument, not a field of `value`, and is never inferred from the artifact.
 *
 * In this order, refusing with the first failing check's code:
 *
 * 1. the transactions whose ids are the artifact's genesis ids pass
 *    `validateAPNTPoolGenesisV1` (its codes), and the `2^g` records are located
 *    at the range genesis transaction's outputs by their own locks;
 * 2. no transaction is listed twice, and no outpoint is spent by two listed
 *    transactions (`pool-history-duplicate`: the chain admits neither);
 * 3. every other transaction is classed by what the chain shows of it:
 *    - it spends an output under the settlement lock: that must be its input 0,
 *      and it must read as a settlement of this deployment
 *      ({@link readAPNTPoolSettlementNullifiersV1}; `pool-history-settlement`),
 *      because the covenant runs there and refuses anything else; the output's
 *      transaction may not be later (`pool-history-order`);
 *    - it reads as a settlement but spends no settlement-lock output of the
 *      read: the transaction that created its verdict is missing
 *      (`pool-history-gap`);
 *    - otherwise it must pay the settlement lock (a ladder's verdict output, or
 *      anyone's payment or lookalike), and is skipped; one that neither spends
 *      nor pays it is not in the lock's history (`pool-history-foreign`);
 * 4. the settlements are applied by height, and within one block (whose order
 *    is canonical by txid, so a child may precede its parent) by dependency,
 *    then position. For statement nullifier `j` of a settlement with `M`
 *    withdrawals and `C` distinct anchors:
 *    - input `C + 1 + j` spends the live record whose data contains
 *      `κ(nf_j)`, at the outpoint the replay located it at, with that record's
 *      redeem push as its unlocking bytecode (`pool-history-record-outpoint`);
 *      an outpoint whose transaction is absent from the read is a missing
 *      settlement (`pool-history-gap`), and one whose transaction is later,
 *      `pool-history-order`;
 *    - outputs `M + 1 + C + 2j` and `M + 1 + C + 2j + 1` are its two splits,
 *      each under its own record lock, with the range category, minting, an
 *      empty commitment, amount zero and the record value
 *      (`pool-history-split`).
 *
 * What a pass shows: the read is consistent with the covenants' rules from the
 * audited genesis on, every settled nullifier is listed, and each live record
 * sits at the outpoint given. What it does not show: that the read is complete
 * (a withheld latest settlement leaves its records looking live and its
 * nullifiers looking unspent), that any transaction is included or final (the
 * caller's chain evidence decides both), that any proof was sound, or wallet
 * acceptance. The settlement-authority argument holds on chain only once
 * ARCH-190's open stand-in factory is replaced by the real verdict factory.
 */
export function replayAPNTPoolSettlementHistoryV1(value: unknown, requiredArtifactRevision: 1 | 2 = 1): APNTPoolSettlementHistoryResultV1 {
  try {
    const [clone] = poolBoundary([value]);
    const input = poolRecord(clone, ["artifact", "transactions"], F.SHAPE);
    const entries = historyEntriesOf(input.transactions);

    // 1. The audited genesis, and its records' outpoints.
    const genesisIds = genesisTxidsOf(input.artifact);
    const isGenesis = (entry: HistoryEntry) => genesisIds.has(bytesToHex(entry.tx.txidDisplay32));
    const genesisEntries = entries.filter(isGenesis);
    const genesis = validateAPNTPoolGenesisV1({ artifact: input.artifact, genesisTransactions: genesisEntries.map((entry) => entry.raw) }, requiredArtifactRevision);
    if (!genesis.valid) poolFail(genesis.failureCode);
    const artifact = input.artifact as APNTPoolDeploymentArtifactV1;
    const deploymentId32 = genesis.deploymentId32;
    const rangeCategory = pool32(artifact.categories.range.wire32, F.SHAPE);
    const settlementRedeem = poolAnyBytes(artifact.covenants.settlement.redeemBytecode, F.SHAPE);
    const settlementLock = poolAnyBytes(artifact.covenants.settlement.lockingBytecode, F.SHAPE);
    const code = poolAnyBytes(artifact.covenants.range.redeemBytecode, F.SHAPE);
    const recordValue = artifact.values.rangeRecordSats;
    const pendingTail = deriveAPNTPoolPendingBatchLayoutV1(getAPNTPoolTreeCovenantSourceV1("pendingBatch"), {
      rootCategoryWire32: pool32(artifact.categories.root.wire32, F.SHAPE),
    }).tail;
    const lockOf = (data: Uint8Array) => deriveAPNTPoolRangeRecordLockV1({ codeBytecode: code, record66: data });

    const live = new Map<string, LiveRecord>();
    const grid = new Map(deriveAPNTPoolRangeGenesisRecordsV1(artifact.rangeGenesisLog2).map((data) => [bytesToHex(lockOf(data).lockingBytecode), data]));
    const rangeGenesis = genesisEntries.find((entry) => poolEqual(entry.tx.txidDisplay32, artifact.categories.range.genesisTxidDisplay32))!;
    rangeGenesis.tx.outputs.forEach((output, index) => {
      const data = grid.get(bytesToHex(output.lockingBytecode));
      const minting = output.token !== null && output.token.nft !== null && output.token.nft.capability === "minting" && poolEqual(output.token.categoryWire32, rangeCategory);
      if (data !== undefined && minting) live.set(outpointKey(rangeGenesis.tx.txidWire32, index), liveRecordOf(data, rangeGenesis.tx, index, rangeGenesis.height));
    });
    poolRequire(live.size === grid.size, F.GENESIS_RANGE_GAP);
    const genesisHeight = Math.max(...genesisEntries.map((entry) => entry.height));

    // 2. One listing per transaction, one spend per outpoint.
    const byTxid = new Map<string, HistoryEntry>();
    const spent = new Set<string>();
    for (const entry of entries) {
      const key = bytesToHex(entry.tx.txidWire32);
      poolRequire(!byTxid.has(key), F.HISTORY_DUPLICATE);
      byTxid.set(key, entry);
      for (const spend of entry.tx.inputs) {
        const outpoint = outpointKey(spend.outpointTxidWire32, spend.outpointIndex);
        poolRequire(!spent.has(outpoint), F.HISTORY_DUPLICATE);
        spent.add(outpoint);
      }
    }

    // 3. What each history transaction is, from what the chain shows of it.
    const lockOutputs = new Map<string, number>();
    for (const entry of entries) {
      entry.tx.outputs.forEach((output, index) => {
        if (poolEqual(output.lockingBytecode, settlementLock)) lockOutputs.set(outpointKey(entry.tx.txidWire32, index), entry.height);
      });
    }
    const settlements: SettlementEntry[] = [];
    let otherTransactionCount = 0;
    for (const entry of entries) {
      if (isGenesis(entry)) continue;
      const read = readAPNTPoolSettlementNullifiersV1({
        transaction: entry.raw, deploymentId32, verdictCategoryWire32: pool32(artifact.categories.verdict.wire32, F.SHAPE),
        settlementRedeemBytecode: settlementRedeem, pendingBatchTailBytecode: pendingTail,
      });
      const lockInputs = entry.tx.inputs.flatMap((spend, index) => (lockOutputs.has(outpointKey(spend.outpointTxidWire32, spend.outpointIndex)) ? [index] : []));
      if (lockInputs.length === 0) {
        poolRequire(!read.valid, F.HISTORY_GAP);
        poolRequire(entry.tx.outputs.some((output) => poolEqual(output.lockingBytecode, settlementLock)), F.HISTORY_FOREIGN);
        otherTransactionCount += 1;
        continue;
      }
      poolRequire(lockInputs.length === 1 && lockInputs[0] === 0 && read.valid, F.HISTORY_SETTLEMENT);
      const verdictSpend = entry.tx.inputs[0]!;
      poolRequire(lockOutputs.get(outpointKey(verdictSpend.outpointTxidWire32, verdictSpend.outpointIndex))! <= entry.height, F.HISTORY_ORDER);
      settlements.push({
        entry,
        commitment: read.statementCommitment32,
        nullifiers: read.nullifiers32,
        actions: read.actions,
        discoveryTags: read.discoveryTags8,
        copies: new Set(read.actions.map((action) => bytesToHex(action.anchor32))).size,
        withdrawals: read.actions.filter((action) => action.withdrawalSats > 0n).length,
      });
    }

    // 4. Each settlement's insertions, in chain order.
    const recordInputsLive = (settlement: SettlementEntry): boolean => settlement.nullifiers.every((_, j) => {
      const spend = settlement.entry.tx.inputs[settlement.copies + 1 + j];
      return spend !== undefined && live.has(outpointKey(spend.outpointTxidWire32, spend.outpointIndex));
    });
    const apply = (settlement: SettlementEntry): void => {
      const { tx, height } = settlement.entry;
      const consumed: string[] = [];
      const created: LiveRecord[] = [];
      settlement.nullifiers.forEach((nullifier, j) => {
        const spend = tx.inputs[settlement.copies + 1 + j];
        poolRequire(spend !== undefined, F.HISTORY_RECORD_OUTPOINT);
        const key = outpointKey(spend.outpointTxidWire32, spend.outpointIndex);
        const record = live.get(key);
        if (record === undefined) {
          const creator = byTxid.get(bytesToHex(spend.outpointTxidWire32));
          poolRequire(creator !== undefined, F.HISTORY_GAP);
          poolRequire(creator.height <= height, F.HISTORY_ORDER);
          poolFail(F.HISTORY_RECORD_OUTPOINT);
        }
        const kappa = deriveAPNTPoolRangeKeyV1(nullifier);
        poolRequire(record.lo < kappa && kappa < record.hi, F.HISTORY_RECORD_OUTPOINT);
        poolRequire(poolEqual(spend.unlockingBytecode, lockOf(record.data).unlockingBytecode), F.HISTORY_RECORD_OUTPOINT);
        const { left66, right66 } = splitAPNTPoolRangeRecordV1(record.data, nullifier);
        [left66, right66].forEach((data, side) => {
          const index = 1 + settlement.withdrawals + settlement.copies + 2 * j + side;
          const output = tx.outputs[index];
          poolRequire(
            output !== undefined && output.token !== null && output.token.nft !== null
              && poolEqual(output.token.categoryWire32, rangeCategory) && output.token.nft.capability === "minting"
              && output.token.nft.commitment.length === 0 && output.token.amount === 0n
              && output.valueSats === recordValue && poolEqual(output.lockingBytecode, lockOf(data).lockingBytecode),
            F.HISTORY_SPLIT,
          );
          created.push(liveRecordOf(data, tx, index, height));
        });
        consumed.push(key);
      });
      for (const key of consumed) live.delete(key);
      for (const record of created) live.set(outpointKey(record.outpoint.txidWire32, record.outpoint.index), record);
    };
    settlements.sort((a, b) => a.entry.height - b.entry.height || a.entry.position - b.entry.position);
    const settled: SettlementEntry[] = [];
    for (let start = 0; start < settlements.length;) {
      let end = start;
      while (end < settlements.length && settlements[end]!.entry.height === settlements[start]!.entry.height) end += 1;
      const block = settlements.slice(start, end);
      while (block.length > 0) {
        const ready = block.findIndex(recordInputsLive);
        // None ready: the first one's own refusal is the finding.
        const [next] = block.splice(ready === -1 ? 0 : ready, 1);
        apply(next!);
        settled.push(next!);
      }
      start = end;
    }

    const liveRecords = [...live.values()].sort((a, b) => (a.lo < b.lo ? -1 : 1));
    return Object.freeze({
      valid: true,
      failureCode: null,
      genesisHeight,
      settlements: Object.freeze(settled.map((settlement) => Object.freeze({
        txidDisplay32: settlement.entry.tx.txidDisplay32,
        height: settlement.entry.height,
        position: settlement.entry.position,
        statementCommitment32: settlement.commitment,
        nullifiers32: settlement.nullifiers,
        actions: settlement.actions,
        discoveryTags8: settlement.discoveryTags,
      }))),
      liveRecords: Object.freeze(liveRecords.map((record) => Object.freeze({ record66: record.data, outpoint: record.outpoint, createdHeight: record.createdHeight }))),
      otherTransactionCount,
    });
  } catch (error) {
    return Object.freeze({ valid: false, failureCode: poolFailureCodeOf(error), genesisHeight: null, settlements: null, liveRecords: null, otherTransactionCount: null });
  }
}

// ---------------------------------------------------------------------------
// The note tree's history: every fold from the audited genesis (ENG-505).
// ---------------------------------------------------------------------------

/** One fold of the note tree: the settled batch it appended, where its leaves went, and the root it made. */
export type APNTPoolFoldV1 = Readonly<{
  txidDisplay32: Bytes32;
  height: number;
  position: number;
  /** The settlement whose pending verdict it burned: its input 1 spends that settlement's output 0. */
  settlementTxidDisplay32: Bytes32;
  /** `n` before the fold: the batch's `2B` leaves sit at tree positions `leafCountBefore .. leafCount − 1`. */
  leafCountBefore: number;
  /** `n'` after the fold. */
  leafCount: number;
  /** `root(F', n')`: what output 0 commits and each of outputs `1..K` carries. */
  root32: Bytes32;
}>;

export type APNTPoolTreeHistoryResultV1 =
  | Readonly<{
    valid: true;
    failureCode: null;
    /** {@link replayAPNTPoolSettlementHistoryV1} of the same read, without its folds and tree-update lookalikes. */
    settlementHistory: Extract<APNTPoolSettlementHistoryResultV1, { valid: true }>;
    /** Every fold, in chain order: each spends the tree update the one before it created. */
    folds: readonly APNTPoolFoldV1[];
    /** Every folded leaf in fold order: the leaf at tree position `i` is entry `i`. */
    leaves32: readonly Bytes32[];
    /** Transactions that pay the tree-update lock without folding and are not in the settlement lock's history: skipped. */
    otherTreeTransactionCount: number;
  }>
  | Readonly<{ valid: false; failureCode: APNTPoolFailureV1; settlementHistory: null; folds: null; leaves32: null; otherTreeTransactionCount: null }>;

const reversedBytes = (bytes: Uint8Array): Uint8Array => Uint8Array.from(bytes).reverse();

/**
 * The pool's note tree from a deployment's audited genesis and one chain read
 * holding the complete histories of both pool locks that record it: the
 * settlement lock's (every settlement) and the tree-update lock's (the
 * genesis tree update and every fold) (ENG-505; design.md, "Note tree, root
 * copies and the tree update": "Leaf positions follow fold order, which the
 * chain fixes, and a wallet rebuilds paths from the tree-update history").
 * `value` is `{ artifact, transactions }`, as for
 * {@link replayAPNTPoolSettlementHistoryV1}; a read of the settlement lock
 * alone is a read with no folds.
 * `requiredArtifactRevision` selects the exact genesis artifact revision
 * (default `1`, inbox `2`) for both this audit and the nested settlement
 * replay. It is a second argument, not a field of `value`.
 *
 * In this order, refusing with the first failing check's code:
 *
 * 1. the genesis passes `validateAPNTPoolGenesisV1` (its codes), and no
 *    transaction is listed twice nor any outpoint spent twice
 *    (`pool-history-duplicate`);
 * 2. each transaction is classed by what the chain shows of it:
 *    - it **reads as a fold** when input 0's unlocking bytecode is exactly the
 *      pushes `<F> <leaves> <tree-update redeem>` and output 0 carries the
 *      root category's minting token under the tree-update lock. The audited
 *      genesis creates exactly one such token, under that covenant, which
 *      recreates it only at output 0 of a fold, so nothing else can;
 *    - it is a **tree-update lookalike** when it pays the tree-update lock,
 *      does not read as a fold, and is not in the settlement lock's history
 *      (it neither pays the settlement lock nor spends a listed output under
 *      it, and does not read as a settlement): skipped;
 *    - every other transaction, and a fold that also pays the settlement lock,
 *      goes to {@link replayAPNTPoolSettlementHistoryV1} unchanged (its codes);
 * 3. from the genesis tree update (the root genesis transaction's output
 *    under the tree-update lock carrying the minting token), the transaction
 *    that spends the current tree update is the next fold; it must spend it
 *    at input 0 and read as a fold (`pool-history-fold`), at a height not
 *    below the tree update's (`pool-history-order`), and:
 *    - its input 1 spends output 0 of a settlement the replay settled and no
 *      earlier fold folded (`pool-history-fold`; `pool-history-gap` if that
 *      transaction is not in the read), at a height not above the fold's
 *      (`pool-history-order`), with the unlocking bytecode exactly the push of
 *      that batch's pending redeem `0x20 ‖ H_cm ‖ tail`;
 *    - its pushed `F` is 1,024 bytes, output 0's token has no amount, outputs
 *      `1..K` are the root category's immutable tokens under the root-copy
 *      lock, and every later output carries no token (`pool-history-fold`);
 *    - `evaluateAPNTPoolTreeUpdateV1` accepts it (its codes) with input 0's
 *      committed state, the batch's `H_cm = SHA-256` of the settled
 *      statement's leaves as the only pending batch, the pushed `F` at the
 *      committed `n`, the pushed leaves, output 0's commitment and the `K`
 *      copies: so the pushed leaves are exactly the settled batch's, appended
 *      in statement order;
 * 4. every transaction that reads as a fold is on that chain
 *    (`pool-history-gap`: the fold it spends is missing from the read).
 *
 * What a pass shows: the read is consistent with the tree covenants from the
 * audited genesis on, each folded leaf sits at the position given, and each
 * fold's root is the root of the leaves before it. What it does not show: that
 * the read is complete (a withheld latest fold leaves its batch looking
 * unfolded, and a wallet then cannot anchor to it: liveness, not a wrong
 * path), that any transaction is included or final (the caller's chain
 * evidence decides both), that any proof was sound, or wallet acceptance or
 * spendability. Root copies are not tracked: every folded root keeps `K` live
 * copies, since only a settlement spends one and the settlement covenant
 * recreates it.
 */
export function replayAPNTPoolTreeHistoryV1(value: unknown, requiredArtifactRevision: 1 | 2 = 1): APNTPoolTreeHistoryResultV1 {
  try {
    const [clone] = poolBoundary([value]);
    const input = poolRecord(clone, ["artifact", "transactions"], F.SHAPE);
    const entries = historyEntriesOf(input.transactions);

    // 1. The audited genesis; one listing per transaction, one spend per outpoint.
    const genesisIds = genesisTxidsOf(input.artifact);
    const isGenesis = (entry: HistoryEntry) => genesisIds.has(bytesToHex(entry.tx.txidDisplay32));
    const genesis = validateAPNTPoolGenesisV1({ artifact: input.artifact, genesisTransactions: entries.filter(isGenesis).map((entry) => entry.raw) }, requiredArtifactRevision);
    if (!genesis.valid) poolFail(genesis.failureCode);
    const artifact = input.artifact as APNTPoolDeploymentArtifactV1;
    const treeLock = poolAnyBytes(artifact.covenants.treeUpdate.lockingBytecode, F.SHAPE);
    const treeRedeem = poolAnyBytes(artifact.covenants.treeUpdate.redeemBytecode, F.SHAPE);
    const copyLock = poolAnyBytes(artifact.covenants.rootCopy.lockingBytecode, F.SHAPE);
    const settlementLock = poolAnyBytes(artifact.covenants.settlement.lockingBytecode, F.SHAPE);
    const rootCategory = pool32(artifact.categories.root.wire32, F.SHAPE);
    const copies = artifact.rootCopyCount;
    const pendingTail = deriveAPNTPoolPendingBatchLayoutV1(getAPNTPoolTreeCovenantSourceV1("pendingBatch"), { rootCategoryWire32: rootCategory }).tail;
    const byTxid = new Map<string, HistoryEntry>();
    const spenders = new Map<string, { entry: HistoryEntry; input: number }>();
    for (const entry of entries) {
      const key = bytesToHex(entry.tx.txidWire32);
      poolRequire(!byTxid.has(key), F.HISTORY_DUPLICATE);
      byTxid.set(key, entry);
      entry.tx.inputs.forEach((spend, index) => {
        const outpoint = outpointKey(spend.outpointTxidWire32, spend.outpointIndex);
        poolRequire(!spenders.has(outpoint), F.HISTORY_DUPLICATE);
        spenders.set(outpoint, { entry, input: index });
      });
    }

    // 2. Folds, tree-update lookalikes, and the settlement lock's history.
    const rootMinting = (output: APNTPoolTransactionV1["outputs"][number] | undefined) => output !== undefined && output.token !== null
      && output.token.nft !== null && output.token.nft.capability === "minting" && poolEqual(output.token.categoryWire32, rootCategory);
    const readsAsFold = (entry: HistoryEntry): boolean => {
      const first = entry.tx.inputs[0];
      if (first === undefined) return false;
      let pushes: Uint8Array[];
      try { pushes = pushesOf(first.unlockingBytecode); } catch { return false; }
      const output = entry.tx.outputs[0];
      return pushes.length === 3 && poolEqual(pushes[2]!, treeRedeem) && rootMinting(output) && poolEqual(output!.lockingBytecode, treeLock);
    };
    const pays = (entry: HistoryEntry, lock: Uint8Array) => entry.tx.outputs.some((output) => poolEqual(output.lockingBytecode, lock));
    const settlementOutputs = new Set<string>();
    for (const entry of entries) {
      entry.tx.outputs.forEach((output, index) => {
        if (poolEqual(output.lockingBytecode, settlementLock)) settlementOutputs.add(outpointKey(entry.tx.txidWire32, index));
      });
    }
    const readsAsSettlement = (entry: HistoryEntry) => readAPNTPoolSettlementNullifiersV1({
      transaction: entry.raw, deploymentId32: genesis.deploymentId32, verdictCategoryWire32: pool32(artifact.categories.verdict.wire32, F.SHAPE),
      settlementRedeemBytecode: poolAnyBytes(artifact.covenants.settlement.redeemBytecode, F.SHAPE), pendingBatchTailBytecode: pendingTail,
    }).valid;
    const inSettlementHistory = (entry: HistoryEntry) => pays(entry, settlementLock)
      || entry.tx.inputs.some((spend) => settlementOutputs.has(outpointKey(spend.outpointTxidWire32, spend.outpointIndex)))
      || readsAsSettlement(entry);
    const foldCandidates = new Set(entries.filter((entry) => !isGenesis(entry) && readsAsFold(entry)));
    const lookalikes = new Set(entries.filter((entry) => !isGenesis(entry) && !foldCandidates.has(entry) && pays(entry, treeLock) && !inSettlementHistory(entry)));
    const settlementRead = entries.filter((entry) => !lookalikes.has(entry) && (!foldCandidates.has(entry) || pays(entry, settlementLock)));
    const settlementHistory = replayAPNTPoolSettlementHistoryV1({
      artifact: input.artifact,
      transactions: settlementRead.map((entry) => ({ transaction: entry.raw, height: entry.height, position: entry.position })),
    }, requiredArtifactRevision);
    if (!settlementHistory.valid) poolFail(settlementHistory.failureCode);
    const settledByWire = new Map(settlementHistory.settlements.map((batch) => [bytesToHex(reversedBytes(batch.txidDisplay32)), batch]));

    // 3. The folds, from the genesis tree update.
    const rootGenesis = entries.find((entry) => poolEqual(entry.tx.txidDisplay32, artifact.categories.root.genesisTxidDisplay32))!;
    const genesisIndex = rootGenesis.tx.outputs.findIndex((output) => poolEqual(output.lockingBytecode, treeLock) && rootMinting(output));
    poolRequire(genesisIndex >= 0, F.HISTORY_FOLD);
    let current = { txidWire32: rootGenesis.tx.txidWire32, index: genesisIndex, height: rootGenesis.height };
    let commitment = rootGenesis.tx.outputs[genesisIndex]!.token!.nft!.commitment;
    const folds: APNTPoolFoldV1[] = [];
    const leaves: Bytes32[] = [];
    const walked = new Set<HistoryEntry>();
    const folded = new Set<string>();
    for (let spender = spenders.get(outpointKey(current.txidWire32, current.index)); spender !== undefined; spender = spenders.get(outpointKey(current.txidWire32, current.index))) {
      const { entry } = spender;
      poolRequire(spender.input === 0 && foldCandidates.has(entry), F.HISTORY_FOLD);
      poolRequire(entry.height >= current.height, F.HISTORY_ORDER);
      const [frontierPush, leafPush] = pushesOf(entry.tx.inputs[0]!.unlockingBytecode) as [Uint8Array, Uint8Array, Uint8Array];
      poolRequire(frontierPush.length === APNT_POOL_V1_FRONTIER_BYTES, F.HISTORY_FOLD);
      const pendingSpend = entry.tx.inputs[1];
      poolRequire(pendingSpend !== undefined, F.HISTORY_FOLD);
      const batchKey = bytesToHex(pendingSpend.outpointTxidWire32);
      const batch = settledByWire.get(batchKey);
      if (batch === undefined) {
        poolRequire(byTxid.has(batchKey), F.HISTORY_GAP);
        poolFail(F.HISTORY_FOLD);
      }
      poolRequire(pendingSpend.outpointIndex === 0 && !folded.has(batchKey), F.HISTORY_FOLD);
      poolRequire(batch.height <= entry.height, F.HISTORY_ORDER);
      const leafListDigest = poolSha256(null, poolConcat(...batch.actions.flatMap((action) => action.commitments32)));
      let pendingPushes: Uint8Array[];
      try { pendingPushes = pushesOf(pendingSpend.unlockingBytecode); } catch { return poolFail(F.HISTORY_FOLD); }
      poolRequire(pendingPushes.length === 1 && poolEqual(pendingPushes[0]!, poolConcat(Uint8Array.of(0x20), leafListDigest, pendingTail)), F.HISTORY_FOLD);
      const next = entry.tx.outputs[0]!;
      const copyOutputs = entry.tx.outputs.slice(1, 1 + copies);
      poolRequire(
        next.token!.amount === 0n && copyOutputs.length === copies
          && copyOutputs.every((output) => poolEqual(output.lockingBytecode, copyLock) && output.token !== null && output.token.nft !== null
            && output.token.nft.capability === "none" && output.token.amount === 0n && poolEqual(output.token.categoryWire32, rootCategory))
          && entry.tx.outputs.slice(1 + copies).every((output) => output.token === null),
        F.HISTORY_FOLD,
      );
      const leafCountBefore = decodeAPNTPoolTreeUpdateCommitmentV1(commitment).leafCount;
      const update = evaluateAPNTPoolTreeUpdateV1({
        treeUpdateCommitment72: commitment,
        pendingBatches: new Set([bytesToHex(leafListDigest)]),
        frontierState: poolConcat(poolU64le(BigInt(leafCountBefore), F.TREE_STATE), frontierPush),
        leaves: leafPush,
        nextTreeUpdateCommitment72: next.token!.nft!.commitment,
        rootCopies32: copyOutputs.map((output) => output.token!.nft!.commitment),
      });
      if (!update.valid) poolFail(update.failureCode);
      for (let at = 0; at < leafPush.length; at += 32) leaves.push(pool32(leafPush.slice(at, at + 32), F.TREE_LEAVES));
      const root32 = decodeAPNTPoolTreeUpdateCommitmentV1(next.token!.nft!.commitment).root32;
      folds.push(Object.freeze({
        txidDisplay32: entry.tx.txidDisplay32, height: entry.height, position: entry.position,
        settlementTxidDisplay32: batch.txidDisplay32, leafCountBefore, leafCount: update.frontier.leafCount, root32,
      }));
      folded.add(batchKey);
      walked.add(entry);
      commitment = next.token!.nft!.commitment;
      current = { txidWire32: entry.tx.txidWire32, index: 0, height: entry.height };
    }

    // 4. No fold off the chain.
    for (const candidate of foldCandidates) poolRequire(walked.has(candidate), F.HISTORY_GAP);
    return Object.freeze({
      valid: true,
      failureCode: null,
      settlementHistory,
      folds: Object.freeze(folds),
      leaves32: Object.freeze(leaves),
      otherTreeTransactionCount: lookalikes.size,
    });
  } catch (error) {
    return Object.freeze({ valid: false, failureCode: poolFailureCodeOf(error), settlementHistory: null, folds: null, leaves32: null, otherTreeTransactionCount: null });
  }
}
