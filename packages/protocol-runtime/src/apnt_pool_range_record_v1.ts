import {
  APNT_POOL_FAILURE_V1 as F,
  pool32,
  poolAnyBytes,
  poolArray,
  poolBoundary,
  poolBytes,
  poolConcat,
  poolEqual,
  poolFailureCodeOf,
  poolRecord,
  poolRequire,
  poolSha256,
  type APNTPoolFailureV1,
} from "./apnt_pool_contract_v1.js";
import { pushScriptData } from "./apnt_cashassembly_compiler_v0.js";
import { bytesToHex } from "./bytes.js";
import { decodeAPNTPoolStatementV1 } from "./apnt_pool_statement_v1.js";

/**
 * APNT shielded pool v1: nullifier range records, host semantics (task 3.1;
 * design.md, "Nullifier range records"; `apnt-pool-nullifier-range-records`).
 *
 * ```text
 * κ(nf)      = 2·int_le(nf) + 1                       an odd integer in [1, 2^257 − 1]
 * endpoint   = an integer in [0, 2^257], 33 bytes unsigned little-endian
 * record     = data lo ‖ hi (66 bytes), lo < hi       no inserted key k has lo < k < hi
 * genesis    = G = 2^g records, record i = (i·2^(257−g), (i+1)·2^(257−g)); defined for
 *              0 ≤ g ≤ 9, and a deployment needs g ≥ 1 (`validateAPNTPoolGenesisV1`)
 * insert nf  = spend the one record with lo < κ < hi, create (lo, κ) and (κ, hi)
 * ```
 *
 * Genesis boundaries are even and keys odd, so until its insertion every
 * nullifier value, including 0 and `2^256 − 1`, has exactly one containing
 * record, and after it none.
 *
 * Where a record's data lives (ARCH-234 D2, ARCH-245). A record is a range
 * minting NFT with an EMPTY commitment under its own lock
 * `P2SH32(push(lo‖hi) ‖ OP_DROP ‖ CODE)`, CODE the range record's code
 * (`apnt_pool_range_record_covenant_v1.ts`). Its data is in its redeem, so
 * the chain shows it only when the record is spent; an unspent record's data
 * follows from the genesis grid and the nullifiers every settlement inserted.
 * {@link deriveAPNTPoolRangeRecordLockV1} and
 * {@link decodeAPNTPoolRangeRecordUnlockingV1} are that encoding.
 *
 * The statement's `2B` nullifiers, in statement order (record `k`, slot `s`,
 * index `j = 2k + s`), and a settlement's record inputs correspond one to one:
 * record input `C + 1 + j` (after the `C` root copies) splits at `κ(nf_j)`,
 * and its two records are outputs `M + 1 + C + 2j` and `M + 1 + C + 2j + 1`
 * (after the pending output, the `M` withdrawals and the `C` recreated copies);
 * the settlement covenant's check 4 enforces it
 * (`cashassembly/apnt_pool_settlement_v1.casm`).
 * {@link evaluateAPNTPoolRangeInsertionV1} models that rule on the records'
 * data, and {@link evaluateAPNTPoolRangeSettlementV1} on the bytes the
 * covenant reads (record unlocking bytecodes, split locks and tokens);
 * {@link assembleAPNTPoolRangeInsertionV1} is the assembly-time check that the
 * statement's keys lie in pairwise distinct current records, which a record
 * can split at only one key per transaction.
 *
 * Host semantics only: the covenant's settlement authority, the positions it
 * reads, its stray-record scans, chain reads and the genesis audit (task 3.2)
 * are not here.
 */

export const APNT_POOL_V1_RANGE_ENDPOINT_BYTES = 33;
export const APNT_POOL_V1_RANGE_RECORD_DATA_BYTES = 66;
/** The largest endpoint, `2^257`. */
export const APNT_POOL_V1_RANGE_ENDPOINT_MAXIMUM = 1n << 257n;
/** `g ≤ 9`: 512 genesis records fit one 100,000-byte standard transaction (design.md, "Genesis"). */
export const APNT_POOL_V1_RANGE_GENESIS_MAXIMUM_LOG2 = 9;

export type APNTPoolRangeRecordV1 = Readonly<{ lo: bigint; hi: bigint }>;

function readUnsignedLe(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) value = (value << 8n) | BigInt(bytes[index]!);
  return value;
}

function endpointBytes(value: unknown): Uint8Array {
  poolRequire(typeof value === "bigint" && value >= 0n && value <= APNT_POOL_V1_RANGE_ENDPOINT_MAXIMUM, F.RANGE_ENDPOINT);
  const out = new Uint8Array(APNT_POOL_V1_RANGE_ENDPOINT_BYTES);
  let rest = value;
  for (let index = 0; index < out.length; index += 1) { out[index] = Number(rest & 0xffn); rest >>= 8n; }
  return out;
}

function endpointValue(bytes: unknown): bigint {
  const value = readUnsignedLe(poolBytes(bytes, APNT_POOL_V1_RANGE_ENDPOINT_BYTES, F.RANGE_ENDPOINT));
  poolRequire(value <= APNT_POOL_V1_RANGE_ENDPOINT_MAXIMUM, F.RANGE_ENDPOINT);
  return value;
}

function recordOf(bytes: unknown): APNTPoolRangeRecordV1 {
  const data = poolBytes(bytes, APNT_POOL_V1_RANGE_RECORD_DATA_BYTES, F.RANGE_RECORD);
  const lo = endpointValue(data.slice(0, APNT_POOL_V1_RANGE_ENDPOINT_BYTES));
  const hi = endpointValue(data.slice(APNT_POOL_V1_RANGE_ENDPOINT_BYTES));
  poolRequire(lo < hi, F.RANGE_RECORD);
  return Object.freeze({ lo, hi });
}

function dataOf(lo: bigint, hi: bigint): Uint8Array {
  poolRequire(typeof lo === "bigint" && typeof hi === "bigint" && lo < hi, F.RANGE_RECORD);
  return poolConcat(endpointBytes(lo), endpointBytes(hi));
}

function keyOf(nullifier32: unknown): bigint {
  return 2n * readUnsignedLe(pool32(nullifier32, F.NULLIFIER)) + 1n;
}

const contains = (record: APNTPoolRangeRecordV1, key: bigint): boolean => record.lo < key && key < record.hi;

function splitAt(record: APNTPoolRangeRecordV1, key: bigint): readonly [Uint8Array, Uint8Array] {
  poolRequire(contains(record, key), F.RANGE_NOT_CONTAINED);
  return Object.freeze([dataOf(record.lo, key), dataOf(key, record.hi)] as const);
}

/** The statement's `2B` range keys, in statement order: `κ(nf_j)`, `j = 2k + s`. */
function statementKeys(statement: unknown, deploymentId32: unknown): bigint[] {
  const decoded = decodeAPNTPoolStatementV1(statement, deploymentId32);
  return decoded.fields.flatMap((fields) => fields.nullifiers32.map((nf) => keyOf(nf)));
}

/** `κ(nf) = 2·int_le(nf) + 1`, for a 32-byte nullifier. */
export function deriveAPNTPoolRangeKeyV1(nullifier32: unknown): bigint {
  [nullifier32] = poolBoundary([nullifier32]);
  return keyOf(nullifier32);
}

/** A 33-byte unsigned little-endian endpoint of an integer in `[0, 2^257]`. */
export function encodeAPNTPoolRangeEndpointV1(value: unknown): Uint8Array {
  [value] = poolBoundary([value]);
  return endpointBytes(value);
}

/** Strict decode of a 33-byte endpoint; refuses a value above `2^257`. */
export function decodeAPNTPoolRangeEndpointV1(bytes: unknown): bigint {
  [bytes] = poolBoundary([bytes]);
  return endpointValue(bytes);
}

/** The 66-byte data `lo ‖ hi` of a record `{ lo, hi }` with `lo < hi`, both in `[0, 2^257]`. */
export function encodeAPNTPoolRangeRecordDataV1(value: unknown): Uint8Array {
  [value] = poolBoundary([value]);
  const input = poolRecord(value, ["lo", "hi"], F.RANGE_RECORD);
  return dataOf(input.lo as bigint, input.hi as bigint);
}

/** Strict decode of a 66-byte record's data; refuses any other length, an endpoint above `2^257`, and `lo ≥ hi`. */
export function decodeAPNTPoolRangeRecordDataV1(bytes: unknown): APNTPoolRangeRecordV1 {
  [bytes] = poolBoundary([bytes]);
  return recordOf(bytes);
}

/** The `G = 2^g` genesis records' data, in ascending order, for `0 ≤ g ≤ 9`. */
export function deriveAPNTPoolRangeGenesisRecordsV1(log2Count: unknown): readonly Uint8Array[] {
  [log2Count] = poolBoundary([log2Count]);
  poolRequire(
    typeof log2Count === "number" && Number.isSafeInteger(log2Count) && log2Count >= 0 && log2Count <= APNT_POOL_V1_RANGE_GENESIS_MAXIMUM_LOG2,
    F.RANGE_GENESIS,
  );
  const step = APNT_POOL_V1_RANGE_ENDPOINT_MAXIMUM >> BigInt(log2Count);
  return Object.freeze(Array.from({ length: 2 ** log2Count }, (_, i) => dataOf(BigInt(i) * step, BigInt(i + 1) * step)));
}

/**
 * The two records an insertion creates: `lo ‖ κ` and `κ ‖ hi`. Refuses with
 * `pool-range-not-contained` unless `lo < κ(nf) < hi`, which covers a key that
 * is already a boundary (a double insertion).
 */
export function splitAPNTPoolRangeRecordV1(record66: unknown, nullifier32: unknown): Readonly<{ left66: Uint8Array; right66: Uint8Array }> {
  [record66, nullifier32] = poolBoundary([record66, nullifier32]);
  const [left66, right66] = splitAt(recordOf(record66), keyOf(nullifier32));
  return Object.freeze({ left66, right66 });
}

export type APNTPoolRangeAssemblyResultV1 =
  | Readonly<{
    valid: true;
    failureCode: null;
    /** For each statement nullifier `j`, in statement order, the index of its containing live record. */
    recordIndices: readonly number[];
    /** The records the settlement spends, in the order its range-category inputs must take. */
    spentRecords66: readonly Uint8Array[];
    /** The records it creates, in the order its range-category outputs must take. */
    createdRecords66: readonly Uint8Array[];
  }>
  | Readonly<{ valid: false; failureCode: APNTPoolFailureV1; recordIndices: null; spentRecords66: null; createdRecords66: null }>;

/**
 * Assembly-time range check, before aggregate proving: every statement key lies
 * in exactly one current record, and the `2B` keys lie in pairwise distinct
 * records.
 *
 * - `pool-range-not-contained`: a key lies in no live record, i.e. it is
 *   already inserted (or the live set is incomplete);
 * - `pool-range-overlap`: two live records contain one key, which a verified
 *   genesis and the covenant's induction never produce;
 * - `pool-range-same-record`: two keys share a record. The settlement could not
 *   insert both, because a record splits at one key per transaction; the
 *   aggregator leaves one of the two actions to a later batch.
 *
 * `liveRecords66` is the current record set as 66-byte data, from the
 * caller's own chain read: the genesis grid refined by every settled
 * statement's nullifiers, since an unspent record's data is inside its lock
 * hash. A split only refines the partition, so a passing statement still
 * passes after concurrent settlements insert other keys; it is then rebuilt
 * against the new records with the same proof and signatures.
 */
export function assembleAPNTPoolRangeInsertionV1(value: unknown): APNTPoolRangeAssemblyResultV1 {
  try {
    const [clone] = poolBoundary([value]);
    const input = poolRecord(clone, ["statement", "deploymentId32", "liveRecords66"], F.SHAPE);
    const keys = statementKeys(input.statement, input.deploymentId32);
    const live = poolArray(input.liveRecords66, 0xffff_ffff, F.RANGE_RECORD).map(recordOf);
    const recordIndices: number[] = [];
    for (const key of keys) {
      const containing = live.flatMap((record, index) => (contains(record, key) ? [index] : []));
      poolRequire(containing.length >= 1, F.RANGE_NOT_CONTAINED);
      poolRequire(containing.length === 1, F.RANGE_OVERLAP);
      poolRequire(!recordIndices.includes(containing[0]!), F.RANGE_SAME_RECORD);
      recordIndices.push(containing[0]!);
    }
    const spentRecords66 = recordIndices.map((index) => dataOf(live[index]!.lo, live[index]!.hi));
    const createdRecords66 = recordIndices.flatMap((index, j) => splitAt(live[index]!, keys[j]!));
    return Object.freeze({
      valid: true,
      failureCode: null,
      recordIndices: Object.freeze(recordIndices),
      spentRecords66: Object.freeze(spentRecords66),
      createdRecords66: Object.freeze(createdRecords66),
    });
  } catch (error) {
    return Object.freeze({ valid: false, failureCode: poolFailureCodeOf(error), recordIndices: null, spentRecords66: null, createdRecords66: null });
  }
}

export type APNTPoolRangeInsertionResultV1 =
  | Readonly<{ valid: true; failureCode: null }>
  | Readonly<{ valid: false; failureCode: APNTPoolFailureV1 }>;

/**
 * Host model of the settlement covenant's check 4 on the records' data, given
 * its record inputs' data in input order and its split outputs' data in
 * output order:
 *
 * - exactly `2B` records are spent (`pool-range-input-count`): one per
 *   statement nullifier, so none is skipped;
 * - no record is listed twice (`pool-range-same-record`): the chain refuses
 *   one UTXO spent twice, and a record splits at one key per transaction;
 * - the `j`-th spent record strictly contains `κ(nf_j)`
 *   (`pool-range-not-contained`);
 * - exactly `4B` records are created (`pool-range-output-count`), and created
 *   records `2j` and `2j + 1` are `lo ‖ κ` and `κ ‖ hi` (`pool-range-split`).
 *
 * Every spent record's data must decode canonically (`pool-range-record`).
 * Locks, capabilities, amounts, values and the settlement authority are
 * modelled by {@link evaluateAPNTPoolRangeSettlementV1}, not here.
 */
export function evaluateAPNTPoolRangeInsertionV1(value: unknown): APNTPoolRangeInsertionResultV1 {
  try {
    const [clone] = poolBoundary([value]);
    const input = poolRecord(clone, ["statement", "deploymentId32", "spentRecords66", "createdRecords66"], F.SHAPE);
    const keys = statementKeys(input.statement, input.deploymentId32);
    const spent = poolArray(input.spentRecords66, 0xffff_ffff, F.RANGE_RECORD);
    const created = poolArray(input.createdRecords66, 0xffff_ffff, F.RANGE_RECORD);
    poolRequire(spent.length === keys.length, F.RANGE_INPUT_COUNT);
    const spentHex = spent.map((record) => bytesToHex(poolBytes(record, APNT_POOL_V1_RANGE_RECORD_DATA_BYTES, F.RANGE_RECORD)));
    poolRequire(new Set(spentHex).size === spentHex.length, F.RANGE_SAME_RECORD);
    const expected = spent.flatMap((record, j) => splitAt(recordOf(record), keys[j]!));
    poolRequire(created.length === expected.length, F.RANGE_OUTPUT_COUNT);
    created.forEach((record, index) => {
      poolRequire(poolEqual(poolBytes(record, APNT_POOL_V1_RANGE_RECORD_DATA_BYTES, F.RANGE_SPLIT), expected[index]!), F.RANGE_SPLIT);
    });
    return Object.freeze({ valid: true, failureCode: null });
  } catch (error) {
    return Object.freeze({ valid: false, failureCode: poolFailureCodeOf(error) });
  }
}

// ---------------------------------------------------------------------------
// The record encoding of ARCH-234 D2 (ARCH-245): data in the redeem, an empty
// token commitment, and the settlement covenant's check 4 on those bytes.
// ---------------------------------------------------------------------------

const OP_DROP = 0x75;
/** The range record's code CODE is at most this long (its builder's bound). */
const MAXIMUM_RECORD_CODE_BYTES = 400;
const hash256 = (bytes: Uint8Array): Uint8Array => poolSha256(null, poolSha256(null, bytes));
const p2sh32 = (redeem: Uint8Array): Uint8Array => poolConcat(Uint8Array.of(0xaa, 0x20), hash256(redeem), Uint8Array.of(0x87));

function recordCodeOf(value: unknown): Uint8Array {
  const code = poolAnyBytes(value, F.COVENANT_PARAMETER);
  poolRequire(code.length >= 1 && code.length <= MAXIMUM_RECORD_CODE_BYTES, F.COVENANT_PARAMETER);
  return code;
}

const recordRedeemOf = (code: Uint8Array, data: Uint8Array): Uint8Array => poolConcat(pushScriptData(data), Uint8Array.of(OP_DROP), code);

export type APNTPoolRangeRecordLockV1 = Readonly<{
  /** `push(lo‖hi) ‖ OP_DROP ‖ CODE`. */
  redeemBytecode: Uint8Array;
  /** `OP_HASH256 <HASH256(redeem)> OP_EQUAL`: the record's own lock. */
  lockingBytecode: Uint8Array;
  /** `push(redeem)`: the only unlocking bytecode the settlement covenant admits for the record (RECORD_REDEEM). */
  unlockingBytecode: Uint8Array;
}>;

/**
 * A record's redeem, lock and unlocking bytecode, for its 66-byte data and the
 * deployment's record code CODE (`buildAPNTPoolRangeRecordCovenantV1`). The
 * data must decode canonically (`pool-range-record`); a CODE outside 1..400
 * bytes is `pool-covenant-parameter`.
 */
export function deriveAPNTPoolRangeRecordLockV1(value: unknown): APNTPoolRangeRecordLockV1 {
  [value] = poolBoundary([value]);
  const input = poolRecord(value, ["codeBytecode", "record66"], F.SHAPE);
  const code = recordCodeOf(input.codeBytecode);
  const data = poolBytes(input.record66, APNT_POOL_V1_RANGE_RECORD_DATA_BYTES, F.RANGE_RECORD);
  recordOf(data);
  const redeemBytecode = recordRedeemOf(code, data);
  return Object.freeze({ redeemBytecode, lockingBytecode: p2sh32(redeemBytecode), unlockingBytecode: pushScriptData(redeemBytecode) });
}

function unlockingData(code: Uint8Array, unlocking: Uint8Array): Uint8Array {
  // Every record redeem has the same length, so the same head: the redeem push's opcode and length, then 0x42.
  const shape = pushScriptData(recordRedeemOf(code, new Uint8Array(APNT_POOL_V1_RANGE_RECORD_DATA_BYTES)));
  const head = shape.slice(0, shape.length - code.length - 1 - APNT_POOL_V1_RANGE_RECORD_DATA_BYTES);
  const tail = shape.slice(shape.length - code.length - 1);
  poolRequire(
    unlocking.length === shape.length
      && poolEqual(unlocking.subarray(0, head.length), head)
      && poolEqual(unlocking.subarray(unlocking.length - tail.length), tail),
    F.RANGE_RECORD_REDEEM,
  );
  return unlocking.slice(head.length, head.length + APNT_POOL_V1_RANGE_RECORD_DATA_BYTES);
}

/**
 * The 66 data bytes of a record input, from its unlocking bytecode, exactly as
 * the settlement covenant reads them (RECORD_REDEEM): the unlocking must be
 * `push(push(data) ‖ OP_DROP ‖ CODE)` for some 66 bytes of data, else
 * `pool-range-record-redeem`. The data is returned as read, not decoded; P2SH32
 * makes it the data the input's lock commits.
 */
export function decodeAPNTPoolRangeRecordUnlockingV1(value: unknown): Uint8Array {
  [value] = poolBoundary([value]);
  const input = poolRecord(value, ["codeBytecode", "unlockingBytecode"], F.SHAPE);
  return unlockingData(recordCodeOf(input.codeBytecode), poolAnyBytes(input.unlockingBytecode, F.RANGE_RECORD_REDEEM));
}

export type APNTPoolRangeTokenV1 = Readonly<{
  /** The token category in wire order. */
  categoryWire32: Uint8Array;
  capability: "none" | "mutable" | "minting";
  commitment: Uint8Array;
  amount: bigint;
}>;

const CAPABILITIES = ["none", "mutable", "minting"];

function isRecordToken(value: unknown, range: Uint8Array, emptyCommitment: boolean): boolean {
  if (value === null) return false;
  const token = poolRecord(value, ["categoryWire32", "capability", "commitment", "amount"], F.SHAPE);
  poolRequire(typeof token.capability === "string" && CAPABILITIES.includes(token.capability) && typeof token.amount === "bigint", F.SHAPE);
  const commitment = poolAnyBytes(token.commitment, F.SHAPE);
  return poolEqual(pool32(token.categoryWire32, F.SHAPE), range) && token.capability === "minting"
    && (!emptyCommitment || (commitment.length === 0 && token.amount === 0n));
}

/**
 * Byte-level host model of the settlement covenant's check 4 (task 3.4,
 * `cashassembly/apnt_pool_settlement_v1.casm`), for one settlement's record
 * inputs `C + 1 .. C + 2B` in input order and its split outputs
 * `M + 1 + C .. M + C + 4B` in output order. In the covenant's order, for each
 * statement nullifier `j` and refusing with the first failing check's code:
 *
 * - exactly `2B` record inputs (`pool-range-input-count`) and `4B` split
 *   outputs (`pool-range-output-count`): the structural reading of the fixed
 *   positions;
 * - record input `j` carries the range category with minting
 *   (RECORD_CATEGORY, `pool-range-record-token`);
 * - its unlocking is exactly the record push for CODE (RECORD_REDEEM,
 *   `pool-range-record-redeem`), and the data it carries decodes canonically
 *   (`pool-range-record`; the covenant does not decode, and a record with
 *   non-canonical data exists only under an unaudited genesis);
 * - no record's data is listed twice (`pool-range-same-record`);
 * - `lo < κ(nf_j) < hi` (KEY_ABOVE_LO, KEY_BELOW_HI, `pool-range-not-contained`);
 * - splits `2j` and `2j + 1` each carry the range category with minting, an
 *   empty commitment and amount zero (OUT_CATEGORY, OUT_COMMITMENT_EMPTY,
 *   OUT_AMOUNT, `pool-range-split-token`), the record value (OUT_VALUE,
 *   `pool-range-split-value`), and the lock of `lo‖κ` and `κ‖hi`
 *   respectively (OUT_LOCK, `pool-range-split`: a split's data is its lock).
 *
 * Not modelled: the settlement authority, the positions themselves (`C` and
 * `M`), and the scans NO_STRAY_RECORD and NO_STRAY_RECORD_OUT over the other
 * inputs and outputs.
 */
export function evaluateAPNTPoolRangeSettlementV1(value: unknown): APNTPoolRangeInsertionResultV1 {
  try {
    const [clone] = poolBoundary([value]);
    const input = poolRecord(clone, [
      "statement", "deploymentId32", "rangeCategoryWire32", "codeBytecode", "recordValueSats", "recordInputs", "splitOutputs",
    ], F.SHAPE);
    const keys = statementKeys(input.statement, input.deploymentId32);
    const range = pool32(input.rangeCategoryWire32, F.SHAPE);
    const code = recordCodeOf(input.codeBytecode);
    const recordValue = input.recordValueSats;
    poolRequire(typeof recordValue === "bigint" && recordValue >= 1n, F.SHAPE);
    const records = poolArray(input.recordInputs, 0xffff_ffff, F.SHAPE);
    const splits = poolArray(input.splitOutputs, 0xffff_ffff, F.SHAPE);
    poolRequire(records.length === keys.length, F.RANGE_INPUT_COUNT);
    poolRequire(splits.length === 2 * keys.length, F.RANGE_OUTPUT_COUNT);
    const seen = new Set<string>();
    keys.forEach((key, j) => {
      const recordInput = poolRecord(records[j], ["unlockingBytecode", "token"], F.SHAPE);
      poolRequire(isRecordToken(recordInput.token, range, false), F.RANGE_RECORD_TOKEN);
      const data = unlockingData(code, poolAnyBytes(recordInput.unlockingBytecode, F.RANGE_RECORD_REDEEM));
      const record = recordOf(data);
      poolRequire(!seen.has(bytesToHex(data)), F.RANGE_SAME_RECORD);
      seen.add(bytesToHex(data));
      const expected = splitAt(record, key);
      expected.forEach((splitData, side) => {
        const split = poolRecord(splits[2 * j + side], ["lockingBytecode", "valueSats", "token"], F.SHAPE);
        poolRequire(isRecordToken(split.token, range, true), F.RANGE_SPLIT_TOKEN);
        poolRequire(split.valueSats === recordValue, F.RANGE_SPLIT_VALUE);
        poolRequire(poolEqual(poolAnyBytes(split.lockingBytecode, F.RANGE_SPLIT), p2sh32(recordRedeemOf(code, splitData))), F.RANGE_SPLIT);
      });
    });
    return Object.freeze({ valid: true, failureCode: null });
  } catch (error) {
    return Object.freeze({ valid: false, failureCode: poolFailureCodeOf(error) });
  }
}
