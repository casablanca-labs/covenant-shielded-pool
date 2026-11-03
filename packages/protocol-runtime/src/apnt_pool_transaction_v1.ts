import { bytesToHex, type Bytes32 } from "./bytes.js";
import {
  APNT_POOL_FAILURE_V1 as F,
  APNT_POOL_V1_MAX_MONEY_SATS,
  pool32,
  poolAnyBytes,
  poolBoundary,
  poolRequire,
  poolSha256,
} from "./apnt_pool_contract_v1.js";

/**
 * APNT shielded pool v1: the strict decoder of a raw BCH transaction with
 * CashTokens token prefixes, through which chain data such as a genesis
 * transaction (task 3.2) enters the host.
 *
 * ```text
 * tx       = u32le(version) ‖ cs(#in) ‖ input* ‖ cs(#out) ‖ output* ‖ u32le(locktime)
 * input    = outpoint txid (32, wire order) ‖ u32le(index) ‖ cs(len) ‖ unlocking ‖ u32le(sequence)
 * output   = u64le(value) ‖ cs(len) ‖ [token prefix] ‖ locking bytecode
 * prefix   = 0xef ‖ category (32, wire order) ‖ bitfield ‖ [cs(len) ‖ commitment] ‖ [cs(amount)]
 * txid     = HASH256(tx) in wire order; its display form is the reverse
 * ```
 *
 * `cs` is a CompactSize and must be minimal. The token prefix follows
 * CHIP-2022-02 (CashTokens): the reserved bit is clear; the capability is
 * none (0), mutable (1) or minting (2) and needs an NFT; a commitment needs an
 * NFT and is 1 to 128 bytes (the BCH 2026 consensus limit); an encoded amount
 * is 1 to `2^63 − 1`; a prefix encodes an NFT, an amount or both. Further, the
 * version is 1 or 2, every value is at most `MAX_MONEY`, the transaction has at
 * least one input and one output and at most 1,000,000 bytes, no two inputs
 * spend the same outpoint (wire-order txid and index; a consensus rule that
 * Libauth's structural decoder does not apply), and no byte trails the
 * locktime. Anything else refuses with `pool-transaction`.
 *
 * Byte order: a category and an outpoint txid are kept in **wire order**, as
 * the bytes appear in the transaction and as `OP_UTXOTOKENCATEGORY` and
 * `OP_OUTPOINTTXHASH` return them. Display order, what explorers and Libauth's
 * `token.category` show, is the reverse; only the transaction's own id is
 * given in both.
 *
 * Structural decoding only: no script, signature, token-conservation or
 * standardness check, so a decoded transaction is not a valid one, and chain
 * inclusion is a chain read's to establish.
 */

export const APNT_POOL_V1_TRANSACTION_MAXIMUM_BYTES = 1_000_000;
export const APNT_POOL_V1_TOKEN_COMMITMENT_MAXIMUM_BYTES = 128;
export const APNT_POOL_V1_TOKEN_AMOUNT_MAXIMUM = (1n << 63n) - 1n;

export type APNTPoolTokenCapabilityV1 = "none" | "mutable" | "minting";

export type APNTPoolTransactionTokenV1 = Readonly<{
  /** The token category, wire order. */
  categoryWire32: Bytes32;
  /** The fungible amount; 0 when the prefix encodes none. */
  amount: bigint;
  /** The non-fungible token, or `null` when the prefix encodes none. */
  nft: Readonly<{ capability: APNTPoolTokenCapabilityV1; commitment: Uint8Array }> | null;
}>;

export type APNTPoolTransactionInputV1 = Readonly<{
  /** The spent outpoint's transaction id, wire order. */
  outpointTxidWire32: Bytes32;
  outpointIndex: number;
  unlockingBytecode: Uint8Array;
  sequenceNumber: number;
}>;

export type APNTPoolTransactionOutputV1 = Readonly<{
  valueSats: bigint;
  /** The locking bytecode after any token prefix. */
  lockingBytecode: Uint8Array;
  token: APNTPoolTransactionTokenV1 | null;
}>;

export type APNTPoolTransactionV1 = Readonly<{
  /** `HASH256` of the transaction bytes: the id as outpoints and categories carry it. */
  txidWire32: Bytes32;
  /** The same id reversed: the display form. */
  txidDisplay32: Bytes32;
  version: number;
  inputs: readonly APNTPoolTransactionInputV1[];
  outputs: readonly APNTPoolTransactionOutputV1[];
  locktime: number;
}>;

const TOKEN_PREFIX = 0xef;
const TOKEN_RESERVED_BIT = 0x80;
const TOKEN_HAS_COMMITMENT_LENGTH = 0x40;
const TOKEN_HAS_NFT = 0x20;
const TOKEN_HAS_AMOUNT = 0x10;
const TOKEN_CAPABILITY_MASK = 0x0f;
const CAPABILITIES: readonly APNTPoolTokenCapabilityV1[] = Object.freeze(["none", "mutable", "minting"]);
/** The smallest value each CompactSize width may carry: anything below it has a shorter encoding. */
const COMPACT_MINIMUM: ReadonlyMap<number, readonly [number, bigint]> = new Map([[0xfd, [2, 0xfdn]], [0xfe, [4, 0x1_0000n]], [0xff, [8, 0x1_0000_0000n]]]);

type Cursor = { readonly bytes: Uint8Array; offset: number };

function take(cursor: Cursor, length: number): Uint8Array {
  poolRequire(Number.isSafeInteger(length) && length >= 0 && cursor.offset + length <= cursor.bytes.length, F.TRANSACTION);
  const out = cursor.bytes.slice(cursor.offset, cursor.offset + length);
  cursor.offset += length;
  return out;
}

function unsignedLe(cursor: Cursor, width: number): bigint {
  const bytes = take(cursor, width);
  let value = 0n;
  for (let index = width - 1; index >= 0; index -= 1) value = (value << 8n) | BigInt(bytes[index]!);
  return value;
}

function compactSize(cursor: Cursor): bigint {
  const prefix = Number(unsignedLe(cursor, 1));
  const wide = COMPACT_MINIMUM.get(prefix);
  if (wide === undefined) return BigInt(prefix);
  const value = unsignedLe(cursor, wide[0]);
  poolRequire(value >= wide[1], F.TRANSACTION);
  return value;
}

/** A CompactSize count or length that the remaining bytes could still hold. */
function compactLength(cursor: Cursor): number {
  const value = compactSize(cursor);
  poolRequire(value <= BigInt(cursor.bytes.length - cursor.offset), F.TRANSACTION);
  return Number(value);
}

function tokenOf(field: Uint8Array): { token: APNTPoolTransactionTokenV1 | null; lockingBytecode: Uint8Array } {
  if (field.length === 0 || field[0] !== TOKEN_PREFIX) return { token: null, lockingBytecode: field };
  const cursor: Cursor = { bytes: field, offset: 1 };
  const categoryWire32 = pool32(take(cursor, 32), F.TRANSACTION);
  const bitfield = take(cursor, 1)[0]!;
  poolRequire((bitfield & TOKEN_RESERVED_BIT) === 0, F.TRANSACTION);
  const capability = bitfield & TOKEN_CAPABILITY_MASK;
  poolRequire(capability < CAPABILITIES.length, F.TRANSACTION);
  const hasNft = (bitfield & TOKEN_HAS_NFT) !== 0;
  const hasCommitment = (bitfield & TOKEN_HAS_COMMITMENT_LENGTH) !== 0;
  const hasAmount = (bitfield & TOKEN_HAS_AMOUNT) !== 0;
  poolRequire(!hasCommitment || hasNft, F.TRANSACTION);
  poolRequire(hasNft || (capability === 0 && hasAmount), F.TRANSACTION);
  let commitment: Uint8Array = new Uint8Array(0);
  if (hasCommitment) {
    const length = compactLength(cursor);
    poolRequire(length >= 1 && length <= APNT_POOL_V1_TOKEN_COMMITMENT_MAXIMUM_BYTES, F.TRANSACTION);
    commitment = take(cursor, length);
  }
  let amount = 0n;
  if (hasAmount) {
    amount = compactSize(cursor);
    poolRequire(amount >= 1n && amount <= APNT_POOL_V1_TOKEN_AMOUNT_MAXIMUM, F.TRANSACTION);
  }
  const nft = hasNft ? Object.freeze({ capability: CAPABILITIES[capability]!, commitment }) : null;
  return { token: Object.freeze({ categoryWire32, amount, nft }), lockingBytecode: take(cursor, field.length - cursor.offset) };
}

/** The decoder proper, on bytes the host already owns. */
export function poolDecodeTransaction(bytes: Uint8Array): APNTPoolTransactionV1 {
  poolRequire(bytes.length <= APNT_POOL_V1_TRANSACTION_MAXIMUM_BYTES, F.TRANSACTION);
  const cursor: Cursor = { bytes, offset: 0 };
  const version = Number(unsignedLe(cursor, 4));
  poolRequire(version === 1 || version === 2, F.TRANSACTION);
  const inputCount = compactLength(cursor);
  poolRequire(inputCount >= 1, F.TRANSACTION);
  const inputs: APNTPoolTransactionInputV1[] = [];
  const outpoints = new Set<string>();
  for (let index = 0; index < inputCount; index += 1) {
    const outpointTxidWire32 = pool32(take(cursor, 32), F.TRANSACTION);
    const outpointIndex = Number(unsignedLe(cursor, 4));
    const outpoint = `${bytesToHex(outpointTxidWire32)}:${String(outpointIndex)}`;
    poolRequire(!outpoints.has(outpoint), F.TRANSACTION);
    outpoints.add(outpoint);
    const unlockingBytecode = take(cursor, compactLength(cursor));
    const sequenceNumber = Number(unsignedLe(cursor, 4));
    inputs.push(Object.freeze({ outpointTxidWire32, outpointIndex, unlockingBytecode, sequenceNumber }));
  }
  const outputCount = compactLength(cursor);
  poolRequire(outputCount >= 1, F.TRANSACTION);
  const outputs: APNTPoolTransactionOutputV1[] = [];
  for (let index = 0; index < outputCount; index += 1) {
    const valueSats = unsignedLe(cursor, 8);
    poolRequire(valueSats <= APNT_POOL_V1_MAX_MONEY_SATS, F.TRANSACTION);
    const { token, lockingBytecode } = tokenOf(take(cursor, compactLength(cursor)));
    outputs.push(Object.freeze({ valueSats, lockingBytecode, token }));
  }
  const locktime = Number(unsignedLe(cursor, 4));
  poolRequire(cursor.offset === bytes.length, F.TRANSACTION);
  const txidWire32 = poolSha256(null, poolSha256(null, bytes));
  return Object.freeze({
    txidWire32,
    txidDisplay32: pool32(txidWire32.slice().reverse(), F.TRANSACTION),
    version,
    inputs: Object.freeze(inputs),
    outputs: Object.freeze(outputs),
    locktime,
  });
}

/**
 * Strict decode of a raw BCH transaction with CashTokens prefixes. Refuses
 * with `pool-transaction` (see the module comment), or `pool-boundary` for an
 * input the host boundary cannot clone.
 */
export function decodeAPNTPoolTransactionV1(bytes: unknown): APNTPoolTransactionV1 {
  [bytes] = poolBoundary([bytes]);
  return poolDecodeTransaction(poolAnyBytes(bytes, F.TRANSACTION));
}

/** A transaction to encode: the decoder's fields without the ids, which follow from the bytes. */
export type APNTPoolTransactionDraftV1 = Readonly<{
  version: number;
  inputs: readonly APNTPoolTransactionInputV1[];
  outputs: readonly APNTPoolTransactionOutputV1[];
  locktime: number;
}>;

function unsignedLeBytes(value: bigint, width: number): Uint8Array {
  const out = new Uint8Array(width);
  let rest = value;
  for (let index = 0; index < width; index += 1) {
    out[index] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return out;
}

/** The minimal CompactSize of `value`, the only form the decoder accepts. */
function compactSizeBytes(value: bigint): Uint8Array {
  if (value < 0xfdn) return Uint8Array.of(Number(value));
  if (value <= 0xffffn) return Uint8Array.of(0xfd, ...unsignedLeBytes(value, 2));
  if (value <= 0xffff_ffffn) return Uint8Array.of(0xfe, ...unsignedLeBytes(value, 4));
  return Uint8Array.of(0xff, ...unsignedLeBytes(value, 8));
}

const flat = (parts: readonly Uint8Array[]): Uint8Array => {
  const bytes = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.length;
  }
  return bytes;
};
const withLength = (bytes: Uint8Array): Uint8Array[] => [compactSizeBytes(BigInt(bytes.length)), bytes];

function tokenField(token: APNTPoolTransactionTokenV1 | null, lockingBytecode: Uint8Array): Uint8Array {
  if (token === null) return lockingBytecode;
  const nft = token.nft;
  const commitment = nft?.commitment ?? new Uint8Array(0);
  const bitfield = (nft === null ? 0 : TOKEN_HAS_NFT | CAPABILITIES.indexOf(nft.capability))
    | (commitment.length > 0 ? TOKEN_HAS_COMMITMENT_LENGTH : 0) | (token.amount > 0n ? TOKEN_HAS_AMOUNT : 0);
  return flat([
    Uint8Array.of(TOKEN_PREFIX), token.categoryWire32, Uint8Array.of(bitfield),
    ...(commitment.length > 0 ? withLength(commitment) : []),
    ...(token.amount > 0n ? [compactSizeBytes(token.amount)] : []),
    lockingBytecode,
  ]);
}

/** One output as a transaction carries it: `u64le(value) ‖ cs(len) ‖ [token prefix] ‖ locking bytecode`. */
export function poolEncodeOutput(output: APNTPoolTransactionOutputV1): Uint8Array {
  return flat([unsignedLeBytes(output.valueSats, 8), ...withLength(tokenField(output.token, output.lockingBytecode))]);
}

/**
 * The encoder the decoder inverts, on a draft the host built itself: the same
 * layout (wire-order outpoint txids and categories, minimal CompactSizes). It
 * decodes its own output strictly and refuses with `pool-transaction` what the
 * decoder refuses (a value above `MAX_MONEY`, a repeated outpoint, a malformed
 * token), so it never emits bytes the decoder would not read back. Internal:
 * the package index does not export it.
 */
export function poolEncodeTransaction(draft: APNTPoolTransactionDraftV1): Uint8Array {
  const parts: Uint8Array[] = [unsignedLeBytes(BigInt(draft.version), 4), compactSizeBytes(BigInt(draft.inputs.length))];
  for (const input of draft.inputs) {
    parts.push(input.outpointTxidWire32, unsignedLeBytes(BigInt(input.outpointIndex), 4), ...withLength(input.unlockingBytecode), unsignedLeBytes(BigInt(input.sequenceNumber), 4));
  }
  parts.push(compactSizeBytes(BigInt(draft.outputs.length)), ...draft.outputs.map(poolEncodeOutput), unsignedLeBytes(BigInt(draft.locktime), 4));
  const bytes = flat(parts);
  const decoded = poolDecodeTransaction(bytes);
  poolRequire(decoded.inputs.length === draft.inputs.length && decoded.outputs.length === draft.outputs.length, F.TRANSACTION);
  return bytes;
}
