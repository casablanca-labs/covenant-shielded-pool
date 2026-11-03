import { createHash } from "node:crypto";

import { asBytes32, type Bytes32 } from "./bytes.js";

/**
 * APNT shielded pool v1: shared contract for the host semantics.
 *
 * Target: `protocol-design`, "Canonical
 * encodings" (task 2.1). Every pool module takes its domain tags, sizes,
 * failure codes and its one hash from here, so no second copy of any of them
 * exists.
 *
 * Pool hashes are raw `SHA-256(tag ‖ payload)` with the ASCII tag and no length
 * prefix. That is not the framing of `hash.ts`'s `sha256DomainSeparated`
 * (length-prefixed personalization, domain and payload), which therefore
 * cannot produce these bytes; {@link apntPoolSha256V1} is the pool's single
 * hash function.
 *
 * Host semantics only: no circuit, covenant, proof, chain read or wallet
 * state lives here.
 */

/** Host relation identity. A label, not a proof identity or an allowlist entry. */
export const APNT_POOL_ACTION_RELATION_V1_IDENTITY = "apnt-pool-action-host-rel-v1";

/** BCH `MAX_MONEY`, satoshis. Every value, deposit, withdrawal and fee lies in `[0, MAX_MONEY]`. */
export const APNT_POOL_V1_MAX_MONEY_SATS = 2_100_000_000_000_000n;

/** secp256k1 group order `n_G`. */
export const APNT_POOL_V1_CURVE_ORDER =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/**
 * The sixteen domain tags, as ASCII with no length prefix and no terminator.
 * Pairwise prefix-free (asserted by the test suite). A successor pool version
 * changes the `v1` component of every tag. `tagAuthorization` is the
 * tag-authorization message's (historical-record); `discoveryTag` is the v1 change and
 * dummy fill's (historical-record). `commitmentRandomness` and
 * `packetDigest` are the pad16 packet's (historical-record, historical-record); they replaced the
 * AES-256-GCM packet key's `APNT-POOL-v1:pk`, which is retired.
 */
export const APNT_POOL_V1_DOMAIN_TAGS = Object.freeze({
  commitment: "APNT-POOL-v1:cm",
  nullifier: "APNT-POOL-v1:nf",
  owner: "APNT-POOL-v1:owner",
  nullifierKeyCommitment: "APNT-POOL-v1:nkc",
  recoveryTag: "APNT-POOL-v1:rt",
  commitmentRandomness: "APNT-POOL-v1:rcm",
  packetDigest: "APNT-POOL-v1:pad",
  treeNode: "APNT-POOL-v1:node",
  frontier: "APNT-POOL-v1:frontier",
  actionAuthorization: "APNT-POOL-v1:action-auth",
  discoveryTag: "APNT-POOL-v1:dtag",
  tagAuthorization: "APNT-POOL-v1:dt-auth",
  statement: "APNT-POOL-v1:statement",
  deployment: "APNT-POOL-v1:deployment",
  migrationInbox: "APNT-POOL-v1:migrate",
  profile: "APNT-POOL-v1:profile",
} as const);
export type APNTPoolDomainTagV1 = typeof APNT_POOL_V1_DOMAIN_TAGS[keyof typeof APNT_POOL_V1_DOMAIN_TAGS];

export const APNT_POOL_V1_POINT_BYTES = 33;
/** The pad16 packet: an 8-byte padded value, then an 8-byte key check (historical-record). */
export const APNT_POOL_V1_PACKET_BYTES = 16;
/** The packet's first part, `u64le(v)` under the digest's first 8 bytes; the rest is the key check. */
export const APNT_POOL_V1_PACKET_VALUE_BYTES = 8;
export const APNT_POOL_V1_ACTION_RECORD_BYTES = 314;
/** A discovery tag `dt_j`: 8 bytes per output slot, outside `A` and `S` (historical-record). */
export const APNT_POOL_V1_DISCOVERY_TAG_BYTES = 8;
export const APNT_POOL_V1_STATEMENT_HEADER_BYTES = 88;
export const APNT_POOL_V1_STATEMENT_MAXIMUM_ACTIONS = 0xffff;
export const APNT_POOL_V1_TREE_DEPTH = 32;
/** Leaf capacity `2^32 − 1`: a full depth-32 frontier has no slot at level 32. */
export const APNT_POOL_V1_TREE_CAPACITY = 0xffff_ffff;

/** Closed, stable failure codes. They never carry a value, a field name or witness bytes. */
export const APNT_POOL_FAILURE_V1 = Object.freeze({
  SHAPE: "pool-shape",
  WITNESS_SHAPE: "pool-witness-shape",
  RECORD_LENGTH: "pool-record-length",
  RECORD_AMOUNT: "pool-record-amount",
  RECORD_WITHDRAWAL_LOCK: "pool-record-withdrawal-lock",
  RECORD_KEY: "pool-record-key",
  DISCOVERY_TAG: "pool-discovery-tag",
  STATEMENT_FIELD: "pool-statement-field",
  STATEMENT_LENGTH: "pool-statement-length",
  STATEMENT_TAG: "pool-statement-tag",
  STATEMENT_COUNT: "pool-statement-count",
  STATEMENT_DEPLOYMENT: "pool-statement-deployment",
  STATEMENT_ORDER: "pool-statement-order",
  STATEMENT_DUPLICATE_NULLIFIER: "pool-statement-duplicate-nullifier",
  STATEMENT_DUPLICATE_COMMITMENT: "pool-statement-duplicate-commitment",
  PROFILE_SYSTEM: "pool-profile-system-id",
  PROFILE_PARAMETERS: "pool-profile-parameters",
  DEPLOYMENT_NETWORK: "pool-deployment-network",
  DEPLOYMENT_CATEGORY: "pool-deployment-category",
  VALUE_RANGE: "pool-value-range",
  SPEND_KEY: "pool-spend-key",
  RERANDOMIZER: "pool-rerandomizer",
  RERANDOMIZED_KEY: "pool-rerandomized-key",
  NULLIFIER: "pool-nullifier",
  NULLIFIER_DUPLICATE: "pool-nullifier-duplicate",
  MEMBERSHIP: "pool-membership",
  RHO_INDEX: "pool-rho-index",
  OUTPUT_COMMITMENT: "pool-output-commitment",
  PACKET: "pool-packet",
  BALANCE: "pool-balance",
  NULLIFIER_REPLAYED: "pool-nullifier-replayed",
  DIGEST_SET_ENTRY: "pool-digest-set-entry",
  TREE_STATE: "pool-tree-state",
  TREE_COMMITMENT: "pool-tree-commitment",
  TREE_CAPACITY: "pool-tree-capacity",
  TREE_FRONTIER: "pool-tree-frontier",
  TREE_ROOT: "pool-tree-root",
  TREE_ROOT_COPIES: "pool-tree-root-copies",
  TREE_VERDICT_NOT_PENDING: "pool-tree-verdict-not-pending",
  TREE_LEAVES: "pool-tree-leaves",
  MIGRATION_LENGTH: "pool-migration-length",
  MIGRATION_DEPLOYMENT: "pool-migration-deployment",
  MIGRATION_AMOUNT: "pool-migration-amount",
  MIGRATION_COMMITMENT: "pool-migration-commitment",
  MIGRATION_PACKET: "pool-migration-packet",
  RANGE_ENDPOINT: "pool-range-endpoint",
  RANGE_RECORD: "pool-range-record",
  RANGE_GENESIS: "pool-range-genesis",
  RANGE_NOT_CONTAINED: "pool-range-not-contained",
  RANGE_OVERLAP: "pool-range-overlap",
  RANGE_SAME_RECORD: "pool-range-same-record",
  RANGE_INPUT_COUNT: "pool-range-input-count",
  RANGE_OUTPUT_COUNT: "pool-range-output-count",
  RANGE_SPLIT: "pool-range-split",
  RANGE_RECORD_REDEEM: "pool-range-record-redeem",
  RANGE_RECORD_TOKEN: "pool-range-record-token",
  RANGE_SPLIT_TOKEN: "pool-range-split-token",
  RANGE_SPLIT_VALUE: "pool-range-split-value",
  SETTLEMENT_SPEND: "pool-settlement-spend",
  SETTLEMENT_PENDING: "pool-settlement-pending",
  HISTORY_DUPLICATE: "pool-history-duplicate",
  HISTORY_SETTLEMENT: "pool-history-settlement",
  HISTORY_FOREIGN: "pool-history-foreign",
  HISTORY_GAP: "pool-history-gap",
  HISTORY_ORDER: "pool-history-order",
  HISTORY_RECORD_OUTPOINT: "pool-history-record-outpoint",
  HISTORY_SPLIT: "pool-history-split",
  HISTORY_FOLD: "pool-history-fold",
  COVENANT_PARAMETER: "pool-covenant-parameter",
  TRANSACTION: "pool-transaction",
  GENESIS_ARTIFACT: "pool-genesis-artifact",
  GENESIS_CATEGORY_ORDER: "pool-genesis-category-order",
  GENESIS_DEPLOYMENT: "pool-genesis-deployment",
  GENESIS_TXID: "pool-genesis-txid",
  GENESIS_OUTPOINT: "pool-genesis-outpoint",
  GENESIS_COVENANT: "pool-genesis-covenant",
  GENESIS_CONFINEMENT: "pool-genesis-confinement",
  GENESIS_AMOUNT: "pool-genesis-amount",
  GENESIS_STRAY: "pool-genesis-stray",
  GENESIS_VALUE: "pool-genesis-value",
  GENESIS_MISSING: "pool-genesis-missing",
  GENESIS_RANGE_RECORD: "pool-genesis-range-record",
  GENESIS_RANGE_BOUNDARY: "pool-genesis-range-boundary",
  GENESIS_RANGE_OVERLAP: "pool-genesis-range-overlap",
  GENESIS_RANGE_GAP: "pool-genesis-range-gap",
  GENESIS_RANGE_SINGLE_RECORD: "pool-genesis-range-single-record",
  DEPLOY_FUNDING: "pool-deploy-funding",
  DEPLOY_PARAMETER: "pool-deploy-parameter",
  DEPLOY_FACTORY: "pool-deploy-factory",
  DEPLOY_SIGNED: "pool-deploy-signed",
  DEPLOY_SIZE: "pool-deploy-size",
  BOUNDARY: "pool-boundary",
} as const);
export type APNTPoolFailureV1 = typeof APNT_POOL_FAILURE_V1[keyof typeof APNT_POOL_FAILURE_V1];

const CLOSED_FAILURE_CODES: ReadonlySet<string> = new Set(Object.values(APNT_POOL_FAILURE_V1));

/**
 * Exceptions carry only a closed code, never witness values or caller field
 * names. Internal: the package index does not export this class. Only an
 * instance thrown by {@link poolRequire} counts as a host failure; one built
 * anywhere else is never reported.
 */
export class APNTPoolHostErrorV1 extends Error {
  constructor(readonly code: APNTPoolFailureV1) { super(code); }
}

/** The errors the host threw itself, from its own checks. */
const HOST_ERRORS = new WeakSet<object>();

export function poolRequire(condition: unknown, code: APNTPoolFailureV1): asserts condition {
  if (!condition) poolFail(code);
}

export function poolFail(code: APNTPoolFailureV1): never {
  const error = Object.freeze(new APNTPoolHostErrorV1(code));
  HOST_ERRORS.add(error);
  throw error;
}

/**
 * The failure code of an error the host threw itself, if it is a closed code;
 * otherwise `fallback`, itself a closed code (else `pool-shape`). A caller's
 * error, however much it looks like a host error, never supplies a code.
 */
export function poolFailureCodeOf(error: unknown, fallback: APNTPoolFailureV1 = APNT_POOL_FAILURE_V1.SHAPE): APNTPoolFailureV1 {
  const closedFallback = CLOSED_FAILURE_CODES.has(fallback) ? fallback : APNT_POOL_FAILURE_V1.SHAPE;
  if (typeof error !== "object" || error === null || !HOST_ERRORS.has(error)) return closedFallback;
  const code = (error as APNTPoolHostErrorV1).code;
  return CLOSED_FAILURE_CODES.has(code) ? code : closedFallback;
}

/*
 * The host input boundary (historical-record; `apnt-pool-note-statement`, "The host
 * input boundary").
 *
 * Threat model: untrusted pool data enters the host only as bytes, through the
 * strict decoders. In-process object inputs come from trusted code and are
 * canonicalized defensively, by one primitive at every exported host entry
 * point:
 *
 * 1. {@link poolBoundary} takes a structured clone of the arguments. The clone
 *    throws on a proxy, a function or a symbol; it reads every getter once
 *    and keeps the value as data; and it turns a `Uint8Array`, `Array` or
 *    `Set` subclass into the plain intrinsic holding the actual contents.
 *    Anything the clone rejects, including an error that caller code throws
 *    while being cloned, is refused with `pool-boundary`.
 * 2. The clone is then validated with intrinsic-only operations by the shape
 *    helpers below. No method of the input is called, and no caller code runs
 *    after the clone, so every failure code comes from a host check.
 */
const cloneStructured = globalThis.structuredClone;
const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(Uint8Array.prototype) as object;
const typedArrayNameOf = Reflect.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, Symbol.toStringTag)!.get!;
const typedArrayLengthOf = Reflect.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, "length")!.get!;
const typedArraySetFrom = Uint8Array.prototype.set;
const setSizeOf = Reflect.getOwnPropertyDescriptor(Set.prototype, "size")!.get!;
const setValuesOf = Set.prototype.values;

/** The one host boundary: a structured clone of an entry point's arguments, or `pool-boundary`. */
export function poolBoundary(args: readonly unknown[]): unknown[] {
  let clone: unknown;
  try {
    clone = cloneStructured(args);
  } catch {
    poolFail(APNT_POOL_FAILURE_V1.BOUNDARY);
  }
  return clone as unknown[];
}

function isUint8Array(value: unknown): value is Uint8Array {
  return Reflect.apply(typedArrayNameOf, value, []) === "Uint8Array";
}

function byteLengthOf(value: Uint8Array): number {
  return Reflect.apply(typedArrayLengthOf, value, []) as number;
}

function ownDataValue(value: object, key: PropertyKey, code: APNTPoolFailureV1): unknown {
  const descriptor = Reflect.getOwnPropertyDescriptor(value, key);
  poolRequire(descriptor !== undefined && Object.hasOwn(descriptor, "value"), code);
  return descriptor.value;
}

/**
 * A cloned plain object with exactly these own keys (so no extra, for example
 * secret, field slips through); returns a frozen copy of their values.
 */
export function poolRecord(value: unknown, keys: readonly string[], code: APNTPoolFailureV1): Readonly<Record<string, unknown>> {
  poolRequire(typeof value === "object" && value !== null && !Array.isArray(value), code);
  const prototype = Object.getPrototypeOf(value);
  poolRequire(prototype === Object.prototype || prototype === null, code);
  const own = Reflect.ownKeys(value);
  poolRequire(own.length === keys.length && keys.every((key) => own.includes(key)), code);
  const copy: Record<string, unknown> = Object.create(null);
  for (const key of keys) copy[key] = ownDataValue(value, key, code);
  return Object.freeze(copy);
}

/** A cloned plain array of at most `maximumLength` elements; returns a frozen copy, read index by index. */
export function poolArray(value: unknown, maximumLength: number, code: APNTPoolFailureV1): readonly unknown[] {
  poolRequire(Array.isArray(value) && Object.getPrototypeOf(value) === Array.prototype, code);
  const length = ownDataValue(value, "length", code);
  poolRequire(typeof length === "number" && Number.isSafeInteger(length) && length >= 0 && length <= maximumLength, code);
  const copy: unknown[] = [];
  for (let index = 0; index < length; index += 1) copy.push(ownDataValue(value, String(index), code));
  return Object.freeze(copy);
}

/**
 * A fresh copy of a cloned `Uint8Array`, of any length. The copy is taken by
 * the intrinsic `%TypedArray%` operations into an unshared buffer: a cloned view
 * of a `SharedArrayBuffer` still shares memory, and the copy is what every
 * later check and hash reads.
 */
export function poolAnyBytes(value: unknown, code: APNTPoolFailureV1): Uint8Array {
  poolRequire(isUint8Array(value), code);
  const copy = new Uint8Array(byteLengthOf(value));
  Reflect.apply(typedArraySetFrom, copy, [value]);
  return copy;
}

export function poolBytes(value: unknown, length: number, code: APNTPoolFailureV1): Uint8Array {
  const copy = poolAnyBytes(value, code);
  poolRequire(copy.length === length, code);
  return copy;
}

export function pool32(value: unknown, code: APNTPoolFailureV1): Bytes32 {
  return asBytes32("pool", poolBytes(value, 32, code));
}

export function poolPair<T>(value: unknown, code: APNTPoolFailureV1, item: (entry: unknown) => T): readonly [T, T] {
  const pair = poolArray(value, 2, code);
  poolRequire(pair.length === 2, code);
  return Object.freeze([item(pair[0]), item(pair[1])] as const);
}

export function poolConcat(...parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) { poolRequire(isUint8Array(part), APNT_POOL_FAILURE_V1.SHAPE); total += byteLengthOf(part); }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) { Reflect.apply(typedArraySetFrom, out, [part, offset]); offset += byteLengthOf(part); }
  return out;
}

/** Byte equality by the intrinsic length and indexed reads; a subclass's `every` or `length` is never called. */
export function poolEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (!isUint8Array(a) || !isUint8Array(b)) return false;
  const length = byteLengthOf(a);
  if (length !== byteLengthOf(b)) return false;
  for (let index = 0; index < length; index += 1) if (a[index] !== b[index]) return false;
  return true;
}

/** Unsigned lexicographic byte order: the order of the bytes read as a big-endian integer. */
export function poolCompareBytes(a: Uint8Array, b: Uint8Array): number {
  poolRequire(isUint8Array(a) && isUint8Array(b), APNT_POOL_FAILURE_V1.SHAPE);
  const lengthA = byteLengthOf(a);
  const lengthB = byteLengthOf(b);
  const length = Math.min(lengthA, lengthB);
  for (let index = 0; index < length; index += 1) {
    const difference = a[index]! - b[index]!;
    if (difference !== 0) return difference;
  }
  return lengthA - lengthB;
}

const textEncoder = new TextEncoder();
const DOMAIN_TAGS: ReadonlySet<string> = new Set(Object.values(APNT_POOL_V1_DOMAIN_TAGS));

/** A listed domain tag's bytes; anything else, including an object with `toString`, refuses with `pool-shape`. */
export function poolTagBytes(tag: APNTPoolDomainTagV1): Uint8Array {
  poolRequire(typeof tag === "string" && DOMAIN_TAGS.has(tag), APNT_POOL_FAILURE_V1.SHAPE);
  return textEncoder.encode(tag);
}

/** The pool's one hash, internal form: `SHA-256(tag ‖ parts…)` over the host's own bytes. */
export function poolSha256(tag: APNTPoolDomainTagV1 | null, ...parts: readonly Uint8Array[]): Bytes32 {
  const hash = createHash("sha256");
  if (tag !== null) hash.update(poolTagBytes(tag));
  for (const part of parts) {
    poolRequire(isUint8Array(part), APNT_POOL_FAILURE_V1.SHAPE);
    hash.update(part);
  }
  return asBytes32("pool sha256", new Uint8Array(hash.digest()));
}

/**
 * The pool's one hash: `SHA-256(tag ‖ parts…)`. `tag` is one of the fifteen
 * domain tags or `null`, and each part is a `Uint8Array`; anything else refuses
 * with `pool-shape`, and an input the boundary cannot clone with `pool-boundary`.
 */
export function apntPoolSha256V1(tag: APNTPoolDomainTagV1 | null, ...parts: readonly Uint8Array[]): Bytes32 {
  const [clonedTag, ...clonedParts] = poolBoundary([tag, ...parts]);
  poolRequire(clonedTag === null || (typeof clonedTag === "string" && DOMAIN_TAGS.has(clonedTag)), APNT_POOL_FAILURE_V1.SHAPE);
  return poolSha256(clonedTag as APNTPoolDomainTagV1 | null, ...clonedParts.map((part) => poolAnyBytes(part, APNT_POOL_FAILURE_V1.SHAPE)));
}

/** `u64le` of an integer already known to be in `[0, 2^64)`. */
export function poolU64le(value: bigint, code: APNTPoolFailureV1): Uint8Array {
  poolRequire(typeof value === "bigint" && value >= 0n && value <= 0xffff_ffff_ffff_ffffn, code);
  const out = new Uint8Array(8);
  let rest = value;
  for (let index = 0; index < 8; index += 1) { out[index] = Number(rest & 0xffn); rest >>= 8n; }
  return out;
}

export function poolReadU64le(bytes: Uint8Array, offset: number): bigint {
  let value = 0n;
  for (let index = 7; index >= 0; index -= 1) value = (value << 8n) | BigInt(bytes[offset + index]!);
  return value;
}

export function poolU16le(value: number, code: APNTPoolFailureV1): Uint8Array {
  poolRequire(Number.isSafeInteger(value) && value >= 0 && value <= 0xffff, code);
  return Uint8Array.of(value & 0xff, value >>> 8);
}

/** A value, deposit, withdrawal or fee: a bigint in `[0, MAX_MONEY]`. */
export function poolMoney(value: unknown, code: APNTPoolFailureV1): bigint {
  poolRequire(typeof value === "bigint" && value >= 0n && value <= APNT_POOL_V1_MAX_MONEY_SATS, code);
  return value;
}

export function poolMoneyU64le(value: unknown, code: APNTPoolFailureV1): Uint8Array {
  return poolU64le(poolMoney(value, code), code);
}

const CANONICAL_DIGEST_HEX = /^[0-9a-f]{64}$/;
/** A bound on the entries a digest-set input may carry. */
const MAXIMUM_DIGEST_SET_ENTRIES = 0x1_0000_0000;

let createDigestSet: (entries: Iterable<unknown>, code: APNTPoolFailureV1) => APNTPoolDigestSetV1;

/**
 * An immutable set of 32-byte digests, held as canonical lowercase hex: the one
 * shape the pool's host set models (inserted nullifiers, pending verdicts)
 * return (historical-record H2).
 *
 * Every entry must be exactly 64 lowercase hex digits, so a noncanonical
 * spelling of a digest (uppercase, a prefix, another length, a non-string) is
 * refused rather than silently read as absent. An instance exposes no mutator;
 * every change returns a new set. `digests` is its entries as a frozen array:
 * the data a structured clone of the set carries, so a set passed back to the
 * host arrives as that data, and membership is computed from it by the host,
 * never by the input's methods. It models a set of chain facts; it is not a
 * covenant or chain state.
 */
export class APNTPoolDigestSetV1 implements ReadonlySet<string> {
  readonly digests: readonly string[];
  readonly #entries = new Set<string>();

  static {
    createDigestSet = (entries, code) => new APNTPoolDigestSetV1(entries, code);
  }

  private constructor(entries: Iterable<unknown>, code: APNTPoolFailureV1) {
    for (const entry of entries) {
      poolRequire(typeof entry === "string" && CANONICAL_DIGEST_HEX.test(entry), code);
      this.#entries.add(entry);
    }
    this.digests = Object.freeze([...this.#entries]);
    Object.freeze(this);
  }

  /** A digest set from a caller's `Set` of canonical hex or a digest set, through the host boundary. */
  static from(value: unknown): APNTPoolDigestSetV1 {
    const [clone] = poolBoundary([value]);
    return poolDigestSet(clone, APNT_POOL_FAILURE_V1.DIGEST_SET_ENTRY);
  }

  /** A new set without `removed`; `this` is unchanged. */
  without(removed: string): APNTPoolDigestSetV1 {
    return createDigestSet([...this.#entries].filter((entry) => entry !== removed), APNT_POOL_FAILURE_V1.DIGEST_SET_ENTRY);
  }

  get size(): number { return this.#entries.size; }
  has(value: string): boolean { return this.#entries.has(value); }
  forEach(callback: (value: string, key: string, set: ReadonlySet<string>) => void, thisArg?: unknown): void {
    for (const entry of this.#entries) callback.call(thisArg, entry, entry, this);
  }
  entries(): SetIterator<[string, string]> { return this.#entries.entries(); }
  keys(): SetIterator<string> { return this.#entries.keys(); }
  values(): SetIterator<string> { return this.#entries.values(); }
  [Symbol.iterator](): SetIterator<string> { return this.#entries.values(); }
}
Object.freeze(APNTPoolDigestSetV1.prototype);
Object.freeze(APNTPoolDigestSetV1);

/**
 * A digest set from a cloned value: a native `Set` (read through the intrinsic
 * `Set.prototype.values`), or the `{ digests }` data a cloned digest set
 * carries. Every entry is checked; anything else refuses with `code`.
 */
export function poolDigestSet(value: unknown, code: APNTPoolFailureV1): APNTPoolDigestSetV1 {
  let isSet = true;
  try { Reflect.apply(setSizeOf, value, []); } catch { isSet = false; }
  if (isSet) return createDigestSet(Reflect.apply(setValuesOf, value, []) as Iterable<unknown>, code);
  const record = poolRecord(value, ["digests"], code);
  return createDigestSet(poolArray(record.digests, MAXIMUM_DIGEST_SET_ENTRIES, code), code);
}
