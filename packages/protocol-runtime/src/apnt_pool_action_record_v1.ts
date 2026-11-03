import { type Bytes32 } from "./bytes.js";
import {
  APNT_POOL_FAILURE_V1 as F,
  APNT_POOL_V1_ACTION_RECORD_BYTES,
  APNT_POOL_V1_DISCOVERY_TAG_BYTES,
  APNT_POOL_V1_DOMAIN_TAGS as TAG,
  APNT_POOL_V1_MAX_MONEY_SATS,
  APNT_POOL_V1_PACKET_BYTES,
  APNT_POOL_V1_POINT_BYTES,
  pool32,
  poolBoundary,
  poolBytes,
  poolConcat,
  poolMoneyU64le,
  poolPair,
  poolReadU64le,
  poolRecord,
  poolRequire,
  poolSha256,
} from "./apnt_pool_contract_v1.js";
import { assertAPNTPoolRecordKeyV1 } from "./apnt_pool_note_v1.js";

/**
 * APNT shielded pool v1: the 314-byte action record `A` and its authorization
 * digest `ad` (design.md, "Canonical encodings"). Revision 3 of registry
 * entry 1 (pad16, HUM-84): the packets are 16 bytes, and every field after
 * them moved up by 82 bytes from the 396-byte revision-2 record.
 *
 * | Offset | Bytes | Field |
 * |---|---|---|
 * | 0   | 32 | anchor |
 * | 32  | 32 | nf_0 |
 * | 64  | 32 | nf_1 |
 * | 96  | 33 | rk_0, SEC1c |
 * | 129 | 33 | rk_1, SEC1c |
 * | 162 | 32 | cm_0 |
 * | 194 | 32 | cm_1 |
 * | 226 | 16 | packet_0 |
 * | 242 | 16 | packet_1 |
 * | 258 | 8  | deposit, u64le |
 * | 266 | 8  | withdrawal, u64le |
 * | 274 | 8  | fee, u64le |
 * | 282 | 32 | wlock_hash (32 zero bytes if and only if withdrawal = 0) |
 *
 * `ad = SHA-256("APNT-POOL-v1:action-auth" ‖ deployment_id ‖ A)`, and the
 * tag-authorization message over the action's two 8-byte discovery tags
 * (HUM-75), which travel outside `A` and `S`:
 *
 * ```text
 * m = SHA-256("APNT-POOL-v1:dt-auth" ‖ ad ‖ dt_0 ‖ dt_1)
 * ```
 *
 * The owner of each slot signs `m` with BCH EC-Schnorr, and
 * `OP_CHECKDATASIG(sig, m, rk)` verifies that signature over `SHA-256(m)`.
 * No signature, proof or verdict is part of `A`, `ad` or `m`, and no tag is
 * part of `A` or `ad`. Statement order stays by `ad`, never by `m` or a tag.
 */
export const APNT_POOL_V1_ACTION_RECORD_OFFSETS = Object.freeze({
  anchor: 0,
  nullifier0: 32,
  nullifier1: 64,
  rerandomizedKey0: 96,
  rerandomizedKey1: 129,
  commitment0: 162,
  commitment1: 194,
  packet0: 226,
  packet1: 242,
  deposit: 258,
  withdrawal: 266,
  fee: 274,
  withdrawalLockHash: 282,
} as const);

export type APNTPoolActionRecordFieldsV1 = Readonly<{
  anchor32: Bytes32;
  nullifiers32: readonly [Bytes32, Bytes32];
  rerandomizedKeys33: readonly [Uint8Array, Uint8Array];
  commitments32: readonly [Bytes32, Bytes32];
  packets16: readonly [Uint8Array, Uint8Array];
  depositSats: bigint;
  withdrawalSats: bigint;
  feeSats: bigint;
  /** `SHA-256(withdrawal locking bytecode)`, or 32 zero bytes if and only if the withdrawal is 0. */
  withdrawalLockHash32: Bytes32;
}>;

const RECORD_KEYS = [
  "anchor32", "nullifiers32", "rerandomizedKeys33", "commitments32", "packets16",
  "depositSats", "withdrawalSats", "feeSats", "withdrawalLockHash32",
] as const;

function isZero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}

function recordAmount(value: unknown): bigint {
  poolRequire(typeof value === "bigint" && value >= 0n && value <= APNT_POOL_V1_MAX_MONEY_SATS, F.RECORD_AMOUNT);
  return value;
}

function withdrawalLockRule(withdrawalSats: bigint, withdrawalLockHash32: Uint8Array): void {
  poolRequire(withdrawalSats === 0n ? isZero(withdrawalLockHash32) : !isZero(withdrawalLockHash32), F.RECORD_WITHDRAWAL_LOCK);
}

export function normalizeAPNTPoolActionRecordFieldsV1(value: unknown): APNTPoolActionRecordFieldsV1 {
  [value] = poolBoundary([value]);
  const r = poolRecord(value, RECORD_KEYS, F.SHAPE);
  const fields: APNTPoolActionRecordFieldsV1 = Object.freeze({
    anchor32: pool32(r.anchor32, F.SHAPE),
    nullifiers32: poolPair(r.nullifiers32, F.SHAPE, (entry) => pool32(entry, F.SHAPE)),
    rerandomizedKeys33: poolPair(r.rerandomizedKeys33, F.SHAPE, (entry) => assertAPNTPoolRecordKeyV1(entry)),
    commitments32: poolPair(r.commitments32, F.SHAPE, (entry) => pool32(entry, F.SHAPE)),
    packets16: poolPair(r.packets16, F.SHAPE, (entry) => poolBytes(entry, APNT_POOL_V1_PACKET_BYTES, F.SHAPE)),
    depositSats: recordAmount(r.depositSats),
    withdrawalSats: recordAmount(r.withdrawalSats),
    feeSats: recordAmount(r.feeSats),
    withdrawalLockHash32: pool32(r.withdrawalLockHash32, F.SHAPE),
  });
  withdrawalLockRule(fields.withdrawalSats, fields.withdrawalLockHash32);
  return fields;
}

export function encodeAPNTPoolActionRecordV1(value: unknown): Uint8Array {
  [value] = poolBoundary([value]);
  const r = normalizeAPNTPoolActionRecordFieldsV1(value);
  const record = poolConcat(
    r.anchor32,
    r.nullifiers32[0], r.nullifiers32[1],
    r.rerandomizedKeys33[0], r.rerandomizedKeys33[1],
    r.commitments32[0], r.commitments32[1],
    r.packets16[0], r.packets16[1],
    poolMoneyU64le(r.depositSats, F.RECORD_AMOUNT),
    poolMoneyU64le(r.withdrawalSats, F.RECORD_AMOUNT),
    poolMoneyU64le(r.feeSats, F.RECORD_AMOUNT),
    r.withdrawalLockHash32,
  );
  poolRequire(record.length === APNT_POOL_V1_ACTION_RECORD_BYTES, F.RECORD_LENGTH);
  return record;
}

/** Strict decode: exactly 314 bytes, amounts in `[0, MAX_MONEY]`, valid `rk` points, the `wlock_hash` rule. */
export function decodeAPNTPoolActionRecordV1(value: unknown): APNTPoolActionRecordFieldsV1 {
  [value] = poolBoundary([value]);
  const bytes = poolBytes(value, APNT_POOL_V1_ACTION_RECORD_BYTES, F.RECORD_LENGTH);
  const O = APNT_POOL_V1_ACTION_RECORD_OFFSETS;
  const at = (offset: number, length: number) => bytes.slice(offset, offset + length);
  return normalizeAPNTPoolActionRecordFieldsV1({
    anchor32: at(O.anchor, 32),
    nullifiers32: [at(O.nullifier0, 32), at(O.nullifier1, 32)],
    rerandomizedKeys33: [at(O.rerandomizedKey0, APNT_POOL_V1_POINT_BYTES), at(O.rerandomizedKey1, APNT_POOL_V1_POINT_BYTES)],
    commitments32: [at(O.commitment0, 32), at(O.commitment1, 32)],
    packets16: [at(O.packet0, APNT_POOL_V1_PACKET_BYTES), at(O.packet1, APNT_POOL_V1_PACKET_BYTES)],
    depositSats: poolReadU64le(bytes, O.deposit),
    withdrawalSats: poolReadU64le(bytes, O.withdrawal),
    feeSats: poolReadU64le(bytes, O.fee),
    withdrawalLockHash32: at(O.withdrawalLockHash, 32),
  });
}

/** `ad = SHA-256("APNT-POOL-v1:action-auth" ‖ deployment_id ‖ A)`, over a strictly decodable `A`: one copy is decoded and hashed. */
export function deriveAPNTPoolActionAuthorizationDigestV1(deploymentId32: unknown, record314: unknown): Bytes32 {
  [deploymentId32, record314] = poolBoundary([deploymentId32, record314]);
  const deploymentId = pool32(deploymentId32, F.STATEMENT_FIELD);
  const record = poolBytes(record314, APNT_POOL_V1_ACTION_RECORD_BYTES, F.RECORD_LENGTH);
  decodeAPNTPoolActionRecordV1(record);
  return poolSha256(TAG.actionAuthorization, deploymentId, record);
}

/**
 * `m = SHA-256("APNT-POOL-v1:dt-auth" ‖ ad ‖ dt_0 ‖ dt_1)` (HUM-75), over a
 * 32-byte `ad` and the action's discovery tags `[dt_0, dt_1]`, output 0's
 * first, each exactly 8 bytes (`pool-discovery-tag` otherwise). The owners sign
 * `m` in place of `ad`; the settlement covenant recomputes it from the record
 * and the tags in input 0's signature push. Nothing checks what a tag
 * contains: its fill rule is the wallet's.
 */
export function deriveAPNTPoolTagAuthorizationMessageV1(ad32: unknown, discoveryTags8: unknown): Bytes32 {
  [ad32, discoveryTags8] = poolBoundary([ad32, discoveryTags8]);
  const ad = pool32(ad32, F.SHAPE);
  const tags = poolPair(discoveryTags8, F.DISCOVERY_TAG, (entry) => poolBytes(entry, APNT_POOL_V1_DISCOVERY_TAG_BYTES, F.DISCOVERY_TAG));
  return poolSha256(TAG.tagAuthorization, ad, tags[0], tags[1]);
}

/**
 * The 32-byte hash a slot's BCH EC-Schnorr signature is made over, for the
 * 32-byte message given to `OP_CHECKDATASIG(sig, message, rk)`:
 * `SHA-256(message)`, because the opcode hashes its message once with SHA-256
 * before verifying. The owners' message is the tag-authorization message `m`
 * (HUM-75), so they sign `SHA-256(m)`. Before HUM-75 it was `ad`; the committed
 * `signedHash` vectors are this function's value over `ad`, which is no longer
 * what an owner signs.
 */
export function deriveAPNTPoolAuthorizationSignedHashV1(message32: unknown): Bytes32 {
  [message32] = poolBoundary([message32]);
  return poolSha256(null, pool32(message32, F.SHAPE));
}
