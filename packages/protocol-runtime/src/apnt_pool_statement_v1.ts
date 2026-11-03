import { bytesToHex, type Bytes32 } from "./bytes.js";
import {
  APNT_POOL_FAILURE_V1 as F,
  APNT_POOL_V1_ACTION_RECORD_BYTES,
  APNT_POOL_V1_DOMAIN_TAGS as TAG,
  APNT_POOL_V1_STATEMENT_HEADER_BYTES,
  APNT_POOL_V1_STATEMENT_MAXIMUM_ACTIONS,
  APNTPoolDigestSetV1,
  pool32,
  poolCompareBytes,
  poolConcat,
  poolEqual,
  poolFailureCodeOf,
  poolAnyBytes,
  poolArray,
  poolBoundary,
  poolBytes,
  poolDigestSet,
  poolRecord,
  poolRequire,
  poolSha256,
  poolTagBytes,
  poolU16le,
  poolU64le,
  type APNTPoolFailureV1,
} from "./apnt_pool_contract_v1.js";
import {
  decodeAPNTPoolActionRecordV1,
  deriveAPNTPoolActionAuthorizationDigestV1,
  type APNTPoolActionRecordFieldsV1,
} from "./apnt_pool_action_record_v1.js";

/**
 * APNT shielded pool v1: `deployment_id`, `profile_id`, the statement `S`, and
 * the host model of nullifier insertion (design.md, "Canonical encodings";
 * "Nullifiers are owner-secret and unique by construction").
 *
 * ```text
 * S = "APNT-POOL-v1:statement" ‖ deployment_id ‖ profile_id ‖ u16le(B) ‖ A_1 ‖ … ‖ A_B
 *     offsets 0 (22 B), 22 (32 B), 54 (32 B), 86 (2 B), 88 + 314·(k − 1) (314 B)
 *     |S| = 88 + 314·B, 1 ≤ B ≤ 65,535
 * runBind32 = SHA-256(S)
 * ```
 *
 * Records are in strictly ascending byte-lexicographic `ad` order: `ad` is
 * compared as 32 unsigned bytes from the first, equivalently as a big-endian
 * integer, never as little-endian (design.md, "Statement"; pinned by ARCH-142).
 * A test pins it on X1's pair, whose little-endian order is the reverse.
 */

export const APNT_POOL_V1_STATEMENT_OFFSETS = Object.freeze({
  tag: 0,
  deploymentId: 22,
  profileId: 54,
  actionCount: 86,
  firstRecord: APNT_POOL_V1_STATEMENT_HEADER_BYTES,
} as const);

/**
 * The listed child proof systems of the registry (`apnt-pool-proof-system`):
 * 1 gnark Groth16 on BN254, 2 Halo 2 with IPA on the Pasta curves. Only these
 * derive a `profile_id`. Which profiles a deployment accepts is the aggregate
 * program's compiled allowlist, not this list.
 */
export const APNT_POOL_V1_PROOF_SYSTEM_IDS = Object.freeze({
  gnarkGroth16Bn254: 1,
  halo2IpaPasta: 2,
} as const);

/**
 * Reserved, not listed (ARCH-142): 3 is held for Binius64 so no other system
 * takes it, and it is refused, like 0 and every unlisted value, until a
 * registry entry names its verifier and its one `vp` serialization with a
 * parity vector. Without that entry a `profile_id` over `vp` bytes has no
 * defined meaning. Activating it changes the registry, this list and the
 * aggregate program only; `S`, `A` and the covenants carry `profile_id` as
 * 32 opaque bytes and do not change.
 */
export const APNT_POOL_V1_RESERVED_PROOF_SYSTEM_IDS = Object.freeze({
  binius64: 3,
} as const);
const LISTED_SYSTEM_IDS: ReadonlySet<number> = new Set(Object.values(APNT_POOL_V1_PROOF_SYSTEM_IDS));

/** `profile_id = SHA-256("APNT-POOL-v1:profile" ‖ u16le(system_id) ‖ u64le(len(vp)) ‖ vp)`. */
export function deriveAPNTPoolProfileIdV1(value: unknown): Bytes32 {
  [value] = poolBoundary([value]);
  const input = poolRecord(value, ["systemId", "verifierParameters"], F.PROFILE_PARAMETERS);
  const systemId = input.systemId;
  poolRequire(typeof systemId === "number" && LISTED_SYSTEM_IDS.has(systemId), F.PROFILE_SYSTEM);
  const vp = poolAnyBytes(input.verifierParameters, F.PROFILE_PARAMETERS);
  return poolSha256(TAG.profile, poolU16le(systemId, F.PROFILE_SYSTEM), poolU64le(BigInt(vp.length), F.PROFILE_PARAMETERS), vp);
}

/** BN254's scalar field order `r`, the native field of registry entry 1 (gnark-crypto `ecc.BN254.ScalarField()`). */
export const APNT_POOL_V1_BN254_SCALAR_ORDER =
  0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;

/**
 * Registry entry 1's public-input rule (HUM-80, ENG-437; unchanged by
 * revision 3's pad16 record, HUM-84, ENG-454): an action proof's one public
 * input is
 *
 * ```text
 * x = int_be(SHA-256(A)) mod r
 * ```
 *
 * over the 314 bytes of `A`, untagged, with `r` the BN254 scalar field order.
 * The digest is read big-endian, byte 0 most significant; about 81% of
 * digests are at least `r`, so the reduction runs on most records.
 *
 * Every verifier derives `x` from the `A` it holds (in `S` for the aggregate
 * program) and never takes `x`, or an integer spelling of it, from a prover:
 * the proof binds the field element, and `int_be(d)` and `int_be(d) − r`
 * name the same one. Like `ad`, `x` is defined over the record's bytes; the
 * strict record decode is the statement codec's, and a record it refuses
 * has no satisfying witness. Refuses anything but exactly 314 bytes with
 * `pool-record-length`.
 */
export function deriveAPNTPoolActionPublicInputV1(record314: unknown): bigint {
  [record314] = poolBoundary([record314]);
  const record = poolBytes(record314, APNT_POOL_V1_ACTION_RECORD_BYTES, F.RECORD_LENGTH);
  return BigInt(`0x${bytesToHex(poolSha256(null, record))}`) % APNT_POOL_V1_BN254_SCALAR_ORDER;
}

/**
 * The deployment network domain: one unsigned byte in the `deployment_id`
 * preimage. `local` (`0x99`, ARCH-293, operator decision 2026-09-27; REV-278)
 * is a zero-value-only local simulation deployment: it is not a BCH network,
 * and it names no chain. Which chain evidence a `local` deployment may be read
 * from is an entry policy of the wallet and the aggregator, not of this domain.
 * Adding it changed no `mainnet` or `chipnet` byte, id or vector.
 */
export const APNT_POOL_V1_NETWORK_BYTES = Object.freeze({ mainnet: 0x00, chipnet: 0x01, local: 0x99 } as const);
export type APNTPoolNetworkV1 = keyof typeof APNT_POOL_V1_NETWORK_BYTES;

/**
 * `deployment_id = SHA-256("APNT-POOL-v1:deployment" ‖ network_byte ‖ cat_verdict ‖ cat_range ‖ cat_root ‖ cat_meter)`.
 *
 * Categories are in **wire order** (the genesis txid reversed from its display
 * form), as `OP_UTXOTOKENCATEGORY` returns them. `meterCategoryWire32: null`
 * means a deployment without a meter and encodes as 32 zero bytes. The pool has
 * no meter since ARCH-196 (operator decision 2026-09-24), so every pool
 * deployment passes `null`; the encoding and its committed vectors, some of
 * which carry a meter category, are unchanged. `network` is one of the domain's
 * labels, compared exactly; any other value, a byte included, is refused with
 * `pool-deployment-network`.
 */
export function deriveAPNTPoolDeploymentIdV1(value: unknown): Bytes32 {
  [value] = poolBoundary([value]);
  const input = poolRecord(value, [
    "network", "verdictCategoryWire32", "rangeCategoryWire32", "rootCategoryWire32", "meterCategoryWire32",
  ], F.DEPLOYMENT_CATEGORY);
  const network = input.network;
  poolRequire(network === "mainnet" || network === "chipnet" || network === "local", F.DEPLOYMENT_NETWORK);
  const meterCategory = input.meterCategoryWire32;
  const meter = meterCategory === null ? new Uint8Array(32) : pool32(meterCategory, F.DEPLOYMENT_CATEGORY);
  return poolSha256(
    TAG.deployment,
    Uint8Array.of(APNT_POOL_V1_NETWORK_BYTES[network]),
    pool32(input.verdictCategoryWire32, F.DEPLOYMENT_CATEGORY),
    pool32(input.rangeCategoryWire32, F.DEPLOYMENT_CATEGORY),
    pool32(input.rootCategoryWire32, F.DEPLOYMENT_CATEGORY),
    meter,
  );
}

export type APNTPoolStatementV1 = Readonly<{
  deploymentId32: Bytes32;
  profileId32: Bytes32;
  /** The records in statement order (strictly ascending `ad`), each exactly 314 bytes. */
  records: readonly Uint8Array[];
  /** Their decoded fields, same order. */
  fields: readonly APNTPoolActionRecordFieldsV1[];
}>;

function checkRecordSet(deploymentId32: Uint8Array, records: readonly Uint8Array[], sortedAlready: boolean): readonly Uint8Array[] {
  const withDigest = records.map((record) => ({ record, ad: deriveAPNTPoolActionAuthorizationDigestV1(deploymentId32, record) }));
  const ordered = sortedAlready ? withDigest : withDigest.slice().sort((a, b) => poolCompareBytes(a.ad, b.ad));
  for (let k = 1; k < ordered.length; k += 1) {
    poolRequire(poolCompareBytes(ordered[k - 1]!.ad, ordered[k]!.ad) < 0, F.STATEMENT_ORDER);
  }
  const nullifiers = new Set<string>();
  const commitments = new Set<string>();
  for (const { record } of ordered) {
    const fields = decodeAPNTPoolActionRecordV1(record);
    for (const nf of fields.nullifiers32) {
      const key = bytesToHex(nf);
      poolRequire(!nullifiers.has(key), F.STATEMENT_DUPLICATE_NULLIFIER);
      nullifiers.add(key);
    }
    for (const cm of fields.commitments32) {
      const key = bytesToHex(cm);
      poolRequire(!commitments.has(key), F.STATEMENT_DUPLICATE_COMMITMENT);
      commitments.add(key);
    }
  }
  return ordered.map(({ record }) => record);
}

/**
 * Canonical encoder. Places the records in ascending `ad` order (the order is
 * a function of the record set, so it carries no aggregator choice) and
 * refuses equal records and any nullifier or commitment that appears twice.
 */
export function encodeAPNTPoolStatementV1(value: unknown): Uint8Array {
  [value] = poolBoundary([value]);
  const input = poolRecord(value, ["deploymentId32", "profileId32", "records"], F.STATEMENT_FIELD);
  const deploymentId32 = pool32(input.deploymentId32, F.STATEMENT_FIELD);
  const profileId32 = pool32(input.profileId32, F.STATEMENT_FIELD);
  const listed = poolArray(input.records, APNT_POOL_V1_STATEMENT_MAXIMUM_ACTIONS, F.STATEMENT_COUNT);
  poolRequire(listed.length >= 1, F.STATEMENT_COUNT);
  const records = listed.map((record) => poolBytes(record, APNT_POOL_V1_ACTION_RECORD_BYTES, F.RECORD_LENGTH));
  const ordered = checkRecordSet(deploymentId32, records, false);
  return poolConcat(
    poolTagBytes(TAG.statement),
    deploymentId32,
    profileId32,
    poolU16le(ordered.length, F.STATEMENT_COUNT),
    ...ordered,
  );
}

/**
 * Strict decode. Refuses any length other than `88 + 314·B`, a wrong tag,
 * `B = 0`, a `deployment_id` other than the expected one, a record that does
 * not decode, records out of strictly ascending `ad` order, and any nullifier
 * or commitment that appears twice. Whether `profile_id` is allowlisted is the
 * aggregate program's check and is not made here.
 */
export function decodeAPNTPoolStatementV1(statement: unknown, expectedDeploymentId32: unknown): APNTPoolStatementV1 {
  [statement, expectedDeploymentId32] = poolBoundary([statement, expectedDeploymentId32]);
  const expected = pool32(expectedDeploymentId32, F.STATEMENT_FIELD);
  const S = poolAnyBytes(statement, F.STATEMENT_LENGTH);
  poolRequire(S.length >= APNT_POOL_V1_STATEMENT_HEADER_BYTES, F.STATEMENT_LENGTH);
  const O = APNT_POOL_V1_STATEMENT_OFFSETS;
  poolRequire(poolEqual(S.subarray(O.tag, O.deploymentId), poolTagBytes(TAG.statement)), F.STATEMENT_TAG);
  const actionCount = S[O.actionCount]! | (S[O.actionCount + 1]! << 8);
  poolRequire(actionCount >= 1, F.STATEMENT_COUNT);
  poolRequire(S.length === APNT_POOL_V1_STATEMENT_HEADER_BYTES + APNT_POOL_V1_ACTION_RECORD_BYTES * actionCount, F.STATEMENT_LENGTH);
  const deploymentId32 = pool32(S.slice(O.deploymentId, O.profileId), F.STATEMENT_FIELD);
  poolRequire(poolEqual(deploymentId32, expected), F.STATEMENT_DEPLOYMENT);
  const profileId32 = pool32(S.slice(O.profileId, O.actionCount), F.STATEMENT_FIELD);
  const records: Uint8Array[] = [];
  for (let k = 0; k < actionCount; k += 1) {
    const start = O.firstRecord + APNT_POOL_V1_ACTION_RECORD_BYTES * k;
    records.push(S.slice(start, start + APNT_POOL_V1_ACTION_RECORD_BYTES));
  }
  checkRecordSet(deploymentId32, records, true);
  return Object.freeze({
    deploymentId32,
    profileId32,
    records: Object.freeze(records),
    fields: Object.freeze(records.map((record) => decodeAPNTPoolActionRecordV1(record))),
  });
}

/** `runBind32 = SHA-256(S)`, the proof verdict's commitment, over a strictly decodable `S`: one copy is decoded and hashed. */
export function deriveAPNTPoolStatementCommitmentV1(statement: unknown, expectedDeploymentId32: unknown): Bytes32 {
  [statement, expectedDeploymentId32] = poolBoundary([statement, expectedDeploymentId32]);
  const S = poolAnyBytes(statement, F.STATEMENT_LENGTH);
  decodeAPNTPoolStatementV1(S, expectedDeploymentId32);
  return poolSha256(null, S);
}

export type APNTPoolNullifierInsertionResultV1 =
  | Readonly<{ valid: true; failureCode: null; inserted: APNTPoolDigestSetV1 }>
  | Readonly<{ valid: false; failureCode: APNTPoolFailureV1; inserted: null }>;

/**
 * Host model of the set a settlement inserts into the nullifier range records.
 *
 * Every one of the statement's `2B` nullifiers is inserted, real or dummy:
 * the record does not say which slots are dummies, and inserting dummy
 * nullifiers is what keeps `ρ` unique across actions (design.md, "Dummy
 * notes"; X2). A nullifier already inserted refuses the whole statement.
 *
 * This models the set, not the range-record covenant (task 3.1), its
 * doubled-odd range key, or its one-record-per-nullifier layout.
 *
 * `alreadyInserted` is a `Set` of nullifiers as exactly 64 lowercase hex digits,
 * or a previous result's `inserted`. Any other entry (uppercase, another length,
 * a non-string) refuses with `pool-digest-set-entry`, so a noncanonical spelling
 * cannot make an inserted nullifier look absent (REV-133 H2). The arguments pass
 * the host boundary first, so membership is computed from the set's cloned
 * entries, never by its methods. The input is never mutated, and `inserted` is
 * an immutable {@link APNTPoolDigestSetV1}.
 */
export function insertAPNTPoolStatementNullifiersV1(
  alreadyInserted: ReadonlySet<string>,
  statement: unknown,
  expectedDeploymentId32: unknown,
): APNTPoolNullifierInsertionResultV1 {
  try {
    const [inserted, S, deploymentId32] = poolBoundary([alreadyInserted, statement, expectedDeploymentId32]);
    const prior = poolDigestSet(inserted, F.DIGEST_SET_ENTRY);
    const decoded = decodeAPNTPoolStatementV1(S, deploymentId32);
    const next = new Set(prior);
    for (const fields of decoded.fields) {
      for (const nf of fields.nullifiers32) {
        const key = bytesToHex(nf);
        poolRequire(!next.has(key), F.NULLIFIER_REPLAYED);
        next.add(key);
      }
    }
    return Object.freeze({ valid: true, failureCode: null, inserted: poolDigestSet(next, F.DIGEST_SET_ENTRY) });
  } catch (error) {
    return Object.freeze({ valid: false, failureCode: poolFailureCodeOf(error), inserted: null });
  }
}
