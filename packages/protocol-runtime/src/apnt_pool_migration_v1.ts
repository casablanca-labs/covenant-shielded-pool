import { type Bytes32 } from "./bytes.js";
import {
  APNT_POOL_FAILURE_V1 as F,
  APNT_POOL_V1_DOMAIN_TAGS as TAG,
  APNT_POOL_V1_PACKET_BYTES,
  pool32,
  poolBoundary,
  poolBytes,
  poolConcat,
  poolEqual,
  poolFailureCodeOf,
  poolMoney,
  poolMoneyU64le,
  poolReadU64le,
  poolRecord,
  poolRequire,
  poolSha256,
  type APNTPoolFailureV1,
} from "./apnt_pool_contract_v1.js";
import { decodeAPNTPoolStatementV1 } from "./apnt_pool_statement_v1.js";

/**
 * APNT shielded pool v1: the migration inbox's committed preimage, its hash
 * `h`, and a host model of the inbox's release condition (design.md,
 * "Versioning and migration"; `apnt-pool-versioning-migration`). The inbox
 * covenant (task 3.6) and the migration action (task 7.1) mirror these
 * semantics; nothing here is that covenant.
 *
 * ```text
 * h = SHA-256("APNT-POOL-v1:migrate" ‖ deployment_id_{n+1} ‖ cm_new ‖ SHA-256(packet_new) ‖ u64le(W))
 *     the preimage after the tag is 104 bytes: offsets 0 (32 B), 32 (32 B), 64 (32 B), 96 (8 B)
 * ```
 *
 * Step 1, an ordinary pool-`n` action, withdraws `W` to the inbox lock
 * `L_inbox(h)`. Step 2, a pool-`n+1` deposit action, must carry a record with
 * `deposit = W`, `cm_0 = cm_new` and `packet_0 = packet_new`. `W` lies in
 * `[1, MAX_MONEY]`: step 1 is a withdrawal, and a record's `wlock_hash` is
 * nonzero only when its withdrawal is.
 *
 * Not here: the inbox lock `L_inbox(h)` and therefore step 1's `wlock_hash`
 * (task 3.6), the step-2 dummies derived from the seed and a migration counter
 * (wallet), and the spending transaction's inputs, outputs and values.
 */

export const APNT_POOL_V1_MIGRATION_INBOX_PREIMAGE_BYTES = 104;
export const APNT_POOL_V1_MIGRATION_INBOX_OFFSETS = Object.freeze({
  successorDeploymentId: 0,
  commitment: 32,
  packetHash: 64,
  amount: 96,
} as const);

export type APNTPoolMigrationInboxV1 = Readonly<{
  /** `deployment_id_{n+1}`, the pool the value moves into. */
  successorDeploymentId32: Bytes32;
  /** `cm_new`. */
  commitment32: Bytes32;
  /** `SHA-256(packet_new)`. */
  packetHash32: Bytes32;
  /** `W`, satoshis, in `[1, MAX_MONEY]`. */
  amountSats: bigint;
}>;

function migrationAmount(value: unknown): bigint {
  const amount = poolMoney(value, F.MIGRATION_AMOUNT);
  poolRequire(amount > 0n, F.MIGRATION_AMOUNT);
  return amount;
}

/** The 104-byte preimage from `deployment_id_{n+1}`, `cm_new`, the 16-byte `packet_new` and `W`. */
export function encodeAPNTPoolMigrationInboxPreimageV1(value: unknown): Uint8Array {
  [value] = poolBoundary([value]);
  const input = poolRecord(value, ["successorDeploymentId32", "commitment32", "packet16", "amountSats"], F.SHAPE);
  return poolConcat(
    pool32(input.successorDeploymentId32, F.MIGRATION_DEPLOYMENT),
    pool32(input.commitment32, F.MIGRATION_COMMITMENT),
    poolSha256(null, poolBytes(input.packet16, APNT_POOL_V1_PACKET_BYTES, F.MIGRATION_PACKET)),
    poolMoneyU64le(migrationAmount(input.amountSats), F.MIGRATION_AMOUNT),
  );
}

/**
 * Strict decode: exactly 104 bytes (`pool-migration-length`), the successor
 * `deployment_id` equal to the expected one (`pool-migration-deployment`), and
 * `W` in `[1, MAX_MONEY]` (`pool-migration-amount`). `cm_new` and the packet
 * hash are any 32 bytes here; the release check binds them.
 */
export function decodeAPNTPoolMigrationInboxPreimageV1(value: unknown, expectedSuccessorDeploymentId32: unknown): APNTPoolMigrationInboxV1 {
  [value, expectedSuccessorDeploymentId32] = poolBoundary([value, expectedSuccessorDeploymentId32]);
  const expected = pool32(expectedSuccessorDeploymentId32, F.MIGRATION_DEPLOYMENT);
  const preimage = poolBytes(value, APNT_POOL_V1_MIGRATION_INBOX_PREIMAGE_BYTES, F.MIGRATION_LENGTH);
  const O = APNT_POOL_V1_MIGRATION_INBOX_OFFSETS;
  const successorDeploymentId32 = pool32(preimage.slice(O.successorDeploymentId, O.commitment), F.MIGRATION_DEPLOYMENT);
  poolRequire(poolEqual(successorDeploymentId32, expected), F.MIGRATION_DEPLOYMENT);
  return Object.freeze({
    successorDeploymentId32,
    commitment32: pool32(preimage.slice(O.commitment, O.packetHash), F.MIGRATION_COMMITMENT),
    packetHash32: pool32(preimage.slice(O.packetHash, O.amount), F.MIGRATION_PACKET),
    amountSats: migrationAmount(poolReadU64le(preimage, O.amount)),
  });
}

/** `h = SHA-256("APNT-POOL-v1:migrate" ‖ preimage)`, over a strictly decodable preimage: one copy is decoded and hashed. */
export function deriveAPNTPoolMigrationInboxHashV1(value: unknown, expectedSuccessorDeploymentId32: unknown): Bytes32 {
  [value, expectedSuccessorDeploymentId32] = poolBoundary([value, expectedSuccessorDeploymentId32]);
  const preimage = poolBytes(value, APNT_POOL_V1_MIGRATION_INBOX_PREIMAGE_BYTES, F.MIGRATION_LENGTH);
  decodeAPNTPoolMigrationInboxPreimageV1(preimage, expectedSuccessorDeploymentId32);
  return poolSha256(TAG.migrationInbox, preimage);
}

export type APNTPoolMigrationInboxReleaseResultV1 =
  | Readonly<{ valid: true; failureCode: null }>
  | Readonly<{ valid: false; failureCode: APNTPoolFailureV1 }>;

/**
 * Host model of the inbox's release condition: the successor pool's statement
 * `S` decodes strictly under the inbox's own `deployment_id_{n+1}`, and one of
 * its records has `cm_0 = cm_new` (`pool-migration-commitment`),
 * `SHA-256(packet_0)` equal to the committed hash (`pool-migration-packet`),
 * and `deposit = W` (`pool-migration-amount`). At most one record can match,
 * because no commitment appears twice in `S`.
 *
 * A sound proof already binds `packet_0` to `cm_0`; the packet check is the
 * inbox's own, as the spec requires. That the spending transaction settles
 * this `S`, and moves the inbox's value into pool coins, is the covenant's.
 */
export function evaluateAPNTPoolMigrationInboxReleaseV1(value: unknown): APNTPoolMigrationInboxReleaseResultV1 {
  try {
    const [clone] = poolBoundary([value]);
    const input = poolRecord(clone, ["preimage104", "successorDeploymentId32", "statement"], F.SHAPE);
    const inbox = decodeAPNTPoolMigrationInboxPreimageV1(input.preimage104, input.successorDeploymentId32);
    const statement = decodeAPNTPoolStatementV1(input.statement, inbox.successorDeploymentId32);
    const record = statement.fields.find((fields) => poolEqual(fields.commitments32[0], inbox.commitment32));
    poolRequire(record !== undefined, F.MIGRATION_COMMITMENT);
    poolRequire(poolEqual(poolSha256(null, record.packets16[0]), inbox.packetHash32), F.MIGRATION_PACKET);
    poolRequire(record.depositSats === inbox.amountSats, F.MIGRATION_AMOUNT);
    return Object.freeze({ valid: true, failureCode: null });
  } catch (error) {
    return Object.freeze({ valid: false, failureCode: poolFailureCodeOf(error) });
  }
}
