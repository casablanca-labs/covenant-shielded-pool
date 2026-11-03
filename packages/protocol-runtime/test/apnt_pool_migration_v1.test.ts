import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  APNT_POOL_FAILURE_V1 as F,
  APNT_POOL_V1_DOMAIN_TAGS,
  APNT_POOL_V1_MAX_MONEY_SATS,
  APNTPoolHostErrorV1,
  apntPoolSha256V1,
} from "../src/apnt_pool_contract_v1.js";
import { decodeAPNTPoolActionRecordV1, encodeAPNTPoolActionRecordV1 } from "../src/apnt_pool_action_record_v1.js";
import { encodeAPNTPoolStatementV1 } from "../src/apnt_pool_statement_v1.js";
import { deriveAPNTPoolActionRecordV1, evaluateAPNTPoolActionV1, type APNTPoolActionWitnessV1 } from "../src/apnt_pool_action_relation_v1.js";
import {
  APNT_POOL_V1_MIGRATION_INBOX_PREIMAGE_BYTES,
  decodeAPNTPoolMigrationInboxPreimageV1,
  deriveAPNTPoolMigrationInboxHashV1,
  encodeAPNTPoolMigrationInboxPreimageV1,
  evaluateAPNTPoolMigrationInboxReleaseV1,
} from "../src/apnt_pool_migration_v1.js";
import { asInputWitness, flip, hex, isNonPalindromic, lab, makeInputNote, makeOutput, unhex, vectors } from "./apnt_pool_v1_fixture.js";

const fv: any = JSON.parse(readFileSync(new URL("../test-vectors/public-apnt-pool-v1-frontier-vectors.json", import.meta.url), "utf8"));
const inboxVectors = fv.reference.inbox;

const codeOf = (thunk: () => unknown): string | null => {
  try { thunk(); return null; } catch (error) { return error instanceof APNTPoolHostErrorV1 ? error.code : "non-pool-error"; }
};
const u64le = (n: bigint) => { const b = new Uint8Array(8); let x = n; for (let i = 0; i < 8; i += 1) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };

// Pool n+1 is the slice-1 reference deployment; pool n is another deployment.
const NEXT = unhex(vectors.reference.statement.deploymentId);
const PREVIOUS = lab("migration:pool-n deployment");
const PROF = unhex(vectors.reference.statement.profileId);
const OTHER_RECORD = unhex(vectors.reference.statement.recordsInput[1]);
const W = 1_234_567_890_123n;
const FEE = 2_000n;

/** The step-2 deposit action: two dummy inputs, deposit W, the migrated note in output `slot`, a dummy in the other. */
function stepTwo(tag: string, slot: 0 | 1 = 0, deposit = W): { record: Uint8Array; witness: APNTPoolActionWitnessV1 } {
  const dummies = [makeInputNote(`${tag}:dummy-in-0`, 0n), makeInputNote(`${tag}:dummy-in-1`, 0n)] as const;
  const values = slot === 0 ? [deposit - FEE, 0n] : [0n, deposit - FEE];
  const witness: APNTPoolActionWitnessV1 = {
    inputs: [asInputWitness(dummies[0], null), asInputWitness(dummies[1], null)],
    outputs: [makeOutput(`${tag}:out-0`, values[0]!, dummies[0].nullifier32), makeOutput(`${tag}:out-1`, values[1]!, dummies[1].nullifier32)],
  };
  const record = deriveAPNTPoolActionRecordV1({
    anchor32: lab(`${tag}:anchor`), witness, depositSats: deposit, withdrawalSats: 0n, feeSats: FEE, withdrawalLockHash32: new Uint8Array(32),
  });
  return { record, witness };
}
const fieldsOf = (record: Uint8Array) => decodeAPNTPoolActionRecordV1(record);
const preimageFor = (record: Uint8Array, slot: 0 | 1 = 0, amountSats = W, successorDeploymentId32 = NEXT) => encodeAPNTPoolMigrationInboxPreimageV1({
  successorDeploymentId32, commitment32: fieldsOf(record).commitments32[slot], packet16: fieldsOf(record).packets16[slot], amountSats,
});
const statementOf = (records: Uint8Array[], deploymentId32 = NEXT) => encodeAPNTPoolStatementV1({ deploymentId32, profileId32: PROF, records });
const release = (preimage104: Uint8Array, statement: Uint8Array, successorDeploymentId32 = NEXT) =>
  evaluateAPNTPoolMigrationInboxReleaseV1({ preimage104, successorDeploymentId32, statement });

describe("pool v1 migration inbox: preimage codec", () => {
  it("reference vectors: the 104-byte preimage and h, from the independent public reference construction", () => {
    for (const v of [inboxVectors.synthetic, inboxVectors.referenceRecord0]) {
      const preimage = encodeAPNTPoolMigrationInboxPreimageV1({
        successorDeploymentId32: unhex(v.successorDeploymentId), commitment32: unhex(v.commitment), packet16: unhex(v.packet), amountSats: BigInt(v.amountSats),
      });
      expect(preimage).toHaveLength(APNT_POOL_V1_MIGRATION_INBOX_PREIMAGE_BYTES);
      expect(hex(preimage)).toBe(v.preimage);
      expect(hex(deriveAPNTPoolMigrationInboxHashV1(preimage, unhex(v.successorDeploymentId)))).toBe(v.h);
    }
  });

  it("layout: deployment_id ‖ cm_new ‖ SHA-256(packet_new) ‖ u64le(W), W little-endian (non-palindromic), round trip", () => {
    const { record } = stepTwo("layout");
    const preimage = preimageFor(record);
    const f = fieldsOf(record);
    expect(hex(preimage)).toBe(hex(new Uint8Array([...NEXT, ...f.commitments32[0], ...apntPoolSha256V1(null, f.packets16[0]), ...u64le(W)])));
    expect(isNonPalindromic(preimage.subarray(96))).toBe(true);
    expect(hex(preimage.subarray(96))).not.toBe(hex(u64le(W).reverse()));
    const decoded = decodeAPNTPoolMigrationInboxPreimageV1(preimage, NEXT);
    expect([hex(decoded.successorDeploymentId32), hex(decoded.commitment32), hex(decoded.packetHash32), decoded.amountSats])
      .toEqual([hex(NEXT), hex(f.commitments32[0]), hex(apntPoolSha256V1(null, f.packets16[0])), W]);
    expect(hex(deriveAPNTPoolMigrationInboxHashV1(preimage, NEXT))).toBe(hex(apntPoolSha256V1(APNT_POOL_V1_DOMAIN_TAGS.migrationInbox, preimage)));
  });

  it("length: 103 or 105 bytes is refused", () => {
    const preimage = preimageFor(stepTwo("length").record);
    expect(codeOf(() => decodeAPNTPoolMigrationInboxPreimageV1(preimage.subarray(1), NEXT))).toBe(F.MIGRATION_LENGTH);
    expect(codeOf(() => decodeAPNTPoolMigrationInboxPreimageV1(new Uint8Array([...preimage, 0]), NEXT))).toBe(F.MIGRATION_LENGTH);
  });

  it("field deployment_id: a preimage naming another pool than the inbox's own is refused", () => {
    const preimage = preimageFor(stepTwo("deployment").record, 0, W, PREVIOUS);
    expect(codeOf(() => decodeAPNTPoolMigrationInboxPreimageV1(preimage, NEXT))).toBe(F.MIGRATION_DEPLOYMENT);
    expect(codeOf(() => encodeAPNTPoolMigrationInboxPreimageV1({ successorDeploymentId32: NEXT.subarray(1), commitment32: lab("c"), packet16: new Uint8Array(16), amountSats: W }))).toBe(F.MIGRATION_DEPLOYMENT);
  });

  it("field W: 0, or MAX_MONEY + 1 that still fits u64, is refused by the encoder and the decoder", () => {
    const preimage = preimageFor(stepTwo("amount").record);
    for (const amount of [0n, APNT_POOL_V1_MAX_MONEY_SATS + 1n]) {
      const bad = new Uint8Array([...preimage.subarray(0, 96), ...u64le(amount)]);
      expect(codeOf(() => decodeAPNTPoolMigrationInboxPreimageV1(bad, NEXT))).toBe(F.MIGRATION_AMOUNT);
      expect(codeOf(() => encodeAPNTPoolMigrationInboxPreimageV1({ successorDeploymentId32: NEXT, commitment32: lab("c"), packet16: new Uint8Array(16), amountSats: amount }))).toBe(F.MIGRATION_AMOUNT);
    }
    expect(decodeAPNTPoolMigrationInboxPreimageV1(new Uint8Array([...preimage.subarray(0, 96), ...u64le(APNT_POOL_V1_MAX_MONEY_SATS)]), NEXT).amountSats).toBe(APNT_POOL_V1_MAX_MONEY_SATS);
  });

  it("fields cm_new and packet: a 31-byte commitment or a 56-byte packet is refused by the encoder", () => {
    expect(codeOf(() => encodeAPNTPoolMigrationInboxPreimageV1({ successorDeploymentId32: NEXT, commitment32: lab("c").subarray(1), packet16: new Uint8Array(16), amountSats: W }))).toBe(F.MIGRATION_COMMITMENT);
    expect(codeOf(() => encodeAPNTPoolMigrationInboxPreimageV1({ successorDeploymentId32: NEXT, commitment32: lab("c"), packet16: new Uint8Array(15), amountSats: W }))).toBe(F.MIGRATION_PACKET);
  });
});

describe("pool v1 migration inbox: release into a pool-n+1 settlement (host model of task 3.6)", () => {
  it("positive: the step-2 deposit action is a valid action, and a statement carrying it releases the inbox", () => {
    const step = stepTwo("positive");
    expect(evaluateAPNTPoolActionV1(step).valid).toBe(true);
    expect(release(preimageFor(step.record), statementOf([step.record, OTHER_RECORD]))).toEqual({ valid: true, failureCode: null });
  });

  it("field cm_new: a statement without the committed note, or with it only as output 1, is refused (inbox diverted)", () => {
    const step = stepTwo("divert");
    const elsewhere = stepTwo("divert:other");
    expect(release(preimageFor(step.record), statementOf([elsewhere.record, OTHER_RECORD])).failureCode).toBe(F.MIGRATION_COMMITMENT);
    const slotOne = stepTwo("divert:slot-1", 1);
    expect(evaluateAPNTPoolActionV1(slotOne).valid).toBe(true);
    expect(release(preimageFor(slotOne.record, 1), statementOf([slotOne.record])).failureCode).toBe(F.MIGRATION_COMMITMENT);
  });

  it("field packet: a record carrying cm_new with another packet_0 is refused", () => {
    const step = stepTwo("packet");
    const fields = fieldsOf(step.record);
    const altered = encodeAPNTPoolActionRecordV1({ ...fields, packets16: [flip(fields.packets16[0], 10), fields.packets16[1]] });
    expect(release(preimageFor(step.record), statementOf([altered])).failureCode).toBe(F.MIGRATION_PACKET);
  });

  it("field W: a deposit of W − 1 or W + 1 against an inbox of W is refused", () => {
    for (const deposit of [W - 1n, W + 1n]) {
      const step = stepTwo(`amount:${deposit}`, 0, deposit);
      expect(evaluateAPNTPoolActionV1(step).valid).toBe(true);
      expect(release(preimageFor(step.record, 0, W), statementOf([step.record])).failureCode).toBe(F.MIGRATION_AMOUNT);
    }
  });

  it("field deployment_id: an inbox naming another pool, or a statement of another pool, is refused", () => {
    const step = stepTwo("deployment");
    expect(release(preimageFor(step.record, 0, W, PREVIOUS), statementOf([step.record])).failureCode).toBe(F.MIGRATION_DEPLOYMENT);
    expect(release(preimageFor(step.record), statementOf([step.record], PREVIOUS)).failureCode).toBe(F.STATEMENT_DEPLOYMENT);
  });

  it("the release reads only public bytes: the preimage, the successor's deployment_id and S", () => {
    const step = stepTwo("public");
    const extra = { preimage104: preimageFor(step.record), successorDeploymentId32: NEXT, statement: statementOf([step.record]), witness: step.witness };
    expect(evaluateAPNTPoolMigrationInboxReleaseV1(extra)).toEqual({ valid: false, failureCode: F.SHAPE });
  });
});
