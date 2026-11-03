import {prepareActionAudit,bindActionAudit,preparePublicInputBinding} from "./public-apnt-pool-v1-origin-audit.js";
import {publicU64,replacePublicBytes,clonePublic,restoreHex,restorePublicWitness,markPublicRecord,encodePublicWitness,bindHex} from "./public-apnt-pool-v1-origin.js";
import { encodeAPNTPoolActionWitnessJsonV1 } from "../src/apnt_pool_action_witness_json_v1.js";
import { createHash } from "node:crypto";
import {
  APNT_POOL_FAILURE_V1 as F,
  APNT_POOL_V1_CURVE_ORDER,
  APNT_POOL_V1_DOMAIN_TAGS,
  APNT_POOL_V1_MAX_MONEY_SATS,
  apntPoolSha256V1,
} from "../src/apnt_pool_contract_v1.js";
import {
  deriveAPNTPoolCommitmentRandomnessV1,
  deriveAPNTPoolNoteCommitmentV1,
  deriveAPNTPoolNullifierKeyCommitmentV1,
  deriveAPNTPoolNullifierV1,
  deriveAPNTPoolOwnerTagV1,
  deriveAPNTPoolPacketDigestV1,
  deriveAPNTPoolRecoveryTagV1,
  sealAPNTPoolPacketV1,
} from "../src/apnt_pool_note_v1.js";
import { APNT_POOL_V1_ACTION_RECORD_OFFSETS as OFF } from "../src/apnt_pool_action_record_v1.js";
import { apntPoolMembershipRootV1 } from "../src/apnt_pool_tree_v1.js";
import {
  deriveAPNTPoolActionRecordV1,
  evaluateAPNTPoolActionV1,
  type APNTPoolActionWitnessV1,
  type APNTPoolInputWitnessV1,
  type APNTPoolOutputWitnessV1,
} from "../src/apnt_pool_action_relation_v1.js";
import { APNT_POOL_V1_PROOF_SYSTEM_IDS, deriveAPNTPoolProfileIdV1 } from "../src/apnt_pool_statement_v1.js";
import {
  asInputWitness, flip, hex, lab, makeInputNote, makeOutput, pointOf, scalarOf, sparseTree, unhex, witnessFromVector,
  type TestInputNote,
} from "./public-apnt-pool-v1-recipe.js";

// Pure case constructors extracted from the pinned consumer; no fixture reads or test initializers.
export const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export const HOST_TEST_BN254_R_CONSTANT = 21888242871839275222246405745257275088548364400416711303107332548332654657537n;

export const PALLAS_P = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001n;

export type Action = { record: Uint8Array; witness: APNTPoolActionWitnessV1 };

export type Amounts = { deposit?: bigint; withdrawal?: bigint; fee?: bigint; wlock?: Uint8Array };

export const u64le = publicU64;

export const withBytes = replacePublicBytes;

export const clone = (w: APNTPoolActionWitnessV1): any => clonePublic(w);

export const fromVector = (rel: any): Action => ({ record: restoreHex(rel,["record"]), witness: restorePublicWitness(witnessFromVector(rel.witness),rel.witness) });

export function derive(anchor32: Uint8Array, witness: APNTPoolActionWitnessV1, amounts: Amounts = {}): Uint8Array {
  return markPublicRecord(deriveAPNTPoolActionRecordV1({
    anchor32, witness, depositSats: amounts.deposit ?? 0n, withdrawalSats: amounts.withdrawal ?? 0n, feeSats: amounts.fee ?? 2_000n,
    withdrawalLockHash32: amounts.wlock ?? new Uint8Array(32),
  }), amounts);
}

export function rawPacket(digest: Uint8Array, valueSats: bigint): Uint8Array {
  return new Uint8Array([...u64le(valueSats).map((b, i) => b ^ digest[i]!), ...digest.slice(8, 16)]);
}

export const retiredTagSha256 = (tag: string, ...parts: Uint8Array[]) => {
  const h = createHash("sha256").update(tag);
  for (const part of parts) h.update(part);
  return new Uint8Array(h.digest());
};

export const cmOf = (record: Uint8Array, j: number) => record.slice(OFF.commitment0 + 32 * j, OFF.commitment0 + 32 * (j + 1));

export const packetOf = (record: Uint8Array, j: number) => record.slice(OFF.packet0 + 16 * j, OFF.packet0 + 16 * (j + 1));

export function honestPair(prefix: string) {
  const in0 = makeInputNote(`${prefix}:in0`, 500_000n);
  const in1 = makeInputNote(`${prefix}:in1`, 250_000n);
  const tree = sparseTree([lab(`${prefix}:leaf:0`), in0.commitment32, lab(`${prefix}:leaf:2`), in1.commitment32]);
  const witness: APNTPoolActionWitnessV1 = {
    inputs: [asInputWitness(in0, tree.path(1)), asInputWitness(in1, tree.path(3))],
    outputs: [makeOutput(`${prefix}:out0`, 600_000n, in0.nullifier32), makeOutput(`${prefix}:out1`, 148_000n, in1.nullifier32)],
  };
  return { in0, in1, tree, witness, record: derive(tree.root, witness) };
}

export function realAndDummy(prefix: string, value: bigint, outputs: (in0: TestInputNote, dummy: TestInputNote) => [APNTPoolOutputWitnessV1, APNTPoolOutputWitnessV1], amounts: Amounts = {}) {
  const in0 = makeInputNote(`${prefix}:in0`, value);
  const dummy = makeInputNote(`${prefix}:dummy`, 0n);
  const tree = sparseTree([in0.commitment32]);
  const witness: APNTPoolActionWitnessV1 = { inputs: [asInputWitness(in0, tree.path(0)), asInputWitness(dummy, null)], outputs: outputs(in0, dummy) };
  return { in0, dummy, tree, witness, record: derive(tree.root, witness, amounts) };
}

export function spendableNote(prefix: string, valueSats: bigint, rho32: Uint8Array): TestInputNote {
  const spendKey33 = pointOf(scalarOf(`${prefix}:ask`));
  const nullifierKey32 = lab(`${prefix}:nk`);
  const commitmentRandomness32 = deriveAPNTPoolCommitmentRandomnessV1(lab(`${prefix}:K`), rho32);
  const recoveryTag32 = deriveAPNTPoolRecoveryTagV1(lab(`${prefix}:K`));
  const commitment32 = deriveAPNTPoolNoteCommitmentV1({
    valueSats, ownerTag32: deriveAPNTPoolOwnerTagV1(spendKey33, nullifierKey32), rho32, commitmentRandomness32, recoveryTag32,
  });
  return {
    valueSats, spendKey33, nullifierKey32, rho32, commitmentRandomness32, recoveryTag32, rerandomizer: scalarOf(`${prefix}:alpha`),
    membership: null, commitment32, nullifier32: deriveAPNTPoolNullifierV1(nullifierKey32, rho32, commitment32),
  };
}

export type Entry = {
  name: string;
  kind: "positive" | "negative";
  hostFailureCode: string | null;
  representable: boolean;
  note: string;
  record: string | null;
  witness: unknown;
};

export function entry(kind: Entry["kind"], name: string, note: string, action: Action): Entry {
  const proof = prepareActionAudit(action.witness);
  const inputBinding = preparePublicInputBinding(action.witness);
  const verdict = evaluateAPNTPoolActionV1(action);
  const result = {
    name, kind, hostFailureCode: verdict.failureCode, representable: true, note,
    record: hex(action.record),
    witness: encodePublicWitness(action.witness),
  };
  bindHex(result,["record"],action.record);bindActionAudit(result,name,proof,inputBinding);return result;
}

export function structural(name: string, hostFailureCode: string, note: string): Entry {
  return { name, kind: "negative", hostFailureCode, representable: false, note, record: null, witness: null };
}
