import { type Bytes32 } from "./bytes.js";
import {
  APNT_POOL_ACTION_RELATION_V1_IDENTITY,
  APNT_POOL_FAILURE_V1 as F,
  APNT_POOL_V1_POINT_BYTES,
  pool32,
  poolBoundary,
  poolBytes,
  poolEqual,
  poolFailureCodeOf,
  poolMoney,
  poolPair,
  poolRecord,
  poolRequire,
  type APNTPoolFailureV1,
} from "./apnt_pool_contract_v1.js";
import {
  assertAPNTPoolSpendKeyV1,
  deriveAPNTPoolCommitmentRandomnessV1,
  deriveAPNTPoolNoteCommitmentV1,
  deriveAPNTPoolNullifierV1,
  deriveAPNTPoolOwnerTagV1,
  deriveAPNTPoolRecoveryTagV1,
  deriveAPNTPoolRerandomizedKeyV1,
  sealAPNTPoolPacketV1,
} from "./apnt_pool_note_v1.js";
import { apntPoolMembershipRootV1, normalizeAPNTPoolMembershipPathV1, type APNTPoolMembershipPathV1 } from "./apnt_pool_tree_v1.js";
import { decodeAPNTPoolActionRecordV1, encodeAPNTPoolActionRecordV1 } from "./apnt_pool_action_record_v1.js";

/**
 * APNT shielded pool v1: the deterministic host action relation (task 2.1,
 * 2.2). design.md, "Actions", items 1–7; spec `apnt-pool-note-statement`.
 *
 * One fixed-shape action, 2 inputs and 2 outputs, evaluated by itself with its
 * 314-byte record `A` as the only public input. It holds when, for its
 * private witness:
 *
 * 1. every note value, and the record's deposit, withdrawal and fee, lies in
 *    `[0, MAX_MONEY]` — this is what stops a field wrap-around from minting;
 * 2. for each input slot `s`, `ak_s` is a valid point (never infinity),
 *    `α_s ∈ [0, n_G)`, `R = ak_s + α_s·G` is not infinity and `SEC1c(R)` is the
 *    record's `rk_s`;
 * 3. each input's `nf` is `SHA-256(nf tag ‖ nk ‖ ρ ‖ cm)` over its commitment
 *    under its owner tag `O = SHA-256(owner tag ‖ SEC1c(ak) ‖ nkc)`, where
 *    `nkc = SHA-256(nkc tag ‖ nk)` of the same `nk`, and equals the record's
 *    `nf_s`;
 * 4. the two input nullifiers differ (so one note cannot fill both slots);
 * 5. every input with `v ≠ 0` has a depth-32 path to the record's `anchor`;
 *    an input with `v = 0` is exempt, and only such an input (dummy
 *    semantics). The anchor is proved only as the root the path reaches;
 *    whether it is authentic is the settlement covenant's check;
 * 6. output `j` takes `ρ_out_j = nf_in_j` (the index rule, anti faerie gold);
 * 7. each output's commitment is the record's `cm_j`, with its `rcm` derived
 *    as `SHA-256(rcm tag ‖ K ‖ ρ_out_j)` from the same `K` and `ρ` the recovery
 *    tag and the packet read (HUM-84; the witness carries no output `rcm`);
 * 8. each output's 16-byte packet is `(u64le(v) ⊕ d[0..8)) ‖ d[8..16)` with
 *    `d = SHA-256(pad tag ‖ K ‖ ρ_out_j ‖ cm_j)`;
 * 9. `Σ v_in + deposit = Σ v_out + withdrawal + fee` over the integers.
 *
 * Dummy slots are complete notes of value zero and pass every check but the
 * membership exemption; the relation cannot tell them from real slots and
 * does not try to. No requirement constrains two actions jointly: cross-action
 * uniqueness of nullifiers, and hence of `ρ`, is the settlement's insertion
 * (`insertAPNTPoolStatementNullifiersV1`).
 *
 * The witness carries `ak`, `nk` and `α`, never `ask` or `rsk`: a delegate
 * holding the whole witness can prove and still cannot sign. Owner signatures
 * are outside the relation (design.md, "Authorization"); the settlement
 * covenant checks them (task 3.4).
 *
 * The result is closed and public-safe: identity, validity and a stable
 * failure code, never a value or a witness byte.
 */

export type APNTPoolInputWitnessV1 = Readonly<{
  valueSats: bigint;
  /** `ak`, 33-byte SEC1c. */
  spendKey33: Uint8Array;
  /** `nk`. */
  nullifierKey32: Uint8Array;
  /** `ρ` of the input note. */
  rho32: Uint8Array;
  /** `rcm`. */
  commitmentRandomness32: Uint8Array;
  /** The input note's `tag = SHA-256(rt tag ‖ K)`. */
  recoveryTag32: Uint8Array;
  /** `α`, in `[0, n_G)`. */
  rerandomizer: bigint;
  /** Required when `valueSats ≠ 0`; ignored (and may be null) when it is 0. */
  membership: APNTPoolMembershipPathV1 | null;
}>;

export type APNTPoolOutputWitnessV1 = Readonly<{
  valueSats: bigint;
  /** The recipient's owner tag `O`: all a payer learns of the owner. */
  ownerTag32: Uint8Array;
  /** Must equal the nullifier of the input in the same slot index. */
  rho32: Uint8Array;
  /** The recipient's `K`. The output's `rcm` is derived from it and `ρ`; there is no `rcm` field. */
  recoveryKey32: Uint8Array;
}>;

export type APNTPoolActionWitnessV1 = Readonly<{
  inputs: readonly [APNTPoolInputWitnessV1, APNTPoolInputWitnessV1];
  outputs: readonly [APNTPoolOutputWitnessV1, APNTPoolOutputWitnessV1];
}>;

export type APNTPoolActionResultV1 = Readonly<{
  relationIdentity: typeof APNT_POOL_ACTION_RELATION_V1_IDENTITY;
  valid: boolean;
  failureCode: APNTPoolFailureV1 | null;
}>;

const INPUT_KEYS = [
  "valueSats", "spendKey33", "nullifierKey32", "rho32", "commitmentRandomness32", "recoveryTag32", "rerandomizer", "membership",
] as const;
const OUTPUT_KEYS = ["valueSats", "ownerTag32", "rho32", "recoveryKey32"] as const;

function normalizeInput(value: unknown): APNTPoolInputWitnessV1 {
  const w = poolRecord(value, INPUT_KEYS, F.WITNESS_SHAPE);
  poolRequire(typeof w.valueSats === "bigint" && typeof w.rerandomizer === "bigint", F.WITNESS_SHAPE);
  return Object.freeze({
    valueSats: w.valueSats,
    spendKey33: poolBytes(w.spendKey33, APNT_POOL_V1_POINT_BYTES, F.WITNESS_SHAPE),
    nullifierKey32: pool32(w.nullifierKey32, F.WITNESS_SHAPE),
    rho32: pool32(w.rho32, F.WITNESS_SHAPE),
    commitmentRandomness32: pool32(w.commitmentRandomness32, F.WITNESS_SHAPE),
    recoveryTag32: pool32(w.recoveryTag32, F.WITNESS_SHAPE),
    rerandomizer: w.rerandomizer,
    membership: w.membership === null ? null : normalizeAPNTPoolMembershipPathV1(w.membership),
  });
}

function normalizeOutput(value: unknown): APNTPoolOutputWitnessV1 {
  const w = poolRecord(value, OUTPUT_KEYS, F.WITNESS_SHAPE);
  poolRequire(typeof w.valueSats === "bigint", F.WITNESS_SHAPE);
  return Object.freeze({
    valueSats: w.valueSats,
    ownerTag32: pool32(w.ownerTag32, F.WITNESS_SHAPE),
    rho32: pool32(w.rho32, F.WITNESS_SHAPE),
    recoveryKey32: pool32(w.recoveryKey32, F.WITNESS_SHAPE),
  });
}

export function normalizeAPNTPoolActionWitnessV1(value: unknown): APNTPoolActionWitnessV1 {
  [value] = poolBoundary([value]);
  const w = poolRecord(value, ["inputs", "outputs"], F.WITNESS_SHAPE);
  return Object.freeze({
    inputs: poolPair(w.inputs, F.WITNESS_SHAPE, normalizeInput),
    outputs: poolPair(w.outputs, F.WITNESS_SHAPE, normalizeOutput),
  });
}

function inputCommitment(input: APNTPoolInputWitnessV1): Bytes32 {
  return deriveAPNTPoolNoteCommitmentV1({
    valueSats: input.valueSats,
    ownerTag32: deriveAPNTPoolOwnerTagV1(input.spendKey33, input.nullifierKey32),
    rho32: input.rho32,
    commitmentRandomness32: input.commitmentRandomness32,
    recoveryTag32: input.recoveryTag32,
  });
}

/** An output's `cm`, over `rcm = SHA-256(rcm tag ‖ K ‖ ρ)` from its own `K` and `ρ`. */
function outputCommitment(output: APNTPoolOutputWitnessV1): Bytes32 {
  return deriveAPNTPoolNoteCommitmentV1({
    valueSats: output.valueSats,
    ownerTag32: output.ownerTag32,
    rho32: output.rho32,
    commitmentRandomness32: deriveAPNTPoolCommitmentRandomnessV1(output.recoveryKey32, output.rho32),
    recoveryTag32: deriveAPNTPoolRecoveryTagV1(output.recoveryKey32),
  });
}

function outputPacket(output: APNTPoolOutputWitnessV1, commitment32: Uint8Array): Uint8Array {
  return sealAPNTPoolPacketV1({
    recoveryKey32: output.recoveryKey32,
    rho32: output.rho32,
    commitment32,
    valueSats: output.valueSats,
  });
}

function checkAction(recordBytes: unknown, witnessValue: unknown): void {
  const record = decodeAPNTPoolActionRecordV1(recordBytes);
  const witness = normalizeAPNTPoolActionWitnessV1(witnessValue);
  const { inputs, outputs } = witness;

  // 1. Ranges, before any value is encoded or summed.
  for (const note of [...inputs, ...outputs]) poolMoney(note.valueSats, F.VALUE_RANGE);

  for (const s of [0, 1] as const) {
    const input = inputs[s];
    // 2. Ownership key, α range and re-randomized key.
    assertAPNTPoolSpendKeyV1(input.spendKey33);
    poolRequire(poolEqual(deriveAPNTPoolRerandomizedKeyV1(input.spendKey33, input.rerandomizer), record.rerandomizedKeys33[s]), F.RERANDOMIZED_KEY);
    // 3. Nullifier over the input's own commitment.
    const nf = deriveAPNTPoolNullifierV1(input.nullifierKey32, input.rho32, inputCommitment(input));
    poolRequire(poolEqual(nf, record.nullifiers32[s]), F.NULLIFIER);
  }

  // 4. Distinct input nullifiers.
  poolRequire(!poolEqual(record.nullifiers32[0], record.nullifiers32[1]), F.NULLIFIER_DUPLICATE);

  // 5. Membership if and only if v ≠ 0.
  for (const input of inputs) {
    if (input.valueSats === 0n) continue;
    poolRequire(input.membership !== null, F.MEMBERSHIP);
    poolRequire(poolEqual(apntPoolMembershipRootV1(inputCommitment(input), input.membership), record.anchor32), F.MEMBERSHIP);
  }

  for (const j of [0, 1] as const) {
    const output = outputs[j];
    // 6. The index rule: ρ_out_j = nf_in_j.
    poolRequire(poolEqual(output.rho32, record.nullifiers32[j]), F.RHO_INDEX);
    // 7. Output commitment, over the derived rcm.
    const cm = outputCommitment(output);
    poolRequire(poolEqual(cm, record.commitments32[j]), F.OUTPUT_COMMITMENT);
    // 8. Packet under the cm-bound digest.
    poolRequire(poolEqual(outputPacket(output, cm), record.packets16[j]), F.PACKET);
  }

  // 9. Exact balance over the integers. Each term is already in [0, MAX_MONEY].
  const left = inputs[0].valueSats + inputs[1].valueSats + record.depositSats;
  const right = outputs[0].valueSats + outputs[1].valueSats + record.withdrawalSats + record.feeSats;
  poolRequire(left === right, F.BALANCE);
}

/** Evaluates `{ record, witness }`. Refuses any other key, including a caller-supplied verdict. */
export function evaluateAPNTPoolActionV1(value: unknown): APNTPoolActionResultV1 {
  try {
    const [clone] = poolBoundary([value]);
    const input = poolRecord(clone, ["record", "witness"], F.SHAPE);
    checkAction(input.record, input.witness);
    return Object.freeze({ relationIdentity: APNT_POOL_ACTION_RELATION_V1_IDENTITY, valid: true, failureCode: null });
  } catch (error) {
    return Object.freeze({ relationIdentity: APNT_POOL_ACTION_RELATION_V1_IDENTITY, valid: false, failureCode: poolFailureCodeOf(error) });
  }
}

/**
 * Derives the public record a witness implies: `nf_s`, `rk_s`, `cm_j` and
 * `packet_j` exactly as the relation recomputes them, around the given
 * anchor, deposit, withdrawal, fee and `wlock_hash`. It checks only what
 * encoding needs (ranges, keys, the `wlock_hash` rule), not the relation:
 * run {@link evaluateAPNTPoolActionV1} for that. Nothing here takes a
 * signing key.
 */
export function deriveAPNTPoolActionRecordV1(value: unknown): Uint8Array {
  [value] = poolBoundary([value]);
  const input = poolRecord(value, ["anchor32", "witness", "depositSats", "withdrawalSats", "feeSats", "withdrawalLockHash32"], F.SHAPE);
  const witness = normalizeAPNTPoolActionWitnessV1(input.witness);
  for (const note of [...witness.inputs, ...witness.outputs]) poolMoney(note.valueSats, F.VALUE_RANGE);
  const nullifiers32 = witness.inputs.map((i) => deriveAPNTPoolNullifierV1(i.nullifierKey32, i.rho32, inputCommitment(i))) as [Bytes32, Bytes32];
  const rerandomizedKeys33 = witness.inputs.map((i) => deriveAPNTPoolRerandomizedKeyV1(i.spendKey33, i.rerandomizer)) as [Uint8Array, Uint8Array];
  const commitments32 = witness.outputs.map(outputCommitment) as [Bytes32, Bytes32];
  const packets16 = witness.outputs.map((o, j) => outputPacket(o, commitments32[j]!)) as [Uint8Array, Uint8Array];
  return encodeAPNTPoolActionRecordV1({
    anchor32: input.anchor32,
    nullifiers32,
    rerandomizedKeys33,
    commitments32,
    packets16,
    depositSats: input.depositSats,
    withdrawalSats: input.withdrawalSats,
    feeSats: input.feeSats,
    withdrawalLockHash32: input.withdrawalLockHash32,
  });
}
