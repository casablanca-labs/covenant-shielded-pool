import { describe, expect, it } from "vitest";

import { APNT_POOL_FAILURE_V1 as F, APNT_POOL_V1_CURVE_ORDER, APNT_POOL_V1_MAX_MONEY_SATS, apntPoolSha256V1, APNT_POOL_V1_DOMAIN_TAGS } from "../src/apnt_pool_contract_v1.js";
import {
  deriveAPNTPoolNoteCommitmentV1, deriveAPNTPoolNullifierKeyCommitmentV1, deriveAPNTPoolNullifierV1, deriveAPNTPoolOwnerTagV1, deriveAPNTPoolRecoveryTagV1,
  deriveAPNTPoolCommitmentRandomnessV1, deriveAPNTPoolPacketDigestV1, openAPNTPoolPacketV1, sealAPNTPoolPacketV1,
} from "../src/apnt_pool_note_v1.js";
import { APNT_POOL_V1_ACTION_RECORD_OFFSETS as OFF } from "../src/apnt_pool_action_record_v1.js";
import { encodeAPNTPoolStatementV1, insertAPNTPoolStatementNullifiersV1 } from "../src/apnt_pool_statement_v1.js";
import {
  deriveAPNTPoolActionRecordV1,
  evaluateAPNTPoolActionV1,
  type APNTPoolActionWitnessV1,
} from "../src/apnt_pool_action_relation_v1.js";
import {
  asInputWitness, flip, hex, lab, makeInputNote, makeOutput, pointOf, scalarOf, sparseTree, unhex, vectors, witnessFromVector,
  type TestInputNote,
} from "./apnt_pool_v1_fixture.js";

const ref = vectors.reference;
const REL1 = ref.relation[0];
const REL2 = ref.relation[1];

type Action = { record: Uint8Array; witness: APNTPoolActionWitnessV1 };

function fromVector(rel: typeof REL1): Action {
  return { record: unhex(rel.record), witness: witnessFromVector(rel.witness) };
}
function derive(anchor32: Uint8Array, witness: APNTPoolActionWitnessV1, amounts: { deposit?: bigint; withdrawal?: bigint; fee?: bigint; wlock?: Uint8Array } = {}): Uint8Array {
  return deriveAPNTPoolActionRecordV1({
    anchor32, witness, depositSats: amounts.deposit ?? 0n, withdrawalSats: amounts.withdrawal ?? 0n, feeSats: amounts.fee ?? 2_000n,
    withdrawalLockHash32: amounts.wlock ?? new Uint8Array(32),
  });
}
const failureOf = (action: unknown) => evaluateAPNTPoolActionV1(action).failureCode;
/** Deep, mutable copy of a witness (Uint8Arrays copied). */
const clone = (w: APNTPoolActionWitnessV1): any => structuredClone(w);
const withRecordBytes = (record: Uint8Array, offset: number, bytes: Uint8Array) => { const out = record.slice(); out.set(bytes, offset); return out; };
const u64le = (v: bigint) => { const b = new Uint8Array(8); let x = v; for (let i = 0; i < 8; i += 1) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
/** A pad16 packet sealed by hand under any digest and any u64 value, with no range check, as a malicious prover could. */
const padPacket = (digest: Uint8Array, valueSats: bigint) => new Uint8Array([...u64le(valueSats).map((b, i) => b ^ digest[i]!), ...digest.subarray(8, 16)]);

/** Two real inputs in one tree, a payment and a change output (balanced, fee 2,000). */
function honestPair(prefix: string) {
  const in0 = makeInputNote(`${prefix}:in0`, 500_000n);
  const in1 = makeInputNote(`${prefix}:in1`, 250_000n);
  const tree = sparseTree([lab(`${prefix}:leaf:0`), in0.commitment32, lab(`${prefix}:leaf:2`), in1.commitment32]);
  const witness: APNTPoolActionWitnessV1 = {
    inputs: [asInputWitness(in0, tree.path(1)), asInputWitness(in1, tree.path(3))],
    outputs: [makeOutput(`${prefix}:out0`, 600_000n, in0.nullifier32), makeOutput(`${prefix}:out1`, 148_000n, in1.nullifier32)],
  };
  return { in0, in1, tree, witness, record: derive(tree.root, witness) };
}

describe("pool v1 host action relation: positives", () => {
  it("accepts both reference relation vectors (real/real with deposit and withdrawal; real/dummy with a dummy output)", () => {
    for (const rel of [REL1, REL2]) expect(evaluateAPNTPoolActionV1(fromVector(rel))).toEqual({ relationIdentity: "apnt-pool-action-host-rel-v1", valid: true, failureCode: null });
  });
  it("accepts a locally built honest action and returns only identity, validity and a code", () => {
    const { record, witness } = honestPair("pos");
    const result = evaluateAPNTPoolActionV1({ record, witness });
    expect(result).toEqual({ relationIdentity: "apnt-pool-action-host-rel-v1", valid: true, failureCode: null });
    expect(Object.keys(result).sort()).toEqual(["failureCode", "relationIdentity", "valid"]);
  });
  it("a dummy input (v = 0) needs no membership path and is otherwise checked in full", () => {
    const a = fromVector(REL2);
    expect(a.witness.inputs[1].valueSats).toBe(0n);
    expect(a.witness.inputs[1].membership).toBeNull();
    expect(failureOf(a)).toBeNull();
    const badKey = clone(a.witness); badKey.inputs[1].rerandomizer += 1n;
    expect(failureOf({ record: a.record, witness: badKey })).toBe(F.RERANDOMIZED_KEY);
    const badNk = clone(a.witness); badNk.inputs[1].nullifierKey32 = flip(badNk.inputs[1].nullifierKey32);
    expect(failureOf({ record: a.record, witness: badNk })).toBe(F.NULLIFIER);
    const badDummyPacket = withRecordBytes(a.record, OFF.packet1, flip(a.record.slice(OFF.packet1, OFF.packet1 + 16), 10));
    expect(failureOf({ record: badDummyPacket, witness: a.witness })).toBe(F.PACKET);
  });
});

describe("pool v1 host action relation: one named negative per requirement", () => {
  it("shape: a caller-supplied verdict field is refused (no caller acceptance)", () => {
    expect(failureOf({ ...fromVector(REL1), valid: true })).toBe(F.SHAPE);
  });

  it("witness: a witness carrying spend authority (ask or rsk) is refused", () => {
    const a = fromVector(REL1);
    for (const field of ["ask", "rsk"]) {
      const w = clone(a.witness); w.inputs[0][field] = lab("synthetic forbidden field");
      expect(failureOf({ record: a.record, witness: w })).toBe(F.WITNESS_SHAPE);
    }
  });

  it("record: 313 and 315 bytes, and revision 2's 396, are refused", () => {
    const a = fromVector(REL1);
    expect(a.record).toHaveLength(314);
    expect(failureOf({ record: a.record.subarray(0, 313), witness: a.witness })).toBe(F.RECORD_LENGTH);
    expect(failureOf({ record: new Uint8Array([...a.record, 0]), witness: a.witness })).toBe(F.RECORD_LENGTH);
    expect(failureOf({ record: new Uint8Array([...a.record, ...new Uint8Array(82)]), witness: a.witness })).toBe(F.RECORD_LENGTH);
  });

  it("record: a fee above MAX_MONEY that still fits u64 is refused", () => {
    const a = fromVector(REL1);
    expect(failureOf({ record: withRecordBytes(a.record, OFF.fee, u64le(APNT_POOL_V1_MAX_MONEY_SATS + 1n)), witness: a.witness })).toBe(F.RECORD_AMOUNT);
  });

  it("record: wlock_hash is zero if and only if withdrawal = 0", () => {
    const withdrawing = fromVector(REL1);
    expect(failureOf({ record: withRecordBytes(withdrawing.record, OFF.withdrawalLockHash, new Uint8Array(32)), witness: withdrawing.witness })).toBe(F.RECORD_WITHDRAWAL_LOCK);
    const notWithdrawing = fromVector(REL2);
    expect(failureOf({ record: withRecordBytes(notWithdrawing.record, OFF.withdrawalLockHash, lab("stray wlock")), witness: notWithdrawing.witness })).toBe(F.RECORD_WITHDRAWAL_LOCK);
  });

  it("record: an rk that is not a compressed point is refused", () => {
    const a = fromVector(REL1);
    const notAPoint = new Uint8Array(33); notAPoint[0] = 0x02; // x = 0 has no square root on secp256k1
    expect(failureOf({ record: withRecordBytes(a.record, OFF.rerandomizedKey0, notAPoint), witness: a.witness })).toBe(F.RECORD_KEY);
  });

  it("value range: a note value of MAX_MONEY + 1 is refused", () => {
    const a = fromVector(REL1);
    const w = clone(a.witness); w.outputs[1].valueSats = APNT_POOL_V1_MAX_MONEY_SATS + 1n;
    expect(failureOf({ record: a.record, witness: w })).toBe(F.VALUE_RANGE);
  });

  it("value range: an output of MAX_MONEY + 1 in a self-consistent record (its cm, packet and integer balance all hold) is refused", () => {
    const big = makeInputNote("range:big", APNT_POOL_V1_MAX_MONEY_SATS);
    const one = makeInputNote("range:one", 1n);
    const tree = sparseTree([big.commitment32, one.commitment32]);
    const out1 = makeOutput("range:out1", APNT_POOL_V1_MAX_MONEY_SATS + 1n, one.nullifier32);
    const witness: APNTPoolActionWitnessV1 = {
      inputs: [asInputWitness(big, tree.path(0)), asInputWitness(one, tree.path(1))],
      outputs: [makeOutput("range:out0", 0n, big.nullifier32), out1],
    };
    // Encoders refuse v > MAX_MONEY, so the record is derived at MAX_MONEY and output 1's cm and packet
    // are then rebuilt by hand over MAX_MONEY + 1, exactly as a malicious prover would.
    const inRange = derive(tree.root, { ...witness, outputs: [witness.outputs[0], { ...out1, valueSats: APNT_POOL_V1_MAX_MONEY_SATS }] }, { fee: 0n });
    const rcm1 = deriveAPNTPoolCommitmentRandomnessV1(out1.recoveryKey32, out1.rho32);
    const cm1 = apntPoolSha256V1(APNT_POOL_V1_DOMAIN_TAGS.commitment, u64le(out1.valueSats), out1.ownerTag32, out1.rho32, rcm1, deriveAPNTPoolRecoveryTagV1(out1.recoveryKey32));
    const packet1 = padPacket(deriveAPNTPoolPacketDigestV1(out1.recoveryKey32, out1.rho32, cm1), out1.valueSats);
    const record = withRecordBytes(withRecordBytes(inRange, OFF.commitment1, cm1), OFF.packet1, packet1);
    expect(big.valueSats + one.valueSats).toBe(0n + out1.valueSats); // balances over the integers
    expect(failureOf({ record, witness })).toBe(F.VALUE_RANGE);
  });

  it("field wrap-around: an output value that balances only modulo the proof field is refused by the range check", () => {
    const a = fromVector(REL1);
    const BN254_R = 21888242871839275222246405745257275088548364400416711303107332548332654657537n;
    const PALLAS_P = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001n;
    for (const p of [BN254_R, PALLAS_P]) {
      const w = clone(a.witness);
      // Output 0 claims 1,000,000 more than it may; output 1 carries p − 1,000,000, i.e. "−1,000,000" in the field.
      w.outputs[0].valueSats += 1_000_000n;
      w.outputs[1].valueSats = p - 1_000_000n + w.outputs[1].valueSats;
      const left: bigint = w.inputs[0].valueSats + w.inputs[1].valueSats + BigInt(REL1.depositSats);
      const right: bigint = w.outputs[0].valueSats + w.outputs[1].valueSats + BigInt(REL1.withdrawalSats) + BigInt(REL1.feeSats);
      expect(((left - right) % p + p) % p).toBe(0n); // balances in the field
      expect(left === right).toBe(false); // not over the integers
      expect(failureOf({ record: a.record, witness: w })).toBe(F.VALUE_RANGE);
    }
  });

  it("ownership: an ak that is not a curve point is refused", () => {
    const a = fromVector(REL1);
    const w = clone(a.witness); const bad = new Uint8Array(33); bad[0] = 0x03; w.inputs[0].spendKey33 = bad;
    expect(failureOf({ record: a.record, witness: w })).toBe(F.SPEND_KEY);
  });

  it("rk: α outside [0, n_G) is refused", () => {
    const a = fromVector(REL1);
    for (const alpha of [APNT_POOL_V1_CURVE_ORDER, -1n]) {
      const w = clone(a.witness); w.inputs[0].rerandomizer = alpha;
      expect(failureOf({ record: a.record, witness: w })).toBe(F.RERANDOMIZER);
    }
  });

  it("rk: α = n_G − ask puts ak + α·G at infinity and is refused", () => {
    const ask = scalarOf("infinity:ask");
    const w = clone(fromVector(REL1).witness); w.inputs[0].spendKey33 = pointOf(ask); w.inputs[0].rerandomizer = APNT_POOL_V1_CURVE_ORDER - ask;
    expect(failureOf({ record: unhex(REL1.record), witness: w })).toBe(F.RERANDOMIZED_KEY);
  });

  it("rk: the record's rk under the un-randomized ak, or under another α, is refused", () => {
    const a = fromVector(REL1);
    expect(failureOf({ record: withRecordBytes(a.record, OFF.rerandomizedKey0, a.witness.inputs[0].spendKey33), witness: a.witness })).toBe(F.RERANDOMIZED_KEY);
    const w = clone(a.witness); w.inputs[1].rerandomizer = (w.inputs[1].rerandomizer + 7n) % APNT_POOL_V1_CURVE_ORDER;
    expect(failureOf({ record: a.record, witness: w })).toBe(F.RERANDOMIZED_KEY);
  });

  it("nullifier: a record nullifier that is not the input's derived nf is refused", () => {
    const a = fromVector(REL1);
    expect(failureOf({ record: withRecordBytes(a.record, OFF.nullifier1, flip(a.record.slice(OFF.nullifier1, OFF.nullifier1 + 32), 31)), witness: a.witness })).toBe(F.NULLIFIER);
  });

  it("nullifier (ENG-329): a holder of a note's nkc and ak forms its owner tag and still cannot compute its nf; holding nk it can (firing control)", () => {
    const { record } = honestPair("nkc-holder");
    // Output 0 as its payer made it, and as the chain shows it.
    const v = 600_000n;
    const ak = pointOf(scalarOf("nkc-holder:out0:ask"));
    const nk = lab("nkc-holder:out0:nk");
    const nkc = deriveAPNTPoolNullifierKeyCommitmentV1(nk);
    const O = deriveAPNTPoolOwnerTagV1(ak, nk);
    expect(hex(apntPoolSha256V1(APNT_POOL_V1_DOMAIN_TAGS.owner, ak, nkc))).toBe(hex(O));
    const rho = record.slice(OFF.nullifier0, OFF.nullifier0 + 32);
    const cm = record.slice(OFF.commitment0, OFF.commitment0 + 32);
    const packet = record.slice(OFF.packet0, OFF.packet0 + 16);
    const K = lab("nkc-holder:out0:K");
    const rcm = deriveAPNTPoolCommitmentRandomnessV1(K, rho);
    const nf = deriveAPNTPoolNullifierV1(nk, rho, cm);
    // Every candidate for nk the holder can form: each 32-byte window of all it holds, and each held
    // 32-byte value hashed under every pool tag.
    const candidates = (held: Uint8Array[]) => {
      const all = new Uint8Array(held.reduce((n, b) => n + b.length, 0));
      held.reduce((at, b) => { all.set(b, at); return at + b.length; }, 0);
      const out: Uint8Array[] = [];
      for (let i = 0; i + 32 <= all.length; i += 1) out.push(all.slice(i, i + 32));
      for (const b of held.filter((x) => x.length === 32)) for (const tag of Object.values(APNT_POOL_V1_DOMAIN_TAGS)) out.push(apntPoolSha256V1(tag, b));
      return out;
    };
    const finds = (held: Uint8Array[]) => candidates(held).filter((c) => hex(deriveAPNTPoolNullifierV1(c, rho, cm)) === hex(nf)).length;
    const holds = [u64le(v), O, rho, rcm, deriveAPNTPoolRecoveryTagV1(K), K, cm, packet, nkc, ak];
    // 281 held bytes give 250 windows; seven held 32-byte values under sixteen tags give 112 hashes (ENG-527 added APNT-POOL-v1:dtag).
    expect(candidates(holds).length).toBe(250 + 7 * 16);
    expect(finds(holds)).toBe(0);
    expect(finds([...holds, nk])).toBeGreaterThan(0);
  });

  it("nullifier (ENG-329): the record a build that fed nkc into nf would accept is refused, under the true nk and with nkc presented as nk", () => {
    const { in0, in1, tree, witness } = honestPair("nkc-faulty");
    const nkc = [in0, in1].map((n) => deriveAPNTPoolNullifierKeyCommitmentV1(n.nullifierKey32));
    const faulty = [in0, in1].map((n, s) => deriveAPNTPoolNullifierV1(nkc[s], n.rho32, n.commitment32));
    const outputsOver = (rho0: Uint8Array, rho1: Uint8Array) => [makeOutput("nkc-faulty:out0", 600_000n, rho0), makeOutput("nkc-faulty:out1", 148_000n, rho1)] as const;
    const trueNk: APNTPoolActionWitnessV1 = { inputs: witness.inputs, outputs: outputsOver(faulty[0]!, faulty[1]!) };
    const record = withRecordBytes(withRecordBytes(derive(tree.root, trueNk), OFF.nullifier0, faulty[0]!), OFF.nullifier1, faulty[1]!);
    expect(failureOf({ record, witness: trueNk })).toBe(F.NULLIFIER);
    const nkcAsNk = clone(trueNk);
    nkcAsNk.inputs[0].nullifierKey32 = nkc[0];
    nkcAsNk.inputs[1].nullifierKey32 = nkc[1];
    expect(failureOf({ record, witness: nkcAsNk })).toBe(F.NULLIFIER);
    // Control: the same notes and output keys over the true nullifiers form a valid action.
    const control: APNTPoolActionWitnessV1 = { inputs: witness.inputs, outputs: outputsOver(in0.nullifier32, in1.nullifier32) };
    expect(failureOf({ record: derive(tree.root, control), witness: control })).toBeNull();
    for (const s of [0, 1]) expect(hex(faulty[s]!)).not.toBe(hex([in0, in1][s]!.nullifier32));
  });

  it("nullifier (ENG-329): nkc presented as nk in a record built from that witness names another owner tag, so the note is not in the tree", () => {
    const { in0, tree, witness } = honestPair("nkc-as-nk");
    const w = clone(witness);
    w.inputs[0].nullifierKey32 = deriveAPNTPoolNullifierKeyCommitmentV1(in0.nullifierKey32);
    const nf0 = deriveAPNTPoolNullifierV1(w.inputs[0].nullifierKey32, in0.rho32, deriveAPNTPoolNoteCommitmentV1({
      valueSats: in0.valueSats, ownerTag32: deriveAPNTPoolOwnerTagV1(in0.spendKey33, w.inputs[0].nullifierKey32), rho32: in0.rho32,
      commitmentRandomness32: in0.commitmentRandomness32, recoveryTag32: in0.recoveryTag32,
    }));
    w.outputs[0] = makeOutput("nkc-as-nk:out0", 600_000n, nf0);
    expect(failureOf({ record: derive(tree.root, w), witness: w })).toBe(F.MEMBERSHIP);
  });

  it("nullifier: one note in both input slots is refused", () => {
    const note = makeInputNote("both-slots", 400_000n);
    const tree = sparseTree([note.commitment32]);
    const witness: APNTPoolActionWitnessV1 = {
      inputs: [asInputWitness(note, tree.path(0)), { ...asInputWitness(note, tree.path(0)), rerandomizer: scalarOf("both-slots:alpha-2") }],
      outputs: [makeOutput("both-slots:out0", 400_000n, note.nullifier32), makeOutput("both-slots:out1", 398_000n, note.nullifier32)],
    };
    expect(failureOf({ record: derive(tree.root, witness), witness })).toBe(F.NULLIFIER_DUPLICATE);
  });

  it("membership: a nonzero-value input absent from the tree is refused, with or without a path", () => {
    const { in0, in1, tree, witness } = honestPair("absent");
    const outsider = makeInputNote("absent:outsider", 250_000n);
    const w: APNTPoolActionWitnessV1 = {
      inputs: [witness.inputs[0], asInputWitness(outsider, tree.path(3))],
      outputs: [witness.outputs[0], makeOutput("absent:out1", 148_000n, outsider.nullifier32)],
    };
    expect(failureOf({ record: derive(tree.root, w), witness: w })).toBe(F.MEMBERSHIP);
    const noPath = { ...w, inputs: [w.inputs[0], asInputWitness(outsider, null)] as const };
    expect(failureOf({ record: derive(tree.root, noPath), witness: noPath })).toBe(F.MEMBERSHIP);
    expect([in0.valueSats, in1.valueSats]).toEqual([500_000n, 250_000n]);
  });

  it("membership: a note in a self-built tree fails under an authentic anchor", () => {
    const { tree, witness } = honestPair("fabricated");
    const unbacked = makeInputNote("fabricated:unbacked", 9_000_000n);
    const selfBuilt = sparseTree([unbacked.commitment32]);
    const w: APNTPoolActionWitnessV1 = {
      inputs: [witness.inputs[0], asInputWitness(unbacked, selfBuilt.path(0))],
      outputs: [witness.outputs[0], makeOutput("fabricated:out1", 8_898_000n, unbacked.nullifier32)],
    };
    expect(failureOf({ record: derive(tree.root, w), witness: w })).toBe(F.MEMBERSHIP);
  });

  it("non-claim: the relation proves only the root a path reaches; anchor authenticity is the settlement covenant's check", () => {
    // A self-built tree holding an unbacked note satisfies the relation under its own root. Refusing that
    // anchor is check 3 of the pool settlement covenant (task 3.4, REV-129 H0-R2-1), not this relation.
    const unbacked = makeInputNote("self-anchor:unbacked", 9_000_000n);
    const dummy = makeInputNote("self-anchor:dummy", 0n);
    const selfBuilt = sparseTree([unbacked.commitment32]);
    const w: APNTPoolActionWitnessV1 = {
      inputs: [asInputWitness(unbacked, selfBuilt.path(0)), asInputWitness(dummy, null)],
      outputs: [makeOutput("self-anchor:out0", 8_998_000n, unbacked.nullifier32), makeOutput("self-anchor:out1", 0n, dummy.nullifier32)],
    };
    expect(failureOf({ record: derive(selfBuilt.root, w), witness: w })).toBeNull();
  });

  it("ρ index rule: faerie gold inside one action (both outputs take nf_in_0, equal leaves) is refused", () => {
    const { tree, witness, in0 } = honestPair("faerie");
    const twin = makeOutput("faerie:twin", 374_000n, in0.nullifier32);
    const w: APNTPoolActionWitnessV1 = { inputs: witness.inputs, outputs: [twin, twin] };
    const record = derive(tree.root, w);
    expect(hex(record.slice(OFF.commitment0, OFF.commitment0 + 32))).toBe(hex(record.slice(OFF.commitment1, OFF.commitment1 + 32)));
    expect(failureOf({ record, witness: w })).toBe(F.RHO_INDEX);
    // The same record in a statement is refused a second time, for its repeated commitment.
    expect(() => encodeAPNTPoolStatementV1({ deploymentId32: lab("dep"), profileId32: lab("prof"), records: [record] })).toThrow(F.STATEMENT_DUPLICATE_COMMITMENT);
  });

  it("ρ index rule: swapped ρ (output 0 takes nf_in_1) is refused", () => {
    const { tree, witness, in0, in1 } = honestPair("swap");
    const w: APNTPoolActionWitnessV1 = {
      inputs: witness.inputs,
      outputs: [makeOutput("swap:out0", 600_000n, in1.nullifier32), makeOutput("swap:out1", 148_000n, in0.nullifier32)],
    };
    expect(failureOf({ record: derive(tree.root, w), witness: w })).toBe(F.RHO_INDEX);
  });

  it("output commitment: a record cm that is not the output's commitment is refused", () => {
    const a = fromVector(REL1);
    expect(failureOf({ record: withRecordBytes(a.record, OFF.commitment0, flip(a.record.slice(OFF.commitment0, OFF.commitment0 + 32), 17)), witness: a.witness })).toBe(F.OUTPUT_COMMITMENT);
  });

  it("output commitment (pad16): a record cm over an rcm not derived from the output's own K and ρ is refused, even with a packet that matches it", () => {
    const a = fromVector(REL1);
    const out = a.witness.outputs[0];
    const tag = deriveAPNTPoolRecoveryTagV1(out.recoveryKey32);
    const cmOver = (rcm: Uint8Array) => apntPoolSha256V1(APNT_POOL_V1_DOMAIN_TAGS.commitment, u64le(out.valueSats), out.ownerTag32, out.rho32, rcm, tag);
    const otherK = lab("rcm-derivation:other-K");
    for (const rcm of [
      lab("rcm-derivation:payer-chosen"), // a payer-chosen rcm, as before pad16
      apntPoolSha256V1(APNT_POOL_V1_DOMAIN_TAGS.commitmentRandomness, out.recoveryKey32), // ρ left out
      deriveAPNTPoolCommitmentRandomnessV1(otherK, out.rho32), // under another K
      deriveAPNTPoolCommitmentRandomnessV1(out.recoveryKey32, a.witness.outputs[1].rho32), // over the other slot's ρ
    ]) {
      const cm = cmOver(rcm);
      const packet = sealAPNTPoolPacketV1({ recoveryKey32: out.recoveryKey32, rho32: out.rho32, commitment32: cm, valueSats: out.valueSats });
      expect(failureOf({ record: withRecordBytes(withRecordBytes(a.record, OFF.commitment0, cm), OFF.packet0, packet), witness: a.witness })).toBe(F.OUTPUT_COMMITMENT);
    }
    // Control: the derived rcm rebuilds the record's own cm.
    expect(hex(cmOver(deriveAPNTPoolCommitmentRandomnessV1(out.recoveryKey32, out.rho32)))).toBe(hex(a.record.slice(OFF.commitment0, OFF.commitment0 + 32)));
  });

  it("packet: a flipped padded-value or key-check bit, a packet under the digest without cm, for another value, or for the other output is refused", () => {
    const a = fromVector(REL1);
    for (const index of [3, 12]) {
      expect(failureOf({ record: withRecordBytes(a.record, OFF.packet0, flip(a.record.slice(OFF.packet0, OFF.packet0 + 16), index)), witness: a.witness })).toBe(F.PACKET);
    }
    const out = a.witness.outputs[0];
    const cm = a.record.slice(OFF.commitment0, OFF.commitment0 + 32);
    const faultyPacket = padPacket(apntPoolSha256V1(APNT_POOL_V1_DOMAIN_TAGS.packetDigest, out.recoveryKey32, out.rho32), out.valueSats);
    expect(faultyPacket).toHaveLength(16);
    expect(failureOf({ record: withRecordBytes(a.record, OFF.packet0, faultyPacket), witness: a.witness })).toBe(F.PACKET);
    const digest = deriveAPNTPoolPacketDigestV1(out.recoveryKey32, out.rho32, cm);
    for (const v of [out.valueSats + 1n, 0n]) {
      expect(failureOf({ record: withRecordBytes(a.record, OFF.packet0, padPacket(digest, v)), witness: a.witness })).toBe(F.PACKET);
    }
    expect(failureOf({ record: withRecordBytes(a.record, OFF.packet0, a.record.slice(OFF.packet1, OFF.packet1 + 16)), witness: a.witness })).toBe(F.PACKET);
    // Control: the hand-built packet over the true value is the record's own.
    expect(hex(padPacket(digest, out.valueSats))).toBe(hex(a.record.slice(OFF.packet0, OFF.packet0 + 16)));
  });

  it("balance: off by one in the fee or the deposit is refused", () => {
    const a = fromVector(REL1);
    expect(failureOf({ record: withRecordBytes(a.record, OFF.fee, u64le(BigInt(REL1.feeSats) + 1n)), witness: a.witness })).toBe(F.BALANCE);
    expect(failureOf({ record: withRecordBytes(a.record, OFF.deposit, u64le(BigInt(REL1.depositSats) - 1n)), witness: a.witness })).toBe(F.BALANCE);
  });

  it("balance: a withdrawal that the notes do not cover is refused", () => {
    const { tree, witness } = honestPair("overdraw");
    const record = derive(tree.root, witness, { withdrawal: 1n, wlock: lab("overdraw:wlock") });
    expect(failureOf({ record, witness })).toBe(F.BALANCE);
  });
});

describe("pool v1 successive actions (host level)", () => {
  /** The note an output creates, as its owner rebuilds it from the chain and its own keys. */
  function spendableNote(prefix: string, valueSats: bigint, rho32: Uint8Array): TestInputNote {
    const spendKey33 = pointOf(scalarOf(`${prefix}:ask`));
    const nullifierKey32 = lab(`${prefix}:nk`);
    // The owner rebuilds rcm from its K and the note's public ρ (pad16): nothing per note is stored or sent.
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

  it("32 chained actions: every created note opens from its packet and is spendable by its owner; nullifiers and leaves never repeat", () => {
    const deployment = lab("chain:deployment");
    let inserted: ReadonlySet<string> = new Set();
    const leaves = new Set<string>();
    let wallet: [TestInputNote, TestInputNote] = [makeInputNote("chain:genesis:0", 1_000_000n), makeInputNote("chain:genesis:1", 1_000_000n)];
    const fee = 1_000n;
    for (let k = 0; k < 32; k += 1) {
      const withDummy = k % 3 === 2;
      const [w0, w1] = wallet;
      const in1 = withDummy ? makeInputNote(`chain:${k}:dummy-in`, 0n) : w1;
      const tree = sparseTree(withDummy ? [w0.commitment32] : [w0.commitment32, w1.commitment32]);
      const total = w0.valueSats + in1.valueSats - fee;
      const values = withDummy ? [total, 0n] : [total / 3n, total - total / 3n];
      const prefixes = [`chain:${k}:out0`, withDummy ? `chain:${k}:dummy-out` : `chain:${k}:out1`];
      const witness: APNTPoolActionWitnessV1 = {
        inputs: [asInputWitness(w0, tree.path(0)), asInputWitness(in1, withDummy ? null : tree.path(1))],
        outputs: [makeOutput(prefixes[0]!, values[0]!, w0.nullifier32), makeOutput(prefixes[1]!, values[1]!, in1.nullifier32)],
      };
      const record = derive(tree.root, witness, { fee });
      expect(failureOf({ record, witness })).toBeNull();
      const settled = insertAPNTPoolStatementNullifiersV1(inserted, encodeAPNTPoolStatementV1({ deploymentId32: deployment, profileId32: lab("chain:profile"), records: [record] }), deployment);
      expect(settled.failureCode).toBeNull();
      inserted = settled.inserted!;
      const created = [0, 1].map((j) => {
        const cm = record.subarray(OFF.commitment0 + 32 * j, OFF.commitment0 + 32 * (j + 1));
        const rho = record.subarray(OFF.nullifier0 + 32 * j, OFF.nullifier0 + 32 * (j + 1));
        const packet = record.subarray(OFF.packet0 + 16 * j, OFF.packet0 + 16 * (j + 1));
        const prefix = prefixes[j]!;
        const opened = openAPNTPoolPacketV1({ recoveryKey32: lab(`${prefix}:K`), ownerTag32: witness.outputs[j]!.ownerTag32, rho32: rho, commitment32: cm, packet16: packet });
        expect(opened?.valueSats).toBe(values[j]);
        const note = spendableNote(prefix, opened!.valueSats, rho);
        expect(hex(note.commitmentRandomness32)).toBe(hex(opened!.commitmentRandomness32));
        expect(hex(note.commitment32)).toBe(hex(cm));
        expect(leaves.has(hex(cm))).toBe(false);
        leaves.add(hex(cm));
        return note;
      });
      wallet = withDummy ? [created[0]!, w1] : [created[0]!, created[1]!];
    }
    expect(inserted.size).toBe(64);
    expect(leaves.size).toBe(64);
    expect(wallet[0].valueSats + wallet[1].valueSats).toBe(2_000_000n - 32n * fee);
  });
});
