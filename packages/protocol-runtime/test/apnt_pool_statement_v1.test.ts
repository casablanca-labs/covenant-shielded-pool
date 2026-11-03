import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";

import {
  APNT_POOL_FAILURE_V1 as F,
  APNT_POOL_V1_DOMAIN_TAGS,
  APNTPoolDigestSetV1,
  APNTPoolHostErrorV1,
  apntPoolSha256V1,
  poolCompareBytes,
} from "../src/apnt_pool_contract_v1.js";
import {
  deriveAPNTPoolCommitmentRandomnessV1,
  deriveAPNTPoolNoteCommitmentV1,
  deriveAPNTPoolOwnerTagV1,
  deriveAPNTPoolPacketDigestV1,
  deriveAPNTPoolRecoveryTagV1,
  detectAPNTPoolPacketV1,
  openAPNTPoolPacketV1,
  sealAPNTPoolPacketV1,
} from "../src/apnt_pool_note_v1.js";
import { deriveAPNTPoolActionAuthorizationDigestV1 } from "../src/apnt_pool_action_record_v1.js";
import {
  APNT_POOL_V1_PROOF_SYSTEM_IDS,
  APNT_POOL_V1_RESERVED_PROOF_SYSTEM_IDS,
  decodeAPNTPoolStatementV1,
  deriveAPNTPoolDeploymentIdV1,
  deriveAPNTPoolProfileIdV1,
  encodeAPNTPoolStatementV1,
  insertAPNTPoolStatementNullifiersV1,
} from "../src/apnt_pool_statement_v1.js";
import { deriveAPNTPoolActionRecordV1, evaluateAPNTPoolActionV1, type APNTPoolActionWitnessV1 } from "../src/apnt_pool_action_relation_v1.js";
import { asInputWitness, hex, lab, makeInputNote, makeOutput, pointOf, scalarOf, unhex, vectors } from "./apnt_pool_v1_fixture.js";

const ref = vectors.reference;
const DEP = unhex(ref.statement.deploymentId);
const PROF = unhex(ref.statement.profileId);
const RECORDS: Uint8Array[] = ref.statement.recordsInput.map(unhex);
const S = unhex(ref.statement.statement);

const codeOf = (thunk: () => unknown): string | null => {
  try { thunk(); return null; } catch (error) { return error instanceof APNTPoolHostErrorV1 ? error.code : "non-pool-error"; }
};
const u16le = (v: number) => Uint8Array.of(v & 0xff, v >> 8);
const header = (b: number) => new Uint8Array([...S.subarray(0, 86), ...u16le(b)]);

describe("pool v1 statement codec: named negatives", () => {
  it("S one byte longer or shorter is refused", () => {
    expect(codeOf(() => decodeAPNTPoolStatementV1(new Uint8Array([...S, 0x00]), DEP))).toBe(F.STATEMENT_LENGTH);
    expect(codeOf(() => decodeAPNTPoolStatementV1(S.subarray(0, S.length - 1), DEP))).toBe(F.STATEMENT_LENGTH);
    expect(codeOf(() => decodeAPNTPoolStatementV1(S, DEP))).toBeNull();
  });

  it("a u16le(B) that disagrees with the length is refused", () => {
    expect(codeOf(() => decodeAPNTPoolStatementV1(new Uint8Array([...header(1), ...S.subarray(88)]), DEP))).toBe(F.STATEMENT_LENGTH);
    expect(codeOf(() => decodeAPNTPoolStatementV1(new Uint8Array([...header(3), ...S.subarray(88)]), DEP))).toBe(F.STATEMENT_LENGTH);
  });

  it("a non-32-byte profile_id is refused by the encoder, and a statement framed with one is refused by the decoder", () => {
    for (const length of [31, 33]) {
      expect(codeOf(() => encodeAPNTPoolStatementV1({ deploymentId32: DEP, profileId32: new Uint8Array(length).fill(0x5a), records: RECORDS }))).toBe(F.STATEMENT_FIELD);
    }
    const prof33 = new Uint8Array([...PROF, 0x07]);
    const shifted = new Uint8Array([...S.subarray(0, 54), ...prof33, ...u16le(2), ...S.subarray(88)]);
    expect(shifted.length).toBe(S.length + 1);
    expect(codeOf(() => decodeAPNTPoolStatementV1(shifted, DEP))).toBe(F.STATEMENT_LENGTH);
  });

  it("a wrong tag, B = 0 and a foreign deployment_id are refused", () => {
    const badTag = S.slice(); badTag[21] = 0x53; // "…statemenS"
    expect(codeOf(() => decodeAPNTPoolStatementV1(badTag, DEP))).toBe(F.STATEMENT_TAG);
    expect(codeOf(() => decodeAPNTPoolStatementV1(header(0), DEP))).toBe(F.STATEMENT_COUNT);
    expect(codeOf(() => decodeAPNTPoolStatementV1(S, lab("foreign deployment")))).toBe(F.STATEMENT_DEPLOYMENT);
    expect(codeOf(() => encodeAPNTPoolStatementV1({ deploymentId32: DEP, profileId32: PROF, records: [] }))).toBe(F.STATEMENT_COUNT);
  });

  it("records out of ascending ad order, and equal records, are refused", () => {
    const reversed = new Uint8Array([...header(2), ...S.subarray(402), ...S.subarray(88, 402)]);
    expect(codeOf(() => decodeAPNTPoolStatementV1(reversed, DEP))).toBe(F.STATEMENT_ORDER);
    expect(codeOf(() => encodeAPNTPoolStatementV1({ deploymentId32: DEP, profileId32: PROF, records: [RECORDS[0]!, RECORDS[0]!] }))).toBe(F.STATEMENT_ORDER);
    const twice = new Uint8Array([...header(2), ...S.subarray(88, 402), ...S.subarray(88, 402)]);
    expect(codeOf(() => decodeAPNTPoolStatementV1(twice, DEP))).toBe(F.STATEMENT_ORDER);
  });

  it("ad order is byte-lexicographic, not little-endian: pinned on X1's pair, whose two orders disagree", () => {
    const x1 = vectors.overlap.x1;
    const originalDep = unhex(x1.deploymentId), prof = unhex(x1.profileId);
    const pair: Uint8Array[] = x1.statementB2.records.map(unhex);
    expect(pair.map(r => hex(deriveAPNTPoolActionAuthorizationDigestV1(originalDep, r)))).toEqual(x1.statementB2.ads);
    expect(hex(encodeAPNTPoolStatementV1({ deploymentId32: originalDep, profileId32: prof, records: pair }))).toBe(x1.statementB2.sortedStatement);
    // Keep the historical inventory title and frozen X1 records. Their public
    // reconstruction changed the old digest literals and no longer separates
    // the two orders. A fixed test deployment restores that adversarial premise.
    const dep = lab("statement-order-disagreement");
    const independentAd = (r: Uint8Array) => new Uint8Array(createHash("sha256")
      .update("APNT-POOL-v1:action-auth").update(dep).update(r).digest());
    const records = [...pair].sort((a, b) => poolCompareBytes(independentAd(a), independentAd(b)));
    const [a, b] = records.map((r) => deriveAPNTPoolActionAuthorizationDigestV1(dep, r));
    expect([hex(a!), hex(b!)]).toEqual(records.map(r => hex(independentAd(r))));
    const le = (x: Uint8Array) => BigInt("0x" + hex(x.slice().reverse()));
    expect(poolCompareBytes(a!, b!) < 0).toBe(true); // lexicographic: a first
    expect(le(a!) > le(b!)).toBe(true); // little-endian: b first
    const encoded = encodeAPNTPoolStatementV1({ deploymentId32: dep, profileId32: prof, records });
    expect(codeOf(() => decodeAPNTPoolStatementV1(encoded, dep))).toBeNull();
    expect(hex(encoded.subarray(88, 402))).toBe(hex(records[0]!));
    const littleEndianOrder = new Uint8Array([...encoded.subarray(0, 88), ...records[1]!, ...records[0]!]);
    expect(codeOf(() => decodeAPNTPoolStatementV1(littleEndianOrder, dep))).toBe(F.STATEMENT_ORDER);
  });
});

describe("pool v1 nullifier uniqueness across actions", () => {
  /** Action `k` reuses one dummy input note in slot 0 and pays identical fields to output 0. */
  function reusedDummyAction(k: number): { record: Uint8Array; witness: APNTPoolActionWitnessV1 } {
    const reused = makeInputNote("reused-dummy", 0n);
    const fresh = makeInputNote(`reused-dummy:fresh:${k}`, 0n);
    const witness: APNTPoolActionWitnessV1 = {
      inputs: [asInputWitness(reused, null), { ...asInputWitness(fresh, null), rerandomizer: scalarOf(`reused-dummy:alpha:${k}`) }],
      outputs: [makeOutput("reused-dummy:twin-out", 0n, reused.nullifier32), makeOutput(`reused-dummy:out1:${k}`, 0n, fresh.nullifier32)],
    };
    const record = deriveAPNTPoolActionRecordV1({
      anchor32: lab(`reused-dummy:anchor:${k}`), witness, depositSats: 2_000n, withdrawalSats: 0n, feeSats: 2_000n, withdrawalLockHash32: new Uint8Array(32),
    });
    return { record, witness };
  }
  const commitment0 = (record: Uint8Array) => hex(record.subarray(162, 194));

  it("a cross-action reused dummy: each action is valid alone, the second settlement's dummy nullifier is refused as replayed", () => {
    const [a1, a2] = [reusedDummyAction(1), reusedDummyAction(2)];
    expect(evaluateAPNTPoolActionV1(a1).valid).toBe(true);
    expect(evaluateAPNTPoolActionV1(a2).valid).toBe(true);
    expect(commitment0(a1.record)).toBe(commitment0(a2.record)); // identical leaves if both settled
    const S1 = encodeAPNTPoolStatementV1({ deploymentId32: DEP, profileId32: PROF, records: [a1.record] });
    const S2 = encodeAPNTPoolStatementV1({ deploymentId32: DEP, profileId32: PROF, records: [a2.record] });
    const first = insertAPNTPoolStatementNullifiersV1(new Set(), S1, DEP);
    expect(first.valid).toBe(true);
    expect(first.inserted?.size).toBe(2); // both nullifiers, the dummy one included
    expect(insertAPNTPoolStatementNullifiersV1(first.inserted!, S2, DEP)).toEqual({ valid: false, failureCode: F.NULLIFIER_REPLAYED, inserted: null });
  });

  it("firing control: a settlement model that leaves dummy nullifiers uninserted settles both and duplicates a leaf", () => {
    // The faulty model needs private knowledge of which slots are dummies; the real one cannot have it.
    const faultyInsert = (set: Set<string>, action: { record: Uint8Array; witness: APNTPoolActionWitnessV1 }) => {
      for (const s of [0, 1] as const) {
        if (action.witness.inputs[s].valueSats === 0n) continue;
        const nf = hex(action.record.subarray(32 + 32 * s, 64 + 32 * s));
        if (set.has(nf)) return false;
        set.add(nf);
      }
      return true;
    };
    const leaves: string[] = [];
    const set = new Set<string>();
    for (const action of [reusedDummyAction(1), reusedDummyAction(2)]) {
      expect(faultyInsert(set, action)).toBe(true);
      leaves.push(commitment0(action.record));
    }
    expect(new Set(leaves).size).toBe(1);
  });

  it("the same reused dummy twice in one statement is refused as a repeated nullifier", () => {
    const records = [reusedDummyAction(1).record, reusedDummyAction(2).record];
    expect(codeOf(() => encodeAPNTPoolStatementV1({ deploymentId32: DEP, profileId32: PROF, records }))).toBe(F.STATEMENT_DUPLICATE_NULLIFIER);
  });

  it("the insertion model never mutates its input set", () => {
    const unrelated = hex(lab("an unrelated inserted nullifier"));
    const before = new Set<string>([unrelated]);
    const result = insertAPNTPoolStatementNullifiersV1(before, S, DEP);
    expect(result.valid).toBe(true);
    expect(result.inserted?.size).toBe(5);
    expect([...before]).toEqual([unrelated]);
  });
});

describe("pool v1 nullifier insertion model: the set boundary (REV-133 H2)", () => {
  const nf = hex(RECORDS[0]!.subarray(32, 64)); // the first record's first nullifier, as REV-133's probe used
  const refusedAtBoundary = { valid: false, failureCode: F.DIGEST_SET_ENTRY, inserted: null };

  it("byte-level replay: the nullifier in canonical lowercase hex is refused as replayed", () => {
    expect(insertAPNTPoolStatementNullifiersV1(new Set([nf]), S, DEP)).toEqual({ valid: false, failureCode: F.NULLIFIER_REPLAYED, inserted: null });
  });

  it("uppercase-hex replay: the same nullifier in uppercase is refused at the boundary, not accepted", () => {
    expect(nf.toUpperCase()).not.toBe(nf); // the nullifier has hex letters, so the case control discriminates
    expect(insertAPNTPoolStatementNullifiersV1(new Set([nf.toUpperCase()]), S, DEP)).toEqual(refusedAtBoundary);
  });

  it("other noncanonical entries: mixed case, 63 or 65 digits, a 0x prefix, a non-hex digit, a number or bytes are refused", () => {
    const mixed = nf.replace(/[a-f]/, (c) => c.toUpperCase());
    for (const entry of [mixed, nf.slice(1), `${nf}0`, `0x${nf.slice(2)}`, `${nf.slice(1)}g`, 7, RECORDS[0]!.subarray(32, 64)]) {
      expect(insertAPNTPoolStatementNullifiersV1(new Set<any>([entry]), S, DEP)).toEqual(refusedAtBoundary);
    }
  });

  it("a set model that is not a Set (an array, a plain object, a Map) is refused", () => {
    for (const value of [[nf], { [nf]: true }, new Map([[nf, nf]])]) {
      expect(insertAPNTPoolStatementNullifiersV1(value as any, S, DEP)).toEqual(refusedAtBoundary);
    }
  });

  it("the result is immutable: it has no mutator, Set methods refuse it, and a replay after trying to clear it is still refused", () => {
    const first = insertAPNTPoolStatementNullifiersV1(new Set(), S, DEP);
    expect(first.valid).toBe(true);
    const inserted = first.inserted!;
    expect(inserted).toBeInstanceOf(APNTPoolDigestSetV1);
    expect(inserted).not.toBeInstanceOf(Set);
    for (const mutator of ["add", "delete", "clear"]) expect((inserted as any)[mutator]).toBeUndefined();
    expect(() => Set.prototype.clear.call(inserted as any)).toThrow(TypeError);
    expect(() => Set.prototype.add.call(inserted as any, "00")).toThrow(TypeError);
    expect(() => { (inserted as any).size = 0; }).toThrow(TypeError);
    expect(Object.isFrozen(inserted)).toBe(true);
    expect(inserted.size).toBe(4);
    expect(insertAPNTPoolStatementNullifiersV1(inserted, S, DEP)).toEqual({ valid: false, failureCode: F.NULLIFIER_REPLAYED, inserted: null });
  });

  it("a result chains into the next insertion unchanged, and iterates as lowercase hex", () => {
    const first = insertAPNTPoolStatementNullifiersV1(new Set(), S, DEP);
    expect([...first.inserted!].every((entry) => /^[0-9a-f]{64}$/.test(entry))).toBe(true);
    expect(first.inserted!.has(nf)).toBe(true);
    const seen: string[] = [];
    first.inserted!.forEach((value, key, set) => { expect(key).toBe(value); expect(set).toBe(first.inserted); seen.push(value); });
    expect(seen).toEqual([...first.inserted!.values()]);
  });
});

describe("pool v1 identifiers: named negatives", () => {
  it("profile_id: system id 0, an unlisted id, or non-byte vp is refused", () => {
    for (const systemId of [0, 4, 0x0102, 1.5]) expect(codeOf(() => deriveAPNTPoolProfileIdV1({ systemId, verifierParameters: new Uint8Array(4) }))).toBe(F.PROFILE_SYSTEM);
    expect(codeOf(() => deriveAPNTPoolProfileIdV1({ systemId: 1, verifierParameters: "vk" }))).toBe(F.PROFILE_PARAMETERS);
  });

  it("profile_id: system id 3, reserved for Binius64, is refused until its registry entry exists (ARCH-142)", () => {
    expect(Object.values(APNT_POOL_V1_PROOF_SYSTEM_IDS)).toEqual([1, 2]);
    expect(APNT_POOL_V1_RESERVED_PROOF_SYSTEM_IDS.binius64).toBe(3);
    for (const verifierParameters of [new Uint8Array(), lab("binius64 vp")]) {
      expect(codeOf(() => deriveAPNTPoolProfileIdV1({ systemId: 3, verifierParameters }))).toBe(F.PROFILE_SYSTEM);
    }
    // X10 (ENG-268) hashed (3, empty) as a preimage; that hash is not a profile id the host derives.
    const rawPreimageHash = apntPoolSha256V1(APNT_POOL_V1_DOMAIN_TAGS.profile, Uint8Array.of(3, 0), new Uint8Array(8));
    expect(hex(rawPreimageHash)).toBe(vectors.overlap.x10.profileIdSystem3EmptyVp);
  });

  it("deployment_id: an unknown network or a 31-byte category is refused", () => {
    const cats = { verdictCategoryWire32: lab("v"), rangeCategoryWire32: lab("r"), rootCategoryWire32: lab("t"), meterCategoryWire32: null };
    expect(codeOf(() => deriveAPNTPoolDeploymentIdV1({ ...cats, network: "testnet4" }))).toBe(F.DEPLOYMENT_NETWORK);
    expect(codeOf(() => deriveAPNTPoolDeploymentIdV1({ ...cats, network: "chipnet", rootCategoryWire32: lab("t").subarray(1) }))).toBe(F.DEPLOYMENT_CATEGORY);
  });
});

describe("pool v1 packet: one pad per plaintext across candidate retries", () => {
  // Two candidate actions spend the same input nullifier (so output 0 has the same ρ) to the same K,
  // after a fee or output revision: a different v. Both derive the same rcm from K and ρ (pad16).
  const K = lab("retry:K");
  const rho = lab("retry:rho = nf_in_0");
  const O = deriveAPNTPoolOwnerTagV1(pointOf(scalarOf("retry:recipient-ask")), lab("retry:recipient-nk"));
  const rcm = deriveAPNTPoolCommitmentRandomnessV1(K, rho);
  const u64le = (v: bigint) => { const out = new Uint8Array(8); for (let i = 0, x = v; i < 8; i += 1, x >>= 8n) out[i] = Number(x & 0xffn); return out; };
  const candidates = [100_000n, 101_000n].map((v) => {
    const cm = deriveAPNTPoolNoteCommitmentV1({ valueSats: v, ownerTag32: O, rho32: rho, commitmentRandomness32: rcm, recoveryTag32: deriveAPNTPoolRecoveryTagV1(K) });
    return { v, cm, plaintext: u64le(v) };
  });
  const xor = (a: Uint8Array, b: Uint8Array) => a.map((x, i) => x ^ b[i]!);
  const pad = (digest: Uint8Array, plaintext: Uint8Array) => new Uint8Array([...xor(plaintext, digest), ...digest.subarray(8, 16)]);
  const leaks = (p0: Uint8Array, p1: Uint8Array) => hex(xor(p0.subarray(0, 8), p1.subarray(0, 8))) === hex(xor(candidates[0]!.plaintext, candidates[1]!.plaintext));

  it("the canonical cm-bound digest differs per candidate and the packets' XOR does not leak the values' XOR", () => {
    const packets = candidates.map((c) => sealAPNTPoolPacketV1({ recoveryKey32: K, rho32: rho, commitment32: c.cm, valueSats: c.v }));
    expect(hex(deriveAPNTPoolPacketDigestV1(K, rho, candidates[0]!.cm))).not.toBe(hex(deriveAPNTPoolPacketDigestV1(K, rho, candidates[1]!.cm)));
    expect(leaks(packets[0]!, packets[1]!)).toBe(false);
  });

  it("faulty-digest control: a digest without cm (the pre-REV-129 rule's shape) leaks the values' XOR, so the detector fires", () => {
    const faultyDigest = apntPoolSha256V1(APNT_POOL_V1_DOMAIN_TAGS.packetDigest, K, rho);
    const packets = candidates.map((c) => pad(faultyDigest, c.plaintext));
    expect(leaks(packets[0]!, packets[1]!)).toBe(true);
  });

  it("an identical retry gives an identical packet; the recipient opens it from K and public ρ, cm; wrong K, cm or O fails", () => {
    const c = candidates[0]!;
    const input = { recoveryKey32: K, rho32: rho, commitment32: c.cm, valueSats: c.v };
    const packet = sealAPNTPoolPacketV1(input);
    expect(hex(sealAPNTPoolPacketV1(input))).toBe(hex(packet));
    const opened = openAPNTPoolPacketV1({ recoveryKey32: K, ownerTag32: O, rho32: rho, commitment32: c.cm, packet16: packet });
    expect(opened?.valueSats).toBe(c.v);
    expect(hex(opened!.commitmentRandomness32)).toBe(hex(rcm));
    expect(openAPNTPoolPacketV1({ recoveryKey32: lab("retry:other-K"), ownerTag32: O, rho32: rho, commitment32: c.cm, packet16: packet })).toBeNull();
    expect(openAPNTPoolPacketV1({ recoveryKey32: K, ownerTag32: O, rho32: rho, commitment32: candidates[1]!.cm, packet16: packet })).toBeNull();
    expect(openAPNTPoolPacketV1({ recoveryKey32: K, ownerTag32: lab("retry:other-O"), rho32: rho, commitment32: c.cm, packet16: packet })).toBeNull();
    expect(detectAPNTPoolPacketV1({ recoveryKey32: lab("retry:other-K"), rho32: rho, commitment32: c.cm, packet16: packet })).toBeNull();
  });

  it("the key check alone is a wrong-key filter, not an ownership check: a payer holding K seals a candidate for its own O that only the full tier refuses (REV-202)", () => {
    // The payer knows the recipient's K (from the invoice) and seals a note to its own owner tag under it.
    const payerO = deriveAPNTPoolOwnerTagV1(pointOf(scalarOf("retry:payer-ask")), lab("retry:payer-nk"));
    const cm = deriveAPNTPoolNoteCommitmentV1({ valueSats: 7_000n, ownerTag32: payerO, rho32: rho, commitmentRandomness32: rcm, recoveryTag32: deriveAPNTPoolRecoveryTagV1(K) });
    const packet = sealAPNTPoolPacketV1({ recoveryKey32: K, rho32: rho, commitment32: cm, valueSats: 7_000n });
    // The incoming tier (K alone) sees a candidate with its value…
    expect(detectAPNTPoolPacketV1({ recoveryKey32: K, rho32: rho, commitment32: cm, packet16: packet })).toEqual({ valueSats: 7_000n });
    // …the recipient's full tier refuses it, since cm does not rebuild under the recipient's O…
    expect(openAPNTPoolPacketV1({ recoveryKey32: K, ownerTag32: O, rho32: rho, commitment32: cm, packet16: packet })).toBeNull();
    // …and it opens only under the owner tag it was committed to.
    expect(openAPNTPoolPacketV1({ recoveryKey32: K, ownerTag32: payerO, rho32: rho, commitment32: cm, packet16: packet })?.valueSats).toBe(7_000n);
  });

  it("the range filter: a key check that matches over a value above MAX_MONEY is not a candidate", () => {
    const c = candidates[0]!;
    const digest = deriveAPNTPoolPacketDigestV1(K, rho, c.cm);
    const overMax = pad(digest, u64le(2_100_000_000_000_001n));
    expect(detectAPNTPoolPacketV1({ recoveryKey32: K, rho32: rho, commitment32: c.cm, packet16: overMax })).toBeNull();
    // Control: the same construction at MAX_MONEY is a candidate, so the refusal above is the range check's.
    expect(detectAPNTPoolPacketV1({ recoveryKey32: K, rho32: rho, commitment32: c.cm, packet16: pad(digest, u64le(2_100_000_000_000_000n)) }))
      .toEqual({ valueSats: 2_100_000_000_000_000n });
    // And a flipped key-check byte is not a candidate.
    const honest = sealAPNTPoolPacketV1({ recoveryKey32: K, rho32: rho, commitment32: c.cm, valueSats: c.v });
    for (const index of [8, 15]) {
      const flipped = honest.slice(); flipped[index] = flipped[index]! ^ 0x01;
      expect(detectAPNTPoolPacketV1({ recoveryKey32: K, rho32: rho, commitment32: c.cm, packet16: flipped })).toBeNull();
    }
  });
});
