import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  APNT_POOL_FAILURE_V1 as F,
  APNTPoolDigestSetV1,
  APNTPoolHostErrorV1,
  apntPoolSha256V1,
  poolEqual,
  poolFailureCodeOf,
  poolRequire,
  poolTagBytes,
} from "../src/apnt_pool_contract_v1.js";
import * as packageIndex from "../src/index.js";
import { apntPoolMembershipRootV1, apntPoolTreeNodeV1, normalizeAPNTPoolMembershipPathV1 } from "../src/apnt_pool_tree_v1.js";
import {
  deriveAPNTPoolCommitmentRandomnessV1,
  deriveAPNTPoolNoteCommitmentV1,
  deriveAPNTPoolNullifierKeyCommitmentV1,
  deriveAPNTPoolNullifierV1,
  deriveAPNTPoolOwnerTagV1,
  deriveAPNTPoolRecoveryTagV1,
  detectAPNTPoolPacketV1,
  isAPNTPoolCompressedPointV1,
  openAPNTPoolPacketV1,
  sealAPNTPoolPacketV1,
} from "../src/apnt_pool_note_v1.js";
import {
  decodeAPNTPoolActionRecordV1,
  deriveAPNTPoolActionAuthorizationDigestV1,
  deriveAPNTPoolTagAuthorizationMessageV1,
  encodeAPNTPoolActionRecordV1,
} from "../src/apnt_pool_action_record_v1.js";
import {
  decodeAPNTPoolStatementV1,
  deriveAPNTPoolDeploymentIdV1,
  deriveAPNTPoolProfileIdV1,
  deriveAPNTPoolStatementCommitmentV1,
  encodeAPNTPoolStatementV1,
  insertAPNTPoolStatementNullifiersV1,
} from "../src/apnt_pool_statement_v1.js";
import {
  deriveAPNTPoolActionRecordV1,
  evaluateAPNTPoolActionV1,
  normalizeAPNTPoolActionWitnessV1,
} from "../src/apnt_pool_action_relation_v1.js";
import {
  apntPoolEmptyFrontierV1,
  decodeAPNTPoolFrontierStateV1,
  decodeAPNTPoolTreeUpdateCommitmentV1,
  deriveAPNTPoolFrontierRootV1,
  encodeAPNTPoolFrontierStateV1,
  encodeAPNTPoolTreeUpdateCommitmentV1,
  encodeAPNTPoolStatementLeavesV1,
  evaluateAPNTPoolTreeUpdateV1,
  foldAPNTPoolStatementIntoFrontierV1,
  normalizeAPNTPoolFrontierV1,
} from "../src/apnt_pool_frontier_v1.js";
import {
  decodeAPNTPoolMigrationInboxPreimageV1,
  deriveAPNTPoolMigrationInboxHashV1,
  encodeAPNTPoolMigrationInboxPreimageV1,
  evaluateAPNTPoolMigrationInboxReleaseV1,
} from "../src/apnt_pool_migration_v1.js";
import { hex, lab, sparseTree, unhex, vectors, witnessFromVector } from "./apnt_pool_v1_fixture.js";

/**
 * The host input boundary (REV-138 H1, REV-139, ARCH-145): no caller override,
 * getter, subclass or proxy may decide a pool host result. Every exported entry
 * point takes a structured clone of its arguments; a proxy, a function or a
 * throwing getter is refused with `pool-boundary`, a getter is read exactly
 * once, and a subclass arrives as the plain intrinsic holding its contents.
 * Every negative here gives the host an input whose behaviour disagrees with
 * its contents, and requires the answer that the contents alone give.
 */

const fv: any = JSON.parse(readFileSync(new URL("../test-vectors/public-apnt-pool-v1-frontier-vectors.json", import.meta.url), "utf8"));
const codeOf = (thunk: () => unknown): string | null => {
  try { thunk(); return null; } catch (error) { return error instanceof APNTPoolHostErrorV1 ? error.code : "non-pool-error"; }
};

const S = unhex(vectors.reference.statement.statement);
const DEP = unhex(vectors.reference.statement.deploymentId);
const PROF = unhex(vectors.reference.statement.profileId);
const RECORDS: Uint8Array[] = vectors.reference.statement.recordsInput.map(unhex);
const UNSETTLED = encodeAPNTPoolStatementV1({ deploymentId32: DEP, profileId32: PROF, records: [RECORDS[1]!] });
/** The leaves a fold pushes (ARCH-245 F1), and a pending batch as the fold identifies it: SHA-256 of those leaves. */
const leavesOf = (statement: Uint8Array) => encodeAPNTPoolStatementLeavesV1(statement, DEP);
const verdictOf = (statement: Uint8Array) => hex(apntPoolSha256V1(null, leavesOf(statement)));
const NF = hex(RECORDS[0]!.subarray(32, 64));

/** An honest tree update folding `statement`'s leaves onto the empty frontier. */
function treeUpdate(statement: Uint8Array, pendingBatches: unknown) {
  const prior = apntPoolEmptyFrontierV1();
  const next = foldAPNTPoolStatementIntoFrontierV1(prior, statement, DEP);
  const root = deriveAPNTPoolFrontierRootV1(next);
  return {
    treeUpdateCommitment72: encodeAPNTPoolTreeUpdateCommitmentV1(prior),
    pendingBatches,
    frontierState: encodeAPNTPoolFrontierStateV1(prior),
    leaves: leavesOf(statement),
    nextTreeUpdateCommitment72: encodeAPNTPoolTreeUpdateCommitmentV1(next),
    rootCopies32: [root, root],
  };
}

/** `value` with `key` turned into an accessor that counts its reads. */
function withAccessor<T extends object>(value: T, key: string, answers: (read: number) => unknown = () => (value as any)[key]) {
  const copy: any = { ...value };
  delete copy[key];
  const reads = { count: 0 };
  Object.defineProperty(copy, key, { enumerable: true, configurable: true, get: () => answers(reads.count++) });
  return { value: copy, reads };
}

/** A plain Uint8Array copy of `bytes` whose own `length` accessor reports `claimed`. */
function lyingLength(bytes: Uint8Array, claimed: number): Uint8Array {
  const copy = new Uint8Array(bytes);
  Object.defineProperty(copy, "length", { get: () => claimed });
  return copy;
}
const plusOneByte = (bytes: Uint8Array) => new Uint8Array([...bytes, 0x5a]);

/** An array holding `real` whose own iterator, `map` and `forEach` present `shown` instead. */
function lyingArray(real: readonly unknown[], shown: readonly unknown[]): unknown[] {
  const array: any[] = [...real];
  Object.defineProperty(array, Symbol.iterator, { value: function* () { yield* shown; } });
  Object.defineProperty(array, "map", { value: (f: (v: unknown, i: number) => unknown) => shown.map(f) });
  Object.defineProperty(array, "forEach", { value: (f: (v: unknown, i: number) => void) => shown.forEach(f) });
  return array;
}

// The private constructor is a TypeScript rule only; a JavaScript caller can subclass.
const DigestSetBase = APNTPoolDigestSetV1 as unknown as new (entries: Iterable<unknown>, code: string) => APNTPoolDigestSetV1;

describe("REV-138 H1: the pending-verdict set", () => {
  it("control: an empty APNTPoolDigestSetV1 subclass whose has() returns true is refused with pool-tree-verdict-not-pending", () => {
    class AlwaysPending extends DigestSetBase { has(_value: string): boolean { return true; } }
    const forged = new AlwaysPending([], F.DIGEST_SET_ENTRY);
    expect([...forged]).toEqual([]);
    expect(forged.has(verdictOf(S))).toBe(true); // the lie the model must not believe
    expect(evaluateAPNTPoolTreeUpdateV1(treeUpdate(S, new Set()))).toEqual({ valid: false, failureCode: F.TREE_VERDICT_NOT_PENDING, frontier: null, pendingBatches: null });
    expect(evaluateAPNTPoolTreeUpdateV1(treeUpdate(S, forged))).toEqual({ valid: false, failureCode: F.TREE_VERDICT_NOT_PENDING, frontier: null, pendingBatches: null });
  });

  it("a subclass that holds the verdict but whose has() returns false still folds: membership is a fact of the entries", () => {
    class NeverPending extends DigestSetBase { has(): boolean { return false; } }
    const result = evaluateAPNTPoolTreeUpdateV1(treeUpdate(S, new NeverPending([verdictOf(S)], F.DIGEST_SET_ENTRY)));
    expect([result.valid, result.failureCode]).toEqual([true, null]);
    expect(result.pendingBatches).toBeInstanceOf(APNTPoolDigestSetV1);
    expect(Object.getPrototypeOf(result.pendingBatches)).toBe(APNTPoolDigestSetV1.prototype);
  });

  it("a native Set subclass whose has() returns true but that holds nothing is refused", () => {
    class LyingSet extends Set<string> { has(): boolean { return true; } }
    expect(evaluateAPNTPoolTreeUpdateV1(treeUpdate(S, new LyingSet())).failureCode).toBe(F.TREE_VERDICT_NOT_PENDING);
  });

  it("the digest set is copied, never passed through, and its class and prototype cannot be patched", () => {
    const set = APNTPoolDigestSetV1.from(new Set([verdictOf(S)]));
    expect(APNTPoolDigestSetV1.from(set)).not.toBe(set);
    expect([Object.isFrozen(APNTPoolDigestSetV1), Object.isFrozen(APNTPoolDigestSetV1.prototype)]).toEqual([true, true]);
    expect(() => { (APNTPoolDigestSetV1.prototype as any).has = () => true; }).toThrow(TypeError);
    expect(() => { (APNTPoolDigestSetV1 as any).from = () => set; }).toThrow(TypeError);
  });
});

describe("the insertion model: the same pattern", () => {
  it("a digest-set subclass that holds an inserted nullifier but hides it from has, size and iteration still refuses the replay", () => {
    class Hiding extends DigestSetBase {
      has(): boolean { return false; }
      get size(): number { return 0; }
      values(): SetIterator<string> { return new Set<string>().values(); }
      keys(): SetIterator<string> { return new Set<string>().keys(); }
      entries(): SetIterator<[string, string]> { return new Set<string>().entries(); }
      [Symbol.iterator](): SetIterator<string> { return new Set<string>().values(); }
      forEach(): void {}
    }
    const hiding = new Hiding([NF], F.DIGEST_SET_ENTRY);
    expect([...hiding]).toEqual([]);
    expect(insertAPNTPoolStatementNullifiersV1(hiding, S, DEP)).toEqual({ valid: false, failureCode: F.NULLIFIER_REPLAYED, inserted: null });
  });

  it("a native Set subclass that hides an inserted nullifier from has and iteration still refuses the replay", () => {
    class HidingSet extends Set<string> {
      has(): boolean { return false; }
      values(): SetIterator<string> { return new Set<string>().values(); }
      [Symbol.iterator](): SetIterator<string> { return new Set<string>().values(); }
    }
    expect(insertAPNTPoolStatementNullifiersV1(new HidingSet([NF]), S, DEP)).toEqual({ valid: false, failureCode: F.NULLIFIER_REPLAYED, inserted: null });
  });

  it("a proxy standing in for a Set is refused at the boundary", () => {
    expect(insertAPNTPoolStatementNullifiersV1(new Proxy(new Set<string>(), {}), S, DEP)).toEqual({ valid: false, failureCode: F.BOUNDARY, inserted: null });
  });

  it("a digest set crosses the boundary as its digests data; that data shape is checked like any set", () => {
    const first = insertAPNTPoolStatementNullifiersV1(new Set(), UNSETTLED, DEP);
    expect(structuredClone(first.inserted)).toEqual({ digests: [...first.inserted!] });
    expect(insertAPNTPoolStatementNullifiersV1({ digests: [...first.inserted!] } as any, UNSETTLED, DEP).failureCode).toBe(F.NULLIFIER_REPLAYED);
    expect(insertAPNTPoolStatementNullifiersV1({ digests: [NF.toUpperCase()] } as any, S, DEP).failureCode).toBe(F.DIGEST_SET_ENTRY);
    expect(insertAPNTPoolStatementNullifiersV1({ digests: [NF], extra: 1 } as any, S, DEP).failureCode).toBe(F.DIGEST_SET_ENTRY);
  });
});

/** Outputs made comparable: bytes as hex, bigints as strings, digest sets as their entries. */
const summary = (x: unknown): unknown => {
  if (x instanceof Uint8Array) return hex(x);
  if (typeof x === "bigint") return `${x}n`;
  if (x instanceof APNTPoolDigestSetV1) return [...x];
  if (Array.isArray(x)) return x.map(summary);
  if (x !== null && typeof x === "object") return Object.fromEntries(Object.entries(x).map(([k, v]) => [k, summary(v)]));
  return x;
};
const outcomeOf = (thunk: () => unknown) => {
  try { return { ok: summary(thunk()) }; } catch (error) { return { code: error instanceof APNTPoolHostErrorV1 ? error.code : "non-pool-error" }; }
};

describe("records: the boundary clone reads each getter exactly once, and the host uses that value", () => {
  it("tree update: a leaves getter that changes on its second read (unsettled leaves, then the pending ones) is refused as not pending", () => {
    // Outputs consistent with folding UNSETTLED, whose batch is not pending; only S's is pending.
    const honest = treeUpdate(UNSETTLED, new Set([verdictOf(S)]));
    const { value, reads } = withAccessor(honest, "leaves", (read) => (read === 0 ? leavesOf(UNSETTLED) : leavesOf(S)));
    expect(evaluateAPNTPoolTreeUpdateV1(value)).toEqual({ valid: false, failureCode: F.TREE_VERDICT_NOT_PENDING, frontier: null, pendingBatches: null });
    expect(reads.count).toBe(1);
  });

  it("tree update: the same getter answering the pending leaves first folds them, once, whatever it answers later", () => {
    const { value, reads } = withAccessor(treeUpdate(S, new Set([verdictOf(S)])), "leaves", (read) => (read === 0 ? leavesOf(S) : leavesOf(UNSETTLED)));
    const result = evaluateAPNTPoolTreeUpdateV1(value);
    expect([result.valid, result.frontier?.leafCount]).toEqual([true, 4]);
    expect(reads.count).toBe(1);
  });

  const rel = vectors.reference.relation[0];
  const witness = witnessFromVector(rel.witness);
  const record = unhex(rel.record);
  const recordFields = decodeAPNTPoolActionRecordV1(record);
  const note = { valueSats: 5n, ownerTag32: lab("b:O"), rho32: lab("b:rho"), commitmentRandomness32: deriveAPNTPoolCommitmentRandomnessV1(lab("b:K"), lab("b:rho")), recoveryTag32: deriveAPNTPoolRecoveryTagV1(lab("b:K")) };
  const cm = deriveAPNTPoolNoteCommitmentV1(note);
  const packetInput = { recoveryKey32: lab("b:K"), rho32: lab("b:rho"), commitment32: cm, valueSats: 5n };
  const openInput = { recoveryKey32: lab("b:K"), ownerTag32: lab("b:O"), rho32: lab("b:rho"), commitment32: cm, packet16: sealAPNTPoolPacketV1(packetInput) };
  const detectInput = { recoveryKey32: lab("b:K"), rho32: lab("b:rho"), commitment32: cm, packet16: openInput.packet16 };
  const inbox = fv.reference.inbox.synthetic;
  const inboxFields = { successorDeploymentId32: unhex(inbox.successorDeploymentId), commitment32: unhex(inbox.commitment), packet16: unhex(inbox.packet), amountSats: BigInt(inbox.amountSats) };
  const tree = sparseTree([lab("b:leaf")]);
  // Record 0 of S deposits 50,000 into its cm_0; the reference inbox vector commits to exactly that.
  const release = { preimage104: unhex(fv.reference.inbox.referenceRecord0.preimage), successorDeploymentId32: DEP, statement: S };
  const cases: ReadonlyArray<readonly [string, object, string, (value: any) => unknown]> = [
    ["evaluateAPNTPoolTreeUpdateV1", treeUpdate(S, new Set([verdictOf(S)])), "rootCopies32", (v) => evaluateAPNTPoolTreeUpdateV1(v)],
    ["evaluateAPNTPoolActionV1", { record, witness }, "record", (v) => evaluateAPNTPoolActionV1(v)],
    ["deriveAPNTPoolActionRecordV1", { anchor32: unhex(rel.anchor), witness, depositSats: BigInt(rel.depositSats), withdrawalSats: BigInt(rel.withdrawalSats), feeSats: BigInt(rel.feeSats), withdrawalLockHash32: unhex(rel.withdrawalLockHash32) }, "feeSats", (v) => deriveAPNTPoolActionRecordV1(v)],
    ["normalizeAPNTPoolActionWitnessV1", witness, "inputs", (v) => normalizeAPNTPoolActionWitnessV1(v)],
    ["encodeAPNTPoolActionRecordV1", recordFields, "anchor32", (v) => encodeAPNTPoolActionRecordV1(v)],
    ["encodeAPNTPoolStatementV1", { deploymentId32: DEP, profileId32: PROF, records: RECORDS }, "records", (v) => encodeAPNTPoolStatementV1(v)],
    ["deriveAPNTPoolProfileIdV1", { systemId: 1, verifierParameters: lab("b:vp") }, "verifierParameters", (v) => deriveAPNTPoolProfileIdV1(v)],
    ["deriveAPNTPoolDeploymentIdV1", { network: "chipnet", verdictCategoryWire32: lab("b:v"), rangeCategoryWire32: lab("b:r"), rootCategoryWire32: lab("b:t"), meterCategoryWire32: lab("b:m") }, "meterCategoryWire32", (v) => deriveAPNTPoolDeploymentIdV1(v)],
    ["normalizeAPNTPoolMembershipPathV1", tree.path(0), "siblings32", (v) => normalizeAPNTPoolMembershipPathV1(v)],
    ["normalizeAPNTPoolFrontierV1", apntPoolEmptyFrontierV1(), "leafCount", (v) => normalizeAPNTPoolFrontierV1(v)],
    ["encodeAPNTPoolMigrationInboxPreimageV1", inboxFields, "amountSats", (v) => encodeAPNTPoolMigrationInboxPreimageV1(v)],
    ["evaluateAPNTPoolMigrationInboxReleaseV1", release, "statement", (v) => evaluateAPNTPoolMigrationInboxReleaseV1(v)],
    ["deriveAPNTPoolNoteCommitmentV1", note, "valueSats", (v) => deriveAPNTPoolNoteCommitmentV1(v)],
    ["sealAPNTPoolPacketV1", packetInput, "valueSats", (v) => sealAPNTPoolPacketV1(v)],
    ["openAPNTPoolPacketV1", openInput, "commitment32", (v) => openAPNTPoolPacketV1(v)],
    ["detectAPNTPoolPacketV1", detectInput, "commitment32", (v) => detectAPNTPoolPacketV1(v)],
  ];

  it.each(cases)("%s: a getter that changes on its second read is read once, and the result is the first value's", (_name, honest, key, run) => {
    const first = (honest as any)[key];
    const { value, reads } = withAccessor(honest, key, (read) => (read === 0 ? first : "a different second answer"));
    expect(outcomeOf(() => run(value))).toEqual(outcomeOf(() => run(honest)));
    expect(reads.count).toBe(1);
  });

  it("the honest inputs succeed (positive controls, so each row above compares against a real result)", () => {
    for (const [name, honest, , run] of cases) {
      const outcome = outcomeOf(() => run(honest)) as { ok?: any; code?: string };
      expect([name, outcome.code]).toEqual([name, undefined]);
      if (outcome.ok !== null && typeof outcome.ok === "object" && "valid" in outcome.ok) expect([name, outcome.ok.valid]).toEqual([name, true]);
    }
    expect(openAPNTPoolPacketV1(openInput)?.valueSats).toBe(5n);
    expect(detectAPNTPoolPacketV1(detectInput)?.valueSats).toBe(5n);
  });
});

describe("byte strings: copied by intrinsic operations; a lying length or a proxy decides nothing", () => {
  const record = RECORDS[0]!;
  const inbox = fv.reference.inbox.synthetic;
  const preimage = unhex(inbox.preimage);
  const successor = unhex(inbox.successorDeploymentId);
  const state = encodeAPNTPoolFrontierStateV1(apntPoolEmptyFrontierV1());
  const commitment72 = encodeAPNTPoolTreeUpdateCommitmentV1(apntPoolEmptyFrontierV1());
  const point = unhex(vectors.reference.note.inputs.ak);

  it("runBind32: S plus one byte, reporting |S| as its length, is refused (not hashed as S ‖ 0x5a)", () => {
    expect(codeOf(() => deriveAPNTPoolStatementCommitmentV1(lyingLength(plusOneByte(S), S.length), DEP))).toBe(F.STATEMENT_LENGTH);
    expect(codeOf(() => decodeAPNTPoolStatementV1(lyingLength(plusOneByte(S), S.length), DEP))).toBe(F.STATEMENT_LENGTH);
  });

  it("tree update: the leaves plus one byte with a lying length are refused, though SHA-256 of those bytes is pending", () => {
    const leaves = leavesOf(S);
    const input = { ...treeUpdate(S, new Set([hex(apntPoolSha256V1(null, plusOneByte(leaves)))])), leaves: lyingLength(plusOneByte(leaves), leaves.length) };
    expect(evaluateAPNTPoolTreeUpdateV1(input).failureCode).toBe(F.TREE_LEAVES);
  });

  it("ad: a record plus one byte with a lying length is refused (not hashed as 315 bytes)", () => {
    expect(codeOf(() => deriveAPNTPoolActionAuthorizationDigestV1(DEP, lyingLength(plusOneByte(record), 314)))).toBe(F.RECORD_LENGTH);
    expect(codeOf(() => decodeAPNTPoolActionRecordV1(lyingLength(plusOneByte(record), 314)))).toBe(F.RECORD_LENGTH);
  });

  it("m (HUM-75): a tag plus one byte with a lying length is refused (not hashed as 9 bytes); a proxy tag or tag pair is refused at the boundary", () => {
    const ad = deriveAPNTPoolActionAuthorizationDigestV1(DEP, record);
    const dt = [lab("b:dt0").subarray(0, 8), lab("b:dt1").subarray(0, 8)];
    expect(codeOf(() => deriveAPNTPoolTagAuthorizationMessageV1(ad, [lyingLength(plusOneByte(dt[0]!), 8), dt[1]]))).toBe(F.DISCOVERY_TAG);
    expect(codeOf(() => deriveAPNTPoolTagAuthorizationMessageV1(ad, [dt[0], new Proxy(dt[1]!, {})]))).toBe(F.BOUNDARY);
    expect(codeOf(() => deriveAPNTPoolTagAuthorizationMessageV1(ad, new Proxy(dt, {})))).toBe(F.BOUNDARY);
    expect(hex(deriveAPNTPoolTagAuthorizationMessageV1(ad, dt.map((tag) => Buffer.from(tag))))).toBe(hex(deriveAPNTPoolTagAuthorizationMessageV1(ad, dt)));
  });

  it("profile_id: vp's length prefix is its true length, whatever length it reports", () => {
    const vp = lab("b:vp").subarray(0, 20);
    expect(hex(deriveAPNTPoolProfileIdV1({ systemId: 1, verifierParameters: lyingLength(vp, 7) }))).toBe(hex(deriveAPNTPoolProfileIdV1({ systemId: 1, verifierParameters: vp })));
  });

  it("migration h, frontier state and tree-update commitment: one byte more with a lying length is refused", () => {
    expect(codeOf(() => deriveAPNTPoolMigrationInboxHashV1(lyingLength(plusOneByte(preimage), 104), successor))).toBe(F.MIGRATION_LENGTH);
    expect(codeOf(() => decodeAPNTPoolMigrationInboxPreimageV1(lyingLength(plusOneByte(preimage), 104), successor))).toBe(F.MIGRATION_LENGTH);
    expect(codeOf(() => decodeAPNTPoolFrontierStateV1(lyingLength(plusOneByte(state), 1032)))).toBe(F.TREE_STATE);
    expect(codeOf(() => decodeAPNTPoolTreeUpdateCommitmentV1(lyingLength(plusOneByte(commitment72), 72)))).toBe(F.TREE_COMMITMENT);
  });

  it("32-byte fields and points: one byte more with a lying length is refused", () => {
    expect(codeOf(() => deriveAPNTPoolNullifierV1(lyingLength(plusOneByte(lab("b:nk")), 32), lab("b:rho"), lab("b:cm")))).toBe(F.WITNESS_SHAPE);
    expect(codeOf(() => apntPoolTreeNodeV1(lyingLength(plusOneByte(lab("b:l")), 32), lab("b:r")))).toBe(F.MEMBERSHIP);
    expect(isAPNTPoolCompressedPointV1(point)).toBe(true);
    expect(isAPNTPoolCompressedPointV1(lyingLength(plusOneByte(point), 33))).toBe(false);
    expect(codeOf(() => deriveAPNTPoolOwnerTagV1(lyingLength(plusOneByte(point), 33), lab("b:nk")))).toBe(F.SPEND_KEY);
    expect(codeOf(() => deriveAPNTPoolOwnerTagV1(point, lyingLength(plusOneByte(lab("b:nk")), 32)))).toBe(F.WITNESS_SHAPE);
    expect(codeOf(() => deriveAPNTPoolNullifierKeyCommitmentV1(lyingLength(plusOneByte(lab("b:nk")), 32)))).toBe(F.WITNESS_SHAPE);
  });

  it("a proxy standing in for a Uint8Array is refused at the boundary; a genuine subclass (Buffer) is read by its contents", () => {
    expect(codeOf(() => deriveAPNTPoolRecoveryTagV1(new Proxy(lab("b:K"), {})))).toBe(F.BOUNDARY);
    expect(codeOf(() => deriveAPNTPoolNullifierKeyCommitmentV1(new Proxy(lab("b:nk"), {})))).toBe(F.BOUNDARY);
    expect(isAPNTPoolCompressedPointV1(new Proxy(point, {}))).toBe(false);
    expect(codeOf(() => deriveAPNTPoolStatementCommitmentV1(new Proxy(S, {}), DEP))).toBe(F.BOUNDARY);
    expect(hex(deriveAPNTPoolRecoveryTagV1(Buffer.from(lab("b:K"))))).toBe(hex(deriveAPNTPoolRecoveryTagV1(lab("b:K"))));
  });

  it("a view over a SharedArrayBuffer, or over part of a larger buffer, is read by its contents", () => {
    const shared = new Uint8Array(new SharedArrayBuffer(32));
    shared.set(lab("b:K"));
    const window = new Uint8Array(new ArrayBuffer(48), 8, 32);
    window.set(lab("b:K"));
    expect(hex(deriveAPNTPoolRecoveryTagV1(shared))).toBe(hex(deriveAPNTPoolRecoveryTagV1(lab("b:K"))));
    expect(hex(deriveAPNTPoolRecoveryTagV1(window))).toBe(hex(deriveAPNTPoolRecoveryTagV1(lab("b:K"))));
  });
});

describe("arrays: copied index by index; a lying iterator or map is never consulted", () => {
  it("tree update: root copies holding a fabricated root, iterating as two honest roots, are refused", () => {
    const honest = treeUpdate(S, new Set([verdictOf(S)]));
    const [root] = honest.rootCopies32;
    const rootCopies32 = lyingArray([root, unhex(fv.overlap.x6.fakeRoot)], [root, root]);
    expect(evaluateAPNTPoolTreeUpdateV1({ ...honest, rootCopies32 }).failureCode).toBe(F.TREE_ROOT);
  });

  it("membership: the root comes from the path's elements, not from what its map returns", () => {
    const tree = sparseTree([lab("b:leaf0"), lab("b:leaf1")]);
    const path = tree.path(1);
    const wrong = path.siblings32.map((_, h) => lab(`b:wrong:${h}`));
    const lying = { position: 1, siblings32: lyingArray(wrong, path.siblings32) };
    expect(hex(apntPoolMembershipRootV1(lab("b:leaf1"), path))).toBe(hex(tree.root));
    expect(hex(apntPoolMembershipRootV1(lab("b:leaf1"), lying))).toBe(hex(apntPoolMembershipRootV1(lab("b:leaf1"), { position: 1, siblings32: wrong })));
  });

  it("frontier and statement: entries and records are the arrays' elements, not what their methods return", () => {
    const entries = apntPoolEmptyFrontierV1().entries32.map((_, h) => lab(`b:F:${h}`));
    const lyingEntries = lyingArray(entries, apntPoolEmptyFrontierV1().entries32);
    expect(normalizeAPNTPoolFrontierV1({ leafCount: 3, entries32: lyingEntries }).entries32.map(hex)).toEqual(entries.map(hex));
    const encoded = encodeAPNTPoolStatementV1({ deploymentId32: DEP, profileId32: PROF, records: lyingArray(RECORDS, [RECORDS[1]!]) });
    expect(hex(encoded)).toBe(hex(S));
  });

  it("an array element getter is read once: its first answer is the copy the host checks", () => {
    const honest = treeUpdate(S, new Set([verdictOf(S)]));
    const fake = unhex(fv.overlap.x6.fakeRoot);
    for (const [firstAnswer, expected] of [[honest.rootCopies32[0], null], [fake, F.TREE_ROOT]] as const) {
      let reads = 0;
      const copies: unknown[] = [honest.rootCopies32[0]];
      Object.defineProperty(copies, "1", { enumerable: true, get: () => (reads++ === 0 ? firstAnswer : fake) });
      expect(evaluateAPNTPoolTreeUpdateV1({ ...honest, rootCopies32: copies }).failureCode).toBe(expected);
      expect(reads).toBe(1);
    }
  });
});

describe("failure codes: only from the host's own checks, and only closed codes", () => {
  const lookAlike = Object.assign(Object.create(APNTPoolHostErrorV1.prototype), { code: "attacker-chosen text" });
  const openCode = new APNTPoolHostErrorV1("attacker-chosen text" as any);

  it("a proxy whose traps would throw a look-alike or open-code error is refused at the boundary; no trap runs", () => {
    for (const error of [lookAlike, openCode]) {
      let trapCalls = 0;
      const throwing = new Proxy({}, { ownKeys() { trapCalls += 1; throw error; }, get() { trapCalls += 1; throw error; } });
      expect(evaluateAPNTPoolTreeUpdateV1(throwing).failureCode).toBe(F.BOUNDARY);
      expect(evaluateAPNTPoolActionV1(throwing).failureCode).toBe(F.BOUNDARY);
      expect(evaluateAPNTPoolMigrationInboxReleaseV1(throwing).failureCode).toBe(F.BOUNDARY);
      expect(trapCalls).toBe(0);
    }
  });
});

describe("the pool hash: listed tags and Uint8Array parts only", () => {
  it("an unlisted tag, a tag object with toString, or a string part is refused", () => {
    expect(codeOf(() => apntPoolSha256V1("APNT-POOL-v1:bogus" as any))).toBe(F.SHAPE);
    expect(codeOf(() => apntPoolSha256V1({ toString: () => "APNT-POOL-v1:cm" } as any))).toBe(F.BOUNDARY);
    expect(codeOf(() => apntPoolSha256V1({ tag: "APNT-POOL-v1:cm" } as any))).toBe(F.SHAPE);
    expect(codeOf(() => apntPoolSha256V1(null, "abc" as any))).toBe(F.SHAPE);
    expect(codeOf(() => apntPoolSha256V1("APNT-POOL-v1:cm", lab("b:x")))).toBeNull();
  });
});

describe("REV-139 and the fix-2 ruling: the named negatives", () => {
  const honest = treeUpdate(S, new Set([verdictOf(S)]));
  const [root] = honest.rootCopies32;
  const wrong = new Uint8Array(root!);
  wrong[0] = wrong[0]! ^ 0x01;

  it("the platform: structuredClone throws on a proxy over an array and over a plain object (measured in this Node)", () => {
    expect(() => structuredClone(new Proxy([1, 2, 3], {}))).toThrow();
    expect(() => structuredClone(new Proxy({ a: 1 }, {}))).toThrow();
    expect(() => structuredClone({ inner: new Proxy({}, {}) })).toThrow();
  });

  it("REV-139's probe: root copies [root, root, wrong] behind a proxy whose length descriptor says 2 are refused at the boundary", () => {
    const rootCopies32 = [root, root, wrong];
    const lying = new Proxy(rootCopies32, {
      getOwnPropertyDescriptor(target, key) {
        const descriptor = Reflect.getOwnPropertyDescriptor(target, key);
        return key === "length" ? { ...descriptor, value: 2 } : descriptor;
      },
    });
    expect(Reflect.getOwnPropertyDescriptor(lying, "length")?.value).toBe(2);
    expect(evaluateAPNTPoolTreeUpdateV1({ ...honest, rootCopies32 })).toEqual({ valid: false, failureCode: F.TREE_ROOT, frontier: null, pendingBatches: null });
    expect(evaluateAPNTPoolTreeUpdateV1({ ...honest, rootCopies32: lying })).toEqual({ valid: false, failureCode: F.BOUNDARY, frontier: null, pendingBatches: null });
  });

  it("a proxy that reports length 2 through both get and its descriptor is refused at the boundary", () => {
    const lying = new Proxy([root, root, wrong], {
      get(target, key, receiver) { return key === "length" ? 2 : Reflect.get(target, key, receiver); },
      getOwnPropertyDescriptor(target, key) {
        const descriptor = Reflect.getOwnPropertyDescriptor(target, key);
        return key === "length" ? { ...descriptor, value: 2 } : descriptor;
      },
    });
    expect(evaluateAPNTPoolTreeUpdateV1({ ...honest, rootCopies32: lying }).failureCode).toBe(F.BOUNDARY);
  });

  it("a genuine-looking host error thrown by caller code while the input is cloned is reported as pool-boundary", () => {
    let registered: unknown;
    try { poolRequire(false, F.TREE_ROOT); } catch (error) { registered = error; }
    expect(poolFailureCodeOf(registered)).toBe(F.TREE_ROOT); // the host's own error, positive control
    for (const error of [registered, new APNTPoolHostErrorV1(F.TREE_ROOT), lookAlikeError()]) {
      const { value } = withAccessor(honest, "leaves", () => { throw error; });
      expect(evaluateAPNTPoolTreeUpdateV1(value).failureCode).toBe(F.BOUNDARY);
      expect(codeOf(() => deriveAPNTPoolDeploymentIdV1(withAccessor({ network: "chipnet", verdictCategoryWire32: lab("b:v"), rangeCategoryWire32: lab("b:r"), rootCategoryWire32: lab("b:t"), meterCategoryWire32: null }, "network", () => { throw error; }).value))).toBe(F.BOUNDARY);
    }
  });

  it("a Uint8Array subclass with a lying every(): the host compares contents, and the helper does too", () => {
    class LyingEvery extends Uint8Array { override every(): boolean { return true; } }
    expect(evaluateAPNTPoolTreeUpdateV1({ ...honest, rootCopies32: [root, new LyingEvery(wrong)] }).failureCode).toBe(F.TREE_ROOT);
    const next = new Uint8Array(honest.nextTreeUpdateCommitment72);
    next[40] = next[40]! ^ 0x01; // the root field of the commitment
    expect(evaluateAPNTPoolTreeUpdateV1({ ...honest, nextTreeUpdateCommitment72: new LyingEvery(next) }).failureCode).toBe(F.TREE_ROOT);
    expect(poolEqual(new LyingEvery([1]), new Uint8Array([2]))).toBe(false);
    expect(Uint8Array.prototype.every.call(new LyingEvery([1]), (x, i) => x === [2][i])).toBe(false);
  });

  it("direct helper calls: an unregistered host error, an open fallback and a tag object are refused", () => {
    expect(poolFailureCodeOf(new APNTPoolHostErrorV1(F.TREE_ROOT))).toBe(F.SHAPE);
    expect(poolFailureCodeOf(new Error("other"), "caller chosen" as any)).toBe(F.SHAPE);
    expect(codeOf(() => poolTagBytes({ toString: () => "APNT-POOL-v1:cm" } as any))).toBe(F.SHAPE);
    expect(codeOf(() => poolTagBytes("APNT-POOL-v1:cm"))).toBeNull();
  });

  it("the package index exports neither the host error class nor any internal helper", () => {
    const exported = Object.keys(packageIndex);
    for (const name of ["APNTPoolHostErrorV1", "poolRequire", "poolFail", "poolFailureCodeOf", "poolBoundary", "poolRecord", "poolArray", "poolBytes", "pool32", "poolEqual", "poolTagBytes", "poolSha256", "poolDigestSet", "poolTreeNode"]) {
      expect([name, exported.includes(name)]).toEqual([name, false]);
    }
    expect(exported.includes("evaluateAPNTPoolTreeUpdateV1")).toBe(true);
  });
});

function lookAlikeError(): unknown {
  return Object.assign(Object.create(APNTPoolHostErrorV1.prototype), { code: F.TREE_ROOT });
}
