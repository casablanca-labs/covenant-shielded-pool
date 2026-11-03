import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { APNT_POOL_FAILURE_V1 as F, APNTPoolHostErrorV1 } from "../src/apnt_pool_contract_v1.js";
import { encodeAPNTPoolStatementV1 } from "../src/apnt_pool_statement_v1.js";
import {
  APNT_POOL_V1_RANGE_ENDPOINT_MAXIMUM,
  assembleAPNTPoolRangeInsertionV1,
  decodeAPNTPoolRangeEndpointV1,
  deriveAPNTPoolRangeGenesisRecordsV1,
  deriveAPNTPoolRangeKeyV1,
  encodeAPNTPoolRangeEndpointV1,
  encodeAPNTPoolRangeRecordDataV1,
  evaluateAPNTPoolRangeInsertionV1,
  splitAPNTPoolRangeRecordV1,
  deriveAPNTPoolRangeRecordLockV1,
  decodeAPNTPoolRangeRecordUnlockingV1,
  evaluateAPNTPoolRangeSettlementV1,
} from "../src/apnt_pool_range_record_v1.js";
import {
  assembleAPNTPoolRangeRecordCovenantV1,
  buildAPNTPoolRangeRecordCovenantV1,
  deriveAPNTPoolRangeRecordLayoutV1,
  getAPNTPoolRangeRecordCovenantSourceV1,
} from "../src/apnt_pool_range_record_covenant_v1.js";
import * as packageIndex from "../src/index.js";
import { hex, isNonPalindromic, lab, unhex, vectors } from "./apnt_pool_v1_fixture.js";

/**
 * Task 3.1 host side: range keys, endpoints, record data, genesis records and
 * splits against an independent public reference; the one-to-one
 * nullifier/record rule the settlement covenant enforces (check 4), on the
 * records' data and on the bytes it reads (ARCH-234 D2, ARCH-245: each record's
 * data in its redeem, under its own lock, with an empty commitment); and the
 * assembly-time check that a statement's keys lie in pairwise distinct current
 * records. The covenants run in both BCH 2026 VMs in
 * `reference-aggregator/test/apnt_pool_range_record_v1_local_vm.test.ts` and
 * `apnt_pool_settlement_covenant_v1_local_vm.test.ts`.
 */

const rv: any = JSON.parse(readFileSync(new URL("../test-vectors/public-apnt-pool-v1-range-vectors.json", import.meta.url), "utf8"));
const ref = rv.reference;
const E = APNT_POOL_V1_RANGE_ENDPOINT_MAXIMUM;

const codeOf = (thunk: () => unknown): string | null => {
  try { thunk(); return null; } catch (error) { return error instanceof APNTPoolHostErrorV1 ? error.code : "non-pool-error"; }
};

const S = unhex(vectors.reference.statement.statement);
const DEP = unhex(vectors.reference.statement.deploymentId);
const PROF = unhex(vectors.reference.statement.profileId);
const RECORDS: Uint8Array[] = vectors.reference.statement.recordsInput.map(unhex);
const G9 = deriveAPNTPoolRangeGenesisRecordsV1(9);
const byG9 = ref.statementInsertion.byGenesis.g9;

/** The reference record with both nullifiers replaced (rk stays a valid point; commitments stay distinct). */
function recordWithNullifiers(base: Uint8Array, nf0: Uint8Array, nf1: Uint8Array, tag: string): Uint8Array {
  const out = base.slice();
  out.set(nf0, 32);
  out.set(nf1, 64);
  out.set(lab(`${tag}:cm0`), 162);
  out.set(lab(`${tag}:cm1`), 194);
  return out;
}
const statementOf = (records: Uint8Array[]) => encodeAPNTPoolStatementV1({ deploymentId32: DEP, profileId32: PROF, records });
const keyNf = (name: string) => unhex(ref.keys.find((k: any) => k.name === name).nullifier);

describe("pool v1 range records: reference vectors (independent public reference construction)", () => {
  it("endpoints: 33-byte unsigned little-endian in [0, 2^257], both directions", () => {
    for (const { value, bytes33 } of ref.endpoints) {
      expect(hex(encodeAPNTPoolRangeEndpointV1(BigInt(value)))).toBe(bytes33);
      expect(decodeAPNTPoolRangeEndpointV1(unhex(bytes33))).toBe(BigInt(value));
    }
    expect(ref.endpointMaximum).toBe(E.toString());
  });

  it("keys: κ = 2·int_le(nf) + 1 at 0, 1, the maximum, labels and both neighbours of a genesis boundary", () => {
    expect(ref.keys.length).toBe(8);
    for (const { nullifier, key, key33 } of ref.keys) {
      const kappa = deriveAPNTPoolRangeKeyV1(unhex(nullifier));
      expect(kappa).toBe(BigInt(key));
      expect(kappa % 2n).toBe(1n);
      expect(hex(encodeAPNTPoolRangeEndpointV1(kappa))).toBe(key33);
    }
    expect(isNonPalindromic(keyNf("labelA"))).toBe(true);
  });

  it("genesis: g = 0, 1, 3 exactly, and g = 9 by count, digest and three sampled records", () => {
    for (const g of [0, 1, 3]) expect(deriveAPNTPoolRangeGenesisRecordsV1(g).map(hex)).toEqual(ref.genesis[`g${g}`]);
    const all = new Uint8Array(G9.length * 66);
    G9.forEach((record, i) => all.set(record, 66 * i));
    expect(G9.length).toBe(ref.genesis.g9.count);
    expect(hex(new Uint8Array(createHash("sha256").update(all).digest()))).toBe(ref.genesis.g9.sha256OfConcatenation);
    expect([hex(G9[0]!), hex(G9[255]!), hex(G9[511]!)]).toEqual([ref.genesis.g9.first, ref.genesis.g9.record255, ref.genesis.g9.last]);
  });

  it("splits: sentinels 0 and 2^256 − 1, both neighbours of a genesis boundary, a label, the whole range", () => {
    for (const { record66, nullifier, left66, right66 } of ref.splits) {
      const split = splitAPNTPoolRangeRecordV1(unhex(record66), unhex(nullifier));
      expect([hex(split.left66), hex(split.right66)]).toEqual([left66, right66]);
    }
  });

  it("a key equal to lo or hi, a key outside, and the big-endian reading of a label are refused as not contained", () => {
    for (const { record66, nullifier } of ref.notContained) {
      expect(codeOf(() => splitAPNTPoolRangeRecordV1(unhex(record66), unhex(nullifier)))).toBe(F.RANGE_NOT_CONTAINED);
    }
    expect(ref.byteOrder.littleEndianRecord).not.toBe(ref.byteOrder.bigEndianRecord);
    expect(codeOf(() => splitAPNTPoolRangeRecordV1(G9[ref.byteOrder.littleEndianRecord]!, unhex(ref.byteOrder.nullifier)))).toBeNull();
  });

  it("the reference statement: record per key, spent and created records for g = 3 and g = 9, and the first shared record for g = 0, 1, 2", () => {
    expect(ref.statementInsertion.nullifiers).toEqual([0, 1].flatMap((k) => [88 + 314 * k + 32, 88 + 314 * k + 64].map((at) => hex(S.subarray(at, at + 32)))));
    for (const g of [3, 9]) {
      const entry = ref.statementInsertion.byGenesis[`g${g}`];
      const result = assembleAPNTPoolRangeInsertionV1({ statement: S, deploymentId32: DEP, liveRecords66: deriveAPNTPoolRangeGenesisRecordsV1(g) });
      expect(result.valid).toBe(true);
      expect([result.recordIndices, result.spentRecords66?.map(hex), result.createdRecords66?.map(hex)])
        .toEqual([entry.recordIndices, entry.spentRecords66, entry.createdRecords66]);
      expect(evaluateAPNTPoolRangeInsertionV1({ statement: S, deploymentId32: DEP, spentRecords66: result.spentRecords66, createdRecords66: result.createdRecords66 }))
        .toEqual({ valid: true, failureCode: null });
    }
    for (const g of [0, 1, 2]) {
      const entry = ref.statementInsertion.byGenesis[`g${g}`];
      expect(entry.pairwiseDistinct).toBe(false);
      expect(assembleAPNTPoolRangeInsertionV1({ statement: S, deploymentId32: DEP, liveRecords66: deriveAPNTPoolRangeGenesisRecordsV1(g) }).failureCode)
        .toBe(F.RANGE_SAME_RECORD);
    }
  });
});

describe("pool v1 range records: the one-to-one nullifier/record rule (host model of the covenant)", () => {
  const spent = byG9.spentRecords66.map(unhex);
  const created = byG9.createdRecords66.map(unhex);
  const evaluate = (spentRecords66: Uint8Array[], createdRecords66: Uint8Array[], statement = S) =>
    evaluateAPNTPoolRangeInsertionV1({ statement, deploymentId32: DEP, spentRecords66, createdRecords66 }).failureCode;

  it("positive: 2B spent records in statement-nullifier order, 4B created records in split order", () => {
    expect(evaluate(spent, created)).toBeNull();
  });

  it("a skipped statement nullifier (one record input too few) is refused", () => {
    expect(evaluate(spent.slice(0, 3), created.slice(0, 6))).toBe(F.RANGE_INPUT_COUNT);
  });

  it("an extra record input is refused", () => {
    expect(evaluate([...spent, G9[0]!], [...created, ...created.slice(0, 2)])).toBe(F.RANGE_INPUT_COUNT);
  });

  it("spent records out of statement-nullifier order are refused as not containing their key", () => {
    expect(evaluate([spent[1]!, spent[0]!, spent[2]!, spent[3]!], [...created.slice(2, 4), ...created.slice(0, 2), ...created.slice(4)])).toBe(F.RANGE_NOT_CONTAINED);
  });

  it("an extra created record, a missing one, a swapped pair and a widened right record are refused", () => {
    const whole = encodeAPNTPoolRangeRecordDataV1({ lo: 0n, hi: E });
    expect(evaluate(spent, [...created, whole])).toBe(F.RANGE_OUTPUT_COUNT);
    expect(evaluate(spent, created.slice(0, 7))).toBe(F.RANGE_OUTPUT_COUNT);
    expect(evaluate(spent, [created[1]!, created[0]!, ...created.slice(2)])).toBe(F.RANGE_SPLIT);
    const kappa0 = deriveAPNTPoolRangeKeyV1(unhex(ref.statementInsertion.nullifiers[0]));
    expect(evaluate(spent, [created[0]!, encodeAPNTPoolRangeRecordDataV1({ lo: kappa0, hi: E }), ...created.slice(2)])).toBe(F.RANGE_SPLIT);
  });

  it("double insertion: a statement nullifier whose key is already a boundary has no containing record", () => {
    // After the reference insertion, re-spend its left half for nullifier 0 (κ = hi) and its right half (κ = lo).
    expect(evaluate([created[0]!, ...spent.slice(1)], [created[0]!, created[0]!, ...created.slice(2)])).toBe(F.RANGE_NOT_CONTAINED);
    expect(evaluate([created[1]!, ...spent.slice(1)], [created[1]!, created[1]!, ...created.slice(2)])).toBe(F.RANGE_NOT_CONTAINED);
    const after = [...G9.filter((_, i) => !byG9.recordIndices.includes(i)), ...created];
    expect(assembleAPNTPoolRangeInsertionV1({ statement: S, deploymentId32: DEP, liveRecords66: after }).failureCode).toBe(F.RANGE_NOT_CONTAINED);
  });

  it("one record listed twice for two keys is refused as the same record (ENG-316, REV-145 H2); two distinct containing records are accepted", () => {
    // One action: nullifiers with top bytes 0x10 and 0x20 lie in g = 1 record 0; 0xf0 lies in record 1.
    const nf = (tag: string, top: number) => { const out = lab(tag).slice(); out[31] = top; return out; };
    const [a, b, c] = [nf("eng316:a", 0x10), nf("eng316:b", 0x20), nf("eng316:c", 0xf0)];
    const G0 = deriveAPNTPoolRangeGenesisRecordsV1(0);
    const G1 = deriveAPNTPoolRangeGenesisRecordsV1(1);
    const splits = (records: Uint8Array[], nullifiers: Uint8Array[]) => records.flatMap((record, j) => {
      const split = splitAPNTPoolRangeRecordV1(record, nullifiers[j]!);
      return [split.left66, split.right66];
    });
    const sameRecord = statementOf([recordWithNullifiers(RECORDS[0]!, a, b, "eng316:same")]);
    for (const record of [G0[0]!, G1[0]!]) {
      expect(evaluate([record, record], splits([record, record], [a, b]), sameRecord)).toBe(F.RANGE_SAME_RECORD);
    }
    const distinct = statementOf([recordWithNullifiers(RECORDS[0]!, a, c, "eng316:distinct")]);
    expect(evaluate([G1[0]!, G1[1]!], splits([G1[0]!, G1[1]!], [a, c]), distinct)).toBeNull();
    expect(assembleAPNTPoolRangeInsertionV1({ statement: sameRecord, deploymentId32: DEP, liveRecords66: [...G1] }).failureCode).toBe(F.RANGE_SAME_RECORD);
  });

  it("a non-canonical spent record (67 bytes, lo ≥ hi, an endpoint above 2^257) is refused", () => {
    expect(evaluate([new Uint8Array([...spent[0]!, 0]), ...spent.slice(1)], created)).toBe(F.RANGE_RECORD);
    const reversed = new Uint8Array([...spent[0]!.slice(33), ...spent[0]!.slice(0, 33)]);
    expect(evaluate([reversed, ...spent.slice(1)], created)).toBe(F.RANGE_RECORD);
    const above = spent[0]!.slice();
    above.set(encodeAPNTPoolRangeEndpointV1(E), 33);
    above[65] = 0x03; // hi = 3·2^256 > 2^257
    expect(evaluate([above, ...spent.slice(1)], created)).toBe(F.RANGE_ENDPOINT);
  });
});

describe("pool v1 range records: assembly-time same-record check and contention", () => {
  it("two statement keys in one current record: the host refuses before proving, naming neither key", () => {
    // Two records whose four nullifiers all lie in genesis record 0 of g = 9 (keys below 2^248).
    const small = (tag: string, n: number) => { const nf = new Uint8Array(32); nf.set(lab(tag).subarray(0, 16)); nf[31] = 0; nf[30] = n; return nf; };
    const records = [
      recordWithNullifiers(RECORDS[0]!, small("s:a", 1), small("s:b", 2), "same:0"),
      recordWithNullifiers(RECORDS[1]!, small("s:c", 3), small("s:d", 4), "same:1"),
    ];
    const statement = statementOf(records);
    const result = assembleAPNTPoolRangeInsertionV1({ statement, deploymentId32: DEP, liveRecords66: G9 });
    expect(result).toEqual({ valid: false, failureCode: F.RANGE_SAME_RECORD, recordIndices: null, spentRecords66: null, createdRecords66: null });
  });

  it("a seeded overlapping record in the live set is refused as overlap, not silently used", () => {
    const whole = encodeAPNTPoolRangeRecordDataV1({ lo: 0n, hi: E });
    expect(assembleAPNTPoolRangeInsertionV1({ statement: S, deploymentId32: DEP, liveRecords66: [...G9, whole] }).failureCode).toBe(F.RANGE_OVERLAP);
  });

  it("concurrent split: another settlement splits our record first; the same statement is rebuilt against the new record", () => {
    // A foreign nullifier whose key is ours minus 2: same genesis record, just below our key.
    const ours = unhex(ref.statementInsertion.nullifiers[2]);
    const foreignInt = BigInt("0x" + hex(ours.slice().reverse())) - 1n;
    const foreign = encodeAPNTPoolRangeEndpointV1(foreignInt).subarray(0, 32);
    const target = byG9.recordIndices[2] as number;
    const split = splitAPNTPoolRangeRecordV1(G9[target]!, foreign);
    const live = [...G9.filter((_, i) => i !== target), split.left66, split.right66];
    const rebuilt = assembleAPNTPoolRangeInsertionV1({ statement: S, deploymentId32: DEP, liveRecords66: live });
    expect(rebuilt.valid).toBe(true);
    expect(hex(rebuilt.spentRecords66![2]!)).toBe(hex(split.right66));
    expect(hex(rebuilt.spentRecords66![2]!)).not.toBe(byG9.spentRecords66[2]);
    expect(rebuilt.spentRecords66!.filter((_, j) => j !== 2).map(hex)).toEqual(byG9.spentRecords66.filter((_: string, j: number) => j !== 2));
    expect(evaluateAPNTPoolRangeInsertionV1({ statement: S, deploymentId32: DEP, spentRecords66: rebuilt.spentRecords66, createdRecords66: rebuilt.createdRecords66 }).valid).toBe(true);
  });

  it("splits only refine the partition: after random foreign insertions the reference keys stay in pairwise distinct records", () => {
    let live = [...G9];
    for (let n = 0; n < 200; n += 1) {
      const nf = lab(`foreign:${n}`);
      const result = assembleAPNTPoolRangeInsertionV1({ statement: statementOf([recordWithNullifiers(RECORDS[0]!, nf, lab(`foreign:${n}:b`), `f:${n}`)]), deploymentId32: DEP, liveRecords66: live });
      if (!result.valid) continue;
      const spentHex = new Set(result.spentRecords66.map(hex));
      live = [...live.filter((record) => !spentHex.has(hex(record))), ...result.createdRecords66];
      const ours = assembleAPNTPoolRangeInsertionV1({ statement: S, deploymentId32: DEP, liveRecords66: live });
      expect([n, ours.valid]).toEqual([n, true]);
    }
    expect(live.length).toBeGreaterThan(G9.length + 300);
  });
});

describe("pool v1 range records: encoders refuse out-of-range values", () => {
  it("endpoints outside [0, 2^257], a non-bigint and a wrong width are refused", () => {
    expect(codeOf(() => encodeAPNTPoolRangeEndpointV1(-1n))).toBe(F.RANGE_ENDPOINT);
    expect(codeOf(() => encodeAPNTPoolRangeEndpointV1(E + 1n))).toBe(F.RANGE_ENDPOINT);
    expect(codeOf(() => encodeAPNTPoolRangeEndpointV1(5))).toBe(F.RANGE_ENDPOINT);
    expect(codeOf(() => decodeAPNTPoolRangeEndpointV1(new Uint8Array(32)))).toBe(F.RANGE_ENDPOINT);
    expect(codeOf(() => decodeAPNTPoolRangeEndpointV1(encodeAPNTPoolRangeEndpointV1(E).map((b, i) => (i === 32 ? 3 : b))))).toBe(F.RANGE_ENDPOINT);
  });

  it("a record needs lo < hi; genesis needs an integer 0 ≤ g ≤ 9; a nullifier needs 32 bytes", () => {
    expect(codeOf(() => encodeAPNTPoolRangeRecordDataV1({ lo: 5n, hi: 5n }))).toBe(F.RANGE_RECORD);
    expect(codeOf(() => encodeAPNTPoolRangeRecordDataV1({ lo: 5n, hi: 6n, extra: 1 }))).toBe(F.RANGE_RECORD);
    for (const g of [-1, 10, 1.5, "3"]) expect(codeOf(() => deriveAPNTPoolRangeGenesisRecordsV1(g))).toBe(F.RANGE_GENESIS);
    expect(codeOf(() => deriveAPNTPoolRangeKeyV1(new Uint8Array(31)))).toBe(F.NULLIFIER);
  });
});

describe("pool v1 range records: the host input boundary", () => {
  it("a proxy is refused with pool-boundary at every range entry point", () => {
    const proxy = new Proxy({}, {});
    expect(codeOf(() => deriveAPNTPoolRangeKeyV1(proxy))).toBe(F.BOUNDARY);
    expect(codeOf(() => splitAPNTPoolRangeRecordV1(proxy, keyNf("labelA")))).toBe(F.BOUNDARY);
    expect(codeOf(() => encodeAPNTPoolRangeRecordDataV1(proxy))).toBe(F.BOUNDARY);
    expect(assembleAPNTPoolRangeInsertionV1(proxy).failureCode).toBe(F.BOUNDARY);
    expect(evaluateAPNTPoolRangeInsertionV1({ statement: S, deploymentId32: DEP, spentRecords66: new Proxy([], {}), createdRecords66: [] }).failureCode).toBe(F.BOUNDARY);
  });

  it("a live-record array getter is read once: the host answers from its first value", () => {
    let reads = 0;
    const input = { statement: S, deploymentId32: DEP } as any;
    Object.defineProperty(input, "liveRecords66", { enumerable: true, get: () => (reads++ === 0 ? G9 : [encodeAPNTPoolRangeRecordDataV1({ lo: 0n, hi: E })]) });
    const result = assembleAPNTPoolRangeInsertionV1(input);
    expect([reads, result.valid, result.recordIndices]).toEqual([1, true, byG9.recordIndices]);
  });

  it("a spent record reporting 66 bytes while holding 67 is read by its contents and refused", () => {
    const lying = new Uint8Array([...unhex(byG9.spentRecords66[0]), 0x5a]);
    Object.defineProperty(lying, "length", { get: () => 66 });
    const spent = [lying, ...byG9.spentRecords66.slice(1).map(unhex)];
    expect(evaluateAPNTPoolRangeInsertionV1({ statement: S, deploymentId32: DEP, spentRecords66: spent, createdRecords66: byG9.createdRecords66.map(unhex) }).failureCode).toBe(F.RANGE_RECORD);
  });

  it("the package index exports the range entry points and the covenant builder", () => {
    const exported = Object.keys(packageIndex);
    for (const name of [
      "deriveAPNTPoolRangeKeyV1", "assembleAPNTPoolRangeInsertionV1", "evaluateAPNTPoolRangeInsertionV1", "splitAPNTPoolRangeRecordV1",
      "buildAPNTPoolRangeRecordCovenantV1", "assembleAPNTPoolRangeRecordCovenantV1", "deriveAPNTPoolRangeRecordLayoutV1",
      "deriveAPNTPoolRangeRecordLockV1", "decodeAPNTPoolRangeRecordUnlockingV1", "evaluateAPNTPoolRangeSettlementV1",
      "encodeAPNTPoolRangeRecordDataV1", "decodeAPNTPoolRangeRecordDataV1",
    ]) {
      expect([name, exported.includes(name)]).toEqual([name, true]);
    }
  });
});

describe("pool v1 range-record covenant builder (the record code, ARCH-234 D2)", () => {
  const SETTLEMENT_LOCK = new Uint8Array([0xaa, 0x20, ...lab("settlement-lock"), 0x87]);
  const VERDICT = unhex(vectors.reference.deploymentId.categoriesWire.verdict);
  const parameters = () => ({ verdictCategoryWire32: VERDICT, settlementLockingBytecode: SETTLEMENT_LOCK });

  it("compiles deterministically to a 75-byte code: <0> OP_UTXOBYTECODE <settlement lock> OP_EQUALVERIFY <0> OP_UTXOTOKENCATEGORY <V> OP_EQUAL, V in wire order", () => {
    const a = buildAPNTPoolRangeRecordCovenantV1(parameters());
    const b = buildAPNTPoolRangeRecordCovenantV1(parameters());
    expect(hex(a.codeBytecode)).toBe(hex(b.codeBytecode));
    expect(hex(a.codeBytecode)).toBe(`00c723${hex(SETTLEMENT_LOCK)}8800ce20${hex(VERDICT)}87`);
    expect(a.codeBytecode.length).toBe(75);
    expect(hex(a.codeBytecode)).not.toContain(hex(VERDICT.slice().reverse()));
    const layout = deriveAPNTPoolRangeRecordLayoutV1(getAPNTPoolRangeRecordCovenantSourceV1());
    expect([hex(layout.prefix), hex(layout.middle), hex(layout.tail)]).toEqual(["00c723", "8800ce20", "87"]);
  });

  it("names exactly the two checks the local-VM ablations remove; each ablated source keeps the layout the settlement rebuilds", () => {
    const source = getAPNTPoolRangeRecordCovenantSourceV1();
    const names = [...source.matchAll(/^\/\/@check ([A-Z_]+)$/gmu)].map((m) => m[1]);
    expect(names).toEqual(["AUTH_LOCK", "AUTH_CATEGORY"]);
    for (const name of names) {
      const region = new RegExp(`^//@check ${name!}\\n([\\s\\S]*?)^//@end\\n`, "mu").exec(source)!;
      const ablated = source.replace(region[0], `${/^\/\/@ablated (.*)$/mu.exec(region[1]!)![1]!}\n`);
      expect(() => deriveAPNTPoolRangeRecordLayoutV1(ablated)).not.toThrow();
    }
  });

  it("refuses malformed parameters with pool-covenant-parameter: a settlement lock that is not P2SH32, a bad category, an unknown or retired field", () => {
    const bad = [
      { ...parameters(), verdictCategoryWire32: "00".repeat(32) },
      { ...parameters(), verdictCategoryWire32: new Uint8Array(31) },
      { ...parameters(), settlementLockingBytecode: new Uint8Array(0) },
      { ...parameters(), settlementLockingBytecode: SETTLEMENT_LOCK.slice(0, 34) },
      { ...parameters(), recordValueSats: 1000n }, // moved to the settlement (OUT_VALUE)
      { ...parameters(), rangeCategoryWire32: unhex(vectors.reference.deploymentId.categoriesWire.range) },
      { ...parameters(), extra: 1 },
    ];
    for (const value of bad) expect(codeOf(() => buildAPNTPoolRangeRecordCovenantV1(value))).toBe(F.COVENANT_PARAMETER);
  });

  it("refuses a template with an unreplaced marker or one that is not a string", () => {
    const source = getAPNTPoolRangeRecordCovenantSourceV1();
    expect(() => assembleAPNTPoolRangeRecordCovenantV1(source.replace("@VERDICT_CATEGORY_PUSH@ OP_EQUAL\n", "@UNKNOWN_PUSH@ OP_EQUAL\n"), parameters())).toThrow(/UNKNOWN_PUSH/u);
    expect(() => assembleAPNTPoolRangeRecordCovenantV1(1 as unknown as string, parameters())).toThrow(/template/u);
  });
});

describe("pool v1 range records: data in the redeem (ARCH-234 D2) and the settlement's check 4 on bytes", () => {
  const SETTLEMENT_LOCK = new Uint8Array([0xaa, 0x20, ...lab("settlement-lock"), 0x87]);
  const VERDICT = unhex(vectors.reference.deploymentId.categoriesWire.verdict);
  const R = unhex(vectors.reference.deploymentId.categoriesWire.range);
  const CODE = buildAPNTPoolRangeRecordCovenantV1({ verdictCategoryWire32: VERDICT, settlementLockingBytecode: SETTLEMENT_LOCK }).codeBytecode;
  const OTHER_CODE = buildAPNTPoolRangeRecordCovenantV1({ verdictCategoryWire32: VERDICT, settlementLockingBytecode: new Uint8Array([0xaa, 0x20, ...lab("other-settlement"), 0x87]) }).codeBytecode;
  const lockOf = (data: Uint8Array, code = CODE) => deriveAPNTPoolRangeRecordLockV1({ codeBytecode: code, record66: data });
  const spent = byG9.spentRecords66.map(unhex) as Uint8Array[];
  const created = byG9.createdRecords66.map(unhex) as Uint8Array[];
  const record = (capability: "none" | "mutable" | "minting" = "minting", commitment: Uint8Array = new Uint8Array(0), amount = 0n, category = R) => ({ categoryWire32: category, capability, commitment, amount });
  const honest = () => ({
    statement: S, deploymentId32: DEP, rangeCategoryWire32: R, codeBytecode: CODE, recordValueSats: 1000n,
    recordInputs: spent.map((data) => ({ unlockingBytecode: lockOf(data).unlockingBytecode, token: record() })),
    splitOutputs: created.map((data) => ({ lockingBytecode: lockOf(data).lockingBytecode, valueSats: 1000n, token: record() })),
  });
  const evaluate = (change: (input: ReturnType<typeof honest>) => void = () => {}) => {
    const input = honest();
    change(input);
    return evaluateAPNTPoolRangeSettlementV1(input).failureCode;
  };

  it("a record's redeem is push(lo‖hi) ‖ OP_DROP ‖ CODE (143 bytes), its lock P2SH32 of that, its unlocking the 145-byte push; the data reads back", () => {
    const L = lockOf(G9[0]!);
    expect(hex(L.redeemBytecode)).toBe(`42${hex(G9[0]!)}75${hex(CODE)}`);
    expect([L.redeemBytecode.length, L.unlockingBytecode.length, hex(L.unlockingBytecode.slice(0, 3))]).toEqual([143, 145, "4c8f42"]);
    const h = createHash("sha256").update(createHash("sha256").update(L.redeemBytecode).digest()).digest();
    expect(hex(L.lockingBytecode)).toBe(`aa20${hex(new Uint8Array(h))}87`);
    expect(hex(decodeAPNTPoolRangeRecordUnlockingV1({ codeBytecode: CODE, unlockingBytecode: L.unlockingBytecode }))).toBe(hex(G9[0]!));
    // Every record has its own lock.
    expect(new Set(G9.map((data) => hex(lockOf(data).lockingBytecode))).size).toBe(512);
  });

  it("a non-canonical record's data, or a CODE outside 1..400 bytes, is refused before any lock is derived", () => {
    expect(codeOf(() => lockOf(new Uint8Array([...G9[0]!, 0])))).toBe(F.RANGE_RECORD);
    expect(codeOf(() => lockOf(new Uint8Array([...G9[0]!.slice(33), ...G9[0]!.slice(0, 33)])))).toBe(F.RANGE_RECORD);
    expect(codeOf(() => lockOf(G9[0]!, new Uint8Array(0)))).toBe(F.COVENANT_PARAMETER);
    expect(codeOf(() => lockOf(G9[0]!, new Uint8Array(401)))).toBe(F.COVENANT_PARAMETER);
  });

  it("RECORD_REDEEM: an unlocking that is not exactly the record push for this CODE is pool-range-record-redeem", () => {
    const L = lockOf(G9[3]!);
    const decode = (unlocking: Uint8Array, code = CODE) => codeOf(() => decodeAPNTPoolRangeRecordUnlockingV1({ codeBytecode: code, unlockingBytecode: unlocking }));
    expect(decode(L.unlockingBytecode)).toBeNull();
    const cases: Array<[string, Uint8Array]> = [
      ["one byte appended", new Uint8Array([...L.unlockingBytecode, 0x51])],
      ["a leading push", new Uint8Array([0x51, ...L.unlockingBytecode])],
      ["a truncated tail", L.unlockingBytecode.slice(0, 144)],
      ["OP_PUSHDATA2 instead of OP_PUSHDATA1", new Uint8Array([0x4d, 0x8f, 0x00, ...L.unlockingBytecode.slice(2)])],
      ["the data pushed with OP_PUSHDATA1", new Uint8Array([0x4c, 0x90, 0x4c, 0x42, ...L.unlockingBytecode.slice(3)])],
      ["the data dropped with OP_NIP", new Uint8Array([...L.unlockingBytecode.slice(0, 69), 0x77, ...L.unlockingBytecode.slice(70)])],
    ];
    for (const [name, unlocking] of cases) expect([name, decode(unlocking)]).toEqual([name, F.RANGE_RECORD_REDEEM]);
    expect(decode(L.unlockingBytecode, OTHER_CODE)).toBe(F.RANGE_RECORD_REDEEM);
  });

  it("positive: the reference statement's four records and eight splits (the Python reference's data) pass the byte-level model", () => {
    expect(evaluate()).toBeNull();
  });

  it("each check of check 4 refuses with its named code", () => {
    const kappa0 = deriveAPNTPoolRangeKeyV1(unhex(ref.statementInsertion.nullifiers[0]));
    const table: Array<[string, (input: ReturnType<typeof honest>) => void, string]> = [
      ["a skipped statement nullifier", (i) => { i.recordInputs.pop(); }, F.RANGE_INPUT_COUNT],
      ["an extra split", (i) => { i.splitOutputs.push(i.splitOutputs[0]!); }, F.RANGE_OUTPUT_COUNT],
      ["RECORD_CATEGORY: an immutable range token as record 0", (i) => { i.recordInputs[0]!.token = record("none"); }, F.RANGE_RECORD_TOKEN],
      ["RECORD_CATEGORY: a foreign category as record 1", (i) => { i.recordInputs[1]!.token = record("minting", new Uint8Array(0), 0n, lab("foreign")); }, F.RANGE_RECORD_TOKEN],
      ["RECORD_CATEGORY: no token at record 2", (i) => { (i.recordInputs[2] as any).token = null; }, F.RANGE_RECORD_TOKEN],
      ["RECORD_REDEEM: record 0's unlocking under another deployment's code", (i) => { i.recordInputs[0]!.unlockingBytecode = lockOf(spent[0]!, OTHER_CODE).unlockingBytecode; }, F.RANGE_RECORD_REDEEM],
      ["the same record's data for two keys", (i) => { i.recordInputs[1]!.unlockingBytecode = i.recordInputs[0]!.unlockingBytecode; }, F.RANGE_SAME_RECORD],
      ["KEY_*: record 0 spent after its key was inserted (the reference's right split, lo = κ)", (i) => { i.recordInputs[0]!.unlockingBytecode = lockOf(created[1]!).unlockingBytecode; }, F.RANGE_NOT_CONTAINED],
      ["KEY_*: records 0 and 1 swapped", (i) => { [i.recordInputs[0], i.recordInputs[1]] = [i.recordInputs[1]!, i.recordInputs[0]!]; }, F.RANGE_NOT_CONTAINED],
      ["OUT_CATEGORY: the right split immutable", (i) => { i.splitOutputs[1]!.token = record("none"); }, F.RANGE_SPLIT_TOKEN],
      ["OUT_COMMITMENT_EMPTY: the left split carrying lo‖κ as a commitment", (i) => { i.splitOutputs[0]!.token = record("minting", created[0]!); }, F.RANGE_SPLIT_TOKEN],
      ["OUT_AMOUNT: a split with a fungible amount", (i) => { i.splitOutputs[2]!.token = record("minting", new Uint8Array(0), 1n); }, F.RANGE_SPLIT_TOKEN],
      ["OUT_VALUE: a split one satoshi short", (i) => { i.splitOutputs[3]!.valueSats = 999n; }, F.RANGE_SPLIT_VALUE],
      ["OUT_LOCK: the right split widened to (κ, 2^257)", (i) => { i.splitOutputs[1]!.lockingBytecode = lockOf(encodeAPNTPoolRangeRecordDataV1({ lo: kappa0, hi: E })).lockingBytecode; }, F.RANGE_SPLIT],
      ["OUT_LOCK: the two splits of record 0 swapped", (i) => { [i.splitOutputs[0], i.splitOutputs[1]] = [i.splitOutputs[1]!, i.splitOutputs[0]!]; }, F.RANGE_SPLIT],
      ["OUT_LOCK: a split under the record code of another deployment", (i) => { i.splitOutputs[5]!.lockingBytecode = lockOf(created[5]!, OTHER_CODE).lockingBytecode; }, F.RANGE_SPLIT],
    ];
    for (const [name, change, code] of table) expect([name, evaluate(change)]).toEqual([name, code]);
  });
});
