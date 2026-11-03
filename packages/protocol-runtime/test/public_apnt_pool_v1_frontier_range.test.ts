import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { buildPublicFrontierRange, buildPublicParityStatement, serializePublicFrontierRange } from "../test-vectors/generate-public-apnt-pool-v1-frontier-range.js";
import { PUBLIC_FRONTIER_RANGE_INPUTS } from "../test-vectors/public-apnt-pool-v1-frontier-range-inputs.js";
const built = buildPublicFrontierRange();
describe("public frontier and range construction", () => {
  it("reproduces both exact public artifacts from source without reading either artifact as input", () => {
    for (const [kind, value] of Object.entries(built)) {
      const bytes = readFileSync(new URL("../test-vectors/public-apnt-pool-v1-" + kind + "-vectors.json", import.meta.url), "utf8");
      expect(serializePublicFrontierRange(value)).toBe(bytes);
    }
  });
  it("retains every aggregate legacy case family and exhausts all carry depths with explicit public additions", () => {
    const f = built.frontier.reference, r = built.range.reference;
    expect([f.sequence.leaves.length, f.sequence.steps.length, f.fold.cases.length, built.frontier.overlap.x4.cases.length]).toEqual([64, 64, 4, 20]);
    expect([r.endpoints.length, r.keys.length, r.splits.length, r.notContained.length]).toEqual([10, 8, 6, 4]);
    expect(f.high.length).toBe(63);
    for (let depth = 1; depth <= 31; depth++) expect(f.high.some(row => row.carries.includes(depth))).toBe(true);
    expect(f.high.filter(row => row.fullAfterTail).length).toBe(2);
    expect(f.fold.cases.filter(row => row.refused).length).toBe(1);
    expect(Object.values(r.statementInsertion.byGenesis).map(row => row.pairwiseDistinct)).toEqual([false, false, false, true, true]);
  });
  it("freezes public labels and dimensions and refuses undeclared parity sizes", () => {
    expect(Object.isFrozen(PUBLIC_FRONTIER_RANGE_INPUTS)).toBe(true);
    expect(Object.isFrozen(PUBLIC_FRONTIER_RANGE_INPUTS.labels)).toBe(true);
    expect(new Set(PUBLIC_FRONTIER_RANGE_INPUTS.labels).size).toBe(PUBLIC_FRONTIER_RANGE_INPUTS.labels.length);
    for (const count of [0, 17, 1.5]) expect(() => buildPublicParityStatement(count)).toThrow("public parity action count");
    expect(buildPublicParityStatement(16)).toHaveLength(88 + 396 * 16);
  });
});
