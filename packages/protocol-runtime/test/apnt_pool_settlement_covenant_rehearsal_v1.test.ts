// Independently authored F1 source controls; no archive bodies, operational inputs or proof execution.
import { describe, it, expect } from "vitest";
import { buildAPNTPoolSettlementCovenantsV1 } from "../src/apnt_pool_settlement_covenant_v1.js";
const parameters = () => ({ network: "local", verdictCategoryWire32: new Uint8Array(32).fill(7), rangeCategoryWire32: new Uint8Array(32).fill(8), rootCategoryWire32: new Uint8Array(32).fill(9), rootCopyCount: 2, rootCopySats: 1n, foldBountySats: 3n, recordValueSats: 1n });
describe("F1 settlement source construction", () => {
  it("rebuilds settlement and pool-coin code deterministically", () => {
    const built = buildAPNTPoolSettlementCovenantsV1(parameters());
    expect(buildAPNTPoolSettlementCovenantsV1(parameters())).toEqual(built);
    expect(built.settlement.lockingBytecode).not.toEqual(built.poolCoin.lockingBytecode);
  });
  it("rejects aliased deployment categories", () => {
    const p = parameters(); p.rangeCategoryWire32 = p.verdictCategoryWire32;
    expect(() => buildAPNTPoolSettlementCovenantsV1(p)).toThrowError(expect.objectContaining({ code: "pool-covenant-parameter" }));
  });
  it("rejects a fold bounty that does not cover all root copies", () => {
    expect(() => buildAPNTPoolSettlementCovenantsV1({ ...parameters(), foldBountySats: 2n })).toThrowError(expect.objectContaining({ code: "pool-covenant-parameter" }));
  });
});
