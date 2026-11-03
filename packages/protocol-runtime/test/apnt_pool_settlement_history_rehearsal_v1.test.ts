// Independently authored F1 source controls; no archive bodies, operational inputs or proof execution.
import { describe, it, expect } from "vitest";
import { replayAPNTPoolSettlementHistoryV1, replayAPNTPoolTreeHistoryV1, readAPNTPoolSettlementStatementV1 } from "../src/apnt_pool_settlement_history_v1.js";
describe("F1 history read boundary", () => {
  it("does not produce settlement state from malformed history", () => {
    expect(replayAPNTPoolSettlementHistoryV1(null)).toEqual({ valid: false, failureCode: "pool-shape", genesisHeight: null, settlements: null, liveRecords: null, otherTransactionCount: null });
  });
  it("does not produce tree state from malformed history", () => {
    expect(replayAPNTPoolTreeHistoryV1(null)).toEqual({ valid: false, failureCode: "pool-shape", settlementHistory: null, folds: null, leaves32: null, otherTreeTransactionCount: null });
  });
  it("does not expose a commitment or actions for an empty statement", () => {
    const result = readAPNTPoolSettlementStatementV1(new Uint8Array());
    expect(result.valid).toBe(false);
    expect(result.statementCommitment32).toBeNull(); expect(result.actions).toBeNull();
  });
});
