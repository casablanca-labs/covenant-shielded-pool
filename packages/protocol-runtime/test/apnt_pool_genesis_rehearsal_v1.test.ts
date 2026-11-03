// Independently authored F1 source controls; no archive bodies, operational inputs or proof execution.
import { describe, it, expect } from "vitest";
import { validateAPNTPoolGenesisV1 } from "../src/apnt_pool_genesis_v1.js";
describe("F1 genesis audit boundary", () => {
  it("returns a closed failure with no deployment output on malformed input", () => {
    expect(validateAPNTPoolGenesisV1(null)).toEqual({ valid: false, failureCode: "pool-shape", deploymentId32: null, rangeRecords66: null });
  });
  it("maps a clone-time accessor error to the canonical boundary failure", () => {
    let calls = 0; const value = { genesisTransactions: [] };
    Object.defineProperty(value, "artifact", { enumerable: true, get() { calls++; throw new Error("synthetic clone-time error"); } });
    expect(validateAPNTPoolGenesisV1(value)).toEqual({ valid: false, failureCode: "pool-boundary", deploymentId32: null, rangeRecords66: null });
    expect(calls).toBe(1);
  });
});
