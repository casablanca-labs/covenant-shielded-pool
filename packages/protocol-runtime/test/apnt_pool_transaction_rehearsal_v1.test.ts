// Independently authored F1 source controls; no archive bodies, operational inputs or proof execution.
import { describe, it, expect } from "vitest";
import { poolEncodeTransaction, decodeAPNTPoolTransactionV1 } from "../src/apnt_pool_transaction_v1.js";
import { APNT_POOL_FAILURE_V1 as F, pool32 } from "../src/apnt_pool_contract_v1.js";
const draft = () => ({ version: 2, locktime: 0, inputs: [{ outpointTxidWire32: pool32(new Uint8Array(32).fill(7), F.TRANSACTION), outpointIndex: 0, unlockingBytecode: new Uint8Array(), sequenceNumber: 0xffffffff }], outputs: [{ valueSats: 0n, lockingBytecode: Uint8Array.of(0x51), token: null }] });
describe("F1 transaction codec", () => {
  it("roundtrips a zero-value synthetic transaction without changing wire bytes", () => {
    const bytes = poolEncodeTransaction(draft()), decoded = decodeAPNTPoolTransactionV1(bytes);
    expect(poolEncodeTransaction(decoded)).toEqual(bytes);
    expect(decoded.outputs[0]!.valueSats).toBe(0n);
  });
  it("refuses a duplicate outpoint", () => {
    const p = draft(); p.inputs.push(p.inputs[0]!);
    expect(() => poolEncodeTransaction(p)).toThrowError(expect.objectContaining({ code: "pool-transaction" }));
  });
  it("refuses trailing bytes after a complete transaction", () => {
    expect(() => decodeAPNTPoolTransactionV1(Uint8Array.of(...poolEncodeTransaction(draft()), 0))).toThrowError(expect.objectContaining({ code: "pool-transaction" }));
  });
});
