import { describe, expect, it } from "vitest";

import {
  APNT_CASHASSEMBLY_OPCODE_BYTES_V0,
  compileApntCashAssemblySourceV0,
  encodeScriptNumberPush,
} from "../src/apnt_cashassembly_compiler_v0.js";
import { bytesToHex } from "../src/bytes.js";

describe("task 21.8(a) — the CashAssembly assembler keeps its bytes across the rename", () => {
  it("keeps the opcode table addressable under its neutral name", () => {
    // A spot check that the moved table is the same table, not a retyped copy.
    expect(APNT_CASHASSEMBLY_OPCODE_BYTES_V0.OP_CHECKSIG).toBe(0xac);
    expect(APNT_CASHASSEMBLY_OPCODE_BYTES_V0.OP_UTXOTOKENCATEGORY).toBe(0xce);
    expect(compileApntCashAssemblySourceV0("OP_1 OP_DROP OP_1")).toEqual(
      Uint8Array.of(0x51, 0x75, 0x51),
    );
  });
});

describe("ENG-339 — numeric pushes are minimal script numbers for every safe integer", () => {
  it("encodes 2^31 and above correctly (the 32-bit bitwise encoding made 4,294,967,295 a push of 255)", () => {
    const cases: [number, string][] = [
      [0, "00"], [1, "51"], [16, "60"], [17, "0111"], [127, "017f"], [128, "028000"], [255, "02ff00"], [256, "020001"],
      [2 ** 31 - 1, "04ffffff7f"], [2 ** 31, "050000008000"], [2 ** 32 - 1, "05ffffffff00"], [2 ** 32, "050000000001"],
      [2_100_000_000_000_000, "070040075af07507"], [Number.MAX_SAFE_INTEGER, "07ffffffffffff1f"],
    ];
    for (const [value, expected] of cases) {
      expect([value, bytesToHex(encodeScriptNumberPush(value))]).toEqual([value, expected]);
      expect([value, bytesToHex(compileApntCashAssemblySourceV0(`<${String(value)}>`))]).toEqual([value, expected]);
    }
  });

  it("refuses a negative, fractional or unsafe number", () => {
    for (const value of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1]) expect(() => encodeScriptNumberPush(value)).toThrow(/invalid/u);
  });
});
