// Independently authored F1 source controls; no archive bodies, operational inputs or proof execution.
import { describe, it, expect } from "vitest";
import { getAPNTPoolRangeRecordCovenantSourceV1, assembleAPNTPoolRangeRecordCovenantV1, deriveAPNTPoolRangeRecordLayoutV1 } from "../src/apnt_pool_range_record_covenant_v1.js";
const source = getAPNTPoolRangeRecordCovenantSourceV1();
const parameters = () => ({ verdictCategoryWire32: new Uint8Array(32).fill(7), settlementLockingBytecode: Uint8Array.of(0xaa, 0x20, ...new Uint8Array(32).fill(9), 0x87) });
describe("F1 range-record source construction", () => {
  it("reconstructs code with the declared lock-before-category layout", () => {
    const p = parameters(), layout = deriveAPNTPoolRangeRecordLayoutV1(source);
    const built = assembleAPNTPoolRangeRecordCovenantV1(source, p);
    expect(built.codeBytecode).toEqual(Uint8Array.of(...layout.prefix, ...p.settlementLockingBytecode, ...layout.middle, ...p.verdictCategoryWire32, ...layout.tail));
  });
  it("refuses a malformed lock length", () => {
    expect(() => assembleAPNTPoolRangeRecordCovenantV1(source, { ...parameters(), settlementLockingBytecode: new Uint8Array(34) })).toThrowError(expect.objectContaining({ code: "pool-covenant-parameter" }));
  });
  it("refuses a template without the required embedded constants", () => {
    expect(() => deriveAPNTPoolRangeRecordLayoutV1("OP_1")).toThrow(/embed/);
  });
});
