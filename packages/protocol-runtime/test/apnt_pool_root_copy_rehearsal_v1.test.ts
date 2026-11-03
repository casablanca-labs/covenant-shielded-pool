// Independently authored F1 source controls; no archive bodies, operational inputs or proof execution.
import { describe, it, expect } from "vitest";
import { getAPNTPoolTreeCovenantSourceV1, assembleAPNTPoolRootCopyCovenantV1 } from "../src/apnt_pool_tree_covenants_v1.js";
const source = getAPNTPoolTreeCovenantSourceV1("rootCopy");
const parameters = () => ({ verdictCategoryWire32: new Uint8Array(32).fill(7), settlementLockingBytecode: Uint8Array.of(0xaa, 0x20, ...new Uint8Array(32).fill(9), 0x87) });
describe("F1 root-copy source construction", () => {
  it("rebuilds deterministically and binds the settlement lock", () => {
    const a = parameters(), first = assembleAPNTPoolRootCopyCovenantV1(source, a);
    expect(assembleAPNTPoolRootCopyCovenantV1(source, parameters())).toEqual(first);
    a.settlementLockingBytecode[2] = 8;
    expect(assembleAPNTPoolRootCopyCovenantV1(source, a).lockingBytecode).not.toEqual(first.lockingBytecode);
  });
  it("refuses malformed category parameters before assembly", () => {
    expect(() => assembleAPNTPoolRootCopyCovenantV1(source, { ...parameters(), verdictCategoryWire32: new Uint8Array(31) })).toThrowError(expect.objectContaining({ code: "pool-covenant-parameter" }));
  });
  it("refuses an unresolved template marker", () => {
    expect(() => assembleAPNTPoolRootCopyCovenantV1(source + "\n@F1_UNRESOLVED@", parameters())).toThrow(/marker/);
  });
});
