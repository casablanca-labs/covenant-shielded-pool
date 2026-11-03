// Independently authored F1 source controls; no archive bodies, operational inputs or proof execution.
import { describe, it, expect } from "vitest";
import { buildAPNTPoolInboxCovenantV1, assembleAPNTPoolInboxCovenantV1, getAPNTPoolInboxCovenantSourceV1 } from "../src/apnt_pool_inbox_covenant_v1.js";
const parameters = () => ({ verdictCategoryWire32: new Uint8Array(32).fill(7), settlementLockingBytecode: Uint8Array.of(0xaa, 0x20, ...new Uint8Array(32).fill(9), 0x87) });
describe("F1 inbox source construction", () => {
  it("binds the refund delay and deployment lock deterministically", () => {
    const p = parameters(), first = buildAPNTPoolInboxCovenantV1(p);
    expect(first.refundDelayBlocks).toBe(1008);
    expect(buildAPNTPoolInboxCovenantV1(parameters())).toEqual(first);
    p.settlementLockingBytecode[2] = 8;
    expect(buildAPNTPoolInboxCovenantV1(p).codeSha256).not.toEqual(first.codeSha256);
  });
  it("rejects a non-P2SH32 settlement lock", () => {
    const p = parameters(); p.settlementLockingBytecode[0] = 0;
    expect(() => buildAPNTPoolInboxCovenantV1(p)).toThrowError(expect.objectContaining({ code: "pool-covenant-parameter" }));
  });
  it("refuses an unresolved source marker", () => {
    expect(() => assembleAPNTPoolInboxCovenantV1(getAPNTPoolInboxCovenantSourceV1() + "\n@F1_UNRESOLVED@", parameters())).toThrow(/marker/);
  });
});
