// Independently authored F1 source controls; no archive bodies, operational inputs or proof execution.
import { describe, it, expect } from "vitest";
import { getAPNTPoolTreeCovenantSourceV1, assembleAPNTPoolPendingBatchCovenantV1, deriveAPNTPoolPendingBatchLayoutV1 } from "../src/apnt_pool_tree_covenants_v1.js";
const source = getAPNTPoolTreeCovenantSourceV1("pendingBatch");
const rootCategoryWire32 = new Uint8Array(32).fill(7);
describe("F1 pending-batch source construction", () => {
  it("reconstructs the redeem from the derived digest-independent layout", () => {
    const leafListDigest32 = new Uint8Array(32).fill(11);
    const layout = deriveAPNTPoolPendingBatchLayoutV1(source, { rootCategoryWire32 });
    const built = assembleAPNTPoolPendingBatchCovenantV1(source, { rootCategoryWire32, leafListDigest32 });
    expect(built.redeemBytecode).toEqual(Uint8Array.of(...layout.head, ...leafListDigest32, ...layout.tail));
  });
  it("binds the leaf-list digest in the resulting lock", () => {
    const a = assembleAPNTPoolPendingBatchCovenantV1(source, { rootCategoryWire32, leafListDigest32: new Uint8Array(32).fill(11) });
    const b = assembleAPNTPoolPendingBatchCovenantV1(source, { rootCategoryWire32, leafListDigest32: new Uint8Array(32).fill(12) });
    expect(a.lockingBytecode).not.toEqual(b.lockingBytecode);
  });
  it("refuses an undersized digest", () => {
    expect(() => assembleAPNTPoolPendingBatchCovenantV1(source, { rootCategoryWire32, leafListDigest32: new Uint8Array(31) })).toThrowError(expect.objectContaining({ code: "pool-covenant-parameter" }));
  });
});
