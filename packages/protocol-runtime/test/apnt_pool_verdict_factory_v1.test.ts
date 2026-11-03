import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";

const tamperFactorySource = vi.hoisted(() => ({ enabled: false }));
vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  const readFileSync = ((path: unknown, ...rest: unknown[]) => {
    const source = (actual.readFileSync as any)(path, ...rest);
    return tamperFactorySource.enabled && String(path).endsWith("apnt_pool_verdict_factory_v1.casm")
      ? `${String(source)}\n// tampered by source-pin test\n` : source;
  }) as typeof actual.readFileSync;
  return { ...actual, default: { ...actual, readFileSync }, readFileSync };
});

import { buildAPNTPoolSettlementCovenantsV1 } from "../src/apnt_pool_settlement_covenant_v1.js";
import {
  APNT_POOL_V1_VERDICT_FACTORY_PIN as PIN,
  APNT_POOL_V1_LOCAL_VERDICT_FACTORY_PIN as LOCAL_PIN,
  assembleAPNTPoolVerdictFactoryV1,
  buildAPNTPoolVerdictFactoryV1,
  getAPNTPoolVerdictFactorySourceV1,
} from "../src/apnt_pool_verdict_factory_v1.js";

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");
const bin = (value: string) => Uint8Array.from(Buffer.from(value, "hex"));
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const vectors = JSON.parse(readFileSync(new URL("../test-vectors/apnt-pool-v1-vectors.json", import.meta.url), "utf8"));
const categories = vectors.reference.deploymentId.categoriesWire;
const settlement = buildAPNTPoolSettlementCovenantsV1({
  network: "chipnet", verdictCategoryWire32: bin(categories.verdict), rangeCategoryWire32: bin(categories.range),
  rootCategoryWire32: bin(categories.root), rootCopyCount: 3, rootCopySats: 1000n,
  foldBountySats: 20000n, recordValueSats: 1000n,
});
const parameters = { network: "chipnet", verdictCategoryWire32: bin(categories.verdict), settlementLockingBytecode: settlement.settlement.lockingBytecode };
const localSettlement = buildAPNTPoolSettlementCovenantsV1({
  network: "local", verdictCategoryWire32: bin(categories.verdict), rangeCategoryWire32: bin(categories.range),
  rootCategoryWire32: bin(categories.root), rootCopyCount: 3, rootCopySats: 1000n,
  foldBountySats: 20000n, recordValueSats: 1000n,
});
const localParameters = { ...parameters, network: "local", settlementLockingBytecode: localSettlement.settlement.lockingBytecode };
// Frozen deployment identities use their original parameter tuples. MAIN is
// independently regenerated and remains covered by the parameter-binding test.
const referenceParameters = {
  network: "chipnet", verdictCategoryWire32: bin(PIN.referenceVerdictCategoryWire32),
  settlementLockingBytecode: bin(PIN.referenceSettlementLockingBytecode),
};
const localReferenceParameters = {
  network: "local", verdictCategoryWire32: bin(LOCAL_PIN.referenceVerdictCategoryWire32),
  settlementLockingBytecode: bin(LOCAL_PIN.referenceSettlementLockingBytecode),
};

describe("ENG-615 pinned Chipnet pool-mode verdict factory", () => {
  it("rebuilds the pinned 264-byte redeem and P2SH32 identity for the reference deployment", () => {
    const source = getAPNTPoolVerdictFactorySourceV1();
    const built = buildAPNTPoolVerdictFactoryV1(referenceParameters);
    expect(sha256(new TextEncoder().encode(source))).toBe(PIN.sourceSha256);
    expect(built.redeemBytecode.length).toBe(264);
    expect(hex(built.redeemBytecode)).toBe(PIN.referenceRedeemBytecode);
    expect(hex(built.redeemSha256)).toBe(PIN.referenceRedeemSha256);
    expect(hex(built.lockingBytecode)).toBe("aa207ad634494ce3b869cc91aba653cf627f501cd417bc5f5256dd7b2e53e6b1082987");
    expect(hex(built.redeemBytecode)).toContain(PIN.graphRootLockingBytecode);
    expect(hex(built.redeemBytecode)).toContain(PIN.recursionRootLe32);
  });

  it("binds category and settlement while refusing a mainnet use of the Chipnet key", () => {
    const honest = buildAPNTPoolVerdictFactoryV1(parameters);
    const otherCategory = buildAPNTPoolVerdictFactoryV1({ ...parameters, verdictCategoryWire32: bin(categories.root) });
    const otherSettlement = buildAPNTPoolVerdictFactoryV1({ ...parameters, settlementLockingBytecode: otherCategory.lockingBytecode });
    expect(hex(otherCategory.redeemSha256)).not.toBe(hex(honest.redeemSha256));
    expect(hex(otherSettlement.redeemSha256)).not.toBe(hex(honest.redeemSha256));
    const local = buildAPNTPoolVerdictFactoryV1(localParameters);
    const otherLocalCategory = buildAPNTPoolVerdictFactoryV1({ ...localParameters, verdictCategoryWire32: bin(categories.root) });
    const otherLocalSettlement = buildAPNTPoolVerdictFactoryV1({ ...localParameters, settlementLockingBytecode: otherCategory.lockingBytecode });
    expect(hex(otherLocalCategory.redeemSha256)).not.toBe(hex(local.redeemSha256));
    expect(hex(otherLocalSettlement.redeemSha256)).not.toBe(hex(local.redeemSha256));
    expect(hex(local.redeemSha256)).not.toBe(hex(honest.redeemSha256));
    expect(() => buildAPNTPoolVerdictFactoryV1({ ...parameters, network: "mainnet" })).toThrow();
  });

  it("refuses a changed compiled redeem for the reference deployment even with the same parameters", () => {
    const source = getAPNTPoolVerdictFactorySourceV1();
    const altered = source.replace("OP_INPUTINDEX <@N@>", "OP_1 OP_DROP\nOP_INPUTINDEX <@N@>");
    expect(altered).not.toBe(source);
    expect(() => assembleAPNTPoolVerdictFactoryV1(altered, referenceParameters)).toThrow("reference bytecode pin mismatch");
  });

  it("refuses source text whose digest differs from the shipped source pin", () => {
    const honest = getAPNTPoolVerdictFactorySourceV1();
    const nonReference = { ...parameters, verdictCategoryWire32: bin(categories.root) };
    expect(hex(buildAPNTPoolVerdictFactoryV1(nonReference).redeemBytecode)).not.toBe(PIN.referenceRedeemBytecode);
    tamperFactorySource.enabled = true;
    try {
      expect(() => getAPNTPoolVerdictFactorySourceV1()).toThrow("source pin mismatch");
      expect(() => buildAPNTPoolVerdictFactoryV1(nonReference)).toThrow("source pin mismatch");
    } finally {
      tamperFactorySource.enabled = false;
    }
    expect(getAPNTPoolVerdictFactorySourceV1()).toBe(honest);
  });

  it("binds the pin literals to the committed verifier graph and canonical guest build records", () => {
    const graphPath = "tools/pool-onetx-verifier-prototype/pool-key/chipnet-zero-value-rev3-graph-v1.json";
    const canonicalPath = "tools/apnt-pool-aggregate-sp1/canonical-build/chipnet-zero-value-rev3-canonical-build-v1.json";
    const graph = JSON.parse(readFileSync(new URL(`../../../${graphPath}`, import.meta.url), "utf8"));
    const canonical = JSON.parse(readFileSync(new URL(`../../../${canonicalPath}`, import.meta.url), "utf8"));
    expect(PIN.graphRecord).toBe(graphPath);
    expect(graph.program.record).toBe(canonicalPath);
    expect(PIN.graphRootLockingBytecode).toBe(graph.graph.root);
    expect(PIN.recursionRootLe32).toBe(graph.wrapper.s3Le32);
    expect(PIN.programVkeyHash).toBe(graph.program.programVkeyHash);
    expect(PIN.programVkeyHash).toBe(canonical.record.programVkeyHash);
  });
});

describe("ENG-595 pinned local 0x99 verdict factory", () => {
  it("rebuilds a distinct reference factory from the local graph and settlement", () => {
    const local = buildAPNTPoolVerdictFactoryV1(localReferenceParameters);
    const chipnet = buildAPNTPoolVerdictFactoryV1(referenceParameters);
    expect(local.redeemBytecode.length).toBe(264);
    expect(hex(local.redeemBytecode)).toBe(LOCAL_PIN.referenceRedeemBytecode);
    expect(hex(local.redeemSha256)).toBe(LOCAL_PIN.referenceRedeemSha256);
    expect(hex(local.lockingBytecode)).toBe("aa20b1d3c898443cc2e01afb8a6d3415be526d63a5171e65932b3642bc50dd6f2a7287");
    expect(hex(local.redeemBytecode)).toContain(LOCAL_PIN.referenceSettlementLockingBytecode);
    expect(hex(local.redeemBytecode)).toContain(LOCAL_PIN.graphRootLockingBytecode);
    expect(hex(local.redeemBytecode)).not.toContain(PIN.graphRootLockingBytecode);
    expect(hex(chipnet.redeemBytecode)).toBe(PIN.referenceRedeemBytecode);
    expect(hex(local.redeemBytecode)).not.toBe(hex(chipnet.redeemBytecode));
  });

  it("checks local reference bytes and binds its graph to its own canonical guest record", () => {
    const source = getAPNTPoolVerdictFactorySourceV1();
    const altered = source.replace("OP_INPUTINDEX <@N@>", "OP_1 OP_DROP\nOP_INPUTINDEX <@N@>");
    expect(() => assembleAPNTPoolVerdictFactoryV1(altered, localReferenceParameters)).toThrow("reference bytecode pin mismatch");
    const graphPath = "tools/pool-onetx-verifier-prototype/pool-key/local-zero-value-v1-graph.json";
    const canonicalPath = "tools/apnt-pool-aggregate-local-sp1/canonical-build/local-zero-value-canonical-build-v1.json";
    const graph = JSON.parse(readFileSync(new URL(`../../../${graphPath}`, import.meta.url), "utf8"));
    const canonical = JSON.parse(readFileSync(new URL(`../../../${canonicalPath}`, import.meta.url), "utf8"));
    expect(LOCAL_PIN.graphRecord).toBe(graphPath);
    expect(graph.program.record).toBe(canonicalPath);
    expect(LOCAL_PIN.graphRootLockingBytecode).toBe(graph.graph.root);
    expect(LOCAL_PIN.recursionRootLe32).toBe(graph.wrapper.s3Le32);
    expect(LOCAL_PIN.programVkeyHash).toBe(graph.program.programVkeyHash);
    expect(LOCAL_PIN.programVkeyHash).toBe(canonical.record.programVkeyHash);
    expect(LOCAL_PIN.programVkeyHash).not.toBe(PIN.programVkeyHash);
    expect(() => buildAPNTPoolVerdictFactoryV1({ ...localParameters, network: "mainnet" })).toThrow();
  });
});
