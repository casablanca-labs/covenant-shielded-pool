// Zero-value fixture supply for the reviewed, network-bound pool verdict factory.
import { buildAPNTPoolVerdictFactoryV1 } from "../../packages/protocol-runtime/dist/index.js";

export const SHIPPED_FACTORY_TOKENS = Object.freeze([Object.freeze({ capability: "minting", commitment: new Uint8Array(0), valueSats: 10_000n })]);

export function shippedFactoryFor(network) {
  if (network !== "chipnet" && network !== "local") throw new Error("pool fixture factory network refused");
  return Object.freeze({
    tokens: SHIPPED_FACTORY_TOKENS,
    redeemFor: (context) => buildAPNTPoolVerdictFactoryV1({
      network,
      verdictCategoryWire32: context.verdictCategoryWire32,
      settlementLockingBytecode: context.settlementLockingBytecode,
    }).redeemBytecode,
    label: `PINNED ${network} VERDICT FACTORY - SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY`,
  });
}
