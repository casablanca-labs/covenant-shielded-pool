// Independently authored F1 source controls; no archive bodies, operational inputs or proof execution.
import { beforeAll, describe, it, expect } from "vitest";
import { buildAPNTPoolGenesisV1 } from "../src/apnt_pool_genesis_builder_v1.js";
describe("F1 genesis builder boundary", () => {
  it("returns only a failure code for malformed construction input", () => {
    expect(buildAPNTPoolGenesisV1(null)).toEqual({ valid: false, failureCode: "pool-shape" });
  });
  it("maps a clone-time accessor error to the canonical boundary failure", () => {
    let calls = 0; const value = {};
    Object.defineProperty(value, "funding", { enumerable: true, get() { calls++; throw new Error("synthetic clone-time error"); } });
    expect(buildAPNTPoolGenesisV1(value)).toEqual({ valid: false, failureCode: "pool-boundary" });
    expect(calls).toBe(1);
  });
});


import {
  decodeTransactionBch, encodeTransactionBch, generateSigningSerializationBch,
  hash160, hash256, secp256k1,
} from "@bitauth/libauth";
import { createHash } from "node:crypto";
import { createVirtualMachineBch2026Bchn } from "../src/apnt_pool_bchn_vm.js";
import { validateAPNTPoolGenesisV1 } from "../src/apnt_pool_genesis_v1.js";
import { buildAPNTPoolVerdictFactoryV1 } from "../src/apnt_pool_verdict_factory_v1.js";
import { replayAPNTPoolSettlementHistoryV1, replayAPNTPoolTreeHistoryV1 } from "../src/apnt_pool_settlement_history_v1.js";
import { devInstallationSelectionV1 } from "../src/apnt_pool_dev_verifier_installation_v1.js";
import type { APNTPoolGenesisBuildStepV1 } from "../src/apnt_pool_genesis_builder_v1.js";

// Disclosed synthetic, single-party, zero-value proof setup. These offline funding
// numbers are simulation inputs, never wallet funds or chain outpoints. This key
// is derived from a public test label and has no live authority. No loader, proof,
// native verifier, wallet or network is invoked by these construction controls.
const labelHash = (label: string) => new Uint8Array(createHash("sha256").update("F1 synthetic construction: " + label).digest());
const joinBytes = (...parts: Uint8Array[]) => Uint8Array.from(parts.flatMap(part => [...part]));
function decoded<T>(value: T | string): T {
  if (typeof value === "string") throw new Error("synthetic transaction codec refused");
  return value;
}
function prepareSyntheticGenesis() {
  const key = labelHash("public deployer key"), pub = decoded(secp256k1.derivePublicKeyCompressed(key));
  const lock = joinBytes(Uint8Array.of(0x76, 0xa9, 0x14), hash160(pub), Uint8Array.of(0x88, 0xac));
  const input = {
    network: "chipnet",
    funding: { txidDisplay32: labelHash("unfunded outpoint"), index: 1, valueSats: 1_500_000n, lockingBytecode: lock, unlockingBytes: 100 },
    parameters: { rangeGenesisLog2: 3, rootCopyCount: 3,
      values: { rangeRecordSats: 1_000n, treeUpdateSats: 2_000n, rootCopySats: 1_000n, foldBountySats: 20_000n } },
    policy: { feeSatsPerByte: 2n, dustRelaySatsPerKb: 1_000n },
    verifierFactory: { tokens: [{ capability: "minting", commitment: new Uint8Array(0), valueSats: 10_000n }], redeemBytecode: null as Uint8Array | null },
    signedTransactions: [] as Uint8Array[],
  };
  const steps: APNTPoolGenesisBuildStepV1[] = [];
  for (let round = 0; round < 6; round++) {
    const result = buildAPNTPoolGenesisV1(input);
    if (!result.valid) throw new Error("synthetic builder refused: " + result.failureCode);
    if (result.state === "complete") return { complete: result, steps, input };
    if (result.state === "factory") {
      input.verifierFactory.redeemBytecode = buildAPNTPoolVerdictFactoryV1({
        network: result.factoryContext.network,
        verdictCategoryWire32: result.factoryContext.verdictCategoryWire32,
        settlementLockingBytecode: result.factoryContext.settlementLockingBytecode,
      }).redeemBytecode;
      continue;
    }
    const tx = decoded(decodeTransactionBch(result.step.unsignedTransaction));
    const sourceOutputs = result.step.sourceOutputs.map(output => ({ lockingBytecode: output.lockingBytecode, valueSatoshis: output.valueSats }));
    for (let inputIndex = 0; inputIndex < tx.inputs.length; inputIndex++) {
      const preimage = generateSigningSerializationBch({ transaction: tx, sourceOutputs, inputIndex }, {
        coveredBytecode: lock, signingSerializationType: Uint8Array.of(0x41),
      });
      const signature = decoded(secp256k1.signMessageHashSchnorr(key, hash256(preimage)));
      tx.inputs[inputIndex]!.unlockingBytecode = joinBytes(Uint8Array.of(65), signature, Uint8Array.of(0x41, 33), pub);
    }
    steps.push(result.step);
    input.signedTransactions.push(encodeTransactionBch(tx));
  }
  throw new Error("synthetic construction did not finish its finite steps");
}

describe("F1 synthetic genesis construction and history", () => {
  let prepared: ReturnType<typeof prepareSyntheticGenesis>;
  beforeAll(() => { prepared = prepareSyntheticGenesis(); });
  it("completes four staged transactions and passes the revision two genesis audit", () => {
    const { complete, steps } = prepared;
    expect(steps.map(step => step.name)).toEqual(["seed-verdict", "seed-range", "seed-root", "genesis"]);
    expect(complete.transactions).toHaveLength(4);
    const audit = validateAPNTPoolGenesisV1({ artifact: complete.artifact, genesisTransactions: complete.genesisTransactions }, 2);
    expect(audit.valid).toBe(true);
    if (!audit.valid) return;
    expect(audit.rangeRecords66).toHaveLength(8);
    expect(audit.inbox).not.toBeNull();
    expect(complete.transactions.every((tx, index) => tx.bytes === steps[index]!.signedBytes && tx.feeSats === steps[index]!.feeSats)).toBe(true);
  });
  it("verifies every synthetic signed transaction in the standard and consensus BCHN accounting VMs", () => {
    for (const standard of [true, false]) {
      const vm = createVirtualMachineBch2026Bchn(standard);
      prepared.steps.forEach((step, index) => {
        const transaction = decoded(decodeTransactionBch(prepared.complete.transactions[index]!.transaction));
        const sourceOutputs = step.sourceOutputs.map(output => ({ lockingBytecode: output.lockingBytecode, valueSatoshis: output.valueSats }));
        expect(vm.verify({ transaction, sourceOutputs })).toBe(true);
      });
    }
  });
  it("replays the audited genesis into the initial range and empty tree histories", () => {
    const { complete } = prepared;
    const transactions = complete.genesisTransactions.map((transaction, position) => ({ transaction, height: 1, position }));
    const history = replayAPNTPoolSettlementHistoryV1({ artifact: complete.artifact, transactions }, 2);
    expect(history.valid).toBe(true);
    if (!history.valid) return;
    expect(history.liveRecords).toHaveLength(8);
    expect(history.settlements).toHaveLength(0);
    const tree = replayAPNTPoolTreeHistoryV1({ artifact: complete.artifact, transactions }, 2);
    expect(tree.valid).toBe(true);
    if (!tree.valid) return;
    expect(tree.folds).toHaveLength(0);
    expect(tree.leaves32).toHaveLength(0);
  });
  it("refuses a genesis history with an omitted transaction instead of inventing initial state", () => {
    const { complete } = prepared;
    const transactions = complete.genesisTransactions.slice(1).map((transaction, position) => ({ transaction, height: 1, position }));
    const history = replayAPNTPoolSettlementHistoryV1({ artifact: complete.artifact, transactions }, 2);
    expect(history.valid).toBe(false);
    expect(history.liveRecords).toBeNull();
  });
  it("refuses a changed signed seed and its invalid signature in the VM", () => {
    const signed: Uint8Array[] = prepared.input.signedTransactions.map(bytes => bytes.slice());
    const tx = decoded(decodeTransactionBch(signed[0]!));
    tx.outputs[0]!.valueSatoshis += 1n;
    signed[0] = encodeTransactionBch(tx);
    const result = buildAPNTPoolGenesisV1({ ...prepared.input, signedTransactions: signed });
    expect(result.valid).toBe(false);
    const sourceOutputs = prepared.steps[0]!.sourceOutputs.map(output => ({ lockingBytecode: output.lockingBytecode, valueSatoshis: output.valueSats }));
    expect(createVirtualMachineBch2026Bchn(false).verify({ transaction: tx, sourceOutputs })).not.toBe(true);
  });
  it("refuses a caller constructed installation handle without loading absent later stage artifacts", () => {
    let refusal: unknown;
    try { devInstallationSelectionV1({}); } catch (error) { refusal = error; }
    expect(refusal).toMatchObject({ code: "dev-zero-conf-installation" });
  });
});
