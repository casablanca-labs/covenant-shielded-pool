import { readFileSync } from "node:fs";

import { bytesToHex, type Bytes32 } from "./bytes.js";
import { compileApntCashAssemblySourceV0, pushScriptData } from "./apnt_cashassembly_compiler_v0.js";
import {
  APNT_POOL_FAILURE_V1 as F, pool32, poolAnyBytes, poolBoundary, poolConcat,
  poolEqual, poolRecord, poolRequire, poolSha256,
} from "./apnt_pool_contract_v1.js";

/** Chipnet simulated single-party setup. This build is for explicitly labelled zero-value tests only. */
export const APNT_POOL_V1_VERDICT_FACTORY_PIN = Object.freeze({
  sourceSha256: "b52a29b9cedea9e878a53f340190fe46d97c2868de1a6c1516979ba8fc916805",
  graphRootLockingBytecode: "aa20274d14cb9777914073ff2e53d96af531d9712f50898239188f45223e0d31855387",
  /** SP1 6.3.1 recursion VKey root, in the little-endian scalar order read by the verifier graph. */
  recursionRootLe32: "5253f257d0403257286d46defa5bc098b01408cd500ec06c4d9798e90e852f00",
  programVkeyHash: "00a69d739feae9fecf1ad3db30a73f967912fda951c849e374492f1a14fd7fed",
  /** Reference Chipnet pool deployment from apnt-pool-v1-vectors.json, K=3, P_fold=20,000. */
  referenceVerdictCategoryWire32: "636ab47e7c13bf0ea34d1481fc08e2a3327ce63cfdc055511632019bcc0abaa7",
  referenceSettlementLockingBytecode: "aa2051b470922c2679acd36518d4a5c0e02b9802bf35f69103d98289c2d68f6c629587",
  referenceRedeemSha256: "33eb3d848ec5bbab25c766ae5f5502a701d0238b4bc02be1bcbffb292d56ec3b",
  referenceRedeemBytecode: "c05b9dc35c9dc4535ba569c0ce21636ab47e7c13bf0ea34d1481fc08e2a3327ce63cfdc055511632019bcc0abaa7028800c723aa20274d14cb9777914073ff2e53d96af531d9712f50898239188f45223e0d318553878800006576d1c0ce01207f758876d3009d76cd23aa2051b470922c2679acd36518d4a5c0e02b9802bf35f69103d98289c2d68f6c6295878876cc02e803a26976d28201209d7b7c7e7c8b76c452949c6675a8517f7c011f847c7ebc024c847c7e205253f257d0403257286d46defa5bc098b01408cd500ec06c4d9798e90e852f007e00ca01427f7588c45294d1c0ce88c45294cdc0c788c45294d20088c45294d3009dc45294ccc0c6a269c45194d1827791",
  graphRecord: "tools/pool-onetx-verifier-prototype/pool-key/chipnet-zero-value-rev3-graph-v1.json",
  inputs: 11,
  maximumVerdicts: 8,
  verdictFloorSats: 1000,
});

/** Separate local 0x99 zero-value build. The Chipnet pin above remains frozen. */
export const APNT_POOL_V1_LOCAL_VERDICT_FACTORY_PIN = Object.freeze({
  sourceSha256: APNT_POOL_V1_VERDICT_FACTORY_PIN.sourceSha256,
  graphRootLockingBytecode: "aa207279097d5add3d3bde8044526a79be41415946596725f6681cf3c788cbc5cad187",
  recursionRootLe32: APNT_POOL_V1_VERDICT_FACTORY_PIN.recursionRootLe32,
  programVkeyHash: "008b67415acd3c7ae6e9c2ad0887a6ae6a322c4b1da8b97670b217255f0067ca",
  referenceVerdictCategoryWire32: "636ab47e7c13bf0ea34d1481fc08e2a3327ce63cfdc055511632019bcc0abaa7",
  referenceSettlementLockingBytecode: "aa2098264081b56af8a6774212ea2cefe5ff72b77f85fd25a2d4644e51f8b3b7de1a87",
  referenceRedeemSha256: "c9503268bc43b4276ba371005f9c499bd7ac6476c934f3911075995902026081",
  referenceRedeemBytecode: "c05b9dc35c9dc4535ba569c0ce21636ab47e7c13bf0ea34d1481fc08e2a3327ce63cfdc055511632019bcc0abaa7028800c723aa207279097d5add3d3bde8044526a79be41415946596725f6681cf3c788cbc5cad1878800006576d1c0ce01207f758876d3009d76cd23aa2098264081b56af8a6774212ea2cefe5ff72b77f85fd25a2d4644e51f8b3b7de1a878876cc02e803a26976d28201209d7b7c7e7c8b76c452949c6675a8517f7c011f847c7ebc024c847c7e205253f257d0403257286d46defa5bc098b01408cd500ec06c4d9798e90e852f007e00ca01427f7588c45294d1c0ce88c45294cdc0c788c45294d20088c45294d3009dc45294ccc0c6a269c45194d1827791",
  graphRecord: "tools/pool-onetx-verifier-prototype/pool-key/local-zero-value-v1-graph.json",
  inputs: APNT_POOL_V1_VERDICT_FACTORY_PIN.inputs,
  maximumVerdicts: APNT_POOL_V1_VERDICT_FACTORY_PIN.maximumVerdicts,
  verdictFloorSats: APNT_POOL_V1_VERDICT_FACTORY_PIN.verdictFloorSats,
});

export type APNTPoolVerdictFactoryV1 = Readonly<{
  redeemBytecode: Uint8Array;
  lockingBytecode: Uint8Array;
  redeemSha256: Bytes32;
}>;

const fromHex = (hex: string): Uint8Array => Uint8Array.from(Buffer.from(hex, "hex"));
const casmPush = (bytes: Uint8Array): string => `0x${bytesToHex(pushScriptData(bytes))}`;
const hash256 = (bytes: Uint8Array): Uint8Array => poolSha256(null, poolSha256(null, bytes));

export function getAPNTPoolVerdictFactorySourceV1(): string {
  const source = readFileSync(new URL("./cashassembly/apnt_pool_verdict_factory_v1.casm", import.meta.url), "utf8");
  if (bytesToHex(poolSha256(null, new TextEncoder().encode(source))) !== APNT_POOL_V1_VERDICT_FACTORY_PIN.sourceSha256) {
    throw new Error("APNT pool verdict factory source pin mismatch");
  }
  return source;
}

/** Assemble only the pinned pool mode. The graph root fixes the program key and the verifier's full script chain. */
export function assembleAPNTPoolVerdictFactoryV1(source: string, parameters: unknown): APNTPoolVerdictFactoryV1 {
  [parameters] = poolBoundary([parameters]);
  const input = poolRecord(parameters, ["network", "verdictCategoryWire32", "settlementLockingBytecode"], F.COVENANT_PARAMETER);
  poolRequire(input.network === "chipnet" || input.network === "local", F.COVENANT_PARAMETER);
  const verdict = pool32(input.verdictCategoryWire32, F.COVENANT_PARAMETER);
  const settlementLock = poolAnyBytes(input.settlementLockingBytecode, F.COVENANT_PARAMETER);
  poolRequire(settlementLock.length === 35 && settlementLock[0] === 0xaa && settlementLock[1] === 0x20 && settlementLock[34] === 0x87, F.COVENANT_PARAMETER);
  if (typeof source !== "string") throw new Error("APNT pool verdict factory source is not a string");
  const pin = { chipnet: APNT_POOL_V1_VERDICT_FACTORY_PIN, local: APNT_POOL_V1_LOCAL_VERDICT_FACTORY_PIN }[input.network as "chipnet" | "local"];
  const markers: Readonly<Record<string, string>> = {
    "@N@": String(pin.inputs),
    "@N_PLUS_1@": String(pin.inputs + 1),
    "@VERDICT_FLOOR@": String(pin.verdictFloorSats),
    "@OUTPUT_COUNT_CHECK@": `<3> <${String(pin.maximumVerdicts + 3)}> OP_WITHIN OP_VERIFY`,
    "@M_VALUE@": "OP_TXOUTPUTCOUNT <2> OP_SUB",
    "@M_PLUS_1_VALUE@": "OP_TXOUTPUTCOUNT <1> OP_SUB",
    "@V_MINTING_PUSH@": casmPush(poolConcat(verdict, Uint8Array.of(0x02))),
    "@GRAPH_ROOT_PUSH@": casmPush(fromHex(pin.graphRootLockingBytecode)),
    "@SETTLEMENT_LOCK_PUSH@": casmPush(settlementLock),
    "@S3_LE_PUSH@": casmPush(fromHex(pin.recursionRootLe32)),
    "@COMMITMENT_SIZE_CHECK@": "OP_SIZE <32> OP_NUMEQUALVERIFY",
    "@DIGEST@": "OP_SHA256",
    "@LOOP_INIT@": "<0> <0>",
    "@ACCUMULATE@": "OP_ROT OP_SWAP OP_CAT OP_SWAP",
  };
  let text = source;
  for (const [marker, replacement] of Object.entries(markers)) text = text.split(marker).join(replacement);
  if (/@[A-Z_0-9]+@/u.test(text.replace(/\/\/.*$/gmu, ""))) throw new Error("APNT pool verdict factory has an unreplaced marker");
  const redeemBytecode = compileApntCashAssemblySourceV0(text);
  const lockingBytecode = poolConcat(Uint8Array.of(0xaa, 0x20), hash256(redeemBytecode), Uint8Array.of(0x87));
  const redeemSha256 = poolSha256(null, redeemBytecode);
  if (poolEqual(verdict, fromHex(pin.referenceVerdictCategoryWire32)) && poolEqual(settlementLock, fromHex(pin.referenceSettlementLockingBytecode))) {
    if (!poolEqual(redeemBytecode, fromHex(pin.referenceRedeemBytecode)) || !poolEqual(redeemSha256, fromHex(pin.referenceRedeemSha256))) {
      throw new Error("APNT pool verdict factory reference bytecode pin mismatch");
    }
  }
  return Object.freeze({ redeemBytecode, lockingBytecode, redeemSha256 });
}

export function buildAPNTPoolVerdictFactoryV1(parameters: unknown): APNTPoolVerdictFactoryV1 {
  const source = getAPNTPoolVerdictFactorySourceV1();
  return assembleAPNTPoolVerdictFactoryV1(source, parameters);
}
