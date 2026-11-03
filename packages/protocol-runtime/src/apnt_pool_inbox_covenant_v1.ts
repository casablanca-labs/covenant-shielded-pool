import { readFileSync } from "node:fs";

import { bytesToHex, type Bytes32 } from "./bytes.js";
import { compileApntCashAssemblySourceV0, encodeScriptNumberPush, pushScriptData } from "./apnt_cashassembly_compiler_v0.js";
import { decodeAPNTPoolActionRecordV1 } from "./apnt_pool_action_record_v1.js";
import {
  APNT_POOL_FAILURE_V1 as F, APNT_POOL_V1_MAX_MONEY_SATS, pool32, poolAnyBytes,
  poolBoundary, poolConcat, poolRecord, poolRequire, poolSha256, poolMoneyU64le,
} from "./apnt_pool_contract_v1.js";

/** The block-based BIP68 refund delay; the local ledger or node checks UTXO age. */
export const APNT_POOL_V1_INBOX_REFUND_DELAY_BLOCKS = 1008;
export const APNT_POOL_V1_INBOX_DATA_BYTES = 89;
const INBOX_REDEEM_MAXIMUM_BYTES = 520; // One redeem push in a BCH unlocking script.
const P2SH32_BYTES = 35;
const SOURCE_FILE = "apnt_pool_inbox_v1.casm";

export type APNTPoolInboxCovenantParametersV1 = Readonly<{
  verdictCategoryWire32: Uint8Array;
  settlementLockingBytecode: Uint8Array;
}>;

export type APNTPoolInboxCovenantV1 = Readonly<{
  /** Deployment-specific CODE, without the record's data push. */
  codeBytecode: Uint8Array;
  codeSha256: Bytes32;
  refundDelayBlocks: typeof APNT_POOL_V1_INBOX_REFUND_DELAY_BLOCKS;
}>;

export type APNTPoolInboxLockV1 = Readonly<{
  data89: Uint8Array;
  redeemBytecode: Uint8Array;
  lockingBytecode: Uint8Array;
}>;

export function getAPNTPoolInboxCovenantSourceV1(): string {
  return readFileSync(new URL(`./cashassembly/${SOURCE_FILE}`, import.meta.url), "utf8");
}

const casmPush = (bytes: Uint8Array): string => `0x${bytesToHex(pushScriptData(bytes))}`;
const casmNumber = (value: number): string => `0x${bytesToHex(encodeScriptNumberPush(value))}`;

/** Assemble the reviewed ARCH-280 A source. A malformed source is a builder failure. */
export function assembleAPNTPoolInboxCovenantV1(source: string, parameters: unknown): APNTPoolInboxCovenantV1 {
  [parameters] = poolBoundary([parameters]);
  const input = poolRecord(parameters, ["verdictCategoryWire32", "settlementLockingBytecode"], F.COVENANT_PARAMETER);
  const verdict = pool32(input.verdictCategoryWire32, F.COVENANT_PARAMETER);
  const settlementLock = poolAnyBytes(input.settlementLockingBytecode, F.COVENANT_PARAMETER);
  poolRequire(settlementLock.length === P2SH32_BYTES && settlementLock[0] === 0xaa && settlementLock[1] === 0x20 && settlementLock[34] === 0x87, F.COVENANT_PARAMETER);
  if (typeof source !== "string") throw new Error("APNTPoolInboxCovenantV1 template is not a string");
  const compile = (redeemLength: number): Uint8Array => {
    let text = source;
    for (const [marker, token] of [
      ["@VERDICT_CATEGORY_PUSH@", casmPush(verdict)],
      ["@SETTLEMENT_LOCK_PUSH@", casmPush(settlementLock)],
      ["@REDEEM_LENGTH_PUSH@", casmNumber(redeemLength)],
      ["@REFUND_DELAY_PUSH@", casmNumber(APNT_POOL_V1_INBOX_REFUND_DELAY_BLOCKS)],
    ] as const) text = text.split(marker).join(token);
    const leftover = /@[A-Z0-9_]+@/u.exec(text);
    if (leftover !== null) throw new Error(`APNTPoolInboxCovenantV1 unreplaced marker ${leftover[0]}`);
    return compileApntCashAssemblySourceV0(text);
  };
  // The redeem length occupies the same minimal number-push width in both passes.
  const probe = compile(999);
  const redeemLength = 2 + APNT_POOL_V1_INBOX_DATA_BYTES + probe.length;
  if (redeemLength > INBOX_REDEEM_MAXIMUM_BYTES) throw new Error("APNTPoolInboxCovenantV1 redeem exceeds 520 bytes");
  const codeBytecode = compile(redeemLength);
  if (codeBytecode.length !== probe.length || 2 + APNT_POOL_V1_INBOX_DATA_BYTES + codeBytecode.length !== redeemLength) {
    throw new Error("APNTPoolInboxCovenantV1 redeem length changed during assembly");
  }
  return Object.freeze({
    codeBytecode,
    codeSha256: poolSha256(null, codeBytecode),
    refundDelayBlocks: APNT_POOL_V1_INBOX_REFUND_DELAY_BLOCKS,
  });
}

export function buildAPNTPoolInboxCovenantV1(parameters: unknown): APNTPoolInboxCovenantV1 {
  return assembleAPNTPoolInboxCovenantV1(getAPNTPoolInboxCovenantSourceV1(), parameters);
}

/** Build the one record-specific lock; caller must obtain CODE from the audited deployment. */
export function deriveAPNTPoolInboxLockV1(value: unknown): APNTPoolInboxLockV1 {
  [value] = poolBoundary([value]);
  const input = poolRecord(value, ["record314", "codeBytecode"], F.SHAPE);
  const record = decodeAPNTPoolActionRecordV1(input.record314);
  poolRequire(record.depositSats > 0n && record.depositSats <= APNT_POOL_V1_MAX_MONEY_SATS, F.RECORD_AMOUNT);
  const code = poolAnyBytes(input.codeBytecode, F.COVENANT_PARAMETER);
  poolRequire(code.length >= 1 && 2 + APNT_POOL_V1_INBOX_DATA_BYTES + code.length <= INBOX_REDEEM_MAXIMUM_BYTES, F.COVENANT_PARAMETER);
  const data89 = poolConcat(record.commitments32[0], record.packets16[0], poolMoneyU64le(record.depositSats, F.RECORD_AMOUNT), record.rerandomizedKeys33[0]);
  const redeemBytecode = poolConcat(pushScriptData(data89), code);
  const lockingBytecode = poolConcat(Uint8Array.of(0xaa, 0x20), poolSha256(null, poolSha256(null, redeemBytecode)), Uint8Array.of(0x87));
  return Object.freeze({ data89, redeemBytecode, lockingBytecode });
}
