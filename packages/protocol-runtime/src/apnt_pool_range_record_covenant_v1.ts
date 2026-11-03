import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { bytesToHex } from "./bytes.js";
import { compileApntCashAssemblySourceV0, pushScriptData } from "./apnt_cashassembly_compiler_v0.js";
import {
  APNT_POOL_FAILURE_V1 as F,
  pool32,
  poolAnyBytes,
  poolBoundary,
  poolConcat,
  poolEqual,
  poolRecord,
  poolRequire,
} from "./apnt_pool_contract_v1.js";

/**
 * APNT shielded pool v1: the builder of the nullifier range record's code
 * (task 3.1; ARCH-234 D2, ARCH-245). It compiles
 * `cashassembly/apnt_pool_range_record_v1.casm` with the deployment's
 * parameters into CODE, the part of every record's P2SH32 redeem below its
 * data push:
 *
 * ```text
 * redeem = push(lo‖hi) ‖ OP_DROP ‖ CODE     lock = OP_HASH256 <HASH256(redeem)> OP_EQUAL
 * ```
 *
 * so each record has its own lock (`deriveAPNTPoolRangeRecordLockV1` in
 * `apnt_pool_range_record_v1.ts`). CODE checks only the settlement authority;
 * the insertion is the settlement covenant's check 4. The source explains
 * every check.
 *
 * Locking-template construction only. Executing it against the BCH 2026 VMs
 * is `@bch-cloak/reference-aggregator`'s
 * (`apnt_pool_range_record_v1_local_vm.test.ts`,
 * `apnt_pool_settlement_covenant_v1_local_vm.test.ts`), the package that
 * depends on Libauth, as for the repository's other covenants. Nothing here is
 * proof verification, chain validation, wallet acceptance or spendability, and
 * no deployment is pinned: the parameters are a deployment's to choose.
 *
 * Source format. One section of CashAssembly, compiled by the repository's
 * CashAssembly compiler after these parameter markers are replaced:
 *
 * - `@VERDICT_CATEGORY_PUSH@`: the verdict category in wire order, with no
 *   capability byte;
 * - `@SETTLEMENT_LOCK_PUSH@`: the pool settlement locking bytecode.
 *
 * The settlement covenant rebuilds CODE at run time from its own lock and
 * category, so CODE must embed each constant once, the lock first:
 * {@link deriveAPNTPoolRangeRecordLayoutV1} reads that layout from a source's
 * compiled bytes and refuses any other shape.
 */

export type APNTPoolRangeRecordCovenantParametersV1 = Readonly<{
  /** The verdict category `V`, wire order (the genesis txid reversed from display order). */
  verdictCategoryWire32: Uint8Array;
  /** The pool settlement locking bytecode that input 0 must be under: a P2SH32 lock. */
  settlementLockingBytecode: Uint8Array;
}>;

export type APNTPoolRangeRecordCovenantV1 = Readonly<{
  /** CODE: the record redeem below its data push, `push(lo‖hi) ‖ OP_DROP ‖ CODE`. */
  codeBytecode: Uint8Array;
}>;

/** CODE's layout around its two embedded constants: `PREFIX ‖ settlement lock ‖ MIDDLE ‖ V ‖ TAIL`. */
export type APNTPoolRangeRecordLayoutV1 = Readonly<{ prefix: Uint8Array; middle: Uint8Array; tail: Uint8Array }>;

const SOURCE_FILE = "apnt_pool_range_record_v1.casm";
const UNREPLACED_MARKER = /@[A-Z0-9_]+@/u;
/** A P2SH32 locking bytecode: `OP_HASH256 <32 bytes> OP_EQUAL`. */
const P2SH32_BYTES = 35;
/** CODE stays well inside a 520-byte redeem push with its 67-byte data push and OP_DROP. */
const MAXIMUM_CODE_BYTES = 400;

/** The CashAssembly source with its parameter markers, as shipped beside the built module. */
export function getAPNTPoolRangeRecordCovenantSourceV1(): string {
  return readFileSync(new URL(`./cashassembly/${SOURCE_FILE}`, import.meta.url), "utf8");
}

const casmPush = (bytes: Uint8Array): string => `0x${bytesToHex(pushScriptData(bytes))}`;

function templateError(message: string): never {
  throw new Error(`APNTPoolRangeRecordCovenantV1 template ${message}`);
}

function compile(source: unknown, verdict: Uint8Array, settlementLock: Uint8Array): Uint8Array {
  if (typeof source !== "string") templateError("is not a string");
  let out = source;
  for (const [marker, token] of [["@VERDICT_CATEGORY_PUSH@", casmPush(verdict)], ["@SETTLEMENT_LOCK_PUSH@", casmPush(settlementLock)]] as const) {
    out = out.split(marker).join(token);
  }
  const leftover = UNREPLACED_MARKER.exec(out);
  if (leftover !== null) templateError(`leaves marker ${leftover[0]} unreplaced`);
  const code = compileApntCashAssemblySourceV0(out);
  if (code.length < 1 || code.length > MAXIMUM_CODE_BYTES) templateError("compiles to a code outside 1..400 bytes");
  return code;
}

function occurrences(haystack: Uint8Array, needle: Uint8Array): number[] {
  const found: number[] = [];
  for (let at = 0; at + needle.length <= haystack.length; at += 1) {
    if (poolEqual(haystack.subarray(at, at + needle.length), needle)) found.push(at);
  }
  return found;
}

/**
 * The layout `PREFIX ‖ L ‖ MIDDLE ‖ V ‖ TAIL` of a range-record source's CODE,
 * found by compiling it with two sentinel pairs: each constant must appear
 * exactly once, the lock before the category, at the same offsets in both. A
 * source of any other shape is refused, since the settlement could not
 * rebuild its CODE.
 */
export function deriveAPNTPoolRangeRecordLayoutV1(source: string): APNTPoolRangeRecordLayoutV1 {
  const sentinel = (tag: string) => {
    const lock = poolConcat(Uint8Array.of(0xaa, 0x20), new Uint8Array(createHash("sha256").update(`range-record-layout:${tag}:lock`).digest()), Uint8Array.of(0x87));
    const verdict = new Uint8Array(createHash("sha256").update(`range-record-layout:${tag}:verdict`).digest());
    const code = compile(source, verdict, lock);
    const lockAt = occurrences(code, lock);
    const verdictAt = occurrences(code, verdict);
    if (lockAt.length !== 1 || verdictAt.length !== 1 || lockAt[0]! + lock.length > verdictAt[0]!) templateError("does not embed its lock and category once each, lock first");
    return { prefix: code.slice(0, lockAt[0]), middle: code.slice(lockAt[0]! + lock.length, verdictAt[0]), tail: code.slice(verdictAt[0]! + verdict.length) };
  };
  const a = sentinel("a");
  const b = sentinel("b");
  if (!poolEqual(a.prefix, b.prefix) || !poolEqual(a.middle, b.middle) || !poolEqual(a.tail, b.tail)) templateError("layout depends on its constants");
  return Object.freeze(a);
}

/**
 * Compiles a range-record source (the shipped one, or a variant of it) with a
 * deployment's parameters. Parameters are refused with
 * `pool-covenant-parameter`; a malformed template throws.
 */
export function assembleAPNTPoolRangeRecordCovenantV1(source: string, parameters: unknown): APNTPoolRangeRecordCovenantV1 {
  [parameters] = poolBoundary([parameters]);
  const input = poolRecord(parameters, ["verdictCategoryWire32", "settlementLockingBytecode"], F.COVENANT_PARAMETER);
  const verdict = pool32(input.verdictCategoryWire32, F.COVENANT_PARAMETER);
  const settlementLock = poolAnyBytes(input.settlementLockingBytecode, F.COVENANT_PARAMETER);
  poolRequire(settlementLock.length === P2SH32_BYTES, F.COVENANT_PARAMETER);
  return Object.freeze({ codeBytecode: compile(source, verdict, settlementLock) });
}

/** The range record's code for a deployment's parameters, from the shipped source. */
export function buildAPNTPoolRangeRecordCovenantV1(parameters: unknown): APNTPoolRangeRecordCovenantV1 {
  return assembleAPNTPoolRangeRecordCovenantV1(getAPNTPoolRangeRecordCovenantSourceV1(), parameters);
}
