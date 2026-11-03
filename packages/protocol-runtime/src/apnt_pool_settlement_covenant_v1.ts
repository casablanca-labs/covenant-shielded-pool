import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { bytesToHex } from "./bytes.js";
import {
  compileApntCashAssemblySourceV0,
  concatBytes,
  pushScriptData,
} from "./apnt_cashassembly_compiler_v0.js";
import {
  APNT_POOL_FAILURE_V1 as F,
  APNT_POOL_V1_DOMAIN_TAGS as TAG,
  APNT_POOL_V1_MAX_MONEY_SATS,
  pool32,
  poolAnyBytes,
  poolBoundary,
  poolConcat,
  poolEqual,
  poolRecord,
  poolRequire,
  poolTagBytes,
} from "./apnt_pool_contract_v1.js";
import { deriveAPNTPoolDeploymentIdV1, type APNTPoolNetworkV1 } from "./apnt_pool_statement_v1.js";
import { deriveAPNTPoolPendingBatchLayoutV1, getAPNTPoolTreeCovenantSourceV1 } from "./apnt_pool_tree_covenants_v1.js";
import { deriveAPNTPoolRangeRecordLayoutV1, getAPNTPoolRangeRecordCovenantSourceV1 } from "./apnt_pool_range_record_covenant_v1.js";

/**
 * APNT shielded pool v1: builders of the pool settlement covenant and the
 * pool-coin covenant (task 3.4; design.md, "Settlement and the proof
 * verdict"). Each compiles its `cashassembly/*.casm` source, whose header
 * explains every check, with a deployment's parameters into a P2SH32 redeem
 * script and lock:
 *
 * - `apnt_pool_settlement_v1.casm`: the lock the verifier ladder's terminal
 *   verdict sits under; spending it settles a statement, checks 1–7 at
 *   input 0 (the pool has no meter or deposit cap: ARCH-196), the owners'
 *   signatures over the tag-authorization message `m` that binds each
 *   record's two discovery tags (HUM-75), the range records' insertion
 *   (check 4, ARCH-234 D2) and the batch's pending lock committing its leaf
 *   list (check 6, ARCH-236 F1; both ARCH-245);
 * - `apnt_pool_coin_v1.casm`: the lock of every pool coin, spendable only
 *   under the settlement authority.
 *
 * Lock wiring. The pool-coin, root-copy and range-record locks embed the
 * settlement lock, so the settlement lock embeds none of them. It embeds the
 * pending-batch redeem's layout `0x20 ‖ H_cm ‖ OP_DROP ‖ PCODE` (PCODE embeds
 * only the root category), the categories it identifies tokens by, and two
 * compiled layouts `PREFIX ‖ settlement lock ‖ MIDDLE ‖ verdict category ‖
 * TAIL`, from which it derives at run time the pool-coin lock and the range
 * record's code CODE (so each record's lock `P2SH32(push(lo‖hi) ‖ OP_DROP ‖
 * CODE)`). This module reads the three layouts from the pool-coin,
 * range-record and pending-batch sources' compiled bytes, so they cannot
 * drift apart.
 *
 * Locking-template construction only. Executing them against the BCH 2026 VMs
 * is `@bch-cloak/reference-aggregator`'s
 * (`apnt_pool_settlement_covenant_v1_local_vm.test.ts`). Nothing here is proof
 * verification, chain validation, wallet acceptance or spendability, and no
 * deployment is pinned.
 *
 * Source format. `//@function <id> <NAME>` sections and a `//@main` section,
 * which defines each function with `@FUNCTION_<id>_PUSH@ <id> OP_DEFINE`, each
 * compiled by the repository's CashAssembly compiler after its markers are
 * replaced; a source with no section header is all main (the pool coin).
 * Markers:
 *
 * - `@VERDICT_CATEGORY_PUSH@`, `@ROOT_CATEGORY_PUSH@`, `@RANGE_CATEGORY_PUSH@`:
 *   those categories in wire order, with no capability byte;
 * - `@RANGE_CATEGORY_MINTING_PUSH@`: the range category followed by `0x02`;
 * - `@STATEMENT_HEADER_PUSH@`: `"APNT-POOL-v1:statement" ‖ deployment_id`,
 *   the id derived with its `cat_meter` field as 32 zero bytes, the
 *   canonical encoding's form for a deployment without a meter, which every
 *   pool deployment now is;
 * - `@AUTH_TAG_PUSH@`: `"APNT-POOL-v1:action-auth"`;
 * - `@DT_AUTH_TAG_PUSH@`: `"APNT-POOL-v1:dt-auth"`, the tag-authorization
 *   message's tag (HUM-75): the owners sign `m`, not `ad`;
 * - `@PENDING_HEAD_PUSH@`, `@PENDING_TAIL_PUSH@`: the pending-batch redeem's
 *   layout pieces around `H_cm`;
 * - `@FOLD_BOUNTY_PUSH@`: `P_fold`, satoshis;
 * - `@RECORD_VALUE_PUSH@`: the satoshi value of every range record;
 * - `@POOL_COIN_PREFIX_PUSH@`, `@POOL_COIN_MIDDLE_PUSH@`,
 *   `@POOL_COIN_TAIL_PUSH@`: the pool-coin layout pieces;
 * - `@RECORD_SUFFIX_PREFIX_PUSH@` (`OP_DROP ‖ PREFIX`),
 *   `@RECORD_SUFFIX_MIDDLE_PUSH@`, `@RECORD_SUFFIX_TAIL_PUSH@`: the range
 *   record's layout pieces; `@RECORD_DATA_HEAD_PUSH@`: the opcode that pushes
 *   a record's 66 data bytes; `@RECORD_UNLOCKING_HEAD_PUSH@` and
 *   `@RECORD_UNLOCKING_HEAD_LENGTH@`: the bytes before the data in a record
 *   input's unlocking (the redeem push's opcode and length, then the data
 *   push's opcode) and their count;
 * - `@SETTLEMENT_LOCK_PUSH@` (pool coin only): the settlement locking bytecode.
 */

export type APNTPoolSettlementCovenantV1 = Readonly<{
  /** The P2SH32 redeem script. */
  redeemBytecode: Uint8Array;
  /** `OP_HASH256 <HASH256(redeem)> OP_EQUAL`. */
  lockingBytecode: Uint8Array;
}>;

export type APNTPoolSettlementCovenantKindV1 = "settlement" | "poolCoin";

export type APNTPoolSettlementCovenantParametersV1 = Readonly<{
  /** The deployment network; `local` is the zero-value-only local simulation deployment (ARCH-293). */
  network: APNTPoolNetworkV1;
  /** The verdict category `V`, wire order (the genesis txid reversed from display order). */
  verdictCategoryWire32: Uint8Array;
  /** The range category `R`, wire order. */
  rangeCategoryWire32: Uint8Array;
  /** The root category `T`, wire order. */
  rootCategoryWire32: Uint8Array;
  /** `K`, the root copies each fold mints: only bounds `P_fold` here. */
  rootCopyCount: number;
  /** The satoshi value of each root copy: only bounds `P_fold` here. */
  rootCopySats: bigint;
  /** `P_fold`, the least value of the pending output; above `K × rootCopySats` (ENG-339 interface rule 5). */
  foldBountySats: bigint;
  /** The satoshi value of every range record the settlement creates, from the deployment artifact. */
  recordValueSats: bigint;
}>;

/**
 * The sources one settlement build reads: its own, and the three whose
 * compiled layouts it embeds (the pool coin, the range record and the pending
 * batch), each the shipped source or a variant of it.
 */
export type APNTPoolSettlementSourcesV1 = Readonly<{ settlement: string; poolCoin: string; rangeRecord: string; pendingBatch: string }>;

export type APNTPoolCoinCovenantParametersV1 = Readonly<{
  /** The verdict category `V`, wire order. */
  verdictCategoryWire32: Uint8Array;
  /** The pool settlement locking bytecode that input 0 must be under. */
  settlementLockingBytecode: Uint8Array;
}>;

export type APNTPoolSettlementCovenantsV1 = Readonly<{
  settlement: APNTPoolSettlementCovenantV1;
  poolCoin: APNTPoolSettlementCovenantV1;
}>;

/** The pool-coin redeem's layout around its two embedded constants. */
export type APNTPoolCoinLayoutV1 = Readonly<{ prefix: Uint8Array; middle: Uint8Array; tail: Uint8Array }>;

const SOURCE_FILES: Readonly<Record<APNTPoolSettlementCovenantKindV1, string>> = {
  settlement: "apnt_pool_settlement_v1.casm",
  poolCoin: "apnt_pool_coin_v1.casm",
};
const FUNCTION_HEADER = /^\/\/@function (\d+) ([A-Z0-9_]+)$/u;
const MAIN_HEADER = "//@main";
const UNREPLACED_MARKER = /@[A-Z0-9_]+@/u;
const MAXIMUM_LOCKING_BYTECODE_BYTES = 10_000;
const MAXIMUM_ROOT_COPIES = 0xffff;
/** A P2SH32 locking bytecode: `OP_HASH256 <32 bytes> OP_EQUAL`. */
const P2SH32_BYTES = 35;

/** A covenant's CashAssembly source with its parameter markers, as shipped beside the built module. */
export function getAPNTPoolSettlementCovenantSourceV1(kind: APNTPoolSettlementCovenantKindV1): string {
  const file = SOURCE_FILES[kind];
  if (file === undefined) throw new Error("APNTPoolSettlementCovenantV1 unknown covenant kind");
  return readFileSync(new URL(`./cashassembly/${file}`, import.meta.url), "utf8");
}

const casmPush = (bytes: Uint8Array): string => `0x${bytesToHex(pushScriptData(bytes))}`;

const hash256 = (bytes: Uint8Array): Uint8Array =>
  new Uint8Array(createHash("sha256").update(createHash("sha256").update(bytes).digest()).digest());

function templateError(message: string): never {
  throw new Error(`APNTPoolSettlementCovenantV1 template ${message}`);
}

/** A source's function and main sections; a source with no section header is all main (the pool coin). */
function sectionsOf(source: string): { functions: string[]; main: string } {
  const lines = source.split(/\r?\n/u).map((line) => line.trim());
  if (!lines.some((line) => line === MAIN_HEADER || FUNCTION_HEADER.test(line))) return { functions: [], main: source };
  const functions: string[] = [];
  let main: string | null = null;
  let current: string[] | null = null;
  let currentId: number | "main" | null = null;
  const close = () => {
    if (current === null || currentId === null) return;
    if (currentId === "main") main = current.join("\n");
    else functions[currentId] = current.join("\n");
  };
  for (const line of source.split(/\r?\n/u)) {
    const trimmed = line.trim();
    const header = FUNCTION_HEADER.exec(trimmed);
    if (header !== null || trimmed === MAIN_HEADER) {
      if (currentId === "main") templateError("has a section after //@main");
      close();
      if (header !== null) {
        const id = Number(header[1]);
        if (id !== functions.length || functions[id] !== undefined) templateError(`defines function ${String(id)} out of order`);
        functions[id] = "";
        currentId = id;
      } else {
        currentId = "main";
      }
      current = [];
      continue;
    }
    if (current === null) {
      if (trimmed.length > 0 && !trimmed.startsWith("//")) templateError("has code before its first section");
      continue;
    }
    current.push(line);
  }
  close();
  if (main === null) templateError("has no //@main section");
  return { functions, main };
}

function substitute(section: string, markers: ReadonlyMap<string, string>): string {
  let out = section;
  for (const [marker, token] of markers) out = out.split(marker).join(token);
  const leftover = UNREPLACED_MARKER.exec(out);
  if (leftover !== null) templateError(`leaves marker ${leftover[0]} unreplaced`);
  return out;
}

function assemble(source: unknown, markers: ReadonlyMap<string, string>): APNTPoolSettlementCovenantV1 {
  if (typeof source !== "string") templateError("is not a string");
  const { functions, main } = sectionsOf(source);
  const withFunctions = new Map(markers);
  functions.forEach((body, id) => {
    withFunctions.set(`@FUNCTION_${String(id)}_PUSH@`, casmPush(compileApntCashAssemblySourceV0(substitute(body, markers))));
  });
  const redeemBytecode = compileApntCashAssemblySourceV0(substitute(main, withFunctions));
  poolRequire(redeemBytecode.length <= MAXIMUM_LOCKING_BYTECODE_BYTES, F.COVENANT_PARAMETER);
  const lockingBytecode = concatBytes([Uint8Array.of(0xaa), pushScriptData(hash256(redeemBytecode)), Uint8Array.of(0x87)]);
  return Object.freeze({ redeemBytecode, lockingBytecode });
}

function lockOf(value: unknown): Uint8Array {
  const lock = poolAnyBytes(value, F.COVENANT_PARAMETER);
  poolRequire(lock.length >= 1 && lock.length <= MAXIMUM_LOCKING_BYTECODE_BYTES, F.COVENANT_PARAMETER);
  return lock;
}

function coinMarkers(verdict: Uint8Array, settlementLock: Uint8Array): Map<string, string> {
  return new Map([
    ["@SETTLEMENT_LOCK_PUSH@", casmPush(settlementLock)],
    ["@VERDICT_CATEGORY_PUSH@", casmPush(verdict)],
  ]);
}

/** Compiles a pool-coin covenant source (the shipped one, or a variant). Parameters are refused with `pool-covenant-parameter`. */
export function assembleAPNTPoolCoinCovenantV1(source: string, parameters: unknown): APNTPoolSettlementCovenantV1 {
  [parameters] = poolBoundary([parameters]);
  const input = poolRecord(parameters, ["verdictCategoryWire32", "settlementLockingBytecode"], F.COVENANT_PARAMETER);
  const verdict = pool32(input.verdictCategoryWire32, F.COVENANT_PARAMETER);
  const settlementLock = lockOf(input.settlementLockingBytecode);
  poolRequire(settlementLock.length === P2SH32_BYTES, F.COVENANT_PARAMETER);
  return assemble(source, coinMarkers(verdict, settlementLock));
}

function occurrences(haystack: Uint8Array, needle: Uint8Array): number[] {
  const found: number[] = [];
  for (let at = 0; at + needle.length <= haystack.length; at += 1) {
    if (poolEqual(haystack.subarray(at, at + needle.length), needle)) found.push(at);
  }
  return found;
}

/**
 * The layout `PREFIX ‖ L ‖ MIDDLE ‖ V ‖ TAIL` of a pool-coin source's redeem,
 * found by compiling it with two sentinel pairs: each constant must appear
 * exactly once, the lock before the category, at the same offsets in both.
 * A source of any other shape is refused, since the settlement could not
 * derive its lock.
 */
export function deriveAPNTPoolCoinLayoutV1(poolCoinSource: string): APNTPoolCoinLayoutV1 {
  const sentinel = (tag: string) => {
    const lock = poolConcat(Uint8Array.of(0xaa, 0x20), new Uint8Array(createHash("sha256").update(`pool-coin-layout:${tag}:lock`).digest()), Uint8Array.of(0x87));
    const verdict = new Uint8Array(createHash("sha256").update(`pool-coin-layout:${tag}:verdict`).digest());
    const redeem = assemble(poolCoinSource, coinMarkers(verdict, lock)).redeemBytecode;
    const lockAt = occurrences(redeem, lock);
    const verdictAt = occurrences(redeem, verdict);
    if (lockAt.length !== 1 || verdictAt.length !== 1 || lockAt[0]! + lock.length > verdictAt[0]!) templateError("pool coin does not embed its lock and category once each, lock first");
    return {
      prefix: redeem.slice(0, lockAt[0]),
      middle: redeem.slice(lockAt[0]! + lock.length, verdictAt[0]),
      tail: redeem.slice(verdictAt[0]! + verdict.length),
    };
  };
  const a = sentinel("a");
  const b = sentinel("b");
  if (!poolEqual(a.prefix, b.prefix) || !poolEqual(a.middle, b.middle) || !poolEqual(a.tail, b.tail)) templateError("pool coin layout depends on its constants");
  return Object.freeze(a);
}

type Settlement = {
  network: APNTPoolNetworkV1;
  verdict: Uint8Array;
  range: Uint8Array;
  root: Uint8Array;
  foldBounty: bigint;
  recordValue: bigint;
};

function settlementOf(input: Readonly<Record<string, unknown>>): Settlement {
  const network = input.network;
  poolRequire(network === "chipnet" || network === "mainnet" || network === "local", F.COVENANT_PARAMETER);
  const verdict = pool32(input.verdictCategoryWire32, F.COVENANT_PARAMETER);
  const range = pool32(input.rangeCategoryWire32, F.COVENANT_PARAMETER);
  const root = pool32(input.rootCategoryWire32, F.COVENANT_PARAMETER);
  poolRequire(new Set([verdict, range, root].map(bytesToHex)).size === 3, F.COVENANT_PARAMETER);
  const copies = input.rootCopyCount;
  poolRequire(typeof copies === "number" && Number.isSafeInteger(copies) && copies >= 2 && copies <= MAXIMUM_ROOT_COPIES, F.COVENANT_PARAMETER);
  const copySats = input.rootCopySats;
  poolRequire(typeof copySats === "bigint" && copySats >= 1n && copySats <= APNT_POOL_V1_MAX_MONEY_SATS, F.COVENANT_PARAMETER);
  const foldBounty = input.foldBountySats;
  poolRequire(typeof foldBounty === "bigint" && foldBounty > BigInt(copies) * copySats && foldBounty <= APNT_POOL_V1_MAX_MONEY_SATS, F.COVENANT_PARAMETER);
  const recordValue = input.recordValueSats;
  poolRequire(typeof recordValue === "bigint" && recordValue >= 1n && recordValue <= APNT_POOL_V1_MAX_MONEY_SATS, F.COVENANT_PARAMETER);
  return { network, verdict, range, root, foldBounty, recordValue };
}

const SETTLEMENT_KEYS = [
  "network", "verdictCategoryWire32", "rangeCategoryWire32", "rootCategoryWire32",
  "rootCopyCount", "rootCopySats", "foldBountySats", "recordValueSats",
] as const;
/** A range record's data: `lo ‖ hi`, 66 bytes. */
const RECORD_DATA_BYTES = 66;
const OP_DROP = 0x75;

function sourcesOf(value: unknown): APNTPoolSettlementSourcesV1 {
  if (typeof value !== "object" || value === null) templateError("sources are not an object");
  const sources = value as Record<string, unknown>;
  for (const name of ["settlement", "poolCoin", "rangeRecord", "pendingBatch"]) {
    if (typeof sources[name] !== "string") templateError(`source ${name} is not a string`);
  }
  return sources as APNTPoolSettlementSourcesV1;
}

/**
 * Compiles a settlement covenant source (the shipped one, or a variant) with
 * the pool-coin, range-record and pending-batch sources whose layouts it
 * embeds. Parameters are refused with `pool-covenant-parameter`; a malformed
 * template throws.
 */
export function assembleAPNTPoolSettlementCovenantV1(sources: APNTPoolSettlementSourcesV1, parameters: unknown): APNTPoolSettlementCovenantV1 {
  const source = sourcesOf(sources);
  [parameters] = poolBoundary([parameters]);
  const input = poolRecord(parameters, SETTLEMENT_KEYS, F.COVENANT_PARAMETER);
  const s = settlementOf(input);
  const deploymentId = deriveAPNTPoolDeploymentIdV1({
    network: s.network, verdictCategoryWire32: s.verdict, rangeCategoryWire32: s.range,
    rootCategoryWire32: s.root, meterCategoryWire32: null,
  });
  const coin = deriveAPNTPoolCoinLayoutV1(source.poolCoin);
  const record = deriveAPNTPoolRangeRecordLayoutV1(source.rangeRecord);
  const pending = deriveAPNTPoolPendingBatchLayoutV1(source.pendingBatch, { rootCategoryWire32: s.root });
  // A record input's unlocking is push(push(data) ‖ OP_DROP ‖ CODE); every CODE of this layout has one length.
  const codeBytes = record.prefix.length + P2SH32_BYTES + record.middle.length + 32 + record.tail.length;
  const dataPush = pushScriptData(new Uint8Array(RECORD_DATA_BYTES));
  const unlocking = pushScriptData(new Uint8Array(dataPush.length + 1 + codeBytes));
  const unlockingHead = concatBytes([unlocking.slice(0, unlocking.length - dataPush.length - 1 - codeBytes), dataPush.slice(0, dataPush.length - RECORD_DATA_BYTES)]);
  const markers = new Map([
    ["@VERDICT_CATEGORY_PUSH@", casmPush(s.verdict)],
    ["@ROOT_CATEGORY_PUSH@", casmPush(s.root)],
    ["@RANGE_CATEGORY_PUSH@", casmPush(s.range)],
    ["@RANGE_CATEGORY_MINTING_PUSH@", casmPush(concatBytes([s.range, Uint8Array.of(0x02)]))],
    ["@STATEMENT_HEADER_PUSH@", casmPush(concatBytes([poolTagBytes(TAG.statement), deploymentId]))],
    ["@AUTH_TAG_PUSH@", casmPush(poolTagBytes(TAG.actionAuthorization))],
    ["@DT_AUTH_TAG_PUSH@", casmPush(poolTagBytes(TAG.tagAuthorization))],
    ["@PENDING_HEAD_PUSH@", casmPush(pending.head)],
    ["@PENDING_TAIL_PUSH@", casmPush(pending.tail)],
    ["@FOLD_BOUNTY_PUSH@", `<${s.foldBounty.toString(10)}>`],
    ["@RECORD_VALUE_PUSH@", `<${s.recordValue.toString(10)}>`],
    ["@POOL_COIN_PREFIX_PUSH@", casmPush(coin.prefix)],
    ["@POOL_COIN_MIDDLE_PUSH@", casmPush(coin.middle)],
    ["@POOL_COIN_TAIL_PUSH@", casmPush(coin.tail)],
    ["@RECORD_SUFFIX_PREFIX_PUSH@", casmPush(concatBytes([Uint8Array.of(OP_DROP), record.prefix]))],
    ["@RECORD_SUFFIX_MIDDLE_PUSH@", casmPush(record.middle)],
    ["@RECORD_SUFFIX_TAIL_PUSH@", casmPush(record.tail)],
    ["@RECORD_DATA_HEAD_PUSH@", casmPush(dataPush.slice(0, dataPush.length - RECORD_DATA_BYTES))],
    ["@RECORD_UNLOCKING_HEAD_PUSH@", casmPush(unlockingHead)],
    ["@RECORD_UNLOCKING_HEAD_LENGTH@", `<${String(unlockingHead.length)}>`],
  ]);
  return assemble(source.settlement, markers);
}

/** The shipped sources of one settlement build. */
export function getAPNTPoolSettlementSourcesV1(): APNTPoolSettlementSourcesV1 {
  return Object.freeze({
    settlement: getAPNTPoolSettlementCovenantSourceV1("settlement"),
    poolCoin: getAPNTPoolSettlementCovenantSourceV1("poolCoin"),
    rangeRecord: getAPNTPoolRangeRecordCovenantSourceV1(),
    pendingBatch: getAPNTPoolTreeCovenantSourceV1("pendingBatch"),
  });
}

/**
 * The settlement and pool-coin covenants for a deployment, from the shipped
 * sources: the settlement, then the pool coin that embeds the settlement lock.
 */
export function buildAPNTPoolSettlementCovenantsV1(parameters: unknown): APNTPoolSettlementCovenantsV1 {
  [parameters] = poolBoundary([parameters]);
  const input = poolRecord(parameters, SETTLEMENT_KEYS, F.COVENANT_PARAMETER);
  const sources = getAPNTPoolSettlementSourcesV1();
  const poolCoinSource = sources.poolCoin;
  const settlement = assembleAPNTPoolSettlementCovenantV1(sources, input);
  const poolCoin = assembleAPNTPoolCoinCovenantV1(poolCoinSource, {
    verdictCategoryWire32: input.verdictCategoryWire32,
    settlementLockingBytecode: settlement.lockingBytecode,
  });
  return Object.freeze({ settlement, poolCoin });
}
