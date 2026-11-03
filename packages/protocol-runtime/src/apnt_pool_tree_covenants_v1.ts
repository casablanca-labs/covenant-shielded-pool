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
  poolEqual,
  poolRecord,
  poolRequire,
  poolTagBytes,
} from "./apnt_pool_contract_v1.js";

/**
 * APNT shielded pool v1: builders for the note tree's three covenants (task
 * 3.3; design.md, "Note tree, root copies and the tree update"). Each compiles
 * its `cashassembly/*.casm` source, whose header explains every check, with a
 * deployment's parameters into a P2SH32 redeem script and lock:
 *
 * - `apnt_pool_tree_update_v1.casm`: the one tree update, holding the root
 *   category's minting NFT and the committed frontier; each spend folds one
 *   pending batch from its pushed leaves and mints `K` root copies of the new
 *   root;
 * - `apnt_pool_root_copy_v1.casm`: the lock of every root copy, spent only
 *   under the settlement authority and recreated unchanged;
 * - `apnt_pool_pending_batch_v1.casm`: the lock a settlement moves its verdict
 *   to, spendable only as input 1 of a fold. Its redeem is
 *   `<H_cm> OP_DROP ‖ PCODE` (ARCH-236 F1, ARCH-245): each batch has its own
 *   pending lock, committing the SHA-256 of its leaves.
 *
 * The locks depend on each other in one direction: the tree update embeds the
 * pending-batch redeem's layout and the root-copy lock; the root copy embeds
 * the settlement lock; the pending-batch redeem embeds only the root category.
 * So the settlement covenant (task 3.4) may embed the pending-batch layout but
 * not the root-copy or tree-update lock.
 *
 * Locking-template construction only. Executing them against the BCH 2026 VMs
 * is `@bch-cloak/reference-aggregator`'s
 * (`apnt_pool_tree_covenants_v1_local_vm.test.ts`). Nothing here is proof
 * verification, chain validation, wallet acceptance or spendability, and no
 * deployment is pinned.
 *
 * Source format. A source is one section of CashAssembly with parameter
 * markers, compiled by the repository's CashAssembly compiler after they are
 * replaced:
 *
 * - `@ROOT_CATEGORY_PUSH@`, `@ROOT_CATEGORY_MINTING_PUSH@`: the root category
 *   in wire order, alone and followed by `0x02` (minting);
 * - `@VERDICT_CATEGORY_PUSH@`: the verdict category in wire order, with no
 *   capability byte;
 * - `@SETTLEMENT_LOCK_PUSH@`, `@ROOT_COPY_LOCK_PUSH@`: locking bytecodes;
 * - `@LEAF_LIST_DIGEST_PUSH@` (pending batch): a batch's `H_cm`;
 * - `@PENDING_TAIL_PUSH@`, `@PENDING_UNLOCKING_HEAD_PUSH@`,
 *   `@PENDING_UNLOCKING_HEAD_LENGTH@` (tree update): the pending redeem's tail
 *   `OP_DROP ‖ PCODE`, and the head of its unlocking push (the push opcode
 *   and length, then the digest's push opcode) and that head's length;
 * - `@ROOT_COPY_VALUE_PUSH@`: the satoshi value of each minted root copy;
 * - `@ROOT_COPY_END_PUSH@`: `K + 1`, the first output after the copies;
 * - `@NODE_TAG_PUSH@`, `@FRONTIER_TAG_PUSH@`: the domain tags of `node` and
 *   `H_F`.
 */

export type APNTPoolTreeCovenantV1 = Readonly<{
  /** The P2SH32 redeem script. */
  redeemBytecode: Uint8Array;
  /** `OP_HASH256 <HASH256(redeem)> OP_EQUAL`. */
  lockingBytecode: Uint8Array;
}>;

export type APNTPoolTreeCovenantKindV1 = "treeUpdate" | "rootCopy" | "pendingBatch";

export type APNTPoolTreeUpdateCovenantParametersV1 = Readonly<{
  /** The root category `T`, wire order (the genesis txid reversed from display order). */
  rootCategoryWire32: Uint8Array;
  /** The verdict category `V`, wire order. */
  verdictCategoryWire32: Uint8Array;
  /** The pending-batch redeem's tail `OP_DROP ‖ PCODE` (`deriveAPNTPoolPendingBatchLayoutV1`). */
  pendingBatchTailBytecode: Uint8Array;
  /** The root-copy lock of outputs `1..K`. */
  rootCopyLockingBytecode: Uint8Array;
  /** `K ≥ 2`, the root copies minted per fold. */
  rootCopyCount: number;
  /** The satoshi value of each minted root copy, from the deployment artifact. */
  rootCopySats: bigint;
}>;

export type APNTPoolRootCopyCovenantParametersV1 = Readonly<{
  /** The verdict category `V`, wire order. */
  verdictCategoryWire32: Uint8Array;
  /** The pool settlement locking bytecode that input 0 must be under. */
  settlementLockingBytecode: Uint8Array;
}>;

export type APNTPoolPendingBatchCovenantParametersV1 = Readonly<{
  /** The root category `T`, wire order. */
  rootCategoryWire32: Uint8Array;
  /** `H_cm = SHA-256(cm_{1,0} ‖ cm_{1,1} ‖ … ‖ cm_{B,1})`, the batch's leaves in statement order. */
  leafListDigest32: Uint8Array;
}>;

/** A pending-batch redeem's layout: `head ‖ H_cm ‖ tail`, with `head` the 32-byte push opcode. */
export type APNTPoolPendingBatchLayoutV1 = Readonly<{ head: Uint8Array; tail: Uint8Array }>;

export type APNTPoolNoteTreeCovenantParametersV1 = Readonly<{
  rootCategoryWire32: Uint8Array;
  verdictCategoryWire32: Uint8Array;
  settlementLockingBytecode: Uint8Array;
  rootCopyCount: number;
  rootCopySats: bigint;
}>;

export type APNTPoolNoteTreeCovenantsV1 = Readonly<{
  treeUpdate: APNTPoolTreeCovenantV1;
  rootCopy: APNTPoolTreeCovenantV1;
  /** The pending-batch redeem's layout; each batch's lock is `assembleAPNTPoolPendingBatchCovenantV1` of its `H_cm`. */
  pendingBatch: APNTPoolPendingBatchLayoutV1;
}>;

const SOURCE_FILES: Readonly<Record<APNTPoolTreeCovenantKindV1, string>> = {
  treeUpdate: "apnt_pool_tree_update_v1.casm",
  rootCopy: "apnt_pool_root_copy_v1.casm",
  pendingBatch: "apnt_pool_pending_batch_v1.casm",
};
const UNREPLACED_MARKER = /@[A-Z0-9_]+@/u;
const MAXIMUM_LOCKING_BYTECODE_BYTES = 10_000;
const OP_DROP = 0x75;
/** A pending-batch redeem stays one direct push (opcode 0x01..0x4b), so its unlocking head is two bytes. */
const MAXIMUM_PENDING_REDEEM_BYTES = 0x4b;
/** A bound on the parameter, not a value of `K` (D3). */
const MAXIMUM_ROOT_COPIES = 0xffff;

/** A covenant's CashAssembly source with its parameter markers, as shipped beside the built module. */
export function getAPNTPoolTreeCovenantSourceV1(kind: APNTPoolTreeCovenantKindV1): string {
  const file = SOURCE_FILES[kind];
  if (file === undefined) throw new Error("APNTPoolTreeCovenantV1 unknown covenant kind");
  return readFileSync(new URL(`./cashassembly/${file}`, import.meta.url), "utf8");
}

const casmPush = (bytes: Uint8Array): string => `0x${bytesToHex(pushScriptData(bytes))}`;

const hash256 = (bytes: Uint8Array): Uint8Array =>
  new Uint8Array(createHash("sha256").update(createHash("sha256").update(bytes).digest()).digest());

function assemble(source: unknown, markers: ReadonlyMap<string, string>): APNTPoolTreeCovenantV1 {
  if (typeof source !== "string") throw new Error("APNTPoolTreeCovenantV1 template is not a string");
  let out = source;
  for (const [marker, token] of markers) out = out.split(marker).join(token);
  const leftover = UNREPLACED_MARKER.exec(out);
  if (leftover !== null) throw new Error(`APNTPoolTreeCovenantV1 template leaves marker ${leftover[0]} unreplaced`);
  const redeemBytecode = compileApntCashAssemblySourceV0(out);
  const lockingBytecode = concatBytes([Uint8Array.of(0xaa), pushScriptData(hash256(redeemBytecode)), Uint8Array.of(0x87)]);
  return Object.freeze({ redeemBytecode, lockingBytecode });
}

function lockOf(value: unknown): Uint8Array {
  const lock = poolAnyBytes(value, F.COVENANT_PARAMETER);
  poolRequire(lock.length >= 1 && lock.length <= MAXIMUM_LOCKING_BYTECODE_BYTES, F.COVENANT_PARAMETER);
  return lock;
}

/** A pending-batch redeem's tail, `OP_DROP ‖ PCODE`: a redeem `0x20 ‖ H_cm ‖ tail` must fit one direct push. */
function pendingTailOf(value: unknown): Uint8Array {
  const tail = poolAnyBytes(value, F.COVENANT_PARAMETER);
  poolRequire(tail.length >= 2 && tail[0] === OP_DROP && 1 + 32 + tail.length <= MAXIMUM_PENDING_REDEEM_BYTES, F.COVENANT_PARAMETER);
  return tail;
}

function categoryMarkers(root: Uint8Array | null, verdict: Uint8Array | null): [string, string][] {
  const markers: [string, string][] = [];
  if (root !== null) {
    markers.push(["@ROOT_CATEGORY_MINTING_PUSH@", casmPush(concatBytes([root, Uint8Array.of(0x02)]))]);
    markers.push(["@ROOT_CATEGORY_PUSH@", casmPush(root)]);
  }
  if (verdict !== null) markers.push(["@VERDICT_CATEGORY_PUSH@", casmPush(verdict)]);
  return markers;
}

/**
 * Compiles a tree-update covenant source (the shipped one, or a variant of it).
 * Parameters are refused with `pool-covenant-parameter`; a malformed template
 * throws.
 */
export function assembleAPNTPoolTreeUpdateCovenantV1(source: string, parameters: unknown): APNTPoolTreeCovenantV1 {
  [parameters] = poolBoundary([parameters]);
  const input = poolRecord(parameters, [
    "rootCategoryWire32", "verdictCategoryWire32", "pendingBatchTailBytecode", "rootCopyLockingBytecode", "rootCopyCount", "rootCopySats",
  ], F.COVENANT_PARAMETER);
  const root = pool32(input.rootCategoryWire32, F.COVENANT_PARAMETER);
  const verdict = pool32(input.verdictCategoryWire32, F.COVENANT_PARAMETER);
  poolRequire(!poolEqual(root, verdict), F.COVENANT_PARAMETER);
  const pendingTail = pendingTailOf(input.pendingBatchTailBytecode);
  const copyLock = lockOf(input.rootCopyLockingBytecode);
  // The unlocking of input 1: push(0x20 ‖ H_cm ‖ tail), whose first two bytes are the push opcode and 0x20.
  const unlockingHead = pushScriptData(concatBytes([Uint8Array.of(0x20), new Uint8Array(32), pendingTail])).slice(0, 2);
  const copies = input.rootCopyCount;
  poolRequire(typeof copies === "number" && Number.isSafeInteger(copies) && copies >= 2 && copies <= MAXIMUM_ROOT_COPIES, F.COVENANT_PARAMETER);
  const copyValue = input.rootCopySats;
  poolRequire(typeof copyValue === "bigint" && copyValue >= 1n && copyValue <= APNT_POOL_V1_MAX_MONEY_SATS, F.COVENANT_PARAMETER);
  return assemble(source, new Map([
    ...categoryMarkers(root, verdict),
    ["@PENDING_TAIL_PUSH@", casmPush(pendingTail)],
    ["@PENDING_UNLOCKING_HEAD_PUSH@", casmPush(unlockingHead)],
    ["@PENDING_UNLOCKING_HEAD_LENGTH@", `<${String(unlockingHead.length)}>`],
    ["@ROOT_COPY_LOCK_PUSH@", casmPush(copyLock)],
    ["@ROOT_COPY_VALUE_PUSH@", `<${copyValue.toString(10)}>`],
    ["@ROOT_COPY_END_PUSH@", `<${String(copies + 1)}>`],
    ["@NODE_TAG_PUSH@", casmPush(poolTagBytes(TAG.treeNode))],
    ["@FRONTIER_TAG_PUSH@", casmPush(poolTagBytes(TAG.frontier))],
  ]));
}

/** Compiles a root-copy covenant source. Parameters are refused with `pool-covenant-parameter`. */
export function assembleAPNTPoolRootCopyCovenantV1(source: string, parameters: unknown): APNTPoolTreeCovenantV1 {
  [parameters] = poolBoundary([parameters]);
  const input = poolRecord(parameters, ["verdictCategoryWire32", "settlementLockingBytecode"], F.COVENANT_PARAMETER);
  const verdict = pool32(input.verdictCategoryWire32, F.COVENANT_PARAMETER);
  return assemble(source, new Map([
    ...categoryMarkers(null, verdict),
    ["@SETTLEMENT_LOCK_PUSH@", casmPush(lockOf(input.settlementLockingBytecode))],
  ]));
}

/**
 * Compiles a pending-batch lock source for one batch's `H_cm`. Parameters are
 * refused with `pool-covenant-parameter`.
 */
export function assembleAPNTPoolPendingBatchCovenantV1(source: string, parameters: unknown): APNTPoolTreeCovenantV1 {
  [parameters] = poolBoundary([parameters]);
  const input = poolRecord(parameters, ["rootCategoryWire32", "leafListDigest32"], F.COVENANT_PARAMETER);
  return assemble(source, new Map([
    ...categoryMarkers(pool32(input.rootCategoryWire32, F.COVENANT_PARAMETER), null),
    ["@LEAF_LIST_DIGEST_PUSH@", casmPush(pool32(input.leafListDigest32, F.COVENANT_PARAMETER))],
  ]));
}

/**
 * The layout `head ‖ H_cm ‖ tail` of a pending-batch source's redeem, found by
 * compiling it with two sentinel digests: `head` must be the one-byte push of
 * 32 bytes and `tail` must not depend on the digest, else the settlement and
 * the tree update could not rebuild the lock. Parameters are refused with
 * `pool-covenant-parameter`; any other shape throws.
 */
export function deriveAPNTPoolPendingBatchLayoutV1(source: string, parameters: unknown): APNTPoolPendingBatchLayoutV1 {
  [parameters] = poolBoundary([parameters]);
  const input = poolRecord(parameters, ["rootCategoryWire32"], F.COVENANT_PARAMETER);
  const root = pool32(input.rootCategoryWire32, F.COVENANT_PARAMETER);
  const shape = (tag: string) => {
    const digest = new Uint8Array(createHash("sha256").update(`pending-batch-layout:${tag}`).digest());
    const redeem = assembleAPNTPoolPendingBatchCovenantV1(source, { rootCategoryWire32: root, leafListDigest32: digest }).redeemBytecode;
    if (redeem.length < 34 || redeem[0] !== 0x20 || !poolEqual(redeem.subarray(1, 33), digest)) throw new Error("APNTPoolTreeCovenantV1 pending batch does not open with its leaf-list digest");
    return redeem.slice(33);
  };
  const tail = shape("a");
  if (!poolEqual(tail, shape("b"))) throw new Error("APNTPoolTreeCovenantV1 pending batch layout depends on its digest");
  pendingTailOf(tail);
  return Object.freeze({ head: Uint8Array.of(0x20), tail });
}

/**
 * The note tree's three covenants for a deployment, from the shipped sources:
 * the pending-batch layout and the root copy first, then the tree update that
 * embeds both.
 */
export function buildAPNTPoolNoteTreeCovenantsV1(parameters: unknown): APNTPoolNoteTreeCovenantsV1 {
  [parameters] = poolBoundary([parameters]);
  const input = poolRecord(parameters, [
    "rootCategoryWire32", "verdictCategoryWire32", "settlementLockingBytecode", "rootCopyCount", "rootCopySats",
  ], F.COVENANT_PARAMETER);
  const pendingBatch = deriveAPNTPoolPendingBatchLayoutV1(getAPNTPoolTreeCovenantSourceV1("pendingBatch"), {
    rootCategoryWire32: input.rootCategoryWire32,
  });
  const rootCopy = assembleAPNTPoolRootCopyCovenantV1(getAPNTPoolTreeCovenantSourceV1("rootCopy"), {
    verdictCategoryWire32: input.verdictCategoryWire32,
    settlementLockingBytecode: input.settlementLockingBytecode,
  });
  const treeUpdate = assembleAPNTPoolTreeUpdateCovenantV1(getAPNTPoolTreeCovenantSourceV1("treeUpdate"), {
    rootCategoryWire32: input.rootCategoryWire32,
    verdictCategoryWire32: input.verdictCategoryWire32,
    pendingBatchTailBytecode: pendingBatch.tail,
    rootCopyLockingBytecode: rootCopy.lockingBytecode,
    rootCopyCount: input.rootCopyCount,
    rootCopySats: input.rootCopySats,
  });
  return Object.freeze({ treeUpdate, rootCopy, pendingBatch });
}
