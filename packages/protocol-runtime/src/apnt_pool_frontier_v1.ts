import { bytesToHex, type Bytes32 } from "./bytes.js";
import {
  APNT_POOL_FAILURE_V1 as F,
  APNT_POOL_V1_DOMAIN_TAGS as TAG,
  APNT_POOL_V1_TREE_CAPACITY,
  APNT_POOL_V1_TREE_DEPTH,
  APNTPoolDigestSetV1,
  pool32,
  poolAnyBytes,
  poolArray,
  poolBoundary,
  poolBytes,
  poolConcat,
  poolEqual,
  poolFailureCodeOf,
  poolReadU64le,
  poolRecord,
  poolRequire,
  poolDigestSet,
  poolSha256,
  poolU64le,
  type APNTPoolFailureV1,
} from "./apnt_pool_contract_v1.js";
import { apntPoolEmptyRootsV1, poolTreeNode } from "./apnt_pool_tree_v1.js";
import { decodeAPNTPoolStatementV1, type APNTPoolStatementV1 } from "./apnt_pool_statement_v1.js";

/**
 * APNT shielded pool v1: the note-tree frontier, its hash `H_F`, the tree
 * update's token commitment, and a host model of the tree-update transition
 * (design.md, "Note tree, root copies and the tree update"). The tree-update
 * covenant (task 3.3) mirrors these semantics; nothing here is that covenant.
 *
 * ```text
 * state (n, F), F = F_0 ‖ … ‖ F_31 (1,024 bytes), 0 ≤ n ≤ 2^32 − 1
 * append(F, n, x): require n < 2^32 − 1; k = n; h = 0
 *                  while k is odd: x = node(F_h, x); k = k / 2; h = h + 1
 *                  F_h = x; n = n + 1
 * root(F, n):      x = Z_0; s = n
 *                  for h in 0..31: x = (s odd) ? node(F_h, x) : node(x, Z_h); s = s / 2
 * H_F(F, n)      = SHA-256("APNT-POOL-v1:frontier" ‖ u64le(n) ‖ F)
 * commitment     = u64le(n) ‖ H_F(F, n) ‖ root(F, n)            (72 bytes)
 * ```
 *
 * `F_h` keeps what `append` last wrote at level `h`, including entries that no
 * root reads any more. `H_F` covers them, so the canonical frontier is exactly
 * what `append` produces: a frontier with a stale entry cleared has the same
 * root and a different `H_F`, and the tree update refuses it.
 *
 * The empty frontier is `F = 0^1024`, every `F_h = Z_0`, as X4 used; the
 * note-tree spec pins it, with its `H_F(empty)` and `Z_32` (ARCH-144). The
 * genesis commitment is `u64le(0) ‖ H_F(0^1024, 0) ‖ Z_32`.
 */

export const APNT_POOL_V1_FRONTIER_BYTES = 32 * APNT_POOL_V1_TREE_DEPTH;
/** `u64le(n) ‖ F`: the frontier state a tree update pushes, and `H_F`'s preimage after the tag. */
export const APNT_POOL_V1_FRONTIER_STATE_BYTES = 8 + APNT_POOL_V1_FRONTIER_BYTES;
export const APNT_POOL_V1_TREE_UPDATE_COMMITMENT_BYTES = 72;

export type APNTPoolFrontierV1 = Readonly<{
  /** `n`, the leaf count, `0 ≤ n ≤ 2^32 − 1`. */
  leafCount: number;
  /** `F_0 … F_31`, 32 bytes each. */
  entries32: readonly Bytes32[];
}>;

function frontierOf(leafCount: number, entries32: readonly Bytes32[]): APNTPoolFrontierV1 {
  return Object.freeze({ leafCount, entries32: Object.freeze(entries32.slice()) });
}

/** A frontier from a cloned value (internal: no boundary clone). */
function frontierValue(value: unknown): APNTPoolFrontierV1 {
  const frontier = poolRecord(value, ["leafCount", "entries32"], F.TREE_STATE);
  const leafCount = frontier.leafCount;
  poolRequire(typeof leafCount === "number" && Number.isSafeInteger(leafCount) && leafCount >= 0 && leafCount <= APNT_POOL_V1_TREE_CAPACITY, F.TREE_STATE);
  const entries = poolArray(frontier.entries32, APNT_POOL_V1_TREE_DEPTH, F.TREE_STATE);
  poolRequire(entries.length === APNT_POOL_V1_TREE_DEPTH, F.TREE_STATE);
  return frontierOf(leafCount, entries.map((entry) => pool32(entry, F.TREE_STATE)));
}

function stateBytes(frontier: APNTPoolFrontierV1): Uint8Array {
  return poolConcat(poolU64le(BigInt(frontier.leafCount), F.TREE_STATE), ...frontier.entries32);
}

function frontierHash(frontier: APNTPoolFrontierV1): Bytes32 {
  return poolSha256(TAG.frontier, stateBytes(frontier));
}

function append(frontier: APNTPoolFrontierV1, leaf32: unknown): APNTPoolFrontierV1 {
  poolRequire(frontier.leafCount < APNT_POOL_V1_TREE_CAPACITY, F.TREE_CAPACITY);
  const entries = frontier.entries32.slice();
  let x = pool32(leaf32, F.TREE_STATE);
  let k = frontier.leafCount;
  let h = 0;
  while (k % 2 === 1) {
    x = poolTreeNode(entries[h], x);
    k = (k - 1) / 2;
    h += 1;
  }
  entries[h] = x;
  return frontierOf(frontier.leafCount + 1, entries);
}

function frontierRoot(frontier: APNTPoolFrontierV1): Bytes32 {
  const Z = apntPoolEmptyRootsV1();
  let x = Z[0]!;
  let s = frontier.leafCount;
  for (let h = 0; h < APNT_POOL_V1_TREE_DEPTH; h += 1) {
    x = s % 2 === 1 ? poolTreeNode(frontier.entries32[h], x) : poolTreeNode(x, Z[h]);
    s = Math.floor(s / 2);
  }
  return x;
}

function treeUpdateCommitment(frontier: APNTPoolFrontierV1): Uint8Array {
  return poolConcat(poolU64le(BigInt(frontier.leafCount), F.TREE_STATE), frontierHash(frontier), frontierRoot(frontier));
}

function decodeState(value: unknown): APNTPoolFrontierV1 {
  const state = poolBytes(value, APNT_POOL_V1_FRONTIER_STATE_BYTES, F.TREE_STATE);
  const leafCount = poolReadU64le(state, 0);
  poolRequire(leafCount <= BigInt(APNT_POOL_V1_TREE_CAPACITY), F.TREE_STATE);
  const entries: Bytes32[] = [];
  for (let h = 0; h < APNT_POOL_V1_TREE_DEPTH; h += 1) entries.push(pool32(state.slice(8 + 32 * h, 40 + 32 * h), F.TREE_STATE));
  return frontierOf(Number(leafCount), entries);
}

function decodeCommitment(value: unknown): APNTPoolTreeUpdateCommitmentV1 {
  const commitment = poolBytes(value, APNT_POOL_V1_TREE_UPDATE_COMMITMENT_BYTES, F.TREE_COMMITMENT);
  const leafCount = poolReadU64le(commitment, 0);
  poolRequire(leafCount <= BigInt(APNT_POOL_V1_TREE_CAPACITY), F.TREE_COMMITMENT);
  return Object.freeze({
    leafCount: Number(leafCount),
    frontierHash32: pool32(commitment.slice(8, 40), F.TREE_COMMITMENT),
    root32: pool32(commitment.slice(40, 72), F.TREE_COMMITMENT),
  });
}

export function normalizeAPNTPoolFrontierV1(value: unknown): APNTPoolFrontierV1 {
  [value] = poolBoundary([value]);
  return frontierValue(value);
}

/** The empty frontier: `n = 0`, `F = 0^1024`, as the note-tree spec pins it (see the module comment). */
export function apntPoolEmptyFrontierV1(): APNTPoolFrontierV1 {
  const zero = apntPoolEmptyRootsV1()[0]!;
  return frontierOf(0, Array.from({ length: APNT_POOL_V1_TREE_DEPTH }, () => zero));
}

/** `u64le(n) ‖ F`, 1,032 bytes. */
export function encodeAPNTPoolFrontierStateV1(value: unknown): Uint8Array {
  [value] = poolBoundary([value]);
  return stateBytes(frontierValue(value));
}

/** Strict decode of `u64le(n) ‖ F`: exactly 1,032 bytes and `n ≤ 2^32 − 1`. */
export function decodeAPNTPoolFrontierStateV1(value: unknown): APNTPoolFrontierV1 {
  [value] = poolBoundary([value]);
  return decodeState(value);
}

/** `H_F(F, n) = SHA-256("APNT-POOL-v1:frontier" ‖ u64le(n) ‖ F)`. */
export function deriveAPNTPoolFrontierHashV1(value: unknown): Bytes32 {
  [value] = poolBoundary([value]);
  return frontierHash(frontierValue(value));
}

/** `append(F, n, leaf)`. Refuses at `n = 2^32 − 1` with `pool-tree-capacity`; the input is not changed. */
export function appendAPNTPoolFrontierV1(value: unknown, leaf32: unknown): APNTPoolFrontierV1 {
  [value, leaf32] = poolBoundary([value, leaf32]);
  return append(frontierValue(value), leaf32);
}

/** `root(F, n)`. Reads `F_h` only where bit `h` of `n` is set. */
export function deriveAPNTPoolFrontierRootV1(value: unknown): Bytes32 {
  [value] = poolBoundary([value]);
  return frontierRoot(frontierValue(value));
}

/** The tree update's token commitment `u64le(n) ‖ H_F ‖ root`, 72 bytes. */
export function encodeAPNTPoolTreeUpdateCommitmentV1(value: unknown): Uint8Array {
  [value] = poolBoundary([value]);
  return treeUpdateCommitment(frontierValue(value));
}

export type APNTPoolTreeUpdateCommitmentV1 = Readonly<{ leafCount: number; frontierHash32: Bytes32; root32: Bytes32 }>;

/** Strict decode: exactly 72 bytes and `n ≤ 2^32 − 1`. */
export function decodeAPNTPoolTreeUpdateCommitmentV1(value: unknown): APNTPoolTreeUpdateCommitmentV1 {
  [value] = poolBoundary([value]);
  return decodeCommitment(value);
}

function appendStatementLeaves(frontier: APNTPoolFrontierV1, statement: APNTPoolStatementV1): APNTPoolFrontierV1 {
  let next = frontier;
  for (const fields of statement.fields) {
    for (const commitment of fields.commitments32) next = append(next, commitment);
  }
  return next;
}

/**
 * Appends `cm_{k,0}`, then `cm_{k,1}`, for `k = 1..B` in statement order, of a
 * strictly decodable `S`. A batch that would pass capacity is refused whole
 * (`pool-tree-capacity`); no partial fold is returned.
 */
export function foldAPNTPoolStatementIntoFrontierV1(value: unknown, statement: unknown, expectedDeploymentId32: unknown): APNTPoolFrontierV1 {
  [value, statement, expectedDeploymentId32] = poolBoundary([value, statement, expectedDeploymentId32]);
  return appendStatementLeaves(frontierValue(value), decodeAPNTPoolStatementV1(statement, expectedDeploymentId32));
}

/**
 * The leaves a fold pushes for a strictly decodable `S` (ARCH-236 F1):
 * `cm_{1,0} ‖ cm_{1,1} ‖ … ‖ cm_{B,1}`, 64·B bytes in statement order.
 */
export function encodeAPNTPoolStatementLeavesV1(statement: unknown, expectedDeploymentId32: unknown): Uint8Array {
  [statement, expectedDeploymentId32] = poolBoundary([statement, expectedDeploymentId32]);
  const decoded = decodeAPNTPoolStatementV1(statement, expectedDeploymentId32);
  return poolConcat(...decoded.fields.flatMap((fields) => fields.commitments32));
}

/**
 * `H_cm = SHA-256(leaves)` of a strictly decodable `S`: the digest the
 * settlement covenant computes from `S` and commits in the batch's pending
 * lock (task 3.4, check 6). A plain SHA-256: it is compared only with the
 * leaves a fold pushes.
 */
export function deriveAPNTPoolLeafListDigestV1(statement: unknown, expectedDeploymentId32: unknown): Bytes32 {
  return poolSha256(null, encodeAPNTPoolStatementLeavesV1(statement, expectedDeploymentId32));
}

export type APNTPoolTreeUpdateInputV1 = Readonly<{
  /** Input 0's token commitment, `u64le(n) ‖ H_F ‖ root`. */
  treeUpdateCommitment72: Uint8Array;
  /**
   * The unspent pending batches, each as its pending lock's `H_cm` in 64
   * lowercase hex digits: a `Set`, or a previous result's `pendingBatches`.
   */
  pendingBatches: ReadonlySet<string>;
  /** The pushed `u64le(n) ‖ F`. */
  frontierState: Uint8Array;
  /** The pushed leaves, 64·B bytes. */
  leaves: Uint8Array;
  /** Output 0's token commitment. */
  nextTreeUpdateCommitment72: Uint8Array;
  /** Outputs 1..K: each root copy's 32-byte commitment. */
  rootCopies32: readonly Uint8Array[];
}>;

export type APNTPoolTreeUpdateResultV1 =
  | Readonly<{ valid: true; failureCode: null; frontier: APNTPoolFrontierV1; pendingBatches: APNTPoolDigestSetV1 }>
  | Readonly<{ valid: false; failureCode: APNTPoolFailureV1; frontier: null; pendingBatches: null }>;

const TREE_UPDATE_KEYS = [
  "treeUpdateCommitment72", "pendingBatches", "frontierState", "leaves", "nextTreeUpdateCommitment72", "rootCopies32",
] as const;
/** A batch has B ≥ 1 actions, so at least two leaves; `B ≤ 0xffff` bounds the list. */
const MAXIMUM_LEAVES_BYTES = 64 * 0xffff;
const MINIMUM_ROOT_COPIES = 2;
/** A bound on the copies read, not a value of `K` (D3). */
const MAXIMUM_ROOT_COPIES = 0xffff;

/**
 * Host model of one tree-update transaction, design.md steps 1–7:
 *
 * 1. the pushed `(n, F)` hashes to input 0's committed `H_F` at its committed
 *    `n` (`pool-tree-frontier`: a tampered frontier or leaf count);
 * 2. the pushed leaves are a non-empty whole number of 64-byte pairs
 *    (`pool-tree-leaves`), and `SHA-256(leaves)` is an unspent pending
 *    batch's `H_cm` (`pool-tree-verdict-not-pending`: a forged batch, or one
 *    folded before);
 * 3. the leaves are appended in order without passing capacity
 *    (`pool-tree-capacity`);
 * 4. output 0 commits `u64le(n') ‖ H_F(F', n')` (`pool-tree-frontier`) and
 *    `root'` (`pool-tree-root`), and at least two root copies (`K ≥ 2`,
 *    `pool-tree-root-copies`) each carry `root'` (`pool-tree-root`: a
 *    fabricated root);
 * 5. the verdict is burned: the returned `pendingBatches` no longer holds its
 *    `H_cm`, so each batch folds once. `H_cm` identifies a batch: each leaf
 *    commits its input's nullifier `ρ`, and nullifiers are inserted once.
 *
 * Not modelled: token categories and capabilities, the output count and order,
 * values, the pending lock's redeem and fold bounty, and `K`'s value (D3). The
 * pending set models chain state; the covenant reads input 1's redeem, not a
 * set.
 *
 * The input passes the host boundary first (ARCH-145): it is structurally
 * cloned, so a proxy, a function or a throwing getter refuses with
 * `pool-boundary`, and every check reads the clone. The leaves are copied once
 * and that copy is both hashed and appended; the pending set's membership is
 * computed from its cloned entries, never by its methods.
 */
export function evaluateAPNTPoolTreeUpdateV1(value: unknown): APNTPoolTreeUpdateResultV1 {
  try {
    const [clone] = poolBoundary([value]);
    const input = poolRecord(clone, TREE_UPDATE_KEYS, F.SHAPE);
    const committed = decodeCommitment(input.treeUpdateCommitment72);
    const frontier = decodeState(input.frontierState);
    poolRequire(
      frontier.leafCount === committed.leafCount && poolEqual(frontierHash(frontier), committed.frontierHash32),
      F.TREE_FRONTIER,
    );
    const pending = poolDigestSet(input.pendingBatches, F.DIGEST_SET_ENTRY);
    const leaves = poolAnyBytes(input.leaves, F.TREE_LEAVES);
    poolRequire(leaves.length >= 64 && leaves.length % 64 === 0 && leaves.length <= MAXIMUM_LEAVES_BYTES, F.TREE_LEAVES);
    const batch = bytesToHex(poolSha256(null, leaves));
    poolRequire(pending.has(batch), F.TREE_VERDICT_NOT_PENDING);
    let next = frontier;
    for (let at = 0; at < leaves.length; at += 32) next = append(next, leaves.slice(at, at + 32));
    const claimed = decodeCommitment(input.nextTreeUpdateCommitment72);
    poolRequire(
      claimed.leafCount === next.leafCount && poolEqual(claimed.frontierHash32, frontierHash(next)),
      F.TREE_FRONTIER,
    );
    const root = frontierRoot(next);
    poolRequire(poolEqual(claimed.root32, root), F.TREE_ROOT);
    const copies = poolArray(input.rootCopies32, MAXIMUM_ROOT_COPIES, F.TREE_ROOT_COPIES);
    poolRequire(copies.length >= MINIMUM_ROOT_COPIES, F.TREE_ROOT_COPIES);
    for (const copy of copies) poolRequire(poolEqual(pool32(copy, F.TREE_ROOT_COPIES), root), F.TREE_ROOT);
    return Object.freeze({ valid: true, failureCode: null, frontier: next, pendingBatches: pending.without(batch) });
  } catch (error) {
    return Object.freeze({ valid: false, failureCode: poolFailureCodeOf(error), frontier: null, pendingBatches: null });
  }
}
