import { type Bytes32 } from "./bytes.js";
import {
  APNT_POOL_FAILURE_V1 as F,
  APNT_POOL_V1_DOMAIN_TAGS as TAG,
  APNT_POOL_V1_TREE_CAPACITY,
  APNT_POOL_V1_TREE_DEPTH,
  pool32,
  poolArray,
  poolBoundary,
  poolRecord,
  poolRequire,
  poolSha256,
} from "./apnt_pool_contract_v1.js";

/**
 * APNT shielded pool v1: the note tree's host semantics for membership.
 *
 * design.md, "Note tree, root copies and the tree update":
 *
 * ```text
 * depth D = 32; leaves are output commitments cm; empty leaf Z_0 = 0^32
 * node(l, r) = SHA-256("APNT-POOL-v1:node" ‖ l ‖ r)
 * Z_{h+1}    = node(Z_h, Z_h)
 * ```
 *
 * A membership path is the leaf's 32 position bits (bit `h` set means the
 * running node is the right child at level `h`) and its 32 siblings, leaf
 * level first. The path proves only the root it reaches; whether that root is
 * authentic is the settlement covenant's anchor check (task 3.4), never this
 * module's. The frontier, `H_F` and the tree update are task 3.3 and are not
 * implemented here.
 *
 * {@link deriveAPNTPoolMembershipPathV1} builds a path from the leaves
 * themselves, in append order, as a wallet does from the tree-update history
 * ("Leaf positions follow fold order, which the chain fixes, and a wallet
 * rebuilds paths from the tree-update history").
 */

/** `node(l, r)`, internal form over the host's own values (no boundary clone). */
export function poolTreeNode(left32: unknown, right32: unknown): Bytes32 {
  return poolSha256(TAG.treeNode, pool32(left32, F.MEMBERSHIP), pool32(right32, F.MEMBERSHIP));
}

export function apntPoolTreeNodeV1(left32: unknown, right32: unknown): Bytes32 {
  [left32, right32] = poolBoundary([left32, right32]);
  return poolTreeNode(left32, right32);
}

let emptyRoots: readonly Bytes32[] | undefined;

/** `Z_0 … Z_32`: 33 entries, `Z_0 = 0^32`. */
export function apntPoolEmptyRootsV1(): readonly Bytes32[] {
  if (emptyRoots === undefined) {
    const roots: Bytes32[] = [pool32(new Uint8Array(32), F.MEMBERSHIP)];
    for (let h = 0; h < APNT_POOL_V1_TREE_DEPTH; h += 1) roots.push(poolTreeNode(roots[h], roots[h]));
    emptyRoots = Object.freeze(roots);
  }
  return emptyRoots.map((root) => pool32(root, F.MEMBERSHIP));
}

export type APNTPoolMembershipPathV1 = Readonly<{
  /** Leaf position as 32 bits, `0 ≤ position ≤ 2^32 − 1`. */
  position: number;
  /** Exactly 32 siblings of 32 bytes, leaf level first. */
  siblings32: readonly Uint8Array[];
}>;

function membershipPath(value: unknown): APNTPoolMembershipPathV1 {
  const path = poolRecord(value, ["position", "siblings32"], F.MEMBERSHIP);
  const position = path.position;
  poolRequire(typeof position === "number" && Number.isSafeInteger(position) && position >= 0 && position <= 0xffff_ffff, F.MEMBERSHIP);
  const siblings = poolArray(path.siblings32, APNT_POOL_V1_TREE_DEPTH, F.MEMBERSHIP);
  poolRequire(siblings.length === APNT_POOL_V1_TREE_DEPTH, F.MEMBERSHIP);
  return Object.freeze({ position, siblings32: Object.freeze(siblings.map((sibling) => pool32(sibling, F.MEMBERSHIP))) });
}

export function normalizeAPNTPoolMembershipPathV1(value: unknown): APNTPoolMembershipPathV1 {
  const [path] = poolBoundary([value]);
  return membershipPath(path);
}

/**
 * The membership path of the leaf at `position` in the tree whose leaves are
 * exactly `leaves32`, in append order: leaf count `n = leaves32.length`, and
 * every later leaf `Z_0`. The path reaches `root(F, n)` of the frontier those
 * `n` appends give (`apnt_pool_frontier_v1.ts`): at level `h` an absent right
 * sibling is the empty subtree `Z_h`, exactly as `root(F, n)` reads it.
 * Refused with `pool-membership` for a position not below `n`. It hashes
 * every level of the whole tree, about `2n` node hashes per call; an
 * incremental witness is not implemented.
 */
export function deriveAPNTPoolMembershipPathV1(leaves32: unknown, position: unknown): APNTPoolMembershipPathV1 {
  [leaves32, position] = poolBoundary([leaves32, position]);
  let level: Bytes32[] = poolArray(leaves32, APNT_POOL_V1_TREE_CAPACITY, F.MEMBERSHIP).map((leaf) => pool32(leaf, F.MEMBERSHIP));
  poolRequire(typeof position === "number" && Number.isSafeInteger(position) && position >= 0 && position < level.length, F.MEMBERSHIP);
  const Z = apntPoolEmptyRootsV1();
  const siblings32: Bytes32[] = [];
  let index = position;
  for (let h = 0; h < APNT_POOL_V1_TREE_DEPTH; h += 1) {
    const sibling = index % 2 === 0 ? index + 1 : index - 1;
    siblings32.push(sibling < level.length ? level[sibling]! : Z[h]!);
    const next: Bytes32[] = [];
    for (let at = 0; at < level.length; at += 2) next.push(poolTreeNode(level[at], at + 1 < level.length ? level[at + 1] : Z[h]));
    level = next;
    index = Math.floor(index / 2);
  }
  return Object.freeze({ position, siblings32: Object.freeze(siblings32) });
}

/** The root a depth-32 path reaches from `leaf`. */
export function apntPoolMembershipRootV1(leaf32: unknown, pathValue: unknown): Bytes32 {
  [leaf32, pathValue] = poolBoundary([leaf32, pathValue]);
  const path = membershipPath(pathValue);
  let node = pool32(leaf32, F.MEMBERSHIP);
  let bits = path.position;
  for (let h = 0; h < APNT_POOL_V1_TREE_DEPTH; h += 1) {
    const sibling = path.siblings32[h]!;
    node = (bits & 1) === 1 ? poolTreeNode(sibling, node) : poolTreeNode(node, sibling);
    bits = Math.floor(bits / 2);
  }
  return node;
}
