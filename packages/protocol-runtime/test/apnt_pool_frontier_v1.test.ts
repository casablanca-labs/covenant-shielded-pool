import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  APNT_POOL_FAILURE_V1 as F,
  APNT_POOL_V1_TREE_CAPACITY,
  APNTPoolHostErrorV1,
  apntPoolSha256V1,
} from "../src/apnt_pool_contract_v1.js";
import { apntPoolEmptyRootsV1, apntPoolTreeNodeV1 } from "../src/apnt_pool_tree_v1.js";
import { encodeAPNTPoolStatementV1 } from "../src/apnt_pool_statement_v1.js";
import {
  apntPoolEmptyFrontierV1,
  appendAPNTPoolFrontierV1,
  decodeAPNTPoolFrontierStateV1,
  decodeAPNTPoolTreeUpdateCommitmentV1,
  deriveAPNTPoolFrontierHashV1,
  deriveAPNTPoolFrontierRootV1,
  encodeAPNTPoolFrontierStateV1,
  encodeAPNTPoolTreeUpdateCommitmentV1,
  encodeAPNTPoolStatementLeavesV1,
  deriveAPNTPoolLeafListDigestV1,
  evaluateAPNTPoolTreeUpdateV1,
  foldAPNTPoolStatementIntoFrontierV1,
  normalizeAPNTPoolFrontierV1,
  type APNTPoolFrontierV1,
} from "../src/apnt_pool_frontier_v1.js";
import { hex, isNonPalindromic, lab, sparseTree, unhex, vectors } from "./apnt_pool_v1_fixture.js";

const fv: any = JSON.parse(readFileSync(new URL("../test-vectors/public-apnt-pool-v1-frontier-vectors.json", import.meta.url), "utf8"));
const ref = fv.reference;
const x4 = fv.overlap.x4;
const x6 = fv.overlap.x6;

const codeOf = (thunk: () => unknown): string | null => {
  try { thunk(); return null; } catch (error) { return error instanceof APNTPoolHostErrorV1 ? error.code : "non-pool-error"; }
};
const u64le = (n: bigint) => { const b = new Uint8Array(8); let x = n; for (let i = 0; i < 8; i += 1) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
const chunk32 = (bytes: Uint8Array) => Array.from({ length: bytes.length / 32 }, (_, i) => bytes.slice(32 * i, 32 * i + 32));
const frontierFromHex = (leafCount: number, entriesHex: string) => normalizeAPNTPoolFrontierV1({ leafCount, entries32: chunk32(unhex(entriesHex)) });
const appendAll = (start: APNTPoolFrontierV1, leaves: readonly Uint8Array[]) => leaves.reduce((f, leaf) => appendAPNTPoolFrontierV1(f, leaf), start);

/** The frontier reached by appending `n0` copies of `U_0` from the empty frontier (checked against the reference's H_F). */
function uniformFrontier(n0: number): APNTPoolFrontierV1 {
  const U = [unhex(ref.uniformLeaf)];
  for (let h = 0; h < 32; h += 1) U.push(apntPoolTreeNodeV1(U[h], U[h]));
  return normalizeAPNTPoolFrontierV1({ leafCount: n0, entries32: U.slice(0, 32).map((u, h) => (2 ** h <= n0 ? u : new Uint8Array(32))) });
}

// The slice-1 reference statement: two records, four leaves, under the reference deployment.
const S = unhex(vectors.reference.statement.statement);
const DEP = unhex(vectors.reference.statement.deploymentId);
const PROF = unhex(vectors.reference.statement.profileId);
const RECORDS: Uint8Array[] = vectors.reference.statement.recordsInput.map(unhex);
/** A pending batch as the fold identifies it (ARCH-245 F1): its pending lock's H_cm, SHA-256 of its leaves. */
const batchOf = (statement: Uint8Array) => hex(apntPoolSha256V1(null, encodeAPNTPoolStatementLeavesV1(statement, DEP)));
/** `cm_{k,0}`, `cm_{k,1}` of every record, in statement order. */
const leavesOf = (statement: Uint8Array) => Array.from({ length: (statement.length - 88) / 314 }, (_, k) => 88 + 314 * k)
  .flatMap((at) => [statement.slice(at + 162, at + 194), statement.slice(at + 194, at + 226)]);

describe("pool v1 frontier: reference vectors (independent public reference construction)", () => {
  it("genesis: F = 0^1024 and n = 0; its root is Z_32 and X4's genesis frontier hash is the same bytes", () => {
    const empty = apntPoolEmptyFrontierV1();
    expect(hex(encodeAPNTPoolFrontierStateV1(empty))).toBe("00".repeat(1032));
    expect(hex(deriveAPNTPoolFrontierHashV1(empty))).toBe(ref.genesis.frontierHash);
    expect(hex(deriveAPNTPoolFrontierRootV1(empty))).toBe(ref.genesis.root);
    expect(ref.genesis.root).toBe(hex(apntPoolEmptyRootsV1()[32]!));
    expect(hex(encodeAPNTPoolTreeUpdateCommitmentV1(empty))).toBe(ref.genesis.commitment);
    expect(x4.cases.find((c: any) => c.startLeafCount === 0).oldFrontierHash).toBe(ref.genesis.frontierHash);
  });

  it("64 distinct leaves from genesis: H_F and root after every append (the reference checks each root against a naive tree)", () => {
    let f = apntPoolEmptyFrontierV1();
    ref.sequence.leaves.forEach((leafHex: string, i: number) => {
      expect(isNonPalindromic(unhex(leafHex))).toBe(true);
      f = appendAPNTPoolFrontierV1(f, unhex(leafHex));
      const step = ref.sequence.steps[i];
      expect([f.leafCount, hex(deriveAPNTPoolFrontierHashV1(f)), hex(deriveAPNTPoolFrontierRootV1(f))]).toEqual([step.leafCount, step.frontierHash, step.root]);
    });
  });

  it("stale entries are canonical: after two appends F_0 still holds leaf 0; clearing it keeps the root and changes H_F", () => {
    const f = appendAll(apntPoolEmptyFrontierV1(), ref.sequence.leaves.slice(0, 2).map(unhex));
    const stale = ref.sequence.staleEntryAfterTwo;
    expect(hex(encodeAPNTPoolFrontierStateV1(f).subarray(8))).toBe(stale.frontier);
    expect(hex(f.entries32[0]!)).toBe(ref.sequence.leaves[0]);
    const cleaned = normalizeAPNTPoolFrontierV1({ leafCount: 2, entries32: [new Uint8Array(32), ...f.entries32.slice(1)] });
    expect(hex(deriveAPNTPoolFrontierRootV1(cleaned))).toBe(stale.root);
    expect(hex(deriveAPNTPoolFrontierHashV1(f))).toBe(stale.frontierHash);
    expect(hex(deriveAPNTPoolFrontierHashV1(cleaned))).toBe(stale.cleanedFrontierHash);
    expect(stale.cleanedFrontierHash).not.toBe(stale.frontierHash);
  });

  it("high leaf counts: carries through 31 levels, the full tree at 2^32 − 1, and its refused next append", () => {
    for (const c of ref.high) {
      let f = uniformFrontier(c.startLeafCount);
      c.rows.forEach((row: any, j: number) => {
        if (j > 0) f = appendAPNTPoolFrontierV1(f, unhex(c.tail[j - 1]));
        expect([f.leafCount, hex(deriveAPNTPoolFrontierHashV1(f)), hex(deriveAPNTPoolFrontierRootV1(f))]).toEqual([row.leafCount, row.frontierHash, row.root]);
      });
      expect(f.leafCount === APNT_POOL_V1_TREE_CAPACITY).toBe(c.fullAfterTail);
      if (c.fullAfterTail) expect(codeOf(() => appendAPNTPoolFrontierV1(f, lab("one past capacity")))).toBe(F.TREE_CAPACITY);
    }
    expect(ref.high.find((c: any) => c.startLeafCount === 2 ** 31 - 1).carries[0]).toBe(31);
  });

  it("fold of the slice-1 reference statement: the next commitment for each start, and the overflowing start refused whole", () => {
    expect(ref.fold.leaves).toEqual(leavesOf(S).map(hex));
    for (const c of ref.fold.cases) {
      const prior = decodeAPNTPoolFrontierStateV1(unhex(c.priorFrontierState));
      expect(hex(encodeAPNTPoolTreeUpdateCommitmentV1(prior))).toBe(c.priorCommitment);
      if (c.refused) {
        expect(codeOf(() => foldAPNTPoolStatementIntoFrontierV1(prior, S, DEP))).toBe(F.TREE_CAPACITY);
        expect(hex(encodeAPNTPoolFrontierStateV1(prior))).toBe(c.priorFrontierState); // no partial fold
      } else {
        expect(hex(encodeAPNTPoolTreeUpdateCommitmentV1(foldAPNTPoolStatementIntoFrontierV1(prior, S, DEP)))).toBe(c.nextCommitment);
      }
    }
  });
});

describe("pool v1 frontier: overlap with X4 (ENG-262) and X6 (ENG-268)", () => {
  it("X4: all 20 cases — old H_F, then the root and new H_F after its leaves — reproduce byte for byte", () => {
    expect(x4.cases).toHaveLength(20);
    for (const c of x4.cases) {
      const start = frontierFromHex(c.startLeafCount, x4.frontiersByStartLeafCount[c.startLeafCount]);
      expect(hex(deriveAPNTPoolFrontierHashV1(start))).toBe(c.oldFrontierHash);
      const end = appendAll(start, x4.leavesOfSixteenActions.slice(0, c.leafCount).map(unhex));
      expect([hex(deriveAPNTPoolFrontierRootV1(end)), hex(deriveAPNTPoolFrontierHashV1(end))]).toEqual([c.expectedRoot, c.expectedFrontierHash]);
    }
  });

  it("X4 capacity case: at n = 2^32 − 2 the first leaf matches X4's reference, and the second is refused", () => {
    const c = x4.capacityCase;
    const start = frontierFromHex(c.startLeafCount, x4.frontiersByStartLeafCount[c.startLeafCount]);
    expect(hex(deriveAPNTPoolFrontierHashV1(start))).toBe(c.oldFrontierHash);
    const one = appendAPNTPoolFrontierV1(start, unhex(x4.leavesOfSixteenActions[0]));
    expect([one.leafCount, hex(deriveAPNTPoolFrontierRootV1(one)), hex(deriveAPNTPoolFrontierHashV1(one))]).toEqual([APNT_POOL_V1_TREE_CAPACITY, c.expectedRoot, c.expectedFrontierHash]);
    expect(codeOf(() => appendAPNTPoolFrontierV1(one, unhex(x4.leavesOfSixteenActions[1])))).toBe(F.TREE_CAPACITY);
  });

  it("X6: its authentic roots R1, R2, R3 are the frontier roots after 2, 4 and 6 appends; its fabricated root after one", () => {
    const leaves = x6.realLeaves.map(unhex);
    const at = (n: number) => hex(deriveAPNTPoolFrontierRootV1(appendAll(apntPoolEmptyFrontierV1(), leaves.slice(0, n))));
    expect([at(2), at(4), at(6)]).toEqual([x6.R1, x6.R2, x6.R3]);
    expect(hex(deriveAPNTPoolFrontierRootV1(appendAPNTPoolFrontierV1(apntPoolEmptyFrontierV1(), unhex(x6.fakeCommitment))))).toBe(x6.fakeRoot);
    expect(x6.emptyRootZ32).toBe(ref.genesis.root);
  });

  it("a folded note is a member under the fold's root: the frontier root equals the slice-1 membership root", () => {
    const leaves = Array.from({ length: 7 }, (_, i) => lab(`frontier-membership:${i}`));
    const tree = sparseTree(leaves);
    expect(hex(deriveAPNTPoolFrontierRootV1(appendAll(apntPoolEmptyFrontierV1(), leaves)))).toBe(hex(tree.root));
  });
});

describe("pool v1 frontier codecs: named negatives", () => {
  it("frontier state: 1,031 or 1,033 bytes, or n = 2^32 in its u64le, is refused", () => {
    const state = encodeAPNTPoolFrontierStateV1(apntPoolEmptyFrontierV1());
    expect(codeOf(() => decodeAPNTPoolFrontierStateV1(state.subarray(1)))).toBe(F.TREE_STATE);
    expect(codeOf(() => decodeAPNTPoolFrontierStateV1(new Uint8Array([...state, 0])))).toBe(F.TREE_STATE);
    expect(codeOf(() => decodeAPNTPoolFrontierStateV1(new Uint8Array([...u64le(2n ** 32n), ...state.subarray(8)])))).toBe(F.TREE_STATE);
    expect(decodeAPNTPoolFrontierStateV1(new Uint8Array([...u64le(2n ** 32n - 1n), ...state.subarray(8)])).leafCount).toBe(APNT_POOL_V1_TREE_CAPACITY);
  });

  it("tree-update commitment: 71 or 73 bytes, or n = 2^32, is refused", () => {
    const commitment = encodeAPNTPoolTreeUpdateCommitmentV1(apntPoolEmptyFrontierV1());
    expect(commitment).toHaveLength(72);
    expect(codeOf(() => decodeAPNTPoolTreeUpdateCommitmentV1(commitment.subarray(1)))).toBe(F.TREE_COMMITMENT);
    expect(codeOf(() => decodeAPNTPoolTreeUpdateCommitmentV1(new Uint8Array([...commitment, 0])))).toBe(F.TREE_COMMITMENT);
    expect(codeOf(() => decodeAPNTPoolTreeUpdateCommitmentV1(new Uint8Array([...u64le(2n ** 32n), ...commitment.subarray(8)])))).toBe(F.TREE_COMMITMENT);
  });

  it("frontier value: 31 or 33 entries, a 31-byte entry, or a leaf count past capacity is refused", () => {
    const entries = apntPoolEmptyFrontierV1().entries32;
    expect(codeOf(() => normalizeAPNTPoolFrontierV1({ leafCount: 0, entries32: entries.slice(1) }))).toBe(F.TREE_STATE);
    expect(codeOf(() => normalizeAPNTPoolFrontierV1({ leafCount: 0, entries32: [...entries, entries[0]] }))).toBe(F.TREE_STATE);
    expect(codeOf(() => normalizeAPNTPoolFrontierV1({ leafCount: 0, entries32: [new Uint8Array(31), ...entries.slice(1)] }))).toBe(F.TREE_STATE);
    expect(codeOf(() => normalizeAPNTPoolFrontierV1({ leafCount: APNT_POOL_V1_TREE_CAPACITY + 1, entries32: entries }))).toBe(F.TREE_STATE);
  });
});

describe("pool v1 tree update: host model of the transition and its named negatives", () => {
  /** An honest tree update folding `statement`'s leaves onto `prior`, with `copies` root copies. */
  function honest(prior: APNTPoolFrontierV1, statement: Uint8Array, pending: ReadonlySet<string> = new Set([batchOf(statement)]), copies = 2) {
    const next = foldAPNTPoolStatementIntoFrontierV1(prior, statement, DEP);
    const root = deriveAPNTPoolFrontierRootV1(next);
    return {
      treeUpdateCommitment72: encodeAPNTPoolTreeUpdateCommitmentV1(prior),
      pendingBatches: pending,
      frontierState: encodeAPNTPoolFrontierStateV1(prior),
      leaves: encodeAPNTPoolStatementLeavesV1(statement, DEP),
      nextTreeUpdateCommitment72: encodeAPNTPoolTreeUpdateCommitmentV1(next),
      rootCopies32: Array.from({ length: copies }, () => root),
    };
  }

  it("the leaves are cm_{k,0} ‖ cm_{k,1} in statement order, and H_cm is their plain SHA-256", () => {
    const leaves = encodeAPNTPoolStatementLeavesV1(S, DEP);
    expect(hex(leaves)).toBe(leavesOf(S).map(hex).join(""));
    expect(leaves.length).toBe(64 * 2);
    expect(hex(deriveAPNTPoolLeafListDigestV1(S, DEP))).toBe(hex(apntPoolSha256V1(null, leaves)));
    expect(batchOf(S)).toBe(hex(deriveAPNTPoolLeafListDigestV1(S, DEP)));
    expect(codeOf(() => deriveAPNTPoolLeafListDigestV1(S, lab("foreign deployment")))).toBe(F.STATEMENT_DEPLOYMENT);
    expect(codeOf(() => encodeAPNTPoolStatementLeavesV1(S.subarray(0, S.length - 1), DEP))).toBe(F.STATEMENT_LENGTH);
  });
  const withRoot = (commitment: Uint8Array, root: Uint8Array) => new Uint8Array([...commitment.subarray(0, 40), ...root]);
  const fakeRoot = () => unhex(x6.fakeRoot); // X6's self-built tree holding an unbacked note

  it("positive: an honest fold is valid, returns the next frontier and burns the verdict", () => {
    const input = honest(uniformFrontier(1_000_003), S);
    const result = evaluateAPNTPoolTreeUpdateV1(input);
    expect([result.valid, result.failureCode]).toEqual([true, null]);
    expect(hex(encodeAPNTPoolTreeUpdateCommitmentV1(result.frontier!))).toBe(hex(input.nextTreeUpdateCommitment72));
    expect(result.pendingBatches!.has(batchOf(S))).toBe(false);
    expect(result.pendingBatches!.size).toBe(0);
  });

  it("capacity overflow: a batch whose fourth leaf would pass 2^32 − 1 is refused whole", () => {
    const prior = decodeAPNTPoolFrontierStateV1(unhex(ref.fold.cases.find((c: any) => c.refused).priorFrontierState));
    expect(prior.leafCount).toBe(2 ** 32 - 4);
    // The claimed outputs are an honest fold from one leaf lower; the refusal comes before they are read.
    const input = { ...honest(uniformFrontier(2 ** 32 - 5), S), treeUpdateCommitment72: encodeAPNTPoolTreeUpdateCommitmentV1(prior), frontierState: encodeAPNTPoolFrontierStateV1(prior) };
    expect(evaluateAPNTPoolTreeUpdateV1(input)).toEqual({ valid: false, failureCode: F.TREE_CAPACITY, frontier: null, pendingBatches: null });
  });

  it("capacity: a batch that fills the tree exactly folds, and any later batch is refused", () => {
    const full = evaluateAPNTPoolTreeUpdateV1(honest(uniformFrontier(2 ** 32 - 5), S));
    expect(full.valid).toBe(true);
    expect(full.frontier!.leafCount).toBe(APNT_POOL_V1_TREE_CAPACITY);
    const later = encodeAPNTPoolStatementV1({ deploymentId32: DEP, profileId32: PROF, records: [RECORDS[1]!] });
    expect(codeOf(() => foldAPNTPoolStatementIntoFrontierV1(full.frontier, later, DEP))).toBe(F.TREE_CAPACITY);
  });

  it("fabricated root: output 0 carrying a root that is not the append (here X6's self-built tree) is refused", () => {
    const input = honest(uniformFrontier(1_000_003), S);
    expect(evaluateAPNTPoolTreeUpdateV1({ ...input, nextTreeUpdateCommitment72: withRoot(input.nextTreeUpdateCommitment72, fakeRoot()) }).failureCode).toBe(F.TREE_ROOT);
  });

  it("fabricated root: honest output 0 but one root copy carrying a fabricated root is refused", () => {
    const input = honest(uniformFrontier(1_000_003), S);
    expect(evaluateAPNTPoolTreeUpdateV1({ ...input, rootCopies32: [input.rootCopies32[0]!, fakeRoot()] }).failureCode).toBe(F.TREE_ROOT);
  });

  it("fabricated root: a self-consistent commitment for another leaf order, or with one record dropped, is refused", () => {
    const prior = uniformFrontier(1_000_003);
    const input = honest(prior, S);
    const leaves = leavesOf(S);
    for (const wrong of [[leaves[1]!, leaves[0]!, leaves[2]!, leaves[3]!], leaves.slice(0, 2)]) {
      const forged = appendAll(prior, wrong);
      const root = deriveAPNTPoolFrontierRootV1(forged);
      const result = evaluateAPNTPoolTreeUpdateV1({ ...input, nextTreeUpdateCommitment72: encodeAPNTPoolTreeUpdateCommitmentV1(forged), rootCopies32: [root, root] });
      expect(result.failureCode).toBe(F.TREE_FRONTIER);
    }
  });

  it("root copies: fewer than two, or a 31-byte copy, is refused", () => {
    const input = honest(uniformFrontier(1_000_003), S);
    expect(evaluateAPNTPoolTreeUpdateV1({ ...input, rootCopies32: input.rootCopies32.slice(0, 1) }).failureCode).toBe(F.TREE_ROOT_COPIES);
    expect(evaluateAPNTPoolTreeUpdateV1({ ...input, rootCopies32: [input.rootCopies32[0]!, input.rootCopies32[0]!.subarray(1)] }).failureCode).toBe(F.TREE_ROOT_COPIES);
    expect(evaluateAPNTPoolTreeUpdateV1(honest(uniformFrontier(1_000_003), S, undefined, 3)).valid).toBe(true);
  });

  it("tampered frontier or leaf count: a flipped entry, a cleared stale entry (same root) or n + 1 is refused", () => {
    const prior = appendAll(apntPoolEmptyFrontierV1(), ref.sequence.leaves.slice(0, 6).map(unhex)); // n = 6: F_0 is stale
    const input = honest(prior, S);
    const state = encodeAPNTPoolFrontierStateV1(prior);
    const flipped = state.slice(); flipped[40] = flipped[40]! ^ 0x01; // F_1, read by the root at n = 6
    const cleared = state.slice(); cleared.fill(0, 8, 40);
    expect(hex(deriveAPNTPoolFrontierRootV1(decodeAPNTPoolFrontierStateV1(cleared)))).toBe(hex(deriveAPNTPoolFrontierRootV1(prior)));
    const plusOne = new Uint8Array([...u64le(7n), ...state.subarray(8)]);
    for (const frontierState of [flipped, cleared, plusOne]) {
      // The attacker's outputs are consistent with its pushed state, so only the committed-H_F check can refuse.
      const forged = foldAPNTPoolStatementIntoFrontierV1(decodeAPNTPoolFrontierStateV1(frontierState), S, DEP);
      const root = deriveAPNTPoolFrontierRootV1(forged);
      const attack = { ...input, frontierState, nextTreeUpdateCommitment72: encodeAPNTPoolTreeUpdateCommitmentV1(forged), rootCopies32: [root, root] };
      expect(evaluateAPNTPoolTreeUpdateV1(attack).failureCode).toBe(F.TREE_FRONTIER);
    }
    expect(evaluateAPNTPoolTreeUpdateV1(input).valid).toBe(true);
  });

  it("forged batch: leaves whose SHA-256 is not a pending batch's H_cm are refused, as is the settled list reordered or one leaf flipped", () => {
    const unsettled = encodeAPNTPoolStatementV1({ deploymentId32: DEP, profileId32: PROF, records: [RECORDS[1]!] });
    expect(evaluateAPNTPoolTreeUpdateV1(honest(uniformFrontier(1_000_003), unsettled, new Set([batchOf(S)]))).failureCode).toBe(F.TREE_VERDICT_NOT_PENDING);
    const input = honest(uniformFrontier(1_000_003), S);
    const leaves = leavesOf(S);
    const flipped = input.leaves.slice(); flipped[40] = flipped[40]! ^ 0x01;
    for (const wrong of [new Uint8Array([...leaves[1]!, ...leaves[0]!, ...leaves[2]!, ...leaves[3]!]), flipped]) {
      expect(evaluateAPNTPoolTreeUpdateV1({ ...input, leaves: wrong }).failureCode).toBe(F.TREE_VERDICT_NOT_PENDING);
    }
  });

  it("fold twice: the second fold of a batch is refused because the first burned its verdict", () => {
    const first = evaluateAPNTPoolTreeUpdateV1(honest(uniformFrontier(1_000_003), S));
    expect(first.valid).toBe(true);
    const again = honest(first.frontier!, S, first.pendingBatches!);
    expect(evaluateAPNTPoolTreeUpdateV1(again)).toEqual({ valid: false, failureCode: F.TREE_VERDICT_NOT_PENDING, frontier: null, pendingBatches: null });
  });

  it("firing control: a model that does not burn the verdict folds the batch twice and appends its leaves twice", () => {
    const pending = new Set([batchOf(S)]);
    const first = evaluateAPNTPoolTreeUpdateV1(honest(uniformFrontier(1_000_003), S, pending));
    const second = evaluateAPNTPoolTreeUpdateV1(honest(first.frontier!, S, pending)); // the unburned set
    expect(second.valid).toBe(true);
    expect(second.frontier!.leafCount).toBe(1_000_003 + 8); // four distinct commitments, each a leaf twice
  });

  it("the pending set boundary: an uppercase digest is refused, not read as absent or present", () => {
    const upper = batchOf(S).toUpperCase();
    expect(upper).not.toBe(batchOf(S));
    expect(evaluateAPNTPoolTreeUpdateV1(honest(uniformFrontier(1_000_003), S, new Set([upper]))).failureCode).toBe(F.DIGEST_SET_ENTRY);
  });

  it("leaves that are not a non-empty whole number of 64-byte pairs are refused before any append, even when their SHA-256 is pending", () => {
    const input = honest(uniformFrontier(1_000_003), S);
    for (const leaves of [new Uint8Array(0), input.leaves.subarray(0, 32), input.leaves.subarray(0, 96), new Uint8Array([...input.leaves, 0x00])]) {
      const pending = new Set([hex(apntPoolSha256V1(null, leaves))]);
      expect([leaves.length, evaluateAPNTPoolTreeUpdateV1({ ...input, leaves, pendingBatches: pending }).failureCode]).toEqual([leaves.length, F.TREE_LEAVES]);
    }
  });
});
