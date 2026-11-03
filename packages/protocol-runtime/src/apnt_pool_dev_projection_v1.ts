import { bytesToHex, type Bytes32 } from "./bytes.js";
import { APNT_POOL_FAILURE_V1 as F, pool32, poolAnyBytes, poolArray, poolBoundary, poolEqual, poolFail, poolFailureCodeOf, poolRecord, poolRequire, type APNTPoolFailureV1 } from "./apnt_pool_contract_v1.js";
import type { APNTPoolActionRecordFieldsV1 } from "./apnt_pool_action_record_v1.js";
import type { APNTPoolDeploymentArtifactV1Rev2 } from "./apnt_pool_genesis_v1.js";
import { replayAPNTPoolTreeHistoryV1, type APNTPoolHistoryTransactionV1 } from "./apnt_pool_settlement_history_v1.js";
import { poolDecodeTransaction, type APNTPoolTransactionV1 } from "./apnt_pool_transaction_v1.js";

/** Inactive structural input. Confirmed coordinates are supplied context, never authenticated here.
 * A confirmed read is a closure boundary; every pending input needs its exact parent in this read.
 * The declared display id is checked against bytes after rejecting cyclic dependency envelopes.
 */
export type APNTPoolDevProjectionInputV1 = Readonly<{
  artifact: APNTPoolDeploymentArtifactV1Rev2;
  transactions: readonly Readonly<{
    transaction: Uint8Array;
    txidDisplay32: Bytes32;
    confirmed: Readonly<{ height: number; position: number }> | null;
  }>[];
}>;
export type APNTPoolDevProjectionV1 = Readonly<{
  status: "dev-structural";
  settlements: readonly Readonly<{
    txidDisplay32: Bytes32; statementCommitment32: Bytes32;
    nullifiers32: readonly Bytes32[]; actions: readonly APNTPoolActionRecordFieldsV1[];
    discoveryTags8: readonly (readonly [Uint8Array, Uint8Array])[] | null;
  }>[];
  liveRecords: readonly Readonly<{
    record66: Uint8Array;
    outpoint: Readonly<{ txidWire32: Bytes32; txidDisplay32: Bytes32; index: number }>;
  }>[];
  folds: readonly Readonly<{
    txidDisplay32: Bytes32; settlementTxidDisplay32: Bytes32;
    provisionalTreeIndexBefore: number; provisionalTreeIndexAfter: number; root32: Bytes32;
  }>[];
  leaves32: readonly Bytes32[];
}>;
export type APNTPoolDevProjectionResultV1 = Readonly<{ ok: true; value: APNTPoolDevProjectionV1 }>
  | Readonly<{ ok: false; code: APNTPoolFailureV1 }>;

type Node = { raw: Uint8Array; tx: APNTPoolTransactionV1; id: Bytes32;
  confirmed: { height: number; position: number } | null; parents: Set<Node>; ancestors: Set<Node> };
const key = (id: Uint8Array) => bytesToHex(id);
const outpoint = (id: Uint8Array, index: number) => `${key(id)}:${String(index)}`;
const coordinate = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0 && v <= 0xffff_ffff;

/** Q3 B preflight only. No verification/acceptance capability, cache, transport, policy or persistence.
 * First failure: shape/bytes, duplicate listing/spend, missing parent/index, cycle, id binding,
 * confirmation order, canonical replay, ambiguous pending settlement order.
 * Internal coordinates serve only unchanged replay; the explicit output constructors discard them.
 */
export function projectAPNTPoolDevStructureV1(value: unknown): APNTPoolDevProjectionResultV1 {
  try {
    const [clone] = poolBoundary([value]);
    const input = poolRecord(clone, ["artifact", "transactions"], F.SHAPE);
    const nodes: Node[] = poolArray(input.transactions, 4096, F.SHAPE).map((item) => {
      const fields = poolRecord(item, ["transaction", "txidDisplay32", "confirmed"], F.SHAPE);
      const raw = poolAnyBytes(fields.transaction, F.TRANSACTION);
      const tx = poolDecodeTransaction(raw);
      poolRequire(tx.version === 2, F.TRANSACTION);
      const id = pool32(fields.txidDisplay32, F.SHAPE);
      let confirmed: Node["confirmed"] = null;
      if (fields.confirmed !== null) {
        const context = poolRecord(fields.confirmed, ["height", "position"], F.SHAPE);
        poolRequire(coordinate(context.height) && coordinate(context.position), F.SHAPE);
        confirmed = { height: context.height, position: context.position };
      }
      return { raw, tx, id, confirmed, parents: new Set(), ancestors: new Set() };
    });
    const byWire = new Map<string, Node>();
    const spent = new Set<string>();
    for (const node of nodes) {
      const id = key(node.id.slice().reverse());
      poolRequire(!byWire.has(id), F.HISTORY_DUPLICATE);
      byWire.set(id, node);
      for (const spend of node.tx.inputs) {
        const at = outpoint(spend.outpointTxidWire32, spend.outpointIndex);
        poolRequire(!spent.has(at), F.HISTORY_DUPLICATE);
        spent.add(at);
      }
    }
    for (const node of nodes) for (const spend of node.tx.inputs) {
      const parent = byWire.get(key(spend.outpointTxidWire32));
      poolRequire(parent !== undefined || node.confirmed !== null, F.HISTORY_GAP);
      if (parent !== undefined) {
        poolRequire(spend.outpointIndex < parent.tx.outputs.length, F.HISTORY_RECORD_OUTPOINT);
        node.parents.add(parent);
      }
    }
    const ordered: Node[] = [];
    const remaining = new Set(nodes);
    while (remaining.size > 0) {
      const ready = [...remaining].filter((n) => [...n.parents].every((p) => !remaining.has(p)))
        .sort((a, b) => key(a.id).localeCompare(key(b.id)));
      poolRequire(ready.length > 0, F.HISTORY_ORDER);
      for (const node of ready) {
        for (const parent of node.parents) {
          node.ancestors.add(parent);
          for (const ancestor of parent.ancestors) node.ancestors.add(ancestor);
        }
        ordered.push(node);
        remaining.delete(node);
      }
    }
    for (const node of ordered) {
      poolRequire(poolEqual(node.id, node.tx.txidDisplay32), F.TRANSACTION);
      if (node.confirmed !== null) for (const parent of node.parents) {
        poolRequire(parent.confirmed !== null && parent.confirmed.height <= node.confirmed.height, F.HISTORY_ORDER);
      }
    }
    const artifact = input.artifact as APNTPoolDeploymentArtifactV1Rev2;
    // Full graph checked above. Select by paid/spent locks, not successful decoding:
    // malformed relevant spends must remain in canonical replay's refusal scope.
    const locks = [poolAnyBytes(artifact.covenants.settlement.lockingBytecode, F.SHAPE),
      poolAnyBytes(artifact.covenants.treeUpdate.lockingBytecode, F.SHAPE)];
    const genesis = new Set(Object.values(artifact.categories).map((category) => key(category.genesisTxidDisplay32)));
    const settlementRedeem = poolAnyBytes(artifact.covenants.settlement.redeemBytecode, F.SHAPE);
    const relevant = new Set<string>();
    for (const node of nodes) node.tx.outputs.forEach((output, index) => {
      if (locks.some((lock) => poolEqual(lock, output.lockingBytecode))) relevant.add(outpoint(node.tx.txidWire32, index));
    });
    const baseHeight = Math.max(0, ...nodes.map((n) => n.confirmed?.height ?? 0));
    poolRequire(baseHeight < 0xffff_ffff, F.HISTORY_ORDER);
    const transactions: APNTPoolHistoryTransactionV1[] = [];
    for (const [position, node] of ordered.entries()) {
      if (genesis.has(key(node.id)) || node.tx.outputs.some((output) => locks.some((lock) => poolEqual(lock, output.lockingBytecode)))
        || node.tx.inputs.some((spend) => relevant.has(outpoint(spend.outpointTxidWire32, spend.outpointIndex)))
        || node.tx.inputs.some((spend) => spend.unlockingBytecode.length >= settlementRedeem.length
          && poolEqual(spend.unlockingBytecode.slice(-settlementRedeem.length), settlementRedeem))) {
        transactions.push({ transaction: node.raw, height: node.confirmed?.height ?? baseHeight + 1, position: node.confirmed?.position ?? position });
      }
    }
    const replay = replayAPNTPoolTreeHistoryV1({ artifact: input.artifact, transactions }, 2);
    if (!replay.valid) poolFail(replay.failureCode);
    const settlements = replay.settlementHistory.settlements;
    for (let i = 0; i < settlements.length; i++) for (let j = i + 1; j < settlements.length; j++) {
      const a = byWire.get(key(settlements[i]!.txidDisplay32.slice().reverse()))!;
      const b = byWire.get(key(settlements[j]!.txidDisplay32.slice().reverse()))!;
      // Confirmed context orders the base before pending settlements. Only two
      // pending insertions need ancestry to determine their shared range order;
      // fabricated coordinates must never order incomparable pending settlements.
      poolRequire((a.confirmed !== null || b.confirmed !== null) || a.ancestors.has(b) || b.ancestors.has(a), F.HISTORY_ORDER);
    }
    return Object.freeze({ ok: true, value: Object.freeze({
      status: "dev-structural",
      settlements: Object.freeze(settlements.map((batch) => Object.freeze({
        txidDisplay32: batch.txidDisplay32.slice() as Bytes32,
        statementCommitment32: batch.statementCommitment32.slice() as Bytes32,
        nullifiers32: Object.freeze(batch.nullifiers32.map((nf) => nf.slice() as Bytes32)),
        actions: Object.freeze(batch.actions.map((action) => Object.freeze({
          anchor32: action.anchor32.slice() as Bytes32,
          nullifiers32: Object.freeze([action.nullifiers32[0].slice() as Bytes32, action.nullifiers32[1].slice() as Bytes32] as const),
          rerandomizedKeys33: Object.freeze([action.rerandomizedKeys33[0].slice(), action.rerandomizedKeys33[1].slice()] as const),
          commitments32: Object.freeze([action.commitments32[0].slice() as Bytes32, action.commitments32[1].slice() as Bytes32] as const),
          packets16: Object.freeze([action.packets16[0].slice(), action.packets16[1].slice()] as const),
          depositSats: action.depositSats,
          withdrawalSats: action.withdrawalSats,
          withdrawalLockHash32: action.withdrawalLockHash32.slice() as Bytes32,
          feeSats: action.feeSats,
        }))),
        discoveryTags8: batch.discoveryTags8 === null ? null : Object.freeze(batch.discoveryTags8.map((tags) => Object.freeze([tags[0].slice(), tags[1].slice()] as const))),
      }))),
      liveRecords: Object.freeze(replay.settlementHistory.liveRecords.map((record) => Object.freeze({
        record66: record.record66.slice(), outpoint: Object.freeze({ txidWire32: record.outpoint.txidWire32.slice() as Bytes32,
          txidDisplay32: record.outpoint.txidDisplay32.slice() as Bytes32, index: record.outpoint.index }),
      }))),
      folds: Object.freeze(replay.folds.map((fold) => Object.freeze({
        txidDisplay32: fold.txidDisplay32.slice() as Bytes32, settlementTxidDisplay32: fold.settlementTxidDisplay32.slice() as Bytes32,
        provisionalTreeIndexBefore: fold.leafCountBefore, provisionalTreeIndexAfter: fold.leafCount, root32: fold.root32.slice() as Bytes32,
      }))),
      leaves32: Object.freeze(replay.leaves32.map((leaf) => leaf.slice() as Bytes32)),
    }) });
  } catch (error) { return Object.freeze({ ok: false, code: poolFailureCodeOf(error) }); }
}
