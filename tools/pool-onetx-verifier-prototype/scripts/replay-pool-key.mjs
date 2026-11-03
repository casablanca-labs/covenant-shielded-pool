// ENG-510 (task 5.4 slice 2a): replay, in both BCH 2026 VMs, what the verifier graph regenerated
// for the pinned Chipnet pool program key can show BEFORE a pool aggregate proof exists.
//
// Research prototype (R-384 construction). SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY.
// Local VM evidence only. The planning proof is the retained L1 SP1 6.3.1 wrapper proof of the
// seal-era aggregate program: a real proof of ANOTHER program, so the pool-keyed terminal must
// refuse it. Nothing here is a pool proof.
//
//   1. pool graph + L1's witness + the deployable pool factory: refused at the terminal (the
//      pairing binds s0) and at the factory (L1's s1 is not a pool runBind32), both VMs; every
//      other graph input accepts.
//   2. the honest graph of L1's own key + L1's witness + the pool factory: every graph input
//      accepts; only the factory refuses (its root is the pool graph's).
//   3. the pool graph's lockings equal the committed record's.
//
// usage: node replay-pool-key.mjs POOL_GATED_JSON HONEST_GATED_JSON VECTORS_DIR OUT_JSON
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { accepted, bin, buildTransaction, evaluate, rejected } from './onetx-lib.mjs';
import { GRAPH_RECORD, mintingToken, poolFactory, SETTLEMENT_LOCK, V_DISPLAY } from './pool-deployment.mjs';

const [poolPath, honestPath, vectorsDir, outPath] = process.argv.slice(2);
assert(outPath, 'usage: replay-pool-key.mjs POOL_GATED_JSON HONEST_GATED_JSON VECTORS_DIR OUT_JSON');
const pool = JSON.parse(readFileSync(poolPath, 'utf8')).rekeyed;
const honest = JSON.parse(readFileSync(honestPath, 'utf8'));
const L1 = JSON.parse(readFileSync(`${vectorsDir}/L1.json`, 'utf8'));
const v5 = JSON.parse(readFileSync(new URL('../../apnt-pool-aggregate-sp1/fixtures/pool-aggregate-statement-vectors-v5.json', import.meta.url), 'utf8'));
const runBind = bin(v5.vectors.find(x => x.name === 'b1-rel1').runBind32);

assert.deepEqual(pool.steps.map(s => s.locking), GRAPH_RECORD.graph.lockings, 'the scratch pool graph is the committed record');
assert.equal(honest.steps.length, 11);
const factory = poolFactory();
const tx = graph => buildTransaction({ graph, factory, factoryToken: mintingToken(),
  verdicts: [{ commitment: runBind, lock: SETTLEMENT_LOCK, category: V_DISPLAY }] });
const summary = r => ({ bytes: r.bytes, verify: { standard: r.standard.verify, consensus: r.consensus.verify },
  failing: { standard: r.standard.failing, consensus: r.consensus.failing },
  totalOperationCost: { standard: r.standard.totalOperationCost, consensus: r.consensus.totalOperationCost },
  perInput: r.standard.inputs.map((x, i) => ({ index: i, unlockingBytes: x.unlockingBytes, budget: x.budget,
    standard: x.operationCost, consensus: r.consensus.inputs[i].operationCost, success: [x.success, r.consensus.inputs[i].success] })) });

const onPool = evaluate(tx(pool.steps));
assert(rejected(onPool));
assert.deepEqual(onPool.standard.failing, [10, 11]);
assert.deepEqual(onPool.consensus.failing, [10, 11]);
const onHonest = evaluate(tx(honest.steps));
assert(rejected(onHonest));
assert.deepEqual(onHonest.standard.failing, [11]);
assert.deepEqual(onHonest.consensus.failing, [11]);
assert(!accepted(onHonest));

const out = {
  label: 'ENG-510 pool-key replay without a pool proof: research prototype, SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY, local VMs only',
  planningProof: { label: 'L1', programVkeyHash: L1.programVkeyHash, publicValuesBytes: L1.publicValuesBytes },
  poolProgramVkeyHash: GRAPH_RECORD.program.programVkeyHash,
  factory: { redeemBytes: factory.redeem.length, lockingHex: Buffer.from(factory.locking).toString('hex') },
  verdictCommitment: v5.vectors.find(x => x.name === 'b1-rel1').runBind32,
  poolGraphWithL1Witness: { ...summary(onPool), reading: 'refused at the terminal (10: the pairing binds the pool program key) and at the factory (11: L1 s1 is not mask(SHA-256(runBind32))); inputs 0-9 accept. Its size uses L1 witness bytes on the pool lockings: an estimate of the pool-mode transaction, not a measurement of it' },
  honestGraphWithPoolFactory: { ...summary(onHonest), reading: 'every graph input accepts L1 under its own key; only the pool factory (pinned to the pool graph root) refuses' },
};
writeFileSync(outPath, JSON.stringify(out, null, 1) + '\n');
console.log(JSON.stringify({ poolGraph: { bytes: onPool.bytes, failing: out.poolGraphWithL1Witness.failing },
  honestGraph: { bytes: onHonest.bytes, failing: out.honestGraphWithPoolFactory.failing }, factoryRedeemBytes: factory.redeem.length }, null, 1));
