// Research prototype — not reviewed (R-384, ARCH-232).
//
// Verdict fan-out: one verifier run authorizes M settlements.
//   shape (a): the verifier transaction mints M distinct verdicts, C_j = runBind_j; the aggregate
//              commits runBind_1 ‖ … ‖ runBind_M, so s1 = mask(SHA-256(C_0 ‖ … ‖ C_{M-1})).
//              Settlements are unchanged. Aggregate-of-aggregates (c) has this same on-chain shape.
//   shape (b): the verifier transaction mints M copies of one verdict committing a Merkle root R
//              of the M runBinds; s1 = mask(SHA-256(R)); each settlement proves inclusion (see
//              measure-merkle-settlement.mjs for that side).
// Real-proof positives use demo modes (the retained proofs' public values are 179-byte APNTAGV3
// strings): (a) splits them over the M verdict commitments, (b) commits SHA-256 of them in every
// copy. Pool modes are measured for exact transaction size on the real graph (where only the gate,
// input 11, refuses: L1's public values are not runBinds) and as gate positives on a stub root.
//
// usage: node measure-fanout.mjs GATED_JSON VECTORS_DIR OUT_JSON
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { bin, reverse, vMinting33, SETTLEMENT_LOCK, buildTransaction, evaluate, accepted, rejected,
  stubGraph, le32, maskedDigestScalar, buildFactory } from './onetx-lib.mjs';
import { sha256, p2sh32 } from './factory.mjs';

const [gatedPath, vectorsDir, outPath] = process.argv.slice(2);
const gated = JSON.parse(readFileSync(gatedPath));
const L1 = JSON.parse(readFileSync(`${vectorsDir}/L1.json`));
const L1proof = JSON.parse(readFileSync(L1.proofFile));
const pv = bin(L1proof.publicValuesHex);
assert.equal(pv.length, 179);
const graph = gated.steps;
const root = bin(graph[0].locking);
const s3Le32 = bin(L1.s3Le32);
const base = { N: 11, vMinting33, graphRoot: root, settlementLock: SETTLEMENT_LOCK, s3Le32 };
const stubRedeem = Uint8Array.of(0x75, 0x51);
const stubLock = p2sh32(stubRedeem);
const stubFor = s1 => {
  const s = stubGraph(Uint8Array.from([...le32(s1), ...s3Le32]));
  return [{ locking: stubLock, unlocking: Uint8Array.from([...s[0].unlocking, 0x02, ...stubRedeem]) }, ...s.slice(1)];
};
const chunks = (bytes, m) => {
  const size = Math.ceil(bytes.length / m); const out = [];
  for (let i = 0; i < m; i++) out.push(bytes.slice(i * size, Math.min(bytes.length, (i + 1) * size)));
  assert(out.every(c => c.length > 0 && c.length <= 128));
  return out;
};
const summary = r => ({ bytes: r.bytes, standardVerify: r.standard.verify, consensusVerify: r.consensus.verify,
  failing: { standard: r.standard.failing, consensus: r.consensus.failing },
  factoryOperationCost: { standard: r.standard.inputs[11]?.operationCost, consensus: r.consensus.inputs[11]?.operationCost },
  factoryBudget: r.standard.inputs[11]?.budget, totalStandardOperationCost: r.standard.totalOperationCost });
const results = { M1Reference: null, shapes: { a: {}, b: {} }, negatives: [], ablations: [] };
const must = (name, r, expect) => {
  const ok = expect === 'accept' ? accepted(r) : rejected(r);
  if (!ok) throw new Error(`${name}: expected ${expect}: ${JSON.stringify(summary(r))}`);
  return summary(r);
};

for (const M of [1, 2, 4, 8]) {
  const runBinds = Array.from({ length: M }, (_, j) => sha256(Buffer.from(`R-384 pool statement ${j} of ${M} (synthetic)`)));
  // ---- shape (a) ----
  {
    const entry = {};
    if (M >= 2) {
      const f = buildFactory({ ...base, M, mode: 'demo-chunks', shape: 'a' });
      const parts = chunks(pv, M);
      entry.demoRealProof = must(`a-demo-M${M}`, evaluate(buildTransaction({ graph, factory: f,
        verdicts: parts.map(c => ({ commitment: c })) })), 'accept');
      entry.demoRealProof.factoryRedeemBytes = f.redeem.length;
      // negative: the same chunks in another order
      const swapped = [parts[1], parts[0], ...parts.slice(2)];
      results.negatives.push({ name: `a-demo-M${M}-verdicts-swapped`, ...must(`a-demo-M${M}-swap`,
        evaluate(buildTransaction({ graph, factory: f, verdicts: swapped.map(c => ({ commitment: c })) })), 'reject') });
    }
    const pf = buildFactory({ ...base, M, mode: 'pool', shape: 'a' });
    const onReal = evaluate(buildTransaction({ graph, factory: pf, verdicts: runBinds.map(c => ({ commitment: c })) }));
    assert(rejected(onReal));
    assert.deepEqual(onReal.standard.failing, [11]); assert.deepEqual(onReal.consensus.failing, [11]);
    entry.poolRealGraph = { bytes: onReal.bytes, refusedOnlyAtGate: true, factoryRedeemBytes: pf.redeem.length,
      factoryStandardOperationCost: onReal.standard.inputs[11].operationCost };
    const s1 = maskedDigestScalar(Uint8Array.from(runBinds.flatMap(c => [...c])));
    const sf = buildFactory({ ...base, M, mode: 'pool', shape: 'a', graphRoot: stubLock });
    entry.poolStubPositive = must(`a-pool-stub-M${M}`, evaluate(buildTransaction({ graph: stubFor(s1), factory: sf,
      verdicts: runBinds.map(c => ({ commitment: c })) })), 'accept');
    if (M >= 2) {
      results.negatives.push({ name: `a-pool-M${M}-verdicts-swapped`, ...must(`a-pool-M${M}-swap`, evaluate(buildTransaction({
        graph: stubFor(s1), factory: sf, verdicts: [runBinds[1], runBinds[0], ...runBinds.slice(2)].map(c => ({ commitment: c })) })), 'reject') });
      results.negatives.push({ name: `a-pool-M${M}-one-verdict-dropped`, ...must(`a-pool-M${M}-drop`, evaluate(buildTransaction({
        graph: stubFor(s1), factory: sf, verdicts: runBinds.slice(0, -1).map(c => ({ commitment: c })) })), 'reject') });
      results.negatives.push({ name: `a-pool-M${M}-verdict-duplicated`, ...must(`a-pool-M${M}-dup`, evaluate(buildTransaction({
        graph: stubFor(s1), factory: sf, verdicts: [runBinds[0], ...runBinds.slice(0, -1)].map(c => ({ commitment: c })) })), 'reject') });
      // Boundary shift: same concatenation, commitments of 33 and 31 bytes. COMMITMENT_SIZE refuses it;
      // with that check removed the gate accepts it (the witness of the check).
      const shifted = runBinds.map(c => c);
      shifted[0] = Uint8Array.from([...runBinds[0], runBinds[1][0]]);
      shifted[1] = runBinds[1].slice(1);
      const shiftTx = f => buildTransaction({ graph: stubFor(s1), factory: f, verdicts: shifted.map(c => ({ commitment: c })) });
      results.negatives.push({ name: `a-pool-M${M}-boundary-shift`, ...must(`a-pool-M${M}-shift`, evaluate(shiftTx(sf)), 'reject') });
      if (M === 2) {
        const ablated = buildFactory({ ...base, M, mode: 'pool', shape: 'a', graphRoot: stubLock, ablate: ['COMMITMENT_SIZE'] });
        const w = evaluate(shiftTx(ablated));
        results.ablations.push({ check: 'COMMITMENT_SIZE', attack: 'boundary shift, M = 2, pool mode, stub root',
          attackPassesAblated: accepted(w), attackRefusedByFull: true });
        assert(accepted(w));
      }
    }
    results.shapes.a[M] = entry;
  }
  // ---- shape (b) ----
  if (M >= 2) {
    const entry = {};
    const f = buildFactory({ ...base, M, mode: 'demo-digest', shape: 'b' });
    const C = bin(L1.publicValuesSha256);
    entry.demoRealProof = must(`b-demo-M${M}`, evaluate(buildTransaction({ graph, factory: f,
      verdicts: Array.from({ length: M }, () => ({ commitment: C })) })), 'accept');
    entry.demoRealProof.factoryRedeemBytes = f.redeem.length;
    const odd = Array.from({ length: M }, (_, j) => ({ commitment: j === M - 1 ? reverse(C) : C }));
    results.negatives.push({ name: `b-demo-M${M}-one-copy-differs`, ...must(`b-demo-M${M}-odd`,
      evaluate(buildTransaction({ graph, factory: f, verdicts: odd })), 'reject') });
    const R = sha256(Buffer.from(`R-384 Merkle root of ${M} runBinds (synthetic)`));
    const pf = buildFactory({ ...base, M, mode: 'pool', shape: 'b' });
    const onReal = evaluate(buildTransaction({ graph, factory: pf, verdicts: Array.from({ length: M }, () => ({ commitment: R })) }));
    assert(rejected(onReal));
    assert.deepEqual(onReal.standard.failing, [11]);
    entry.poolRealGraph = { bytes: onReal.bytes, refusedOnlyAtGate: true, factoryRedeemBytes: pf.redeem.length,
      factoryStandardOperationCost: onReal.standard.inputs[11].operationCost };
    const sf = buildFactory({ ...base, M, mode: 'pool', shape: 'b', graphRoot: stubLock });
    entry.poolStubPositive = must(`b-pool-stub-M${M}`, evaluate(buildTransaction({ graph: stubFor(maskedDigestScalar(R)), factory: sf,
      verdicts: Array.from({ length: M }, () => ({ commitment: R })) })), 'accept');
    results.shapes.b[M] = entry;
  }
}
// ---- variable M, shape (a): one factory; each verifier run chooses 1 <= M <= 8 (M = outputs - 2) ----
{
  const maxM = 8;
  const vf = buildFactory({ ...base, mode: 'pool', shape: 'a', variableMaxM: maxM });
  const vfStub = buildFactory({ ...base, mode: 'pool', shape: 'a', variableMaxM: maxM, graphRoot: stubLock });
  const vfDemo = buildFactory({ ...base, mode: 'demo-chunks', shape: 'a', variableMaxM: maxM });
  results.variableM = { maxM, poolRedeemBytes: vf.redeem.length, demoRedeemBytes: vfDemo.redeem.length, perM: {}, refused: {} };
  const runBindsFor = M => Array.from({ length: M }, (_, j) => sha256(Buffer.from(`R-384 variable-M statement ${j} of ${M}`)));
  for (const M of [1, 2, 4, 8]) {
    const runBinds = runBindsFor(M);
    const s1 = maskedDigestScalar(Uint8Array.from(runBinds.flatMap(c => [...c])));
    const verdicts = runBinds.map(c => ({ commitment: c }));
    const onReal = evaluate(buildTransaction({ graph, factory: vf, verdicts }));
    assert(rejected(onReal)); assert.deepEqual(onReal.standard.failing, [11]); assert.deepEqual(onReal.consensus.failing, [11]);
    const entry = { poolRealGraphBytes: onReal.bytes,
      poolStubPositive: must(`variable-pool-stub-M${M}`, evaluate(buildTransaction({ graph: stubFor(s1), factory: vfStub, verdicts })), 'accept') };
    if (M >= 2) entry.demoRealProof = must(`variable-demo-M${M}`, evaluate(buildTransaction({ graph, factory: vfDemo,
      verdicts: chunks(pv, M).map(c => ({ commitment: c })) })), 'accept');
    results.variableM.perM[M] = entry;
  }
  const nine = runBindsFor(9);
  const s1nine = maskedDigestScalar(Uint8Array.from(nine.flatMap(c => [...c])));
  results.variableM.refused.M9 = must('variable-M9', evaluate(buildTransaction({ graph: stubFor(s1nine), factory: vfStub,
    verdicts: nine.map(c => ({ commitment: c })) })), 'reject');
  results.variableM.refused.M0 = must('variable-M0', evaluate(buildTransaction({ graph: stubFor(maskedDigestScalar(new Uint8Array())),
    factory: vfStub, verdicts: [] })), 'reject');
  // A run minting fewer verdicts than the proof committed (M = 2 of a 4-statement proof) is refused.
  const four = runBindsFor(4);
  const s1four = maskedDigestScalar(Uint8Array.from(four.flatMap(c => [...c])));
  results.variableM.refused.truncatedTo2Of4 = must('variable-truncated', evaluate(buildTransaction({ graph: stubFor(s1four), factory: vfStub,
    verdicts: four.slice(0, 2).map(c => ({ commitment: c })) })), 'reject');
}
results.M1Reference = results.shapes.a[1];
writeFileSync(outPath, JSON.stringify(results, null, 1) + '\n');
const brief = {};
for (const shape of ['a', 'b']) for (const [M, e] of Object.entries(results.shapes[shape])) brief[`${shape}-M${M}`] = {
  poolBytes: e.poolRealGraph.bytes, poolFactoryRedeem: e.poolRealGraph.factoryRedeemBytes,
  demoRealProofBytes: e.demoRealProof?.bytes, demoFactoryStdOps: e.demoRealProof?.factoryOperationCost?.standard,
  poolStubFactoryStdOps: e.poolStubPositive.factoryOperationCost.standard };
brief.variableM = { poolRedeemBytes: results.variableM.poolRedeemBytes, perM: Object.fromEntries(Object.entries(results.variableM.perM)
  .map(([M, e]) => [M, { poolBytes: e.poolRealGraphBytes, demoRealProofBytes: e.demoRealProof?.bytes,
    stubFactoryStdOps: e.poolStubPositive.factoryOperationCost.standard }])), refused: Object.keys(results.variableM.refused) };
console.log(JSON.stringify({ brief, negatives: results.negatives.map(n => n.name), ablations: results.ablations }, null, 1));
