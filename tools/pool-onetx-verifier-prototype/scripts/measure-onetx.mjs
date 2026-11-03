// Research prototype — not reviewed (R-384, ARCH-231).
//
// The one-transaction pool verifier with its verdict gate, measured in both BCH 2026 VMs
// (libauth 3.1.0-next.8, createVirtualMachineBch2026(true) standard and (false) consensus),
// with full transaction verify() and every input evaluated.
//
// Inputs 0..10: the residue-construction graph (gated driver, one extra input expected).
// Input 11: the verdict factory. Outputs: verdict, factory returned, change.
//
// usage: node measure-onetx.mjs GATED_JSON REKEYED_GATED_JSON VECTORS_DIR OUT_JSON
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import {
  bin, hex, reverse, V_DISPLAY, W_DISPLAY, vMinting33, SETTLEMENT_LOCK, PENDING_LOCK, ATTACKER_P2PKH,
  buildTransaction, evaluate, accepted, rejected, stubGraph, le32, maskedDigestScalar, buildFactory,
} from './onetx-lib.mjs';
import { CHECKS, sha256, p2sh32 } from './factory.mjs';

const [gatedPath, rekeyedPath, vectorsDir, outPath] = process.argv.slice(2);
const gated = JSON.parse(readFileSync(gatedPath));
const rekeyed = JSON.parse(readFileSync(rekeyedPath)).rekeyed;
const rec = l => JSON.parse(readFileSync(`${vectorsDir}/${l}.json`));
const R = { L1: rec('L1'), L2: rec('L2'), A: rec('A'), B: rec('B') };
const graphs = { L1: gated.steps, L2: gated.extraProofs.L2.steps, A: gated.extraProofs.A.steps, B: gated.extraProofs.B.steps };
const root = bin(graphs.L1[0].locking);
for (const l of Object.keys(graphs)) assert.equal(graphs[l][0].locking, graphs.L1[0].locking);
const rekeyedRoot = bin(rekeyed.steps[0].locking);
assert.notDeepEqual(rekeyedRoot, root);
const s3Le32 = bin(R.L1.s3Le32);
for (const l of Object.keys(R)) assert.equal(R[l].s3Le32, R.L1.s3Le32);
const C = l => bin(R[l].publicValuesSha256); // demo verdict commitment: SHA-256 of the proof's public values

const base = { N: 11, M: 1, vMinting33, graphRoot: root, settlementLock: SETTLEMENT_LOCK, s3Le32 };
const factory = buildFactory({ ...base, mode: 'demo-digest' });
const results = { factory: { redeemBytes: factory.redeem.length, lockingBytes: factory.locking.length,
  unlockingBytes: factory.unlocking.length, redeemHex: hex(factory.redeem) }, positives: {}, negatives: [], ablations: [] };

const run = (name, program, expect) => {
  const r = evaluate(program);
  const ok = expect === 'accept' ? accepted(r) : rejected(r);
  const entry = { name, expect, bytes: r.bytes, ok,
    standard: { verify: r.standard.verify, failing: r.standard.failing },
    consensus: { verify: r.consensus.verify, failing: r.consensus.failing } };
  if (!ok) throw new Error(`${name}: expected ${expect}, got ${JSON.stringify(entry)}`);
  return { r, entry };
};

// ---- positives: four real proofs, one graph, one factory ----
for (const l of ['L1', 'L2', 'A', 'B']) {
  const program = buildTransaction({ graph: graphs[l], factory, verdicts: [{ commitment: C(l) }] });
  const { r } = run(`positive-${l}`, program, 'accept');
  results.positives[l] = { bytes: r.bytes, fee: Number(program.fee),
    standardOperationCost: r.standard.totalOperationCost, consensusOperationCost: r.consensus.totalOperationCost,
    minStandardHeadroom: Math.min(...r.standard.inputs.map(x => x.headroom)),
    minConsensusHeadroom: Math.min(...r.consensus.inputs.map(x => x.headroom)),
    perInput: r.standard.inputs.map((x, i) => ({ index: i, unlockingBytes: x.unlockingBytes, budget: x.budget,
      standardOperationCost: x.operationCost, standardHeadroom: x.headroom,
      consensusOperationCost: r.consensus.inputs[i].operationCost, consensusHeadroom: r.consensus.inputs[i].headroom })),
    outputs: program.transaction.outputs.map(o => ({ lockingBytes: o.lockingBytecode.length, value: String(o.valueSatoshis),
      token: o.token ? { commitmentBytes: o.token.nft.commitment.length, capability: o.token.nft.capability } : null })) };
}
const L1 = results.positives.L1;
L1.headroomTo100000 = 100000 - L1.bytes;

// ---- negatives (each must be refused by full verify() in both VMs) ----
const neg = (name, program, note) => { const { entry } = run(name, program, 'reject'); results.negatives.push({ ...entry, note }); };
const tx = (over = {}) => buildTransaction({ graph: graphs.L1, factory, verdicts: [{ commitment: C('L1') }], ...over });

// proof and public values
const ctl = Object.fromEntries(gated.graphControls.map(c => [c.name, c.steps]));
neg('tampered-proof-C-plus-G1', tx({ graph: ctl['on-curve-C-plus-G1-complete-trace-old-root'] }), 'on-curve C+G, complete re-witnessed trace, honest root: only the terminal refuses');
for (const n of ['off-curve-A', 'off-curve-C', 'off-curve-B', 'on-twist-off-subgroup-B', 'Pu0+p', 'Q0xa+p', 'Pu2+p'])
  neg(`malformed-proof-${n}`, tx({ graph: ctl[n] }), 'round-2 input-validation control, re-run in the gated transaction');
for (let i = 0; i <= 10; i++) neg(`graph-state-corruption-input-${i}`, tx({ graph: ctl[`input-${i}-state`] }), 'one live state byte flipped');
neg('wrong-public-value-verdict-only', tx({ verdicts: [{ commitment: C('L2') }] }), 'L1 proof, verdict claims L2\'s public values');
neg('wrong-public-value-consistent-s1', tx({ graph: gated.wrongPublicValue['consistent-wrong-s1'].steps, verdicts: [{ commitment: C('L2') }] }),
  'L1 proof re-witnessed for L2\'s s1 and a verdict for L2: the gate agrees, the pairing refuses');
neg('wrong-recursion-root-s3', tx({ graph: gated.wrongPublicValue['consistent-wrong-s3'].steps }), 's3 + 1, re-witnessed: gate and terminal refuse');
neg('wrong-program-key-rekeyed-graph', tx({ graph: rekeyed.steps }), 'graph keyed to program key s0 with one bit flipped; real L1 proof and honest root');
{
  const f2 = buildFactory({ ...base, mode: 'demo-digest', graphRoot: rekeyedRoot });
  neg('wrong-program-key-factory-pinned-to-rekeyed-graph', buildTransaction({ graph: rekeyed.steps, factory: f2, verdicts: [{ commitment: C('L1') }] }),
    'even a factory pinned to the other program\'s graph mints nothing: the terminal refuses the proof');
  neg('wrong-program-key-honest-graph-foreign-factory', buildTransaction({ graph: graphs.L1, factory: f2, verdicts: [{ commitment: C('L1') }] }),
    'a factory pinned to another program refuses the honest graph');
}
// replay
neg('verdict-replayed-to-different-S', buildTransaction({ graph: graphs.L2, factory, verdicts: [{ commitment: C('L1') }] }), 'L2\'s valid run minting L1\'s verdict');
neg('verdict-for-fabricated-S', tx({ verdicts: [{ commitment: sha256(Buffer.from('R-384 fabricated statement')) }] }), 'valid L1 run, verdict for an arbitrary statement');
// sibling-input substitution and reordering
const splice = (k, from) => graphs.L1.map((s, i) => i === k ? from[k] : s);
neg('substitute-input-0-from-L2-with-L2-verdict', tx({ graph: splice(0, graphs.L2), verdicts: [{ commitment: C('L2') }] }), 'L2\'s scalar carrier spliced into L1\'s run');
neg('substitute-input-0-from-L2-with-L1-verdict', tx({ graph: splice(0, graphs.L2) }), '');
neg('substitute-input-5-from-L2', tx({ graph: splice(5, graphs.L2) }), '');
neg('substitute-terminal-from-L2', tx({ graph: splice(10, graphs.L2) }), '');
neg('swap-graph-inputs-3-4', tx({ graph: graphs.L1.map((s, i) => graphs.L1[i === 3 ? 4 : i === 4 ? 3 : i]) }), '');
neg('factory-at-input-0', tx({ factoryIndex: 0 }), 'graph shifted to inputs 1..11');
neg('factory-at-input-5', tx({ factoryIndex: 5 }), '');
neg('missing-terminal', tx({ graph: graphs.L1.slice(0, 10) }), '11 inputs: factory at 10');
neg('duplicate-terminal', tx({ graph: [...graphs.L1, graphs.L1[10]] }), '13 inputs');
neg('extra-plain-input', tx({ extraInputs: [{ locking: Uint8Array.of(0x51), unlocking: new Uint8Array(), value: 5000n }] }), '13 inputs');
neg('second-factory-input', tx({ extraInputs: [{ locking: factory.locking, unlocking: factory.unlocking, value: 10000n,
  token: { category: V_DISPLAY, amount: 0n, nft: { capability: 'minting', commitment: new Uint8Array() } } }] }), 'two V minting inputs, 13 inputs');
// the verdict output redirected or malformed
neg('verdict-to-pending-lock', tx({ verdicts: [{ commitment: C('L1'), lock: PENDING_LOCK }] }), 'ARCH-190 probe: a verdict straight under the pending lock');
neg('verdict-to-attacker', tx({ verdicts: [{ commitment: C('L1'), lock: ATTACKER_P2PKH }] }), '');
neg('verdict-mutable', tx({ verdicts: [{ commitment: C('L1'), capability: 'mutable' }] }), '');
neg('verdict-minting', tx({ verdicts: [{ commitment: C('L1'), capability: 'minting' }] }), '');
neg('verdict-commitment-33-bytes', tx({ verdicts: [{ commitment: Uint8Array.from([...C('L1'), 0]) }] }), '');
neg('verdict-commitment-reversed', tx({ verdicts: [{ commitment: reverse(C('L1')) }] }), 'byte-order control: non-palindromic digest reversed');
neg('verdict-below-floor', tx({ verdicts: [{ commitment: C('L1'), value: 999n }] }), '');
neg('extra-forged-verdict-output', tx({ extraOutputs: [{ token: { category: V_DISPLAY, amount: 0n, nft: { capability: 'none', commitment: C('L2') } } }] }), 'a fourth output with a second V NFT');
neg('change-is-a-forged-verdict', tx({ change: { lock: SETTLEMENT_LOCK, token: { category: V_DISPLAY, amount: 0n, nft: { capability: 'none', commitment: C('L2') } } } }), '');
neg('factory-not-returned', tx({ factoryReturn: { omit: true } }), 'minting capability burned; 2 outputs');
neg('factory-to-attacker', tx({ factoryReturn: { lock: ATTACKER_P2PKH } }), 'minting NFT stolen');
neg('factory-downgraded-to-mutable', tx({ factoryReturn: { capability: 'mutable' } }), '');
neg('factory-commitment-set', tx({ factoryReturn: { commitment: Uint8Array.of(1) } }), '');
neg('factory-value-reduced', tx({ factoryReturn: { value: 9999n } }), '');
{
  const fDisplay = buildFactory({ ...base, mode: 'demo-digest', vMinting33: Uint8Array.from([...V_DISPLAY, 0x02]) });
  neg('byte-order-category-pinned-in-display-order', buildTransaction({ graph: graphs.L1, factory: fDisplay, verdicts: [{ commitment: C('L1') }] }),
    'the factory pins V in display order; the VM exposes wire order');
}

// ---- one check removed at a time: its attack must pass the ablated factory and fail the full one ----
const attackerRootStub = stubGraph(Uint8Array.from([...le32(R.L1.s1), ...s3Le32])); // no verifier at all
const fabricated = sha256(Buffer.from('R-384 fabricated statement'));
const witnesses = {
  LAYOUT: f => tx({ factory: f, extraOutputs: [{ token: { category: V_DISPLAY, amount: 0n, nft: { capability: 'none', commitment: fabricated } } }] }),
  OWN_TOKEN: f => buildTransaction({ graph: graphs.L1, factory: f, verdicts: [{ commitment: C('L1'), category: W_DISPLAY }],
    factoryToken: { category: W_DISPLAY, amount: 0n, nft: { capability: 'minting', commitment: new Uint8Array() } } }),
  GRAPH_ROOT: f => buildTransaction({ graph: attackerRootStub, factory: f, verdicts: [{ commitment: C('L1') }] }),
  VERDICTS: f => tx({ factory: f, verdicts: [{ commitment: C('L1'), lock: PENDING_LOCK }] }),
  STATEMENT: f => tx({ factory: f, verdicts: [{ commitment: fabricated }] }),
  FACTORY: f => tx({ factory: f, factoryReturn: { lock: ATTACKER_P2PKH } }),
  CHANGE: f => tx({ factory: f, change: { lock: SETTLEMENT_LOCK, token: { category: V_DISPLAY, amount: 0n, nft: { capability: 'none', commitment: fabricated } } } }),
};
for (const check of CHECKS.filter(c => c !== 'COMMITMENT_SIZE')) {
  const ablated = buildFactory({ ...base, mode: 'demo-digest', ablate: [check] });
  const withAblated = evaluate(witnesses[check](ablated));
  const withFull = evaluate(witnesses[check](factory));
  const entry = { check, attackPassesAblated: accepted(withAblated), attackRefusedByFull: rejected(withFull),
    fullFailing: { standard: withFull.standard.failing, consensus: withFull.consensus.failing },
    ablatedVerify: { standard: withAblated.standard.verify, consensus: withAblated.consensus.verify } };
  results.ablations.push(entry);
  if (!entry.attackPassesAblated || !entry.attackRefusedByFull) throw new Error(`ablation witness failed: ${JSON.stringify(entry)}`);
}

// ---- pool mode (M = 1): s1 = mask(SHA-256(runBind32)); one opcode more than demo-digest ----
{
  const runBind = sha256(Buffer.from('R-384 pool statement S (synthetic)'));
  const s1 = maskedDigestScalar(runBind);
  const poolFactory = buildFactory({ ...base, mode: 'pool' });
  const onL1 = evaluate(buildTransaction({ graph: graphs.L1, factory: poolFactory, verdicts: [{ commitment: runBind }] }));
  // With the real L1 graph the pool gate must refuse (L1's public values are not a runBind) and only input 11 fails.
  assert(rejected(onL1));
  assert.deepEqual(onL1.standard.failing, [11]); assert.deepEqual(onL1.consensus.failing, [11]);
  // The factory pins a 35-byte P2SH32 root, so the gate positive uses a P2SH32-wrapped stub root
  // (redeem `OP_DROP OP_1`) whose unlocking starts with the pool scalars. No verifier runs here:
  // this measures the pool gate itself; the graph is measured with real proofs above.
  const stub = stubGraph(Uint8Array.from([...le32(s1), ...s3Le32]));
  const stubRedeem = Uint8Array.of(0x75, 0x51);
  const stubLock = p2sh32(stubRedeem);
  const stubP2sh = [{ locking: stubLock, unlocking: Uint8Array.from([...stub[0].unlocking, 0x02, ...stubRedeem]) }, ...stub.slice(1)];
  const poolStubFactory = buildFactory({ ...base, mode: 'pool', graphRoot: stubLock });
  const pos = evaluate(buildTransaction({ graph: stubP2sh, factory: poolStubFactory, verdicts: [{ commitment: runBind }] }));
  assert(accepted(pos), JSON.stringify(pos.standard.verify));
  const bad = evaluate(buildTransaction({ graph: stubP2sh, factory: poolStubFactory, verdicts: [{ commitment: reverse(runBind) }] }));
  assert(rejected(bad));
  results.poolModeM1 = {
    redeemBytes: poolFactory.redeem.length, redeemDeltaVsDemo: poolFactory.redeem.length - factory.redeem.length,
    realGraphTransactionBytes: onL1.bytes, realGraphRefusedOnlyAtFactory: true,
    stubGatePositive: { standardFactoryOperationCost: pos.standard.inputs[11].operationCost,
      consensusFactoryOperationCost: pos.consensus.inputs[11].operationCost,
      factoryBudget: pos.standard.inputs[11].budget },
    stubGateReversedCommitmentRefused: true,
  };
}
results.demoFactoryOperationCost = { standard: evaluate(tx()).standard.inputs[11].operationCost,
  consensus: evaluate(tx()).consensus.inputs[11].operationCost };
writeFileSync(outPath, JSON.stringify(results, null, 1) + '\n');
console.log(JSON.stringify({
  factory: { redeemBytes: results.factory.redeemBytes, unlockingBytes: results.factory.unlockingBytes },
  positives: Object.fromEntries(Object.entries(results.positives).map(([k, v]) => [k, { bytes: v.bytes,
    std: v.standardOperationCost, con: v.consensusOperationCost, minStdHeadroom: v.minStandardHeadroom }])),
  headroomTo100000: L1.headroomTo100000, negatives: results.negatives.length,
  ablations: results.ablations.map(a => `${a.check}:${a.attackPassesAblated && a.attackRefusedByFull ? 'fires' : 'FAIL'}`),
  poolModeM1: results.poolModeM1, demoFactoryOperationCost: results.demoFactoryOperationCost,
}, null, 1));
