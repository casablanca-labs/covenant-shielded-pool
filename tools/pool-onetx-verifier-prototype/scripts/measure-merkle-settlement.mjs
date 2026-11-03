// Research prototype — not reviewed (R-384, ARCH-232).
//
// The settlement-side cost of fan-out shape (b): a settlement whose input-0 verdict commits a Merkle
// root R of M runBinds must show that SHA-256(S) is a leaf of R. This measures that check alone, in
// both BCH 2026 VMs, as a delta over the shipped covenant's check 1 (SHA-256(S) equals the verdict's
// commitment), which it replaces. A stand-in input 0 (P2SH32, holding the verdict token) runs:
//
//   depth 0 (today):  <S>                OP_SHA256 <own commitment> OP_EQUAL
//   depth d (b):      <S> <sibs> <j>     leaf = SHA-256(S); for each level: sibling from sibs, the
//                                        side from j's low bit; j >> d = 0; |sibs| = 32·d exactly
//
// The unlocking stays canonical (no index or path malleability): the settlement's txid is what the
// fold builds on (design.md, "Implemented (task 3.4, ENG-270)", unlocking rule).
//
// usage: node measure-merkle-settlement.mjs OUT_JSON
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { createVirtualMachineBch2026, encodeTransactionBch } from '@bitauth/libauth';
import { sha256, p2sh32, pushData } from './factory.mjs';

const repo = new URL('../../../', import.meta.url);
const { compileApntCashAssemblySourceV0 } = await import(new URL('packages/protocol-runtime/dist/apnt_cashassembly_compiler_v0.js', repo));
const [outPath] = process.argv.slice(2);
const VMS = { standard: createVirtualMachineBch2026(true), consensus: createVirtualMachineBch2026(false) };
const V = Uint8Array.from({ length: 32 }, (_, i) => (i * 29 + 7) & 0xff);

const script = d => compileApntCashAssemblySourceV0(d === 0
  ? 'OP_SHA256 OP_INPUTINDEX OP_UTXOTOKENCOMMITMENT OP_EQUAL'
  : [
    // stack: S sibs j
    `OP_OVER OP_SIZE <${32 * d}> OP_NUMEQUALVERIFY OP_DROP`,
    'OP_ROT OP_SHA256 OP_ROT',            // j h sibs
    ...Array.from({ length: d }, () =>
      '<32> OP_SPLIT OP_TOALTSTACK <2> OP_PICK <2> OP_MOD OP_IF OP_SWAP OP_ENDIF OP_CAT OP_SHA256 OP_SWAP <2> OP_DIV OP_SWAP OP_FROMALTSTACK'),
    'OP_DROP OP_SWAP <0> OP_NUMEQUALVERIFY',  // the index had exactly d bits
    'OP_INPUTINDEX OP_UTXOTOKENCOMMITMENT OP_EQUAL',
  ].join('\n'));

function tree(leaves) {
  const levels = [leaves];
  while (levels.at(-1).length > 1) {
    const prev = levels.at(-1); const next = [];
    for (let i = 0; i < prev.length; i += 2) next.push(sha256(Uint8Array.from([...prev[i], ...prev[i + 1]])));
    levels.push(next);
  }
  return levels;
}
const pathOf = (levels, j) => levels.slice(0, -1).map((level, l) => level[(j >> l) ^ 1]);
const numPush = j => j === 0 ? Uint8Array.of(0x00) : j <= 16 ? Uint8Array.of(0x50 + j) : pushData(Uint8Array.of(j));

function run(d, j, { S, R, sibs, indexPush }) {
  const redeem = script(d);
  const unlocking = Uint8Array.from([...pushData(S), ...(d === 0 ? [] : [...pushData(sibs), ...indexPush]), ...pushData(redeem)]);
  const transaction = { version: 2, locktime: 0,
    inputs: [{ outpointTransactionHash: Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff), outpointIndex: 1, sequenceNumber: 0, unlockingBytecode: unlocking }],
    outputs: [{ lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n }] };
  const sourceOutputs = [{ lockingBytecode: p2sh32(redeem), valueSatoshis: 100000n,
    token: { category: V, amount: 0n, nft: { capability: 'none', commitment: R } } }];
  const out = { redeemBytes: redeem.length, unlockingBytes: unlocking.length, txBytes: encodeTransactionBch(transaction).length };
  for (const [name, vm] of Object.entries(VMS)) {
    const st = vm.evaluate({ transaction, sourceOutputs, inputIndex: 0 });
    out[name] = { success: vm.stateSuccess(st) === true, operationCost: st.metrics.operationCost,
      hashIterations: st.metrics.hashDigestIterations, error: st.error ?? null };
  }
  return out;
}

const B = 16;
const S = Uint8Array.from({ length: 88 + 396 * B }, (_, i) => (i * 131 + 17) & 0xff); // a stand-in statement, B = 16
const results = { statementBytes: S.length, depths: {} };
for (const d of [0, 1, 2, 3]) {
  const M = 1 << d;
  const leaves = Array.from({ length: M }, (_, j) => sha256(Buffer.from(`runBind ${j}`)));
  const j = M - 1; // the last leaf: every direction bit set where d > 0
  leaves[j] = sha256(S);
  const levels = tree(leaves);
  const R = levels.at(-1)[0];
  const sibs = Uint8Array.from(pathOf(levels, j).flatMap(x => [...x]));
  const ok = run(d, j, { S, R, sibs, indexPush: numPush(j) });
  assert(ok.standard.success && ok.consensus.success, JSON.stringify(ok));
  const entry = { M, positive: ok, negatives: {} };
  const neg = (name, args) => {
    const r = run(d, j, { S, R, sibs, indexPush: numPush(j), ...args });
    assert(!r.standard.success && !r.consensus.success, `${name} accepted at depth ${d}`);
    entry.negatives[name] = { standard: r.standard.error, consensus: r.consensus.error };
  };
  neg('other-statement', { S: Uint8Array.from(S, (b, i) => i === 100 ? b ^ 1 : b) });
  if (d > 0) {
    neg('wrong-index', { indexPush: numPush(j ^ 1) });
    neg('index-out-of-range', { indexPush: numPush(j + M) });
    neg('sibling-flipped', { sibs: Uint8Array.from(sibs, (b, i) => i === 5 ? b ^ 1 : b) });
    neg('path-extra-byte', { sibs: Uint8Array.from([...sibs, 0]) });
    neg('internal-node-as-leaf', { S: Uint8Array.from([...pathOf(levels, j)[0]].concat([...leaves[j]])) });
  }
  results.depths[d] = entry;
}
for (const d of [1, 2, 3]) {
  const e = results.depths[d], z = results.depths[0];
  e.deltaOverToday = { unlockingBytes: e.positive.unlockingBytes - z.positive.unlockingBytes,
    redeemBytes: e.positive.redeemBytes - z.positive.redeemBytes,
    standardOperationCost: e.positive.standard.operationCost - z.positive.standard.operationCost,
    consensusOperationCost: e.positive.consensus.operationCost - z.positive.consensus.operationCost };
}
writeFileSync(outPath, JSON.stringify(results, null, 1) + '\n');
console.log(JSON.stringify(Object.fromEntries(Object.entries(results.depths).map(([d, e]) => [`depth${d}/M${e.M}`,
  { redeem: e.positive.redeemBytes, unlocking: e.positive.unlockingBytes, std: e.positive.standard.operationCost,
    con: e.positive.consensus.operationCost, delta: e.deltaOverToday, negatives: Object.keys(e.negatives) }])), null, 1));
