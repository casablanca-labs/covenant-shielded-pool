// Research prototype — not reviewed (R-384, ARCH-231/232).
// Shared transaction builder and evaluator for the one-transaction verifier measurements.
// Every outpoint hash is non-palindromic; libauth takes outpoint hashes and token
// categories in display order and writes (and exposes to the VM) their reversal,
// which probe-token-category-order.mjs demonstrates.
import assert from 'node:assert/strict';
import { encodeTransactionBch } from '@bitauth/libauth';
import { createVirtualMachineBch2026Bchn } from '../../pool-vm-cost-meter/bchn-vm.mjs';
import { buildFactory, sha256 } from './factory.mjs';

const repo = new URL('../../../', import.meta.url);
const settlementModule = await import(new URL('packages/protocol-runtime/dist/apnt_pool_settlement_covenant_v1.js', repo));
const treeModule = await import(new URL('packages/protocol-runtime/dist/apnt_pool_tree_covenants_v1.js', repo));

export const bin = h => Uint8Array.from(Buffer.from(h, 'hex'));
export const hex = b => Buffer.from(b).toString('hex');
export const reverse = b => Uint8Array.from(b).reverse();
const seq = (n, a, b) => Uint8Array.from({ length: n }, (_, i) => (i * a + b) & 0xff);

// Categories in display order (as libauth's token.category takes them); the VM sees the reversal.
export const V_DISPLAY = seq(32, 29, 7);
export const R_DISPLAY = seq(32, 31, 101);
export const T_DISPLAY = seq(32, 37, 53);
export const W_DISPLAY = seq(32, 41, 17); // a foreign category, for the OWN_TOKEN control
export const vMinting33 = Uint8Array.from([...reverse(V_DISPLAY), 0x02]);
for (const c of [V_DISPLAY, R_DISPLAY, T_DISPLAY, W_DISPLAY]) assert.notDeepEqual(c, reverse(c));

// The shipped pool settlement and pending-batch locks for these categories (task 3.4 sources).
// The settlement builder requires the range-record value; the reference settlement fixture uses 1,000 sats.
const params = { network: 'chipnet', verdictCategoryWire32: reverse(V_DISPLAY), rangeCategoryWire32: reverse(R_DISPLAY),
  rootCategoryWire32: reverse(T_DISPLAY), rootCopyCount: 4, rootCopySats: 1000n, foldBountySats: 5000n,
  recordValueSats: 1000n };
export const SETTLEMENT_LOCK = settlementModule.buildAPNTPoolSettlementCovenantsV1(params).settlement.lockingBytecode;
// The pending lock is used only as a wrong-destination control; give its required
// batch-leaf digest a fixed public fixture value, as in the covenant tests.
export const PENDING_LOCK = treeModule.assembleAPNTPoolPendingBatchCovenantV1(
  treeModule.getAPNTPoolTreeCovenantSourceV1('pendingBatch'),
  { rootCategoryWire32: reverse(T_DISPLAY), leafListDigest32: sha256(Buffer.from('R-384 pending-batch wrong-destination control')) }).lockingBytecode;
export const P2PKH = Uint8Array.from([0x76, 0xa9, 0x14, ...seq(20, 13, 5), 0x88, 0xac]);
export const ATTACKER_P2PKH = Uint8Array.from([0x76, 0xa9, 0x14, ...seq(20, 17, 99), 0x88, 0xac]);
assert.equal(SETTLEMENT_LOCK.length, 35);
assert.equal(PENDING_LOCK.length, 35);

// ENG-764 (R-864): the Chipnet one-transaction verifier is judged under BCHN v29's OP_DEFINE cost, which libauth
// 3.1.0-next.8 alone omits (ARCH-353): libauth's BCH 2026 VM with the defined body charged (pool-vm-cost-meter/bchn-vm.mjs).
export const VMS = { standard: createVirtualMachineBch2026Bchn(true), consensus: createVirtualMachineBch2026Bchn(false) };
export const GRAPH_VALUE = 10000n, FACTORY_VALUE = 10000n, VERDICT_VALUE = 1000n;

const outpoint = i => Uint8Array.from({ length: 32 }, (_, j) => (j * 7 + i * 13 + 1) & 0xff);
const tokenOut = (category, capability, commitment) => ({ category, amount: 0n, nft: { capability, commitment } });

/**
 * graph: [{locking, unlocking}] hex; factory: buildFactory result or {locking, unlocking} bytes;
 * verdicts: [{commitment, lock?, capability?, value?, category?}]; options mutate the factory return,
 * the change and extra outputs. Returns { transaction, sourceOutputs, fee, bytes }.
 */
export function buildTransaction({ graph, factory, factoryToken = tokenOut(V_DISPLAY, 'minting', new Uint8Array()),
  verdicts, factoryReturn = {}, change = {}, extraOutputs = [], factoryIndex, extraInputs = [] }) {
  const graphInputs = graph.map(s => ({ locking: typeof s.locking === 'string' ? bin(s.locking) : s.locking,
    unlocking: typeof s.unlocking === 'string' ? bin(s.unlocking) : s.unlocking, value: GRAPH_VALUE }));
  const factoryInput = { locking: factory.locking, unlocking: factory.unlocking, value: FACTORY_VALUE, token: factoryToken };
  const all = [...graphInputs];
  all.splice(factoryIndex ?? all.length, 0, factoryInput);
  all.push(...extraInputs);
  const inputs = all.map((x, i) => ({ outpointTransactionHash: outpoint(i), outpointIndex: i % 3,
    sequenceNumber: 0, unlockingBytecode: x.unlocking }));
  const sourceOutputs = all.map(x => ({ lockingBytecode: x.locking, valueSatoshis: x.value, ...(x.token ? { token: x.token } : {}) }));
  const outputs = [
    ...verdicts.map(v => ({ lockingBytecode: v.lock ?? SETTLEMENT_LOCK, valueSatoshis: v.value ?? VERDICT_VALUE,
      token: tokenOut(v.category ?? V_DISPLAY, v.capability ?? 'none', v.commitment) })),
    ...(factoryReturn.omit ? [] : [{ lockingBytecode: factoryReturn.lock ?? factory.locking,
      valueSatoshis: factoryReturn.value ?? FACTORY_VALUE,
      token: tokenOut(factoryReturn.category ?? factoryToken.category, factoryReturn.capability ?? 'minting',
        factoryReturn.commitment ?? new Uint8Array()) }]),
    ...(change.omit ? [] : [{ lockingBytecode: change.lock ?? P2PKH, valueSatoshis: 0n, ...(change.token ? { token: change.token } : {}) }]),
    ...extraOutputs.map(o => ({ lockingBytecode: o.lock ?? SETTLEMENT_LOCK, valueSatoshis: o.value ?? VERDICT_VALUE,
      ...(o.token ? { token: o.token } : {}) })),
  ];
  const transaction = { version: 2, locktime: 0, inputs, outputs };
  const bytes = encodeTransactionBch(transaction).length;
  const totalIn = sourceOutputs.reduce((a, o) => a + o.valueSatoshis, 0n);
  const fixedOut = outputs.reduce((a, o) => a + o.valueSatoshis, 0n);
  const fee = BigInt(bytes); // 1 sat/B
  const changeIndex = change.omit ? -1 : verdicts.length + (factoryReturn.omit ? 0 : 1);
  if (changeIndex >= 0) {
    outputs[changeIndex].valueSatoshis = totalIn - fixedOut - fee;
    assert(outputs[changeIndex].valueSatoshis >= 546n, 'change below dust');
  }
  assert.equal(encodeTransactionBch(transaction).length, bytes);
  return { transaction, sourceOutputs, fee, bytes };
}

export function evaluate(program) {
  const result = { bytes: encodeTransactionBch(program.transaction).length };
  for (const [name, vm] of Object.entries(VMS)) {
    const inputs = program.transaction.inputs.map((input, i) => {
      const state = vm.evaluate({ ...program, inputIndex: i });
      const unlockingBytes = input.unlockingBytecode.length;
      const budget = (41 + unlockingBytes) * 800;
      return { index: i, unlockingBytes, budget, operationCost: state.metrics.operationCost,
        headroom: budget - state.metrics.operationCost, success: vm.stateSuccess(state) === true,
        error: state.error ?? (vm.stateSuccess(state) === true ? null : String(vm.stateSuccess(state))) };
    });
    const verify = vm.verify(program);
    result[name] = { verify: verify === true ? true : String(verify), inputs,
      failing: inputs.filter(x => !x.success).map(x => x.index),
      totalOperationCost: inputs.reduce((a, x) => a + x.operationCost, 0) };
  }
  return result;
}

export const accepted = r => r.standard.verify === true && r.consensus.verify === true;
export const rejected = r => r.standard.verify !== true && r.consensus.verify !== true;

// A stand-in graph with NO verifier: input 0 is a bare `OP_DROP OP_1` lock whose unlocking pushes a
// 132-byte blob beginning with the chosen scalars; inputs 1..N-1 are bare OP_1 locks. Used for the
// GRAPH_ROOT ablation witness and for pool-mode gate positives (with a factory pinned to this root).
export function stubGraph(prefix64, N = 11) {
  assert.equal(prefix64.length, 64);
  const blob = Uint8Array.from([...prefix64, ...new Uint8Array(68)]);
  return [
    { locking: Uint8Array.of(0x75, 0x51), unlocking: Uint8Array.from([0x4c, 0x84, ...blob]) },
    ...Array.from({ length: N - 1 }, () => ({ locking: Uint8Array.of(0x51), unlocking: new Uint8Array() })),
  ];
}

export function le32(value) {
  const out = new Uint8Array(32); let x = BigInt(value);
  for (let i = 0; i < 32; i++) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
}
/** SP1 6.3.1 hash_bn254 of public-value bytes: SHA-256 with the top three bits cleared, as a scalar. */
export function maskedDigestScalar(bytes) {
  const d = sha256(bytes); d[0] &= 0x1f;
  return BigInt('0x' + hex(d));
}
export { buildFactory };
