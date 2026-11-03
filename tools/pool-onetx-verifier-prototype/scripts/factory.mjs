// Research prototype — not reviewed (R-384, ARCH-231/232).
//
// Builds the one-transaction verdict factory from ../factory/apnt_pool_onetx_verdict_factory_v0.casm
// with the repository's CashAssembly compiler (packages/protocol-runtime, the compiler the pool
// covenants use). `ablate` removes named //@check blocks (replacing them with their //@ablated
// text, if any) for the one-check-at-a-time controls.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const repo = new URL('../../../', import.meta.url);
const { compileApntCashAssemblySourceV0 } = await import(new URL('packages/protocol-runtime/dist/apnt_cashassembly_compiler_v0.js', repo));
export const FACTORY_SOURCE = readFileSync(new URL('../factory/apnt_pool_onetx_verdict_factory_v0.casm', import.meta.url), 'utf8');
const hex = b => Buffer.from(b).toString('hex');
const push = bytes => {
  assert(bytes.length >= 1 && bytes.length <= 75);
  return `0x${bytes.length.toString(16).padStart(2, '0')}${hex(bytes)}`;
};
export const sha256 = b => Uint8Array.from(createHash('sha256').update(b).digest());
export const hash256 = b => sha256(sha256(b));
export const p2sh32 = redeem => Uint8Array.from([0xaa, 0x20, ...hash256(redeem), 0x87]);
export const CHECKS = ['LAYOUT', 'OWN_TOKEN', 'GRAPH_ROOT', 'VERDICTS', 'COMMITMENT_SIZE', 'STATEMENT', 'FACTORY', 'CHANGE'];

/**
 * shape: 'a' distinct verdicts (the gate hashes C_0 ‖ … ‖ C_{M-1}); 'b' root copies (every C_j = C_0 = R).
 * mode:  'pool'         each commitment exactly 32 bytes; s1 = mask(SHA-256(acc)), acc as the shape defines;
 *        'demo-digest'  each commitment is SHA-256(public values) and is masked directly (shape a with M = 1,
 *                       or shape b): the retained seal-era proofs' public values are 179 bytes, not a runBind;
 *        'demo-chunks'  shape a, commitments are non-empty chunks of the public values; s1 = mask(SHA-256(acc)).
 */
export function buildFactory({ mode, shape = 'a', N = 11, M = 1, vMinting33, graphRoot, settlementLock,
  verdictFloor = 1000, s3Le32, ablate = [], variableMaxM }) {
  // variableMaxM: M is not compiled in; each spend has M = outputs - 2 with 1 <= M <= variableMaxM.
  assert(['pool', 'demo-digest', 'demo-chunks'].includes(mode));
  assert(['a', 'b'].includes(shape));
  // demo-digest (the commitment IS the digest) fits shape b, or shape a with exactly one verdict.
  assert(mode !== 'demo-digest' || shape === 'b' || (M === 1 && variableMaxM === undefined));
  assert(mode !== 'demo-chunks' || shape === 'a');
  assert(vMinting33.length === 33 && vMinting33[32] === 0x02);
  assert(graphRoot.length === 35 && settlementLock.length === 35 && s3Le32.length === 32);
  for (const a of ablate) assert(CHECKS.includes(a), a);
  let source = FACTORY_SOURCE;
  // Remove ablated blocks: //@check NAME ... [//@ablated TEXT] //@end
  source = source.replace(/\/\/@check ([A-Z_]+)\n([\s\S]*?)\/\/@end\n/gu, (_, name, body) => {
    if (!ablate.includes(name)) return body.replace(/^\/\/@ablated.*\n/mu, '');
    const ablated = /^\/\/@ablated (.*)$/mu.exec(body);
    return ablated ? `${ablated[1]}\n` : '';
  });
  const markers = {
    '@N@': String(N), '@N_PLUS_1@': String(N + 1), '@VERDICT_FLOOR@': String(verdictFloor),
    '@OUTPUT_COUNT_CHECK@': variableMaxM ? `<3> <${variableMaxM + 3}> OP_WITHIN OP_VERIFY` : `<${M + 2}> OP_NUMEQUALVERIFY`,
    '@M_VALUE@': variableMaxM ? 'OP_TXOUTPUTCOUNT <2> OP_SUB' : `<${M}>`,
    '@M_PLUS_1_VALUE@': variableMaxM ? 'OP_TXOUTPUTCOUNT <1> OP_SUB' : `<${M + 1}>`,
    '@V_MINTING_PUSH@': push(vMinting33), '@GRAPH_ROOT_PUSH@': push(graphRoot),
    '@SETTLEMENT_LOCK_PUSH@': push(settlementLock), '@S3_LE_PUSH@': push(s3Le32),
    '@COMMITMENT_SIZE_CHECK@': mode === 'demo-chunks' ? 'OP_SIZE <0> OP_GREATERTHAN OP_VERIFY' : 'OP_SIZE <32> OP_NUMEQUALVERIFY',
    '@DIGEST@': mode === 'demo-digest' ? '' : 'OP_SHA256',
    '@LOOP_INIT@': shape === 'a' ? '<0> <0>' : '<0> OP_OUTPUTTOKENCOMMITMENT <0>',
    '@ACCUMULATE@': shape === 'a' ? 'OP_ROT OP_SWAP OP_CAT OP_SWAP' : '<2> OP_PICK OP_EQUALVERIFY',
  };
  for (const [k, v] of Object.entries(markers)) source = source.split(k).join(v);
  assert(!/@[A-Z_0-9]+@/u.test(source.replace(/\/\/.*$/gmu, '')), 'unsubstituted marker');
  const redeem = compileApntCashAssemblySourceV0(source);
  return { source, redeem, locking: p2sh32(redeem), unlocking: pushData(redeem) };
}

export function pushData(bytes) {
  if (bytes.length <= 75) return Uint8Array.from([bytes.length, ...bytes]);
  if (bytes.length <= 255) return Uint8Array.from([0x4c, bytes.length, ...bytes]);
  return Uint8Array.from([0x4d, bytes.length & 0xff, bytes.length >> 8, ...bytes]);
}
