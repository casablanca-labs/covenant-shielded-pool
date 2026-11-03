// Research prototype — not reviewed (R-384, ARCH-231/232).
//
// Derives the public verifier vectors for one retained SP1 6.3.1 Groth16
// wrapper proof. Generalises tools/verifier-intratx-measure/derive-apnt.mjs at
// tag archive/seal-era-final (which handled the L1 proof only) to the four
// retained proofs L1, L2, A and B, and adds an explicit program-key override
// that builds the vectors of a verifier keyed to a DIFFERENT program (a
// negative control: the real proof must then fail off chain and in script).
//
// Reads public proof material only (proof envelope, public values, the fixed
// wrapper key). Constructs no proof. Writes <out>.vectors.json (the
// generator's pairing-vectors format) and <out>.json (a public record).
//
// Also reads a pool aggregate proof's evidence (ENG-510, task 5.4 slice 2b).
//
// usage: node derive-wrapper-vectors.mjs --proof FILE --label L1 --generator DIR --out PREFIX
//          [--program-vkey-override HEX32]
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';

const args = Object.fromEntries(process.argv.slice(2).reduce((pairs, token, i, all) =>
  token.startsWith('--') ? [...pairs, [token.slice(2), all[i + 1]]] : pairs, []));
for (const required of ['proof', 'label', 'generator', 'out']) {
  if (!args[required]) throw new Error(`missing --${required}`);
}
const repoRoot = new URL('../../../', import.meta.url);
const conversion = await import(new URL('packages/reference-aggregator/dist/sp1_groth16_bn254_cashvm_conversion_v0.js', repoRoot));
const req = createRequire(resolve(args.generator, 'package.json'));
const { bn254 } = await import(req.resolve('@noble/curves/bn254.js'));
const sha = value => createHash('sha256').update(value).digest('hex');

// The proof file must be listed, with its exact SHA-256, in its directory's checksum file.
const proofFile = readFileSync(args.proof);
const sumsPath = ['SHA256SUMS.txt', 'SHA256SUMS'].map(n => resolve(dirname(args.proof), n)).find(existsSync);
assert(sumsPath, 'no SHA256SUMS next to the proof file');
const base = args.proof.split('/').at(-1);
assert(readFileSync(sumsPath, 'utf8').split('\n').some(line =>
  line.startsWith(sha(proofFile)) && line.trim().endsWith(base)), 'proof file digest not in SHA256SUMS');
const evidence = JSON.parse(proofFile);
// The retained seal-era proofs, or a pool aggregate proof (ENG-510: tools/apnt-pool-aggregate-sp1
// scripts/aggregate-proof-runner.sh), whose public values are exactly its 32-byte runBind32.
assert(['apnt-successor-aggregate-groth16-proof-evidence-v1', 'apnt-pool-aggregate-groth16-proof-evidence-v1'].includes(evidence.schema));
const publicValues = Buffer.from(evidence.publicValuesHex, 'hex');
if (evidence.schema === 'apnt-pool-aggregate-groth16-proof-evidence-v1') {
  assert.equal(publicValues.length, 32);
  assert.equal(evidence.publicValuesHex, evidence.runBind32);
  assert.equal(evidence.proofNonce, '00000000');
}
const envelope = conversion.parseSP1Groth16ProofEnvelopeV0(Buffer.from(evidence.proofBytesHex, 'hex'));
// The fixed SP1 wrapper key, as the tag's derive-apnt.mjs read it; no pin is created or changed.
const keySource = JSON.parse(readFileSync(new URL('packages/reference-aggregator/fixtures/apnt-import-created-note-cashvm-v0.json', repoRoot)));
const keyBytes = Buffer.from(keySource.mapping.verificationKeyHex, 'hex');
assert.equal(sha(keyBytes).slice(0, 8), envelope.wrapperKeyPrefixHex);
const key = conversion.parseSP1Groth16VerificationKeyV0(keyBytes);
const scalars = conversion.deriveSP1Groth16PublicScalarsV0({
  programVkeyHash32: Buffer.from(evidence.programVkeyHash, 'hex'), publicValues, envelope,
});
const msm = conversion.deriveCashVmPublicInputMsmV0(key, scalars);

const G1 = p => bn254.G1.Point.fromAffine({ x: p.x, y: p.y });
const G2 = p => bn254.G2.Point.fromAffine({
  x: { c0: p.x.real, c1: p.x.imaginary }, y: { c0: p.y.real, c1: p.y.imaginary },
});
const a = G1(envelope.a), b = G2(envelope.b), c = G1(envelope.c);
for (const p of [a, b, c, G1(key.alphaG1), G2(key.betaG2), G2(key.gammaG2), G2(key.deltaG2)]) p.assertValidity();
const verifies = ps => bn254.fields.Fp12.eql(bn254.pairingBatch(ps, true), bn254.fields.Fp12.ONE);
const pairsWith = base0 => {
  const vkx = msm.runtimeScalars.reduce((sum, s, i) => sum.add(s === 0n ? bn254.G1.Point.ZERO
    : G1(msm.runtimeIcPoints[i + 1]).multiply(s)), base0);
  return [
    { g1: a.negate(), g2: b }, { g1: G1(key.alphaG1), g2: G2(key.betaG2) },
    { g1: vkx, g2: G2(key.gammaG2) }, { g1: c, g2: G2(key.deltaG2) },
  ];
};

// The masked public-values digest is scalar 1; SP1 6.3.1 hash_bn254: SHA-256, hash[0] &= 0x1f.
const digest = createHash('sha256').update(publicValues).digest();
const masked = Buffer.from(digest); masked[0] &= 0x1f;
assert.equal(BigInt('0x' + masked.toString('hex')), scalars[1].value);
assert.equal(scalars[2].value, 0n); assert.equal(scalars[4].value, 0n);

let fixedBase = G1(msm.runtimeIcPoints[0]);
let programVkeyHex = evidence.programVkeyHash;
let override = false;
if (args['program-vkey-override']) {
  // Rekey the verifier to another program: IC0' = IC0 + s0'·IC1. The proof is unchanged.
  const other = BigInt('0x' + args['program-vkey-override']);
  assert(other !== scalars[0].value && other < conversion.BN254_SCALAR_FIELD_MODULUS);
  fixedBase = G1(key.ic[0]).add(G1(key.ic[1]).multiply(other));
  programVkeyHex = args['program-vkey-override'];
  override = true;
}
const offChain = verifies(pairsWith(fixedBase));
assert.equal(offChain, !override, override ? 'rekeyed verifier must refuse the real proof' : 'real proof must verify');
// A corrupted, on-curve C must fail under the honest key (negative control of this check itself).
const corrupted = pairsWith(fixedBase); corrupted[3] = { ...corrupted[3], g1: c.add(bn254.G1.Point.BASE) };
assert(!verifies(corrupted));

const g1 = p => ({ x: p.x.toString(), y: p.y.toString() });
const g2 = p => ({ x: { c0: p.x.real.toString(), c1: p.x.imaginary.toString() }, y: { c0: p.y.real.toString(), c1: p.y.imaginary.toString() } });
const fixedAffine = fixedBase.toAffine();
const vec = {
  description: `Retained SP1 6.3.1 wrapper proof ${args.label}; folded two-runtime-input wrapper VK` +
    (override ? `; REKEYED to program ${programVkeyHex} (negative control)` : ''),
  p: bn254.fields.Fp.ORDER.toString(), r: bn254.fields.Fr.ORDER.toString(),
  publicInputs: msm.runtimeScalars.map(String),
  vk: { alpha: g1(key.alphaG1), beta: g2(key.betaG2), gamma: g2(key.gammaG2), delta: g2(key.deltaG2),
    ic: [{ x: fixedAffine.x.toString(), y: fixedAffine.y.toString() }, ...msm.runtimeIcPoints.slice(1).map(g1)] },
  proof: { a: g1(envelope.a), b: g2(envelope.b), c: g1(envelope.c) },
  invalid: { publicInputs: [String(msm.runtimeScalars[0] + 1n), String(msm.runtimeScalars[1])] },
};
// The exact 66 bytes the gate expects at the start of verifier input 0's unlocking bytecode:
// OP_PUSHDATA1 0x84 (the 132-byte GLV genesis blob), LE32(s1), LE32(s3).
const le32 = v => { const out = Buffer.alloc(32); let x = v; for (let i = 0; i < 32; i++) { out[i] = Number(x & 0xffn); x >>= 8n; } return out; };
const [s1, s3] = msm.runtimeScalars;
const record = {
  label: args.label, proofFile: args.proof, proofFileSha256: sha(proofFile),
  programVkeyHash: programVkeyHex, programVkeyOverride: override,
  retainedProgramVkeyHash: evidence.programVkeyHash,
  wrapperVkSha256: sha(keyBytes), proofEnvelopeBytes: evidence.proofBytesHex.length / 2,
  publicValuesBytes: publicValues.length, publicValuesSha256: digest.toString('hex'),
  s1: s1.toString(), s3: s3.toString(),
  s1Le32: le32(s1).toString('hex'), s3Le32: le32(s3).toString('hex'),
  input0PrefixHex: Buffer.concat([Buffer.from([0x4c, 0x84]), le32(s1), le32(s3)]).toString('hex'),
  recursionVkeyRootHex: envelope.recursionVkeyRootHex, exitCodeHex: envelope.exitCodeHex,
  proofNonceHex: envelope.proofNonceHex, offChainPairingAccepted: offChain,
  onCurveCorruptedCRejected: true,
};
const stringify = value => JSON.stringify(value, (_, v) => typeof v === 'bigint' ? v.toString() : v, 2) + '\n';
writeFileSync(`${args.out}.vectors.json`, stringify(vec));
writeFileSync(`${args.out}.json`, stringify(record));
console.log(stringify({ label: record.label, override, offChainPairingAccepted: offChain,
  publicValuesBytes: record.publicValuesBytes, publicValuesSha256: record.publicValuesSha256 }));
