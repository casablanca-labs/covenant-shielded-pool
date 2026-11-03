// Research prototype — not reviewed (R-384, ARCH-231).
//
// Independent check of the terminal's fixed pairing factor (open item 2 of the 2026-09-10 review,
// "the fixed torus constant was not recomputed from the VK"). The six limbs are read from the
// GENERATED terminal CashScript text (not from the generator's JavaScript); they are the quotient-torus
// coordinate u of the fixed Miller factor, the class [1 + u·w] in Fp12*/Fp6*. Final exponentiation
// kills Fp6*, so FE(1 + u·w) must equal e(alpha, beta) · e(IC0', gamma) computed from the verifying key
// alone with noble-curves' own pairing, where IC0' = IC0 + s0·IC1 carries the program key s0.
//
// usage: node check-fixed-constant.mjs TERMINAL_CASH VECTORS_JSON GENERATOR_DIR [OTHER_VECTORS_JSON]
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';

const [terminalPath, vectorsPath, generatorDir, otherPath] = process.argv.slice(2);
const req = createRequire(resolve(generatorDir, 'package.json'));
const { bn254 } = await import(req.resolve('@noble/curves/bn254.js'));
const { Fp2, Fp6, Fp12 } = bn254.fields;
const text = readFileSync(terminalPath, 'utf8');
const call = /fp12MulTorus\(v524,v525,v526,v527,v528,v529,v530,v531,v532,v533,v534,v535,\s*([0-9]+),\s*([0-9]+),\s*([0-9]+),\s*([0-9]+),\s*([0-9]+),\s*([0-9]+)\)/u.exec(text);
assert(call, 'fixed-factor call not found in the terminal source');
const limbs = call.slice(1, 7).map(BigInt);
const u = Fp6.create({ c0: Fp2.fromBigTuple([limbs[0], limbs[1]]), c1: Fp2.fromBigTuple([limbs[2], limbs[3]]),
  c2: Fp2.fromBigTuple([limbs[4], limbs[5]]) });
const X = Fp12.create({ c0: Fp6.ONE, c1: u });
const fe = Fp12.finalExponentiate(X);
const g1 = o => bn254.G1.Point.fromAffine({ x: BigInt(o.x), y: BigInt(o.y) });
const g2 = o => bn254.G2.Point.fromAffine({ x: Fp2.fromBigTuple([BigInt(o.x.c0), BigInt(o.x.c1)]), y: Fp2.fromBigTuple([BigInt(o.y.c0), BigInt(o.y.c1)]) });
const expected = v => Fp12.mul(bn254.pairing(g1(v.vk.alpha), g2(v.vk.beta)), bn254.pairing(g1(v.vk.ic[0]), g2(v.vk.gamma)));
const vec = JSON.parse(readFileSync(vectorsPath, 'utf8'));
const e = expected(vec);
const relation = Fp12.eql(fe, e) ? 'equal' : Fp12.eql(fe, Fp12.inv(e)) ? 'inverse'
  : Fp12.eql(fe, Fp12.conjugate(e)) ? 'conjugate' : 'none';
const out = { terminal: terminalPath, vectors: vectorsPath, limbs: limbs.map(String), relationToVkPairings: relation };
if (otherPath) {
  const other = JSON.parse(readFileSync(otherPath, 'utf8'));
  const eo = expected(other);
  out.other = otherPath;
  out.relationToOtherKey = Fp12.eql(fe, eo) ? 'equal' : Fp12.eql(fe, Fp12.inv(eo)) ? 'inverse' : 'none';
}
console.log(JSON.stringify(out, null, 1));
if (relation === 'none') process.exitCode = 1;
