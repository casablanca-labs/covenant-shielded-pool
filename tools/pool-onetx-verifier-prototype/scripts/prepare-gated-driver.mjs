// Research prototype — not reviewed (R-384, ARCH-231).
// PairFold-5 peval-fuse construction research credit: toorik2 / Margus Kokk.
// Source-owned quotient-torus arithmetic: mr-zwets (groth16_cashscript 0cff585, package
// licence field ISC, no licence file; see ../ATTRIBUTION.md).
//
// Builds the gated driver from the generator's build_vectors_residue.mjs in a scratch copy.
// The first four edits are exactly those of tools/verifier-intratx-measure/round2/prepare.mjs
// at tag archive/seal-era-final (driver extraction only). This slice adds two layout edits
// and a new footer; upstream arithmetic, generated checks and the compiler stay intact:
//
//   1. the graph's input-count pins (input 0 and the last three inputs) expect
//      specs.length + GATED_EXTRA_INPUTS inputs, so the verdict factory can sit after
//      the eleven verifier inputs (it is input 11);
//   2. the driver's internal evaluation transaction appends GATED_EXTRA_INPUTS
//      placeholder inputs (locking OP_1, empty unlocking) so the pins are satisfied while
//      the driver tunes each input's density padding. Graph inputs never read input 11 or
//      any output, so the tuned bytes carry over to the real 12-input transaction, where
//      measure-onetx.mjs re-evaluates every input in both VMs.
//
// With GATED_VARIANT_MAP set (ENG-524), a third edit hands the driver a recorded per-input
// variant choice instead of letting it measure one. With RESCHEDULE on, the driver otherwise
// picks each input's rescheduled or raw compile on its first assembly by comparing tuned op
// cost on that assembly's proof, so the lockings depend on the planning proof (ENG-523). The
// map file is {"schema": "apnt-pool-onetx-graph-variant-map-v1", "variants": [...]}, one
// "resched" or "raw" per graph input, in input order. The driver refuses a map whose length
// is not the graph's input count. A null entry leaves that input to the planning measurement below.
//
// ENG-526 (ARCH-273): the generator's per-chunk choice scored a variant that rejects the planning
// proof as Infinity and silently kept the other, so a proof the graph rejects decided the graph (the
// committed pool-key terminal, planned with a proof it rejects by design). A fourth edit, always
// applied, replaces that choice with gatedChooseVariant (variant-map.mjs): a rejecting variant is
// refused with the named cause VARIANT_REJECTS_PLANNING_PROOF unless GATED_VARIANT_MAP names that
// input's variant. A planning proof that every variant accepts gets the generator's choice unchanged.
// Replays of the committed pool-key graph never measure: run-graph.mjs pool-key passes the pinned map.
//
// ENG-763/ENG-764 (R-864, ARCH-353): a fifth edit, always applied, sets the pad rule. The generator shrinks each input's
// zero pad to the smallest length its VMs accept (tunedLen). Under libauth 3.1.0-next.8 alone that undercounts
// OP_DEFINE, which BCHN v29 and the Functions CHIP also charge the defined body's bytes, and Chipnet refused the first
// stage-2 verifier for it. GATED_PAD_RULE=bchn (the default) runs the driver's two VMs under BCHN's OP_DEFINE cost
// (bchnInstructionSet, tools/pool-vm-cost-meter/bchn-vm.mjs, inlined) and pads every input of an accepted graph to at
// least GATED_PAD_MARGIN op-cost units under its budget (default 10,000), measured again to a fixed point because a pad
// also raises its predecessor's cost (OP_INPUTBYTECODE pushes the successor's whole unlocking). GATED_PAD_RULE=libauth
// with GATED_PAD_MARGIN=0 is the archived rule, unchanged: the local 0x99 replay (run-graph.mjs pool-key-local) uses it
// to reproduce its recorded witnesses. The redeem drops the pad unexamined, so the rule changes no locking.
//
// usage: node prepare-gated-driver.mjs SCRATCH [EXTRA_INPUTS=1]
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { bchnInstructionSet } from '../../pool-vm-cost-meter/bchn-vm.mjs';
import { gatedChooseVariant } from './variant-map.mjs';

const [scratchArg, extraArg = '1'] = process.argv.slice(2);
const scratch = resolve(scratchArg);
const extra = Number(extraArg);
assert(Number.isSafeInteger(extra) && extra >= 0);
const path = `${scratch}/generator/chunked/intratx/build_vectors_residue.mjs`;
const original = readFileSync(path, 'utf8');
const sha = s => createHash('sha256').update(s).digest('hex');
assert.equal(sha(original), 'd659343a783949e43a49342fa9bf2214caab0af730b9a6e2bf62330e175eb3c1',
  'build_vectors_residue.mjs is not the archived groth16_cashscript 0cff585 source');
let source = original;
const replace = (a, b) => { assert.equal(source.split(a).length, 2, a); source = source.replace(a, b); };
// --- round-2 prepare.mjs edits (verbatim logic) ---
replace("import { infinityInstances } from './infinity_fixtures.mjs';\n", '');
const start = source.indexOf('const mp = JSON.parse(');
const end = source.indexOf('function millerPairsFor(inst)', start);
assert(start > 0 && end > start);
source = source.slice(0, start) + source.slice(end);
replace('function buildSpecs(inst) {', 'function buildSpecs(inst, witnessOverride) {');
replace('const root = MILLER_TORUS ? residueTorusWitness(fRaw) : residueWitness(fRaw);',
  'const root = witnessOverride ?? (MILLER_TORUS ? residueTorusWitness(fRaw) : residueWitness(fRaw));');
replace('const resched = s.file.includes',
  "writeFileSync(`${process.env.MEASURE_PREFIX}.input-${i}.cash`, readFileSync(PROBE));\n    const resched = s.file.includes");
// --- R-384 layout edits ---
replace('const expectedInputCount = i === 0 || retainPositionGate ? specs.length : undefined;',
  'const expectedInputCount = i === 0 || retainPositionGate ? specs.length + GATED_EXTRA_INPUTS : undefined;');
replace('function verificationData(inputs) {',
  `const GATED_EXTRA_INPUTS = ${extra};\n` +
  'const GATED_PLACEHOLDERS = Array.from({ length: GATED_EXTRA_INPUTS }, () => ({ locking: Uint8Array.of(0x51), unlocking: new Uint8Array(0) }));\n' +
  'function verificationData(inputs) {\n  inputs = [...inputs, ...GATED_PLACEHOLDERS];');
// --- ENG-526 fail-closed per-chunk choice (always) ---
replace("      chosenCache.set(key, tB < tR ? 'raw' : 'resched');",
  '      chosenCache.set(key, gatedChooseVariant(i, [op1[i], standardOp1[i]], [rawOp, rawStandardOp], tR, tB));');
replace('function argBytesOf(s) {', `${gatedChooseVariant.toString()}\nfunction argBytesOf(s) {`);
// --- ENG-763/ENG-764 pad rule (always) ---
const padRule = { rule: process.env.GATED_PAD_RULE ?? 'bchn', marginUnits: 0 };
assert(padRule.rule === 'bchn' || padRule.rule === 'libauth', `GATED_PAD_RULE must be bchn or libauth, not ${padRule.rule}`);
const marginText = process.env.GATED_PAD_MARGIN ?? (padRule.rule === 'bchn' ? '10000' : '0');
assert(/^(?:0|[1-9]\d{0,5})$/u.test(marginText), `GATED_PAD_MARGIN must be a whole number of op-cost units, not ${marginText}`);
padRule.marginUnits = Number(marginText);
replace('const realVm = createVirtualMachineBch2026(false);\nconst standardVm = createVirtualMachineBch2026(true);\n',
  `import * as GATED_LIBAUTH from '@bitauth/libauth';\nconst GATED_PAD_RULE = ${JSON.stringify(padRule)};\n${bchnInstructionSet.toString()}\n` +
  "const realVm = GATED_PAD_RULE.rule === 'bchn' ? GATED_LIBAUTH.createVirtualMachine(bchnInstructionSet(GATED_LIBAUTH, false)) : createVirtualMachineBch2026(false);\n" +
  "const standardVm = GATED_PAD_RULE.rule === 'bchn' ? GATED_LIBAUTH.createVirtualMachine(bchnInstructionSet(GATED_LIBAUTH, true)) : createVirtualMachineBch2026(true);\n");
replace('const tunedLen = (argLen, opCost) => Math.min(TARGET_UNLOCK, Math.max(argLen + 3, Math.ceil(opCost / 800) - 41));',
  'const tunedLen = (argLen, opCost) => Math.min(TARGET_UNLOCK, Math.max(argLen + 3, Math.ceil((opCost + GATED_PAD_RULE.marginUnits) / 800) - 41));');
replace('    targets = tightened;\n  }\n', [
  '    targets = tightened;',
  '  }',
  '  // ENG-763: every input of an accepted graph keeps at least GATED_PAD_RULE.marginUnits under its budget in both VMs.',
  "  // tunedLen asks for the margin, but raising one pad raises its predecessor's cost (OP_INPUTBYTECODE pushes the",
  "  // successor's whole unlocking): raise each short input and measure again, to a fixed point.",
  '  for (let round = 0; !expectRejected && GATED_PAD_RULE.marginUnits > 0; round += 1) {',
  '    const cost = specs.map((_, i) => Math.max(op2[i].operationCost, standardOp2[i].operationCost));',
  '    const short = specs.map((_, i) => (41 + inputs[i].unlocking.length) * 800 - cost[i] < GATED_PAD_RULE.marginUnits);',
  '    if (!short.some(Boolean)) break;',
  '    targets = targets.map((target, i) => (short[i] ? Math.max(target + 1, tunedLen(argB[i].length + tailLen(i), cost[i])) : target));',
  '    if (round >= 64 || targets.some((target) => target > TARGET_UNLOCK)) {',
  "      throw new Error(`GATED_PAD_MARGIN_UNMET: inputs ${short.flatMap((s, i) => (s ? [i] : [])).join(',')} cannot keep ${GATED_PAD_RULE.marginUnits} units under budget within ${TARGET_UNLOCK} unlocking bytes`);",
  '    }',
  '    inputs = specs.map((_, i) => ({ locking: lockings[i], unlocking: mkUnlock(i, targets[i]) }));',
  '    op2 = specs.map((_, i) => evalInput(inputs, i));',
  '    standardOp2 = specs.map((_, i) => evalInput(inputs, i, standardVm));',
  '  }',
  '',
].join('\n'));
// --- ENG-524 recorded variant map (only when GATED_VARIANT_MAP is set) ---
const mapPath = process.env.GATED_VARIANT_MAP;
let variantMap;
if (mapPath !== undefined) {
  const text = readFileSync(resolve(mapPath));
  const map = JSON.parse(text);
  assert.equal(map.schema, 'apnt-pool-onetx-graph-variant-map-v1', 'GATED_VARIANT_MAP: unknown schema');
  assert(Array.isArray(map.variants) && map.variants.length > 0, 'GATED_VARIANT_MAP: variants must be a non-empty array');
  for (const [i, v] of map.variants.entries()) assert(v === 'resched' || v === 'raw' || v === null, `GATED_VARIANT_MAP: input ${i} is ${JSON.stringify(v)}`);
  variantMap = { path: resolve(mapPath), sha256: sha(text), variants: map.variants };
  replace('  if (!chosenCache.has(key) && P2SH && v.raw) {',
    '  if (GATED_VARIANTS.length !== specs.length) throw new Error(' +
    '`GATED_VARIANT_MAP names ${GATED_VARIANTS.length} graph inputs; the graph has ${specs.length}`);\n' +
    '  if (GATED_VARIANTS[i] !== null) chosenCache.set(key, GATED_VARIANTS[i]);\n' +
    '  if (!chosenCache.has(key) && P2SH && v.raw) {');
  replace('const chosenCache = new Map();',
    `const GATED_VARIANT_MAP = ${JSON.stringify(variantMap)};\nconst GATED_VARIANTS = GATED_VARIANT_MAP.variants;\nconst chosenCache = new Map();`);
}
const cut = source.indexOf('const committedSpecs = buildSpecs(INSTANCES.committed);');
assert(cut > 0);
let footer = readFileSync(new URL('./gated-driver-footer.txt', import.meta.url), 'utf8');
const anchor = 'const out = { mode: GATED_MODE, extraInputs: GATED_EXTRA_INPUTS,';
assert.equal(footer.split(anchor).length, 2, anchor);
footer = footer.replace(anchor, `${anchor} padRule: GATED_PAD_RULE,${variantMap === undefined ? '' : ' variantMap: GATED_VARIANT_MAP,'}`);
source = source.slice(0, cut) + footer;
const output = `${scratch}/generator/chunked/intratx/measure_gated.mjs`;
writeFileSync(output, source);
console.log(JSON.stringify({ output, originalSha256: sha(original), driverSha256: sha(source), extraInputs: extra, padRule,
  changes: ['round-2: omit synthetic fixture initialization', 'round-2: old-root injection',
    'round-2: retain transformed source', `R-384: graph expects ${extra} more input(s) (input-count pins)`,
    'R-384: placeholder input(s) in the driver evaluation transaction', 'R-384: gated footer',
    'ENG-526: a variant that rejects the planning proof never decides the choice',
    `ENG-763: pad rule ${padRule.rule}, margin ${padRule.marginUnits} op-cost units per input`,
    ...(variantMap === undefined ? [] : [`ENG-524: recorded variant map ${variantMap.sha256}`])] }));
