// Research prototype — not reviewed (R-384, ARCH-231).
//
// Generates and assembles one verifier graph in a scratch tree made by setup-scratch.mjs,
// with the round-2 submitted layout (normalized-controls-v3: mode 2, cuts
// 40,82,117,158,201,238,277,313, OP_COST_TARGET 7,950,000, BYTE_BUDGET 9,700,
// rescheduling on) and the gated driver (the graph expects one more input: the factory).
// Every step's command, exit, timestamps and worktree HEAD are recorded next to its output.
//
// usage: node run-graph.mjs SCRATCH NAME VECTORS_JSON VARIANTS
//   VARIANTS (required, ENG-526):
//     pool-key  replay the committed pool-key graph: loads the pinned variant map beside the graph record
//               (variant-map.mjs) and passes it as GATED_VARIANT_MAP; refuses an absent map, a changed
//               digest, a wrong input count, a caller-set GATED_VARIANT_MAP or cuts other than the record's.
//               No input's variant is measured, so the replay proof never shapes the lockings; the run then
//               fails unless the regenerated lockings are the graph record's (a refused output is renamed
//               <name>.gated.refused.json, so nothing downstream reads it).
//     pool-key-local  replay the independently pinned local 0x99 graph and map.
//   Each mode also fixes the driver's pad rule (ENG-763, prepare-gated-driver.mjs): pool-key and plan pad under BCHN
//   v29's OP_DEFINE cost with a margin of 10,000 op-cost units per input (Chipnet relays under that rule);
//   pool-key-local keeps the archived libauth rule with no margin, so it reproduces its recorded witnesses. A replay
//   refuses a caller-set GATED_PAD_RULE or GATED_PAD_MARGIN; plan takes them from the caller when set.
//     plan      explicit planning: the driver measures each input's variant on the planning proof and
//               refuses (VARIANT_REJECTS_PLANNING_PROOF) where a variant rejects it, unless GATED_VARIANT_MAP
//               names that input (null entries are measured). Rekeyed planning must name the terminal.
//   env passed through: GATED_MODE, GATED_EXTRA_PROOFS, GATED_WRONG_S1, GATED_HONEST_VECTORS,
//   MEASURE_CONTROLS (default 1), GATED_EXTRA_INPUTS (default 1), GATED_CUTS (the rekeyed run passes the
//   honest plan's final window explicitly, ...,313,348: the generator's planner test-runs a greedy final
//   window with the planning proof, which a wrong-key terminal can never accept), GATED_VARIANT_MAP (plan
//   only: a recorded per-input rescheduled/raw choice; see prepare-gated-driver.mjs)
import { execFileSync, spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, readFileSync, renameSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { loadPinnedLocalVariantMap, loadPinnedVariantMap } from './variant-map.mjs';

const [scratchArg, name, vectors, variants] = process.argv.slice(2);
if (!scratchArg || !name || !vectors || !['pool-key', 'pool-key-local', 'plan'].includes(variants)) {
  throw new Error('usage: run-graph.mjs SCRATCH NAME VECTORS_JSON pool-key|pool-key-local|plan (a pool-key replay uses its pinned variant map; plan measures)');
}
/** Each mode's pad rule (ENG-763): Chipnet's BCHN accounting with its margin, or the archived rule for the local replay. */
const PAD_RULES = { 'pool-key': { rule: 'bchn', margin: '10000' }, 'pool-key-local': { rule: 'libauth', margin: '0' }, plan: { rule: 'bchn', margin: '10000' } };
let pinnedMap;
if (variants === 'pool-key' || variants === 'pool-key-local') {
  if (process.env.GATED_VARIANT_MAP !== undefined) throw new Error(`${variants}: GATED_VARIANT_MAP is set; a pool-key replay uses only the pinned map`);
  if (process.env.GATED_PAD_RULE !== undefined || process.env.GATED_PAD_MARGIN !== undefined) throw new Error(`${variants}: GATED_PAD_RULE or GATED_PAD_MARGIN is set; a pool-key replay uses its mode's pad rule`);
  pinnedMap = variants === 'pool-key-local' ? loadPinnedLocalVariantMap() : loadPinnedVariantMap();
  const cuts = process.env.GATED_CUTS ?? '40,82,117,158,201,238,277,313';
  if (cuts !== pinnedMap.graph.cuts) throw new Error(`${variants}: GATED_CUTS ${cuts} is not the graph record's ${pinnedMap.graph.cuts}`);
}
const scratch = resolve(scratchArg);
const here = new URL('.', import.meta.url).pathname;
const repo = new URL('../../../', import.meta.url).pathname;
const head = execFileSync('git', ['-C', repo, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
const dirty = execFileSync('git', ['-C', repo, 'status', '--porcelain'], { encoding: 'utf8' }).trim().length > 0;
mkdirSync(`${scratch}/input/src/checkpoints`, { recursive: true });
copyFileSync(resolve(vectors), `${scratch}/input/src/checkpoints/pairing-vectors.json`);
mkdirSync(`${scratch}/runs`, { recursive: true });
const prefix = `${scratch}/runs/${name}`;
const extra = process.env.GATED_EXTRA_INPUTS ?? '1';
const env = { ...process.env,
  VERIFIER_DIR: `${scratch}/input`, FUSE_G2_ENDPOINT: '1', MILLER_AFFINE_G2: '1', MILLER_UNIT_LINES: '1',
  MILLER_TORUS: '1', MILLER_PROJECTIVE_VKX: '1', MILLER_NORMALIZED_PROOF_POINTS: '1', MILLER_RAW_B_INFINITY: '0',
  STAGE_BOUND_LAYOUT: '1', COVENANT_RESIDUE_LAYOUT: '1', COVENANT_TOKEN_CHAIN: '0', MILLER_LINKED_LAYOUT: '1',
  MILLER_LINKED_CUTS: process.env.GATED_CUTS ?? '40,82,117,158,201,238,277,313', OP_COST_TARGET: '7950000', BYTE_BUDGET: '9700',
  RESCHEDULE: 'on', INTRATX_BARE: '0', MEASURE_PREFIX: prefix, MEASURE_CONTROLS: process.env.MEASURE_CONTROLS ?? '1',
  ...(pinnedMap === undefined ? {} : { GATED_VARIANT_MAP: pinnedMap.path }),
  GATED_PAD_RULE: process.env.GATED_PAD_RULE ?? PAD_RULES[variants].rule, GATED_PAD_MARGIN: process.env.GATED_PAD_MARGIN ?? PAD_RULES[variants].margin,
};
writeFileSync(`${prefix}.env.json`, JSON.stringify(Object.fromEntries(Object.entries(env).filter(([k]) =>
  /^(VERIFIER_|FUSE_|MILLER_|STAGE_|COVENANT_|OP_COST_|BYTE_|RESCHEDULE|INTRATX_|MEASURE_|GATED_)/.test(k))), null, 2) + '\n');
const steps = [
  ['prepare', [`${here}prepare-gated-driver.mjs`, scratch, extra]],
  ['generate', [`${scratch}/generator/chunked/pairing/gen_miller_residue.mjs`]],
  ['assemble', [`${scratch}/generator/chunked/intratx/measure_gated.mjs`]],
];
for (const [label, args] of steps) {
  const started = new Date().toISOString();
  const r = spawnSync(process.execPath, args, { env, encoding: 'utf8', maxBuffer: 1 << 28 });
  writeFileSync(`${prefix}-${label}.stdout`, r.stdout ?? '');
  writeFileSync(`${prefix}-${label}.stderr`, r.stderr ?? '');
  const rec = { head, worktreeDirty: dirty, started, finished: new Date().toISOString(), cwd: process.cwd(),
    command: process.execPath, args, code: r.status, signal: r.signal,
    variants: { mode: variants, ...(pinnedMap === undefined ? {} : { pinnedMap: pinnedMap.path, sha256: pinnedMap.sha256 }) } };
  writeFileSync(`${prefix}-${label}.exit.json`, JSON.stringify(rec, null, 2) + '\n');
  console.log(JSON.stringify({ step: label, code: r.status, signal: r.signal }));
  if (r.status !== 0) { process.stderr.write((r.stderr ?? '').slice(-4000)); process.exit(r.status ?? 1); }
}
// Keep the exact generated sources of this graph before another case regenerates them.
mkdirSync(`${prefix}.generated`, { recursive: true });
const manifest = `${scratch}/generator/chunked/pairing/generated/manifest_millerres.json`;
copyFileSync(manifest, `${prefix}.generated/manifest_millerres.json`);
for (const chunk of JSON.parse(readFileSync(manifest)).chunks) {
  const file = `millerres_${String(chunk.idx).padStart(2, '0')}.cash`;
  copyFileSync(`${scratch}/generator/chunked/pairing/generated/${file}`, `${prefix}.generated/${file}`);
}
if (!existsSync(`${prefix}.gated.json`)) throw new Error('driver wrote no gated output');
if (pinnedMap !== undefined) {
  const gated = JSON.parse(readFileSync(`${prefix}.gated.json`, 'utf8'));
  const lockings = (gated.steps ?? gated.rekeyed.steps).map(s => s.locking);
  const recordName = variants === 'pool-key-local' ? 'local-zero-value-v1-graph.json' : 'chipnet-zero-value-rev3-graph-v1.json';
  const record = JSON.parse(readFileSync(new URL(`../pool-key/${recordName}`, import.meta.url), 'utf8'));
  const differ = lockings.map((l, i) => (l === record.graph.lockings[i] ? null : i)).filter(i => i !== null);
  if (lockings.length !== record.graph.lockings.length || differ.length > 0) {
    renameSync(`${prefix}.gated.json`, `${prefix}.gated.refused.json`);
    throw new Error(`${variants}: the regenerated lockings are not the graph record's (inputs ${differ.join(',')}): wrong key or vectors`);
  }
  console.log(JSON.stringify({ poolKey: 'lockings equal the graph record', root: lockings[0], variantMapSha256: pinnedMap.sha256 }));
}
