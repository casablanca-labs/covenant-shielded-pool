// Research prototype — not reviewed (R-384).
//
// ENG-526 (ARCH-273): the committed pool-key graph's per-input variant map, pinned beside the graph
// record, and the gated driver's fail-closed per-chunk variant choice.
//
// With RESCHEDULE on, the generator's driver compiles each graph input two ways (rescheduled and raw)
// and, unless told, picks one per input on its first assembly by comparing tuned op cost on the
// planning proof. So a graph's lockings are a function of the proof it was planned with (ENG-523).
// The committed pool-key graph was planned with a proof its terminal rejects by design; its choices,
// recovered by ENG-524, are pinned in pool-key/chipnet-zero-value-rev3-graph-v1.variant-map.json, and
// every pool-key replay regenerates the graph from that map, never from the replay proof.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const VARIANT_MAP_SCHEMA = 'apnt-pool-onetx-graph-variant-map-v1';
export const VARIANT_MAP_URL = new URL('../pool-key/chipnet-zero-value-rev3-graph-v1.variant-map.json', import.meta.url);
/** SHA-256 of the pinned map file's bytes. A change to the map is a change to the graph record. */
export const VARIANT_MAP_SHA256 = 'dbe32d97876d444afa7980d3e4b70d885d978d618faead043291a92506f92fd6';
const GRAPH_RECORD_URL = new URL('../pool-key/chipnet-zero-value-rev3-graph-v1.json', import.meta.url);
export const LOCAL_VARIANT_MAP_URL = new URL('../pool-key/local-zero-value-v1-graph.variant-map.json', import.meta.url);
export const LOCAL_VARIANT_MAP_SHA256 = '83472cd0c0f2f98e29928b63db16c68561e7427d3fb9298cdbc6a9f7342241ba';
const LOCAL_GRAPH_RECORD_URL = new URL('../pool-key/local-zero-value-v1-graph.json', import.meta.url);

const sha = b => createHash('sha256').update(b).digest('hex');

/**
 * Checks a variant map's bytes against a digest and a graph record: the digest, the schema, one
 * "resched" or "raw" per graph input, and the graph it names. Throws with a named cause.
 */
export function checkVariantMap(bytes, { sha256, graph }) {
  const digest = sha(bytes);
  if (digest !== sha256) throw new Error(`VARIANT_MAP_DIGEST: the variant map's SHA-256 is ${digest}, the pin is ${sha256}`);
  const map = JSON.parse(Buffer.from(bytes).toString('utf8'));
  if (map.schema !== VARIANT_MAP_SCHEMA) throw new Error(`VARIANT_MAP_SCHEMA: ${JSON.stringify(map.schema)}`);
  if (!Array.isArray(map.variants) || map.variants.length !== graph.graph.inputs) {
    throw new Error(`VARIANT_MAP_INPUT_COUNT: the map names ${Array.isArray(map.variants) ? map.variants.length : 'no'} graph inputs; the graph has ${graph.graph.inputs}`);
  }
  for (const [i, v] of map.variants.entries()) {
    if (v !== 'resched' && v !== 'raw') throw new Error(`VARIANT_MAP_VARIANT: input ${i} is ${JSON.stringify(v)}`);
  }
  if (map.graph?.root !== graph.graph.root || map.graph?.lockingsSha256 !== graph.graph.lockingsSha256 || map.graph?.cuts !== graph.generation.cuts) {
    throw new Error('VARIANT_MAP_GRAPH: the map names another graph (root, lockings digest or cuts)');
  }
  return { ...map, sha256: digest };
}

/** The pinned map of the committed pool-key graph; refuses an absent, changed or mismatched file. */
export function loadPinnedVariantMap(url = VARIANT_MAP_URL, sha256 = VARIANT_MAP_SHA256) {
  const path = fileURLToPath(url);
  if (!existsSync(path)) throw new Error(`VARIANT_MAP_ABSENT: ${path}`);
  const graph = JSON.parse(readFileSync(GRAPH_RECORD_URL, 'utf8'));
  return { ...checkVariantMap(readFileSync(path), { sha256, graph }), path };
}

/** The independently pinned local 0x99 graph map. Never falls back to Chipnet. */
export function loadPinnedLocalVariantMap(url = LOCAL_VARIANT_MAP_URL, sha256 = LOCAL_VARIANT_MAP_SHA256) {
  const path = fileURLToPath(url);
  if (!existsSync(path)) throw new Error(`LOCAL_VARIANT_MAP_ABSENT: ${path}`);
  const graph = JSON.parse(readFileSync(LOCAL_GRAPH_RECORD_URL, 'utf8'));
  const pinPath = 'tools/apnt-pool-aggregate-local-sp1/canonical-build/local-zero-value-canonical-build-v1.json';
  const pin = JSON.parse(readFileSync(new URL(`../../../${pinPath}`, import.meta.url), 'utf8'));
  if (graph.program.record !== pinPath || !String(graph.label).startsWith('LOCAL 0x99') ||
      pin.label !== 'LOCAL 0x99 - SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY' ||
      graph.program.programVkeyHash !== pin.record.programVkeyHash ||
      graph.program.guestElfSha256 !== pin.record.guestElfSha256 ||
      graph.program.guestElfBytes !== pin.record.guestElfBytes ||
      graph.program.package !== pin.record.package) {
    throw new Error('LOCAL_VARIANT_MAP_PROGRAM: graph names another build');
  }
  const map = checkVariantMap(readFileSync(path), { sha256, graph });
  if (map.graph.record !== 'tools/pool-onetx-verifier-prototype/pool-key/local-zero-value-v1-graph.json' ||
      map.graph.inputs !== graph.graph.inputs) throw new Error('LOCAL_VARIANT_MAP_GRAPH: wrong graph record');
  return { ...map, path };
}

/**
 * The gated driver's per-chunk variant choice when planning (prepare-gated-driver.mjs embeds this
 * function's source in place of the generator's `tB < tR ? 'raw' : 'resched'`). `resched` and `raw` are
 * each variant's [consensus, standard] outcome on the planning proof at the full unlocking budget; tR and
 * tB are their tuned unlocking lengths (tB is Infinity when raw did not accept). The generator scored a
 * rejecting variant Infinity and silently kept the other, and it compared resched's op cost even when
 * resched rejected, so a proof the graph rejects decided the graph (the rekeyed pool-key terminal).
 * Here a variant that rejects the planning proof can never decide: the choice is refused with a named
 * cause, and the caller must name that input's variant in GATED_VARIANT_MAP. Resched must accept in
 * both VMs. Raw may lose without a verdict only by running out of budget: a density-limit failure
 * (operation cost or hashing) means raw does not fit within the full unlocking budget, which the
 * generator also scored Infinity, and the accepting resched run decides. When every outcome accepts,
 * the choice is the generator's, unchanged.
 */
export function gatedChooseVariant(index, resched, raw, tR, tB) {
  const overBudget = outcome => /would exceed the (operation cost|hashing) density limit/u.test(outcome.error ?? '');
  const rejecting = [];
  for (const [variant, outcomes] of [['resched', resched], ['raw', raw]]) {
    for (const [vm, outcome] of [['consensus', outcomes[0]], ['standard', outcomes[1]]]) {
      if (outcome.accepted || (variant === 'raw' && overBudget(outcome))) continue;
      rejecting.push(`${variant} ${vm}: ${outcome.error ?? 'no single true on the stack'}`);
    }
  }
  if (rejecting.length > 0) {
    throw new Error(`VARIANT_REJECTS_PLANNING_PROOF: graph input ${index}: ${rejecting.join('; ')} ` +
      '(a variant that rejects the planning proof cannot decide the choice; name this input\'s variant in GATED_VARIANT_MAP)');
  }
  return tB < tR ? 'raw' : 'resched';
}
