// ENG-510 (task 5.4 slice 2a): record the one-transaction verifier graph regenerated for the
// pinned pool program key, from a scratch tree run by run-graph.mjs in rekeyed mode.
//
// Research prototype graph (R-384 construction, not externally reviewed). The pool program is the
// labelled Chipnet build of the pool aggregate guest (SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST
// ONLY); its key comes from tools/apnt-pool-aggregate-sp1/canonical-build/. Only the terminal's
// fixed pairing factor depends on the program key (ENG-436), so the graph is generated with a
// retained SP1 6.3.1 wrapper proof of ANOTHER program as the planning proof, keyed to the pool
// program (IC0' = IC0 + s0·IC1): every input but the terminal accepts that proof, and the terminal
// refuses it, in both VMs. No pool aggregate proof exists yet (task 5.4 slice 2b).
//
// The generated CashScript stays outside git (see ../ATTRIBUTION.md); this record carries only the
// P2SH32 lockings, digests and the terminal's six fixed-factor limbs.
//
// usage: node record-pool-key-graph.mjs POOL_RUN_PREFIX HONEST_RUN_PREFIX POOL_VECTORS_PREFIX
//          FIXED_CONSTANT_JSON SETUP_SOURCES_JSON OUT_JSON
//   POOL_RUN_PREFIX   <scratch>/runs/<name> of the rekeyed run (…gated.json, ….generated/, …-*.exit.json)
//   HONEST_RUN_PREFIX the same for the honest run of the planning proof's own key (the one-line-diff control)
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';

const [poolPrefix, honestPrefix, vectorsPrefix, fixedConstantPath, sourcesPath, outPath] = process.argv.slice(2);
assert(outPath, 'usage: record-pool-key-graph.mjs POOL_RUN_PREFIX HONEST_RUN_PREFIX POOL_VECTORS_PREFIX FIXED_CONSTANT_JSON SETUP_SOURCES_JSON OUT_JSON');
const sha = b => createHash('sha256').update(b).digest('hex');
const repo = new URL('../../../', import.meta.url).pathname;
const pin = JSON.parse(readFileSync(`${repo}tools/apnt-pool-aggregate-sp1/canonical-build/chipnet-zero-value-rev3-canonical-build-v1.json`, 'utf8'));
const pool = JSON.parse(readFileSync(`${poolPrefix}.gated.json`, 'utf8'));
const honest = JSON.parse(readFileSync(`${honestPrefix}.gated.json`, 'utf8'));
const vectorsRecord = JSON.parse(readFileSync(`${vectorsPrefix}.json`, 'utf8'));
const vectors = JSON.parse(readFileSync(`${vectorsPrefix}.vectors.json`, 'utf8'));
const fixed = JSON.parse(readFileSync(fixedConstantPath, 'utf8'));
const sources = JSON.parse(readFileSync(sourcesPath, 'utf8'));
const env = JSON.parse(readFileSync(`${poolPrefix}.env.json`, 'utf8'));
const exits = ['prepare', 'generate', 'assemble'].map(s => JSON.parse(readFileSync(`${poolPrefix}-${s}.exit.json`, 'utf8')));

assert.equal(pool.mode, 'rekeyed');
assert.equal(pool.extraInputs, 1, 'the graph must expect the factory as its twelfth input');
assert.equal(vectorsRecord.programVkeyOverride, true);
assert.equal(vectorsRecord.programVkeyHash, pin.record.programVkeyHash, 'the graph is keyed to the pinned Chipnet program key');
assert.notEqual(vectorsRecord.retainedProgramVkeyHash, pin.record.programVkeyHash);
assert.equal(vectorsRecord.offChainPairingAccepted, false);
const steps = pool.rekeyed.steps;
assert.equal(steps.length, 11);
const acceptance = pool.rekeyed.acceptance;
assert.deepEqual(acceptance.map(a => a.consensus && a.standard), [...Array(10).fill(true), false], 'only the terminal refuses');
assert.deepEqual(acceptance.map(a => a.consensus || a.standard), [...Array(10).fill(true), false]);
for (const e of exits) assert.equal(e.code, 0);
assert.equal(fixed.relationToVkPairings, 'equal');
assert.equal(fixed.relationToOtherKey, 'none');

// The one-line diff: only the terminal's source and the manifest's copy of its constants differ.
const gen = p => `${p}.generated`;
const files = readdirSync(gen(poolPrefix)).sort();
assert.deepEqual(files, readdirSync(gen(honestPrefix)).sort());
const differing = files.filter(f => sha(readFileSync(`${gen(poolPrefix)}/${f}`)) !== sha(readFileSync(`${gen(honestPrefix)}/${f}`)));
assert.deepEqual(differing, ['manifest_millerres.json', 'millerres_08.cash']);
const lines = f => readFileSync(f, 'utf8').split('\n');
const [pl, hl] = [lines(`${gen(poolPrefix)}/millerres_08.cash`), lines(`${gen(honestPrefix)}/millerres_08.cash`)];
assert.equal(pl.length, hl.length);
const changedLines = pl.map((l, i) => l === hl[i] ? null : i + 1).filter(Boolean);
for (const limb of fixed.limbs) assert(pl.some(l => l.includes(limb)), 'the recorded limbs are in the pool terminal');

const record = {
  schema: 'apnt-pool-onetx-verifier-graph-record-v1',
  label: 'RESEARCH PROTOTYPE GRAPH (R-384 construction, not externally reviewed) for the Chipnet pool program: SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY; never for value',
  program: {
    record: 'tools/apnt-pool-aggregate-sp1/canonical-build/chipnet-zero-value-rev3-canonical-build-v1.json',
    package: pin.record.package, programVkeyHash: pin.record.programVkeyHash,
    guestElfSha256: pin.record.guestElfSha256, guestElfBytes: pin.record.guestElfBytes,
  },
  wrapper: {
    sp1Version: '6.3.1', wrapperVkSha256: vectorsRecord.wrapperVkSha256,
    recursionVkeyRootHex: vectorsRecord.recursionVkeyRootHex, s3Le32: vectorsRecord.s3Le32,
    s0: BigInt(`0x${pin.record.programVkeyHash}`).toString(),
  },
  generation: {
    generator: sources.sources.generator, compiler: sources.sources.compiler, tagCommit: sources.tagCommit,
    dependencies: sources.dependencies, typescript: sources.typescript,
    driver: 'scripts/prepare-gated-driver.mjs (graph expects 12 inputs: the verdict factory is input 11)',
    mode: 'rekeyed', cuts: env.MILLER_LINKED_CUTS, environment: env,
    worktreeHead: exits[0].head, worktreeDirty: exits[0].worktreeDirty,
    planningProof: { label: 'L1', file: vectorsRecord.proofFile, fileSha256: vectorsRecord.proofFileSha256,
      programVkeyHash: vectorsRecord.retainedProgramVkeyHash,
      note: 'a retained SP1 6.3.1 wrapper proof of the seal-era aggregate program: a different program, so the terminal must refuse it' },
  },
  graph: {
    inputs: 11, transactionInputs: 12, factoryInputIndex: 11,
    root: steps[0].locking,
    lockings: steps.map(s => s.locking),
    lockingsSha256: sha(Buffer.from(steps.map(s => s.locking).join(''), 'hex')),
    planningProofUnlockingBytes: steps.map(s => s.unlocking.length / 2),
    generatedSourcesSha256: Object.fromEntries(files.map(f => [f, sha(readFileSync(`${gen(poolPrefix)}/${f}`))])),
  },
  controls: {
    planningProofAcceptance: acceptance,
    onlyTerminalRefusesThePlanningProof: true,
    honestGraphOfThePlanningProofsKey: { root: honest.steps[0].locking,
      generatedSourcesSha256: Object.fromEntries(files.map(f => [f, sha(readFileSync(`${gen(honestPrefix)}/${f}`))])) },
    differingGeneratedFiles: differing,
    terminalChangedLines: changedLines,
    everyLockingDiffersFromTheHonestGraph: steps.every((s, i) => s.locking !== honest.steps[i].locking),
    fixedFactor: { limbs: fixed.limbs, relationToPoolKeyPairings: fixed.relationToVkPairings, relationToPlanningProofKey: fixed.relationToOtherKey,
      statement: 'FE(1 + u·w) of the terminal limbs equals e(alpha, beta)·e(IC0 + s0·IC1, gamma) for the pinned pool program key s0 (noble-curves pairing); it matches no other key tried' },
  },
  waitsForTheRealProof: [
    'a real pool aggregate proof accepted by every input, the terminal included (both VMs)',
    'the whole-transaction size with that proof, and the proof-specific density padding',
    's1 = mask(SHA-256(runBind32)) read by the pool-mode gate from that proof',
    's3 of that proof equal to the pinned SP1 6.3.1 recursion root',
    'the real-proof controls: tampered and malformed proofs, state corruption, consistent wrong public values, sibling substitution',
  ],
};
writeFileSync(outPath, JSON.stringify(record, null, 2) + '\n');
console.log(JSON.stringify({ root: record.graph.root, lockingsSha256: record.graph.lockingsSha256, differing, changedLines }, null, 1));
