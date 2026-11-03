// Public identity comparisons only: no native setup, prover or chain access.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { deriveAPNTPoolProfileIdV1 } from '../packages/protocol-runtime/dist/apnt_pool_statement_v1.js';
import {
  APNT_POOL_V1_VERDICT_FACTORY_PIN as PIN,
  buildAPNTPoolVerdictFactoryV1,
} from '../packages/protocol-runtime/dist/apnt_pool_verdict_factory_v1.js';
import { getPinnedPoolAggregateBuildSelection } from '../tools/apnt-pool-aggregate-local-sp1/canonical-build/identity-policy.mjs';

const root = new URL('../', import.meta.url);
export const readManifest = () => JSON.parse(readFileSync(new URL('identity-manifest.json', root)));
const read = path => readFileSync(new URL(path, root));
const json = path => JSON.parse(read(path));
const hex = bytes => Buffer.from(bytes).toString('hex');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const requireMatch = (ok, code) => { if (!ok) throw Object.assign(new Error(code), { code }); };
const equal = (a, b, code) => requireMatch(a === b, code);

export function checkReleaseIdentities(manifest = readManifest(), selection = {}) {
  const results = [];
  const check = (id, body) => {
    try { body(); results.push({ id, status: 'PASS' }); }
    catch { results.push({ id, status: 'FAIL' }); }
  };
  const registry = () => json('packages/protocol-runtime/test-vectors/apnt-pool-v1-proof-system-registry-rev3-vectors.json');
  const go = () => read('tools/apnt-pool-action-circuit/registry.go').toString('utf8');
  const goString = name => {
    const match = new RegExp(`\\b${name}\\s*=\\s*"([0-9a-f]+)"`).exec(go());
    requireMatch(match, 'GO_CONSTANT'); return match[1];
  };
  const aggregate = () => getPinnedPoolAggregateBuildSelection('chipnet');
  check('network', () => {
    equal(manifest.schemaVersion, 'shielded-pool-release-identities/1', 'SCHEMA');
    equal(manifest.network, 'chipnet', 'NETWORK');
    equal(selection.network ?? 'chipnet', 'chipnet', 'NETWORK');
    equal(manifest.label, 'SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY', 'LABEL');
  });
  check('circuit ID (published R1CS metadata)', () => {
    equal(manifest.circuit.sha256, registry().chipnetZeroValueVp.provenance.r1csSha256, 'CIRCUIT');
    equal(manifest.circuit.sha256, goString('Revision3R1CSSha256'), 'CIRCUIT');
    const size = /\bRevision3R1CSBytes\s*=\s*([0-9_]+)/u.exec(go());
    requireMatch(size, 'CIRCUIT_SIZE');
    equal(manifest.circuit.sizeBytes, Number(size[1].replaceAll('_', '')), 'CIRCUIT_SIZE');
  });
  check('action verifying key (published bytes)', () => {
    const vp = registry().chipnetZeroValueVp;
    requireMatch(/^(?:[0-9a-f]{2})+$/u.test(vp.vp), 'VK_ENCODING');
    const bytes = Buffer.from(vp.vp, 'hex');
    equal(bytes.length, manifest.actionVerifyingKey.sizeBytes, 'VK_SIZE');
    equal(bytes.length, vp.vpBytes, 'VK_SIZE');
    equal(sha(bytes), manifest.actionVerifyingKey.sha256, 'VK_DIGEST');
    equal(sha(bytes), vp.vpSha256, 'VK_DIGEST');
    equal(sha(bytes), goString('ChipnetZeroValueRevision3VPSha256'), 'VK_DIGEST');
    const source = /\bChipnetZeroValueRevision3VPHex\s*=\s*((?:"[0-9a-f]+"\s*\+\s*)*"[0-9a-f]+")/u.exec(go());
    requireMatch(source, 'VK_SOURCE');
    equal([...source[1].matchAll(/"([0-9a-f]+)"/gu)].map(m => m[1]).join(''), vp.vp, 'VK_BYTES');
  });
  check('action profile', () => {
    const r = registry(), vp = r.chipnetZeroValueVp, p = manifest.actionProfile;
    equal(p.systemId, 1, 'SYSTEM'); equal(p.registryRevision, 3, 'REVISION');
    equal(p.systemId, r.registryEntry.systemId, 'SYSTEM');
    equal(p.registryRevision, r.registryEntry.revision, 'REVISION');
    const derived = hex(deriveAPNTPoolProfileIdV1({ systemId: p.systemId, verifierParameters: Buffer.from(vp.vp, 'hex') }));
    equal(p.id, derived, 'PROFILE'); equal(vp.profileId, derived, 'PROFILE');
    equal(selection.profile ?? derived, derived, 'PROFILE');
    equal(goString('ChipnetZeroValueRevision3ProfileID'), derived, 'PROFILE');
    equal(aggregate().actionVpProfileId, derived, 'PROFILE');
    const rust = read('tools/apnt-pool-aggregate-sp1/core/src/profile.rs').toString('utf8');
    const constant = /pub const CHIPNET_ZERO_VALUE_REVISION_3_PROFILE_ID: \[u8; 32\] =\s*hex32\("([0-9a-f]{64})"\)/u.exec(rust);
    equal(constant?.[1], derived, 'PROFILE');
  });
  check('covenant bytecode (reference verdict factory)', () => {
    requireMatch(manifest.covenants.length === 1, 'COVENANT_COUNT');
    const c = manifest.covenants[0];
    equal(c.network, 'chipnet', 'COVENANT_NETWORK');
    equal(c.id, 'apnt-pool-verdict-factory-v1', 'COVENANT');
    const sources = [
      [c.covenantSource, 'packages/protocol-runtime/src/cashassembly/apnt_pool_verdict_factory_v1.casm'],
      [c.source, 'packages/protocol-runtime/src/apnt_pool_verdict_factory_v1.ts'],
    ];
    for (const [record, path] of sources) {
      equal(record.publicPath, path, 'COVENANT_SOURCE'); equal(sha(read(path)), record.sha256, 'COVENANT_SOURCE');
    }
    equal(c.pin.sourceSha256, PIN.sourceSha256, 'COVENANT_SOURCE');
    equal(c.covenantSource.sha256, PIN.sourceSha256, 'COVENANT_SOURCE');
    const built = buildAPNTPoolVerdictFactoryV1({ network: 'chipnet',
      verdictCategoryWire32: Buffer.from(PIN.referenceVerdictCategoryWire32, 'hex'),
      settlementLockingBytecode: Buffer.from(PIN.referenceSettlementLockingBytecode, 'hex') });
    equal(hex(built.redeemBytecode), PIN.referenceRedeemBytecode, 'COVENANT_BYTES');
    equal(sha(built.redeemBytecode), c.pin.referenceRedeemSha256, 'COVENANT_DIGEST');
    equal(PIN.graphRootLockingBytecode, aggregate().graphRoot, 'COVENANT_GRAPH');
    for (const record of c.records) {
      requireMatch([
        'tools/apnt-pool-aggregate-local-sp1/canonical-build/local-zero-value-canonical-build-v1.json',
        'tools/apnt-pool-aggregate-sp1/canonical-build/chipnet-zero-value-rev3-canonical-build-v1.json',
        'tools/pool-onetx-verifier-prototype/pool-key/chipnet-zero-value-rev3-graph-v1.json',
        'tools/pool-onetx-verifier-prototype/pool-key/local-zero-value-v1-graph.json',
      ].includes(record.publicPath), 'RECORD_PATH');
      equal(sha(read(record.publicPath)), record.sha256, 'RECORD_DIGEST');
    }
    equal(c.records.length, 4, 'RECORD_COUNT');
  });
  check('aggregate digest (published canonical records)', () => {
    const a = manifest.aggregate, p = aggregate();
    equal(a.guestElfSha256, p.guestElfSha256, 'ELF_DIGEST');
    equal(a.guestElfBytes, p.guestElfBytes, 'ELF_SIZE');
    const sums = read('tools/apnt-pool-aggregate-sp1/canonical-build/chipnet-zero-value-rev3-canonical-elf.SHA256SUMS').toString('utf8');
    requireMatch(sums.split('\n').includes(`${a.guestElfSha256}  apnt-pool-aggregate-program-chipnet-zero-value-rev3`), 'ELF_SUMS');
  });
  check('aggregate program VKey (published canonical records)', () => {
    equal(manifest.aggregate.programVkeyHash, aggregate().programVkeyHash, 'PROGRAM_VKEY');
    equal(manifest.aggregate.programVkeyHash, PIN.programVkeyHash, 'PROGRAM_VKEY');
  });
  return results;
}

export function main(args) {
  const selection = {};
  for (let i = 0; i < args.length; i += 2) {
    const key = { '--network': 'network', '--profile': 'profile' }[args[i]];
    if (!key || !args[i + 1] || Object.hasOwn(selection, key)) {
      console.error('usage: check-identities.mjs [--network chipnet] [--profile HEX]'); return 2;
    }
    selection[key] = args[i + 1];
  }
  try {
    const m = readManifest(), results = checkReleaseIdentities(m, selection);
    for (const r of results) console.log(`${r.status} ${r.id}`);
    // Each control changes only one selection field and must fail that field.
    for (const [id, selected, failedId] of [
      ['wrong-profile control', { profile: '00'.repeat(32) }, 'action profile'],
      ['wrong-network control', { network: 'mainnet' }, 'network'],
    ]) {
      const refused = checkReleaseIdentities(m, selected).some(r => r.id === failedId && r.status === 'FAIL');
      results.push({ status: refused ? 'PASS' : 'FAIL' });
      console.log(`${refused ? 'PASS' : 'FAIL'} ${id} (expected refusal)`);
    }
    console.log('UNRUN R1CS compilation/byte hashing; aggregate ELF rebuild/byte hashing; program VKey derivation; installed runtime and setup qualification.');
    return results.every(r => r.status === 'PASS') ? 0 : 1;
  } catch {
    console.error('FAIL release identity input (build first; no input contents printed)'); return 1;
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  process.exitCode = main(process.argv.slice(2));
}
