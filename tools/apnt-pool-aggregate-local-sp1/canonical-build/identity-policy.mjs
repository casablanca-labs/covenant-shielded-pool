// Network-specific public proof-artifact selection for zero-value builds.
// The JSON records are pinned by their exact bytes, so substituting a record
// cannot silently replace the authority for the comparison.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const repo = new URL('../../../', import.meta.url);
const anchors = Object.freeze({
  chipnet: Object.freeze({
    pinPath: 'tools/apnt-pool-aggregate-sp1/canonical-build/chipnet-zero-value-rev3-canonical-build-v1.json',
    pinSha256: '7efcce247693d89e71c711927f3c0c38c98a29dc983944e498adb15f7c1361ee',
    graphPath: 'tools/pool-onetx-verifier-prototype/pool-key/chipnet-zero-value-rev3-graph-v1.json',
    graphSha256: '30c0fa0c96cc66bf1fc6d92859867aa15975b7d66b4cd9bdf3abb4d5df8f28c9',
    mapSha256: 'dbe32d97876d444afa7980d3e4b70d885d978d618faead043291a92506f92fd6',
  }),
  local: Object.freeze({
    pinPath: 'tools/apnt-pool-aggregate-local-sp1/canonical-build/local-zero-value-canonical-build-v1.json',
    pinSha256: '34a2e0c0e02cc50b68a337d7774d0927be318cdcab61f916c04ebe04d22a27e8',
    graphPath: 'tools/pool-onetx-verifier-prototype/pool-key/local-zero-value-v1-graph.json',
    graphSha256: 'dbde208d3edad701b99815fadfe553304037221a578c5ced13190ef5973a2fcd',
    mapSha256: '83472cd0c0f2f98e29928b63db16c68561e7427d3fb9298cdbc6a9f7342241ba',
  }),
});

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const pinnedJson = (path, expected, code) => {
  const bytes = readFileSync(new URL(path, repo));
  if (sha(bytes) !== expected) throw new Error(code);
  return JSON.parse(bytes);
};

export function getPinnedPoolAggregateBuildSelection(network) {
  const anchor = anchors[network];
  if (!anchor) throw new Error('POOL_BUILD_NETWORK');
  const pin = pinnedJson(anchor.pinPath, anchor.pinSha256, 'POOL_BUILD_PIN_RECORD');
  const graph = pinnedJson(anchor.graphPath, anchor.graphSha256, 'POOL_BUILD_GRAPH_RECORD');
  if (graph.program.record !== anchor.pinPath || graph.program.package !== pin.record.package ||
      graph.program.guestElfSha256 !== pin.record.guestElfSha256 ||
      graph.program.guestElfBytes !== pin.record.guestElfBytes ||
      graph.program.programVkeyHash !== pin.record.programVkeyHash ||
      graph.graph.root !== graph.graph.lockings[0] ||
      pin.record.compiledAllowlist.length !== 1 ||
      pin.record.compiledAllowlist[0] !== pin.record.allowlistedVp.profileId) {
    throw new Error('POOL_BUILD_RECORD_BINDING');
  }
  return Object.freeze({
    network,
    pinRecord: anchor.pinPath,
    pinRecordSha256: anchor.pinSha256,
    graphRecord: anchor.graphPath,
    graphRecordSha256: anchor.graphSha256,
    variantMapSha256: anchor.mapSha256,
    guestElfSha256: pin.record.guestElfSha256,
    guestElfBytes: pin.record.guestElfBytes,
    buildLabel: pin.record.buildLabel,
    programVkeyHash: pin.record.programVkeyHash,
    actionVpProfileId: pin.record.compiledAllowlist[0],
    graphRoot: graph.graph.root,
    verifyingProgramLockingsSha256: graph.graph.lockingsSha256,
  });
}

/** Checks each selected public artifact field before setup, graph replay or factory use. */
export function assertPinnedPoolAggregateBuildSelection(network, candidate) {
  const expected = getPinnedPoolAggregateBuildSelection(network);
  for (const [field, value] of Object.entries(expected)) {
    if (candidate?.[field] !== value) throw new Error(`POOL_BUILD_SELECTION_${field}`);
  }
  return expected;
}

// Public-record identity verification only. Native guest/VKey reproduction,
// proof verification and ceremony/CRS qualification remain separate obligations.
export function verifyPublishedPoolAggregateIdentities() {
  for (const network of ['chipnet', 'local']) {
    getPinnedPoolAggregateBuildSelection(network);
    const anchor = anchors[network];
    pinnedJson(anchor.graphPath.replace(/\.json$/, '.variant-map.json'), anchor.mapSha256, 'POOL_BUILD_MAP_RECORD');
  }
  return { networks: 2, pinnedRecords: 6 };
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  if (process.argv.length !== 3 || process.argv[2] !== '--verify-published-identities') {
    process.stderr.write('usage: node identity-policy.mjs --verify-published-identities\n');
    process.exitCode = 2;
  } else {
    try {
      const result = verifyPublishedPoolAggregateIdentities();
      process.stdout.write(`public build identities PASS; networks ${result.networks}; pinned records ${result.pinnedRecords}\n`);
    } catch (error) {
      // Emit a rule ID, never input contents or arbitrary filesystem errors.
      process.stderr.write(`${/^POOL_BUILD_[A-Z0-9_]+$/.test(error?.message) ? error.message : 'POOL_BUILD_INPUT'}\n`);
      process.exitCode = 1;
    }
  }
}
