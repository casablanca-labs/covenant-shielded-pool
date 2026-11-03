// ENG-510 (task 5.4 slice 2a): the deployment the pool-mode verdict factory mints for, and the
// factory itself, as plain ESM for the scripts. It is the settlement suite's deployment
// (packages/reference-aggregator/test/apnt_pool_settlement_v1_fixture.ts `deployment()`): the
// shipped task 3.4 settlement covenant built from the shared pool vectors' three categories, no
// meter, K = 3 root copies of 1,000 sats, a 20,000-sat fold bounty and 1,000-sat range records.
// pool-key-verdict.test.ts asserts the lock here equals the fixture's.
//
// Research prototype factory (R-384), pinned to the verifier graph regenerated for the pinned
// Chipnet pool program key (pool-key/chipnet-zero-value-rev3-graph-v1.json). SIMULATED
// SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY.
import { readFileSync } from 'node:fs';
import { buildFactory } from './factory.mjs';

const repo = new URL('../../../', import.meta.url);
const pr = await import(new URL('packages/protocol-runtime/dist/index.js', repo));
const vectors = JSON.parse(readFileSync(new URL('packages/protocol-runtime/test-vectors/apnt-pool-v1-vectors.json', repo), 'utf8'));
export const GRAPH_RECORD = JSON.parse(readFileSync(new URL('../pool-key/chipnet-zero-value-rev3-graph-v1.json', import.meta.url), 'utf8'));

const bin = h => Uint8Array.from(Buffer.from(h, 'hex'));
const c = vectors.reference.deploymentId.categoriesWire;
export const V_WIRE = bin(c.verdict);
export const V_DISPLAY = Uint8Array.from(V_WIRE).reverse();
export const DEPLOYMENT_ID = bin(vectors.reference.deploymentId.chipnetNoMeter);
export const SETTLEMENT_LOCK = pr.buildAPNTPoolSettlementCovenantsV1({
  network: 'chipnet', verdictCategoryWire32: V_WIRE, rangeCategoryWire32: bin(c.range), rootCategoryWire32: bin(c.root),
  rootCopyCount: 3, rootCopySats: 1000n, foldBountySats: 20000n, recordValueSats: 1000n,
}).settlement.lockingBytecode;
export const V_MINTING = Uint8Array.from([...V_WIRE, 0x02]);
export const S3_LE32 = bin(GRAPH_RECORD.wrapper.s3Le32);
export const GRAPH_ROOT = bin(GRAPH_RECORD.graph.root);
export const MAX_M = 8;
export const FACTORY_PARAMS = { mode: 'pool', shape: 'a', N: 11, vMinting33: V_MINTING, settlementLock: SETTLEMENT_LOCK, s3Le32: S3_LE32, variableMaxM: MAX_M };
/** The deployable pool-mode factory: variable M (1..8), pinned to the pool-key graph root. */
export const poolFactory = (over = {}) => buildFactory({ ...FACTORY_PARAMS, graphRoot: GRAPH_ROOT, ...over });
export const mintingToken = (category = V_DISPLAY) => ({ category, amount: 0n, nft: { capability: 'minting', commitment: new Uint8Array() } });
