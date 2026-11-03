import { createHash } from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { types } from "node:util";
import { APNT_POOL_V1_MAX_MONEY_SATS } from "./apnt_pool_contract_v1.js";
import { APNT_POOL_V1_RANGE_GENESIS_MAXIMUM_LOG2 } from "./apnt_pool_range_record_v1.js";
import { APNT_POOL_V1_INBOX_REFUND_DELAY_BLOCKS } from "./apnt_pool_inbox_covenant_v1.js";
import { APNT_POOL_V1_RANGE_GENESIS_MINIMUM_LOG2 } from "./apnt_pool_genesis_v1.js";
import { deriveAPNTPoolProfileIdV1 } from "./apnt_pool_statement_v1.js";
import { APNT_POOL_V1_LOCAL_VERDICT_FACTORY_PIN, APNT_POOL_V1_VERDICT_FACTORY_PIN } from "./apnt_pool_verdict_factory_v1.js";

/** Closed development vocabulary. The first thirteen values are S1a's vocabulary, verbatim. */
export const APNT_POOL_DEV_FAILURE_V1 = Object.freeze({
  SHAPE: "dev-zero-conf-shape", PURPOSE: "dev-zero-conf-purpose", NETWORK: "dev-zero-conf-network",
  DEPLOYMENT: "dev-zero-conf-deployment", EVIDENCE: "dev-zero-conf-evidence", RELAY: "dev-zero-conf-relay",
  EXACT_BYTES: "dev-zero-conf-exact-bytes", PARENT_MISSING: "dev-zero-conf-parent-missing",
  DEPENDENCY: "dev-zero-conf-dependency", CONFLICT: "dev-zero-conf-conflict", STALE: "dev-zero-conf-stale",
  READ: "dev-zero-conf-read", LIMIT: "dev-zero-conf-limit", INSTALLATION: "dev-zero-conf-installation",
  PROFILE: "dev-zero-conf-profile", CONTEXT: "dev-zero-conf-context", MATURITY: "dev-zero-conf-maturity",
  FINALITY: "dev-zero-conf-finality", BIP68: "dev-zero-conf-bip68", PREVOUT: "dev-zero-conf-prevout",
  TRANSACTION: "dev-zero-conf-transaction", VERIFIER_GRAPH: "dev-zero-conf-verifier-graph",
  FACTORY: "dev-zero-conf-factory", STATEMENT: "dev-zero-conf-statement", SETTLEMENT: "dev-zero-conf-settlement",
  PROJECTION: "dev-zero-conf-projection", FOLD: "dev-zero-conf-fold", WALLET_BINDING: "dev-zero-conf-wallet-binding",
  WALLET_REVISION: "dev-zero-conf-wallet-revision", OPENING: "dev-zero-conf-opening",
} as const);
export type DevFailureCodeV1 = typeof APNT_POOL_DEV_FAILURE_V1[keyof typeof APNT_POOL_DEV_FAILURE_V1];
export type DevResultV1<T> = Readonly<{ ok: true; value: T }> | Readonly<{ ok: false; code: DevFailureCodeV1 }>;
declare const installationBrand: unique symbol;
export type APNTPoolDevVerifierInstallationV1 = Readonly<{ [installationBrand]: true }>;
const F = APNT_POOL_DEV_FAILURE_V1;

/** Internal helpers, deliberately absent from the package root. No provider error is trusted. */
export class DevAdmissionRefusalV1 { constructor(readonly code: DevFailureCodeV1) {} }
export function devRequireV1(condition: unknown, code: DevFailureCodeV1): asserts condition {
  if (!condition) throw new DevAdmissionRefusalV1(code);
}
export function devFailureV1(error: unknown, fallback: DevFailureCodeV1): DevResultV1<never> {
  return Object.freeze({ ok: false, code: error instanceof DevAdmissionRefusalV1 ? error.code : fallback });
}
/** Own enumerable data fields only, captured once; a proxy is refused without running its traps. */
export function devRecordV1(value: unknown, names: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  devRequireV1(value !== null && typeof value === "object" && !types.isProxy(value) && !Array.isArray(value), F.SHAPE); // guard: record
  devRequireV1(Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null, F.SHAPE); // guard: prototype
  const keys = Reflect.ownKeys(value);
  devRequireV1(names.every(k => keys.includes(k)) && keys.every(k => typeof k === "string" && [...names, ...optional].includes(k)), F.SHAPE); // guard: keys
  const copy = Object.create(null) as Record<string, unknown>;
  for (const k of keys) {
    const d = Object.getOwnPropertyDescriptor(value, k);
    devRequireV1(d !== undefined && Object.hasOwn(d, "value") && d.enumerable, F.SHAPE); // guard: descriptor
    copy[k as string] = d.value;
  }
  return copy;
}
export const devHashV1 = (v: unknown): v is string => typeof v === "string" && /^[0-9a-f]{64}$/u.test(v);
export function devCheckpointV1(value: unknown): Readonly<{ height: number; blockHash: string }> {
  const p = devRecordV1(value, ["height", "blockHash"]);
  devRequireV1(typeof p.height === "number" && Number.isSafeInteger(p.height) && p.height >= 0 && p.height <= 0xffff_ffff && devHashV1(p.blockHash), F.SHAPE); // guard: checkpoint-shape
  return Object.freeze({ height: p.height, blockHash: p.blockHash });
}

const ROOT = new URL("../../../", import.meta.url);
const require = createRequire(import.meta.url);
const sha = (v: string | Uint8Array) => createHash("sha256").update(v).digest("hex");
const BUILD = Object.freeze({
  local: "tools/apnt-pool-aggregate-local-sp1/canonical-build/local-zero-value-canonical-build-v1.json",
  chipnet: "tools/apnt-pool-aggregate-sp1/canonical-build/chipnet-zero-value-rev3-canonical-build-v1.json",
});
const GRAPH = Object.freeze({ local: APNT_POOL_V1_LOCAL_VERDICT_FACTORY_PIN.graphRecord, chipnet: APNT_POOL_V1_VERDICT_FACTORY_PIN.graphRecord });
const COVENANTS = ["settlement", "coin", "range_record", "tree_update", "root_copy", "pending_batch", "verdict_factory", "inbox"] as const;
/** Inventory of fixed direct file dependencies; runtimeDistDigest also inventories every dist file. */
export const devInstallationFilesV1 = Object.freeze([
  ...Object.values(BUILD), ...Object.values(GRAPH),
  "tools/pool-action-modules/lib/artifact.mjs", "tools/pool-action-modules/lib/canonical.mjs", "tools/pool-action-modules/lib/refusal.mjs",
  "tools/pool-action-modules/lib/runtime-freshness.mjs",
  "packages/protocol-runtime/test-vectors/apnt-pool-v1-proof-system-registry-rev3-vectors.json",
  "tools/apnt-pool-aggregate-sp1/core/src/profile.rs",
  "packages/reference-aggregator/.local-generated/pool-action-verifier/verifier",
  "packages/reference-aggregator/.local-generated/pool-action-verifier/identity.js",
  ...["protocol-runtime", "chain-io", "reference-aggregator"].flatMap(p => [`packages/${p}/dist/index.js`, `packages/${p}/dist/.runtime-build.json`]),
  ...COVENANTS.flatMap(n => ["src", "dist"].map(d => `packages/protocol-runtime/${d}/cashassembly/apnt_pool_${n}_v1.casm`)),
]);
function bytes(path: string): Buffer {
  const url = new URL(path, ROOT), stat = fs.lstatSync(url);
  devRequireV1(stat.isFile() && stat.size > 0 && stat.size <= 64 * 1024 * 1024, F.INSTALLATION); // guard: asset
  return fs.readFileSync(url);
}
const json = (path: string): any => JSON.parse(bytes(path).toString("utf8"));
type Codec = { canonicalText(v: unknown): string; sha256Hex(v: string): string };
function codec(): Codec {
  for (const path of devInstallationFilesV1.slice(4, 7)) bytes(path);
  return require(fileURLToPath(new URL("tools/pool-action-modules/lib/artifact.mjs", ROOT))) as Codec;
}
/** Exact UTF-8 tagged canonical serialization of the typed artifact; never an envelope/file digest. */
export function devArtifactDigestV1(value: unknown): string {
  const c = codec();
  return c.sha256Hex(c.canonicalText(value));
}
/** Admission schema only; the own-read canonical genesis rebuild/audit is still required by every future consumer. */
export function devArtifactAdmissionV1(value: unknown): void {
  const a = devRecordV1(value, ["poolVersion", "artifactRevision", "network", "deploymentId32", "categories", "covenants",
    "rangeGenesisLog2", "rootCopyCount", "values", "verifierFactoryTokens"]);
  const byteArray = (v: unknown, min: number, max: number): v is Uint8Array => v instanceof Uint8Array && !types.isProxy(v) &&
    v.byteLength >= min && v.byteLength <= max;
  devRequireV1(a.poolVersion === 1 && a.artifactRevision === 2 && byteArray(a.deploymentId32, 32, 32) &&
    typeof a.rangeGenesisLog2 === "number" && Number.isInteger(a.rangeGenesisLog2) && a.rangeGenesisLog2 >= APNT_POOL_V1_RANGE_GENESIS_MINIMUM_LOG2 && a.rangeGenesisLog2 <= APNT_POOL_V1_RANGE_GENESIS_MAXIMUM_LOG2 &&
    typeof a.rootCopyCount === "number" && Number.isSafeInteger(a.rootCopyCount) && a.rootCopyCount >= 2 && a.rootCopyCount <= 0xffff_ffff, F.DEPLOYMENT); // guard: artifact-shape
  const categories = devRecordV1(a.categories, ["verdict", "range", "root"]);
  for (const name of ["verdict", "range", "root"]) {
    const c = devRecordV1(categories[name], ["wire32", "display32", "genesisTxidDisplay32"]);
    devRequireV1(byteArray(c.wire32, 32, 32) && byteArray(c.display32, 32, 32) && byteArray(c.genesisTxidDisplay32, 32, 32) &&
      Buffer.from(c.wire32).reverse().equals(Buffer.from(c.display32)) && Buffer.from(c.display32).reverse().equals(Buffer.from(c.wire32)), F.DEPLOYMENT); // guard: byte-order
  }
  const covenants = devRecordV1(a.covenants, ["settlement", "poolCoin", "range", "treeUpdate", "rootCopy", "verifierFactory", "inbox"]);
  for (const name of ["settlement", "poolCoin", "range", "treeUpdate", "rootCopy", "verifierFactory"]) {
    const c = devRecordV1(covenants[name], ["redeemBytecode", "lockingBytecode"]);
    devRequireV1(byteArray(c.redeemBytecode, 1, 10_000) && byteArray(c.lockingBytecode, 35, 35), F.DEPLOYMENT); // guard: covenant-shape
  }
  const inbox = devRecordV1(covenants.inbox, ["codeBytecode", "codeSha256", "refundDelayBlocks"]);
  devRequireV1(byteArray(inbox.codeBytecode, 1, 429) && byteArray(inbox.codeSha256, 32, 32) && inbox.refundDelayBlocks === APNT_POOL_V1_INBOX_REFUND_DELAY_BLOCKS, F.DEPLOYMENT); // guard: inbox-shape
  const values = devRecordV1(a.values, ["rangeRecordSats", "treeUpdateSats", "rootCopySats", "foldBountySats"]);
  devRequireV1(Object.values(values).every(v => typeof v === "bigint" && v > 0n && v <= APNT_POOL_V1_MAX_MONEY_SATS), F.DEPLOYMENT); // guard: values-shape
  devRequireV1(Array.isArray(a.verifierFactoryTokens) && a.verifierFactoryTokens.length === 1, F.DEPLOYMENT); // guard: factory-shape
  const token = devRecordV1(a.verifierFactoryTokens[0], ["capability", "commitment", "valueSats"]);
  devRequireV1(token.capability === "minting" && byteArray(token.commitment, 0, 0) && typeof token.valueSats === "bigint" &&
    token.valueSats > 0n && token.valueSats <= APNT_POOL_V1_MAX_MONEY_SATS, F.DEPLOYMENT); // guard: token-shape
}
type Installed = Readonly<{ backend: "local" | "chipnet"; profileId: string; programVkeyHash: string;
  graphRoot: string; lockings: readonly string[]; wrapperVkSha256: string; recursionRootLe32: string }>;
const installed = new WeakMap<object, Installed>();
export function devInstallationSelectionV1(handle: unknown): Installed {
  const s = handle !== null && typeof handle === "object" ? installed.get(handle) : undefined;
  devRequireV1(s !== undefined, F.INSTALLATION); // guard: installation-brand
  return s;
}

/** Complete private-repository installation only. Reads public data; never runs a native verifier, builder, prover or VM.
 * Metadata integrity is not proof verification or genesis/chain authentication. No caller paths or overrides. */
export function loadAPNTPoolDevVerifierInstallationV1(backend: "local" | "chipnet"): DevResultV1<APNTPoolDevVerifierInstallationV1> {
  try {
    devRequireV1(backend === "local" || backend === "chipnet", F.NETWORK); // guard: backend
    const pin = backend === "local" ? APNT_POOL_V1_LOCAL_VERDICT_FACTORY_PIN : APNT_POOL_V1_VERDICT_FACTORY_PIN;
    const b = json(BUILD[backend]), g = json(GRAPH[backend]), other = json(GRAPH[backend === "local" ? "chipnet" : "local"]);
    devRequireV1(b.schema === "apnt-pool-aggregate-canonical-build-record-v1" && g.schema === "apnt-pool-onetx-verifier-graph-record-v1", F.INSTALLATION); // guard: metadata-schema
    const p = b.record;
    devRequireV1(g.program.record === BUILD[backend] && g.program.package === p.package && p.programVkeyHash === pin.programVkeyHash &&
      g.program.programVkeyHash === pin.programVkeyHash && devHashV1(p.guestElfSha256) && g.program.guestElfSha256 === p.guestElfSha256 &&
      Number.isSafeInteger(p.guestElfBytes) && p.guestElfBytes > 0 && g.program.guestElfBytes === p.guestElfBytes, F.INSTALLATION); // guard: program
    devRequireV1(Array.isArray(g.graph.lockings) && g.graph.lockings.length === pin.inputs && g.graph.inputs === pin.inputs &&
      g.graph.transactionInputs === pin.inputs + 1 && g.graph.factoryInputIndex === pin.inputs &&
      g.graph.root === pin.graphRootLockingBytecode && g.graph.lockings[0] === pin.graphRootLockingBytecode &&
      g.graph.lockings.every((s: unknown) => typeof s === "string" && /^aa20[0-9a-f]{64}87$/u.test(s)) &&
      new Set(g.graph.lockings).size === pin.inputs && sha(Buffer.from(g.graph.lockings.join(""), "hex")) === g.graph.lockingsSha256, F.VERIFIER_GRAPH); // guard: graph
    devRequireV1(p.sp1Version === "6.3.1" && g.wrapper.sp1Version === p.sp1Version &&
      other.wrapper.sp1Version === p.sp1Version && devHashV1(g.wrapper.wrapperVkSha256) &&
      g.wrapper.wrapperVkSha256 === other.wrapper.wrapperVkSha256 && g.wrapper.s0 === BigInt(`0x${pin.programVkeyHash}`).toString(), F.INSTALLATION); // guard: wrapper
    devRequireV1(g.wrapper.s3Le32 === pin.recursionRootLe32 && g.wrapper.recursionVkeyRootHex === Buffer.from(pin.recursionRootLe32, "hex").reverse().toString("hex") &&
      other.wrapper.s3Le32 === pin.recursionRootLe32 && other.wrapper.recursionVkeyRootHex === g.wrapper.recursionVkeyRootHex, F.INSTALLATION); // guard: recursion
    const registry = json("packages/protocol-runtime/test-vectors/apnt-pool-v1-proof-system-registry-rev3-vectors.json"), vp = registry.chipnetZeroValueVp;
    const profile = Buffer.from(deriveAPNTPoolProfileIdV1({ systemId: 1, verifierParameters: Buffer.from(vp.vp, "hex") })).toString("hex");
    const core = bytes("tools/apnt-pool-aggregate-sp1/core/src/profile.rs").toString("utf8");
    const coreProfile = /pub const CHIPNET_ZERO_VALUE_REVISION_3_PROFILE_ID: \[u8; 32\] =\s*hex32\("([0-9a-f]{64})"\)/u.exec(core)?.[1];
    devRequireV1(registry.registryEntry.systemId === 1 && registry.registryEntry.revision === 3 && vp.vpBytes === 528 &&
      Buffer.from(vp.vp, "hex").length === vp.vpBytes && sha(Buffer.from(vp.vp, "hex")) === vp.vpSha256 && vp.profileId === profile &&
      coreProfile === profile && p.allowlistedVp.registryEntry === 1 && p.allowlistedVp.registryRevision === 3 &&
      p.allowlistedVp.profileId === profile && p.allowlistedVp.vpBytes === vp.vpBytes && p.allowlistedVp.vpSha256 === vp.vpSha256 &&
      Array.isArray(p.compiledAllowlist) && p.compiledAllowlist.length === 1 && p.compiledAllowlist[0] === profile, F.PROFILE); // guard: profile
    const identity = bytes("packages/reference-aggregator/.local-generated/pool-action-verifier/identity.js").toString("utf8");
    const digest = /^export const verifierSha256 = "([0-9a-f]{64})";\n$/u.exec(identity)?.[1];
    devRequireV1(digest !== undefined && sha(bytes("packages/reference-aggregator/.local-generated/pool-action-verifier/verifier")) === digest, F.INSTALLATION); // guard: native
    for (const n of COVENANTS) {
      const source = bytes(`packages/protocol-runtime/src/cashassembly/apnt_pool_${n}_v1.casm`);
      const dist = bytes(`packages/protocol-runtime/dist/cashassembly/apnt_pool_${n}_v1.casm`);
      devRequireV1(source.equals(dist) && (n !== "verdict_factory" || sha(source) === pin.sourceSha256), F.INSTALLATION); // guard: covenant
    }
    // Reuse only the read-only digest functions. Never call assertRuntimeFresh/runtimeNativeSources (they run Cargo/git).
    bytes("tools/pool-action-modules/lib/runtime-freshness.mjs");
    const freshness = require(fileURLToPath(new URL("tools/pool-action-modules/lib/runtime-freshness.mjs", ROOT))) as {
      runtimeDistDigest(root: string, path: string): string; runtimeGeneratedDigest(root: string, path: string): string;
    };
    for (const name of ["protocol-runtime", "chain-io", "reference-aggregator"]) {
      const path = `packages/${name}`, stamp = json(`${path}/dist/.runtime-build.json`);
      bytes(`${path}/dist/index.js`);
      devRequireV1(stamp.schema === "pool-runtime-build-v2" && stamp.distDigest === freshness.runtimeDistDigest(fileURLToPath(ROOT), path) &&
        stamp.generatedDigest === freshness.runtimeGeneratedDigest(fileURLToPath(ROOT), path), F.INSTALLATION); // guard: dist
    }
    codec();
    const handle = Object.freeze(Object.create(null)) as APNTPoolDevVerifierInstallationV1;
    installed.set(handle, Object.freeze({ backend, profileId: profile, programVkeyHash: pin.programVkeyHash,
      graphRoot: pin.graphRootLockingBytecode, lockings: Object.freeze(g.graph.lockings.slice()),
      wrapperVkSha256: g.wrapper.wrapperVkSha256, recursionRootLe32: pin.recursionRootLe32 }));
    return Object.freeze({ ok: true, value: handle });
  } catch (error) { return devFailureV1(error, F.INSTALLATION); }
}
