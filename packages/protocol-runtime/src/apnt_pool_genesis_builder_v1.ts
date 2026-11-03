import { type Bytes32 } from "./bytes.js";
import {
  APNT_POOL_FAILURE_V1 as F,
  APNT_POOL_V1_MAX_MONEY_SATS,
  pool32,
  poolAnyBytes,
  poolArray,
  poolBoundary,
  poolConcat,
  poolEqual,
  poolFail,
  poolFailureCodeOf,
  poolRecord,
  poolRequire,
  poolSha256,
  type APNTPoolFailureV1,
} from "./apnt_pool_contract_v1.js";
import { deriveAPNTPoolDeploymentIdV1, type APNTPoolNetworkV1 } from "./apnt_pool_statement_v1.js";
import {
  apntPoolEmptyFrontierV1,
  deriveAPNTPoolFrontierRootV1,
  encodeAPNTPoolTreeUpdateCommitmentV1,
} from "./apnt_pool_frontier_v1.js";
import {
  APNT_POOL_V1_RANGE_GENESIS_MAXIMUM_LOG2,
  deriveAPNTPoolRangeGenesisRecordsV1,
  deriveAPNTPoolRangeRecordLockV1,
} from "./apnt_pool_range_record_v1.js";
import { buildAPNTPoolRangeRecordCovenantV1 } from "./apnt_pool_range_record_covenant_v1.js";
import { buildAPNTPoolInboxCovenantV1, type APNTPoolInboxCovenantV1 } from "./apnt_pool_inbox_covenant_v1.js";
import { buildAPNTPoolSettlementCovenantsV1 } from "./apnt_pool_settlement_covenant_v1.js";
import { buildAPNTPoolNoteTreeCovenantsV1 } from "./apnt_pool_tree_covenants_v1.js";
import {
  APNT_POOL_V1_TOKEN_COMMITMENT_MAXIMUM_BYTES,
  poolDecodeTransaction,
  poolEncodeOutput,
  poolEncodeTransaction,
  type APNTPoolTokenCapabilityV1,
  type APNTPoolTransactionOutputV1,
  type APNTPoolTransactionV1,
} from "./apnt_pool_transaction_v1.js";
import {
  APNT_POOL_V1_RANGE_GENESIS_MINIMUM_LOG2,
  validateAPNTPoolGenesisV1,
  type APNTPoolArtifactFactoryTokenV1,
  type APNTPoolDeploymentArtifactV1Rev2,
} from "./apnt_pool_genesis_v1.js";

/**
 * APNT shielded pool v1: the revision-2 genesis builder (ENG-614; design.md,
 * "Genesis", "Supply audit, then induction" and "Inbox pin: artifact
 * revision 2").
 *
 * It builds a deposit-taking deployment from one funding outpoint: the
 * transactions that create the pool's three categories and its genesis state,
 * and the revision-2 artifact that pins them. Four transactions, in order:
 *
 * ```text
 * seed-verdict  spends the funding outpoint;  out 0: seed of V,  out 1: change
 * seed-range    spends seed-verdict:1;       out 0: seed of R,  out 1: change
 * seed-root     spends seed-range:1;         out 0: seed of T (all the rest)
 * genesis       spends (V,0), (R,0), (T,0);  the factory tokens, the 2^g range
 *               records, the tree update, the K root copies, then change
 * ```
 *
 * A category's id is the txid of the seed whose output 0 the genesis spends,
 * so each id is known only once that seed is signed: the build is staged, and
 * each call is pure. The caller passes the whole input with every transaction
 * signed so far; the builder rebuilds each earlier step, requires the signed
 * bytes to be that step's template with only its unlocking bytecode filled
 * (of the declared length, so every fee is exact), and returns one of:
 *
 * - `sign`: the next step's unsigned transaction (every unlocking empty), the
 *   outputs its inputs spend (for the signature hash), its signed size and fee;
 * - `factory`: after the three seeds, the context a verifier factory is built
 *   for (the protocol network, the three categories, the settlement lock and
 *   the deployment id); the caller passes the factory's redeem back;
 * - `complete`: the artifact, after the builder audited it and the signed
 *   genesis with `validateAPNTPoolGenesisV1` at revision 2, the four signed
 *   transactions with their sizes and fees, the genesis output positions and
 *   the change outpoint left for later funding.
 *
 * The genesis is audited twice: unsigned, before it is handed out to sign
 * (with the artifact naming the unsigned id, so every other check sees exactly
 * what will be signed), and signed. A genesis the audit refuses, for example
 * one whose factory lock is a pool lock, is therefore refused with the
 * audit's own code before anyone signs it. The seeds carry no pool token and
 * return to the funding lock, so signing or broadcasting one risks nothing.
 *
 * What it builds itself and what it takes. The settlement, pool-coin, range
 * code, tree-update and root-copy covenants and the inbox code are always the
 * shipped builds for the deployment's parameters: the audit accepts no other,
 * so there is nothing to choose. The verifier factory is an input (its redeem
 * and its token list), because no factory is shipped: the audit binds it only
 * as a P2SH32 lock of the artifact's redeem (ARCH-190), and the shipped pool
 * factory is ENG-615's (`lane/pool-verdict-supply`). Until that lands, every
 * factory given here is the caller's, and a live Chipnet genesis waits for it.
 *
 * Before any signature, the first call builds the whole genesis once with
 * placeholder categories, so a parameter the covenant builders refuse, a value
 * below the dust threshold, a genesis above BCHN's 100,000-byte standard
 * transaction size, or funding that cannot cover every fee and output is
 * refused before a seed is signed. Every lock the genesis creates is a
 * 35-byte P2SH32 and no commitment depends on a category, so the real genesis
 * has the probe's size; the builder requires that.
 *
 * Fees and dust. Each transaction pays exactly `feeSatsPerByte` per signed
 * byte. Every output is at least BCHN's dust threshold at `dustRelaySatsPerKb`
 * (3 × the fee at that rate for the output plus a 148-byte spend). Change and
 * the seeds go back to the funding lock: this is the deployer's bootstrap
 * change, not private-transfer change, and no private note exists yet.
 *
 * What this is not. The builder holds no key and checks no signature: the
 * ledger or node verifies scripts. It reads no chain: the funding value and
 * lock are the caller's, and a wrong one yields signatures that fail. Passing
 * its audit is not chain validation or wallet acceptance, and a verifier
 * factory that passes it is not established as sound (ARCH-190).
 */

/** The artifact revision this builder produces and requires of its own audit: a deposit-taking deployment. */
export const APNT_POOL_V1_GENESIS_BUILDER_ARTIFACT_REVISION = 2;

/**
 * The deployment networks the builder accepts, and the protocol network each
 * deploys under. Mainnet has no entry: the pool's setup is a simulated
 * single-party ceremony, and every deployment is a zero-value test.
 *
 * `local-fixture` deploys under `local` (0x99, ENG-595; ARCH-293): the
 * zero-value local simulation domain, which names no chain. Its deployment id
 * is never a Chipnet id, so its artifact opens only at the wallet's and the
 * aggregator's local entry and is refused at their production entry. Only
 * `chipnet` deploys under `chipnet`. Before ENG-595 landed, `local-fixture`
 * deployed under `chipnet` and a local build was byte for byte a Chipnet one;
 * the covenants and the audit take the network from the artifact, so this map
 * is the one place that changed.
 */
export const APNT_POOL_V1_GENESIS_BUILDER_NETWORKS = Object.freeze({
  chipnet: "chipnet",
  "local-fixture": "local",
} as const satisfies Readonly<Record<string, APNTPoolNetworkV1>>);
export type APNTPoolGenesisBuilderNetworkV1 = keyof typeof APNT_POOL_V1_GENESIS_BUILDER_NETWORKS;

export const APNT_POOL_V1_GENESIS_BUILDER_LABELS = Object.freeze({
  chipnet: "CHIPNET POOL DEPLOYMENT - SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY",
  "local-fixture": "LOCAL FIXTURE DEPLOYMENT - protocol network local (0x99), no chain - ZERO-VALUE TEST ONLY",
} as const satisfies Readonly<Record<APNTPoolGenesisBuilderNetworkV1, string>>);

export const APNT_POOL_V1_GENESIS_BUILDER_STEPS = Object.freeze(["seed-verdict", "seed-range", "seed-root", "genesis"] as const);
export type APNTPoolGenesisBuilderStepNameV1 = (typeof APNT_POOL_V1_GENESIS_BUILDER_STEPS)[number];

export type APNTPoolGenesisFundingV1 = Readonly<{
  /** The funding outpoint's txid in display order, as explorers and Libauth show it; the builder writes it reversed. */
  txidDisplay32: Uint8Array;
  index: number;
  valueSats: bigint;
  /** The funding output's locking bytecode; the seeds and all change return to it. */
  lockingBytecode: Uint8Array;
  /** The exact unlocking length the deployer's signer produces for this lock: 100 for P2PKH with a Schnorr signature. */
  unlockingBytes: number;
}>;

export type APNTPoolGenesisParametersV1 = Readonly<{
  /** `g`: `2^g` genesis range records, `1 ≤ g ≤ 9`. */
  rangeGenesisLog2: number;
  /** `K ≥ 2` root copies. */
  rootCopyCount: number;
  values: Readonly<{ rangeRecordSats: bigint; treeUpdateSats: bigint; rootCopySats: bigint; foldBountySats: bigint }>;
}>;

export type APNTPoolGenesisPolicyV1 = Readonly<{
  /** Satoshis per signed byte, 1 to 100: a bound against passing a per-kilobyte rate. */
  feeSatsPerByte: bigint;
  /** BCHN's dust relay fee, satoshis per 1,000 bytes, 1 to 10,000. */
  dustRelaySatsPerKb: bigint;
}>;

export type APNTPoolGenesisFactoryV1 = Readonly<{
  /** The factory tokens, known from the first call: they size the genesis. */
  tokens: readonly APNTPoolArtifactFactoryTokenV1[];
  /** The factory redeem built for the `factory` state's context; `null` until then. */
  redeemBytecode: Uint8Array | null;
}>;

export type APNTPoolGenesisBuildInputV1 = Readonly<{
  network: APNTPoolGenesisBuilderNetworkV1;
  funding: APNTPoolGenesisFundingV1;
  parameters: APNTPoolGenesisParametersV1;
  policy: APNTPoolGenesisPolicyV1;
  verifierFactory: APNTPoolGenesisFactoryV1;
  /** Every step signed so far, in step order: 0 to 4 raw transactions. */
  signedTransactions: readonly Uint8Array[];
}>;

export type APNTPoolGenesisSourceOutputV1 = Readonly<{ lockingBytecode: Uint8Array; valueSats: bigint }>;

export type APNTPoolGenesisBuildStepV1 = Readonly<{
  name: APNTPoolGenesisBuilderStepNameV1;
  position: number;
  /** The transaction with every unlocking bytecode empty. */
  unsignedTransaction: Uint8Array;
  /** What each input spends, in input order: the signature hash covers them. */
  sourceOutputs: readonly APNTPoolGenesisSourceOutputV1[];
  signedBytes: number;
  feeSats: bigint;
}>;

export type APNTPoolGenesisFactoryContextV1 = Readonly<{
  network: APNTPoolNetworkV1;
  deploymentId32: Bytes32;
  verdictCategoryWire32: Bytes32;
  rangeCategoryWire32: Bytes32;
  rootCategoryWire32: Bytes32;
  settlementLockingBytecode: Uint8Array;
}>;

export type APNTPoolGenesisBuiltTransactionV1 = Readonly<{
  name: APNTPoolGenesisBuilderStepNameV1;
  transaction: Uint8Array;
  txidDisplay32: Bytes32;
  bytes: number;
  feeSats: bigint;
}>;

export type APNTPoolGenesisBuildResultV1 =
  | Readonly<{ valid: true; failureCode: null; state: "sign"; step: APNTPoolGenesisBuildStepV1 }>
  | Readonly<{ valid: true; failureCode: null; state: "factory"; factoryContext: APNTPoolGenesisFactoryContextV1 }>
  | Readonly<{
    valid: true;
    failureCode: null;
    state: "complete";
    network: APNTPoolGenesisBuilderNetworkV1;
    label: string;
    artifact: APNTPoolDeploymentArtifactV1Rev2;
    genesisTransactions: readonly Uint8Array[];
    transactions: readonly APNTPoolGenesisBuiltTransactionV1[];
    /** Genesis output indices of each kind. */
    genesisOutputs: Readonly<{ factoryTokens: readonly number[]; rangeRecords: readonly number[]; treeUpdate: number; rootCopies: readonly number[]; change: number }>;
    /** The genesis change: the deployer's own output, left for later funding. */
    remainder: Readonly<{ txidDisplay32: Bytes32; index: number; valueSats: bigint; lockingBytecode: Uint8Array }>;
    inbox: APNTPoolInboxCovenantV1;
  }>
  | Readonly<{ valid: false; failureCode: APNTPoolFailureV1 }>;

type Output = APNTPoolTransactionOutputV1;
type Spend = { txidWire32: Uint8Array; index: number; valueSats: bigint };
type Token = { capability: APNTPoolTokenCapabilityV1; commitment: Uint8Array; valueSats: bigint };
type Input = {
  network: APNTPoolGenesisBuilderNetworkV1;
  protocolNetwork: APNTPoolNetworkV1;
  funding: { txidWire32: Uint8Array; index: number; valueSats: bigint; lock: Uint8Array; unlockingBytes: number };
  g: number;
  copies: number;
  values: { range: bigint; treeUpdate: bigint; rootCopy: bigint; foldBounty: bigint };
  feeRate: bigint;
  dustRate: bigint;
  factoryTokens: Token[];
  factoryRedeem: Uint8Array | null;
  signed: Uint8Array[];
};
type Categories = { verdict: Uint8Array; range: Uint8Array; root: Uint8Array };
type Covenant = { redeemBytecode: Uint8Array; lockingBytecode: Uint8Array };
type Covenants = { settlement: Covenant; poolCoin: Covenant; rangeCode: Uint8Array; treeUpdate: Covenant; rootCopy: Covenant; inbox: APNTPoolInboxCovenantV1 };
type Step = { name: APNTPoolGenesisBuilderStepNameV1; spends: Spend[]; outputs: Output[]; unsigned: Uint8Array; signedBytes: number; feeSats: bigint };

const VERSION = 2;
const LOCKTIME = 0;
const SEQUENCE_FINAL = 0xffff_ffff;
const MAXIMUM_SCRIPT_BYTES = 10_000;
const MAXIMUM_FACTORY_TOKENS = 0xffff;
const MAXIMUM_FEE_RATE = 100n;
const MAXIMUM_DUST_RATE = 10_000n;
/** BCHN's MAX_STANDARD_TX_SIZE (src/policy/policy.h): a larger transaction is valid but neither relayed nor mined. */
const MAXIMUM_STANDARD_TRANSACTION_BYTES = 100_000;
const CAPABILITIES: readonly string[] = ["none", "mutable", "minting"];
/** Stand-in categories for the size probe: distinct, non-palindromic, never a deployment's. */
const PROBE: Categories = {
  verdict: poolSha256(null, Uint8Array.of(0x70, 0x72, 0x6f, 0x62, 0x65, 0x56)),
  range: poolSha256(null, Uint8Array.of(0x70, 0x72, 0x6f, 0x62, 0x65, 0x52)),
  root: poolSha256(null, Uint8Array.of(0x70, 0x72, 0x6f, 0x62, 0x65, 0x54)),
};
const PROBE_FACTORY_REDEEM = Uint8Array.of(0x51);

const reversed = (bytes: Uint8Array): Uint8Array => bytes.slice().reverse();
const hash256 = (bytes: Uint8Array): Bytes32 => poolSha256(null, poolSha256(null, bytes));
const p2sh32 = (redeem: Uint8Array): Uint8Array => poolConcat(Uint8Array.of(0xaa, 0x20), hash256(redeem), Uint8Array.of(0x87));

function sats(value: unknown, code: APNTPoolFailureV1): bigint {
  poolRequire(typeof value === "bigint" && value >= 1n && value <= APNT_POOL_V1_MAX_MONEY_SATS, code);
  return value;
}

function count(value: unknown, minimum: number, maximum: number, code: APNTPoolFailureV1): number {
  poolRequire(typeof value === "number" && Number.isSafeInteger(value) && value >= minimum && value <= maximum, code);
  return value;
}

function script(value: unknown, code: APNTPoolFailureV1): Uint8Array {
  const bytes = poolAnyBytes(value, code);
  poolRequire(bytes.length >= 1 && bytes.length <= MAXIMUM_SCRIPT_BYTES, code);
  return bytes;
}

function inputOf(value: unknown): Input {
  const input = poolRecord(value, ["network", "funding", "parameters", "policy", "verifierFactory", "signedTransactions"], F.SHAPE);
  const network = input.network;
  poolRequire(typeof network === "string" && Object.hasOwn(APNT_POOL_V1_GENESIS_BUILDER_NETWORKS, network), F.DEPLOYMENT_NETWORK);
  const builderNetwork = network as APNTPoolGenesisBuilderNetworkV1;
  const funding = poolRecord(input.funding, ["txidDisplay32", "index", "valueSats", "lockingBytecode", "unlockingBytes"], F.DEPLOY_FUNDING);
  const parameters = poolRecord(input.parameters, ["rangeGenesisLog2", "rootCopyCount", "values"], F.DEPLOY_PARAMETER);
  const values = poolRecord(parameters.values, ["rangeRecordSats", "treeUpdateSats", "rootCopySats", "foldBountySats"], F.DEPLOY_PARAMETER);
  const policy = poolRecord(input.policy, ["feeSatsPerByte", "dustRelaySatsPerKb"], F.DEPLOY_PARAMETER);
  const feeRate = policy.feeSatsPerByte;
  const dustRate = policy.dustRelaySatsPerKb;
  poolRequire(typeof feeRate === "bigint" && feeRate >= 1n && feeRate <= MAXIMUM_FEE_RATE, F.DEPLOY_PARAMETER);
  poolRequire(typeof dustRate === "bigint" && dustRate >= 1n && dustRate <= MAXIMUM_DUST_RATE, F.DEPLOY_PARAMETER);
  const factory = poolRecord(input.verifierFactory, ["tokens", "redeemBytecode"], F.DEPLOY_FACTORY);
  const factoryTokens = poolArray(factory.tokens, MAXIMUM_FACTORY_TOKENS, F.DEPLOY_FACTORY).map((entry) => {
    const token = poolRecord(entry, ["capability", "commitment", "valueSats"], F.DEPLOY_FACTORY);
    poolRequire(typeof token.capability === "string" && CAPABILITIES.includes(token.capability), F.DEPLOY_FACTORY);
    const commitment = poolAnyBytes(token.commitment, F.DEPLOY_FACTORY);
    poolRequire(commitment.length <= APNT_POOL_V1_TOKEN_COMMITMENT_MAXIMUM_BYTES, F.DEPLOY_FACTORY);
    return { capability: token.capability as APNTPoolTokenCapabilityV1, commitment, valueSats: sats(token.valueSats, F.DEPLOY_FACTORY) };
  });
  poolRequire(factoryTokens.length >= 1, F.DEPLOY_FACTORY);
  const signed = poolArray(input.signedTransactions, APNT_POOL_V1_GENESIS_BUILDER_STEPS.length, F.DEPLOY_SIGNED)
    .map((raw) => poolAnyBytes(raw, F.DEPLOY_SIGNED));
  return {
    network: builderNetwork,
    protocolNetwork: APNT_POOL_V1_GENESIS_BUILDER_NETWORKS[builderNetwork],
    funding: {
      txidWire32: reversed(pool32(funding.txidDisplay32, F.DEPLOY_FUNDING)),
      index: count(funding.index, 0, SEQUENCE_FINAL, F.DEPLOY_FUNDING),
      valueSats: sats(funding.valueSats, F.DEPLOY_FUNDING),
      lock: script(funding.lockingBytecode, F.DEPLOY_FUNDING),
      unlockingBytes: count(funding.unlockingBytes, 1, MAXIMUM_SCRIPT_BYTES, F.DEPLOY_FUNDING),
    },
    g: count(parameters.rangeGenesisLog2, APNT_POOL_V1_RANGE_GENESIS_MINIMUM_LOG2, APNT_POOL_V1_RANGE_GENESIS_MAXIMUM_LOG2, F.DEPLOY_PARAMETER),
    // The settlement builder bounds K from above; the probe maps its refusal to pool-deploy-parameter.
    copies: count(parameters.rootCopyCount, 2, Number.MAX_SAFE_INTEGER, F.DEPLOY_PARAMETER),
    values: {
      range: sats(values.rangeRecordSats, F.DEPLOY_PARAMETER),
      treeUpdate: sats(values.treeUpdateSats, F.DEPLOY_PARAMETER),
      rootCopy: sats(values.rootCopySats, F.DEPLOY_PARAMETER),
      foldBounty: sats(values.foldBountySats, F.DEPLOY_PARAMETER),
    },
    feeRate,
    dustRate,
    factoryTokens,
    factoryRedeem: factory.redeemBytecode === null ? null : script(factory.redeemBytecode, F.DEPLOY_FACTORY),
    signed,
  };
}

/** BCHN's dust threshold, as Libauth's `getDustThreshold` computes it for an output that is not a data carrier. */
function dustOf(output: Output, dustRate: bigint): bigint {
  const fee = (BigInt(poolEncodeOutput(output).length + 148) * dustRate) / 1000n;
  return 3n * (fee === 0n ? 1n : fee);
}

const changeOutput = (lock: Uint8Array, valueSats: bigint): Output => ({ valueSats, lockingBytecode: lock, token: null });

/** A transaction spending `spends` into `outputs`, every unlocking bytecode `unlocking` zero bytes long. */
function encodeStep(spends: readonly Spend[], outputs: readonly Output[], unlocking: number): Uint8Array {
  return poolEncodeTransaction({
    version: VERSION,
    inputs: spends.map((spend) => ({ outpointTxidWire32: spend.txidWire32 as Bytes32, outpointIndex: spend.index, unlockingBytecode: new Uint8Array(unlocking), sequenceNumber: SEQUENCE_FINAL })),
    outputs,
    locktime: LOCKTIME,
  });
}

/** The signed size of a step with these outputs then its change: every unlocking bytecode has the declared length. */
const signedSizeOf = (input: Input, spends: readonly Spend[], fixed: readonly Output[]): number =>
  encodeStep(spends, [...fixed, changeOutput(input.funding.lock, 0n)], input.funding.unlockingBytes).length;

/**
 * A step's transaction: the fixed outputs, then the change to the funding lock, which takes what the inputs leave
 * after the fee at the signed size and must not be dust. The root seed has no fixed output, so its change is its
 * output 0, the seed of `T`.
 */
function stepOf(input: Input, name: APNTPoolGenesisBuilderStepNameV1, spends: Spend[], fixed: Output[]): Step {
  const signedBytes = signedSizeOf(input, spends, fixed);
  const feeSats = input.feeRate * BigInt(signedBytes);
  const spent = spends.reduce((total, spend) => total + spend.valueSats, 0n);
  const rest = spent - fixed.reduce((total, output) => total + output.valueSats, 0n) - feeSats;
  poolRequire(rest >= dustOf(changeOutput(input.funding.lock, rest > 0n ? rest : 0n), input.dustRate), F.DEPLOY_FUNDING);
  const outputs = [...fixed, changeOutput(input.funding.lock, rest)];
  return { name, spends, outputs, unsigned: encodeStep(spends, outputs, 0), signedBytes, feeSats };
}

/** A seed's value: the smallest output to the funding lock that is not dust. */
const seedSatsOf = (input: Input): bigint => dustOf(changeOutput(input.funding.lock, 0n), input.dustRate);
const seedOutputsOf = (input: Input, position: 0 | 1 | 2): Output[] => (position < 2 ? [changeOutput(input.funding.lock, seedSatsOf(input))] : []);

/**
 * The shipped covenants for these categories and parameters. A parameter a builder refuses (`K` above its
 * bound, or a fold bounty not above `K × rootCopySats`) is `pool-deploy-parameter`; any other builder failure
 * keeps its own code, as the audit's reviewed-build filter does (ENG-359).
 */
function covenantsOf(input: Input, categories: Categories): Covenants {
  try {
    const settlement = buildAPNTPoolSettlementCovenantsV1({
      network: input.protocolNetwork,
      verdictCategoryWire32: categories.verdict,
      rangeCategoryWire32: categories.range,
      rootCategoryWire32: categories.root,
      rootCopyCount: input.copies,
      rootCopySats: input.values.rootCopy,
      foldBountySats: input.values.foldBounty,
      recordValueSats: input.values.range,
    });
    const settlementLock = settlement.settlement.lockingBytecode;
    const range = buildAPNTPoolRangeRecordCovenantV1({ verdictCategoryWire32: categories.verdict, settlementLockingBytecode: settlementLock });
    const tree = buildAPNTPoolNoteTreeCovenantsV1({
      rootCategoryWire32: categories.root,
      verdictCategoryWire32: categories.verdict,
      settlementLockingBytecode: settlementLock,
      rootCopyCount: input.copies,
      rootCopySats: input.values.rootCopy,
    });
    const inbox = buildAPNTPoolInboxCovenantV1({ verdictCategoryWire32: categories.verdict, settlementLockingBytecode: settlementLock });
    const covenant = (c: Covenant): Covenant => ({ redeemBytecode: c.redeemBytecode, lockingBytecode: c.lockingBytecode });
    return {
      settlement: covenant(settlement.settlement),
      poolCoin: covenant(settlement.poolCoin),
      rangeCode: range.codeBytecode,
      treeUpdate: covenant(tree.treeUpdate),
      rootCopy: covenant(tree.rootCopy),
      inbox,
    };
  } catch (error) {
    if (poolFailureCodeOf(error, F.SHAPE) === F.COVENANT_PARAMETER) poolFail(F.DEPLOY_PARAMETER);
    throw error;
  }
}

type GenesisLayout = { outputs: Output[]; factoryTokens: number[]; rangeRecords: number[]; treeUpdate: number; rootCopies: number[] };

/** The genesis's fixed outputs, every one at least dust: the factory tokens, the `2^g` records, the tree update and the `K` copies. */
function genesisOutputsOf(input: Input, categories: Categories, covenants: Covenants, factoryRedeem: Uint8Array): GenesisLayout {
  const empty = apntPoolEmptyFrontierV1();
  const nft = (category: Uint8Array, capability: APNTPoolTokenCapabilityV1, commitment: Uint8Array) => ({
    categoryWire32: category as Bytes32, amount: 0n, nft: { capability, commitment },
  });
  const factoryLock = p2sh32(factoryRedeem);
  const layout: GenesisLayout = { outputs: [], factoryTokens: [], rangeRecords: [], treeUpdate: -1, rootCopies: [] };
  const add = (output: Output, code: APNTPoolFailureV1): number => {
    poolRequire(output.valueSats >= dustOf(output, input.dustRate), code);
    layout.outputs.push(output);
    return layout.outputs.length - 1;
  };
  for (const token of input.factoryTokens) {
    layout.factoryTokens.push(add({ valueSats: token.valueSats, lockingBytecode: factoryLock, token: nft(categories.verdict, token.capability, token.commitment) }, F.DEPLOY_FACTORY));
  }
  for (const record66 of deriveAPNTPoolRangeGenesisRecordsV1(input.g)) {
    const lockingBytecode = deriveAPNTPoolRangeRecordLockV1({ codeBytecode: covenants.rangeCode, record66 }).lockingBytecode;
    layout.rangeRecords.push(add({ valueSats: input.values.range, lockingBytecode, token: nft(categories.range, "minting", new Uint8Array(0)) }, F.DEPLOY_PARAMETER));
  }
  layout.treeUpdate = add({ valueSats: input.values.treeUpdate, lockingBytecode: covenants.treeUpdate.lockingBytecode, token: nft(categories.root, "minting", encodeAPNTPoolTreeUpdateCommitmentV1(empty)) }, F.DEPLOY_PARAMETER);
  for (let copy = 0; copy < input.copies; copy += 1) {
    layout.rootCopies.push(add({ valueSats: input.values.rootCopy, lockingBytecode: covenants.rootCopy.lockingBytecode, token: nft(categories.root, "none", deriveAPNTPoolFrontierRootV1(empty)) }, F.DEPLOY_PARAMETER));
  }
  return layout;
}

/**
 * The size probe (see the module comment), run on every call before any step: the covenants for stand-in
 * categories, the genesis outputs, and the funding every fee and output needs. Returns the genesis's signed size.
 */
function preflight(input: Input): number {
  const covenants = covenantsOf(input, PROBE);
  const layout = genesisOutputsOf(input, PROBE, covenants, PROBE_FACTORY_REDEEM);
  const spends = (n: number): Spend[] => Array.from({ length: n }, (_, index) => ({ txidWire32: PROBE.verdict, index, valueSats: 0n }));
  const seedBytes = ([0, 1, 2] as const).map((position) => signedSizeOf(input, spends(1), seedOutputsOf(input, position)));
  const genesisBytes = signedSizeOf(input, spends(3), layout.outputs);
  // Only the genesis can exceed it: a seed has one input and at most two outputs, each script at most 10,000 bytes.
  poolRequire(genesisBytes <= MAXIMUM_STANDARD_TRANSACTION_BYTES, F.DEPLOY_SIZE);
  const fees = input.feeRate * BigInt(seedBytes.reduce((a, b) => a + b, 0) + genesisBytes);
  const fixed = layout.outputs.reduce((total, output) => total + output.valueSats, 0n);
  // The seeds of V and R return to the genesis as inputs, so the funding pays only the fees, the genesis's
  // fixed outputs and a change that is not dust.
  const need = fees + fixed + seedSatsOf(input);
  poolRequire(input.funding.valueSats >= need, F.DEPLOY_FUNDING);
  return genesisBytes;
}

/**
 * A signed step: it decodes strictly, every unlocking bytecode has the declared length, and with the unlocking
 * bytecode emptied it is exactly the step's template. Whether the signatures verify is the ledger's check.
 */
function acceptSigned(step: Step, raw: Uint8Array, unlockingBytes: number): APNTPoolTransactionV1 {
  let decoded: APNTPoolTransactionV1;
  try {
    decoded = poolDecodeTransaction(raw);
  } catch {
    return poolFail(F.DEPLOY_SIGNED);
  }
  poolRequire(decoded.inputs.every((input) => input.unlockingBytecode.length === unlockingBytes), F.DEPLOY_SIGNED);
  const emptied = poolEncodeTransaction({ ...decoded, inputs: decoded.inputs.map((input) => ({ ...input, unlockingBytecode: new Uint8Array(0) })) });
  poolRequire(poolEqual(emptied, step.unsigned) && raw.length === step.signedBytes, F.DEPLOY_SIGNED);
  return decoded;
}

function artifactOf(input: Input, categories: Categories, covenants: Covenants, deploymentId32: Bytes32, genesisTxidDisplay32: Uint8Array, factoryRedeem: Uint8Array): APNTPoolDeploymentArtifactV1Rev2 {
  const category = (wire32: Uint8Array) => ({ wire32: wire32.slice(), display32: reversed(wire32), genesisTxidDisplay32: genesisTxidDisplay32.slice() });
  return {
    poolVersion: 1,
    artifactRevision: APNT_POOL_V1_GENESIS_BUILDER_ARTIFACT_REVISION,
    network: input.protocolNetwork,
    deploymentId32,
    categories: { verdict: category(categories.verdict), range: category(categories.range), root: category(categories.root) },
    covenants: {
      settlement: covenants.settlement,
      poolCoin: covenants.poolCoin,
      range: { redeemBytecode: covenants.rangeCode, lockingBytecode: p2sh32(covenants.rangeCode) },
      treeUpdate: covenants.treeUpdate,
      rootCopy: covenants.rootCopy,
      verifierFactory: { redeemBytecode: factoryRedeem, lockingBytecode: p2sh32(factoryRedeem) },
      inbox: { codeBytecode: covenants.inbox.codeBytecode, codeSha256: covenants.inbox.codeSha256, refundDelayBlocks: covenants.inbox.refundDelayBlocks },
    },
    rangeGenesisLog2: input.g,
    rootCopyCount: input.copies,
    values: { rangeRecordSats: input.values.range, treeUpdateSats: input.values.treeUpdate, rootCopySats: input.values.rootCopy, foldBountySats: input.values.foldBounty },
    verifierFactoryTokens: input.factoryTokens.map((token) => ({ capability: token.capability, commitment: token.commitment, valueSats: token.valueSats })),
  };
}

/** The genesis audit at this builder's revision, or its own refusal code; a success must carry the inbox and the expected id. */
function audited(artifact: APNTPoolDeploymentArtifactV1Rev2, genesis: Uint8Array, deploymentId32: Bytes32): APNTPoolInboxCovenantV1 {
  const audit = validateAPNTPoolGenesisV1({ artifact, genesisTransactions: [genesis] }, APNT_POOL_V1_GENESIS_BUILDER_ARTIFACT_REVISION);
  if (!audit.valid) poolFail(audit.failureCode);
  poolRequire(audit.inbox !== null && poolEqual(audit.deploymentId32, deploymentId32), F.SHAPE);
  return audit.inbox;
}

function signResult(step: Step, input: Input, position: number): APNTPoolGenesisBuildResultV1 {
  return Object.freeze({
    valid: true, failureCode: null, state: "sign",
    step: Object.freeze({
      name: step.name,
      position,
      unsignedTransaction: step.unsigned.slice(),
      sourceOutputs: Object.freeze(step.spends.map((spend) => Object.freeze({ lockingBytecode: input.funding.lock.slice(), valueSats: spend.valueSats }))),
      signedBytes: step.signedBytes,
      feeSats: step.feeSats,
    }),
  });
}

/**
 * Builds a revision-2 pool genesis from one funding outpoint, one step per call: see the module comment for the
 * steps, the states and every check. `value` is an {@link APNTPoolGenesisBuildInputV1}. Refusals: a network the
 * builder does not deploy to is `pool-deployment-network`; malformed or insufficient funding
 * `pool-deploy-funding`; a parameter, fee policy or value below dust `pool-deploy-parameter`; a malformed factory,
 * a factory token below dust, or a factory redeem given before its context `pool-deploy-factory`; a genesis above
 * the 100,000-byte standard transaction size (too many factory tokens, records or copies) `pool-deploy-size`; a signed
 * transaction that is not its step's template, or one too many, `pool-deploy-signed`; and the genesis audit's own
 * code when the built deployment fails it.
 */
export function buildAPNTPoolGenesisV1(value: unknown): APNTPoolGenesisBuildResultV1 {
  try {
    const [clone] = poolBoundary([value]);
    const input = inputOf(clone);
    const genesisBytes = preflight(input);
    poolRequire(input.factoryRedeem === null || input.signed.length >= 3, F.DEPLOY_FACTORY);
    const transactions: APNTPoolGenesisBuiltTransactionV1[] = [];
    const record = (step: Step, decoded: APNTPoolTransactionV1, raw: Uint8Array) => transactions.push(Object.freeze({
      name: step.name, transaction: raw.slice(), txidDisplay32: decoded.txidDisplay32, bytes: raw.length, feeSats: step.feeSats,
    }));

    let spend: Spend = { txidWire32: input.funding.txidWire32, index: input.funding.index, valueSats: input.funding.valueSats };
    const seeds: Spend[] = [];
    for (const position of [0, 1, 2] as const) {
      const step = stepOf(input, APNT_POOL_V1_GENESIS_BUILDER_STEPS[position], [spend], seedOutputsOf(input, position));
      if (input.signed.length === position) return signResult(step, input, position);
      const decoded = acceptSigned(step, input.signed[position]!, input.funding.unlockingBytes);
      record(step, decoded, input.signed[position]!);
      seeds.push({ txidWire32: decoded.txidWire32, index: 0, valueSats: step.outputs[0]!.valueSats });
      if (position < 2) spend = { txidWire32: decoded.txidWire32, index: 1, valueSats: step.outputs[1]!.valueSats };
    }

    const categories: Categories = { verdict: seeds[0]!.txidWire32, range: seeds[1]!.txidWire32, root: seeds[2]!.txidWire32 };
    const covenants = covenantsOf(input, categories);
    const deploymentId32 = deriveAPNTPoolDeploymentIdV1({
      network: input.protocolNetwork,
      verdictCategoryWire32: categories.verdict,
      rangeCategoryWire32: categories.range,
      rootCategoryWire32: categories.root,
      meterCategoryWire32: null,
    });
    if (input.factoryRedeem === null) {
      poolRequire(input.signed.length === 3, F.DEPLOY_SIGNED);
      return Object.freeze({
        valid: true, failureCode: null, state: "factory",
        factoryContext: Object.freeze({
          network: input.protocolNetwork,
          deploymentId32,
          verdictCategoryWire32: categories.verdict.slice() as Bytes32,
          rangeCategoryWire32: categories.range.slice() as Bytes32,
          rootCategoryWire32: categories.root.slice() as Bytes32,
          settlementLockingBytecode: covenants.settlement.lockingBytecode.slice(),
        }),
      });
    }

    const layout = genesisOutputsOf(input, categories, covenants, input.factoryRedeem);
    const genesis = stepOf(input, "genesis", seeds, layout.outputs);
    poolRequire(genesis.signedBytes === genesisBytes, F.SHAPE);
    const artifactFor = (genesisTxidDisplay32: Uint8Array) => artifactOf(input, categories, covenants, deploymentId32, genesisTxidDisplay32, input.factoryRedeem!);
    // Audited before it is handed out for signing, so a genesis the audit would refuse (a factory whose lock is a
    // pool lock, say) is never signed. Unsigned, its id is not the signed one: the artifact names the unsigned id
    // here, and every other check sees exactly the outputs and outpoints that will be signed.
    audited(artifactFor(poolDecodeTransaction(genesis.unsigned).txidDisplay32), genesis.unsigned, deploymentId32);
    if (input.signed.length === 3) return signResult(genesis, input, 3);
    const signedGenesis = input.signed[3]!;
    const decoded = acceptSigned(genesis, signedGenesis, input.funding.unlockingBytes);
    record(genesis, decoded, signedGenesis);
    const artifact = artifactFor(decoded.txidDisplay32);
    const audit = audited(artifact, signedGenesis, deploymentId32);
    const change = layout.outputs.length;
    return Object.freeze({
      valid: true, failureCode: null, state: "complete",
      network: input.network,
      label: APNT_POOL_V1_GENESIS_BUILDER_LABELS[input.network],
      artifact: structuredClone(artifact),
      genesisTransactions: Object.freeze([signedGenesis.slice()]),
      transactions: Object.freeze(transactions),
      genesisOutputs: Object.freeze({
        factoryTokens: Object.freeze(layout.factoryTokens), rangeRecords: Object.freeze(layout.rangeRecords),
        treeUpdate: layout.treeUpdate, rootCopies: Object.freeze(layout.rootCopies), change,
      }),
      remainder: Object.freeze({
        txidDisplay32: decoded.txidDisplay32.slice() as Bytes32, index: change,
        valueSats: genesis.outputs[change]!.valueSats, lockingBytecode: input.funding.lock.slice(),
      }),
      inbox: audit,
    });
  } catch (error) {
    return Object.freeze({ valid: false, failureCode: poolFailureCodeOf(error) });
  }
}
