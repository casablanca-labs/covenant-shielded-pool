import { createHash } from "node:crypto";
import { PUBLIC_FRONTIER_RANGE_INPUTS as INPUT } from "./public-apnt-pool-v1-frontier-range-inputs.js";
import { publicReferenceDeploymentContext, buildPublicRelationReferences } from "./public-apnt-pool-v1-frontier-range-context.js";
import { lab as publicLabel } from "./public-apnt-pool-v1-recipe.js";
import { deriveAPNTPoolProfileIdV1, encodeAPNTPoolStatementV1 } from "../src/apnt_pool_statement_v1.js";

/** Independent reference: no frontier/range/migration operation under test is imported.
 * The existing public relation component supplies the unchanged shared statement input;
 * this never calls buildPublicMainReference/buildPublicFixtureSet or reads MAIN.
 * Everything else derives from the frozen public label manifest and protocol dimensions.
 */
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const bytes = (s: string) => Buffer.from(s, "hex");
const join = (...parts: Uint8Array[]) => Buffer.concat(parts);
const hash = (...parts: (Uint8Array | string)[]) => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
};
const tagged = (tag: string, ...parts: Uint8Array[]) => hash("APNT-POOL-v1:" + tag, ...parts);
const le = (n: bigint, width: number) => {
  if (n < 0n || n >= 1n << BigInt(width * 8)) throw Error("reference integer width");
  const b = Buffer.alloc(width);
  for (let i = 0; i < width; i++) { b[i] = Number(n & 255n); n >>= 8n; }
  return b;
};
const int = (b: Uint8Array) => Array.from(b).reduceRight((n, v) => n * 256n + BigInt(v), 0n);
const label = (name: string) => {
  if (!INPUT.labels.includes(name)) throw Error("undeclared public input label");
  return hash(INPUT.domain + ":" + name);
};
const node = (left: Uint8Array, right: Uint8Array) => tagged("node", left, right);
const Z = [Buffer.alloc(32)];
for (let h = 0; h < INPUT.treeDepth; h++) Z.push(node(Z[h]!, Z[h]!));
type Frontier = { n: number; entries: Uint8Array[] };
const empty = (): Frontier => ({ n: 0, entries: Array.from({ length: 32 }, () => Buffer.alloc(32)) });
const state = (f: Frontier) => join(le(BigInt(f.n), 8), ...f.entries);
const frontierHash = (f: Frontier) => tagged("frontier", state(f));
function root(f: Frontier) {
  let value: Uint8Array = Z[0]!, bits = BigInt(f.n);
  for (let h = 0; h < 32; h++, bits >>= 1n)
    value = bits & 1n ? node(f.entries[h]!, value) : node(value, Z[h]!);
  return value;
}
const commitment = (f: Frontier) => join(le(BigInt(f.n), 8), frontierHash(f), root(f));
function append(f: Frontier, leaf: Uint8Array): Frontier {
  if (f.n === INPUT.capacity) throw Error("public-reference-capacity");
  const entries = f.entries.slice();
  let carry = leaf, h = 0, index = BigInt(f.n);
  for (; index & 1n; index >>= 1n, h++) carry = node(entries[h]!, carry);
  entries[h] = carry;
  return { n: f.n + 1, entries };
}
const appendAll = (f: Frontier, leaves: Uint8Array[]) => leaves.reduce(append, f);
const row = (f: Frontier) => ({ leafCount: f.n, frontierHash: hex(frontierHash(f)), root: hex(root(f)) });
function naiveRoot(leaves: Uint8Array[]) {
  let level = leaves.slice();
  for (let h = 0; h < 32; h++) {
    if (!level.length) return Z[32]!;
    if (level.length % 2) level.push(Z[h]!);
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(node(level[i]!, level[i + 1]!));
    level = next;
  }
  return level[0]!;
}
function uniform(n: number): Frontier {
  const levels = [label("frontier-range:uniform")];
  for (let h = 0; h < 31; h++) levels.push(node(levels[h]!, levels[h]!));
  return { n, entries: levels.map((u, h) => 2 ** h <= n ? u : Buffer.alloc(32)) };
}
export function buildPublicParityStatement(actions: number) {
  if (!Number.isInteger(actions) || actions < 1 || actions > 16) throw Error("public parity action count");
  const l = (s: string) => label("frontier-range:x4:" + s);
  const records = Array.from({ length: actions }, (_, k) => join(
    l("r:" + k + ":a"), l("r:" + k + ":nf0"), l("r:" + k + ":nf1"), Buffer.from([2]), l("r:" + k + ":rk0"),
    Buffer.from([3]), l("r:" + k + ":rk1"), l("r:" + k + ":cm0"), l("r:" + k + ":cm1"),
    Buffer.alloc(114, INPUT.legacyParityPaddingByte), le(0n, 8), le(0n, 8), le(2000n, 8), Buffer.alloc(32)));
  return join(Buffer.from("APNT-POOL-v1:statement"), l("deployment-id"), l("profile-id"), le(BigInt(actions), 2), ...records);
}
function publicStatement() {
  const { dep } = publicReferenceDeploymentContext();
  const { pair, dummy } = buildPublicRelationReferences(dep);
  const profile = deriveAPNTPoolProfileIdV1({ systemId: 1, verifierParameters: publicLabel("reference:verifier-parameters") });
  const records = [pair.record, dummy.record];
  return { dep, records, statement: encodeAPNTPoolStatementV1({ deploymentId32: dep, profileId32: profile, records }) };
}
function buildFrontier(shared: ReturnType<typeof publicStatement>) {
  const leaves = Array.from({ length: INPUT.sequenceLength }, (_, i) => label("frontier-range:sequence:" + i));
  let f = empty();
  const steps = leaves.map((leaf, i) => {
    f = append(f, leaf);
    if (hex(root(f)) !== hex(naiveRoot(leaves.slice(0, i + 1)))) throw Error("independent dense-tree disagreement");
    return row(f);
  });
  const two = appendAll(empty(), leaves.slice(0, 2)), cleaned = { ...two, entries: [Buffer.alloc(32), ...two.entries.slice(1)] };
  const high = INPUT.high.map((spec, index) => {
    let prior = uniform(spec.start);
    const rows = [row(prior)], carries: number[] = [];
    const tail = Array.from({ length: spec.tail }, (_, i) => label("frontier-range:high:" + index + ":" + i));
    for (const leaf of tail) {
      let n = prior.n, count = 0;
      while (n % 2) { count++; n = Math.floor(n / 2); }
      carries.push(count); prior = append(prior, leaf); rows.push(row(prior));
    }
    return { startLeafCount: spec.start, tail: tail.map(hex), rows, carries, fullAfterTail: prior.n === INPUT.capacity };
  });
  const statementLeaves = Array.from({ length: 2 }, (_, k) => 88 + 314 * k)
    .flatMap(at => [shared.statement.slice(at + 162, at + 194), shared.statement.slice(at + 194, at + 226)]);
  const cases = INPUT.foldStarts.map(spec => {
    const prior = uniform(spec.start), refused = spec.start + statementLeaves.length > INPUT.capacity;
    return { name: spec.name, priorFrontierState: hex(state(prior)), priorCommitment: hex(commitment(prior)), refused,
      ...(refused ? {} : { nextCommitment: hex(commitment(appendAll(prior, statementLeaves))) }) };
  });
  const x4leaves = Array.from({ length: 16 }, (_, k) => [0, 1].map(s => label("frontier-range:x4:r:" + k + ":cm" + s))).flat();
  const starts = [...INPUT.overlapStarts, INPUT.capacity - 1];
  const frontiersByStartLeafCount = Object.fromEntries(starts.map(n => [n, hex(state(uniform(n)).subarray(8))]));
  const overlapCases = INPUT.overlapActions.flatMap(actions => INPUT.overlapStarts.map(startLeafCount => {
    const prior = uniform(startLeafCount), next = appendAll(prior, x4leaves.slice(0, actions * 2)), statement = buildPublicParityStatement(actions);
    return { actions, leafCount: actions * 2, startLeafCount, oldFrontierHash: hex(frontierHash(prior)),
      expectedRoot: hex(root(next)), expectedFrontierHash: hex(frontierHash(next)), statementSha256: hex(hash(statement)), statementLength: statement.length };
  }));
  const nearFull = uniform(INPUT.capacity - 1), full = append(nearFull, x4leaves[0]!);
  const realLeaves = Array.from({ length: 6 }, (_, i) => label("frontier-range:real:" + i)), fake = label("frontier-range:fake");
  const inbox = (dep: Uint8Array, cm: Uint8Array, packet: Uint8Array, amount: bigint) => {
    const preimage = join(dep, cm, hash(packet), le(amount, 8));
    return { successorDeploymentId: hex(dep), commitment: hex(cm), packet: hex(packet), amountSats: amount.toString(), preimage: hex(preimage), h: hex(tagged("migrate", preimage)) };
  };
  const record = shared.records[0]!;
  return { description: "New deliberately public nonoperational frontier and migration references; independent SHA-256/integer construction.",
    publicReferenceDomain: INPUT.domain,
    reference: { uniformLeaf: hex(label("frontier-range:uniform")),
      genesis: { ...row(empty()), commitment: hex(commitment(empty())) },
      sequence: { leaves: leaves.map(hex), steps, staleEntryAfterTwo: { frontier: hex(state(two).subarray(8)), root: hex(root(two)), frontierHash: hex(frontierHash(two)), cleanedFrontierHash: hex(frontierHash(cleaned)) } },
      high, fold: { leaves: statementLeaves.map(hex), cases },
      inbox: { synthetic: inbox(shared.dep, label("frontier-range:inbox:commitment"), label("frontier-range:inbox:packet").subarray(0, 16), 1234567890123n),
        referenceRecord0: inbox(shared.dep, record.slice(162, 194), record.slice(226, 242), int(record.slice(258, 266))) } },
    overlap: { x4: { leavesOfSixteenActions: x4leaves.map(hex), frontiersByStartLeafCount, cases: overlapCases,
      capacityCase: { startLeafCount: nearFull.n, oldFrontierHash: hex(frontierHash(nearFull)), expectedRoot: hex(root(full)), expectedFrontierHash: hex(frontierHash(full)), statementSha256: hex(hash(buildPublicParityStatement(1))) } },
      x6: { realLeaves: realLeaves.map(hex), R1: hex(naiveRoot(realLeaves.slice(0, 2))), R2: hex(naiveRoot(realLeaves.slice(0, 4))), R3: hex(naiveRoot(realLeaves)),
        fakeCommitment: hex(fake), fakeRoot: hex(naiveRoot([fake])), emptyRootZ32: hex(Z[32]!) } } };
}
function buildRange(shared: ReturnType<typeof publicStatement>) {
  const E = 1n << 257n, boundary = 255n << 248n;
  const endpoint = (v: bigint) => le(v, 33), record = (lo: bigint, hi: bigint) => join(endpoint(lo), endpoint(hi));
  const key = (nf: Uint8Array) => 2n * int(nf) + 1n;
  const nf = (v: bigint) => le(v, 32);
  const genesis = (g: number) => Array.from({ length: 2 ** g }, (_, i) => record(BigInt(i) * (E >> BigInt(g)), BigInt(i + 1) * (E >> BigInt(g))));
  const keys = [
    ["zero", nf(0n)], ["one", nf(1n)], ["maximum", nf((1n << 256n) - 1n)],
    ["labelA", label("frontier-range:labelA")], ["labelB", label("frontier-range:labelB")],
    ["boundary255MinusOne", nf((boundary - 2n) / 2n)], ["boundary255PlusOne", nf(boundary / 2n)], ["middle", nf(1n << 255n)],
  ] as const;
  const G9 = genesis(9), nullifiers = Array.from({ length: 2 }, (_, k) => 88 + 314 * k)
    .flatMap(at => [shared.statement.slice(at + 32, at + 64), shared.statement.slice(at + 64, at + 96)]);
  const split = (r: Uint8Array, n: Uint8Array) => [record(int(r.slice(0, 33)), key(n)), record(key(n), int(r.slice(33)))];
  const named = (name: string) => keys.find(v => v[0] === name)![1];
  const containing = (n: Uint8Array) => G9[Number(key(n) / (E >> 9n))]!;
  const splitInputs = [keys[0]![1], keys[2]![1], named("boundary255MinusOne"), named("boundary255PlusOne"), named("labelA")];
  const splits = [...splitInputs.map(n => ({ r: containing(n), n })), { r: record(0n, E), n: named("labelA") }]
    .map(({ r, n }) => ({ record66: hex(r), nullifier: hex(n), left66: hex(split(r, n)[0]!), right66: hex(split(r, n)[1]!) }));
  const a = named("labelA"), ka = key(a), little = Number(ka / (E >> 9n)), big = Number(key(Buffer.from(a).reverse()) / (E >> 9n));
  const notContained = [[record(ka, E), a], [record(0n, ka), a], [record(0n, 1n), a], [G9[big]!, a]]
    .map(([r, n]) => ({ record66: hex(r!), nullifier: hex(n!) }));
  const byGenesis = Object.fromEntries(INPUT.genesisExponents.map(g => {
    const records = genesis(g), indices = nullifiers.map(n => Number(key(n) / (E >> BigInt(g)))), distinct = new Set(indices).size === indices.length;
    const spent = indices.map(i => records[i]!);
    return ["g" + g, { pairwiseDistinct: distinct, recordIndices: indices,
      ...(distinct ? { spentRecords66: spent.map(hex), createdRecords66: spent.flatMap((r, i) => split(r, nullifiers[i]!)).map(hex) } : {}) }];
  }));
  return { description: "New deliberately public nonoperational range references; independent exact little-endian arithmetic.", publicReferenceDomain: INPUT.domain,
    reference: { endpointMaximum: E.toString(), endpoints: [0n, 1n, 2n, 255n, 256n, (1n << 64n) - 1n, 1n << 128n, (1n << 256n) - 1n, 1n << 256n, E].map(value => ({ value: value.toString(), bytes33: hex(endpoint(value)) })),
      keys: keys.map(([name, n]) => ({ name, nullifier: hex(n), key: key(n).toString(), key33: hex(endpoint(key(n))) })),
      genesis: { g0: genesis(0).map(hex), g1: genesis(1).map(hex), g3: genesis(3).map(hex), g9: { count: G9.length, sha256OfConcatenation: hex(hash(join(...G9))), first: hex(G9[0]!), record255: hex(G9[255]!), last: hex(G9[511]!) } },
      splits, notContained, byteOrder: { nullifier: hex(a), littleEndianRecord: little, bigEndianRecord: big, bigEndianRecord66: hex(G9[big]!) },
      statementInsertion: { nullifiers: nullifiers.map(hex), byGenesis } } };
}
export function buildPublicFrontierRange() {
  const shared = publicStatement();
  return { frontier: buildFrontier(shared), range: buildRange(shared) };
}
export const serializePublicFrontierRange = (value: unknown) => JSON.stringify(value, null, 2) + "\n";
