import { PUBLIC_REFERENCE_DOMAIN } from "./public-apnt-pool-v1-recipe.js";

/** Frozen before construction. All labels are deliberately public, nonoperational inputs.
 * No target vectors, wallet state, randomness, environment or scanner result selects them.
 * The old MAIN generator and its output are never invoked or regenerated.
 */
const noteSuffixes = ["ask", "nk", "rho", "rcm", "K", "alpha"];
const outputSuffixes = ["ask", "nk", "K"];
const notePrefixes = ["reference:real-real:in0", "reference:real-real:in1", "reference:real-dummy:in0", "reference:real-dummy:dummy"];
const outputPrefixes = ["reference:real-real:out0", "reference:real-real:out1", "reference:dummy:output0", "reference:dummy:output1"];
const labels = [
  ...["verdict", "range", "root", "meter"].map(k => "reference:category:" + k),
  "reference:verifier-parameters", "reference:withdrawal-lock",
  "reference:real-real:leaf:0", "reference:real-real:leaf:2",
  ...notePrefixes.flatMap(p => noteSuffixes.map(s => p + ":" + s)),
  ...outputPrefixes.flatMap(p => outputSuffixes.map(s => p + ":" + s)),
  "frontier-range:uniform", "frontier-range:fake", "frontier-range:labelA", "frontier-range:labelB",
  "frontier-range:inbox:commitment", "frontier-range:inbox:packet",
  ...Array.from({ length: 64 }, (_, i) => "frontier-range:sequence:" + i),
  ...Array.from({ length: 6 }, (_, i) => "frontier-range:real:" + i),
  ...Array.from({ length: 64 }, (_, i) => Array.from({ length: 4 }, (_, j) => "frontier-range:high:" + i + ":" + j)).flat(),
  "frontier-range:x4:deployment-id", "frontier-range:x4:profile-id",
  ...Array.from({ length: 16 }, (_, i) => ["a", "nf0", "nf1", "rk0", "rk1", "cm0", "cm1"].map(s => "frontier-range:x4:r:" + i + ":" + s)).flat(),
].sort();
if (new Set(labels).size !== labels.length) throw Error("duplicate public input label");
const capacity = 2 ** 32 - 1;
const high = [
  { start: 2 ** 31 - 1, tail: 3 }, { start: capacity - 2, tail: 2 },
  { start: 2 ** 16 - 1, tail: 3 }, { start: 1_000_003, tail: 4 }, { start: capacity - 1, tail: 1 },
  // Exhaust the closed carry-depth categories instead of importing a private start value.
  ...Array.from({ length: 30 }, (_, i) => ({ start: 2 ** (i + 1) - 1, tail: 3 })).filter(v => v.start !== 2 ** 16 - 1),
  ...Array.from({ length: 29 }, (_, i) => ({ start: capacity - 2 ** (i + 3), tail: 3 })),
];
export const PUBLIC_FRONTIER_RANGE_INPUTS = Object.freeze({
  schema: "public-apnt-frontier-range-inputs/1", domain: PUBLIC_REFERENCE_DOMAIN,
  labels: Object.freeze(labels), treeDepth: 32, capacity, sequenceLength: 64,
  high: Object.freeze(high.map(v => Object.freeze(v))),
  overlapStarts: Object.freeze([0, 1_000_003, 2 ** 16 - 1, 2 ** 31 - 1]),
  overlapActions: Object.freeze([1, 2, 4, 8, 16]),
  foldStarts: Object.freeze([
    Object.freeze({ name: "genesis", start: 0 }), Object.freeze({ name: "fits-exactly", start: capacity - 4 }),
    Object.freeze({ name: "capacity-overflow", start: capacity - 3 }), Object.freeze({ name: "odd-start", start: 2 ** 31 - 1 }),
  ]),
  endpointBits: 257, genesisExponents: Object.freeze([0, 1, 2, 3, 9]),
  publicNumericInputs: Object.freeze(["0", "1", "2", "7", "255", "256", "2000", "3000", "1000", "500000", "250000", "600000", "148000", "1234567890123"]),
  legacyParityRecordBytes: 396, legacyParityPaddingByte: 90,
});
