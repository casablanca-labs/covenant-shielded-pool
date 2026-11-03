import type { APNTPoolActionWitnessV1, APNTPoolInputWitnessV1, APNTPoolOutputWitnessV1 } from "./apnt_pool_action_relation_v1.js";
import { poolBoundary } from "./apnt_pool_contract_v1.js";
import { bytesToHex as hex } from "./bytes.js";

// The existing action-circuit corpus encoding, shared with live wallet requests.
// No relation, circuit assignment, byte order or committed vector changes.
function inputJson(i: APNTPoolInputWitnessV1) {
  return {
    valueSats: i.valueSats.toString(), spendKey33: hex(i.spendKey33), nullifierKey32: hex(i.nullifierKey32), rho32: hex(i.rho32),
    commitmentRandomness32: hex(i.commitmentRandomness32), recoveryTag32: hex(i.recoveryTag32), rerandomizer: i.rerandomizer.toString(),
    membership: i.membership === null ? null : { position: i.membership.position, siblings: i.membership.siblings32.map(hex) },
  };
}
function outputJson(o: APNTPoolOutputWitnessV1) {
  return {
    valueSats: o.valueSats.toString(), ownerTag32: hex(o.ownerTag32), rho32: hex(o.rho32), recoveryKey32: hex(o.recoveryKey32),
  };
}

/** PRIVATE witness JSON for the revision-3 gnark CorpusWitness decoder.
 * This is encoding, not semantic validation; corpus negatives use it too.
 * Callers releasing live material must first evaluate the host relation.
 */
export function encodeAPNTPoolActionWitnessJsonV1(value: APNTPoolActionWitnessV1) {
  const [witness] = poolBoundary([value]) as [APNTPoolActionWitnessV1];
  return { inputs: witness.inputs.map(inputJson), outputs: witness.outputs.map(outputJson) };
}
