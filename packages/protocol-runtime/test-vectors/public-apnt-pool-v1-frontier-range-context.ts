// Exact additive extraction of the two existing public context constructors.
// The frozen MAIN/reference-core file is unchanged and is not in this closure.
import { encodePublicWitness, bindHex, bindHexSlice } from "./public-apnt-pool-v1-origin.js";
import { decodeAPNTPoolActionRecordV1, deriveAPNTPoolActionAuthorizationDigestV1, deriveAPNTPoolAuthorizationSignedHashV1 } from "../src/apnt_pool_action_record_v1.js";
import { deriveAPNTPoolDeploymentIdV1 } from "../src/apnt_pool_statement_v1.js";
import { hex, lab, makeOutput } from "./public-apnt-pool-v1-recipe.js";
import { honestPair, realAndDummy, derive } from "./public-apnt-pool-v1-corpus-helpers.js";

export function publicReferenceDeploymentContext() {
  const categories = { verdict: lab("reference:category:verdict"), range: lab("reference:category:range"), root: lab("reference:category:root"), meter: lab("reference:category:meter") };
  const deployment = (network: string, meter: Uint8Array | null, display = false) => deriveAPNTPoolDeploymentIdV1({
    network,
    verdictCategoryWire32: display ? Uint8Array.from(categories.verdict).reverse() : categories.verdict,
    rangeCategoryWire32: display ? Uint8Array.from(categories.range).reverse() : categories.range,
    rootCategoryWire32: display ? Uint8Array.from(categories.root).reverse() : categories.root,
    meterCategoryWire32: meter,
  });
  const dep = deployment("chipnet", categories.meter);
  return {categories,deployment,dep};
}

export function buildPublicRelationReferences(dep:Uint8Array) {
  const pair = honestPair("reference:real-real");
  const context = decodeAPNTPoolActionRecordV1(pair.record);
  // Both nonzero public deposit and withdrawal are required by the preserved case families.
  pair.record = derive(context.anchor32,pair.witness,{deposit:context.depositSats+7n,withdrawal:context.withdrawalSats+7n,fee:context.feeSats,wlock:lab("reference:withdrawal-lock")});
  const dummy = realAndDummy("reference:real-dummy", 3000n, (input, empty) => [
    makeOutput("reference:dummy:output0", 1000n, input.nullifier32),
    makeOutput("reference:dummy:output1", 0n, empty.nullifier32),
  ]);
  const relation = [pair, dummy].map((action, index) => {
    const record = decodeAPNTPoolActionRecordV1(action.record);
    const ad = deriveAPNTPoolActionAuthorizationDigestV1(dep, action.record);
    const result = {
      name: index === 0 ? "fresh-real-real-deposit-withdrawal" : "fresh-real-dummy-dummy-output",
      anchor: hex(record.anchor32), witness: encodePublicWitness(action.witness),
      depositSats: record.depositSats.toString(), withdrawalSats: record.withdrawalSats.toString(),
      feeSats: record.feeSats.toString(), withdrawalLockHash32: hex(record.withdrawalLockHash32),
      record: hex(action.record), ad: hex(ad), signedHash: hex(deriveAPNTPoolAuthorizationSignedHashV1(ad)),
    };
    bindHex(result,["record"],action.record);
    bindHexSlice(result,["withdrawalLockHash32"],action.record,282,32);
    return result;
  });
  return {pair,dummy,relation};
}
