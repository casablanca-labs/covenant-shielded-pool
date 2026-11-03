// ENG-614: drives the staged genesis builder (packages/protocol-runtime buildAPNTPoolGenesisV1) to its end. The
// caller supplies the signer and the factory; `afterSigned` sees each signed step before the next call (a local
// ledger submits it there), and only after the builder has accepted it. This file holds no key and builds no covenant.
// It does not check what the hook did with a step: a caller that submits must read its ledger back (modules/deploy.mjs
// in tools/pool-action-modules does, before it reports a deployment).
import { buildAPNTPoolGenesisV1 } from "../../packages/protocol-runtime/dist/index.js";

const MAXIMUM_CALLS = 8;

/**
 * `base` is a builder input without `signedTransactions` and with `verifierFactory.redeemBytecode` unset.
 * Returns `{ result, calls, signed }`: `result` is the builder's last result (complete or a refusal), `calls` the
 * state of every call in order.
 *
 * Each signed step goes back to the builder before `afterSigned` sees it: the builder requires it to be its step's
 * template with only the unlocking filled (and audits a signed genesis), so a step it refuses never reaches a ledger
 * or a broadcast. The driver keeps its own copy of the checked bytes, which the signer cannot change after, and the
 * hook gets a copy of that: a hook that writes into its buffer changes nothing the driver builds on.
 */
export async function driveGenesis({ base, sign, factoryRedeem, afterSigned = async () => {}, resumeSigned = [] }) {
  const signed = [];
  const calls = [];
  let redeemBytecode = null;
  const build = (transactions) => {
    const result = buildAPNTPoolGenesisV1({ ...base, verifierFactory: { ...base.verifierFactory, redeemBytecode }, signedTransactions: transactions });
    calls.push(result.valid ? result.state : result.failureCode);
    return result;
  };
  let result = build(signed);
  for (let call = 1; call < MAXIMUM_CALLS; call += 1) {
    if (!result.valid || result.state === "complete") return { result, calls, signed };
    if (result.state === "factory") {
      redeemBytecode = await factoryRedeem(result.factoryContext);
      result = build(signed);
      continue;
    }
    // A preserved signed step is replayed through the builder's exact-template
    // check. It is never sent to the signer or submission hook again.
    const resumed = signed.length < resumeSigned.length;
    const returned = resumed ? resumeSigned[signed.length] : await sign(result.step);
    const raw = returned instanceof Uint8Array ? returned.slice() : returned;
    const next = build([...signed, raw]);
    if (next.valid) {
      if (!resumed) await afterSigned(raw.slice(), result.step);
      signed.push(raw);
    }
    result = next;
  }
  throw new Error("pool-genesis-drive-unfinished");
}
