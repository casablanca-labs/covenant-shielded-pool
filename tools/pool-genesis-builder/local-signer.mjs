// ENG-614: a P2PKH signer for LOCAL LEDGER RUNS AND TESTS ONLY. Every key here is SHA-256 of a public label, so
// anyone can spend what it locks: it must never hold value, and it is refused for Chipnet by the deploy adapter.
// A live deployment signs with the operator's key, held only in the main checkout's .local-live/, never here.
import {
  encodeTransactionBch,
  decodeTransactionBch,
  generateSigningSerializationBch,
  hash160,
  hash256,
  secp256k1,
  sha256,
} from "@bitauth/libauth";

export const SIGHASH_ALL_FORKID = 0x41;
/** SIGHASH_ALL|SIGHASH_UTXOS|FORKID: what the wallet's inbox funding signs (ENG-529). */
export const SIGHASH_ALL_UTXOS_FORKID = 0x61;
/** A Schnorr signature push, its sighash byte and a compressed key push: 1 + 64 + 1 + 1 + 33. */
export const P2PKH_SCHNORR_UNLOCKING_BYTES = 100;

const bytesOf = (value) => {
  if (typeof value === "string") throw new Error(value);
  return value;
};

/** A labelled local test key and its P2PKH lock. */
export function localP2pkh(label) {
  const privateKey = sha256.hash(new TextEncoder().encode(`eng614:local:${label}`));
  const publicKey = bytesOf(secp256k1.derivePublicKeyCompressed(privateKey));
  const lockingBytecode = Uint8Array.of(0x76, 0xa9, 0x14, ...hash160(publicKey), 0x88, 0xac);
  return Object.freeze({ label, privateKey, publicKey, lockingBytecode });
}

/**
 * Signs every input of an unsigned transaction whose source outputs are all `key`'s P2PKH lock. `sourceOutputs`
 * are Libauth outputs (`valueSatoshis`); the signature hash covers them.
 */
export function signP2pkh(unsignedTransaction, sourceOutputs, key, sighash = SIGHASH_ALL_FORKID) {
  const transaction = bytesOf(decodeTransactionBch(unsignedTransaction));
  transaction.inputs.forEach((_, inputIndex) => {
    if (Buffer.compare(Buffer.from(sourceOutputs[inputIndex].lockingBytecode), Buffer.from(key.lockingBytecode)) !== 0) throw new Error("local-signer-owner");
    const preimage = generateSigningSerializationBch({ transaction, sourceOutputs, inputIndex }, { coveredBytecode: key.lockingBytecode, signingSerializationType: Uint8Array.of(sighash) });
    const signature = bytesOf(secp256k1.signMessageHashSchnorr(key.privateKey, hash256(preimage)));
    transaction.inputs[inputIndex].unlockingBytecode = Uint8Array.of(65, ...signature, sighash, 33, ...key.publicKey);
  });
  return encodeTransactionBch(transaction);
}

/** Signs a genesis builder step: its source outputs are the step's own. */
export function signBuilderStep(step, key, sighash = SIGHASH_ALL_FORKID) {
  const sourceOutputs = step.sourceOutputs.map((output) => ({ lockingBytecode: output.lockingBytecode, valueSatoshis: output.valueSats }));
  return signP2pkh(step.unsignedTransaction, sourceOutputs, key, sighash);
}
