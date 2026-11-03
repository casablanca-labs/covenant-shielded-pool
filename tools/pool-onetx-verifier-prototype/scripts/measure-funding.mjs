// Research prototype — not reviewed (R-384, ARCH-231).
//
// Every verifier run spends N fresh UTXOs at the graph's N P2SH32 lockings, so someone (the aggregator)
// creates them first. This measures the serialized size of that funding transaction (one P2PKH input,
// N graph outputs, P2PKH change) and of the alternative where the verifier transaction itself re-funds the
// next run's graph (N extra outputs; needs a factory whose change rule admits token-free extra outputs).
// Signature and key bytes are placeholders of the standard lengths (65-byte Schnorr + sighash, 33-byte key):
// this is a size measurement, not a signed transaction.
//
// usage: node measure-funding.mjs GATED_JSON OUT_JSON
import { readFileSync, writeFileSync } from 'node:fs';
import { encodeTransactionBch } from '@bitauth/libauth';

const [gatedPath, outPath] = process.argv.slice(2);
const gated = JSON.parse(readFileSync(gatedPath));
const lockings = gated.steps.map(s => Uint8Array.from(Buffer.from(s.locking, 'hex')));
const p2pkh = Uint8Array.from([0x76, 0xa9, 0x14, ...Array.from({ length: 20 }, (_, i) => (i * 13 + 5) & 0xff), 0x88, 0xac]);
const p2pkhUnlocking = Uint8Array.from([0x41, ...new Uint8Array(65).fill(0x5a), 0x21, 0x02, ...new Uint8Array(32).fill(0x3c)]);
const fundingTx = n => ({ version: 2, locktime: 0,
  inputs: [{ outpointTransactionHash: Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 9) & 0xff), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: p2pkhUnlocking }],
  outputs: [...lockings.slice(0, n).map(l => ({ lockingBytecode: l, valueSatoshis: 10000n })), { lockingBytecode: p2pkh, valueSatoshis: 50000n }] });
const graphOutputs = lockings.reduce((a, l) => a + 8 + 1 + l.length, 0);
const result = {
  graphInputs: lockings.length,
  separateFundingTransactionBytes: encodeTransactionBch(fundingTx(lockings.length)).length,
  graphOutputsBytes: graphOutputs,
  refundInsideVerifierTransactionBytes: graphOutputs,
  note: 'P2PKH funding input with placeholder signature and key of standard lengths; sizes only',
};
writeFileSync(outPath, JSON.stringify(result, null, 1) + '\n');
console.log(JSON.stringify(result));
