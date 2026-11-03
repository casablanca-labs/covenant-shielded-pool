import { createVirtualMachineBch2026, encodeTransactionBch, hexToBin, binToHex } from '@bitauth/libauth';
const X = Uint8Array.from({ length: 32 }, (_, i) => (i * 11 + 3) & 0xff); // non-palindromic
const outHash = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 1) & 0xff);
// locking: <0> OP_UTXOTOKENCATEGORY <X||02> OP_EQUAL   (bare, spent at input 0)
const lock = Uint8Array.from([0x00, 0xce, 0x21, ...X, 0x02, 0x87]);
const lockRev = Uint8Array.from([0x00, 0xce, 0x21, ...X.slice().reverse(), 0x02, 0x87]);
const vm = createVirtualMachineBch2026(true);
for (const [name, l] of [['direct', lock], ['reversed', lockRev]]) {
  const tx = { version: 2, locktime: 0, inputs: [{ outpointTransactionHash: outHash, outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: new Uint8Array() }],
    outputs: [{ lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: 0n }] };
  const sourceOutputs = [{ lockingBytecode: l, valueSatoshis: 10000n, token: { category: X, amount: 0n, nft: { capability: 'minting', commitment: new Uint8Array() } } }];
  const st = vm.evaluate({ transaction: tx, sourceOutputs, inputIndex: 0 });
  console.log(name, 'top=', st.stack.length ? binToHex(st.stack.at(-1)) : null, 'error=', st.error ?? null);
}
// wire position of a token category in an encoded output
const tx2 = { version: 2, locktime: 0, inputs: [{ outpointTransactionHash: outHash, outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: new Uint8Array() }],
  outputs: [{ lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: 0n, token: { category: X, amount: 0n, nft: { capability: 'none', commitment: Uint8Array.of(1,2,3) } } }] };
const wire = binToHex(encodeTransactionBch(tx2));
console.log('wire contains X as given:', wire.includes(binToHex(X)), 'reversed:', wire.includes(binToHex(X.slice().reverse())));
console.log('wire contains outpoint as given:', wire.includes(binToHex(outHash)), 'reversed:', wire.includes(binToHex(outHash.slice().reverse())));
