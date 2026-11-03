// The local ledger's state machine for the ARCH-267 multi-party simulation gate.
//
// It is the chain the simulated parties read: a regtest-proof-of-work block
// chain with a UTXO set, a mempool and heights. A raw transaction enters the
// mempool only when every rule below holds, checked in this order, refusing
// with the first failing rule's code:
//
//   decode          libauth decodes it and re-encodes it to the same bytes
//   coinbase        it is not a coinbase
//   known           its txid is not already confirmed or in the mempool
//   inputs          no outpoint repeats, each resolves to an unspent output
//                   (confirmed, or a mempool output) no mempool transaction spends
//   maturity        a coinbase output is spent only 100 blocks after it
//   final           nLockTime is final at the next height and median time past
//   bip68           each version >= 2 input's relative lock (BIP68) has matured
//                   at the next block: the VM cannot see the spent output's age
//   value           the inputs cover the outputs
//   vm-standard     libauth's BCH 2026 VM, standard mode, verifies it
//   vm-consensus    libauth's BCH 2026 VM, consensus (nonstandard) mode, verifies it
//
// Mining is explicit (`mine`), deterministic, and orders a block's
// transactions canonically (CTOR, ascending txid) after its coinbase.
//
// What this is not: it does not run BCHN's policy beyond libauth's standard
// VM (no mempool size or fee policy, no ancestor limits, no RBF), it has no
// peer-to-peer layer, no reorganisations and no difficulty adjustment. A
// transaction it accepts is locally valid in both libauth 2026 VMs: that is
// necessary for chain validity, never sufficient.

import {
  binToHex,
  createVirtualMachineBch2026,
  decodeTransaction,
  encodeTransaction,
  hash256,
  hexToBin,
  sha256,
} from "@bitauth/libauth";

export const LEDGER_FAILURE = Object.freeze({
  DECODE: "ledger-decode",
  COINBASE: "ledger-coinbase",
  KNOWN: "ledger-known",
  DUPLICATE_INPUT: "ledger-duplicate-input",
  MISSING_INPUT: "ledger-missing-input",
  MEMPOOL_CONFLICT: "ledger-mempool-conflict",
  MATURITY: "ledger-coinbase-maturity",
  NON_FINAL: "ledger-non-final",
  BIP68: "ledger-bip68-immature",
  VALUE: "ledger-value",
  VM_STANDARD: "ledger-vm-standard",
  VM_CONSENSUS: "ledger-vm-consensus",
});

export const REGTEST_BITS = 0x207fffff;
const REGTEST_TARGET = 0x7fffffn << 232n;
export const COINBASE_MATURITY = 100;
const SEQUENCE_FINAL = 0xffffffff;
const SEQUENCE_DISABLE_FLAG = 1 << 31;
const SEQUENCE_TYPE_FLAG = 1 << 22;
const SEQUENCE_MASK = 0x0000ffff;
const LOCKTIME_THRESHOLD = 500_000_000;
const BLOCK_SPACING_SECONDS = 600;

const reverse = (bytes) => Uint8Array.from(bytes).reverse();
const displayHex = (wire) => binToHex(reverse(wire));
const u32le = (value) => {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value >>> 0, true);
  return out;
};
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};
const outpointKey = (txidDisplayHex, index) => `${txidDisplayHex}:${String(index)}`;
const isCoinbaseInput = (input) => input.outpointIndex === SEQUENCE_FINAL && input.outpointTransactionHash.every((b) => b === 0);

/** Electrum's script hash: SHA-256 of the locking bytecode, byte-reversed, hex. */
export const electrumScripthash = (lockingBytecode) => displayHex(sha256.hash(lockingBytecode));

function merkleRootWire(txidsWire) {
  let level = txidsWire.slice();
  if (level.length === 0) throw new Error("empty block");
  while (level.length > 1) {
    if (level.length % 2 === 1) level.push(level[level.length - 1]);
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(hash256(concat(level[i], level[i + 1])));
    level = next;
  }
  return level[0];
}

/** Electrum's merkle branch for position `pos`: display-order hex siblings, deepest first. */
function merkleBranchDisplay(txidsWire, pos) {
  const branch = [];
  let level = txidsWire.slice();
  let index = pos;
  while (level.length > 1) {
    if (level.length % 2 === 1) level.push(level[level.length - 1]);
    branch.push(displayHex(level[index ^ 1]));
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(hash256(concat(level[i], level[i + 1])));
    level = next;
    index >>= 1;
  }
  return branch;
}

function headerBytes({ version, prevWire, merkleWire, time, bits, nonce }) {
  return concat(u32le(version), prevWire, merkleWire, u32le(time), u32le(bits), u32le(nonce));
}

function workOk(header) {
  return BigInt(`0x${displayHex(hash256(header))}`) <= REGTEST_TARGET;
}

/** The minimal push of a block height, as BIP34 puts it first in a coinbase. */
function heightPush(height) {
  if (height === 0) return Uint8Array.of(0x00);
  const bytes = [];
  let h = height;
  while (h > 0) { bytes.push(h & 0xff); h >>= 8; }
  if ((bytes[bytes.length - 1] & 0x80) !== 0) bytes.push(0);
  return Uint8Array.of(bytes.length, ...bytes);
}

export class LocalLedger {
  /**
   * @param {{ premine: {lockingBytecode: Uint8Array, valueSatoshis: bigint}[], minerLockingBytecode: Uint8Array, genesisTime?: number }} config
   */
  constructor(config) {
    if (!Array.isArray(config.premine) || config.premine.length === 0) throw new Error("premine required");
    this.premine = config.premine.map((o) => ({ lockingBytecode: o.lockingBytecode.slice(), valueSatoshis: BigInt(o.valueSatoshis) }));
    this.minerLock = config.minerLockingBytecode.slice();
    this.genesisTime = config.genesisTime ?? 1_700_000_000;
    this.standardVm = createVirtualMachineBch2026(true);
    this.consensusVm = createVirtualMachineBch2026(false);
    /** @type {{height:number, header:Uint8Array, hashDisplay:string, time:number, txids:string[], txidsWire:Uint8Array[]}[]} */
    this.blocks = [];
    /** txid (display hex) -> { raw, tx, height|null, pos|null } */
    this.transactions = new Map();
    /** outpoint key -> { output, height|null, coinbase, spentBy|null } for every output ever created */
    this.outputs = new Map();
    /** txids in the mempool, in arrival order */
    this.mempool = [];
    /** scripthash -> Set(txid) */
    this.scriptHistory = new Map();
    this.mineGenesisAndPremine();
  }

  get tip() {
    const block = this.blocks[this.blocks.length - 1];
    return { height: block.height, hashDisplay: block.hashDisplay, header: block.header };
  }

  medianTimePast(height) {
    const times = [];
    for (let h = Math.max(0, height - 10); h <= height; h += 1) times.push(this.blocks[h].time);
    times.sort((a, b) => a - b);
    return times[Math.floor(times.length / 2)];
  }

  coinbaseTransaction(height, outputs) {
    return {
      version: 1,
      locktime: 0,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: SEQUENCE_FINAL, sequenceNumber: SEQUENCE_FINAL, unlockingBytecode: concat(heightPush(height), Uint8Array.of(0x04), new TextEncoder().encode("ARCH")) }],
      outputs,
    };
  }

  mineGenesisAndPremine() {
    this.mineBlock([{ lockingBytecode: this.minerLock, valueSatoshis: 50_0000_0000n }], { spendableCoinbase: false });
    this.mineBlock(this.premine, { spendableCoinbase: true });
    for (let i = 0; i < COINBASE_MATURITY; i += 1) this.mineBlock([{ lockingBytecode: this.minerLock, valueSatoshis: 50_0000_0000n }], { spendableCoinbase: true });
  }

  /** Mines `count` blocks, each holding the whole mempool (the first) or nothing; returns their display hashes. */
  mine(count = 1) {
    const hashes = [];
    for (let i = 0; i < count; i += 1) {
      hashes.push(this.mineBlock([{ lockingBytecode: this.minerLock, valueSatoshis: 50_0000_0000n }], { spendableCoinbase: true }));
    }
    return hashes;
  }

  mineBlock(coinbaseOutputs, { spendableCoinbase }) {
    const height = this.blocks.length;
    const coinbase = encodeTransaction(this.coinbaseTransaction(height, coinbaseOutputs));
    const coinbaseTxid = displayHex(hash256(coinbase));
    const included = this.mempool.slice().sort();
    const txids = [coinbaseTxid, ...included];
    const txidsWire = txids.map((t) => reverse(hexToBin(t)));
    const prevWire = height === 0 ? new Uint8Array(32) : reverse(hexToBin(this.blocks[height - 1].hashDisplay));
    const time = this.genesisTime + BLOCK_SPACING_SECONDS * height;
    const merkleWire = merkleRootWire(txidsWire);
    let nonce = 0;
    let header = headerBytes({ version: 0x20000000, prevWire, merkleWire, time, bits: REGTEST_BITS, nonce });
    while (!workOk(header)) {
      nonce += 1;
      header = headerBytes({ version: 0x20000000, prevWire, merkleWire, time, bits: REGTEST_BITS, nonce });
    }
    const hashDisplay = displayHex(hash256(header));
    this.blocks.push({ height, header, hashDisplay, time, txids, txidsWire });
    const coinbaseTx = decodeTransaction(coinbase);
    this.transactions.set(coinbaseTxid, { raw: coinbase, tx: coinbaseTx, height, pos: 0 });
    if (spendableCoinbase) this.indexOutputs(coinbaseTxid, coinbaseTx, height, true);
    included.forEach((txid, i) => {
      const entry = this.transactions.get(txid);
      entry.height = height;
      entry.pos = i + 1;
      for (let vout = 0; vout < entry.tx.outputs.length; vout += 1) this.outputs.get(outpointKey(txid, vout)).height = height;
    });
    this.mempool = [];
    return hashDisplay;
  }

  indexOutputs(txid, tx, height, coinbase) {
    tx.outputs.forEach((output, vout) => {
      this.outputs.set(outpointKey(txid, vout), { output, height, coinbase, spentBy: null });
      this.noteScript(output.lockingBytecode, txid);
    });
  }

  noteScript(lockingBytecode, txid) {
    const key = electrumScripthash(lockingBytecode);
    if (!this.scriptHistory.has(key)) this.scriptHistory.set(key, new Set());
    this.scriptHistory.get(key).add(txid);
  }

  /** Isolated so a test subclass can remove only this rule as a firing control. */
  bip68Failure(tx, input, coinHeight, nextHeight, tipMtp, index) {
    if (tx.version < 2 || (input.sequenceNumber & SEQUENCE_DISABLE_FLAG) !== 0) return null;
    const lock = input.sequenceNumber & SEQUENCE_MASK;
    if ((input.sequenceNumber & SEQUENCE_TYPE_FLAG) !== 0) {
      const coinMtp = this.medianTimePast(Math.max(0, coinHeight - 1));
      const minTime = coinMtp + (lock << 9) - 1;
      return tipMtp > minTime ? null : `input ${String(index)}: time lock ${String(lock << 9)} s`;
    }
    const minHeight = coinHeight + lock - 1;
    return nextHeight > minHeight ? null : `input ${String(index)}: ${String(lock)} blocks, coin at ${String(coinHeight)}, next block ${String(nextHeight)}`;
  }

  /** Checks every rule and, if all hold, admits the transaction to the mempool. */
  submit(raw) {
    const refuse = (code, detail) => Object.freeze({ accepted: false, code, detail });
    const tx = decodeTransaction(raw);
    if (typeof tx === "string") return refuse(LEDGER_FAILURE.DECODE, tx);
    if (binToHex(encodeTransaction(tx)) !== binToHex(raw)) return refuse(LEDGER_FAILURE.DECODE, "non-canonical encoding");
    if (tx.inputs.some(isCoinbaseInput)) return refuse(LEDGER_FAILURE.COINBASE, "coinbase transactions are mined, not submitted");
    const txid = displayHex(hash256(raw));
    if (this.transactions.has(txid)) return refuse(LEDGER_FAILURE.KNOWN, txid);

    const nextHeight = this.tip.height + 1;
    const tipMtp = this.medianTimePast(this.tip.height);
    const seen = new Set();
    const sourceOutputs = [];
    for (const [i, input] of tx.inputs.entries()) {
      // libauth's outpoint hash is display order (the codec reverses it on the wire).
      const key = outpointKey(binToHex(input.outpointTransactionHash), input.outpointIndex);
      if (seen.has(key)) return refuse(LEDGER_FAILURE.DUPLICATE_INPUT, `input ${String(i)}`);
      seen.add(key);
      const coin = this.outputs.get(key);
      if (coin === undefined) return refuse(LEDGER_FAILURE.MISSING_INPUT, `input ${String(i)} spends ${key}`);
      if (coin.spentBy !== null) {
        const spender = this.transactions.get(coin.spentBy);
        return refuse(spender.height === null ? LEDGER_FAILURE.MEMPOOL_CONFLICT : LEDGER_FAILURE.MISSING_INPUT, `input ${String(i)} spends ${key}, already spent by ${coin.spentBy}`);
      }
      const coinHeight = coin.height ?? nextHeight;
      if (coin.coinbase && nextHeight - coinHeight < COINBASE_MATURITY) return refuse(LEDGER_FAILURE.MATURITY, `input ${String(i)}`);
      const relativeLockFailure = this.bip68Failure(tx, input, coinHeight, nextHeight, tipMtp, i);
      if (relativeLockFailure !== null) return refuse(LEDGER_FAILURE.BIP68, relativeLockFailure);
      sourceOutputs.push(coin.output);
    }
    if (tx.locktime !== 0 && tx.inputs.some((input) => input.sequenceNumber !== SEQUENCE_FINAL)) {
      const final = tx.locktime < LOCKTIME_THRESHOLD ? tx.locktime < nextHeight : tx.locktime < tipMtp;
      if (!final) return refuse(LEDGER_FAILURE.NON_FINAL, `locktime ${String(tx.locktime)}`);
    }
    const inTotal = sourceOutputs.reduce((n, o) => n + o.valueSatoshis, 0n);
    const outTotal = tx.outputs.reduce((n, o) => n + o.valueSatoshis, 0n);
    if (outTotal > inTotal) return refuse(LEDGER_FAILURE.VALUE, `outputs ${String(outTotal)} exceed inputs ${String(inTotal)}`);
    const standard = this.standardVm.verify({ sourceOutputs, transaction: tx });
    if (standard !== true) return refuse(LEDGER_FAILURE.VM_STANDARD, String(standard));
    const consensus = this.consensusVm.verify({ sourceOutputs, transaction: tx });
    if (consensus !== true) return refuse(LEDGER_FAILURE.VM_CONSENSUS, String(consensus));

    this.transactions.set(txid, { raw: raw.slice(), tx, height: null, pos: null });
    this.mempool.push(txid);
    for (const input of tx.inputs) {
      const key = outpointKey(binToHex(input.outpointTransactionHash), input.outpointIndex);
      const coin = this.outputs.get(key);
      coin.spentBy = txid;
      this.noteScript(coin.output.lockingBytecode, txid);
    }
    this.indexOutputs(txid, tx, null, false);
    return Object.freeze({ accepted: true, txid, standard: true, consensus: true });
  }

  // ---- Electrum-shaped reads -------------------------------------------------

  transaction(txid) {
    return this.transactions.get(txid);
  }

  headerAt(height) {
    return this.blocks[height]?.header;
  }

  merkle(txid) {
    const entry = this.transactions.get(txid);
    if (entry === undefined || entry.height === null) return undefined;
    const block = this.blocks[entry.height];
    return { block_height: entry.height, pos: entry.pos, merkle: merkleBranchDisplay(block.txidsWire, entry.pos) };
  }

  idFromPos(height, pos) {
    return this.blocks[height]?.txids[pos];
  }

  /** Electrum history: confirmed by (height, position), then the mempool (height 0, or −1 with an unconfirmed parent). */
  history(scripthash) {
    const txids = [...(this.scriptHistory.get(scripthash) ?? [])];
    const confirmed = [];
    const pending = [];
    for (const txid of txids) {
      const entry = this.transactions.get(txid);
      if (entry.height !== null) {
        confirmed.push({ tx_hash: txid, height: entry.height, pos: entry.pos });
      } else {
        const unconfirmedParent = entry.tx.inputs.some((input) => this.transactions.get(binToHex(input.outpointTransactionHash))?.height === null);
        pending.push({ tx_hash: txid, height: unconfirmedParent ? -1 : 0 });
      }
    }
    confirmed.sort((a, b) => a.height - b.height || a.pos - b.pos);
    return [...confirmed.map(({ tx_hash, height }) => ({ tx_hash, height })), ...pending];
  }

  /** Electrum status commits to the same ordered history returned by get_history. */
  historyStatus(scripthash) {
    const history = this.history(scripthash);
    if (history.length === 0) return null;
    const text = history.map(({ tx_hash, height }) => `${tx_hash}:${String(height)}:`).join("");
    return binToHex(sha256.hash(new TextEncoder().encode(text)));
  }

  listUnspent(scripthash, tokenFilter = "include_tokens") {
    const out = [];
    for (const txid of this.scriptHistory.get(scripthash) ?? []) {
      const entry = this.transactions.get(txid);
      entry.tx.outputs.forEach((output, vout) => {
        const coin = this.outputs.get(outpointKey(txid, vout));
        if (coin === undefined || coin.spentBy !== null) return;
        if (electrumScripthash(output.lockingBytecode) !== scripthash) return;
        const hasToken = output.token !== undefined;
        if (tokenFilter === "exclude_tokens" && hasToken) return;
        if (tokenFilter === "tokens_only" && !hasToken) return;
        out.push({ tx_hash: txid, tx_pos: vout, height: coin.height ?? 0, value: Number(output.valueSatoshis), ...(hasToken ? { token_data: tokenData(output.token) } : {}) });
      });
    }
    out.sort((a, b) => (a.height || Infinity) - (b.height || Infinity) || a.tx_hash.localeCompare(b.tx_hash, "en") || a.tx_pos - b.tx_pos);
    return out;
  }

  utxoInfo(txid, vout) {
    const coin = this.outputs.get(outpointKey(txid, vout));
    if (coin === undefined || coin.spentBy !== null) return null;
    return {
      ...(coin.height === null ? {} : { confirmed_height: coin.height }),
      scripthash: electrumScripthash(coin.output.lockingBytecode),
      value: Number(coin.output.valueSatoshis),
      ...(coin.output.token === undefined ? {} : { token_data: tokenData(coin.output.token) }),
    };
  }

  /** Every block and the mempool, raw: the ledger bytes the disclosure checker scans. */
  dump() {
    return {
      blocks: this.blocks.map((b) => ({
        height: b.height,
        hash: b.hashDisplay,
        header: binToHex(b.header),
        transactions: b.txids.map((t) => binToHex(this.transactions.get(t).raw)),
      })),
      mempool: this.mempool.map((t) => binToHex(this.transactions.get(t).raw)),
    };
  }
}

export function tokenData(token) {
  return {
    category: binToHex(token.category),
    amount: token.amount.toString(10),
    ...(token.nft === undefined ? {} : { nft: { capability: token.nft.capability, commitment: binToHex(token.nft.commitment) } }),
  };
}

/** A BCHN/Fulcrum-shaped verbose transaction. */
export function verboseTransaction(ledger, txid) {
  const entry = ledger.transaction(txid);
  if (entry === undefined) return undefined;
  const { tx, raw } = entry;
  const confirmed = entry.height !== null;
  return {
    txid,
    hash: txid,
    hex: binToHex(raw),
    size: raw.length,
    version: tx.version,
    locktime: tx.locktime,
    vin: tx.inputs.map((input) => isCoinbaseInput(input)
      ? { coinbase: binToHex(input.unlockingBytecode), sequence: input.sequenceNumber }
      : { txid: binToHex(input.outpointTransactionHash), vout: input.outpointIndex, scriptSig: { hex: binToHex(input.unlockingBytecode) }, sequence: input.sequenceNumber }),
    vout: tx.outputs.map((output, n) => ({
      n,
      value: Number(output.valueSatoshis) / 1e8,
      scriptPubKey: { hex: binToHex(output.lockingBytecode) },
      ...(output.token === undefined ? {} : { tokenData: tokenData(output.token) }),
    })),
    ...(confirmed ? {
      blockhash: ledger.blocks[entry.height].hashDisplay,
      confirmations: ledger.tip.height - entry.height + 1,
      time: ledger.blocks[entry.height].time,
      blocktime: ledger.blocks[entry.height].time,
    } : {}),
  };
}
