/**
 * Repository-shared CashAssembly text -> BCH bytecode compiler, plus the
 * minimal script-encoding primitives it and every covenant source in this
 * package depend on.
 *
 * This module carries no SRQ3, TRQ1, import-funding, seal, or settlement
 * semantics of any kind. It is a token-for-token assembler: opcode mnemonics
 * from the pinned libauth opcode set, `0x...` literal pushes emitted verbatim,
 * and `<n>` numeric pushes minimally encoded. Everything it can express is
 * decided by the `.casm` source handed to it.
 *
 * It previously lived in `apnt_import_funding_cell.ts` under the name
 * `compileApntImportFundingCellSrq3AggregatorConsumptionCasmV0`, which was
 * always a misnomer: the SRQ3/TRQ1 aggregator-consumption gate was only the
 * first source it happened to compile. Today it also compiles the 128-byte
 * created-note seal, that seal's exit and aggregate branches, and the
 * settlement authorization covenant. Task 21.8(a) of
 * `define-apnt-import-created-note-acceptance-v0` moved it here so that
 * deprecating the SRQ3/TRQ1 *lock* does not read as deprecating this
 * general-purpose *compiler*, which is not deprecated and is not going away.
 *
 * The old export name is retained in `apnt_import_funding_cell.ts` as a thin
 * `@deprecated` re-export of `compileApntCashAssemblySourceV0`; output bytes
 * are identical across the two names by construction, and
 * `apnt_cashassembly_compiler_v0.test.ts` proves it for every current caller.
 */

import { hexToBytes } from "./bytes.js";

export function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/**
 * Minimal BCH data push encoding. Exported so covenant sources that must emit
 * CashAssembly data-push tokens (for example
 * `apnt_settlement_authorization_covenant_v0.ts`) share this one encoding
 * rather than restating it.
 */
export function pushScriptData(bytes: Uint8Array): Uint8Array {
  if (bytes.length <= 75) {
    return concatBytes([Uint8Array.of(bytes.length), bytes]);
  }
  if (bytes.length <= 0xff) {
    return concatBytes([Uint8Array.of(0x4c, bytes.length), bytes]);
  }
  if (bytes.length <= 0xffff) {
    return concatBytes([
      Uint8Array.of(0x4d, bytes.length & 0xff, bytes.length >> 8),
      bytes,
    ]);
  }
  throw new Error("ApntCashAssemblyCompilerV0 pushScriptData exceeds u16");
}

export function encodeScriptNumberPush(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("ApntCashAssemblyCompilerV0 number is invalid");
  }
  if (value === 0) return Uint8Array.of(0x00);
  if (value >= 1 && value <= 16) return Uint8Array.of(0x50 + value);
  // Arithmetic, not `& 0xff` and `>>= 8`: JavaScript's bitwise operators
  // truncate to 32-bit signed integers, which encoded every value from 2^31 up
  // as a shorter, wrong push (4,294,967,295 became 255) until ENG-339. Below
  // 2^31 the two forms give the same bytes.
  const bytes: number[] = [];
  let remaining = value;
  while (remaining > 0) {
    bytes.push(remaining % 256);
    remaining = Math.floor(remaining / 256);
  }
  if ((bytes[bytes.length - 1]! & 0x80) !== 0) {
    bytes.push(0);
  }
  return pushScriptData(Uint8Array.from(bytes));
}

// Byte values are the real BCH consensus opcode set, taken verbatim from the
// pinned `@bitauth/libauth` build's `OpcodesBch2023`/`OpcodesBch2026` enums
// (`bch-2023-opcodes.ts`, `bch-2026-opcodes.ts`) rather than hand-derived, so
// this table cannot silently diverge from the VM this project measures
// against.
export const APNT_CASHASSEMBLY_OPCODE_BYTES_V0 = Object.freeze({
  OP_0: 0x00,
  OP_1: 0x51,
  OP_2: 0x52,
  OP_3: 0x53,
  OP_11: 0x5b,
  OP_12: 0x5c,
  OP_16: 0x60,
  OP_IF: 0x63,
  OP_NOTIF: 0x64,
  OP_BEGIN: 0x65,
  OP_UNTIL: 0x66,
  OP_ELSE: 0x67,
  OP_ENDIF: 0x68,
  OP_VERIFY: 0x69,
  OP_TOALTSTACK: 0x6b,
  OP_FROMALTSTACK: 0x6c,
  OP_2DROP: 0x6d,
  OP_2DUP: 0x6e,
  OP_DEPTH: 0x74,
  OP_DROP: 0x75,
  OP_DUP: 0x76,
  OP_NIP: 0x77,
  OP_OVER: 0x78,
  OP_PICK: 0x79,
  OP_ROLL: 0x7a,
  OP_ROT: 0x7b,
  OP_SWAP: 0x7c,
  OP_TUCK: 0x7d,
  OP_CAT: 0x7e,
  OP_SPLIT: 0x7f,
  OP_NUM2BIN: 0x80,
  OP_BIN2NUM: 0x81,
  OP_SIZE: 0x82,
  OP_AND: 0x84,
  OP_EQUAL: 0x87,
  OP_EQUALVERIFY: 0x88,
  OP_DEFINE: 0x89,
  OP_INVOKE: 0x8a,
  OP_1ADD: 0x8b,
  OP_1SUB: 0x8c,
  OP_LSHIFTNUM: 0x8d,
  OP_RSHIFTNUM: 0x8e,
  OP_NOT: 0x91,
  OP_0NOTEQUAL: 0x92,
  OP_LSHIFTBIN: 0x98,
  OP_RSHIFTBIN: 0x99,
  OP_BOOLAND: 0x9a,
  OP_NUMEQUAL: 0x9c,
  OP_NUMEQUALVERIFY: 0x9d,
  OP_LESSTHAN: 0x9f,
  OP_GREATERTHAN: 0xa0,
  OP_LESSTHANOREQUAL: 0xa1,
  OP_GREATERTHANOREQUAL: 0xa2,
  OP_MIN: 0xa3,
  OP_WITHIN: 0xa5,
  OP_ADD: 0x93,
  OP_SUB: 0x94,
  OP_MUL: 0x95,
  OP_DIV: 0x96,
  OP_MOD: 0x97,
  OP_SHA256: 0xa8,
  OP_HASH256: 0xaa,
  OP_CHECKSIG: 0xac,
  OP_CHECKSIGVERIFY: 0xad,
  OP_CHECKSEQUENCEVERIFY: 0xb2,
  OP_CHECKDATASIGVERIFY: 0xbb,
  OP_REVERSEBYTES: 0xbc,
  OP_INPUTINDEX: 0xc0,
  OP_ACTIVEBYTECODE: 0xc1,
  OP_TXVERSION: 0xc2,
  OP_TXINPUTCOUNT: 0xc3,
  OP_TXOUTPUTCOUNT: 0xc4,
  OP_TXLOCKTIME: 0xc5,
  OP_UTXOVALUE: 0xc6,
  OP_UTXOBYTECODE: 0xc7,
  OP_OUTPOINTTXHASH: 0xc8,
  OP_OUTPOINTINDEX: 0xc9,
  OP_INPUTBYTECODE: 0xca,
  OP_INPUTSEQUENCENUMBER: 0xcb,
  OP_OUTPUTVALUE: 0xcc,
  OP_OUTPUTBYTECODE: 0xcd,
  OP_UTXOTOKENCATEGORY: 0xce,
  OP_UTXOTOKENCOMMITMENT: 0xcf,
  OP_OUTPUTTOKENCATEGORY: 0xd1,
  OP_OUTPUTTOKENCOMMITMENT: 0xd2,
  OP_OUTPUTTOKENAMOUNT: 0xd3,
} as const);

/**
 * Compiles a CashAssembly source string to raw BCH locking/unlocking bytecode.
 *
 * Grammar, in full: `//` line comments are stripped; whitespace-separated
 * tokens are either `<n>` (minimal number push), `0x…` (literal bytes emitted
 * verbatim, so the source itself carries any pushdata prefix), or an opcode
 * mnemonic present in `APNT_CASHASSEMBLY_OPCODE_BYTES_V0`. Unknown tokens and
 * empty results throw rather than silently producing a wrong script.
 */

// Maturity: stable — imported by all four published covenant builders
// (apnt_verifier_factory_v0.ts, apnt_settlement_authorization_covenant_v0.ts,
// apnt_created_note_seal_v0.ts, apnt_created_note_seal_exit_branch_v0.ts).
// Its output underlies frozen pinned bytecode downstream. See AGENTS.md,
// "The maturity ladder".
export function compileApntCashAssemblySourceV0(source: string): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const rawLine of source.split(/\r?\n/u)) {
    const line = rawLine.replace(/\/\/.*$/u, "").trim();
    if (line.length === 0) continue;
    for (const token of line.split(/\s+/u)) {
      const numberMatch = /^<([0-9]+)>$/u.exec(token);
      if (numberMatch) {
        parts.push(encodeScriptNumberPush(Number.parseInt(numberMatch[1]!, 10)));
        continue;
      }
      if (/^0x[0-9a-f]*$/u.test(token)) {
        parts.push(hexToBytes("ApntCashAssemblyCompilerV0.hex", token.slice(2)));
        continue;
      }
      const opcode = APNT_CASHASSEMBLY_OPCODE_BYTES_V0[
        token as keyof typeof APNT_CASHASSEMBLY_OPCODE_BYTES_V0
      ];
      if (opcode === undefined) {
        throw new Error(`ApntCashAssemblyCompilerV0 unsupported token: ${token}`);
      }
      parts.push(Uint8Array.of(opcode));
    }
  }
  const bytecode = concatBytes(parts);
  if (bytecode.length === 0) {
    throw new Error("ApntCashAssemblyCompilerV0 compiled empty bytecode");
  }
  return bytecode;
}
