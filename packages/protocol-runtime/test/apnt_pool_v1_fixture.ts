import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { secp256k1 } from "@noble/curves/secp256k1";

import { bytesToHex, hexToBytes } from "../src/bytes.js";
import { APNT_POOL_V1_CURVE_ORDER } from "../src/apnt_pool_contract_v1.js";
import {
  deriveAPNTPoolNoteCommitmentV1,
  deriveAPNTPoolNullifierV1,
  deriveAPNTPoolOwnerTagV1,
  deriveAPNTPoolRecoveryTagV1,
} from "../src/apnt_pool_note_v1.js";
import { apntPoolEmptyRootsV1, apntPoolMembershipRootV1, apntPoolTreeNodeV1, type APNTPoolMembershipPathV1 } from "../src/apnt_pool_tree_v1.js";
import type { APNTPoolInputWitnessV1, APNTPoolOutputWitnessV1 } from "../src/apnt_pool_action_relation_v1.js";

/**
 * Test-only synthetic material for the pool v1 host suites. Every 32-byte
 * value is SHA-256("eng273:" + name), non-palindromic by construction. The
 * spend secrets here are public test constants; they exist only so tests can
 * derive `ak`, and no relation witness ever carries one.
 */

export const vectors: any = JSON.parse(readFileSync(new URL("../test-vectors/apnt-pool-v1-vectors.json", import.meta.url), "utf8"));
/** The tag-authorization message vectors (HUM-75; ENG-390), from their own independent producer. */
export const tagVectors: any = JSON.parse(readFileSync(new URL("../test-vectors/apnt-pool-v1-tag-authorization-vectors.json", import.meta.url), "utf8"));

export const hex = (bytes: Uint8Array): string => bytesToHex(bytes);
export const unhex = (value: string): Uint8Array => hexToBytes("vector", value);
export const lab = (name: string): Uint8Array => new Uint8Array(createHash("sha256").update(`eng273:${name}`).digest());
export const scalarOf = (name: string): bigint => {
  const value = BigInt("0x" + hex(lab(name))) % APNT_POOL_V1_CURVE_ORDER;
  if (value === 0n) throw new Error("zero test scalar");
  return value;
};
export const pointOf = (scalar: bigint): Uint8Array => secp256k1.Point.BASE.multiply(scalar).toBytes(true);
export const flip = (bytes: Uint8Array, index = 0): Uint8Array => {
  const out = bytes.slice();
  out[index] = out[index]! ^ 0x01;
  return out;
};
export const isNonPalindromic = (bytes: Uint8Array): boolean => hex(bytes) !== hex(bytes.slice().reverse());

export function witnessFromVector(json: any): { inputs: [APNTPoolInputWitnessV1, APNTPoolInputWitnessV1]; outputs: [APNTPoolOutputWitnessV1, APNTPoolOutputWitnessV1] } {
  const input = (i: any): APNTPoolInputWitnessV1 => ({
    valueSats: BigInt(i.valueSats),
    spendKey33: unhex(i.spendKey33),
    nullifierKey32: unhex(i.nullifierKey32),
    rho32: unhex(i.rho32),
    commitmentRandomness32: unhex(i.commitmentRandomness32),
    recoveryTag32: unhex(i.recoveryTag32),
    rerandomizer: BigInt(i.rerandomizer),
    membership: i.membership === null ? null : { position: i.membership.position, siblings32: i.membership.siblings.map(unhex) },
  });
  const output = (o: any): APNTPoolOutputWitnessV1 => ({
    valueSats: BigInt(o.valueSats),
    ownerTag32: unhex(o.ownerTag32),
    rho32: unhex(o.rho32),
    recoveryKey32: unhex(o.recoveryKey32),
  });
  return { inputs: [input(json.inputs[0]), input(json.inputs[1])], outputs: [output(json.outputs[0]), output(json.outputs[1])] };
}

/** A note an input slot can spend, built from labels; tests attach a path from {@link sparseTree}. */
export type TestInputNote = APNTPoolInputWitnessV1 & { commitment32: Uint8Array; nullifier32: Uint8Array };

export function makeInputNote(prefix: string, valueSats: bigint): TestInputNote {
  const spendKey33 = pointOf(scalarOf(`${prefix}:ask`));
  const nullifierKey32 = lab(`${prefix}:nk`);
  const rho32 = lab(`${prefix}:rho`);
  const commitmentRandomness32 = lab(`${prefix}:rcm`);
  const recoveryTag32 = deriveAPNTPoolRecoveryTagV1(lab(`${prefix}:K`));
  const commitment32 = deriveAPNTPoolNoteCommitmentV1({
    valueSats, ownerTag32: deriveAPNTPoolOwnerTagV1(spendKey33, nullifierKey32), rho32, commitmentRandomness32, recoveryTag32,
  });
  return {
    valueSats, spendKey33, nullifierKey32, rho32, commitmentRandomness32, recoveryTag32,
    rerandomizer: scalarOf(`${prefix}:alpha`), membership: null,
    commitment32, nullifier32: deriveAPNTPoolNullifierV1(nullifierKey32, rho32, commitment32),
  };
}

export function asInputWitness(note: TestInputNote, membership: APNTPoolMembershipPathV1 | null = note.membership): APNTPoolInputWitnessV1 {
  return {
    valueSats: note.valueSats, spendKey33: note.spendKey33, nullifierKey32: note.nullifierKey32, rho32: note.rho32,
    commitmentRandomness32: note.commitmentRandomness32, recoveryTag32: note.recoveryTag32, rerandomizer: note.rerandomizer, membership,
  };
}

/** An output witness from labels: no `rcm`, which the relation derives from `K` and `ρ`. */
export function makeOutput(prefix: string, valueSats: bigint, rho32: Uint8Array): APNTPoolOutputWitnessV1 {
  return {
    valueSats,
    ownerTag32: deriveAPNTPoolOwnerTagV1(pointOf(scalarOf(`${prefix}:ask`)), lab(`${prefix}:nk`)),
    rho32,
    recoveryKey32: lab(`${prefix}:K`),
  };
}

/** Depth-32 tree with leaves at positions 0..7 and empty leaves elsewhere. */
export function sparseTree(leaves: readonly Uint8Array[]): { root: Uint8Array; path: (position: number) => APNTPoolMembershipPathV1 } {
  if (leaves.length > 8) throw new Error("sparse test tree holds at most 8 leaves");
  const Z = apntPoolEmptyRootsV1();
  const levels: Uint8Array[][] = [Array.from({ length: 8 }, (_, i) => leaves[i] ?? Z[0]!)];
  while (levels.at(-1)!.length > 1) {
    const level = levels.at(-1)!;
    levels.push(Array.from({ length: level.length / 2 }, (_, i) => apntPoolTreeNodeV1(level[2 * i], level[2 * i + 1])));
  }
  let root = levels[3]![0]!;
  for (let h = 3; h < 32; h += 1) root = apntPoolTreeNodeV1(root, Z[h]);
  const path = (position: number): APNTPoolMembershipPathV1 => {
    const siblings32 = [...[0, 1, 2].map((h) => levels[h]![(position >> h) ^ 1]!), ...Z.slice(3, 32)];
    const reached = apntPoolMembershipRootV1(levels[0]![position]!, { position, siblings32 });
    if (hex(reached) !== hex(root)) throw new Error("sparse test tree path does not reach its root");
    return { position, siblings32 };
  };
  return { root, path };
}
