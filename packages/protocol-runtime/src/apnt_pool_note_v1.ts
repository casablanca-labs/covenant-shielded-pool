import { secp256k1 } from "@noble/curves/secp256k1";

import { type Bytes32 } from "./bytes.js";
import {
  APNT_POOL_FAILURE_V1 as F,
  APNT_POOL_V1_CURVE_ORDER,
  APNT_POOL_V1_DOMAIN_TAGS as TAG,
  APNT_POOL_V1_DISCOVERY_TAG_BYTES,
  APNT_POOL_V1_MAX_MONEY_SATS,
  APNT_POOL_V1_PACKET_BYTES,
  APNT_POOL_V1_PACKET_VALUE_BYTES,
  APNT_POOL_V1_POINT_BYTES,
  pool32,
  poolBoundary,
  poolBytes,
  poolConcat,
  poolEqual,
  poolMoneyU64le,
  poolReadU64le,
  poolRecord,
  poolRequire,
  poolSha256,
} from "./apnt_pool_contract_v1.js";

/**
 * APNT shielded pool v1: notes, nullifiers, packets and re-randomized keys.
 *
 * design.md, "Canonical encodings" (Note, Packet) and "Authorization":
 *
 * ```text
 * nkc    = SHA-256("APNT-POOL-v1:nkc" ‖ nk)
 * O      = SHA-256("APNT-POOL-v1:owner" ‖ SEC1c(ak) ‖ nkc)
 * tag    = SHA-256("APNT-POOL-v1:rt" ‖ K)
 * rcm    = SHA-256("APNT-POOL-v1:rcm" ‖ K ‖ ρ)                 every output, real, change or dummy
 * cm     = SHA-256("APNT-POOL-v1:cm" ‖ u64le(v) ‖ O ‖ ρ ‖ rcm ‖ tag)
 * nf     = SHA-256("APNT-POOL-v1:nf" ‖ nk ‖ ρ ‖ cm)
 * d      = SHA-256("APNT-POOL-v1:pad" ‖ K ‖ ρ ‖ cm)
 * packet = (u64le(v) ⊕ d[0..8)) ‖ d[8..16)                      16 bytes (pad16, HUM-84)
 * rk     = SEC1c(ak + α·G), α ∈ [0, n_G), not the point at infinity
 * ```
 *
 * The owner tag commits to `nk` only through `nkc` (ENG-329), while `nf` takes
 * `nk` itself: a holder of `nkc` and `ak` can form `O` and still cannot
 * compute `nf`, which needs a SHA-256 preimage of `nkc`.
 *
 * An output's `rcm` is derived from its `K` and its own public `ρ` (ARCH-247,
 * HUM-84), so the packet carries only the value. A spent note presents the
 * `rcm` its creating action derived; the relation never checks how an input's
 * `rcm` was made.
 *
 * The packet has no MAC. Its integrity is the proof's: the relation enforces
 * each output's packet from that output's own `v`, `K`, `ρ` and `cm`, and `A`
 * is bound by the public input, the owners' signatures and the statement. A
 * wallet opens only packets of settled, proven actions. The 8-byte key check
 * is a wrong-key trial filter (64 bits; about 77 with `v ≤ MAX_MONEY`, for
 * random wrong-key trials only), not an ownership or authenticity check: a
 * payer holding `K` can seal a packet that passes it for a note committed to
 * another owner, and only the full tier's `cm` recheck under the wallet's own
 * `O` tells the two apart (REV-202).
 *
 * Curve arithmetic is delegated to `@noble/curves`. No signature is produced
 * or verified here: pool authorization is BCH's native EC-Schnorr, checked by
 * the settlement covenant's `OP_CHECKDATASIGVERIFY` (task 3.4), and this
 * package carries no BCH Schnorr implementation.
 */

const Point = secp256k1.Point;
type CurvePoint = InstanceType<typeof Point>;

/** A copy of a valid 33-byte SEC1-compressed point, or `null`; the checked copy is the one callers use. */
function compressedPointBytes(value: unknown): Uint8Array | null {
  let bytes: Uint8Array;
  try { bytes = poolBytes(value, APNT_POOL_V1_POINT_BYTES, F.SHAPE); } catch { return null; }
  if (bytes[0] !== 0x02 && bytes[0] !== 0x03) return null;
  try { Point.fromBytes(bytes); return bytes; } catch { return null; }
}

/** True for a valid 33-byte SEC1-compressed point, which is never the point at infinity. */
export function isAPNTPoolCompressedPointV1(value: unknown): boolean {
  try {
    const [point] = poolBoundary([value]);
    return compressedPointBytes(point) !== null;
  } catch {
    return false;
  }
}

function spendKey(ak33: unknown): Readonly<{ bytes: Uint8Array; point: CurvePoint }> {
  const bytes = compressedPointBytes(ak33);
  poolRequire(bytes !== null, F.SPEND_KEY);
  return Object.freeze({ bytes, point: Point.fromBytes(bytes) });
}

/** `nkc` of an already-cloned `nk`. */
const nullifierKeyCommitment = (nk32: unknown): Bytes32 => poolSha256(TAG.nullifierKeyCommitment, pool32(nk32, F.WITNESS_SHAPE));

/** `nkc = SHA-256("APNT-POOL-v1:nkc" ‖ nk)`, the nullifier-key commitment the owner tag takes in place of `nk`. */
export function deriveAPNTPoolNullifierKeyCommitmentV1(nk32: unknown): Bytes32 {
  [nk32] = poolBoundary([nk32]);
  return nullifierKeyCommitment(nk32);
}

/**
 * `O = SHA-256("APNT-POOL-v1:owner" ‖ SEC1c(ak) ‖ nkc)`, with `nkc` derived here
 * from `nk`; `ak` must be a valid compressed point.
 */
export function deriveAPNTPoolOwnerTagV1(ak33: unknown, nk32: unknown): Bytes32 {
  [ak33, nk32] = poolBoundary([ak33, nk32]);
  return poolSha256(TAG.owner, spendKey(ak33).bytes, nullifierKeyCommitment(nk32));
}

/** `tag = SHA-256("APNT-POOL-v1:rt" ‖ K)`. */
export function deriveAPNTPoolRecoveryTagV1(recoveryKey32: unknown): Bytes32 {
  [recoveryKey32] = poolBoundary([recoveryKey32]);
  return poolSha256(TAG.recoveryTag, pool32(recoveryKey32, F.WITNESS_SHAPE));
}

/**
 * Change/dummy `dt(F, role) = SHA-256("APNT-POOL-v1:dtag" ‖ F ‖ role)[0:8]`.
 * `F` is exactly 32 bytes; v1 permits only the one-byte role `0x00`.
 * Payment tags are recipient-issued invoice fields, copied by the payer.
 * This fill is outside the relation; the owners' signatures bind its bytes.
 */
export function deriveAPNTPoolDiscoveryTagV1(fillKey32: unknown, role: unknown): Uint8Array {
  [fillKey32, role] = poolBoundary([fillKey32, role]);
  const fillKey = pool32(fillKey32, F.DISCOVERY_TAG);
  poolRequire(role === 0x00, F.DISCOVERY_TAG);
  return poolSha256(TAG.discoveryTag, fillKey, Uint8Array.of(role)).slice(0, APNT_POOL_V1_DISCOVERY_TAG_BYTES);
}

export type APNTPoolNoteOpeningV1 = Readonly<{
  valueSats: bigint;
  ownerTag32: Uint8Array;
  rho32: Uint8Array;
  commitmentRandomness32: Uint8Array;
  recoveryTag32: Uint8Array;
}>;

const NOTE_KEYS = ["valueSats", "ownerTag32", "rho32", "commitmentRandomness32", "recoveryTag32"] as const;

/** `cm = SHA-256("APNT-POOL-v1:cm" ‖ u64le(v) ‖ O ‖ ρ ‖ rcm ‖ tag)`, with `v ∈ [0, MAX_MONEY]`. */
export function deriveAPNTPoolNoteCommitmentV1(value: APNTPoolNoteOpeningV1): Bytes32 {
  const [clone] = poolBoundary([value]);
  const note = poolRecord(clone, NOTE_KEYS, F.WITNESS_SHAPE);
  return poolSha256(
    TAG.commitment,
    poolMoneyU64le(note.valueSats, F.VALUE_RANGE),
    pool32(note.ownerTag32, F.WITNESS_SHAPE),
    pool32(note.rho32, F.WITNESS_SHAPE),
    pool32(note.commitmentRandomness32, F.WITNESS_SHAPE),
    pool32(note.recoveryTag32, F.WITNESS_SHAPE),
  );
}

/** `nf = SHA-256("APNT-POOL-v1:nf" ‖ nk ‖ ρ ‖ cm)`. Needs `nk`, which only the owner holds. */
export function deriveAPNTPoolNullifierV1(nk32: unknown, rho32: unknown, commitment32: unknown): Bytes32 {
  [nk32, rho32, commitment32] = poolBoundary([nk32, rho32, commitment32]);
  return poolSha256(
    TAG.nullifier,
    pool32(nk32, F.WITNESS_SHAPE),
    pool32(rho32, F.WITNESS_SHAPE),
    pool32(commitment32, F.WITNESS_SHAPE),
  );
}

/**
 * `rcm = SHA-256("APNT-POOL-v1:rcm" ‖ K ‖ ρ)`: an output's commitment
 * randomness, from its recovery key `K` and its own `ρ` (the creating action's
 * nullifier in the same slot, public in `A`). 32 bytes, used as is: `cm` is a
 * SHA-256 commitment, so nothing is reduced.
 */
export function deriveAPNTPoolCommitmentRandomnessV1(recoveryKey32: unknown, rho32: unknown): Bytes32 {
  [recoveryKey32, rho32] = poolBoundary([recoveryKey32, rho32]);
  return poolSha256(TAG.commitmentRandomness, pool32(recoveryKey32, F.WITNESS_SHAPE), pool32(rho32, F.WITNESS_SHAPE));
}

/**
 * `d = SHA-256("APNT-POOL-v1:pad" ‖ K ‖ ρ ‖ cm)`, the packet digest.
 *
 * Binding `cm` makes one digest pad one plaintext (REV-129 H1-R2-3): two
 * candidate actions that give output `j` the same `ρ` and `K` but a different
 * `v` have different `cm` and so different digests. An identical candidate
 * gives an identical packet, which reveals only the equality its equal `cm`
 * already shows.
 */
export function deriveAPNTPoolPacketDigestV1(recoveryKey32: unknown, rho32: unknown, commitment32: unknown): Bytes32 {
  [recoveryKey32, rho32, commitment32] = poolBoundary([recoveryKey32, rho32, commitment32]);
  return poolSha256(
    TAG.packetDigest,
    pool32(recoveryKey32, F.WITNESS_SHAPE),
    pool32(rho32, F.WITNESS_SHAPE),
    pool32(commitment32, F.WITNESS_SHAPE),
  );
}

export type APNTPoolPacketInputV1 = Readonly<{
  recoveryKey32: Uint8Array;
  rho32: Uint8Array;
  commitment32: Uint8Array;
  valueSats: bigint;
}>;

const PACKET_INPUT_KEYS = ["recoveryKey32", "rho32", "commitment32", "valueSats"] as const;

/** `(a ⊕ b)` over the first `a.length` bytes of `b`. */
function xorPrefix(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let index = 0; index < a.length; index += 1) out[index] = a[index]! ^ b[index]!;
  return out;
}

/** The 16-byte packet `(u64le(v) ⊕ d[0..8)) ‖ d[8..16)`, `d` the digest over `K`, `ρ` and `cm`. */
export function sealAPNTPoolPacketV1(value: APNTPoolPacketInputV1): Uint8Array {
  const [clone] = poolBoundary([value]);
  const input = poolRecord(clone, PACKET_INPUT_KEYS, F.WITNESS_SHAPE);
  const value8 = poolMoneyU64le(input.valueSats, F.VALUE_RANGE);
  const digest = deriveAPNTPoolPacketDigestV1(input.recoveryKey32, input.rho32, input.commitment32);
  const packet = poolConcat(xorPrefix(value8, digest), digest.slice(APNT_POOL_V1_PACKET_VALUE_BYTES, APNT_POOL_V1_PACKET_BYTES));
  poolRequire(packet.length === APNT_POOL_V1_PACKET_BYTES, F.PACKET);
  return packet;
}

/** The value a packet carries under one `K`: an owner-unverified candidate, never an opening. */
export type APNTPoolPacketCandidateV1 = Readonly<{ valueSats: bigint }>;

export type APNTPoolPacketOpeningV1 = Readonly<{ valueSats: bigint; commitmentRandomness32: Bytes32 }>;

const PACKET_FIELDS = ["recoveryKey32", "rho32", "commitment32", "packet16"] as const;

/** `v` if the packet's key check matches `d` over the given fields and `v ≤ MAX_MONEY`; else `null`. */
function packetValue(recoveryKey32: Bytes32, rho32: Bytes32, commitment32: Bytes32, packet: Uint8Array): bigint | null {
  const digest = deriveAPNTPoolPacketDigestV1(recoveryKey32, rho32, commitment32);
  if (!poolEqual(packet.slice(APNT_POOL_V1_PACKET_VALUE_BYTES), digest.slice(APNT_POOL_V1_PACKET_VALUE_BYTES, APNT_POOL_V1_PACKET_BYTES))) return null;
  const valueSats = poolReadU64le(xorPrefix(packet.slice(0, APNT_POOL_V1_PACKET_VALUE_BYTES), digest), 0);
  return valueSats <= APNT_POOL_V1_MAX_MONEY_SATS ? valueSats : null;
}

/**
 * Incoming-tier detection: whether a packet's key check matches under `K`,
 * the public `ρ` and the public `cm`, and if so the value it carries, when
 * that value is at most `MAX_MONEY`. Returns `null` otherwise, and for any
 * malformed field; a `null` says nothing about why.
 *
 * A hit is an owner-unverified candidate. The key check is a wrong-key trial
 * filter (64 bits, about 77 with the range filter, against random wrong
 * keys), not an ownership check: a holder of `K` can seal a matching packet
 * for a note committed to another owner (REV-202). Only
 * {@link openAPNTPoolPacketV1}, which rebuilds `cm` under the recipient's own
 * owner tag, yields an opening.
 */
export function detectAPNTPoolPacketV1(value: Readonly<{
  recoveryKey32: Uint8Array;
  rho32: Uint8Array;
  commitment32: Uint8Array;
  packet16: Uint8Array;
}>): APNTPoolPacketCandidateV1 | null {
  try {
    const [clone] = poolBoundary([value]);
    const fields = poolRecord(clone, PACKET_FIELDS, F.PACKET);
    const valueSats = packetValue(
      pool32(fields.recoveryKey32, F.PACKET),
      pool32(fields.rho32, F.PACKET),
      pool32(fields.commitment32, F.PACKET),
      poolBytes(fields.packet16, APNT_POOL_V1_PACKET_BYTES, F.PACKET),
    );
    return valueSats === null ? null : Object.freeze({ valueSats });
  } catch {
    return null;
  }
}

/**
 * Recipient-side opening (full tier): check the packet's key check under
 * `d(K, ρ, cm)`, recover `v`, derive `rcm` from `K` and `ρ`, then recompute
 * `cm` under the recipient's own owner tag and require it to equal the public
 * `cm`. Returns `null` on any mismatch; a `null` says nothing about why, so a
 * failed trial discloses nothing.
 */
export function openAPNTPoolPacketV1(value: Readonly<{
  recoveryKey32: Uint8Array;
  ownerTag32: Uint8Array;
  rho32: Uint8Array;
  commitment32: Uint8Array;
  packet16: Uint8Array;
}>): APNTPoolPacketOpeningV1 | null {
  try {
    // The fields are cloned once at the boundary; the copies are what the digest, the opening and the check use.
    const [clone] = poolBoundary([value]);
    const fields = poolRecord(clone, ["recoveryKey32", "ownerTag32", ...PACKET_FIELDS.slice(1)], F.PACKET);
    const recoveryKey32 = pool32(fields.recoveryKey32, F.PACKET);
    const rho32 = pool32(fields.rho32, F.PACKET);
    const commitment32 = pool32(fields.commitment32, F.PACKET);
    const valueSats = packetValue(recoveryKey32, rho32, commitment32, poolBytes(fields.packet16, APNT_POOL_V1_PACKET_BYTES, F.PACKET));
    if (valueSats === null) return null;
    const commitmentRandomness32 = deriveAPNTPoolCommitmentRandomnessV1(recoveryKey32, rho32);
    const recomputed = deriveAPNTPoolNoteCommitmentV1({
      valueSats,
      ownerTag32: pool32(fields.ownerTag32, F.PACKET),
      rho32,
      commitmentRandomness32,
      recoveryTag32: deriveAPNTPoolRecoveryTagV1(recoveryKey32),
    });
    if (!poolEqual(recomputed, commitment32)) return null;
    return Object.freeze({ valueSats, commitmentRandomness32 });
  } catch {
    return null;
  }
}

/**
 * `rk = SEC1c(ak + α·G)` (design.md, "Actions" item 3 and "Authorization").
 *
 * Refuses an `ak` that is not a valid compressed point, an `α` outside
 * `[0, n_G)`, and a sum at the point at infinity. The owner later signs under
 * `rk` with `rsk = (ask + α) mod n_G`; nothing here takes `ask` or `rsk`, so a
 * delegate holding `ak` and `α` can derive `rk` and still cannot sign.
 */
export function deriveAPNTPoolRerandomizedKeyV1(ak33: unknown, alpha: unknown): Uint8Array {
  [ak33, alpha] = poolBoundary([ak33, alpha]);
  const ak = spendKey(ak33).point;
  poolRequire(typeof alpha === "bigint" && alpha >= 0n && alpha < APNT_POOL_V1_CURVE_ORDER, F.RERANDOMIZER);
  const sum = alpha === 0n ? ak : ak.add(Point.BASE.multiply(alpha));
  poolRequire(!sum.equals(Point.ZERO), F.RERANDOMIZED_KEY);
  return sum.toBytes(true);
}

/** Structural check of a public 33-byte key field (record `rk`). */
export function assertAPNTPoolRecordKeyV1(rk33: unknown): Uint8Array {
  const bytes = compressedPointBytes(rk33);
  poolRequire(bytes !== null, F.RECORD_KEY);
  return bytes;
}

/** `ak` validity with its stable code, for the relation. */
export function assertAPNTPoolSpendKeyV1(ak33: unknown): void {
  spendKey(ak33);
}
