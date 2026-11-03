//! Registry entry 1's child verifier (one public input since revision 2, HUM-80,
//! ENG-437; revision 3's 314-byte record, pad16, ENG-454): gnark
//! v0.16.3 `groth16/bn254` `Verify` with its BSB22 commitment extension, for
//! the pool action circuit's topology (`tools/apnt-pool-action-circuit/registry.go`),
//! one public input:
//!
//! ```text
//! vp  = [α]1 ‖ [β]1 ‖ [β]2 ‖ [γ]2 ‖ [δ]1 ‖ [δ]2 ‖ u32be(3) ‖ K[0..3]
//!       ‖ u32be(1) ‖ u32be(0) ‖ u32be(1) ‖ G ‖ GσNeg                     528 bytes
//! π   = A ‖ B ‖ C ‖ u32be(1) ‖ D ‖ PoK                                    196 bytes
//! x   = int_be(SHA-256(record)) mod r      computed here from the record in S
//! h   = expand_message_xmd(SHA-256, x(D) ‖ y(D), "bsb22-commitment", 48) mod r
//! L   = K[0] + x·K[1] + h·K[2] + D
//! accept ⇔ e(D, GσNeg)·e(PoK, G) = 1  and  e(−A, B)·e(L, γ)·e(C, δ)·e(α, β) = 1
//! ```
//!
//! The program derives `x` from the record it places in `S` and never takes
//! it from the prover: the proof binds a field element, and `int_be(d)` and
//! `int_be(d) − r` name the same one. Revision 1 (396 byte scalars, a
//! 13,168-byte `vp`) is refused at parse: no revision-1 key is a `vp`.
//!
//! Points are gnark-crypto compressed: flags in the top two bits of the first
//! byte (0b10 the smaller root, 0b11 the larger, 0b01 infinity), G2 as
//! `x.A1 ‖ x.A0`. A single commitment folds with `r⁰ = 1`, so gnark's
//! `BatchVerifyMultiVk` is exactly the one knowledge pairing above.
//!
//! Where this refuses what gnark accepts: a proof point at infinity (gnark
//! decodes it; an honest proof has one with negligible probability). Refusing
//! more never admits a proof gnark refuses. The differential test holds the
//! decoded points, the commitment wire and every verdict equal to gnark's.
//!
//! The ported code is the seal-era `tools/apnt-successor-aggregate-sp1/core`
//! verifier (330 publics), with the pool topology; ENG-421 slice 1 verified
//! 396 byte scalars with a bucket MSM, which the one public input replaces
//! with two full-width scalar multiplications.

use alloc::vec::Vec;
use bn::{pairing_batch, AffineG1, AffineG2, Fq, Fq2, Fr, Gt, G1, G2};
use sha2::{Digest, Sha256};

use crate::record::RECORD_BYTES;
use crate::AggregateError;

pub const PUBLIC_INPUTS: usize = 1;
/// `|K| = 1 + 1 + 1` (the constant one, x, the commitment wire).
pub const K_LENGTH: usize = PUBLIC_INPUTS + 2;
pub const VP_BYTES: usize = 288 + 4 + 32 * K_LENGTH + 12 + 128;
pub const PROOF_BYTES: usize = 196;
/// One commitment, committing no public input, then one commitment key.
const COMMITMENT_TOPOLOGY: [u8; 12] = [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1];

const POINT_MASK: u8 = 0xc0;
const COMPRESSED_SMALLEST: u8 = 0x80;
const COMPRESSED_LARGEST: u8 = 0xc0;
const COMPRESSED_INFINITY: u8 = 0x40;
const BSB22_DST: &[u8] = b"bsb22-commitment";

pub struct VerifyingKey {
    pub(crate) alpha: AffineG1,
    // [β]1 and [δ]1 are in the one serialization and are decoded (curve
    // checked) as gnark's reader does; Verify reads neither.
    #[allow(dead_code)]
    pub(crate) beta_g1: AffineG1,
    pub(crate) beta: AffineG2,
    pub(crate) gamma: AffineG2,
    #[allow(dead_code)]
    pub(crate) delta_g1: AffineG1,
    pub(crate) delta: AffineG2,
    pub(crate) k: Vec<AffineG1>,
    pub(crate) commitment_g: AffineG2,
    pub(crate) commitment_g_sigma_neg: AffineG2,
}

pub struct Proof {
    pub(crate) a: AffineG1,
    pub(crate) b: AffineG2,
    pub(crate) c: AffineG1,
    pub(crate) commitment: AffineG1,
    pub(crate) commitment_pok: AffineG1,
}

fn decode_fq_with_flag(bytes: &[u8]) -> Option<(Fq, u8)> {
    let flag = bytes[0] & POINT_MASK;
    if !matches!(flag, COMPRESSED_SMALLEST | COMPRESSED_LARGEST | COMPRESSED_INFINITY) {
        return None;
    }
    let mut x = [0u8; 32];
    x.copy_from_slice(&bytes[..32]);
    x[0] &= !POINT_MASK;
    if flag == COMPRESSED_INFINITY {
        return x.iter().all(|b| *b == 0).then(|| (Fq::zero(), flag));
    }
    // `from_slice` refuses x ≥ q, as gnark's canonical decode does.
    Fq::from_slice(&x).ok().map(|x| (x, flag))
}

fn decode_g1(bytes: &[u8], allow_infinity: bool) -> Option<AffineG1> {
    let (x, flag) = decode_fq_with_flag(bytes)?;
    if flag == COMPRESSED_INFINITY {
        return allow_infinity.then(AffineG1::zero);
    }
    // (smaller, larger) as integers.
    let (small, large) = AffineG1::get_ys_from_x_unchecked(x)?;
    let y = if flag == COMPRESSED_SMALLEST { small } else { large };
    AffineG1::new(x, y).ok()
}

fn decode_g2(bytes: &[u8]) -> Option<AffineG2> {
    let (x1, flag) = decode_fq_with_flag(&bytes[..32])?;
    if flag == COMPRESSED_INFINITY {
        return None;
    }
    let x0 = Fq::from_slice(&bytes[32..64]).ok()?;
    let x = Fq2::new(x0, x1);
    // (smaller, larger) in gnark's E2 order: by A1, then A0.
    let (small, large) = AffineG2::get_ys_from_x_unchecked(x)?;
    let y = if flag == COMPRESSED_SMALLEST { small } else { large };
    // `new` checks the curve equation and membership in the order-r subgroup.
    AffineG2::new(x, y).ok()
}

impl VerifyingKey {
    /// Registry entry 1's `vp`, exactly `VP_BYTES` long with the action
    /// circuit's topology. `K` points may be infinity (a setup can produce
    /// one); α, β, γ, δ and the commitment keys may not.
    pub fn parse(vp: &[u8]) -> Result<Self, AggregateError> {
        Self::parse_inner(vp).ok_or(AggregateError::VerifierParameters)
    }

    fn parse_inner(vp: &[u8]) -> Option<Self> {
        if vp.len() != VP_BYTES {
            return None;
        }
        let alpha = decode_g1(&vp[0..32], false)?;
        let beta_g1 = decode_g1(&vp[32..64], true)?;
        let beta = decode_g2(&vp[64..128])?;
        let gamma = decode_g2(&vp[128..192])?;
        let delta_g1 = decode_g1(&vp[192..224], true)?;
        let delta = decode_g2(&vp[224..288])?;
        if vp[288..292] != (K_LENGTH as u32).to_be_bytes() {
            return None;
        }
        let k_end = 292 + 32 * K_LENGTH;
        let mut k = Vec::with_capacity(K_LENGTH);
        for point in vp[292..k_end].chunks_exact(32) {
            k.push(decode_g1(point, true)?);
        }
        if vp[k_end..k_end + 12] != COMMITMENT_TOPOLOGY {
            return None;
        }
        let keys = k_end + 12;
        Some(Self {
            alpha,
            beta_g1,
            beta,
            gamma,
            delta_g1,
            delta,
            k,
            commitment_g: decode_g2(&vp[keys..keys + 64])?,
            commitment_g_sigma_neg: decode_g2(&vp[keys + 64..keys + 128])?,
        })
    }
}

impl Proof {
    pub fn parse(bytes: &[u8]) -> Result<Self, AggregateError> {
        if bytes.len() != PROOF_BYTES || bytes[128..132] != [0, 0, 0, 1] {
            return Err(AggregateError::ProofShape);
        }
        let point = |p: Option<AffineG1>| p.ok_or(AggregateError::ProofPoint);
        Ok(Self {
            a: point(decode_g1(&bytes[0..32], false))?,
            b: decode_g2(&bytes[32..96]).ok_or(AggregateError::ProofPoint)?,
            c: point(decode_g1(&bytes[96..128], false))?,
            commitment: point(decode_g1(&bytes[132..164], false))?,
            commitment_pok: point(decode_g1(&bytes[164..196], false))?,
        })
    }
}

/// RFC 9380 `expand_message_xmd` with SHA-256.
fn expand_message_xmd_sha256(message: &[u8], dst: &[u8], len: usize) -> Vec<u8> {
    debug_assert!(dst.len() <= 255 && len <= 255 * 32 && len > 0);
    let ell = len.div_ceil(32);
    let dst_len = [dst.len() as u8];
    let mut h = Sha256::new();
    h.update([0u8; 64]);
    h.update(message);
    h.update((len as u16).to_be_bytes());
    h.update([0u8]);
    h.update(dst);
    h.update(dst_len);
    let b0: [u8; 32] = h.finalize().into();
    let mut h = Sha256::new();
    h.update(b0);
    h.update([1u8]);
    h.update(dst);
    h.update(dst_len);
    let mut previous: [u8; 32] = h.finalize().into();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&previous[..core::cmp::min(32, len)]);
    for i in 2..=ell {
        let mut xor = [0u8; 32];
        for j in 0..32 {
            xor[j] = b0[j] ^ previous[j];
        }
        let mut h = Sha256::new();
        h.update(xor);
        h.update([i as u8]);
        h.update(dst);
        h.update(dst_len);
        previous = h.finalize().into();
        let remaining = len - out.len();
        out.extend_from_slice(&previous[..core::cmp::min(32, remaining)]);
    }
    out
}

/// gnark's commitment wire for a commitment that commits no public input:
/// gnark-crypto `fr.Hash` over the uncompressed `x ‖ y` of D (big-endian,
/// no flag bits for a finite point), L = 48, reduced mod r.
pub(crate) fn commitment_wire(commitment: &AffineG1) -> Result<Fr, AggregateError> {
    let mut message = [0u8; 64];
    commitment.x().to_big_endian(&mut message[..32]).map_err(|_| AggregateError::ProofPoint)?;
    commitment.y().to_big_endian(&mut message[32..]).map_err(|_| AggregateError::ProofPoint)?;
    let uniform = expand_message_xmd_sha256(&message, BSB22_DST, 48);
    Fr::from_bytes_be_mod_order(&uniform).map_err(|_| AggregateError::ProofPoint)
}

/// Registry entry 1's public input, `x = int_be(SHA-256(record)) mod r`: the
/// digest read big-endian and reduced mod the BN254 scalar field order, as
/// the host's `deriveAPNTPoolActionPublicInputV1` does. The program computes
/// it from the record; no prover supplies it.
pub fn public_input(record: &[u8; RECORD_BYTES]) -> Fr {
    public_input_of(record)
}

/// x over any byte string: the rule is length-agnostic; the program applies
/// it only to a 314-byte record (`public_input`). The tests use it for the
/// revision-2 fixtures, whose proofs are over 396-byte records.
pub(crate) fn public_input_of(bytes: &[u8]) -> Fr {
    let digest = crate::sha256(&[bytes]);
    // Never refuses: the conversion is a big-integer remainder below r, whose
    // big-endian bytes (leading zeros stripped, then left-padded) fit 32.
    Fr::from_bytes_be_mod_order(&digest).expect("a remainder below r")
}

/// The Groth16 input `L = K[0] + x·K[1] + h·K[2] + D`.
pub(crate) fn prepared_input(vk: &VerifyingKey, x: Fr, commitment: &AffineG1) -> Result<AffineG1, AggregateError> {
    let wire = commitment_wire(commitment)?;
    let l = vk.k[0] + vk.k[1] * x + vk.k[2] * wire;
    Ok(l + *commitment)
}

fn g1(p: AffineG1) -> G1 {
    p.into()
}

fn knowledge_holds(vk: &VerifyingKey, proof: &Proof) -> bool {
    pairing_batch(&[
        (g1(proof.commitment), G2::from(vk.commitment_g_sigma_neg)),
        (g1(proof.commitment_pok), G2::from(vk.commitment_g)),
    ]) == Gt::one()
}

fn groth16_holds(vk: &VerifyingKey, proof: &Proof, l: AffineG1) -> bool {
    pairing_batch(&[
        (-g1(proof.a), G2::from(proof.b)),
        (g1(l), G2::from(vk.gamma)),
        (g1(proof.c), G2::from(vk.delta)),
        (g1(vk.alpha), G2::from(vk.beta)),
    ]) == Gt::one()
}

/// Verify one child proof against `vp`, its one public input computed from
/// its own record. The knowledge check runs first, as in gnark.
pub fn verify(vk: &VerifyingKey, proof_bytes: &[u8], record: &[u8; RECORD_BYTES]) -> Result<(), AggregateError> {
    verify_bytes(vk, proof_bytes, record)
}

/// `verify` over any byte string as the proof's record (see `public_input_of`).
pub(crate) fn verify_bytes(vk: &VerifyingKey, proof_bytes: &[u8], record: &[u8]) -> Result<(), AggregateError> {
    let proof = Proof::parse(proof_bytes)?;
    if !knowledge_holds(vk, &proof) {
        return Err(AggregateError::CommitmentKnowledge);
    }
    let l = prepared_input(vk, public_input_of(record), &proof.commitment)?;
    if !groth16_holds(vk, &proof, l) {
        return Err(AggregateError::ProofRejected);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod testing {
    //! Test-only views of the verifier's internals, for the differential and
    //! mutation-witness tests. Nothing here is reachable from the guest.
    use super::*;

    pub fn fq_hex(v: Fq) -> alloc::string::String {
        let mut b = [0u8; 32];
        v.to_big_endian(&mut b).unwrap();
        hex::encode(b)
    }
    pub fn fr_hex(v: Fr) -> alloc::string::String {
        let mut b = [0u8; 32];
        v.into_u256().to_big_endian(&mut b).unwrap();
        hex::encode(b)
    }
    pub fn g1(p: &AffineG1) -> (alloc::string::String, alloc::string::String) {
        (fq_hex(p.x()), fq_hex(p.y()))
    }
    pub fn g2(p: &AffineG2) -> [alloc::string::String; 4] {
        [fq_hex(p.x().real()), fq_hex(p.x().imaginary()), fq_hex(p.y().real()), fq_hex(p.y().imaginary())]
    }
    /// The verifier with the knowledge check removed: the mutation witness
    /// that the check is what refuses a replaced PoK.
    pub fn verify_without_knowledge_check(vk: &VerifyingKey, proof_bytes: &[u8], record: &[u8]) -> Result<(), AggregateError> {
        let proof = Proof::parse(proof_bytes)?;
        let l = prepared_input(vk, public_input_of(record), &proof.commitment)?;
        if !groth16_holds(vk, &proof, l) {
            return Err(AggregateError::ProofRejected);
        }
        Ok(())
    }
    /// The verifier with a caller-chosen public input: the mutation
    /// witnesses of the reduction (a wrong x must be refused).
    pub fn verify_with_x(vk: &VerifyingKey, proof_bytes: &[u8], x: Fr) -> Result<(), AggregateError> {
        let proof = Proof::parse(proof_bytes)?;
        if !knowledge_holds(vk, &proof) {
            return Err(AggregateError::CommitmentKnowledge);
        }
        let l = prepared_input(vk, x, &proof.commitment)?;
        if !groth16_holds(vk, &proof, l) {
            return Err(AggregateError::ProofRejected);
        }
        Ok(())
    }
    /// Whether a record's digest is at least r, so that x takes the
    /// reduction (big-endian arrays compare as the integers they encode).
    pub fn digest_at_least_r(record: &[u8]) -> bool {
        let mut r_be = [0u8; 32];
        Fr::modulus().to_big_endian(&mut r_be).expect("32 bytes");
        crate::sha256(&[record]) >= r_be
    }
    /// x by truncation to the top 253 bits instead of mod r.
    pub fn public_input_truncated(record: &[u8]) -> Fr {
        let mut digest = crate::sha256(&[record]);
        let mut carry = 0u8;
        for b in digest.iter_mut() {
            let next = *b & 0x07;
            *b = (*b >> 3) | (carry << 5);
            carry = next;
        }
        Fr::from_bytes_be_mod_order(&digest).expect("32 bytes")
    }
    /// x from the digest read little-endian: the byte-order bug.
    pub fn public_input_little_endian(record: &[u8]) -> Fr {
        let mut digest = crate::sha256(&[record]);
        digest.reverse();
        Fr::from_bytes_be_mod_order(&digest).expect("32 bytes")
    }
}
