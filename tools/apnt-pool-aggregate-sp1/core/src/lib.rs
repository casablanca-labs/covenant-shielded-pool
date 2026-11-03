//! APNT shielded pool v1: the pool aggregate program's relation (task 5.4,
//! ENG-421 slice 1), shared by the SP1 guest and the host tests.
//!
//! Given a verifying key `vp`, a `deployment_id` and `B` action proofs with
//! their 314-byte records `A_k` (registry entry 1 revision 3, pad16), the program
//!
//! 1. computes `profile_id` from the `vp` it verifies under (system 1, gnark
//!    Groth16 on BN254, the only verifier it carries) and refuses any id
//!    outside its compiled allowlist, so a prover can never pick the key;
//! 2. assembles the statement `S` exactly as the host codec
//!    `encodeAPNTPoolStatementV1` does, with every check that codec makes;
//! 3. verifies every child proof against `vp`, with its one public input
//!    `x = int_be(SHA-256(A_k)) mod r` computed here from the record it
//!    places in `S` (registry entry 1 since revision 2, ENG-437) and gnark's BSB22
//!    commitment check;
//! 4. returns `runBind32 = SHA-256(S)`, the proof verdict's commitment
//!    (design.md, "Statement"; the settlement covenant checks
//!    `SHA-256(S)` against the verdict token's commitment,
//!    `apnt_pool_settlement_v1.casm` check 1).
//!
//! The host semantics are canonical. Nothing here is chain validation, wallet
//! acceptance or spendability, and a proof under a development key shows the
//! plumbing works, never that a statement holds for anyone else.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod aggregate;
pub mod error;
pub mod groth16;
pub mod input;
pub mod profile;
pub mod record;
pub mod statement;

pub use error::AggregateError;

use sha2::{Digest, Sha256};

/// `SHA-256(parts…)`, the pool's one hash (raw, no length prefix).
pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests;
