//! The guest's private input, one strict binary layout:
//!
//! ```text
//! u32le(len(vp)) ‖ vp ‖ deployment_id (32) ‖ u16le(B) ‖ (A_k (314) ‖ π_k (196)) × B
//! ```
//!
//! Any other length, a `vp` longer than `MAXIMUM_VP_BYTES`, or a trailing byte
//! refuses with `pool-aggregate-input`. Nothing in it is trusted: `vp` is
//! bound by the allowlist, `deployment_id` by the settlement covenant, the
//! records by the statement checks and the proofs by verification. The input
//! holds no spend authority (no `ask`, `rsk`, `nk` or note opening): only
//! public records and proofs.

use alloc::vec::Vec;

use crate::groth16::PROOF_BYTES;
use crate::record::RECORD_BYTES;
use crate::AggregateError;

/// A bound on `len(vp)` so a hostile length cannot force a large copy. Registry
/// entry 1's `vp` is 528 bytes (revisions 2 and 3; revision 1's was 13,168).
pub const MAXIMUM_VP_BYTES: usize = 1 << 20;
pub const ACTION_BYTES: usize = RECORD_BYTES + PROOF_BYTES;

pub struct Action<'a> {
    pub record: &'a [u8; RECORD_BYTES],
    pub proof: &'a [u8],
}

pub struct AggregateInput<'a> {
    pub vp: &'a [u8],
    pub deployment_id: [u8; 32],
    pub actions: Vec<Action<'a>>,
}

pub fn parse_input(bytes: &[u8]) -> Result<AggregateInput<'_>, AggregateError> {
    let take = |at: usize, n: usize| at.checked_add(n).and_then(|end| bytes.get(at..end)).ok_or(AggregateError::Input);
    let vp_len = u32::from_le_bytes(take(0, 4)?.try_into().unwrap()) as usize;
    if vp_len > MAXIMUM_VP_BYTES {
        return Err(AggregateError::Input);
    }
    let vp = take(4, vp_len)?;
    let mut at = 4 + vp_len;
    let deployment_id: [u8; 32] = take(at, 32)?.try_into().unwrap();
    at += 32;
    let count = u16::from_le_bytes(take(at, 2)?.try_into().unwrap()) as usize;
    at += 2;
    if bytes.len() != at + ACTION_BYTES * count {
        return Err(AggregateError::Input);
    }
    let actions = (0..count)
        .map(|k| {
            let start = at + ACTION_BYTES * k;
            Action {
                record: bytes[start..start + RECORD_BYTES].try_into().unwrap(),
                proof: &bytes[start + RECORD_BYTES..start + ACTION_BYTES],
            }
        })
        .collect();
    Ok(AggregateInput { vp, deployment_id, actions })
}

/// The one encoder, for the host runner and tests.
pub fn encode_input(vp: &[u8], deployment_id: &[u8; 32], actions: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + vp.len() + 34 + ACTION_BYTES * actions.len());
    out.extend_from_slice(&(vp.len() as u32).to_le_bytes());
    out.extend_from_slice(vp);
    out.extend_from_slice(deployment_id);
    out.extend_from_slice(&(actions.len() as u16).to_le_bytes());
    for (record, proof) in actions {
        out.extend_from_slice(record);
        out.extend_from_slice(proof);
    }
    out
}
