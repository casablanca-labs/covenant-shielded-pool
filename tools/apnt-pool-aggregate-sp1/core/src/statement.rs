//! The statement `S` and `runBind32` (design.md, "Statement"), assembled
//! exactly as `encodeAPNTPoolStatementV1` assembles it
//! (`packages/protocol-runtime/src/apnt_pool_statement_v1.ts`).
//!
//! ```text
//! S = "APNT-POOL-v1:statement" ‖ deployment_id ‖ profile_id ‖ u16le(B) ‖ A_1 ‖ … ‖ A_B
//! ad_k = SHA-256("APNT-POOL-v1:action-auth" ‖ deployment_id ‖ A_k)
//! runBind32 = SHA-256(S)
//! ```

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::record::{check_record, field32, offset, RECORD_BYTES};
use crate::{sha256, AggregateError};

pub const STATEMENT_TAG: &[u8; 22] = b"APNT-POOL-v1:statement";
pub const ACTION_AUTH_TAG: &[u8; 24] = b"APNT-POOL-v1:action-auth";
pub const HEADER_BYTES: usize = 88;
pub const MAXIMUM_ACTIONS: usize = 0xffff;

/// `ad = SHA-256("APNT-POOL-v1:action-auth" ‖ deployment_id ‖ A)`, over a record
/// the caller has already checked.
pub fn action_authorization_digest(deployment_id: &[u8; 32], record: &[u8]) -> [u8; 32] {
    sha256(&[ACTION_AUTH_TAG, deployment_id, record])
}

/// The host encoder's checks, in its order:
///
/// 1. `1 ≤ B ≤ 65,535` (`pool-statement-count`);
/// 2. every record exactly 314 bytes, all checked before any decode
///    (`pool-record-length`);
/// 3. each record strictly decoded, in input order, as its `ad` is derived;
/// 4. records sorted by `ad` as unsigned bytes (big-endian integers), and
///    equal digests refused (`pool-statement-order`);
/// 5. in statement order, each record's two nullifiers and then its two
///    commitments against every earlier one (`pool-statement-duplicate-*`).
///
/// The order is a function of the record set, so it carries no aggregator
/// choice.
pub fn assemble_statement(
    deployment_id: &[u8; 32],
    profile_id: &[u8; 32],
    records: &[&[u8]],
) -> Result<Vec<u8>, AggregateError> {
    if records.len() > MAXIMUM_ACTIONS || records.is_empty() {
        return Err(AggregateError::StatementCount);
    }
    if records.iter().any(|r| r.len() != RECORD_BYTES) {
        return Err(AggregateError::RecordLength);
    }
    let mut keyed: Vec<([u8; 32], usize)> = Vec::with_capacity(records.len());
    for (index, record) in records.iter().enumerate() {
        check_record(record)?;
        keyed.push((action_authorization_digest(deployment_id, record), index));
    }
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    if keyed.windows(2).any(|w| w[0].0 >= w[1].0) {
        return Err(AggregateError::StatementOrder);
    }
    let mut nullifiers = BTreeSet::new();
    let mut commitments = BTreeSet::new();
    for (_, index) in &keyed {
        let record = records[*index];
        for at in [offset::NULLIFIER_0, offset::NULLIFIER_1] {
            if !nullifiers.insert(field32(record, at)) {
                return Err(AggregateError::StatementDuplicateNullifier);
            }
        }
        for at in [offset::COMMITMENT_0, offset::COMMITMENT_1] {
            if !commitments.insert(field32(record, at)) {
                return Err(AggregateError::StatementDuplicateCommitment);
            }
        }
    }
    let mut statement = Vec::with_capacity(HEADER_BYTES + RECORD_BYTES * records.len());
    statement.extend_from_slice(STATEMENT_TAG);
    statement.extend_from_slice(deployment_id);
    statement.extend_from_slice(profile_id);
    statement.extend_from_slice(&(records.len() as u16).to_le_bytes());
    for (_, index) in &keyed {
        statement.extend_from_slice(records[*index]);
    }
    debug_assert_eq!(statement.len(), HEADER_BYTES + RECORD_BYTES * records.len());
    Ok(statement)
}

/// `runBind32 = SHA-256(S)`.
pub fn statement_commitment(statement: &[u8]) -> [u8; 32] {
    sha256(&[statement])
}
