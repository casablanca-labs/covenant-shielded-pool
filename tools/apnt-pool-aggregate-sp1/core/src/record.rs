//! The 314-byte action record `A` (design.md, "Canonical encodings"; registry
//! entry 1 revision 3, pad16, HUM-84, ENG-454: 16-byte packets, and the
//! amounts and `wlock_hash` 82 bytes lower than revision 2's 396-byte record),
//! checked as `decodeAPNTPoolActionRecordV1` checks it
//! (`packages/protocol-runtime/src/apnt_pool_action_record_v1.ts`).

use k256::elliptic_curve::sec1::FromEncodedPoint;

use crate::AggregateError;

pub const RECORD_BYTES: usize = 314;
/// BCH `MAX_MONEY`, satoshis.
pub const MAX_MONEY_SATS: u64 = 2_100_000_000_000_000;

/// Field offsets, as `APNT_POOL_V1_ACTION_RECORD_OFFSETS`.
pub mod offset {
    pub const ANCHOR: usize = 0;
    pub const NULLIFIER_0: usize = 32;
    pub const NULLIFIER_1: usize = 64;
    pub const RERANDOMIZED_KEY_0: usize = 96;
    pub const RERANDOMIZED_KEY_1: usize = 129;
    pub const COMMITMENT_0: usize = 162;
    pub const COMMITMENT_1: usize = 194;
    pub const PACKET_0: usize = 226;
    pub const PACKET_1: usize = 242;
    pub const DEPOSIT: usize = 258;
    pub const WITHDRAWAL: usize = 266;
    pub const FEE: usize = 274;
    pub const WITHDRAWAL_LOCK_HASH: usize = 282;
}

/// A valid 33-byte SEC1-compressed secp256k1 point: prefix 02 or 03, `x < p`,
/// and `x³ + 7` a square mod `p`. The prefix is checked first, so the
/// all-zero identity encoding `k256` would otherwise read is never reached.
pub fn is_compressed_point(bytes: &[u8]) -> bool {
    if bytes.len() != 33 || !(bytes[0] == 0x02 || bytes[0] == 0x03) {
        return false;
    }
    match k256::EncodedPoint::from_bytes(bytes) {
        Ok(encoded) => bool::from(k256::AffinePoint::from_encoded_point(&encoded).is_some()),
        Err(_) => false,
    }
}

pub(crate) fn u64le(record: &[u8], at: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&record[at..at + 8]);
    u64::from_le_bytes(b)
}

pub(crate) fn field32(record: &[u8], at: usize) -> [u8; 32] {
    let mut b = [0u8; 32];
    b.copy_from_slice(&record[at..at + 32]);
    b
}

/// The host's strict decode, in its check order: length; `rk_0`, `rk_1`;
/// deposit, withdrawal, fee each in `[0, MAX_MONEY]`; then the `wlock_hash`
/// rule (32 zero bytes if and only if the withdrawal is 0).
pub fn check_record(record: &[u8]) -> Result<(), AggregateError> {
    if record.len() != RECORD_BYTES {
        return Err(AggregateError::RecordLength);
    }
    for at in [offset::RERANDOMIZED_KEY_0, offset::RERANDOMIZED_KEY_1] {
        if !is_compressed_point(&record[at..at + 33]) {
            return Err(AggregateError::RecordKey);
        }
    }
    for at in [offset::DEPOSIT, offset::WITHDRAWAL, offset::FEE] {
        if u64le(record, at) > MAX_MONEY_SATS {
            return Err(AggregateError::RecordAmount);
        }
    }
    let lock_is_zero = record[offset::WITHDRAWAL_LOCK_HASH..offset::WITHDRAWAL_LOCK_HASH + 32]
        .iter()
        .all(|b| *b == 0);
    if (u64le(record, offset::WITHDRAWAL) == 0) != lock_is_zero {
        return Err(AggregateError::RecordWithdrawalLock);
    }
    Ok(())
}
