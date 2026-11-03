/// Closed, stable refusal codes. They never carry a value or witness bytes.
///
/// The first group are the host's own codes
/// (`packages/protocol-runtime/src/apnt_pool_contract_v1.ts`,
/// `APNT_POOL_FAILURE_V1`) for the checks the host statement codec makes; the
/// parity vectors hold the core to the host's code for each. The second group
/// are the aggregate program's own checks, which the host codec does not make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregateError {
    RecordLength,
    RecordAmount,
    RecordWithdrawalLock,
    RecordKey,
    StatementCount,
    StatementOrder,
    StatementDuplicateNullifier,
    StatementDuplicateCommitment,
    ProfileSystem,
    /// The guest input does not parse (length, count, trailing bytes).
    Input,
    /// `profile_id(vp)` is not in the compiled allowlist.
    ProfileNotAllowlisted,
    /// An allowlisted `vp` does not parse as registry entry 1's topology.
    VerifierParameters,
    /// A proof is not 196 bytes with one BSB22 commitment.
    ProofShape,
    /// A proof point does not decode, is the point at infinity, or `B` is
    /// outside the order-r subgroup.
    ProofPoint,
    /// The BSB22 Pedersen knowledge check `e(D, GσNeg)·e(PoK, G) = 1` fails.
    CommitmentKnowledge,
    /// The Groth16 pairing check fails.
    ProofRejected,
}

impl AggregateError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::RecordLength => "pool-record-length",
            Self::RecordAmount => "pool-record-amount",
            Self::RecordWithdrawalLock => "pool-record-withdrawal-lock",
            Self::RecordKey => "pool-record-key",
            Self::StatementCount => "pool-statement-count",
            Self::StatementOrder => "pool-statement-order",
            Self::StatementDuplicateNullifier => "pool-statement-duplicate-nullifier",
            Self::StatementDuplicateCommitment => "pool-statement-duplicate-commitment",
            Self::ProfileSystem => "pool-profile-system-id",
            Self::Input => "pool-aggregate-input",
            Self::ProfileNotAllowlisted => "pool-aggregate-profile-not-allowlisted",
            Self::VerifierParameters => "pool-aggregate-verifier-parameters",
            Self::ProofShape => "pool-aggregate-proof-shape",
            Self::ProofPoint => "pool-aggregate-proof-point",
            Self::CommitmentKnowledge => "pool-aggregate-commitment-knowledge",
            Self::ProofRejected => "pool-aggregate-proof-rejected",
        }
    }
}
