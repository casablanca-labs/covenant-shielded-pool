//! The pool aggregate program's whole relation, in its check order:
//!
//! 1. parse the input (`pool-aggregate-input`);
//! 2. `profile_id = SHA-256("APNT-POOL-v1:profile" ‖ u16le(1) ‖ u64le(len(vp)) ‖ vp)`
//!    over the `vp` the children are verified under, refused unless it is in
//!    the compiled allowlist (`pool-aggregate-profile-not-allowlisted`),
//!    before `vp` is even parsed;
//! 3. parse `vp` (`pool-aggregate-verifier-parameters`);
//! 4. assemble `S` with every host codec check (the host's codes);
//! 5. verify every child proof against `vp`, its one public input computed
//!    from its own record, in input order;
//! 6. return `runBind32 = SHA-256(S)`.
//!
//! The cheap statement checks run before any pairing, so a malformed batch is
//! refused before the costly part; every check still runs on every accepted
//! batch.

use alloc::vec::Vec;

use crate::groth16::{verify, VerifyingKey};
use crate::input::parse_input;
use crate::profile::{derive_profile_id, SYSTEM_ID_GNARK_GROTH16_BN254};
use crate::statement::{assemble_statement, statement_commitment};
use crate::AggregateError;

/// Stage markers, so the guest can report cycles per stage. The host passes
/// [`NoTrace`].
pub trait Tracer {
    fn start(&mut self, stage: &'static str);
    fn end(&mut self, stage: &'static str);
}

pub struct NoTrace;
impl Tracer for NoTrace {
    fn start(&mut self, _: &'static str) {}
    fn end(&mut self, _: &'static str) {}
}

pub const STAGE_PROFILE: &str = "pool-aggregate-profile";
pub const STAGE_VERIFYING_KEY: &str = "pool-aggregate-verifying-key";
pub const STAGE_STATEMENT: &str = "pool-aggregate-statement";
pub const STAGE_CHILD: &str = "pool-aggregate-child-verify";
pub const STAGE_COMMIT: &str = "pool-aggregate-commitment";

pub struct Accepted {
    pub statement: Vec<u8>,
    pub run_bind: [u8; 32],
}

pub fn run(input: &[u8], allowlist: &[[u8; 32]], trace: &mut impl Tracer) -> Result<Accepted, AggregateError> {
    let parsed = parse_input(input)?;

    trace.start(STAGE_PROFILE);
    let profile_id = derive_profile_id(SYSTEM_ID_GNARK_GROTH16_BN254, parsed.vp)?;
    let allowed = allowlist.contains(&profile_id);
    trace.end(STAGE_PROFILE);
    if !allowed {
        return Err(AggregateError::ProfileNotAllowlisted);
    }

    trace.start(STAGE_VERIFYING_KEY);
    let vk = VerifyingKey::parse(parsed.vp);
    trace.end(STAGE_VERIFYING_KEY);
    let vk = vk?;

    trace.start(STAGE_STATEMENT);
    let records: Vec<&[u8]> = parsed.actions.iter().map(|a| a.record.as_slice()).collect();
    let statement = assemble_statement(&parsed.deployment_id, &profile_id, &records);
    trace.end(STAGE_STATEMENT);
    let statement = statement?;

    for action in &parsed.actions {
        trace.start(STAGE_CHILD);
        let verdict = verify(&vk, action.proof, action.record);
        trace.end(STAGE_CHILD);
        verdict?;
    }

    trace.start(STAGE_COMMIT);
    let run_bind = statement_commitment(&statement);
    trace.end(STAGE_COMMIT);
    Ok(Accepted { statement, run_bind })
}
