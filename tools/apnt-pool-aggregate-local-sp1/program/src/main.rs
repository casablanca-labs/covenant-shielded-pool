//! Local 0x99 pool aggregate guest. It uses the same aggregate relation and
//! revision-3 action VP as the Chipnet zero-value test, under a separate
//! program identity. The project can forge proofs under that action VP.
//! This program and its outputs are for zero-value local simulation only.
#![no_main]
sp1_zkvm::entrypoint!(main);

use apnt_pool_aggregate_core::aggregate::{run, Tracer};
use apnt_pool_aggregate_core::profile::CHIPNET_ZERO_VALUE_REVISION_3_PROFILE_ID;

const LOCAL_BUILD_LABEL: &str =
    "APNT pool aggregate, LOCAL 0x99: SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY; never Chipnet, mainnet or value";
const LOCAL_PROFILE_ALLOWLIST: &[[u8; 32]] = &[CHIPNET_ZERO_VALUE_REVISION_3_PROFILE_ID];

struct CycleTracker;

impl Tracer for CycleTracker {
    fn start(&mut self, stage: &'static str) {
        println!("cycle-tracker-report-start: {stage}");
    }
    fn end(&mut self, stage: &'static str) {
        println!("cycle-tracker-report-end: {stage}");
    }
}

pub fn main() {
    core::hint::black_box(LOCAL_BUILD_LABEL);
    let input = sp1_zkvm::io::read_vec();
    match run(&input, LOCAL_PROFILE_ALLOWLIST, &mut CycleTracker) {
        Ok(accepted) => sp1_zkvm::io::commit_slice(&accepted.run_bind),
        Err(error) => {
            let line = format!("apnt-pool-aggregate-refusal: {}\n", error.code());
            let _ = std::io::Write::write_all(&mut std::io::stderr(), line.as_bytes());
            panic!("{}", error.code());
        }
    }
}
