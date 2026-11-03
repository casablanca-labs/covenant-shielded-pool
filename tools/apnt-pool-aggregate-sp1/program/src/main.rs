//! The pool aggregate program (task 5.4): verifies B action proofs under a
//! compiled-allowlist `vp`, assembles the statement `S` and commits
//! `runBind32 = SHA-256(S)` as its only public output.
//!
//! A refusal commits nothing and panics; before it does, the closed refusal
//! code (never a value) goes to stderr as `apnt-pool-aggregate-refusal: CODE`
//! so an execute-only run can name the check that fired.
//!
//! Two packages build this one source: `apnt-pool-aggregate-program` (the
//! default build, or the development test profile) and
//! `apnt-pool-aggregate-program-chipnet-zero-value-rev3` (the labelled
//! Chipnet build, ENG-510). The build's label stays in the ELF as a string.
#![no_main]
sp1_zkvm::entrypoint!(main);

use apnt_pool_aggregate_core::aggregate::{run, Tracer};
use apnt_pool_aggregate_core::profile::{COMPILED_BUILD_LABEL, COMPILED_PROFILE_ALLOWLIST};

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
    // Keeps the build's label in the ELF's read-only data; it commits nothing.
    core::hint::black_box(COMPILED_BUILD_LABEL);
    let input = sp1_zkvm::io::read_vec();
    match run(&input, COMPILED_PROFILE_ALLOWLIST, &mut CycleTracker) {
        Ok(accepted) => sp1_zkvm::io::commit_slice(&accepted.run_bind),
        Err(error) => {
            // One write, so the executor sees the whole line in one chunk
            // (`eprintln!` writes each format piece separately).
            let line = format!("apnt-pool-aggregate-refusal: {}\n", error.code());
            let _ = std::io::Write::write_all(&mut std::io::stderr(), line.as_bytes());
            panic!("{}", error.code());
        }
    }
}
