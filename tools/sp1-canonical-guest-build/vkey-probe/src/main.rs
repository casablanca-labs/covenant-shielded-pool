//! Report the identity of a guest ELF **file**: SHA-256, byte length, and the
//! SP1 program VKey.
//!
//! The four pinned provers each `include_elf!` their own guest, so each can only
//! report the identity of the ELF that its own build script produced. Comparing
//! two *externally* produced ELFs — which is exactly what a path-independence
//! check requires — needs a reader that takes a path. That is all this is.
//!
//! It performs SP1 `setup()` and nothing else. `setup()` derives a verifying key
//! and constructs no proof. There is no `.prove()`, `.groth16()`, `.plonk()` or
//! `.compressed()` anywhere in this binary, and it deliberately reuses
//! `apnt-prover-backend-v0`'s already-reviewed `program_identity` rather than
//! opening a second, unreviewed route to the SP1 client.
//!
//! Output is one JSON object per ELF, on stdout, so runs at different checkout
//! paths can be diffed mechanically instead of by eye.

use std::path::PathBuf;

use anyhow::{Context, Result};
use apnt_prover_backend_v0::{ApntCpuSp1BackendV0, ApntProverBackendV0};
use sp1_sdk::Elf;

fn main() -> Result<()> {
    let paths: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    if paths.is_empty() {
        eprintln!("usage: apnt-sp1-guest-identity-probe <guest-elf-path>...");
        std::process::exit(2);
    }

    let backend = ApntCpuSp1BackendV0::new();

    for path in paths {
        let bytes = std::fs::read(&path)
            .with_context(|| format!("failed to read guest ELF at {}", path.display()))?;
        let elf = Elf::from(bytes);
        let identity = backend
            .program_identity(&elf)
            .with_context(|| format!("SP1 setup failed for {}", path.display()))?;
        println!(
            "{{\"path\":\"{}\",\"guest_elf_sha256\":\"{}\",\"guest_elf_bytes\":{},\"program_vkey_hash\":\"{}\"}}",
            path.display(),
            identity.guest_elf_sha256,
            identity.guest_elf_bytes,
            identity.program_vkey_hash
        );
    }

    Ok(())
}
