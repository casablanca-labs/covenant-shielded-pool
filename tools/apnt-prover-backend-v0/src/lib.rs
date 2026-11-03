//! # `ApntProverBackendV0`
//!
//! The single boundary between *constructing a proving input* and *obtaining a
//! proof for it*.
//!
//! Callers (today: the two SP1 fixture provers; later: aggregator batch
//! assembly) hand this interface the exact proving-input bytes they already
//! construct plus a target proof profile, and receive back a proof, its public
//! values, the program VKey it was proven against, and the guest ELF identity —
//! the same shape every proof fixture in this repository already records.
//!
//! ## What this boundary is for
//!
//! Real, measured SP1 Groth16 proving of the APNT transition guest costs
//! ~170 s wall time and 19-36 GB peak resident memory on CPU. The one real
//! lever left is GPU acceleration, which cannot run on this project's current
//! development hardware. This interface exists so that adding a GPU backend
//! later is an addition, not a rewrite of every calling site.
//!
//! ## What this boundary is explicitly NOT for
//!
//! **It is not a delegated-proving abstraction.** Per `AGENTS.md`'s mission and
//! hard constraints, no code path may require trusting a third party with
//! spend-authority material, and the private proving witness must not be handed
//! to a service this project does not operate. Succinct's prover network and
//! equivalent third-party proving marketplaces were evaluated and rejected for
//! exactly that reason.
//!
//! The shape of this interface enforces that structurally, not by convention:
//!
//! - [`ApntProvingRequestV0`] carries **only** the guest ELF, the proving-input
//!   bytes, the proof profile and the proof nonce. It has no endpoint, no
//!   credential, no API key, no account, no delegation policy, no per-request
//!   backend selection and no fallback list. There is no field a caller could
//!   use to point a single request at somebody else's prover.
//! - Exactly **one** backend is live at a time, and it is chosen by local
//!   configuration ([`select_apnt_prover_backend_v0_from_environment`]) before
//!   any request exists. Backend choice is never negotiated per request, never
//!   inferred from the request, and never auto-detected from the host.
//! - Every backend declares [`ApntProverBackendIdentityV0::operator_controlled`]
//!   and the crate refuses to hand back a backend that does not assert it. The
//!   only constructors for that struct are private to this crate, so an
//!   out-of-crate implementation cannot mint a "trusted" identity for itself.
//!
//! "Where the CPU/GPU cycles run" is configurable. "Who holds the witness" is
//! not.
//!
//! ## Locality neutrality
//!
//! Nothing in the interface assumes the backend runs in-process. A backend may
//! be an in-process prover (today's [`ApntCpuSp1BackendV0`]), a subprocess, or
//! a call to *this project's own* GPU infrastructure — the contract is only
//! that it returns the same verifiable shape. See [`ApntCudaSp1BackendV0`] for
//! the named, unimplemented GPU extension point.

use std::{
    sync::{Mutex, OnceLock, PoisonError},
    time::Instant,
};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use sp1_sdk::{
    blocking::{CpuProver, ProveRequest, Prover, ProverClient},
    Elf, HashableKey, ProvingKey, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin,
    SP1VerifyingKey,
};

/// The environment variable that selects which backend proves.
///
/// Matches this repository's existing configuration pattern (for example
/// `CONSOLE_BRIDGE_PORT` / `CONSOLE_PROFILE` in
/// `packages/cloak-console/server/bridge.mjs`): a named variable read once, with
/// an explicit default, and no auto-detection.
pub const APNT_PROVER_BACKEND_ENVIRONMENT_VARIABLE: &str = "APNT_PROVER_BACKEND";

/// The backend used when [`APNT_PROVER_BACKEND_ENVIRONMENT_VARIABLE`] is unset.
///
/// Defaulting to CPU is deliberate: it is the only backend that is real,
/// working and measured today, and an unset environment must never silently
/// route a proof somewhere else.
pub const APNT_DEFAULT_PROVER_BACKEND_ID: &str = "cpu";

/// The target proof profile a caller asks for.
///
/// Today there is exactly one. It is an enum rather than a string so that
/// adding a second profile is a compile error at every call site rather than a
/// silent behaviour change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApntProofProfileV0 {
    /// SP1 Groth16 over BN254 — the profile every committed APNT proof fixture
    /// records as `sp1-v6.1.0-groth16-bn254-v*`.
    Sp1Groth16Bn254,
}

impl ApntProofProfileV0 {
    /// The stable identifier recorded alongside proofs.
    #[must_use]
    pub const fn proof_mode(self) -> &'static str {
        match self {
            Self::Sp1Groth16Bn254 => "groth16",
        }
    }
}

/// Everything a backend needs to produce a proof, and nothing else.
///
/// Deliberately minimal. See the crate-level documentation for why no
/// endpoint, credential or delegation field may be added here.
#[derive(Debug, Clone)]
pub struct ApntProvingRequestV0 {
    /// The guest program to prove.
    pub guest_elf: Elf,
    /// The exact proving-input bytes the caller already constructs and feeds to
    /// the guest. This crate does not interpret them.
    pub proving_input: Vec<u8>,
    /// The requested proof profile.
    pub profile: ApntProofProfileV0,
    /// The proof nonce. Every committed APNT fixture uses `[0; 4]`.
    pub proof_nonce: [u32; 4],
}

impl ApntProvingRequestV0 {
    /// Build a request with this repository's canonical zero proof nonce.
    #[must_use]
    pub fn new(guest_elf: Elf, proving_input: Vec<u8>, profile: ApntProofProfileV0) -> Self {
        Self { guest_elf, proving_input, profile, proof_nonce: [0; 4] }
    }
}

/// The identity of the guest program a backend actually proved against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApntProgramIdentityV0 {
    /// SP1 program VKey, lowercase hexadecimal with no `0x` prefix.
    pub program_vkey_hash: String,
    /// SHA-256 of the guest ELF bytes, lowercase hexadecimal.
    pub guest_elf_sha256: String,
    /// Length of the guest ELF in bytes.
    pub guest_elf_bytes: usize,
}

/// Which backend produced a proof, and how it is trusted.
///
/// Reportable evidence, not incidental detail: "this proof was generated by the
/// CPU backend in 173 s" is the same honesty-about-provenance discipline this
/// project applies to real-vs-simulated and known-vs-unknown data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApntProverBackendIdentityV0 {
    /// Stable configuration id, e.g. `cpu`.
    backend_id: &'static str,
    /// The value recorded in fixtures' `prover` field, e.g. `local-cpu`.
    recorded_prover_label: &'static str,
    /// Where the cycles run: `in-process`, `subprocess`, or
    /// `operator-controlled-remote`.
    execution_locality: &'static str,
    /// Whether the machine running the proof is controlled by this project or
    /// its operator. Always `true` for any selectable backend.
    operator_controlled: bool,
    /// Whether the private proving witness leaves operator-controlled
    /// infrastructure. Always `false`; there is no constructor that can set it.
    third_party_delegated: bool,
}

impl ApntProverBackendIdentityV0 {
    /// The only constructor, private to this crate: `third_party_delegated` is
    /// hard-wired `false` and `operator_controlled` hard-wired `true`, so no
    /// implementation inside or outside this crate can mint an identity that
    /// claims otherwise.
    const fn for_operator_controlled_backend(
        backend_id: &'static str,
        recorded_prover_label: &'static str,
        execution_locality: &'static str,
    ) -> Self {
        Self {
            backend_id,
            recorded_prover_label,
            execution_locality,
            operator_controlled: true,
            third_party_delegated: false,
        }
    }

    /// Stable configuration id.
    #[must_use]
    pub const fn backend_id(&self) -> &'static str {
        self.backend_id
    }

    /// The label recorded in a proof fixture's `prover` field.
    #[must_use]
    pub const fn recorded_prover_label(&self) -> &'static str {
        self.recorded_prover_label
    }

    /// Where the proving cycles run.
    #[must_use]
    pub const fn execution_locality(&self) -> &'static str {
        self.execution_locality
    }

    /// Always `true` for a selectable backend.
    #[must_use]
    pub const fn operator_controlled(&self) -> bool {
        self.operator_controlled
    }

    /// Always `false`. Exposed so callers and tests can assert it rather than
    /// assume it.
    #[must_use]
    pub const fn third_party_delegated(&self) -> bool {
        self.third_party_delegated
    }
}

/// A proof plus everything needed to record and re-verify it.
pub struct ApntProvenArtifactV0 {
    /// The SP1 proof and its committed public values.
    pub proof: SP1ProofWithPublicValues,
    /// The committed public values, as bytes.
    pub public_values: Vec<u8>,
    /// The verifying key the proof must verify under.
    pub program_vkey: SP1VerifyingKey,
    /// The proven program's identity.
    pub program_identity: ApntProgramIdentityV0,
    /// Which backend produced it.
    pub backend: ApntProverBackendIdentityV0,
    /// The profile that was requested and produced.
    pub profile: ApntProofProfileV0,
    /// Wall time of proof construction alone, in milliseconds.
    pub proof_generation_duration_ms: u128,
}

/// The backend-neutral proving boundary.
///
/// Implementations must not interpret, transform or persist the proving input;
/// it is private witness material.
pub trait ApntProverBackendV0: Send + Sync {
    /// Which backend this is.
    fn identity(&self) -> ApntProverBackendIdentityV0;

    /// Resolve the guest program's identity without proving, so a caller can
    /// pin it against a compiled-in constant *before* spending 170 s of CPU.
    fn program_identity(&self, guest_elf: &Elf) -> Result<ApntProgramIdentityV0>;

    /// Produce a proof for an already-constructed proving input.
    fn prove(&self, request: &ApntProvingRequestV0) -> Result<ApntProvenArtifactV0>;

    /// Natively verify an artifact this backend returned. Returns the
    /// verification duration in microseconds.
    fn verify(&self, artifact: &ApntProvenArtifactV0) -> Result<u128>;
}

/// The CPU backend: today's real, working, measured path.
///
/// This is a pure wrapper around the invocation both SP1 fixture provers
/// already performed inline — `ProverClient::builder().cpu().build()`,
/// `setup`, `prove(..).groth16().with_proof_nonce(..)`, `verify` — with the
/// same `native-gnark` feature this hardware requires. It changes the calling
/// convention only; it does not change what is proven or how.
pub struct ApntCpuSp1BackendV0 {
    /// Built on first use, not on selection. Selecting a backend is a
    /// configuration decision and must stay free; constructing SP1's prover is
    /// real work.
    client: OnceLock<CpuProver>,
    /// One-entry proving-key cache, keyed by guest ELF SHA-256, so
    /// `program_identity` followed by `prove` does not run SP1 setup twice.
    cached_proving_key: Mutex<Option<(String, SP1ProvingKey)>>,
}

impl ApntCpuSp1BackendV0 {
    const IDENTITY: ApntProverBackendIdentityV0 =
        ApntProverBackendIdentityV0::for_operator_controlled_backend("cpu", "local-cpu", "in-process");

    /// Build the CPU backend.
    #[must_use]
    pub const fn new() -> Self {
        Self { client: OnceLock::new(), cached_proving_key: Mutex::new(None) }
    }

    fn client(&self) -> &CpuProver {
        self.client.get_or_init(|| ProverClient::builder().cpu().build())
    }

    fn proving_key(&self, guest_elf: &Elf) -> Result<(String, SP1ProvingKey)> {
        let elf_sha256 = hex::encode(Sha256::digest(guest_elf.as_ref()));
        let mut cache = self.cached_proving_key.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((cached_sha256, cached_key)) = cache.as_ref() {
            if *cached_sha256 == elf_sha256 {
                return Ok((elf_sha256, cached_key.clone()));
            }
        }
        let proving_key =
            self.client().setup(guest_elf.clone()).context("SP1 program setup failed")?;
        *cache = Some((elf_sha256.clone(), proving_key.clone()));
        Ok((elf_sha256, proving_key))
    }
}

impl Default for ApntCpuSp1BackendV0 {
    fn default() -> Self {
        Self::new()
    }
}

impl ApntProverBackendV0 for ApntCpuSp1BackendV0 {
    fn identity(&self) -> ApntProverBackendIdentityV0 {
        Self::IDENTITY
    }

    fn program_identity(&self, guest_elf: &Elf) -> Result<ApntProgramIdentityV0> {
        let (guest_elf_sha256, proving_key) = self.proving_key(guest_elf)?;
        let program_vkey_hash = proving_key
            .verifying_key()
            .bytes32()
            .strip_prefix("0x")
            .context("SP1 program identity is missing its hexadecimal prefix")?
            .to_owned();
        Ok(ApntProgramIdentityV0 {
            program_vkey_hash,
            guest_elf_sha256,
            guest_elf_bytes: guest_elf.as_ref().len(),
        })
    }

    fn prove(&self, request: &ApntProvingRequestV0) -> Result<ApntProvenArtifactV0> {
        let program_identity = self.program_identity(&request.guest_elf)?;
        let (_, proving_key) = self.proving_key(&request.guest_elf)?;
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(request.proving_input.clone());
        let started = Instant::now();
        let proof = match request.profile {
            ApntProofProfileV0::Sp1Groth16Bn254 => self
                .client()
                .prove(&proving_key, stdin)
                .groth16()
                .with_proof_nonce(request.proof_nonce)
                .run()
                .context("SP1 Groth16 proof construction failed")?,
        };
        let proof_generation_duration_ms = started.elapsed().as_millis();
        Ok(ApntProvenArtifactV0 {
            public_values: proof.public_values.as_slice().to_vec(),
            proof,
            program_vkey: proving_key.verifying_key().clone(),
            program_identity,
            backend: Self::IDENTITY,
            profile: request.profile,
            proof_generation_duration_ms,
        })
    }

    fn verify(&self, artifact: &ApntProvenArtifactV0) -> Result<u128> {
        let started = Instant::now();
        self.client()
            .verify(&artifact.proof, &artifact.program_vkey, None)
            .context("native SP1 verification rejected the proof")?;
        Ok(started.elapsed().as_micros())
    }
}

/// The named GPU extension point. **Not implemented.**
///
/// This type exists so that building the GPU backend later is *additive* — a
/// body for [`ApntProverBackendV0::prove`] and a `cuda` feature on `sp1-sdk` —
/// rather than a refactor of the interface, the CPU backend, the selector, or
/// any caller. It is deliberately a real, named, constructible type rather than
/// a `TODO` comment, and it fails closed with an explicit message rather than
/// silently degrading to CPU.
///
/// ## Real requirements a GPU implementation must satisfy
///
/// SP1's CUDA prover (`sp1-sdk` `cuda` feature,
/// `ProverClient::builder().cuda().build()`):
///
/// - Linux, x86_64. Not macOS, and not Apple Silicon — which is why this
///   project's current development hardware cannot run it at all.
/// - An NVIDIA GPU with CUDA 12 and compute capability 8.0 or higher
///   (Ampere and later).
/// - At least 24 GB of VRAM. Real CPU proving of the APNT transition guest
///   peaked at 19.1-30.5 GB resident, so this is a floor, not comfort.
/// - The NVIDIA container toolkit and a working Docker daemon; SP1's CUDA
///   prover runs its GPU server as a container the SDK manages.
///
/// ## In-process or separate service
///
/// Both remain open, and the interface does not force the choice:
///
/// - **In-process CUDA build.** Simplest. The private proving witness never
///   leaves the process. Requires the whole calling tool to be built and run on
///   the Linux/NVIDIA host.
/// - **Separate service on infrastructure this project operates.** Lets a
///   macOS caller drive a Linux GPU host. Requires an authenticated,
///   confidential transport, because the proving input is private witness
///   material.
///
/// **Either way the host must be operated by this project or its operator.**
/// Handing the proving input to a third-party proving service is out of scope
/// for this interface and disqualified by `AGENTS.md`, regardless of cost or
/// convenience.
pub struct ApntCudaSp1BackendV0 {
    _private: (),
}

impl ApntCudaSp1BackendV0 {
    const IDENTITY: ApntProverBackendIdentityV0 = ApntProverBackendIdentityV0::for_operator_controlled_backend(
        "cuda",
        "operator-gpu",
        "operator-controlled-host",
    );

    /// Construct the placeholder. Constructing it is not an error; *using* it
    /// is, until it is implemented.
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: () }
    }

    fn unimplemented<T>() -> Result<T> {
        bail!(
            "the `cuda` APNT prover backend is a documented extension point and is not implemented; \
             it requires SP1's CUDA prover on Linux x86_64 with an NVIDIA GPU (CUDA 12, compute \
             capability 8.0+, >=24GB VRAM) on infrastructure this project operates. Unset \
             {APNT_PROVER_BACKEND_ENVIRONMENT_VARIABLE} to use the real CPU backend."
        )
    }
}

impl Default for ApntCudaSp1BackendV0 {
    fn default() -> Self {
        Self::new()
    }
}

impl ApntProverBackendV0 for ApntCudaSp1BackendV0 {
    fn identity(&self) -> ApntProverBackendIdentityV0 {
        Self::IDENTITY
    }

    fn program_identity(&self, _guest_elf: &Elf) -> Result<ApntProgramIdentityV0> {
        Self::unimplemented()
    }

    fn prove(&self, _request: &ApntProvingRequestV0) -> Result<ApntProvenArtifactV0> {
        Self::unimplemented()
    }

    fn verify(&self, _artifact: &ApntProvenArtifactV0) -> Result<u128> {
        Self::unimplemented()
    }
}

/// Every backend id this build knows about, in configuration order.
pub const APNT_SELECTABLE_PROVER_BACKEND_IDS: [&str; 2] = ["cpu", "cuda"];

/// Select a backend by explicit id.
///
/// The set of ids is closed and compiled in. There is no id that names an
/// arbitrary endpoint, and an unknown id is a hard error rather than a fallback
/// to CPU — a silent fallback would make it impossible to know which backend
/// really proved a given transaction.
pub fn select_apnt_prover_backend_v0(backend_id: &str) -> Result<Box<dyn ApntProverBackendV0>> {
    let backend: Box<dyn ApntProverBackendV0> = match backend_id {
        "cpu" => Box::new(ApntCpuSp1BackendV0::new()),
        "cuda" => Box::new(ApntCudaSp1BackendV0::new()),
        other => bail!(
            "unknown APNT prover backend {other:?}; {APNT_PROVER_BACKEND_ENVIRONMENT_VARIABLE} \
             must be one of {APNT_SELECTABLE_PROVER_BACKEND_IDS:?}"
        ),
    };
    let identity = backend.identity();
    if !identity.operator_controlled() || identity.third_party_delegated() {
        bail!("refusing a prover backend that is not operator-controlled");
    }
    Ok(backend)
}

/// Select a backend from local configuration.
///
/// Reads [`APNT_PROVER_BACKEND_ENVIRONMENT_VARIABLE`] once, defaulting to
/// [`APNT_DEFAULT_PROVER_BACKEND_ID`]. There is deliberately no hardware
/// auto-detection: which backend proves a given transaction must be a decision
/// the operator made, not one the machine made.
pub fn select_apnt_prover_backend_v0_from_environment() -> Result<Box<dyn ApntProverBackendV0>> {
    let configured = std::env::var(APNT_PROVER_BACKEND_ENVIRONMENT_VARIABLE)
        .unwrap_or_else(|_| APNT_DEFAULT_PROVER_BACKEND_ID.to_owned());
    select_apnt_prover_backend_v0(configured.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_backend_is_the_real_cpu_backend() {
        let backend = select_apnt_prover_backend_v0(APNT_DEFAULT_PROVER_BACKEND_ID)
            .expect("cpu backend selectable");
        assert_eq!(backend.identity().backend_id(), "cpu");
        assert_eq!(backend.identity().recorded_prover_label(), "local-cpu");
        assert_eq!(backend.identity().execution_locality(), "in-process");
    }

    #[test]
    fn no_selectable_backend_delegates_to_a_third_party() {
        for backend_id in APNT_SELECTABLE_PROVER_BACKEND_IDS {
            let backend = select_apnt_prover_backend_v0(backend_id).expect("selectable");
            assert!(backend.identity().operator_controlled());
            assert!(!backend.identity().third_party_delegated());
        }
    }

    #[test]
    fn an_unknown_backend_is_refused_rather_than_silently_falling_back() {
        let message = match select_apnt_prover_backend_v0("succinct-prover-network") {
            Ok(_) => panic!("a third-party proving service must not be selectable"),
            Err(error) => error.to_string(),
        };
        assert!(message.contains("unknown APNT prover backend"));
    }

    #[test]
    fn the_gpu_extension_point_fails_closed_instead_of_degrading_to_cpu() {
        let backend = select_apnt_prover_backend_v0("cuda").expect("selectable");
        // `ApntProvenArtifactV0` is deliberately not `Debug` (SP1's verifying
        // key is not), so match rather than `expect_err`.
        let message = match backend.prove(&ApntProvingRequestV0::new(
            Elf::from(&b""[..]),
            Vec::new(),
            ApntProofProfileV0::Sp1Groth16Bn254,
        )) {
            Ok(_) => panic!("the cuda backend must not silently produce a proof"),
            Err(error) => error.to_string(),
        };
        assert!(message.contains("not implemented"));
        assert!(message.contains("CUDA 12"));
        let identity_error = backend
            .program_identity(&Elf::from(&b""[..]))
            .expect_err("the cuda backend cannot resolve a program identity either");
        assert!(identity_error.to_string().contains("not implemented"));
    }
}
