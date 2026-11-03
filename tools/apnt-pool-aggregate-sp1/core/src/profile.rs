//! `profile_id` and the compiled allowlist (design.md, "Profile id";
//! "Binding": the aggregate program computes `profile_id` from the `vp` it
//! verifies children under and accepts only the ids compiled into it).

use crate::{sha256, AggregateError};

pub const PROFILE_TAG: &[u8; 20] = b"APNT-POOL-v1:profile";
/// Registry entry 1: gnark Groth16 on BN254 (gnark v0.16.3, gnark-crypto v0.21.0).
pub const SYSTEM_ID_GNARK_GROTH16_BN254: u16 = 1;
/// Registry entry 2: Halo 2 with IPA on the Pasta curves. Listed, so it
/// derives an id, but this program carries no verifier for it.
pub const SYSTEM_ID_HALO2_IPA_PASTA: u16 = 2;

/// `profile_id = SHA-256("APNT-POOL-v1:profile" ‖ u16le(system_id) ‖ u64le(len(vp)) ‖ vp)`,
/// refusing every system id outside the registry's listed {1, 2}, as the
/// host's `deriveAPNTPoolProfileIdV1` does.
pub fn derive_profile_id(system_id: u16, vp: &[u8]) -> Result<[u8; 32], AggregateError> {
    if system_id != SYSTEM_ID_GNARK_GROTH16_BN254 && system_id != SYSTEM_ID_HALO2_IPA_PASTA {
        return Err(AggregateError::ProfileSystem);
    }
    Ok(sha256(&[
        PROFILE_TAG,
        &system_id.to_le_bytes(),
        &(vp.len() as u64).to_le_bytes(),
        vp,
    ]))
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("not lowercase hex"),
    }
}

const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    assert!(b.len() == 64);
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

/// The profile id of a DEVELOPMENT ZERO-VALUE verifying key of the action
/// circuit of registry entry 1 revision 2 (R1CS `25d3f54d…`, the 396-byte
/// record; revision 3's R1CS is `7c32a8f6…`, so no revision-3 record has a
/// proof under this key: it serves the refusal cases only; made by
/// ARCH-235's gated development Setup, R-386;
/// `fixtures/development-zero-value-rev2/action/vk.bin`, SHA-256 `aca20cf2…`;
/// toxic waste not destroyed; forgeable; never for value). It is not a
/// registry `vp`. Only the `development-zero-value-test-profile` feature
/// compiles it in.
pub const DEVELOPMENT_ZERO_VALUE_ACTION_PROFILE_ID: [u8; 32] =
    hex32("b41bf776a727d47005009dd509031290d2dfa04e1ae1c4a0c1fb0ea427daf3b5");

/// The profile id of a DEVELOPMENT ZERO-VALUE key of a STAND-IN circuit, not
/// the action relation: it proves only `x = int_be(SHA-256(A)) mod r` for a
/// private 396-byte `A` (revision 2's record length, so no 314-byte revision-3
/// record has a proof under it), with the action circuit's exact public shape
/// (`fixtures/development-zero-value-rev2/standin/key-a/vk.bin`, SHA-256
/// `437ee4ae…`). A child's verification cost depends on the key's shape,
/// not on the circuit behind it, so its 17 proofs carry the batch
/// measurements; they prove nothing about any action. Feature-gated like the
/// action key.
pub const DEVELOPMENT_ZERO_VALUE_STANDIN_PROFILE_ID: [u8; 32] =
    hex32("f324e6aaf5301a0c96bd24d94ca395b69604c46060fc9c9057251820ebd4eb06");

/// The profile id of registry entry 1 revision 3's recorded Chipnet vp
/// (ENG-446): the verifying key of the task-5.1c simulated single-party
/// ceremony re-run on revision 3 (ENG-483), whose proving key the action
/// proofs in `fixtures/simulated-ceremony-zero-value-rev3/` were made under
/// (ENG-486). SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY: the project
/// could forge proofs under it; never for value. Two builds compile it in:
/// the labelled Chipnet build (`chipnet-zero-value-rev3-profile`, alone) and
/// the local development profile (`development-zero-value-test-profile`,
/// beside the revision-2 development keys).
pub const CHIPNET_ZERO_VALUE_REVISION_3_PROFILE_ID: [u8; 32] =
    hex32("ea3d52d762f394b2959740126c3fb441165236696a02314a19498b48e2f1c1f2");

#[cfg(all(feature = "development-zero-value-test-profile", feature = "chipnet-zero-value-rev3-profile"))]
compile_error!(
    "development-zero-value-test-profile and chipnet-zero-value-rev3-profile are separate builds; \
     a build with both would allowlist the forgeable development keys under the Chipnet label"
);

/// The compiled allowlist. Empty in the default build: no registry `vp` is
/// compiled into it, so the default program refuses every key. The only `vp`
/// any canonical build carries is the labelled Chipnet build's, below.
#[cfg(not(any(feature = "development-zero-value-test-profile", feature = "chipnet-zero-value-rev3-profile")))]
pub const COMPILED_PROFILE_ALLOWLIST: &[[u8; 32]] = &[];

/// Test build: the two forgeable revision-2 development keys (the refusal
/// cases) and revision 3's Chipnet zero-value vp (the accepted runs).
#[cfg(feature = "development-zero-value-test-profile")]
pub const COMPILED_PROFILE_ALLOWLIST: &[[u8; 32]] = &[
    DEVELOPMENT_ZERO_VALUE_ACTION_PROFILE_ID,
    DEVELOPMENT_ZERO_VALUE_STANDIN_PROFILE_ID,
    CHIPNET_ZERO_VALUE_REVISION_3_PROFILE_ID,
];

/// The labelled Chipnet build (task 5.4 slice 2a, ENG-510): exactly registry
/// entry 1 revision 3's recorded Chipnet zero-value vp, nothing else. It is a
/// distinct program (`apnt-pool-aggregate-program-chipnet-zero-value-rev3`),
/// so its program key differs from every other build's, and it carries
/// [`CHIPNET_BUILD_LABEL`]. SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST
/// ONLY: never a mainnet or value build.
#[cfg(feature = "chipnet-zero-value-rev3-profile")]
pub const COMPILED_PROFILE_ALLOWLIST: &[[u8; 32]] = &[CHIPNET_ZERO_VALUE_REVISION_3_PROFILE_ID];

/// The label every output of a build with the development profile carries.
pub const DEVELOPMENT_LABEL: &str =
    "DEVELOPMENT ZERO-VALUE — toxic waste not destroyed; forgeable; never for value";

/// The label of revision 3's Chipnet keys and everything made under them.
pub const CHIPNET_ZERO_VALUE_LABEL: &str = "SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY";

/// The labelled Chipnet build's own label, which its ELF carries as a string.
pub const CHIPNET_BUILD_LABEL: &str =
    "APNT pool aggregate, Chipnet build, registry entry 1 revision 3: SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY; never mainnet, never value";

/// The default build's label.
pub const DEFAULT_BUILD_LABEL: &str = "APNT pool aggregate, default build: empty allowlist";

/// The label compiled into this build; the guest keeps it in its ELF
/// (`program/src/main.rs`), so the binary itself names what it is.
#[cfg(not(any(feature = "development-zero-value-test-profile", feature = "chipnet-zero-value-rev3-profile")))]
pub const COMPILED_BUILD_LABEL: &str = DEFAULT_BUILD_LABEL;
#[cfg(feature = "development-zero-value-test-profile")]
pub const COMPILED_BUILD_LABEL: &str = DEVELOPMENT_LABEL;
#[cfg(feature = "chipnet-zero-value-rev3-profile")]
pub const COMPILED_BUILD_LABEL: &str = CHIPNET_BUILD_LABEL;

pub const fn compiled_with_development_profile() -> bool {
    cfg!(feature = "development-zero-value-test-profile")
}

pub const fn compiled_with_chipnet_profile() -> bool {
    cfg!(feature = "chipnet-zero-value-rev3-profile")
}
