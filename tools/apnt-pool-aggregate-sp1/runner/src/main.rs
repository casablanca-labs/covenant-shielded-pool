//! Execute-only runner for the pool aggregate guest (ENG-421, task 5.4
//! slice 1). Without the `prove` feature it never proves: the proving path
//! (`src/prove.rs`, task 5.4 slice 2b, ENG-510) is compiled only with it.
//!
//! ```text
//! apnt-pool-aggregate-runner list
//! apnt-pool-aggregate-runner execute --case NAME --elf PATH OUT.json
//! # only with the `prove` feature (ENG-510; src/prove.rs), through scripts/aggregate-proof-runner.sh:
//! apnt-pool-aggregate-runner proof-dry-run --batch b1|b17|live-bN --canonical-elf PATH [--live-input INPUT.json]
//! apnt-pool-aggregate-runner prove-groth16 --batch b1|b17|live-bN --canonical-elf PATH --output OUT.json --call-count-output COUNTS.json [--live-input INPUT.json]
//! ```
//!
//! Each case builds its guest input from the committed fixtures, executes the
//! ELF once under SP1's light (execute-only) client, and holds the result to
//! the case's expectation: a positive must exit 0 and commit exactly the host
//! codec's `runBind32`; a negative must exit non-zero, commit nothing, and
//! print exactly one refusal line naming the expected code. The native core
//! must agree with the guest on every case. One case per process, so the
//! peak RSS recorded is that case's.
//!
//! Registry entry 1 revision 3 (pad16, ENG-454): the guest takes 314-byte
//! records. The positives and most refusals run under the registry's recorded
//! Chipnet vp, with the action proofs of all 18 host positives made under its
//! ceremony keys (ENG-486; `fixtures/simulated-ceremony-zero-value-rev3/`).
//! SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY: the project could
//! forge proofs under those keys, so an accepted run shows the construction
//! and its cost, never validity. The development test build allowlists that
//! vp (`development-zero-value-test-profile`); the default build allowlists
//! nothing; the labelled Chipnet build (`chipnet-*` cases, ENG-510) allowlists
//! exactly that vp. A few refusals keep revision 2's DEVELOPMENT ZERO-VALUE
//! keys and proofs (forgeable; never for value; over 396-byte records): a
//! revision-2 proof over the same action's revision-3 record, and a second
//! stand-in Setup's key and proof. Each case runs only on an ELF that carries
//! its build's label. An ELF built in a worktree is path-dependent: its digest
//! is recorded as a measurement, never as a pin, unless it equals the canonical
//! Chipnet build's pin (`canonical-build/`).

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use anyhow::{bail, ensure, Context, Result};
use apnt_pool_aggregate_core::aggregate::{run, NoTrace};
use apnt_pool_aggregate_core::input::encode_input;
use apnt_pool_aggregate_core::profile::{
    CHIPNET_BUILD_LABEL, CHIPNET_ZERO_VALUE_LABEL, CHIPNET_ZERO_VALUE_REVISION_3_PROFILE_ID, DEFAULT_BUILD_LABEL, DEVELOPMENT_LABEL,
    DEVELOPMENT_ZERO_VALUE_ACTION_PROFILE_ID, DEVELOPMENT_ZERO_VALUE_STANDIN_PROFILE_ID,
};
use apnt_pool_aggregate_core::record::{offset, RECORD_BYTES};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sp1_sdk::blocking::{Prover, ProverClient};
use sp1_sdk::{Elf, SP1Stdin};

#[cfg(feature = "prove")]
mod prove;
#[cfg(feature = "prove")]
mod live;

const MEMORY_FLOOR_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const CYCLE_LIMIT: u64 = 2_000_000_000;
const REFUSAL_PREFIX: &str = "apnt-pool-aggregate-refusal: ";
const PROVER_LOCK: &str = "proof-scratch/.prover.lock";
const SHARED_PROVER_LOCK_PREFIX: &str = "/private/tmp/apnt-gnark-r2-proof-";
/// The canonical Chipnet build's pin record (ENG-510).
const CHIPNET_PIN_RECORD: &str = "canonical-build/chipnet-zero-value-rev3-canonical-build-v1.json";

fn tool(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join(path)
}
fn json_file(path: PathBuf) -> Result<Value> {
    #[cfg(test)]
    { return serde_json::from_slice(&fs::read(&path).map_err(|_| anyhow::anyhow!("pool-protected-C22-io"))?)
        .map_err(|_| anyhow::anyhow!("pool-protected-C22-json")); }
    #[cfg(not(test))]
    { Ok(serde_json::from_slice(&fs::read(&path).with_context(|| path.display().to_string())?)?) }
}
fn unhex(v: &Value) -> Result<Vec<u8>> {
    #[cfg(test)]
    { return hex::decode(v.as_str().context("pool-protected-C22-type")?)
        .map_err(|_| anyhow::anyhow!("pool-protected-C22-hex")); }
    #[cfg(not(test))]
    { Ok(hex::decode(v.as_str().context("hex string")?)?) }
}

/// Which build of the guest a case needs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Build {
    /// `development-zero-value-test-profile`: the two revision-2 development keys and revision 3's Chipnet vp allowlisted.
    Development,
    /// The default build: an empty allowlist.
    Default,
    /// The labelled Chipnet build (`apnt-pool-aggregate-program-chipnet-zero-value-rev3`):
    /// exactly revision 3's Chipnet zero-value vp allowlisted.
    Chipnet,
}

impl Build {
    fn name(self) -> &'static str {
        match self {
            Build::Development => "development",
            Build::Default => "default",
            Build::Chipnet => "chipnet",
        }
    }
    /// The label the build's guest keeps in its ELF (`program/src/main.rs`).
    fn label(self) -> &'static str {
        match self {
            Build::Development => DEVELOPMENT_LABEL,
            Build::Default => DEFAULT_BUILD_LABEL,
            Build::Chipnet => CHIPNET_BUILD_LABEL,
        }
    }
}

enum Expect {
    /// A positive commits exactly the host's runBind32 (v4 run vectors).
    Accept { run_bind: [u8; 32] },
    Refuse { code: &'static str },
}

/// Whose key the case's `vp` is, for its label.
#[derive(Clone, Copy)]
enum Keys {
    /// Revision 3's Chipnet vp, or a public transform of it.
    Ceremony,
    /// Revision 2's development keys.
    Development,
}

struct Case {
    name: String,
    note: &'static str,
    build: Build,
    keys: Keys,
    batch_size: usize,
    input: Vec<u8>,
    expect: Expect,
}

struct Fixtures {
    deployment: [u8; 32],
    /// Revision 2's stand-in key its batch proofs are under.
    vk: Vec<u8>,
    /// A second stand-in Setup's key and its REL1 proof (never allowlisted).
    key_c_vk: Vec<u8>,
    key_c_proof: Vec<u8>,
    /// The action circuit's own development key and its REL1 proof.
    action_vk: Vec<u8>,
    action_proof: Vec<u8>,
    /// (name, revision-3 record, revision-2 stand-in proof of that action's 396-byte record) in corpus order.
    batch: Vec<(String, [u8; RECORD_BYTES], Vec<u8>)>,
    /// Registry entry 1 revision 3's recorded Chipnet vp.
    ceremony_vp: Vec<u8>,
    /// Its δ-rescaled transform and REL1's proof under it (no Setup ran).
    ceremony_alt_vk: Vec<u8>,
    ceremony_alt_proof: Vec<u8>,
    /// Every host positive's ceremony proof, by entry name.
    ceremony_proofs: BTreeMap<String, Vec<u8>>,
    /// The host's accepted runs under the recorded vp (v4).
    runs: Value,
    /// The same under the current no-meter Chipnet deployment id (v5, ENG-510): what slice 2b proves.
    runs_no_meter: Value,
    reference_v3: Value,
}

fn rev2(path: &str) -> Result<Vec<u8>> {
    let path = tool(&format!("fixtures/development-zero-value-rev2/{path}"));
    #[cfg(test)]
    { return fs::read(&path).map_err(|_| anyhow::anyhow!("pool-protected-C22-io")); }
    #[cfg(not(test))]
    { fs::read(&path).with_context(|| path.display().to_string()) }
}

fn rev3(path: &str) -> Result<Vec<u8>> {
    let path = tool(&format!("fixtures/simulated-ceremony-zero-value-rev3/{path}"));
    #[cfg(test)]
    { return fs::read(&path).map_err(|_| anyhow::anyhow!("pool-protected-C22-io")); }
    #[cfg(not(test))]
    { fs::read(&path).with_context(|| path.display().to_string()) }
}

fn fixtures() -> Result<Fixtures> {
    // The revision-3 records come from the codec's statement vectors (v3); the
    // revision-2 proofs are of the same actions' 396-byte records (v1).
    let codec = json_file(tool("fixtures/pool-aggregate-statement-vectors-v3.json"))?;
    let b17 = codec["vectors"].as_array().context("vectors")?.iter().find(|x| x["name"] == "b17-reversed").context("b17")?;
    let mut batch = Vec::new();
    for (n, r) in b17["recordNames"].as_array().context("names")?.iter().zip(b17["records"].as_array().context("records")?) {
        let name = n.as_str().context("name")?.to_owned();
        let proof = rev2(&format!("standin/proofs-a/{name}.proof.bin"))?;
        batch.push((name, unhex(r)?.try_into().map_err(|_| anyhow::anyhow!("record length"))?, proof));
    }
    batch.reverse();
    ensure!(batch.len() == 17, "17 batch actions");
    ensure!(batch[0].0 == "rel1-real-real-deposit-withdrawal", "the first batch record is REL1");
    let registry = json_file(tool("../../packages/protocol-runtime/test-vectors/apnt-pool-v1-proof-system-registry-rev3-vectors.json"))?;
    ensure!(registry["chipnetZeroValueVp"]["label"] == CHIPNET_ZERO_VALUE_LABEL, "the registry's vp is not labelled");
    let runs = json_file(tool("fixtures/pool-aggregate-statement-vectors-v4.json"))?;
    ensure!(runs["deploymentId"] == codec["deploymentId"], "the run vectors' deployment is the codec's");
    let every = runs["vectors"].as_array().context("runs")?.iter().find(|x| x["name"] == "b18-every-positive-reversed").context("b18")?;
    let mut ceremony_proofs = BTreeMap::new();
    for n in every["recordNames"].as_array().context("names")? {
        let name = n.as_str().context("name")?.to_owned();
        let proof = rev3(&format!("proofs/{name}.proof.bin"))?;
        ceremony_proofs.insert(name, proof);
    }
    ensure!(ceremony_proofs.len() == 18, "18 ceremony proofs");
    Ok(Fixtures {
        deployment: unhex(&codec["deploymentId"])?.try_into().map_err(|_| anyhow::anyhow!("deployment"))?,
        ceremony_vp: unhex(&registry["chipnetZeroValueVp"]["vp"])?,
        ceremony_alt_vk: rev3("transform/alt-vk.bin")?,
        ceremony_alt_proof: rev3("transform/alt-proof.bin")?,
        ceremony_proofs,
        runs,
        runs_no_meter: json_file(tool("fixtures/pool-aggregate-statement-vectors-v5.json"))?,
        reference_v3: json_file(tool("fixtures/simulated-ceremony-zero-value-rev3/gnark-reference-v3.json"))?,
        vk: rev2("standin/key-a/vk.bin")?,
        key_c_vk: rev2("standin/key-c/vk.bin")?,
        key_c_proof: rev2("standin/proofs-c/rel1-real-real-deposit-withdrawal.proof.bin")?,
        action_vk: rev2("action/vk.bin")?,
        action_proof: rev2("action/rel1-real-real-deposit-withdrawal.proof.bin")?,
        batch,
    })
}

fn cases(f: &Fixtures) -> Result<Vec<Case>> {
    let b = &f.batch;
    let input = |vp: &[u8], actions: &[(&[u8], &[u8])]| encode_input(vp, &f.deployment, actions);
    let cp = |name: &str| -> Result<&[u8]> { Ok(f.ceremony_proofs.get(name).with_context(|| format!("no ceremony proof of {name}"))?.as_slice()) };
    let vp = f.ceremony_vp.as_slice();
    let mut out = Vec::new();
    // ---- positives: every run vector, its records in the vector's input order with their ceremony proofs ----
    for (name, vector) in [
        ("positive-b1", "b1-rel1"),
        ("positive-b2", "b2-reversed"),
        ("positive-b4", "b4-shuffled"),
        ("positive-b16", "b16-corpus-order"),
        ("positive-b17", "b17-reversed"),
        ("positive-b18", "b18-every-positive-reversed"),
    ] {
        let v = f.runs["vectors"].as_array().context("runs")?.iter().find(|x| x["name"] == vector).with_context(|| format!("no run vector {vector}"))?;
        let records: Vec<Vec<u8>> = v["records"].as_array().context("records")?.iter().map(unhex).collect::<Result<_>>()?;
        let mut actions = Vec::new();
        for (r, n) in records.iter().zip(v["recordNames"].as_array().context("names")?) {
            actions.push((r.as_slice(), cp(n.as_str().context("name")?)?));
        }
        out.push(Case {
            name: name.into(),
            note: "honest positive: distinct actions, each with its own action proof under the Chipnet ceremony keys (SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY)",
            build: Build::Development,
            keys: Keys::Ceremony,
            batch_size: actions.len(),
            input: input(vp, &actions),
            expect: Expect::Accept { run_bind: unhex(&v["runBind32"])?.try_into().map_err(|_| anyhow::anyhow!("runBind32"))? },
        });
    }
    let (r0, r1) = (&b[0].1, &b[1].1);
    ensure!(b[1].0 == "rel2-real-dummy-dummy-output", "the second batch record is REL2");
    let (p0, p1) = (cp(&b[0].0)?, cp(&b[1].0)?);
    let refuse = |name: &str, note: &'static str, build, keys, batch_size, input, code| Case {
        name: name.into(), note, build, keys, batch_size, input, expect: Expect::Refuse { code },
    };
    // ---- refusals beside the accepted runs, under the recorded vp ----
    let mut tampered = *r0;
    tampered[offset::FEE] ^= 1;
    out.push(refuse("negative-tampered-record", "REL1's fee low byte flipped, with REL1's ceremony proof; the record still decodes, and x changes",
        Build::Development, Keys::Ceremony, 1, input(vp, &[(&tampered, p0)]), "pool-aggregate-proof-rejected"));
    out.push(refuse("negative-proof-for-different-record", "REL1 and REL2 with their ceremony proofs swapped",
        Build::Development, Keys::Ceremony, 2, input(vp, &[(r0, p1), (r1, p0)]), "pool-aggregate-proof-rejected"));
    out.push(refuse("negative-proof-under-different-vp", "the δ-rescaled proof, valid under the rescaled key, offered under the recorded vp",
        Build::Development, Keys::Ceremony, 1, input(vp, &[(r0, &f.ceremony_alt_proof)]), "pool-aggregate-proof-rejected"));
    out.push(refuse("negative-prover-supplied-vp", "the δ-rescaled key with its own proof, which really verifies under it: a prover-supplied key the allowlist refuses",
        Build::Development, Keys::Ceremony, 1, input(&f.ceremony_alt_vk, &[(r0, &f.ceremony_alt_proof)]), "pool-aggregate-profile-not-allowlisted"));
    out.push(refuse("negative-default-build-ceremony-vp", "the default build (empty allowlist) with the recorded vp and REL1's honest ceremony proof",
        Build::Default, Keys::Ceremony, 1, input(vp, &[(r0, p0)]), "pool-aggregate-profile-not-allowlisted"));
    out.push(refuse("negative-duplicated-action", "one honest action twice",
        Build::Development, Keys::Ceremony, 2, input(vp, &[(r0, p0), (r0, p0)]), "pool-statement-order"));
    out.push(refuse("negative-b0", "no actions", Build::Development, Keys::Ceremony, 0, input(vp, &[]), "pool-statement-count"));
    let pok = f.reference_v3["cases"].as_array().context("cases")?.iter().find(|c| c["name"] == "proof:pok-plus-generator").context("pok case")?;
    ensure!(pok["vk"] == "batch" && unhex(&pok["record"])? == r0.as_slice(), "the pok case is REL1's under the recorded vp");
    let pok_proof = unhex(&pok["proof"])?;
    out.push(refuse("negative-pok-replaced", "REL1's ceremony proof with the BSB22 knowledge proof replaced by another valid point",
        Build::Development, Keys::Ceremony, 1, input(vp, &[(r0, &pok_proof)]), "pool-aggregate-commitment-knowledge"));
    let mut bad_key = *r0;
    bad_key[offset::RERANDOMIZED_KEY_0] = 0x04;
    out.push(refuse("negative-record-key", "rk_0 with an uncompressed-point prefix",
        Build::Development, Keys::Ceremony, 1, input(vp, &[(&bad_key, p0)]), "pool-record-key"));
    let mut dup_nf = *r1;
    dup_nf[offset::NULLIFIER_0..offset::NULLIFIER_0 + 32].copy_from_slice(&r0[offset::NULLIFIER_1..offset::NULLIFIER_1 + 32]);
    out.push(refuse("negative-duplicate-nullifier", "record 2's nf_0 equal to record 1's nf_1",
        Build::Development, Keys::Ceremony, 2, input(vp, &[(r0, p0), (&dup_nf, p1)]), "pool-statement-duplicate-nullifier"));
    let mut trailing = input(vp, &[(r0, p0)]);
    trailing.push(0);
    out.push(refuse("negative-input-trailing-byte", "one byte after the last action",
        Build::Development, Keys::Ceremony, 1, trailing, "pool-aggregate-input"));
    // Revision 2's framing: a 396-byte record in the 314-byte slot shifts every later field, so the input length refuses.
    let mut rev2_framed = input(vp, &[]);
    rev2_framed.truncate(rev2_framed.len() - 2);
    rev2_framed.extend_from_slice(&1u16.to_le_bytes());
    rev2_framed.extend_from_slice(&[0u8; 396]);
    rev2_framed.extend_from_slice(p0);
    out.push(refuse("negative-revision-2-record-length", "one action with a 396-byte record: the input no longer frames",
        Build::Development, Keys::Ceremony, 1, rev2_framed, "pool-aggregate-input"));
    // ---- refusals that keep revision 2's development keys and proofs ----
    out.push(refuse("negative-revision-2-proof-over-revision-3-record", "REL1's revision-3 record with the revision-2 stand-in proof of REL1's 396-byte record: x is computed over the 314-byte record in S, so the pairing refuses",
        Build::Development, Keys::Development, 1, input(&f.vk, &[(r0, &b[0].2)]), "pool-aggregate-proof-rejected"));
    out.push(refuse("negative-action-revision-2-proof-over-revision-3-record", "REL1's revision-3 record with the revision-2 action circuit's development proof of REL1's 396-byte record",
        Build::Development, Keys::Development, 1, input(&f.action_vk, &[(r0, &f.action_proof)]), "pool-aggregate-proof-rejected"));
    out.push(refuse("negative-prover-supplied-fresh-key", "a second stand-in Setup's key with its own proof; not allowlisted",
        Build::Development, Keys::Development, 1, input(&f.key_c_vk, &[(r0, &f.key_c_proof)]), "pool-aggregate-profile-not-allowlisted"));
    out.push(refuse("negative-proof-under-fresh-key", "a second stand-in Setup's proof offered under the recorded vp: its own Pedersen key fails the knowledge check, which does not read the record",
        Build::Development, Keys::Ceremony, 1, input(vp, &[(r0, &f.key_c_proof)]), "pool-aggregate-commitment-knowledge"));
    // ---- the labelled Chipnet build (ENG-510): its allowlist is exactly the recorded vp ----
    for (name, vector) in [("chipnet-positive-b1", "b1-rel1"), ("chipnet-positive-b17", "b17-reversed")] {
        let positive = out.iter().find(|c| c.name == format!("positive-b{}", &name["chipnet-positive-b".len()..])).context("positive")?;
        let Expect::Accept { run_bind } = positive.expect else { bail!("positive") };
        let v = f.runs["vectors"].as_array().context("runs")?.iter().find(|x| x["name"] == vector).context("vector")?;
        ensure!(hex::encode(run_bind) == v["runBind32"].as_str().context("runBind32")?, "the Chipnet positive's vector");
        out.push(Case {
            name: name.into(),
            note: "honest positive on the Chipnet build: the development positive's exact input, each action with its own proof under the Chipnet ceremony keys (SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY)",
            build: Build::Chipnet,
            keys: Keys::Ceremony,
            batch_size: positive.batch_size,
            input: positive.input.clone(),
            expect: Expect::Accept { run_bind },
        });
    }
    // The statements task 5.4 slice 2b proves: v5, under the current no-meter Chipnet deployment id.
    ensure!(f.runs_no_meter["profileId"] == f.runs["profileId"], "v5 binds the same profile id");
    for v in f.runs_no_meter["vectors"].as_array().context("v5")? {
        let records: Vec<Vec<u8>> = v["records"].as_array().context("records")?.iter().map(unhex).collect::<Result<_>>()?;
        let mut actions = Vec::new();
        for (r, n) in records.iter().zip(v["recordNames"].as_array().context("names")?) {
            actions.push((r.as_slice(), cp(n.as_str().context("name")?)?));
        }
        let deployment: [u8; 32] = unhex(&f.runs_no_meter["deploymentId"])?.try_into().map_err(|_| anyhow::anyhow!("deployment"))?;
        let name = v["name"].as_str().context("name")?;
        out.push(Case {
            name: format!("chipnet-no-meter-{name}"),
            note: "the Chipnet build on a statement under the current no-meter Chipnet deployment id (v5): the input task 5.4 slice 2b proves; ceremony proofs (SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY)",
            build: Build::Chipnet,
            keys: Keys::Ceremony,
            batch_size: actions.len(),
            input: encode_input(vp, &deployment, &actions),
            expect: Expect::Accept { run_bind: unhex(&v["runBind32"])?.try_into().map_err(|_| anyhow::anyhow!("runBind32"))? },
        });
    }
    // The refusals that need the pairing, beside those accepted runs.
    for (name, from) in [
        ("chipnet-negative-tampered-record", "negative-tampered-record"),
        ("chipnet-negative-proof-for-different-record", "negative-proof-for-different-record"),
        ("chipnet-negative-proof-under-different-vp", "negative-proof-under-different-vp"),
        ("chipnet-negative-pok-replaced", "negative-pok-replaced"),
        ("chipnet-negative-proof-under-fresh-key", "negative-proof-under-fresh-key"),
    ] {
        let c = out.iter().find(|c| c.name == from).context("pairing negative")?;
        let Expect::Refuse { code } = c.expect else { bail!("negative") };
        let (note, batch_size, input) = (c.note, c.batch_size, c.input.clone());
        out.push(refuse(name, note, Build::Chipnet, Keys::Ceremony, batch_size, input, code));
    }
    // Every other key, each with a proof that verifies under it, refused at the allowlist.
    out.push(refuse("chipnet-negative-revision-2-action-vp", "the revision-2 action circuit's development key with its own REL1 proof: not the Chipnet build's vp",
        Build::Chipnet, Keys::Development, 1, input(&f.action_vk, &[(r0, &f.action_proof)]), "pool-aggregate-profile-not-allowlisted"));
    out.push(refuse("chipnet-negative-revision-2-standin-vp", "the revision-2 stand-in key with its own REL1 proof: not the Chipnet build's vp",
        Build::Chipnet, Keys::Development, 1, input(&f.vk, &[(r0, &b[0].2)]), "pool-aggregate-profile-not-allowlisted"));
    out.push(refuse("chipnet-negative-second-standin-vp", "a second stand-in Setup's key with its own proof",
        Build::Chipnet, Keys::Development, 1, input(&f.key_c_vk, &[(r0, &f.key_c_proof)]), "pool-aggregate-profile-not-allowlisted"));
    out.push(refuse("chipnet-negative-prover-supplied-vp", "the δ-rescaled Chipnet key with its own proof, which really verifies under it: a prover-supplied key",
        Build::Chipnet, Keys::Ceremony, 1, input(&f.ceremony_alt_vk, &[(r0, &f.ceremony_alt_proof)]), "pool-aggregate-profile-not-allowlisted"));
    Ok(out)
}

fn allowlist(build: Build) -> Vec<[u8; 32]> {
    match build {
        Build::Development => {
            vec![DEVELOPMENT_ZERO_VALUE_ACTION_PROFILE_ID, DEVELOPMENT_ZERO_VALUE_STANDIN_PROFILE_ID, CHIPNET_ZERO_VALUE_REVISION_3_PROFILE_ID]
        }
        Build::Default => vec![],
        Build::Chipnet => vec![CHIPNET_ZERO_VALUE_REVISION_3_PROFILE_ID],
    }
}

/// `Some(record)` when the ELF is the canonical Chipnet build this checkout pins.
fn chipnet_pin(elf_sha256: &str, elf_bytes: usize) -> Result<Option<Value>> {
    let path = tool(CHIPNET_PIN_RECORD);
    if !path.exists() {
        return Ok(None);
    }
    let record = json_file(path)?;
    let pinned = &record["record"];
    let matches = pinned["guestElfSha256"].as_str() == Some(elf_sha256);
    ensure!(!matches || pinned["guestElfBytes"].as_u64() == Some(elf_bytes as u64), "the ELF has the pinned digest but not the pinned length");
    Ok(matches.then_some(record))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ---- machine state ----

fn available_and_swap() -> Result<(u64, String)> {
    let vm = Command::new("vm_stat").output()?;
    ensure!(vm.status.success(), "vm_stat failed");
    let text = String::from_utf8(vm.stdout)?;
    let page: u64 = text.lines().next().and_then(|l| l.split("page size of ").nth(1)).and_then(|v| v.split(' ').next()).context("page size")?.parse()?;
    let pages = |name: &str| -> Result<u64> {
        Ok(text.lines().find(|l| l.starts_with(name)).context("vm_stat field")?.split(':').nth(1).context("value")?.trim().trim_end_matches('.').parse()?)
    };
    let available = (pages("Pages free")? + pages("Pages inactive")? + pages("Pages speculative")?) * page;
    let swap = Command::new("sysctl").args(["-n", "vm.swapusage"]).output()?;
    Ok((available, String::from_utf8(swap.stdout)?.trim().to_owned()))
}

fn peak_rss_bytes() -> Result<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    ensure!(unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } == 0, "getrusage");
    let rss = unsafe { usage.assume_init() }.ru_maxrss as u64;
    Ok(if cfg!(target_os = "macos") { rss } else { rss * 1024 })
}

/// Runs `f` with fd 2 redirected to a file, and returns what was written.
fn capture_stderr<T>(scratch: &Path, f: impl FnOnce() -> T) -> Result<(T, String)> {
    let path = scratch.join(format!("stderr-{}.txt", std::process::id()));
    let file = fs::File::create(&path)?;
    let saved = unsafe { libc::dup(2) };
    ensure!(saved >= 0, "dup");
    ensure!(unsafe { libc::dup2(file.as_raw_fd(), 2) } >= 0, "dup2");
    let out = f();
    unsafe {
        libc::dup2(saved, 2);
        libc::close(saved);
    }
    let mut text = String::new();
    fs::File::open(&path)?.read_to_string(&mut text)?;
    fs::remove_file(&path)?;
    Ok((out, text))
}

fn refusals(stderr: &str) -> Vec<String> {
    stderr.lines().filter_map(|l| l.split(REFUSAL_PREFIX).nth(1)).map(|c| c.trim().to_owned()).collect()
}

fn execute(case_name: &str, elf_path: &Path, out: &Path) -> Result<()> {
    for key in ["RAYON_NUM_THREADS", "CARGO_BUILD_JOBS"] {
        ensure!(std::env::var(key).as_deref() == Ok("4"), "{key} must equal 4");
    }
    // Execution is not proving, but it still waits for the machine: no run
    // while another prover holds a lock.
    let home = std::env::var("HOME")?;
    ensure!(!Path::new(&home).join(PROVER_LOCK).exists(), "~/{PROVER_LOCK} exists: another prover holds the machine");
    let (available, swap_before) = available_and_swap()?;
    ensure!(available >= MEMORY_FLOOR_BYTES, "available memory {available} is below the 16 GiB floor");

    let f = fixtures()?;
    let case = cases(&f)?.into_iter().find(|c| c.name == case_name).with_context(|| format!("no case {case_name}"))?;
    let elf_bytes = fs::read(elf_path)?;
    let elf_sha256 = hex::encode(Sha256::digest(&elf_bytes));
    // A case runs only on an ELF of its own build: each build keeps its label in the ELF.
    ensure!(contains(&elf_bytes, case.build.label().as_bytes()), "the ELF does not carry the {} build's label", case.build.name());
    for other in [Build::Development, Build::Default, Build::Chipnet] {
        ensure!(other.label() == case.build.label() || !contains(&elf_bytes, other.label().as_bytes()), "the ELF carries the {} build's label", other.name());
    }
    let pin = chipnet_pin(&elf_sha256, elf_bytes.len())?;
    ensure!(pin.is_none() || case.build == Build::Chipnet, "the pinned Chipnet ELF offered for a {} case", case.build.name());

    // The native core, with the allowlist of the build the case needs.
    let native = run(&case.input, &allowlist(case.build), &mut NoTrace);
    match (&case.expect, &native) {
        (Expect::Accept { run_bind }, Ok(a)) => ensure!(&a.run_bind == run_bind, "native run bind differs from the host vector"),
        (Expect::Refuse { code }, Err(e)) => ensure!(e.code() == *code, "native refusal {} is not {code}", e.code()),
        _ => bail!("native core disagrees with the case's expectation"),
    }

    let scratch = out.parent().context("OUT parent")?.to_path_buf();
    let client = ProverClient::builder().light().build();
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(case.input.clone());
    let started = Instant::now();
    let (result, stderr) = capture_stderr(&scratch, || {
        client.execute(Elf::from(elf_bytes.clone()), stdin).calculate_gas(true).cycle_limit(CYCLE_LIMIT).run()
    })?;
    let execute_millis = started.elapsed().as_millis();
    let (values, report) = result.with_context(|| format!("case {case_name} returned no execution report"))?;
    let public = values.as_slice().to_vec();
    let refused = refusals(&stderr);
    match &case.expect {
        Expect::Accept { run_bind } => {
            ensure!(report.exit_code == 0, "positive {case_name}: exit {}", report.exit_code);
            ensure!(public == run_bind, "positive {case_name}: committed {} is not the host runBind32", hex::encode(&public));
            ensure!(refused.is_empty(), "positive {case_name} printed a refusal");
        }
        Expect::Refuse { code } => {
            // An SP1 guest panic returns Ok with a non-zero exit code.
            ensure!(report.exit_code != 0, "negative {case_name} exited 0");
            ensure!(public.is_empty(), "negative {case_name} committed {} bytes", public.len());
            ensure!(refused == [code.to_string()], "negative {case_name}: refusals {refused:?}, want [{code}]; guest stderr:\n{stderr}");
        }
    }
    let syscalls: BTreeMap<String, u64> =
        report.syscall_counts.iter().filter(|(_, n)| **n > 0).map(|(code, n)| (format!("{code:?}"), *n)).collect();
    let (_, swap_after) = available_and_swap()?;
    let result = json!({
        "parameters": match case.keys {
            Keys::Ceremony => format!("{CHIPNET_ZERO_VALUE_LABEL}: the project could forge proofs under these keys; never for value"),
            Keys::Development => DEVELOPMENT_LABEL.to_owned(),
        },
        "case": case.name,
        "note": case.note,
        "build": match case.build {
            Build::Development => "development-zero-value-test-profile",
            Build::Default => "default",
            Build::Chipnet => "chipnet-zero-value-rev3 (apnt-pool-aggregate-program-chipnet-zero-value-rev3)",
        },
        "buildLabel": case.build.label(),
        "batchSize": case.batch_size,
        "inputBytes": case.input.len(),
        "expected": match &case.expect {
            Expect::Accept { run_bind } => json!({ "accept": true, "runBind32": hex::encode(run_bind) }),
            Expect::Refuse { code } => json!({ "accept": false, "refusal": code }),
        },
        "elf": { "path": elf_path, "bytes": elf_bytes.len(), "sha256": elf_sha256,
                 "canonicalPin": pin.as_ref().map(|r| json!({ "record": CHIPNET_PIN_RECORD, "programVkeyHash": r["record"]["programVkeyHash"] })),
                 "note": if pin.is_some() {
                     "the canonical Chipnet build (tools/sp1-canonical-guest-build), equal to this checkout's pin"
                 } else {
                     "not a pinned canonical ELF: a local build is path-dependent, a measurement only, never a pin"
                 } },
        "exitCode": report.exit_code,
        "committedHex": hex::encode(&public),
        "refusals": refused,
        "totalInstructions": report.total_instruction_count(),
        "totalSyscalls": report.total_syscall_count(),
        "gas": report.gas(),
        "touchedMemoryAddresses": report.touched_memory_addresses,
        "syscallCounts": syscalls,
        "cycleTracker": report.cycle_tracker,
        "invocationTracker": report.invocation_tracker,
        "executeMillis": execute_millis,
        "processPeakRssBytes": peak_rss_bytes()?,
        "availableBytesBefore": available,
        "swapBefore": swap_before,
        "swapAfter": swap_after,
        "sp1Sdk": "6.3.1",
        "client": "sp1_sdk::blocking light (execute-only); no proof constructed",
        "sharedProverLockPrefix": SHARED_PROVER_LOCK_PREFIX,
    });
    let mut text = serde_json::to_vec_pretty(&result)?;
    text.push(b'\n');
    fs::write(out, text)?;
    println!("{case_name}: exit {} instructions {} gas {:?}", report.exit_code, report.total_instruction_count(), report.gas());
    Ok(())
}

fn main() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(feature = "prove")]
    let proof_network = if args.get(1).map(String::as_str) == Some("--network") {
        ensure!(args.len() >= 3, "pool-network-required");
        let network = prove::ProofNetwork::parse(&args[2])?;
        args.drain(1..3);
        network
    } else {
        prove::ProofNetwork::Chipnet
    };
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["list"] => {
            let f = fixtures()?;
            for c in cases(&f)? {
                println!("{} {}", c.name, c.build.name());
            }
            Ok(())
        }
        ["execute", "--case", name, "--elf", elf, out] => execute(name, Path::new(elf), Path::new(out)),
        #[cfg(feature = "prove")]
        ["proof-dry-run", "--batch", batch, "--canonical-elf", elf] => prove::dry_run(proof_network, batch, Path::new(elf), None),
        #[cfg(feature = "prove")]
        ["prove-groth16", "--batch", batch, "--canonical-elf", elf, "--output", out, "--call-count-output", counts] => {
            prove::prove(proof_network, batch, Path::new(elf), Path::new(out), Path::new(counts), None)
        }
        #[cfg(feature = "prove")]
        ["proof-dry-run", "--batch", batch, "--canonical-elf", elf, "--live-input", input] => {
            prove::dry_run(proof_network, batch, Path::new(elf), Some(Path::new(input)))
        }
        #[cfg(feature = "prove")]
        ["prove-groth16", "--batch", batch, "--canonical-elf", elf, "--output", out, "--call-count-output", counts, "--live-input", input] => {
            prove::prove(proof_network, batch, Path::new(elf), Path::new(out), Path::new(counts), Some(Path::new(input)))
        }
        _ => bail!(
            "usage: apnt-pool-aggregate-runner list | execute --case NAME --elf PATH OUT.json{}",
            if cfg!(feature = "prove") {
                " | proof-dry-run --batch b1|b17|live-bN --canonical-elf PATH [--live-input INPUT.json] | prove-groth16 --batch b1|b17|live-bN --canonical-elf PATH --output OUT.json --call-count-output COUNTS.json [--live-input INPUT.json] (required for live-bN)"
            } else {
                ""
            }
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_lines_are_read_exactly() {
        assert_eq!(refusals("stderr: apnt-pool-aggregate-refusal: pool-record-key\nstderr: panicked at x"), ["pool-record-key"]);
        assert!(refusals("stdout: nothing").is_empty());
    }

    #[test]
    fn build_labels_are_distinct_and_none_contains_another() {
        let all = [Build::Development, Build::Default, Build::Chipnet];
        for a in all {
            for b in all {
                if a != b {
                    assert!(!a.label().contains(b.label()), "{} contains {}", a.name(), b.name());
                }
            }
        }
        assert!(contains(b"xxAPNTyy", b"APNT") && !contains(b"xxAPNyy", b"APNT"));
    }

    #[test]
    #[ignore = "requires excluded frozen proof and reference inputs; not shipped"]
    fn every_case_agrees_with_the_native_core() {
        static HOOK: std::sync::Once = std::sync::Once::new();
        HOOK.call_once(|| std::panic::set_hook(Box::new(|_| eprintln!("pool-protected-C22-panic"))));
        let result = std::panic::catch_unwind(|| {
        let f = fixtures().unwrap_or_else(|_| panic!("pool-protected-C22-fixtures"));
        let all = cases(&f).unwrap_or_else(|_| panic!("pool-protected-C22-cases"));
        assert_eq!(all.len(), 36);
        assert_eq!(all.iter().filter(|c| matches!(c.expect, Expect::Accept { .. })).count(), 11);
        let chipnet: Vec<_> = all.iter().filter(|c| c.build == Build::Chipnet).collect();
        assert_eq!(chipnet.len(), 14);
        assert!(chipnet.iter().all(|c| c.name.starts_with("chipnet-")));
        assert_eq!(chipnet.iter().filter(|c| matches!(c.expect, Expect::Refuse { code: "pool-aggregate-profile-not-allowlisted" })).count(), 4);
        for (ordinal, c) in all.iter().enumerate() {
            let native = run(&c.input, &allowlist(c.build), &mut NoTrace);
            match (&c.expect, native) {
                (Expect::Accept { run_bind }, Ok(a)) => assert!(&a.run_bind == run_bind, "pool-protected-C22-equal:{ordinal}"),
                (Expect::Refuse { code }, Err(e)) => assert!(e.code() == *code, "pool-protected-C22-refusal:{ordinal}"),
                _ => panic!("pool-protected-C22-verdict:{ordinal}"),
            }
        }
        });
        if result.is_err() { panic!("pool-protected-C22-panic"); }
    }
}
