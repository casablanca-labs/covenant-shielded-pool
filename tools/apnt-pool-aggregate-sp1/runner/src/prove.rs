//! Task 5.4 slice 2b's proving path, written by ENG-510 (slice 2a) and run by slice 2b. Compiled
//! only with the `prove` feature and reached only through `scripts/aggregate-proof-runner.sh`,
//! which holds the machine's gates (one prover, the 20 GiB floor, the swap-growth and RSS trips,
//! a clean main checkout, the operator's authorization token).
//!
//! It selects the canonical Chipnet ELF and fixture statements by default. The separate local
//! 0x99 path selects its own canonical ELF and accepts a host-verified canonical live batch.
//! Both paths check SHA-256, length, program key and the zero-value label independently.
//! SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY: the children are verified under a key the
//! project could forge proofs for, so a proof here shows the construction and its cost, never
//! validity.
//!
//! `proof-dry-run` executes the guest (light client) and calls neither setup nor prove.
//! `prove-groth16` calls setup once and prove once: the SP1 core, compress and shrink stages, then
//! the Groth16 wrap through SP1 6.3.1's Docker gnark image. It checks the program key against the
//! pin, the public values against the host's runBind32, native verification, and that a
//! corrupted proof is refused, then writes the evidence file the one-transaction verifier's
//! scripts read (`tools/pool-onetx-verifier-prototype/scripts/derive-wrapper-vectors.mjs`).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::{bail, ensure, Context, Result};
use serde_json::json;
use sha2::{Digest, Sha256};
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::{Elf, HashableKey, ProvingKey, SP1Proof, SP1Stdin};

use super::{cases, fixtures, json_file, tool, Build, Expect, CHIPNET_PIN_RECORD, CYCLE_LIMIT};
use apnt_pool_aggregate_core::profile::CHIPNET_ZERO_VALUE_LABEL;

const LOCAL_PIN_RECORD: &str = "../apnt-pool-aggregate-local-sp1/canonical-build/local-zero-value-canonical-build-v1.json";
const LOCAL_ZERO_VALUE_LABEL: &str = "LOCAL 0x99 - SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofNetwork { Chipnet, Local }

impl ProofNetwork {
    pub fn parse(s: &str) -> Result<Self> {
        match s { "chipnet" => Ok(Self::Chipnet), "local" => Ok(Self::Local), _ => bail!("pool-network-unsupported") }
    }
    pub fn name(self) -> &'static str { match self { Self::Chipnet => "chipnet", Self::Local => "local" } }
    pub fn label(self) -> &'static str { match self { Self::Chipnet => CHIPNET_ZERO_VALUE_LABEL, Self::Local => LOCAL_ZERO_VALUE_LABEL } }
    pub fn pin_record(self) -> &'static str { match self { Self::Chipnet => CHIPNET_PIN_RECORD, Self::Local => LOCAL_PIN_RECORD } }
    pub fn pin_path(self) -> &'static str {
        match self {
            Self::Chipnet => "tools/apnt-pool-aggregate-sp1/canonical-build/chipnet-zero-value-rev3-canonical-build-v1.json",
            Self::Local => "tools/apnt-pool-aggregate-local-sp1/canonical-build/local-zero-value-canonical-build-v1.json",
        }
    }
}

/// The fixture statements: (batch, runner case), both v5. Live inputs use `live-bN`.
pub const PROVABLE: [(&str, &str); 2] = [("b1", "chipnet-no-meter-b1-rel1"), ("b17", "chipnet-no-meter-b17-reversed")];
pub const EVIDENCE_SCHEMA: &str = "apnt-pool-aggregate-groth16-proof-evidence-v1";
const COUNTS_SCHEMA: &str = "apnt-pool-aggregate-sdk-call-counts-v1";

struct Pinned {
    sha256: String,
    bytes: usize,
    vkey: String,
}

fn pinned(network: ProofNetwork) -> Result<Pinned> {
    let record = json_file(tool(network.pin_record()))?;
    ensure!(record["label"] == network.label(), "the pin record is not labelled for {}", network.name());
    let r = &record["record"];
    Ok(Pinned {
        sha256: r["guestElfSha256"].as_str().context("pinned digest")?.to_owned(),
        bytes: r["guestElfBytes"].as_u64().context("pinned length")? as usize,
        vkey: r["programVkeyHash"].as_str().context("pinned program key")?.to_owned(),
    })
}

/// The canonical ELF's bytes, refused unless they are exactly the pinned ones.
fn exact_elf(path: &Path, pin: &Pinned) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).context("canonical ELF metadata")?;
    ensure!(meta.is_file() && !meta.file_type().is_symlink(), "the canonical ELF is not a regular file");
    let bytes = fs::read(path)?;
    ensure!(bytes.len() == pin.bytes, "canonical ELF length {} is not the pinned {}", bytes.len(), pin.bytes);
    ensure!(hex::encode(Sha256::digest(&bytes)) == pin.sha256, "canonical ELF digest is not the pinned one");
    Ok(bytes)
}

struct Statement {
    case: String,
    batch_size: usize,
    input: Vec<u8>,
    run_bind: [u8; 32],
    deployment: String,
    profile: String,
}

fn statement(network: ProofNetwork, batch: &str, live_input: Option<&Path>) -> Result<Statement> {
    if let Some(count) = batch.strip_prefix("live-b") {
        let size: usize = count.parse().map_err(|_| anyhow::anyhow!("pool-live-batch-selector"))?;
        ensure!(size >= 1 && size <= apnt_pool_aggregate_core::statement::MAXIMUM_ACTIONS
            && count == size.to_string(), "pool-live-batch-selector");
        let admitted = super::live::read(network, live_input.context("pool-live-input-required")?)?;
        ensure!(admitted.batch_size == size, "pool-live-batch-selector-mismatch");
        return Ok(Statement {
            case: batch.to_owned(), batch_size: size,
            input: admitted.input, run_bind: admitted.run_bind,
            deployment: hex::encode(admitted.deployment), profile: hex::encode(admitted.profile),
        });
    }
    ensure!(network == ProofNetwork::Chipnet, "pool-local-live-batch-required");
    ensure!(live_input.is_none(), "pool-live-input-requires-live-batch");
    let name = PROVABLE.iter().find(|(b, _)| *b == batch).map(|(_, n)| *n).with_context(|| format!("batch {batch} is not provable here (b1 or b17)"))?;
    let f = fixtures()?;
    let case = cases(&f)?.into_iter().find(|c| c.name == name).with_context(|| format!("no case {name}"))?;
    ensure!(case.build == Build::Chipnet, "{name} is not a Chipnet-build case");
    let Expect::Accept { run_bind } = case.expect else { bail!("{name} is not a positive") };
    let (deployment, profile) = v5_ids()?;
    Ok(Statement { case: case.name, batch_size: case.batch_size, input: case.input, run_bind, deployment, profile })
}

fn v5_ids() -> Result<(String, String)> {
    let v5 = json_file(tool("fixtures/pool-aggregate-statement-vectors-v5.json"))?;
    Ok((v5["deploymentId"].as_str().context("deployment")?.to_owned(), v5["profileId"].as_str().context("profile")?.to_owned()))
}

/// Execute only: the pinned ELF over the statement, exit 0 and exactly the host's runBind32.
pub fn dry_run(network: ProofNetwork, batch: &str, elf_path: &Path, live_input: Option<&Path>) -> Result<()> {
    let st = statement(network, batch, live_input)?;
    let pin = pinned(network)?;
    let elf = exact_elf(elf_path, &pin)?;
    let client = ProverClient::builder().light().build();
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(st.input.clone());
    let started = Instant::now();
    let (values, report) = client
        .execute(Elf::from(elf), stdin)
        .calculate_gas(true)
        .cycle_limit(CYCLE_LIMIT)
        .run()
        .context("the guest returned no execution report")?;
    // An SP1 guest panic returns Ok with a non-zero exit code.
    ensure!(report.exit_code == 0, "the guest exited {}", report.exit_code);
    ensure!(values.as_slice() == st.run_bind, "the guest committed {}, not the host runBind32", hex::encode(values.as_slice()));
    let out = json!({
        "schema": "apnt-pool-aggregate-proof-dry-run-v1",
        "label": network.label(),
        "network": network.name(),
        "batch": batch,
        "case": st.case,
        "batchSize": st.batch_size,
        "deploymentId": st.deployment,
        "profileId": st.profile,
        "inputBytes": st.input.len(),
        "inputSha256": hex::encode(Sha256::digest(&st.input)),
        "runBind32": hex::encode(st.run_bind),
        "canonicalElfSha256": pin.sha256,
        "canonicalElfBytes": pin.bytes,
        "programVkeyHash": pin.vkey,
        "programVkeySource": "the pin record; setup is not called by a dry run",
        "exitCode": report.exit_code,
        "committedHex": hex::encode(values.as_slice()),
        "totalInstructions": report.total_instruction_count(),
        "gas": report.gas(),
        "executeMillis": started.elapsed().as_millis() as u64,
        "processPeakRssBytes": super::peak_rss_bytes()?,
        "client": "sp1_sdk::blocking light (execute only)",
        "proofConstructed": false,
        "setupCallCount": 0,
        "proveCallCount": 0,
    });
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

static SETUP_CALLS: AtomicUsize = AtomicUsize::new(0);
static PROVE_CALLS: AtomicUsize = AtomicUsize::new(0);

fn write_counts(path: &Path) -> Result<()> {
    let body = serde_json::to_vec(&json!({
        "schema": COUNTS_SCHEMA,
        "setupCallCount": SETUP_CALLS.load(Ordering::SeqCst),
        "proveCallCount": PROVE_CALLS.load(Ordering::SeqCst),
    }))?;
    let mut file = OpenOptions::new().write(true).create(true).truncate(true).open(path).context("call-count sidecar")?;
    file.write_all(&body)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

/// One setup and one Groth16 proof of the pinned canonical ELF over the statement.
pub fn prove(network: ProofNetwork, batch: &str, elf_path: &Path, output: &Path, counts: &Path, live_input: Option<&Path>) -> Result<()> {
    let st = statement(network, batch, live_input)?;
    let pin = pinned(network)?;
    let elf = exact_elf(elf_path, &pin)?;
    ensure!(!output.exists() && !counts.exists(), "the proof output or the call-count sidecar already exists");
    write_counts(counts)?;

    let client = ProverClient::builder().cpu().build();
    SETUP_CALLS.fetch_add(1, Ordering::SeqCst);
    write_counts(counts)?;
    let setup_started = Instant::now();
    let pk = client.setup(Elf::from(elf)).with_context(|| format!("SP1 setup of the canonical {} ELF failed", network.name()))?;
    let setup_millis = setup_started.elapsed().as_millis() as u64;
    let vkey = pk.verifying_key().bytes32();
    let vkey = vkey.strip_prefix("0x").context("program key without its 0x prefix")?.to_owned();
    ensure!(vkey == pin.vkey, "program key {vkey} is not the pinned {}", pin.vkey);

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(st.input.clone());
    // The only prove call site: compiled only with the `prove` feature, reached only through the
    // gated harness with the operator's authorization token.
    PROVE_CALLS.fetch_add(1, Ordering::SeqCst);
    write_counts(counts)?;
    let started = Instant::now();
    let proof = client.prove(&pk, stdin).groth16().with_proof_nonce([0; 4]).run().context("SP1 Groth16 aggregate proof construction failed")?;
    let prove_millis = started.elapsed().as_millis() as u64;
    ensure!(proof.public_values.as_slice() == st.run_bind, "the proof's public values are not the host runBind32");

    ensure!(client.verify(&proof, pk.verifying_key(), None).is_ok(), "native verification refused the fresh proof");
    let mut corrupted = proof.clone();
    let SP1Proof::Groth16(inner) = &mut corrupted.proof else { bail!("the prover did not return a Groth16 proof") };
    let first = inner.encoded_proof.as_bytes().first().copied().context("empty encoded proof")?;
    inner.encoded_proof.replace_range(0..1, if first == b'0' { "1" } else { "0" });
    ensure!(client.verify(&corrupted, pk.verifying_key(), None).is_err(), "native verification accepted a corrupted proof");

    let evidence = json!({
        "schema": EVIDENCE_SCHEMA,
        "label": format!("{}: a proof of the labelled {} build; its children are verified under a key the project could forge proofs for; never for value", network.label(), network.name()),
        "network": network.name(),
        "batch": batch,
        "case": st.case,
        "batchSize": st.batch_size,
        "deploymentId": st.deployment,
        "profileId": st.profile,
        "inputSha256": hex::encode(Sha256::digest(&st.input)),
        "runBind32": hex::encode(st.run_bind),
        "canonicalElfSha256": pin.sha256,
        "canonicalElfBytes": pin.bytes,
        "programVkeyHash": vkey,
        "pinRecord": network.pin_path(),
        "publicValuesCodec": "runBind32",
        "publicValuesHex": hex::encode(proof.public_values.as_slice()),
        "proofBytesHex": hex::encode(proof.bytes()),
        "proofNonce": "00000000",
        "setupMillis": setup_millis,
        "proofConstructionMillis": prove_millis,
        "nativeVerificationSucceeded": true,
        "corruptedProofRejected": true,
        "setupCallCount": SETUP_CALLS.load(Ordering::SeqCst),
        "proveCallCount": PROVE_CALLS.load(Ordering::SeqCst),
        "chainValidated": false,
        "walletAccepted": false,
    });
    let mut file = OpenOptions::new().write(true).create_new(true).open(output)?;
    file.write_all(&serde_json::to_vec_pretty(&evidence)?)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    write_counts(counts)?;
    println!("proved {batch}: setup {setup_millis} ms, prove {prove_millis} ms");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_provable_statements_are_the_v5_chipnet_positives() {
        let (deployment, profile) = v5_ids().unwrap();
        let v5 = json_file(tool("fixtures/pool-aggregate-statement-vectors-v5.json")).unwrap();
        for (batch, want) in [("b1", "b1-rel1"), ("b17", "b17-reversed")] {
            let st = statement(ProofNetwork::Chipnet, batch, None).unwrap();
            let v = v5["vectors"].as_array().unwrap().iter().find(|x| x["name"] == want).unwrap();
            assert_eq!(hex::encode(st.run_bind), v["runBind32"].as_str().unwrap());
            assert_eq!(st.batch_size, v["records"].as_array().unwrap().len());
            // The input frames the v5 deployment id right after the vp.
            let vp_len = u32::from_le_bytes(st.input[..4].try_into().unwrap()) as usize;
            assert_eq!(hex::encode(&st.input[4 + vp_len..4 + vp_len + 32]), deployment);
        }
        assert_eq!(profile, "ea3d52d762f394b2959740126c3fb441165236696a02314a19498b48e2f1c1f2");
        assert!(statement(ProofNetwork::Chipnet, "b16", None).is_err() && statement(ProofNetwork::Chipnet, "b2", None).is_err());
    }

    #[test]
    fn only_the_pinned_elf_is_accepted() {
        let pin = pinned(ProofNetwork::Chipnet).unwrap();
        assert_eq!(pin.vkey, "00a69d739feae9fecf1ad3db30a73f967912fda951c849e374492f1a14fd7fed");
        let dir = std::env::temp_dir().join(format!("eng510-exact-elf-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let wrong_length = dir.join("short");
        fs::write(&wrong_length, vec![0u8; 16]).unwrap();
        assert!(exact_elf(&wrong_length, &pin).unwrap_err().to_string().contains("length"));
        let wrong_digest = dir.join("same-length");
        fs::write(&wrong_digest, vec![0u8; pin.bytes]).unwrap();
        assert!(exact_elf(&wrong_digest, &pin).unwrap_err().to_string().contains("digest"));
        let link = dir.join("link");
        std::os::unix::fs::symlink(&wrong_digest, &link).unwrap();
        assert!(exact_elf(&link, &pin).unwrap_err().to_string().contains("regular file"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn local_and_chipnet_pins_are_distinct_and_local_requires_live_b1() {
        let local = pinned(ProofNetwork::Local).unwrap();
        let chipnet = pinned(ProofNetwork::Chipnet).unwrap();
        assert_eq!(local.bytes, 443696);
        assert_eq!(local.vkey, "008b67415acd3c7ae6e9c2ad0887a6ae6a322c4b1da8b97670b217255f0067ca");
        assert_ne!(local.sha256, chipnet.sha256);
        assert_ne!(local.vkey, chipnet.vkey);
        assert_eq!(statement(ProofNetwork::Local, "b1", None).err().unwrap().to_string(), "pool-local-live-batch-required");
        assert_eq!(ProofNetwork::parse("regtest").unwrap_err().to_string(), "pool-network-unsupported");
    }
}
