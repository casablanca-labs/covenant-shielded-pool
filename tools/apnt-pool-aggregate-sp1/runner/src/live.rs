//! Host-only admission for a canonical live-shaped zero-value batch. No witness, key supplied by the
//! caller, acceptance flag, setup or prover: verification uses the guest's unchanged core.

use std::{fs::File, io::Read, path::Path};

use anyhow::{ensure, Context, Result};
use apnt_pool_aggregate_core::{
    aggregate::{run, NoTrace},
    groth16::PROOF_BYTES,
    input::encode_input,
    profile::{derive_profile_id, CHIPNET_ZERO_VALUE_LABEL, CHIPNET_ZERO_VALUE_REVISION_3_PROFILE_ID, SYSTEM_ID_GNARK_GROTH16_BN254},
    record::{check_record, RECORD_BYTES},
    statement::{action_authorization_digest, MAXIMUM_ACTIONS},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{json_file, tool};
use super::prove::ProofNetwork;

pub const SCHEMA: &str = "apnt-pool-aggregate-live-input-v1";
// Enough for the maximum canonical JSON batch, including pretty-print whitespace.
const MAX_FILE_BYTES: u64 = 1024 + (2 * (RECORD_BYTES + PROOF_BYTES) + 128) as u64 * MAXIMUM_ACTIONS as u64;

pub struct Admitted {
    pub input: Vec<u8>,
    pub run_bind: [u8; 32],
    pub deployment: [u8; 32],
    pub profile: [u8; 32],
    pub batch_size: usize,
}

fn fields(value: &Value, keys: &[&str]) -> Result<()> {
    let object = value.as_object().context("pool-live-input-fields")?;
    ensure!(object.len() == keys.len() && keys.iter().all(|k| object.contains_key(*k)), "pool-live-input-fields");
    Ok(())
}

fn bytes(value: &Value, length: usize, code: &'static str) -> Result<Vec<u8>> {
    let s = value.as_str().context(code)?;
    ensure!(s.len() == length * 2 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)), "{code}");
    hex::decode(s).context(code)
}

pub fn read(network: ProofNetwork, path: &Path) -> Result<Admitted> {
    // Bound allocation even for a file that grows after metadata is inspected. Do not echo
    // caller data or serde's error text (which can contain an unexpected field's contents).
    let meta = std::fs::symlink_metadata(path).context("pool-live-input-file")?;
    ensure!(meta.is_file() && !meta.file_type().is_symlink(), "pool-live-input-file");
    let mut data = Vec::new();
    File::open(path).context("pool-live-input-file")?.take(MAX_FILE_BYTES + 1).read_to_end(&mut data).context("pool-live-input-file")?;
    ensure!(data.len() as u64 <= MAX_FILE_BYTES, "pool-live-input-size");
    let value: Value = serde_json::from_slice(&data).map_err(|_| anyhow::anyhow!("pool-live-input-json"))?;
    admit(network, &value)
}

fn admit(network: ProofNetwork, value: &Value) -> Result<Admitted> {
    fields(value, &["schema", "label", "deploymentId", "profileId", "actions"])?;
    ensure!(value["schema"] == SCHEMA, "pool-live-input-schema");
    ensure!(value["label"] == network.label(), "pool-live-input-label");
    let actions = value["actions"].as_array().context("pool-live-input-actions")?;
    ensure!(!actions.is_empty() && actions.len() <= MAXIMUM_ACTIONS, "pool-live-batch-size");
    let deployment: [u8; 32] = bytes(&value["deploymentId"], 32, "pool-live-deployment-id")?.try_into().unwrap();
    let profile: [u8; 32] = bytes(&value["profileId"], 32, "pool-live-profile-id")?.try_into().unwrap();
    // The host runner's default core has an empty allowlist; both recorded builds
    // intentionally share this single child VP id, held to the selected pin.
    let allowlist = [CHIPNET_ZERO_VALUE_REVISION_3_PROFILE_ID];
    ensure!(allowlist.contains(&profile), "pool-aggregate-profile-not-allowlisted");
    let pins = json_file(tool(network.pin_record()))?;
    ensure!(pins["label"] == network.label()
        && pins["record"]["compiledAllowlist"] == json!([hex::encode(allowlist[0])]), "pool-live-profile-pin");
    let registry = json_file(tool("../../packages/protocol-runtime/test-vectors/apnt-pool-v1-proof-system-registry-rev3-vectors.json"))?;
    let entry = &registry["chipnetZeroValueVp"];
    ensure!(entry["label"] == CHIPNET_ZERO_VALUE_LABEL, "pool-live-vp-pin");
    let vp = bytes(&entry["vp"], 528, "pool-live-vp-pin")?;
    let vp_pin = &pins["record"]["allowlistedVp"];
    ensure!(vp_pin["vpBytes"] == vp.len() && vp_pin["vpSha256"] == hex::encode(Sha256::digest(&vp))
        && vp_pin["profileId"] == hex::encode(profile)
        && derive_profile_id(SYSTEM_ID_GNARK_GROTH16_BN254, &vp).map_err(|e| anyhow::anyhow!(e.code()))? == profile,
        "pool-live-vp-pin");
    let mut decoded = Vec::with_capacity(actions.len());
    let mut previous = None;
    for action in actions {
        fields(action, &["recordHex", "proofHex"])?;
        let record = bytes(&action["recordHex"], RECORD_BYTES, "pool-record-length")?;
        check_record(&record).map_err(|e| anyhow::anyhow!(e.code()))?;
        let ad = action_authorization_digest(&deployment, &record);
        // The core encoder sorts a set; the live interface requires that order already.
        ensure!(previous.map_or(true, |prior| prior < ad), "pool-live-action-order");
        previous = Some(ad);
        let proof = bytes(&action["proofHex"], PROOF_BYTES, "pool-aggregate-proof-shape")?;
        decoded.push((record, proof));
    }
    // Exactly the fixtures' input encoder and the guest's statement/child verification path.
    // run() checks S and the gnark proof under vp before any SP1 client is constructed.
    let pairs: Vec<(&[u8], &[u8])> = decoded.iter().map(|(r, p)| (r.as_slice(), p.as_slice())).collect();
    let input = encode_input(&vp, &deployment, &pairs);
    let accepted = run(&input, &allowlist, &mut NoTrace).map_err(|e| anyhow::anyhow!(e.code()))?;
    Ok(Admitted { input, run_bind: accepted.run_bind, deployment, profile, batch_size: actions.len() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use apnt_pool_aggregate_core::input::parse_input;
    use crate::{fixtures, cases};

    fn public_input() -> Value {
        let f = fixtures().unwrap();
        let vector = &f.runs_no_meter["vectors"][0];
        assert_eq!(vector["name"], "b1-rel1");
        json!({
            "schema": SCHEMA, "label": CHIPNET_ZERO_VALUE_LABEL,
            "deploymentId": f.runs_no_meter["deploymentId"],
            "profileId": f.runs_no_meter["profileId"],
            "actions": [{ "recordHex": vector["records"][0],
                "proofHex": hex::encode(&f.ceremony_proofs["rel1-real-real-deposit-withdrawal"]) }],
        })
    }

    fn public_batch(count: usize) -> Value {
        let f = fixtures().unwrap();
        let vector = f.runs_no_meter["vectors"].as_array().unwrap().iter().find(|v| v["name"] == "b17-reversed").unwrap();
        let mut value = public_input();
        let deployment: [u8; 32] = hex::decode(value["deploymentId"].as_str().unwrap()).unwrap().try_into().unwrap();
        let mut actions: Vec<Value> = vector["records"].as_array().unwrap().iter()
            .zip(vector["recordNames"].as_array().unwrap()).take(count)
            .map(|(r, n)| json!({ "recordHex": r, "proofHex": hex::encode(&f.ceremony_proofs[n.as_str().unwrap()]) })).collect();
        actions.sort_by_key(|a| action_authorization_digest(&deployment, &hex::decode(a["recordHex"].as_str().unwrap()).unwrap()));
        value["actions"] = actions.into();
        value
    }

    #[test]
    fn multi_action_admission_and_firing_negatives() {
        let good = public_batch(3);
        let accepted = admit(ProofNetwork::Chipnet, &good).unwrap();
        assert_eq!(accepted.batch_size, 3);
        assert_eq!(parse_input(&accepted.input).unwrap().actions.len(), 3);
        let mut local = good.clone(); local["label"] = ProofNetwork::Local.label().into();
        assert_eq!(accepted.input, admit(ProofNetwork::Local, &local).unwrap().input);
        // The former 16 KiB cap could not admit even B=17. No proving here.
        let seventeen = public_batch(17);
        assert!(serde_json::to_vec_pretty(&seventeen).unwrap().len() > 16 * 1024);
        assert_eq!(admit(ProofNetwork::Chipnet, &seventeen).unwrap().batch_size, 17);
        for (edit, code) in [
            (0, "pool-live-action-order"), (1, "pool-live-action-order"),
            (2, "pool-aggregate-proof-rejected"), (3, "pool-live-batch-size"),
            (4, "pool-live-input-fields"),
        ] {
            let mut v = good.clone();
            let a = v["actions"].as_array_mut().unwrap();
            match edit {
                0 => a.swap(0, 1),
                1 => a[1] = a[0].clone(),
                2 => a[1]["proofHex"] = a[0]["proofHex"].clone(),
                3 => { let first = a[0].clone(); *a = vec![first; MAXIMUM_ACTIONS + 1]; },
                _ => a[1]["privateWitness"] = "forbidden-field-control".into(),
            }
            assert_eq!(admit(ProofNetwork::Chipnet, &v).err().unwrap().to_string(), code);
        }
    }

    #[test]
    fn multi_action_selector_checks_fire_before_sdk() {
        let dir = std::env::temp_dir().join(format!("eng775-selectors-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("input.json");
        std::fs::write(&path, serde_json::to_vec(&public_batch(3)).unwrap()).unwrap();
        let absent = dir.join("absent.elf");
        for selector in ["live-b0", "live-b03", "live-b65536", "live-bx", "live-b+3"] {
            assert_eq!(crate::prove::dry_run(ProofNetwork::Chipnet, selector, &absent, Some(&path)).unwrap_err().to_string(), "pool-live-batch-selector");
        }
        assert_eq!(crate::prove::dry_run(ProofNetwork::Chipnet, "live-b2", &absent, Some(&path)).unwrap_err().to_string(), "pool-live-batch-selector-mismatch");
        // Valid selectors get past admission and stop at the absent ELF, without SDK calls.
        assert!(crate::prove::dry_run(ProofNetwork::Chipnet, "live-b3", &absent, Some(&path)).unwrap_err().to_string().contains("ELF metadata"));
        assert_eq!(crate::prove::dry_run(ProofNetwork::Chipnet, "live-b65535", &absent, None).unwrap_err().to_string(), "pool-live-input-required");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn live_input_uses_the_fixture_encoder_and_binds_the_supplied_deployment() {
        let mut value = public_input();
        let admitted = admit(ProofNetwork::Chipnet, &value).unwrap();
        let fixture = cases(&fixtures().unwrap()).unwrap().into_iter()
            .find(|c| c.name == "chipnet-no-meter-b1-rel1").unwrap();
        assert_eq!(admitted.input, fixture.input);
        let crate::Expect::Accept { run_bind } = fixture.expect else { panic!("positive") };
        assert_eq!(admitted.run_bind, run_bind);
        // No fixed fixture deployment in the live path. The child is bound to A, the
        // aggregate to deployment || profile || records; settlement authenticates deployment.
        let deployment = Sha256::digest(b"ENG-559 public test deployment; not chain truth");
        value["deploymentId"] = hex::encode(deployment).into();
        let different = admit(ProofNetwork::Chipnet, &value).unwrap();
        assert_ne!(different.run_bind, admitted.run_bind);
        assert_eq!(parse_input(&different.input).unwrap().deployment_id.as_slice(), &deployment[..]);
    }

    #[test]
    fn network_labels_and_pin_records_do_not_cross() {
        let chipnet = public_input();
        let mut local = chipnet.clone();
        local["label"] = ProofNetwork::Local.label().into();
        assert_eq!(admit(ProofNetwork::Local, &chipnet).err().unwrap().to_string(), "pool-live-input-label");
        assert_eq!(admit(ProofNetwork::Chipnet, &local).err().unwrap().to_string(), "pool-live-input-label");
        let accepted = admit(ProofNetwork::Local, &local).unwrap();
        assert_eq!(accepted.profile, CHIPNET_ZERO_VALUE_REVISION_3_PROFILE_ID);
        assert_eq!(accepted.run_bind, admit(ProofNetwork::Chipnet, &chipnet).unwrap().run_bind);
    }

    #[test]
    fn every_live_negative_refuses_before_elf_setup_or_prove() {
        let good = public_input();
        assert!(admit(ProofNetwork::Chipnet, &good).is_ok());
        let f = fixtures().unwrap();
        let mut negatives = Vec::new();
        let mut add = |code: &str, v: Value| negatives.push((code.to_owned(), v));
        let mut v = good.clone(); v["actions"] = json!([]); add("pool-live-batch-size", v);
        let mut v = good.clone(); v["actions"] = json!([good["actions"][0], good["actions"][0]]); add("pool-live-action-order", v);
        let mut v = good.clone(); v["profileId"] = hex::encode([0x42; 32]).into(); add("pool-aggregate-profile-not-allowlisted", v);
        let mut v = good.clone(); v["actions"][0]["recordHex"] = "00".into(); add("pool-record-length", v);
        let mut record = hex::decode(good["actions"][0]["recordHex"].as_str().unwrap()).unwrap();
        record[96] = 4;
        let mut v = good.clone(); v["actions"][0]["recordHex"] = hex::encode(record).into(); add("pool-record-key", v);
        let mut v = good.clone(); v["actions"][0]["proofHex"] = "00".into(); add("pool-aggregate-proof-shape", v);
        // Valid point encodings and a genuine proof, but for another record: pairing must fire.
        let mut v = good.clone(); v["actions"][0]["proofHex"] = hex::encode(&f.ceremony_proofs["dummy-dummy-deposit"]).into(); add("pool-aggregate-proof-rejected", v);
        let mut v = good.clone(); v["actions"][0]["proofHex"] = hex::encode(&f.ceremony_alt_proof).into(); add("pool-aggregate-proof-rejected", v);
        let mut v = good.clone(); v["spendAuthority"] = "forbidden-field-control".into(); add("pool-live-input-fields", v);
        let mut v = good.clone(); v["label"] = "production".into(); add("pool-live-input-label", v);
        let dir = std::env::temp_dir().join(format!("eng559-refusals-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("input.json");
        let absent_elf = dir.join("does-not-exist.elf");
        let output = dir.join("must-not-exist.json");
        let counts = dir.join("must-not-exist.counts.json");
        for (code, value) in negatives {
            std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            // If admission were bypassed, the absent ELF would stop these calls before any
            // SDK operation. Requiring the precise cause proves each admission control fires.
            assert_eq!(crate::prove::dry_run(ProofNetwork::Chipnet, "live-b1", &absent_elf, Some(&path)).unwrap_err().to_string(), code);
            assert_eq!(crate::prove::prove(ProofNetwork::Chipnet, "live-b1", &absent_elf, &output, &counts, Some(&path)).unwrap_err().to_string(), code);
            assert!(!output.exists() && !counts.exists());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
