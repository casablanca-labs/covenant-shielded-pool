//! Host tests of the aggregate relation (registry entry 1 revision 3, pad16,
//! ENG-454: one public input over a 314-byte record). Every fixture they read
//! is committed:
//!
//! - `fixtures/simulated-ceremony-zero-value-rev3/` (ENG-486): the action
//!   proofs of all 18 host positives under revision 3's Chipnet ceremony keys
//!   (SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY: the project could
//!   forge proofs under them), their δ-rescaled pair and gnark's revision-3
//!   reference dump; the vp is the registry's recorded one
//!   (`apnt-pool-v1-proof-system-registry-rev3-vectors.json`,
//!   `chipnetZeroValueVp`), and `fixtures/pool-aggregate-statement-vectors-v4.json`
//!   the host's accepted runs under its profile id;
//! - `fixtures/pool-aggregate-statement-vectors-v3.json` and
//!   `packages/protocol-runtime/test-vectors/apnt-pool-v1-vectors.json`: the
//!   TypeScript host codec's revision-3 statements and failure codes;
//! - `packages/protocol-runtime/test-vectors/apnt-pool-v1-action-public-input-vectors.json`:
//!   the host's public input x of 23 records, every quotient 0..5;
//! - `packages/protocol-runtime/test-vectors/apnt-pool-v1-proof-system-registry-rev3-vectors.json`
//!   and the superseded revisions' files: the registry's shape vectors;
//! - revision 2's frozen fixtures, `fixtures/development-zero-value-rev2/`
//!   (DEVELOPMENT ZERO-VALUE keys and proofs, forgeable, never for value: the
//!   revision-2 action circuit's development key with its REL1 proof, STAND-IN
//!   keys of the same public shape with a proof of every batch record, the
//!   δ-rescaled pair and gnark's reference dump) and the 396-byte records its
//!   proofs are over (`fixtures/pool-aggregate-statement-vectors-v1.json`).
//!
//! The Groth16 verifier does not depend on the record length: x is SHA-256 of
//! whatever bytes the proof is over. So its differential and mutation tests
//! run on revision 2's fixtures, reading their records as byte strings, and on
//! revision 3's. The accepted runs and the refusals that need an honest proof
//! beside them (a tampered record, swapped proofs, a δ-rescaled key) run on
//! revision 3's ceremony proofs.

use std::path::PathBuf;
use std::{fs, vec::Vec};

use serde_json::Value;

use bn::Fr;

use crate::aggregate::{run, NoTrace};
use crate::groth16::{commitment_wire, public_input, testing, verify_bytes, Proof, VerifyingKey, PROOF_BYTES, VP_BYTES};
use crate::input::{encode_input, parse_input};
use crate::profile::{
    derive_profile_id, CHIPNET_BUILD_LABEL, CHIPNET_ZERO_VALUE_LABEL, CHIPNET_ZERO_VALUE_REVISION_3_PROFILE_ID, COMPILED_BUILD_LABEL,
    COMPILED_PROFILE_ALLOWLIST, DEFAULT_BUILD_LABEL, DEVELOPMENT_LABEL, DEVELOPMENT_ZERO_VALUE_ACTION_PROFILE_ID, DEVELOPMENT_ZERO_VALUE_STANDIN_PROFILE_ID,
};
use crate::record::{check_record, is_compressed_point, offset, RECORD_BYTES};
use crate::statement::{assemble_statement, statement_commitment};
use crate::AggregateError as E;

// Protected values may participate in every original predicate, never its
// failure text. Rule locations and original array ordinals are metadata only.
std::thread_local! {
    static CONTROL: std::cell::Cell<&'static str> = const { std::cell::Cell::new("helper") };
    static ORDINAL: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
fn control(id: &'static str) {
    static HOOK: std::sync::Once = std::sync::Once::new();
    HOOK.call_once(|| std::panic::set_hook(Box::new(|_| eprintln!("pool-protected-panic"))));
    CONTROL.with(|v| v.set(id));
    ORDINAL.with(|v| v.set(0));
}
fn guarded(body: impl FnOnce()) {
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).is_err() {
        // The libtest boundary sees only a fixed payload, even if a dependency
        // panicked internally while holding protected inputs.
        failure("panic", 0);
    }
}
fn ordinal(index: usize) { ORDINAL.with(|v| v.set(index)); }
fn failure(rule: &str, line: u32) -> ! {
    std::panic!("pool-protected:{}:{}:{}:{}", CONTROL.with(|v| v.get()), rule, line, ORDINAL.with(|v| v.get()))
}
macro_rules! assert_eq {
    ($left:expr, $right:expr $(, $($message:tt)*)?) => {
        match (&$left, &$right) { (left, right) => if !(*left == *right) { failure("equal", line!()); } }
    };
}
macro_rules! assert_ne {
    ($left:expr, $right:expr $(, $($message:tt)*)?) => {
        match (&$left, &$right) { (left, right) => if *left == *right { failure("different", line!()); } }
    };
}
macro_rules! assert {
    ($predicate:expr $(, $($message:tt)*)?) => { if !$predicate { failure("predicate", line!()); } };
}
macro_rules! panic { ($($message:tt)*) => { failure("refused", line!()) }; }
trait ValueSafe<T> { fn safe(self) -> T; }
impl<T> ValueSafe<T> for Option<T> {
    fn safe(self) -> T { match self { Some(v) => v, None => failure("missing", line!()) } }
}
impl<T, E> ValueSafe<T> for Result<T, E> {
    fn safe(self) -> T { match self { Ok(v) => v, Err(_) => failure("decode", line!()) } }
}
trait ValueSafeError<E> { fn safe_err(self) -> E; }
impl<T, E> ValueSafeError<E> for Result<T, E> {
    fn safe_err(self) -> E { match self { Err(e) => e, Ok(_) => failure("expected-refusal", line!()) } }
}

fn tool(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join(path)
}
fn repo(path: &str) -> PathBuf {
    tool("../..").join(path)
}
fn json(path: PathBuf) -> Value {
    serde_json::from_slice(&fs::read(&path).safe()).safe()
}
fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().safe()).safe()
}
fn arr32(v: &Value) -> [u8; 32] {
    unhex(v).try_into().safe()
}
fn rev2(path: &str) -> Vec<u8> {
    fs::read(tool(&format!("fixtures/development-zero-value-rev2/{path}"))).safe()
}
/// The stand-in key of the action circuit's public shape (not the action relation).
fn standin_vk() -> Vec<u8> {
    rev2("standin/key-a/vk.bin")
}
/// A second stand-in Setup: a key no build allowlists.
fn key_c_vk() -> Vec<u8> {
    rev2("standin/key-c/vk.bin")
}
fn key_c_rel1_proof() -> Vec<u8> {
    rev2("standin/proofs-c/rel1-real-real-deposit-withdrawal.proof.bin")
}
/// The action circuit's own development key and its REL1 proof.
fn action_vk() -> Vec<u8> {
    rev2("action/vk.bin")
}
fn action_rel1_proof() -> Vec<u8> {
    rev2("action/rel1-real-real-deposit-withdrawal.proof.bin")
}
fn alt_vk() -> Vec<u8> {
    rev2("transform/alt-vk.bin")
}
fn alt_proof() -> Vec<u8> {
    rev2("transform/alt-proof.bin")
}
/// The revision-3 codec vectors (314-byte records).
fn statement_vectors() -> Value {
    json(tool("fixtures/pool-aggregate-statement-vectors-v3.json"))
}
/// Revision 2's codec vectors, frozen: the 396-byte records its development proofs are over.
fn revision_2_statement_vectors() -> Value {
    json(tool("fixtures/pool-aggregate-statement-vectors-v1.json"))
}

/// The B = 17 record set of a codec vector file, reversed back to corpus order: (name, record).
fn batch_records(v: &Value) -> Vec<(String, Vec<u8>)> {
    let b17 = v["vectors"].as_array().safe().iter().find(|x| x["name"] == "b17-reversed").safe();
    let names = b17["recordNames"].as_array().safe();
    let records = b17["records"].as_array().safe();
    let mut out: Vec<_> = names.iter().zip(records).map(|(n, r)| (n.as_str().safe().to_owned(), unhex(r))).collect();
    out.reverse();
    out
}

/// Revision 2's batch: (entry name, its 396-byte record, its stand-in proof), in corpus order.
fn revision_2_batch() -> Vec<(String, Vec<u8>, Vec<u8>)> {
    batch_records(&revision_2_statement_vectors())
        .into_iter()
        .map(|(name, record)| {
            assert_eq!(record.len(), 396, "{name}");
            let proof = rev2(&format!("standin/proofs-a/{name}.proof.bin"));
            (name, record, proof)
        })
        .collect()
}

/// The same 17 actions' revision-3 records, in corpus order.
fn batch() -> Vec<(String, [u8; RECORD_BYTES])> {
    batch_records(&statement_vectors()).into_iter().map(|(name, r)| (name, r.try_into().safe())).collect()
}

// ---- statement parity with the TypeScript host codec ----

fn check_statement_vector(deployment: &[u8; 32], profile: &[u8; 32], x: &Value) {
    let records: Vec<Vec<u8>> = x["records"].as_array().safe().iter().map(unhex).collect();
    let refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let got = assemble_statement(deployment, profile, &refs);
    let name = x["name"].as_str().safe();
    match x.get("hostFailureCode") {
        Some(code) => assert_eq!(got.err().map(|e| e.code()), code.as_str(), "{name}"),
        None => {
            let s = got.unwrap_or_else(|e| panic!("{name}: refused {}", e.code()));
            assert_eq!(hex::encode(&s), x["statement"].as_str().safe(), "{name}");
            assert_eq!(hex::encode(statement_commitment(&s)), x["runBind32"].as_str().safe(), "{name}");
        }
    }
}

#[test]
#[ignore = "requires excluded frozen proof or reference inputs; not shipped"]
fn statement_equals_the_host_codec_on_every_aggregate_vector() {
    control("C01");
    guarded(|| {
    let v = statement_vectors();
    let (d, p) = (arr32(&v["deploymentId"]), arr32(&v["profileId"]));
    let vectors = v["vectors"].as_array().safe();
    assert_eq!(vectors.len(), 26);
    for (index, x) in vectors.iter().enumerate() {
        ordinal(index);
        check_statement_vector(&d, &p, x);
    }
    });
}

#[test]
fn statement_equals_the_host_codec_on_the_protocol_runtime_vectors() {
    control("C02");
    guarded(|| {
    let v = json(repo("packages/protocol-runtime/test-vectors/apnt-pool-v1-vectors.json"));
    let st = &v["reference"]["statement"];
    let records: Vec<Vec<u8>> = st["recordsInput"].as_array().safe().iter().map(unhex).collect();
    let refs: Vec<&[u8]> = records.iter().map(|r| r.as_slice()).collect();
    let s = assemble_statement(&arr32(&st["deploymentId"]), &arr32(&st["profileId"]), &refs).safe();
    assert_eq!(hex::encode(&s), st["statement"].as_str().safe());
    assert_eq!(s.len() as u64, st["length"].as_u64().safe());
    assert_eq!(hex::encode(statement_commitment(&s)), st["runBind32"].as_str().safe());

    // X1 supplies descending raw input; canonical statements sort ascending.
    let x1 = &v["overlap"]["x1"];
    let (d, p) = (arr32(&x1["deploymentId"]), arr32(&x1["profileId"]));
    let b1 = &x1["statementB1"];
    let r1 = unhex(&b1["record"]);
    assert_eq!(hex::encode(assemble_statement(&d, &p, &[&r1]).safe()), b1["statement"].as_str().safe());
    let b2 = &x1["statementB2"];
    let pair: Vec<Vec<u8>> = b2["records"].as_array().safe().iter().map(unhex).collect();
    assert_eq!(pair.len(), 2);
    let first_ad = crate::statement::action_authorization_digest(&d, &pair[0]);
    let second_ad = crate::statement::action_authorization_digest(&d, &pair[1]);
    assert_ne!(first_ad, second_ad);
    assert!(first_ad > second_ad);
    assert_eq!(b2["x1OrderIsLexAscending"], first_ad < second_ad);
    let canonical = unhex(&b2["sortedStatement"]);
    assert_eq!(&canonical[88..402], pair[1].as_slice());
    assert_eq!(&canonical[402..], pair[0].as_slice());
    for order in [[0usize, 1], [1, 0]] {
        let refs = [pair[order[0]].as_slice(), pair[order[1]].as_slice()];
        assert_eq!(hex::encode(assemble_statement(&d, &p, &refs).safe()), b2["sortedStatement"].as_str().safe());
    }
    assert_eq!(hex::encode(&v["overlap"]["x10"]["x10EncodeOfReferenceRecords"].as_str().safe()), hex::encode(st["statement"].as_str().safe()));
    });
}

#[test]
fn record_keys_agree_with_the_host_point_vectors() {
    control("C03");
    guarded(|| {
    let v = json(repo("packages/protocol-runtime/test-vectors/apnt-pool-v1-vectors.json"));
    for k in v["reference"]["rerandomizedKeys"].as_array().safe() {
        assert!(is_compressed_point(&unhex(&k["rk"])));
        assert!(is_compressed_point(&unhex(&k["ak"])));
    }
    let mut not_point = unhex(&v["reference"]["rerandomizedKeys"][0]["rk"]);
    not_point[0] = 0x04;
    assert!(!is_compressed_point(&not_point));
    assert!(!is_compressed_point(&[0u8; 33]), "the all-zero identity encoding is not a record key");
    });
}

#[test]
#[ignore = "requires excluded frozen proof or reference inputs; not shipped"]
fn statement_count_bounds() {
    control("C04");
    guarded(|| {
    let r = batch()[0].1;
    let many: Vec<&[u8]> = (0..=0xffff).map(|_| r.as_slice()).collect();
    assert_eq!(assemble_statement(&[0; 32], &[0; 32], &many).safe_err(), E::StatementCount);
    assert_eq!(assemble_statement(&[0; 32], &[0; 32], &[]).safe_err(), E::StatementCount);
    });
}

// ---- the public input ----

#[test]
#[ignore = "requires excluded action corpus reference inputs; not shipped"]
fn public_input_equals_the_hosts_on_every_vector_and_the_wrong_readings_differ() {
    control("C05");
    guarded(|| {
    let v = json(repo("packages/protocol-runtime/test-vectors/apnt-pool-v1-action-public-input-vectors.json"));
    let mut r_be = [0u8; 32];
    Fr::modulus().to_big_endian(&mut r_be).safe();
    assert_eq!(v["scalarOrder"].as_str().safe(), "21888242871839275222246405745257275088548364400416034343698204186575808495617");
    assert_eq!(hex::encode(r_be), "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
    let vectors = v["vectors"].as_array().safe();
    assert_eq!(vectors.len(), 23);
    let mut quotients = std::collections::BTreeSet::new();
    for (index, c) in vectors.iter().enumerate() {
        ordinal(index);
        let name = c["name"].as_str().safe();
        let record: [u8; RECORD_BYTES] = unhex(&c["record"]).try_into().safe();
        let x = testing::fr_hex(public_input(&record));
        assert_eq!(x, c["publicInput"].as_str().safe(), "{name}");
        assert_eq!(testing::digest_at_least_r(&record), c["digestAtLeastR"].as_bool().safe(), "{name}");
        // The byte-order and truncation controls: this verifier's own wrong
        // readings reproduce the vector's, and neither is x.
        assert_eq!(testing::fr_hex(testing::public_input_little_endian(&record)), c["wrongReductions"]["littleEndian"].as_str().safe(), "{name}");
        assert_eq!(testing::fr_hex(testing::public_input_truncated(&record)), c["wrongReductions"]["top253Bits"].as_str().safe(), "{name}");
        assert_ne!(c["wrongReductions"]["littleEndian"], c["publicInput"], "{name}");
        assert_ne!(c["wrongReductions"]["top253Bits"], c["publicInput"], "{name}");
        quotients.insert(c["quotient"].as_u64().safe());
    }
    assert_eq!(quotients.into_iter().collect::<Vec<_>>(), [0, 1, 2, 3, 4, 5]);
    });
}

// ---- profile ids and the allowlist ----

#[test]
#[ignore = "requires excluded frozen proof or reference inputs; not shipped"]
fn profile_ids_match_the_host_and_the_registry() {
    control("C06");
    guarded(|| {
    let v = json(repo("packages/protocol-runtime/test-vectors/apnt-pool-v1-vectors.json"));
    let pid = &v["reference"]["profileId"];
    let vp = unhex(&pid["verifierParameters"]);
    assert_eq!(hex::encode(derive_profile_id(1, &vp).safe()), pid["system1"].as_str().safe());
    assert_eq!(hex::encode(derive_profile_id(2, &vp).safe()), pid["system2"].as_str().safe());
    for unlisted in [0u16, 3, 258, 0xffff] {
        assert_eq!(derive_profile_id(unlisted, &vp).safe_err(), E::ProfileSystem);
    }
    let registry = json(repo("packages/protocol-runtime/test-vectors/apnt-pool-v1-proof-system-registry-rev3-vectors.json"));
    assert_eq!(registry["registryEntry"]["revision"], 3);
    let shape = unhex(&registry["shapeVector"]["vp"]);
    assert_eq!(shape.len(), VP_BYTES);
    assert_eq!(VP_BYTES, 528);
    assert_eq!(hex::encode(derive_profile_id(1, &shape).safe()), registry["shapeVector"]["profileId"].as_str().safe());
    // The shape vector parses as revision 3's layout, which is revision 2's
    // (its points are hash-to-curve images, so it is not a verifying key).
    assert!(VerifyingKey::parse(&shape).is_ok());
    // Revision 1's shape (396 public bytes, 13,168 bytes) is refused at parse.
    let rev1 = json(repo("packages/protocol-runtime/test-vectors/apnt-pool-v1-proof-system-registry-vectors.json"));
    let rev1_shape = unhex(&rev1["shapeVector"]["vp"]);
    assert_eq!(rev1_shape.len(), 13_168);
    assert_eq!(VerifyingKey::parse(&rev1_shape).err(), Some(E::VerifierParameters));
    // The development ids are the revision-2 keys' own, and the host's (revision 2's frozen run vectors).
    assert_eq!(derive_profile_id(1, &action_vk()).safe(), DEVELOPMENT_ZERO_VALUE_ACTION_PROFILE_ID);
    assert_eq!(derive_profile_id(1, &standin_vk()).safe(), DEVELOPMENT_ZERO_VALUE_STANDIN_PROFILE_ID);
    let rv = json(tool("fixtures/pool-aggregate-statement-vectors-v2.json"));
    assert_eq!(hex::encode(DEVELOPMENT_ZERO_VALUE_ACTION_PROFILE_ID), rv["profiles"]["action"].as_str().safe());
    assert_eq!(hex::encode(DEVELOPMENT_ZERO_VALUE_STANDIN_PROFILE_ID), rv["profiles"]["standin"].as_str().safe());
    });
}

#[test]
#[ignore = "requires excluded frozen proof or reference inputs; not shipped"]
fn compiled_allowlist_never_holds_a_shape_vector_or_another_key_and_holds_each_builds_ids_only_under_its_feature() {
    control("C07");
    guarded(|| {
    for file in [
        "apnt-pool-v1-proof-system-registry-rev3-vectors.json",
        "apnt-pool-v1-proof-system-registry-rev2-vectors.json",
        "apnt-pool-v1-proof-system-registry-vectors.json",
    ] {
        let registry = json(repo(&format!("packages/protocol-runtime/test-vectors/{file}")));
        assert!(!COMPILED_PROFILE_ALLOWLIST.contains(&arr32(&registry["shapeVector"]["profileId"])), "{file}");
    }
    for other in [alt_vk(), key_c_vk()] {
        assert!(!COMPILED_PROFILE_ALLOWLIST.contains(&derive_profile_id(1, &other).safe()));
    }
    assert!(!COMPILED_PROFILE_ALLOWLIST.contains(&derive_profile_id(1, &ceremony_alt_vk()).safe()));
    if cfg!(feature = "development-zero-value-test-profile") {
        assert_eq!(
            COMPILED_PROFILE_ALLOWLIST,
            &[DEVELOPMENT_ZERO_VALUE_ACTION_PROFILE_ID, DEVELOPMENT_ZERO_VALUE_STANDIN_PROFILE_ID, CHIPNET_ZERO_VALUE_REVISION_3_PROFILE_ID]
        );
        assert_eq!(COMPILED_BUILD_LABEL, DEVELOPMENT_LABEL);
    } else if cfg!(feature = "chipnet-zero-value-rev3-profile") {
        // The labelled Chipnet build: exactly revision 3's recorded Chipnet vp, and the label says what it is.
        assert_eq!(COMPILED_PROFILE_ALLOWLIST, &[CHIPNET_ZERO_VALUE_REVISION_3_PROFILE_ID]);
        assert_eq!(COMPILED_PROFILE_ALLOWLIST[0], derive_profile_id(1, &ceremony_vp()).safe());
        assert_eq!(COMPILED_BUILD_LABEL, CHIPNET_BUILD_LABEL);
    } else {
        assert!(COMPILED_PROFILE_ALLOWLIST.is_empty(), "the default build allowlists nothing");
        assert_eq!(COMPILED_BUILD_LABEL, DEFAULT_BUILD_LABEL);
        assert!(!COMPILED_BUILD_LABEL.contains("ZERO-VALUE") && COMPILED_BUILD_LABEL.contains("empty allowlist"));
    }
    // The Chipnet build's label names the network, the registry revision and the ceremony's label.
    assert!(CHIPNET_BUILD_LABEL.contains("Chipnet") && CHIPNET_BUILD_LABEL.contains("revision 3"));
    assert!(CHIPNET_BUILD_LABEL.contains(CHIPNET_ZERO_VALUE_LABEL) && CHIPNET_BUILD_LABEL.contains("never mainnet, never value"));
    });
}

// ---- the verifier against gnark ----

fn reference() -> Value {
    json(tool("fixtures/development-zero-value-rev2/gnark-reference-v2.json"))
}

fn assert_g1(name: &str, got: &bn::AffineG1, want: &Value) {
    let (x, y) = testing::g1(got);
    assert_eq!((x.as_str(), y.as_str()), (want["x"].as_str().safe(), want["y"].as_str().safe()), "{name}");
}
fn assert_g2(name: &str, got: &bn::AffineG2, want: &Value) {
    let c = testing::g2(got);
    let w = ["x0", "x1", "y0", "y1"].map(|k| want[k].as_str().safe().to_owned());
    assert_eq!(c, w, "{name}");
}

fn keys() -> [(&'static str, Vec<u8>); 3] {
    [("standin", standin_vk()), ("alt", alt_vk()), ("action", action_vk())]
}

#[test]
#[ignore = "requires excluded frozen proof or reference inputs; not shipped"]
fn decoded_points_equal_gnarks() {
    control("C08");
    guarded(|| {
    let r = reference();
    for (name, raw) in keys() {
        let want = &r["verifyingKeys"][name];
        let vk = VerifyingKey::parse(&raw).safe();
        assert_g1("alpha", &vk.alpha, &want["alpha"]);
        assert_g1("beta1", &vk.beta_g1, &want["betaG1"]);
        assert_g2("beta2", &vk.beta, &want["betaG2"]);
        assert_g2("gamma2", &vk.gamma, &want["gammaG2"]);
        assert_g1("delta1", &vk.delta_g1, &want["deltaG1"]);
        assert_g2("delta2", &vk.delta, &want["deltaG2"]);
        let k = want["k"].as_array().safe();
        assert_eq!(k.len(), 3);
        assert_eq!(k.len(), vk.k.len());
        for (i, (got, w)) in vk.k.iter().zip(k).enumerate() {
            assert_g1(&format!("{name} K[{i}]"), got, w);
        }
        assert_g2("G", &vk.commitment_g, &want["commitmentG"]);
        assert_g2("GσNeg", &vk.commitment_g_sigma_neg, &want["commitmentGSigmaNeg"]);
    }
    let proofs = r["proofs"].as_array().safe();
    assert_eq!(proofs.len(), 19, "17 batch proofs, the rescaled one and the action circuit's");
    for (index, p) in proofs.iter().enumerate() {
        ordinal(index);
        let name = p["name"].as_str().safe();
        let proof = Proof::parse(&unhex(&p["proof"])).safe();
        assert_g1(name, &proof.a, &p["a"]);
        assert_g2(name, &proof.b, &p["b"]);
        assert_g1(name, &proof.c, &p["c"]);
        assert_g1(name, &proof.commitment, &p["commitment"]);
        assert_g1(name, &proof.commitment_pok, &p["commitmentPok"]);
        assert_eq!(testing::fr_hex(commitment_wire(&proof.commitment).safe()), p["commitmentWire"].as_str().safe(), "{name} h");
    }
    });
}

#[test]
#[ignore = "requires excluded frozen proof or reference inputs; not shipped"]
fn every_verdict_equals_gnarks() {
    control("C09");
    guarded(|| {
    // Revision 2's reference dump: its records are 396 bytes, read as the byte strings its proofs are over.
    let r = reference();
    let keys = keys();
    let mut accepted = Vec::new();
    let cases = r["cases"].as_array().safe();
    for (index, c) in cases.iter().enumerate() {
        ordinal(index);
        let name = c["name"].as_str().safe();
        let mut vp = keys.iter().find(|(k, _)| *k == c["vk"].as_str().safe()).safe().1.clone();
        for m in c["vkMutations"].as_array().into_iter().flatten() {
            vp[m["offset"].as_u64().safe() as usize] ^= m["xor"].as_u64().safe() as u8;
        }
        let proof = unhex(&c["proof"]);
        let record = unhex(&c["record"]);
        let ours = match c.get("publicInput") {
            // gnark reduced the given integer mod r; so does this conversion.
            Some(x) => VerifyingKey::parse(&vp).and_then(|vk| testing::verify_with_x(&vk, &proof, Fr::from_bytes_be_mod_order(&unhex(x)).safe())),
            None => VerifyingKey::parse(&vp).and_then(|vk| verify_bytes(&vk, &proof, &record)),
        };
        let gnark = c["gnarkAccepted"].as_bool().safe();
        assert_eq!(ours.is_ok(), gnark, "verdict");
        if gnark {
            accepted.push(name.to_owned());
        }
    }
    let honest = accepted.iter().filter(|n| n.starts_with("honest:")).count();
    assert_eq!(honest, 17, "every batch proof with its own record");
    let mut rest: Vec<&str> = accepted.iter().map(String::as_str).filter(|n| !n.starts_with("honest:")).collect();
    rest.sort();
    // δ1 is in the one serialization but Verify does not read it: a flipped
    // byte that still decodes to a point changes nothing.
    assert_eq!(rest, ["action:honest", "alt:alt-proof-under-alt-vk", "vk:delta-g1-byte", "x:honest", "x:unreduced-digest"]);
    assert!(cases.len() >= 100);
    });
}

// ---- mutation witnesses: each refusal is the named check's ----

#[test]
#[ignore = "requires excluded frozen proof or reference inputs; not shipped"]
fn the_knowledge_check_alone_refuses_a_replaced_pok() {
    control("C10");
    guarded(|| {
    let r = reference();
    let case = r["cases"].as_array().safe().iter().find(|c| c["name"] == "proof:pok-plus-generator").safe();
    assert_eq!(case["gnarkAccepted"], false);
    let vk = VerifyingKey::parse(&standin_vk()).safe();
    let proof = unhex(&case["proof"]);
    let record = unhex(&case["record"]);
    assert_eq!(verify_bytes(&vk, &proof, &record).safe_err(), E::CommitmentKnowledge);
    // Without the knowledge check the same proof passes the Groth16 pairing:
    // the check is load-bearing, not overlapped.
    testing::verify_without_knowledge_check(&vk, &proof, &record).safe();
    });
}

#[test]
#[ignore = "requires excluded frozen proof or reference inputs; not shipped"]
fn the_reduction_is_what_the_verifier_computes() {
    control("C11");
    guarded(|| {
    // Every revision-2 stand-in proof verifies with x mod r over its own
    // 396-byte record and is refused with x read little-endian or truncated to
    // its top 253 bits; the reduction runs on 16 of the 17 records, so the
    // controls are not vacuous.
    let vk = VerifyingKey::parse(&standin_vk()).safe();
    let mut reduced = 0;
    for (name, record, proof) in revision_2_batch() {
        verify_bytes(&vk, &proof, &record).unwrap_or_else(|e| panic!("{name}: {}", e.code()));
        assert_eq!(testing::verify_with_x(&vk, &proof, crate::groth16::public_input_of(&record)), Ok(()), "{name}");
        assert_eq!(testing::verify_with_x(&vk, &proof, testing::public_input_little_endian(&record)), Err(E::ProofRejected), "{name} little-endian");
        assert_eq!(testing::verify_with_x(&vk, &proof, testing::public_input_truncated(&record)), Err(E::ProofRejected), "{name} truncated");
        reduced += testing::digest_at_least_r(&record) as usize;
    }
    assert_eq!(reduced, 16);
    });
}

#[test]
#[ignore = "requires excluded frozen proof or reference inputs; not shipped"]
fn a_revision_2_proof_is_refused_over_the_same_actions_revision_3_record() {
    control("C12");
    guarded(|| {
    // The 17 actions of the batch, each with its revision-2 stand-in proof: the
    // proof verifies over its own 396-byte record and is refused over the same
    // action's 314-byte record, because x is SHA-256 of the bytes in S. This is
    // why no run below can be accepted before revision-3 development proofs
    // exist.
    let vk = VerifyingKey::parse(&standin_vk()).safe();
    let rev3 = batch();
    let rev2 = revision_2_batch();
    assert_eq!(rev3.iter().map(|x| &x.0).collect::<Vec<_>>(), rev2.iter().map(|x| &x.0).collect::<Vec<_>>());
    for ((name, record3), (_, record2, proof)) in rev3.iter().zip(&rev2) {
        verify_bytes(&vk, proof, record2).unwrap_or_else(|e| panic!("{name}: {}", e.code()));
        assert_eq!(crate::groth16::verify(&vk, proof, record3), Err(E::ProofRejected), "{name}");
        assert_ne!(public_input(record3), crate::groth16::public_input_of(record2), "{name}");
    }
    // The action circuit's revision-2 key and REL1 proof likewise.
    let action = VerifyingKey::parse(&action_vk()).safe();
    verify_bytes(&action, &action_rel1_proof(), &rev2[0].1).safe();
    assert_eq!(crate::groth16::verify(&action, &action_rel1_proof(), &rev3[0].1), Err(E::ProofRejected));
    });
}

// ---- the whole relation, natively: the refusals that need no revision-3 proof ----

fn batch_input(vp: &[u8], actions: &[(&[u8], &[u8])]) -> Vec<u8> {
    encode_input(vp, &arr32(&statement_vectors()["deploymentId"]), actions)
}

#[test]
#[ignore = "requires excluded frozen proof or reference inputs; not shipped"]
fn the_allowlist_alone_refuses_a_prover_supplied_key() {
    control("C13");
    guarded(|| {
    let (_, record) = &batch()[0];
    let allow = [DEVELOPMENT_ZERO_VALUE_ACTION_PROFILE_ID, DEVELOPMENT_ZERO_VALUE_STANDIN_PROFILE_ID];
    for (vp, proof) in [(alt_vk(), alt_proof()), (key_c_vk(), key_c_rel1_proof())] {
        let input = batch_input(&vp, &[(record.as_slice(), proof.as_slice())]);
        // The program refuses the key, before parsing it…
        assert_eq!(run(&input, &allow, &mut NoTrace).err(), Some(E::ProfileNotAllowlisted));
        // …and with the prover's key allowlisted, the same input passes the
        // allowlist and is refused later, at verification: the allowlist is the
        // check that refused it first. (Its proof is over revision 2's record,
        // so no allowlisting makes it accepted here.)
        let pid = derive_profile_id(1, &vp).safe();
        let later = run(&input, &[allow[0], allow[1], pid], &mut NoTrace).err();
        assert!(matches!(later, Some(E::ProofRejected) | Some(E::CommitmentKnowledge)), "{later:?}");
    }
    });
}

#[test]
#[ignore = "requires excluded frozen proof or reference inputs; not shipped"]
fn run_refuses_each_named_negative_that_needs_no_revision_3_proof() {
    control("C14");
    guarded(|| {
    let b = batch();
    let rev2 = revision_2_batch();
    let vk = standin_vk();
    let allow = [DEVELOPMENT_ZERO_VALUE_ACTION_PROFILE_ID, DEVELOPMENT_ZERO_VALUE_STANDIN_PROFILE_ID];
    let (r0, p0) = (b[0].1, rev2[0].2.clone());
    let (r1, p1) = (b[1].1, rev2[1].2.clone());
    let go = |vp: &[u8], actions: &[(&[u8], &[u8])], allowlist: &[[u8; 32]]| run(&batch_input(vp, actions), allowlist, &mut NoTrace).err();

    // A revision-2 proof over the revision-3 record: x is computed over the 314 bytes in S.
    assert_eq!(go(&vk, &[(&r0, &p0)], &allow), Some(E::ProofRejected));
    assert_eq!(go(&action_vk(), &[(&r0, &action_rel1_proof())], &allow), Some(E::ProofRejected));
    // A prover-supplied verifying key.
    assert_eq!(go(&alt_vk(), &[(&r0, &alt_proof())], &allow), Some(E::ProfileNotAllowlisted));
    assert_eq!(go(&key_c_vk(), &[(&r0, &key_c_rel1_proof())], &allow), Some(E::ProfileNotAllowlisted));
    // The default (empty) allowlist refuses even the development keys.
    assert_eq!(go(&vk, &[(&r0, &p0)], &[]), Some(E::ProfileNotAllowlisted));
    assert_eq!(go(&action_vk(), &[(&r0, &action_rel1_proof())], &[]), Some(E::ProfileNotAllowlisted));
    // The knowledge check does not read the record: a fresh Setup's proof under
    // the allowlisted key (key c draws its own Pedersen key), and each of the
    // two development keys' proofs under the other.
    assert_eq!(go(&vk, &[(&r0, &key_c_rel1_proof())], &allow), Some(E::CommitmentKnowledge));
    assert_eq!(go(&vk, &[(&r0, &action_rel1_proof())], &allow), Some(E::CommitmentKnowledge));
    assert_eq!(go(&action_vk(), &[(&r0, &p0)], &allow), Some(E::CommitmentKnowledge));
    // A revision-1 key, even allowlisted, is refused at parse.
    let rev1 = unhex(&json(repo("packages/protocol-runtime/test-vectors/apnt-pool-v1-proof-system-registry-vectors.json"))["shapeVector"]["vp"]);
    let rev1_pid = derive_profile_id(1, &rev1).safe();
    assert_eq!(go(&rev1, &[(&r0, &p0)], &[rev1_pid]), Some(E::VerifierParameters));
    // A duplicated action.
    assert_eq!(go(&vk, &[(&r0, &p0), (&r0, &p0)], &allow), Some(E::StatementOrder));
    // B = 0.
    assert_eq!(go(&vk, &[], &allow), Some(E::StatementCount));
    // A bad record key.
    let mut bad_key = r0;
    bad_key[offset::RERANDOMIZED_KEY_0] = 0x04;
    assert_eq!(go(&vk, &[(&bad_key, &p0)], &allow), Some(E::RecordKey));
    // A duplicate nullifier across two records.
    let mut dup_nf = r1;
    dup_nf[offset::NULLIFIER_0..offset::NULLIFIER_0 + 32].copy_from_slice(&r0[offset::NULLIFIER_1..offset::NULLIFIER_1 + 32]);
    assert_eq!(go(&vk, &[(&r0, &p0), (&dup_nf, &p1)], &allow), Some(E::StatementDuplicateNullifier));
    // Input framing, including a revision-2 396-byte record.
    let good = batch_input(&vk, &[(&r0, &p0)]);
    assert!(parse_input(&good).is_ok());
    assert_eq!(run(&good[..good.len() - 1], &allow, &mut NoTrace).err(), Some(E::Input));
    let mut long = good.clone();
    long.push(0);
    assert_eq!(run(&long, &allow, &mut NoTrace).err(), Some(E::Input));
    assert_eq!(run(&batch_input(&vk, &[(&rev2[0].1, &p0)]), &allow, &mut NoTrace).err(), Some(E::Input));
    // A proof of the wrong shape.
    let mut short = p0.clone();
    short.truncate(PROOF_BYTES - 1);
    assert_eq!(VerifyingKey::parse(&vk).and_then(|k| crate::groth16::verify(&k, &short, &r0)).err(), Some(E::ProofShape));
    });
}

// ---- revision 3 under the recorded Chipnet vp (ENG-486) ----
//
// SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY: the project ran every
// contribution of the ceremony behind this key and could forge proofs under
// it. These runs show the construction and its cost, never validity to anyone
// but this process.

fn rev3(path: &str) -> Vec<u8> {
    fs::read(tool(&format!("fixtures/simulated-ceremony-zero-value-rev3/{path}"))).safe()
}
fn registry_rev3() -> Value {
    json(repo("packages/protocol-runtime/test-vectors/apnt-pool-v1-proof-system-registry-rev3-vectors.json"))
}
/// Registry entry 1 revision 3's recorded Chipnet vp.
fn ceremony_vp() -> Vec<u8> {
    unhex(&registry_rev3()["chipnetZeroValueVp"]["vp"])
}
/// The recorded vp with δ rescaled by a public scalar, and REL1's ceremony proof with C rescaled to match (no Setup ran).
fn ceremony_alt_vk() -> Vec<u8> {
    rev3("transform/alt-vk.bin")
}
fn ceremony_alt_proof() -> Vec<u8> {
    rev3("transform/alt-proof.bin")
}
fn run_vectors() -> Value {
    json(tool("fixtures/pool-aggregate-statement-vectors-v4.json"))
}
fn reference_v3() -> Value {
    json(tool("fixtures/simulated-ceremony-zero-value-rev3/gnark-reference-v3.json"))
}
/// Every host positive with its ceremony proof, (name, 314-byte record, proof), in corpus order.
fn ceremony_batch() -> Vec<(String, [u8; RECORD_BYTES], Vec<u8>)> {
    let v = run_vectors();
    let every = v["vectors"].as_array().safe().iter().find(|x| x["name"] == "b18-every-positive-reversed").safe();
    let names = every["recordNames"].as_array().safe();
    let records = every["records"].as_array().safe();
    let mut out: Vec<_> = names
        .iter()
        .zip(records)
        .map(|(n, r)| {
            let name = n.as_str().safe().to_owned();
            let proof = rev3(&format!("proofs/{name}.proof.bin"));
            (name, unhex(r).try_into().safe(), proof)
        })
        .collect();
    out.reverse();
    out
}

#[test]
#[ignore = "requires excluded frozen proof or reference inputs; not shipped"]
fn the_recorded_vp_is_the_ceremony_profile_id_of_the_registry_the_host_and_the_run_vectors() {
    control("C15");
    guarded(|| {
    let vp = ceremony_vp();
    let registry = registry_rev3();
    assert_eq!(registry["chipnetZeroValueVp"]["label"], "SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY");
    assert_eq!(vp.len(), VP_BYTES);
    VerifyingKey::parse(&vp).safe();
    let id = derive_profile_id(1, &vp).safe();
    assert_eq!(id, CHIPNET_ZERO_VALUE_REVISION_3_PROFILE_ID);
    assert_eq!(hex::encode(id), registry["chipnetZeroValueVp"]["profileId"].as_str().safe());
    assert_eq!(hex::encode(id), run_vectors()["profileId"].as_str().safe());
    assert_ne!(hex::encode(id), registry["shapeVector"]["profileId"].as_str().safe());
    // The fixture set carries the ceremony's label beside its proofs.
    let label = String::from_utf8(rev3("PARAMETERS-LABEL.txt")).safe();
    assert!(label.starts_with("SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY"), "{label}");
    let provenance = String::from_utf8(rev3("PROVENANCE.txt")).safe();
    assert!(provenance.starts_with("SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY") && provenance.contains(&hex::encode(id)));
    });
}

#[test]
#[ignore = "requires excluded frozen proof or reference inputs; not shipped"]
fn every_ceremony_proof_verifies_over_its_revision_3_record_and_nothing_else() {
    control("C16");
    guarded(|| {
    // 18 proofs, one per host positive; each verifies over its own 314-byte
    // record, is refused over the next record, and, where the reduction runs,
    // with x read little-endian or truncated.
    let vk = VerifyingKey::parse(&ceremony_vp()).safe();
    let batch = ceremony_batch();
    assert_eq!(batch.len(), 18);
    let mut reduced = 0;
    for (i, (name, record, proof)) in batch.iter().enumerate() {
        ordinal(i);
        crate::groth16::verify(&vk, proof, record).unwrap_or_else(|e| panic!("{name}: {}", e.code()));
        let next = &batch[(i + 1) % batch.len()].1;
        assert_eq!(crate::groth16::verify(&vk, proof, next), Err(E::ProofRejected), "{name} over another record");
        if testing::digest_at_least_r(record) {
            reduced += 1;
            assert_eq!(testing::verify_with_x(&vk, proof, testing::public_input_little_endian(record)), Err(E::ProofRejected), "{name}");
            assert_eq!(testing::verify_with_x(&vk, proof, testing::public_input_truncated(record)), Err(E::ProofRejected), "{name}");
        }
    }
    // REL1, REL2, alpha-zero-rk-equals-ak and chain-1 have digests below r.
    assert_eq!(reduced, 14);
    // Revision 2's stand-in key refuses a revision-3 ceremony proof at the knowledge check (its own Pedersen key).
    let standin = VerifyingKey::parse(&standin_vk()).safe();
    assert_eq!(crate::groth16::verify(&standin, &batch[0].2, &batch[0].1), Err(E::CommitmentKnowledge));
    });
}

fn ceremony_keys() -> [(&'static str, Vec<u8>); 2] {
    [("batch", ceremony_vp()), ("alt", ceremony_alt_vk())]
}

#[test]
#[ignore = "requires excluded frozen proof or reference inputs; not shipped"]
fn decoded_points_equal_gnarks_at_revision_3() {
    control("C17");
    guarded(|| {
    let r = reference_v3();
    assert!(r["parameters"].as_str().safe().starts_with("SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY"));
    for (name, raw) in ceremony_keys() {
        let want = &r["verifyingKeys"][name];
        assert_eq!(want["sha256"].as_str().safe(), hex::encode(crate::sha256(&[&raw])), "{name}");
        let vk = VerifyingKey::parse(&raw).safe();
        assert_g1("alpha", &vk.alpha, &want["alpha"]);
        assert_g1("beta1", &vk.beta_g1, &want["betaG1"]);
        assert_g2("beta2", &vk.beta, &want["betaG2"]);
        assert_g2("gamma2", &vk.gamma, &want["gammaG2"]);
        assert_g1("delta1", &vk.delta_g1, &want["deltaG1"]);
        assert_g2("delta2", &vk.delta, &want["deltaG2"]);
        let k = want["k"].as_array().safe();
        assert_eq!(k.len(), 3);
        for (i, (got, w)) in vk.k.iter().zip(k).enumerate() {
            assert_g1(&format!("{name} K[{i}]"), got, w);
        }
        assert_g2("G", &vk.commitment_g, &want["commitmentG"]);
        assert_g2("GσNeg", &vk.commitment_g_sigma_neg, &want["commitmentGSigmaNeg"]);
    }
    assert!(r["verifyingKeys"].get("action").is_none());
    let proofs = r["proofs"].as_array().safe();
    assert_eq!(proofs.len(), 19, "18 ceremony proofs and the rescaled one");
    let batch = ceremony_batch();
    for (index, p) in proofs.iter().enumerate() {
        ordinal(index);
        let name = p["name"].as_str().safe();
        let raw = unhex(&p["proof"]);
        if let Some((_, _, fixture)) = batch.iter().find(|(n, _, _)| n == name) {
            assert_eq!(&raw, fixture, "{name}: the dump's proof is the committed fixture");
        }
        let proof = Proof::parse(&raw).safe();
        assert_g1(name, &proof.a, &p["a"]);
        assert_g2(name, &proof.b, &p["b"]);
        assert_g1(name, &proof.c, &p["c"]);
        assert_g1(name, &proof.commitment, &p["commitment"]);
        assert_g1(name, &proof.commitment_pok, &p["commitmentPok"]);
        assert_eq!(testing::fr_hex(commitment_wire(&proof.commitment).safe()), p["commitmentWire"].as_str().safe(), "{name} h");
    }
    });
}

#[test]
#[ignore = "requires excluded frozen proof or reference inputs; not shipped"]
fn every_verdict_equals_gnarks_at_revision_3() {
    control("C18");
    guarded(|| {
    let r = reference_v3();
    let keys = ceremony_keys();
    let mut accepted = Vec::new();
    let cases = r["cases"].as_array().safe();
    for (index, c) in cases.iter().enumerate() {
        ordinal(index);
        let name = c["name"].as_str().safe();
        let mut vp = keys.iter().find(|(k, _)| *k == c["vk"].as_str().safe()).safe().1.clone();
        for m in c["vkMutations"].as_array().into_iter().flatten() {
            vp[m["offset"].as_u64().safe() as usize] ^= m["xor"].as_u64().safe() as u8;
        }
        let proof = unhex(&c["proof"]);
        let record = unhex(&c["record"]);
        let ours = match c.get("publicInput") {
            Some(x) => VerifyingKey::parse(&vp).and_then(|vk| testing::verify_with_x(&vk, &proof, Fr::from_bytes_be_mod_order(&unhex(x)).safe())),
            None => VerifyingKey::parse(&vp).and_then(|vk| verify_bytes(&vk, &proof, &record)),
        };
        let gnark = c["gnarkAccepted"].as_bool().safe();
        assert_eq!(ours.is_ok(), gnark, "verdict");
        if gnark {
            accepted.push(name.to_owned());
        }
    }
    let honest = accepted.iter().filter(|n| n.starts_with("honest:")).count();
    assert_eq!(honest, 18, "every ceremony proof with its own record");
    let mut rest: Vec<&str> = accepted.iter().map(String::as_str).filter(|n| !n.starts_with("honest:")).collect();
    rest.sort();
    assert_eq!(rest, REV3_ACCEPTED_NON_HONEST);
    assert!(cases.len() >= 100);
    });
}

/// gnark's accepted cases beyond the 18 honest ones in the revision-3 dump:
/// the rescaled pair under its own key; a flipped byte of β1 and of δ1, which
/// the one serialization carries but Verify does not read (each flipped byte
/// still decodes to a point for this key; in revision 2's dump only δ1's did);
/// x given explicitly; and the unreduced digest, which gnark reduces to x.
const REV3_ACCEPTED_NON_HONEST: [&str; 5] =
    ["alt:alt-proof-under-alt-vk", "vk:beta-g1-byte", "vk:delta-g1-byte", "x:honest", "x:unreduced-digest"];

fn ceremony_input(vp: &[u8], actions: &[(&[u8], &[u8])]) -> Vec<u8> {
    encode_input(vp, &arr32(&run_vectors()["deploymentId"]), actions)
}

#[test]
#[ignore = "requires excluded frozen proof or reference inputs; not shipped"]
fn run_accepts_every_revision_3_positive_and_commits_the_hosts_run_bind() {
    control("C19");
    guarded(|| {
    let vp = ceremony_vp();
    let proofs: std::collections::BTreeMap<String, Vec<u8>> = ceremony_batch().into_iter().map(|(n, _, p)| (n, p)).collect();
    let v = run_vectors();
    assert_eq!(arr32(&v["deploymentId"]), arr32(&statement_vectors()["deploymentId"]));
    let allow = [CHIPNET_ZERO_VALUE_REVISION_3_PROFILE_ID];
    let vectors = v["vectors"].as_array().safe();
    assert_eq!(vectors.iter().map(|x| x["records"].as_array().safe().len()).collect::<Vec<_>>(), [1, 2, 4, 16, 17, 18]);
    for (index, x) in vectors.iter().enumerate() {
        ordinal(index);
        let name = x["name"].as_str().safe();
        let records: Vec<Vec<u8>> = x["records"].as_array().safe().iter().map(unhex).collect();
        let names = x["recordNames"].as_array().safe();
        let actions: Vec<(&[u8], &[u8])> =
            records.iter().zip(names).map(|(r, n)| (r.as_slice(), proofs[n.as_str().safe()].as_slice())).collect();
        let input = ceremony_input(&vp, &actions);
        let accepted = run(&input, &allow, &mut NoTrace).unwrap_or_else(|e| panic!("{name}: refused {}", e.code()));
        assert_eq!(hex::encode(accepted.run_bind), x["runBind32"].as_str().safe(), "{name}");
        // The same input under the default (empty) allowlist is refused before anything is verified.
        assert_eq!(run(&input, &[], &mut NoTrace).err(), Some(E::ProfileNotAllowlisted), "{name}");
        if cfg!(feature = "development-zero-value-test-profile") {
            assert_eq!(run(&input, COMPILED_PROFILE_ALLOWLIST, &mut NoTrace).safe().run_bind, accepted.run_bind, "{name}");
        }
    }
    });
}

#[test]
#[ignore = "requires excluded frozen proof or reference inputs; not shipped"]
fn run_refuses_the_pairing_negatives_beside_an_accepted_run_at_revision_3() {
    control("C20");
    guarded(|| {
    let vp = ceremony_vp();
    let b = ceremony_batch();
    let allow = [CHIPNET_ZERO_VALUE_REVISION_3_PROFILE_ID];
    let go = |vp: &[u8], actions: &[(&[u8], &[u8])], allowlist: &[[u8; 32]]| run(&ceremony_input(vp, actions), allowlist, &mut NoTrace);
    let (r0, p0) = (&b[0].1, &b[0].2);
    let (r1, p1) = (&b[1].1, &b[1].2);
    // The honest pair is accepted, so each refusal below is its mutation's.
    go(&vp, &[(r0, p0), (r1, p1)], &allow).safe();
    // A tampered record: the fee's low byte flipped. It still decodes, and x changes.
    let mut tampered = *r0;
    tampered[offset::FEE] ^= 1;
    check_record(&tampered).safe();
    assert_eq!(go(&vp, &[(&tampered, p0)], &allow).err(), Some(E::ProofRejected));
    // Two honest actions with their proofs swapped.
    assert_eq!(go(&vp, &[(r0, p1), (r1, p0)], &allow).err(), Some(E::ProofRejected));
    // The δ-rescaled key: its proof is valid under it, and refused under the recorded vp.
    let (alt_vk, alt_proof) = (ceremony_alt_vk(), ceremony_alt_proof());
    assert_eq!(go(&vp, &[(r0, &alt_proof)], &allow).err(), Some(E::ProofRejected));
    assert_eq!(go(&alt_vk, &[(r0, p0)], &[derive_profile_id(1, &alt_vk).safe()]).err(), Some(E::ProofRejected));
    // Offered as the prover's own key, the allowlist refuses it before parsing…
    assert_eq!(go(&alt_vk, &[(r0, &alt_proof)], &allow).err(), Some(E::ProfileNotAllowlisted));
    // …and it is the allowlist alone: allowlisted, the same input is accepted, because its proof really verifies under it.
    go(&alt_vk, &[(r0, &alt_proof)], &[derive_profile_id(1, &alt_vk).safe()]).safe();
    // A revision-2 proof of the same action, even under an allowlisted key, is refused.
    assert_eq!(go(&vp, &[(r0, &revision_2_batch()[0].2)], &allow).err(), Some(E::CommitmentKnowledge));
    });
}

/// The labelled Chipnet build's allowlist (ENG-510): exactly revision 3's recorded vp.
const CHIPNET_BUILD_ALLOWLIST: [[u8; 32]; 1] = [CHIPNET_ZERO_VALUE_REVISION_3_PROFILE_ID];

#[test]
#[ignore = "requires excluded frozen proof or reference inputs; not shipped"]
fn the_chipnet_build_accepts_only_the_recorded_vp_and_the_default_build_refuses_it() {
    control("C21");
    guarded(|| {
    let vp = ceremony_vp();
    let b = ceremony_batch();
    let (r0, p0) = (&b[0].1, &b[0].2);
    let go = |vp: &[u8], actions: &[(&[u8], &[u8])], allowlist: &[[u8; 32]]| run(&ceremony_input(vp, actions), allowlist, &mut NoTrace);
    // The recorded vp with REL1's honest ceremony proof: accepted by the Chipnet
    // build's allowlist, refused by the default build's before anything is parsed.
    go(&vp, &[(r0, p0)], &CHIPNET_BUILD_ALLOWLIST).safe();
    assert_eq!(go(&vp, &[(r0, p0)], &[]).err(), Some(E::ProfileNotAllowlisted));
    // Every other key, each with a proof that really verifies under it, is refused by the
    // Chipnet build at the allowlist: the revision-2 action circuit's development key, the
    // revision-2 stand-in key, a second stand-in Setup's key and the δ-rescaled Chipnet key.
    // (The revision-2 keys' proofs are of REL1's 396-byte record; here they frame with its
    // 314-byte record, as the runner's cases do, and the allowlist refuses before any pairing.)
    let (_, rel1_record) = &batch()[0];
    assert_eq!(rel1_record, r0);
    let others: [(&str, Vec<u8>, &[u8], Vec<u8>); 4] = [
        ("revision-2 action development key", action_vk(), rel1_record.as_slice(), action_rel1_proof()),
        ("revision-2 stand-in key", standin_vk(), rel1_record.as_slice(), revision_2_batch()[0].2.clone()),
        ("second stand-in key", key_c_vk(), rel1_record.as_slice(), key_c_rel1_proof()),
        ("δ-rescaled Chipnet key", ceremony_alt_vk(), r0.as_slice(), ceremony_alt_proof()),
    ];
    for (name, other_vp, record, proof) in &others {
        let pid = derive_profile_id(1, other_vp).safe();
        assert!(!CHIPNET_BUILD_ALLOWLIST.contains(&pid), "{name}");
        let input = ceremony_input(other_vp, &[(record, proof)]);
        assert_eq!(run(&input, &CHIPNET_BUILD_ALLOWLIST, &mut NoTrace).err(), Some(E::ProfileNotAllowlisted), "{name}");
        if cfg!(feature = "chipnet-zero-value-rev3-profile") {
            assert_eq!(run(&input, COMPILED_PROFILE_ALLOWLIST, &mut NoTrace).err(), Some(E::ProfileNotAllowlisted), "{name}");
        }
    }
    // The development ids are the revision-2 keys' own, so the refusals above are of those keys.
    assert_eq!(derive_profile_id(1, &others[0].1).safe(), DEVELOPMENT_ZERO_VALUE_ACTION_PROFILE_ID);
    assert_eq!(derive_profile_id(1, &others[1].1).safe(), DEVELOPMENT_ZERO_VALUE_STANDIN_PROFILE_ID);
    // Control: the δ-rescaled key's own proof verifies under it once it is allowlisted,
    // so the Chipnet build's refusal of it is the allowlist's alone.
    let alt = &others[3];
    run(&ceremony_input(&alt.1, &[(alt.2, &alt.3)]), &[derive_profile_id(1, &alt.1).safe()], &mut NoTrace).safe();
    // B = 17 under the Chipnet allowlist commits the host's runBind32.
    let v = run_vectors();
    let b17 = v["vectors"].as_array().safe().iter().find(|x| x["name"] == "b17-reversed").safe();
    let proofs: std::collections::BTreeMap<String, Vec<u8>> = b.iter().map(|(n, _, p)| (n.clone(), p.clone())).collect();
    let records: Vec<Vec<u8>> = b17["records"].as_array().safe().iter().map(unhex).collect();
    let actions: Vec<(&[u8], &[u8])> = records
        .iter()
        .zip(b17["recordNames"].as_array().safe())
        .map(|(r, n)| (r.as_slice(), proofs[n.as_str().safe()].as_slice()))
        .collect();
    let accepted = run(&ceremony_input(&vp, &actions), &CHIPNET_BUILD_ALLOWLIST, &mut NoTrace).safe();
    assert_eq!(hex::encode(accepted.run_bind), b17["runBind32"].as_str().safe());
    if cfg!(feature = "chipnet-zero-value-rev3-profile") {
        assert_eq!(run(&ceremony_input(&vp, &actions), COMPILED_PROFILE_ALLOWLIST, &mut NoTrace).safe().run_bind, accepted.run_bind);
    }
    });
}
