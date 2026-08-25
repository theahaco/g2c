//! Smoke test proving the vendored `UltraHonk` verifier still verifies real
//! proofs after being retargeted onto soroban-sdk 26.0.1.
//!
//! Fixtures (`vk`, `proof`, `public_inputs`) are the compiled `simple_circuit`
//! artifacts from upstream `rs-soroban-ultrahonk`'s
//! `tests/simple_circuit/target/`, copied verbatim into
//! `contracts/zk-verifier/tests/fixtures/` so this test is self-contained
//! within nido (no dependency on the sibling `zk` repo at test time).

use soroban_sdk::{testutils::Address as _, Address, Bytes, Env};

mod zk_verifier_contract {
    // Path is relative to CARGO_MANIFEST_DIR (this crate's directory); the
    // wasm lands in the shared workspace-root target/ dir.
    soroban_sdk::contractimport!(
        file = "../../target/wasm32v1-none/contract/nido_zk_verifier.wasm"
    );
}

fn register_client<'a>(env: &'a Env, vk_bytes: &Bytes) -> zk_verifier_contract::Client<'a> {
    let contract_id = env.register(
        zk_verifier_contract::WASM,
        (Address::generate(env), vk_bytes.clone()),
    );
    zk_verifier_contract::Client::new(env, &contract_id)
}

#[test]
fn verify_simple_circuit_proof_succeeds() {
    let vk_bytes_raw: &[u8] = include_bytes!("fixtures/vk");
    let proof_bin: &[u8] = include_bytes!("fixtures/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("fixtures/public_inputs");

    let env = Env::default();
    // Proves the vendored math still verifies under sdk 26.0.1, not budget.
    env.cost_estimate().budget().reset_unlimited();

    let vk_bytes = Bytes::from_slice(&env, vk_bytes_raw);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, pub_inputs_bin);

    let client = register_client(&env, &vk_bytes);
    client.verify_proof(&public_inputs, &proof_bytes);
}

/// The constructor stores the upgrade `admin`, and `set_admin` rotates it
/// (auth enforced the same way the factory's proven `upgrade`/`set_admin`
/// pattern is). Upgrading the wasm itself needs a second installed module, so
/// that path is exercised at the integration level, not here.
#[test]
fn admin_is_stored_and_rotatable() {
    let env = Env::default();
    env.mock_all_auths();
    let vk_bytes = Bytes::from_slice(&env, include_bytes!("fixtures/vk"));

    let admin = Address::generate(&env);
    let id = env.register(zk_verifier_contract::WASM, (admin.clone(), vk_bytes));
    let client = zk_verifier_contract::Client::new(&env, &id);
    assert_eq!(client.admin(), admin);

    let new_admin = Address::generate(&env);
    client.set_admin(&new_admin);
    assert_eq!(client.admin(), new_admin);
}

#[test]
// Error #2 is `Error::ProofParseError` in `contracts/zk-verifier/src/lib.rs`.
// A truncated proof used to panic inside the vendored parser's length
// `assert_eq!` (a host trap); the boundary length pre-check now rejects it with
// a structured `ProofParseError` BEFORE the vendored code runs. `try_verify_proof`
// returns the typed error rather than trapping, proving the failure is clean.
fn verify_with_truncated_proof_returns_parse_error() {
    let vk_bytes_raw: &[u8] = include_bytes!("fixtures/vk");
    let proof_bin: &[u8] = include_bytes!("fixtures/proof");
    let pub_inputs_bin: &[u8] = include_bytes!("fixtures/public_inputs");

    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();

    let vk_bytes = Bytes::from_slice(&env, vk_bytes_raw);
    // Drop the last 32-byte field: a valid-prefix but too-short proof.
    let truncated = &proof_bin[..proof_bin.len() - 32];
    let proof_bytes: Bytes = Bytes::from_slice(&env, truncated);
    let public_inputs: Bytes = Bytes::from_slice(&env, pub_inputs_bin);

    let client = register_client(&env, &vk_bytes);
    let res = client.try_verify_proof(&public_inputs, &proof_bytes);
    // The WASM client's `try_` maps a returned contract error into its own
    // generated `Error` enum; a bad-length proof must surface as the typed
    // `ProofParseError` (not a trap), proving the failure is clean.
    assert_eq!(
        res,
        Err(Ok(zk_verifier_contract::Error::ProofParseError)),
        "a truncated proof must return ProofParseError, not trap"
    );
}

#[test]
// Error #3 is `Error::VerificationFailed` in `contracts/zk-verifier/src/lib.rs`.
#[should_panic(expected = "Error(Contract, #3)")]
fn verify_with_tampered_public_inputs_fails() {
    let vk_bytes_raw: &[u8] = include_bytes!("fixtures/vk");
    let proof_bin: &[u8] = include_bytes!("fixtures/proof");
    let mut pub_inputs_vec = include_bytes!("fixtures/public_inputs").to_vec();
    pub_inputs_vec[0] ^= 0xff; // Tamper with first byte

    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();

    let vk_bytes = Bytes::from_slice(&env, vk_bytes_raw);
    let proof_bytes: Bytes = Bytes::from_slice(&env, proof_bin);
    let public_inputs: Bytes = Bytes::from_slice(&env, &pub_inputs_vec);

    let client = register_client(&env, &vk_bytes);
    client.verify_proof(&public_inputs, &proof_bytes);
}
