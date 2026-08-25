//! M1 Task 1: the ZK-recovery lifecycle fixture harness.
//!
//! Three things live here:
//!
//! 1. `print_lifecycle_prover_toml` -- a `#[ignore]`d generator, not part of
//!    the normal suite. It computes the pinned lifecycle witness (see
//!    `nido_integration_tests::zk_fixture`) using the exact
//!    `soroban_poseidon::poseidon2_hash` construction that `zk_vectors.rs`
//!    already proved matches Noir's `Poseidon2::hash` at arity 2, 4, and 15
//!    -- so these values are guaranteed to match what the circuit computes
//!    for the same witness. `circuits/zk_recovery/scripts/gen_lifecycle_fixture.sh`
//!    (via `just gen-zk-lifecycle-fixture`) runs it and feeds its output to
//!    `nargo`/`bb` to produce the real proof.
//! 2. `fixture_addresses_pin` -- proves `env.register_at` pins a contract's
//!    resolved `Address` to the exact contract-id bytes the fixture's
//!    `auth_hash` binds (`zk_fixture::ACCOUNT`/`CONTROLLER`).
//! 3. `fixture_proof_verifies` -- proves the committed fixture proof is a
//!    REAL, valid `UltraHonk` proof under the M0 verifier wasm + vk.

use nido_integration_tests::{test_key, zk_fixture};
use sha2::{Digest, Sha256};
use soroban_poseidon::{poseidon2_hash, Field as PoseidonField};
use soroban_sdk::address_payload::AddressPayload;
use soroban_sdk::crypto::BnScalar;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Bytes, BytesN, Env, Vec as SVec, U256};
use std::fmt::Write as _;

const DEPTH: usize = 24;

const DOM_LEAF: &str = "0x10d2382af89f3c1732985422f0ba530d1dd0ed3066ecce5650b78f0c4ad8274a";
const DOM_BIND: &str = "0x14fa8513f19a07697a83cf582b40cb80bb2176f890614912553b81cdff71ec81";
const DOM_NULL: &str = "0x138891cc07f52d2ec29e835298ae2120acd9573ec4a83c573885abf9710b73b2";
const DOM_AUTH: &str = "0x2886eb8be3a3ff75b86ac004fdbe5c17fd2de6ab4fd416d38683a2e0e91d9906";

fn hex32(s: &str) -> [u8; 32] {
    let s = s.strip_prefix("0x").unwrap_or(s);
    assert_eq!(s.len(), 64, "expected 32-byte hex string, got {s:?}");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn hex_bytes(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn to_hex(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex_bytes(bytes))
}

/// Same construction as `zk_vectors.rs::p2` (the Rust test that proves the
/// Soroban host's `poseidon2_hash::<4, BnScalar>` reproduces Noir's
/// `Poseidon2::hash` output at every arity the circuit uses). Reusing it
/// here means the fixture's `root/nullifier/auth_hash` are guaranteed to
/// match what `nargo`/`bb` compute for the same witness.
fn p2(env: &Env, inputs: &[[u8; 32]]) -> [u8; 32] {
    let modulus = <BnScalar as PoseidonField>::modulus(env);
    let mut v = SVec::new(env);
    for x in inputs {
        v.push_back(U256::from_be_bytes(env, &Bytes::from_array(env, x)).rem_euclid(&modulus));
    }
    let out = poseidon2_hash::<4, BnScalar>(env, &v);
    let mut a = [0u8; 32];
    out.to_be_bytes().copy_into_slice(&mut a);
    a
}

fn field_u64(x: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&x.to_be_bytes());
    out
}

/// Big-endian 16/16-byte split into two zero-extended 32-byte field
/// elements, matching `main.nr`'s `acct_hi`/`acct_lo` (and
/// `ctrl_hi`/`ctrl_lo`, `npass_hi`/`npass_lo`, `pk_x_hi`/`pk_x_lo`,
/// `pk_y_hi`/`pk_y_lo`) convention.
fn split16(bytes: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut hi = [0u8; 32];
    hi[16..32].copy_from_slice(&bytes[0..16]);
    let mut lo = [0u8; 32];
    lo[16..32].copy_from_slice(&bytes[16..32]);
    (hi, lo)
}

/// zero[0] = 0 (empty leaf), zero[i+1] = hash2(zero[i], zero[i]) -- mirrors
/// `circuits/zk_recovery/src/tests.nr::zero_hashes`.
fn zero_hashes(env: &Env) -> [[u8; 32]; DEPTH] {
    let mut zeros = [[0u8; 32]; DEPTH];
    let mut prev = [0u8; 32];
    for z in &mut zeros {
        *z = prev;
        prev = p2(env, &[prev, prev]);
    }
    zeros
}

fn lifecycle_secret() -> [u8; 32] {
    let digest = Sha256::digest(zk_fixture::SECRET_LABEL);
    let mut out = [0u8; 32];
    out[16..32].copy_from_slice(&digest[0..16]);
    out
}

#[test]
#[ignore = "generator invoked by `just gen-zk-lifecycle-fixture` \
            (circuits/zk_recovery/scripts/gen_lifecycle_fixture.sh), not part of the normal suite"]
// Long, linear witness-printing generator; splitting it would obscure the
// 1:1 correspondence with the Prover.toml fields it emits.
#[allow(clippy::too_many_lines)]
// `pk_x_hi`/`pk_x_lo` vs `pk_y_hi`/`pk_y_lo` mirror the circuit's own
// naming convention (see `split16`'s doc comment) and are clearer named
// this way than disambiguated.
#[allow(clippy::similar_names)]
fn print_lifecycle_prover_toml() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();

    let dom_leaf = hex32(DOM_LEAF);
    let dom_bind = hex32(DOM_BIND);
    let dom_null = hex32(DOM_NULL);
    let dom_auth = hex32(DOM_AUTH);

    let secret = lifecycle_secret();
    let (acct_hi, acct_lo) = split16(&zk_fixture::ACCOUNT);
    let (ctrl_hi, ctrl_lo) = split16(&zk_fixture::CONTROLLER);

    let npass_hash: [u8; 32] = Sha256::digest(zk_fixture::NETWORK_PASSPHRASE.as_bytes()).into();
    let (npass_hi, npass_lo) = split16(&npass_hash);

    let new_pubkey_sec1 = test_key(zk_fixture::NEW_PUBKEY_SEED)
        .verifying_key()
        .to_sec1_bytes();
    assert_eq!(
        new_pubkey_sec1.len(),
        65,
        "P-256 SEC1 pubkey must be 65 bytes"
    );
    assert_eq!(
        new_pubkey_sec1[0], 0x04,
        "P-256 SEC1 pubkey must be uncompressed"
    );
    let mut pk_x = [0u8; 32];
    pk_x.copy_from_slice(&new_pubkey_sec1[1..33]);
    let mut pk_y = [0u8; 32];
    pk_y.copy_from_slice(&new_pubkey_sec1[33..65]);
    let (pk_x_hi, pk_x_lo) = split16(&pk_x);
    let (pk_y_hi, pk_y_lo) = split16(&pk_y);

    let action = field_u64(zk_fixture::ACTION);
    let nonce = field_u64(zk_fixture::NONCE);
    let timelock_secs = field_u64(u64::from(zk_fixture::TIMELOCK_SECS));
    let pk_prefix = field_u64(0x04);

    let zeros = zero_hashes(&env);

    let inner = p2(&env, &[dom_leaf, secret]);
    let stored = p2(&env, &[dom_bind, acct_hi, acct_lo, inner]);

    let mut cur = stored;
    for z in &zeros {
        cur = p2(&env, &[cur, *z]);
    }
    let root = cur;

    let nullifier = p2(&env, &[dom_null, acct_hi, acct_lo, secret]);

    let auth_hash = p2(
        &env,
        &[
            dom_auth,
            action,
            acct_hi,
            acct_lo,
            npass_hi,
            npass_lo,
            ctrl_hi,
            ctrl_lo,
            pk_prefix,
            pk_x_hi,
            pk_x_lo,
            pk_y_hi,
            pk_y_lo,
            nonce,
            timelock_secs,
        ],
    );

    println!("###PROVER_TOML_BEGIN###");
    println!("root = \"{}\"", to_hex(&root));
    println!("nullifier = \"{}\"", to_hex(&nullifier));
    println!("auth_hash = \"{}\"", to_hex(&auth_hash));
    println!("secret = \"{}\"", to_hex(&secret));
    println!("acct_hi = \"{}\"", to_hex(&acct_hi));
    println!("acct_lo = \"{}\"", to_hex(&acct_lo));
    println!("path_bits = [");
    for _ in 0..DEPTH {
        println!("  \"0x00\",");
    }
    println!("]");
    println!("path_siblings = [");
    for z in &zeros {
        println!("  \"{}\",", to_hex(z));
    }
    println!("]");
    println!("action = \"{}\"", to_hex(&action));
    println!("npass_hi = \"{}\"", to_hex(&npass_hi));
    println!("npass_lo = \"{}\"", to_hex(&npass_lo));
    println!("ctrl_hi = \"{}\"", to_hex(&ctrl_hi));
    println!("ctrl_lo = \"{}\"", to_hex(&ctrl_lo));
    println!("pk_prefix = \"{}\"", to_hex(&pk_prefix));
    println!("pk_x_hi = \"{}\"", to_hex(&pk_x_hi));
    println!("pk_x_lo = \"{}\"", to_hex(&pk_x_lo));
    println!("pk_y_hi = \"{}\"", to_hex(&pk_y_hi));
    println!("pk_y_lo = \"{}\"", to_hex(&pk_y_lo));
    println!("nonce = \"{}\"", to_hex(&nonce));
    println!("timelock_secs = \"{}\"", to_hex(&timelock_secs));
    println!("###PROVER_TOML_END###");

    println!("###PROVER_JSON_BEGIN###");
    println!("{{");
    println!("  \"account\": \"{}\",", to_hex(&zk_fixture::ACCOUNT));
    println!("  \"controller\": \"{}\",", to_hex(&zk_fixture::CONTROLLER));
    println!(
        "  \"network_passphrase\": \"{}\",",
        zk_fixture::NETWORK_PASSPHRASE
    );
    println!("  \"nonce\": {},", zk_fixture::NONCE);
    println!("  \"timelock_secs\": {},", zk_fixture::TIMELOCK_SECS);
    println!("  \"action\": {},", zk_fixture::ACTION);
    println!("  \"new_pubkey_seed\": {},", zk_fixture::NEW_PUBKEY_SEED);
    println!("  \"new_pubkey\": \"0x{}\",", hex_bytes(&new_pubkey_sec1));
    println!(
        "  \"secret_label\": \"{}\",",
        String::from_utf8_lossy(zk_fixture::SECRET_LABEL)
    );
    println!("  \"secret\": \"{}\",", to_hex(&secret));
    println!("  \"leaf_stored\": \"{}\",", to_hex(&stored));
    println!("  \"root\": \"{}\",", to_hex(&root));
    println!("  \"nullifier\": \"{}\",", to_hex(&nullifier));
    println!("  \"auth_hash\": \"{}\"", to_hex(&auth_hash));
    println!("}}");
    println!("###PROVER_JSON_END###");
}

/// M1 Task 6: the CANCEL-variant generator, invoked by
/// `just gen-zk-lifecycle-cancel-fixture` (`circuits/zk_recovery/scripts/gen_lifecycle_cancel_fixture.sh`).
/// Computes the witness for a real `action=2` ("cancel recovery") proof over
/// the SAME leaf/secret/root/nullifier as the base lifecycle fixture (spec
/// §2.4: cancel never touches the Merkle tree or the nullifier's derivation,
/// only `auth_hash`), but with `pk_prefix`/`pk_x`/`pk_y`/`timelock_secs` all
/// ZEROED and `nonce = CANCEL_NONCE` (the nonce this cancel proof is bound
/// to -- `2`, i.e. immediately following the base fixture's `nonce = 1`
/// initiate). This mirrors `print_lifecycle_prover_toml` exactly except for
/// those substitutions.
#[test]
#[ignore = "generator invoked by `just gen-zk-lifecycle-cancel-fixture` \
            (circuits/zk_recovery/scripts/gen_lifecycle_cancel_fixture.sh), not part of the normal suite"]
// Long, linear witness-printing generator; splitting it would obscure the
// 1:1 correspondence with the Prover.toml fields it emits.
#[allow(clippy::too_many_lines)]
// `pk_x_hi`/`pk_x_lo` vs `pk_y_hi`/`pk_y_lo` mirror the circuit's own
// naming convention (see `split16`'s doc comment) and are clearer named
// this way than disambiguated.
#[allow(clippy::similar_names)]
fn print_lifecycle_cancel_prover_toml() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();

    let dom_leaf = hex32(DOM_LEAF);
    let dom_bind = hex32(DOM_BIND);
    let dom_null = hex32(DOM_NULL);
    let dom_auth = hex32(DOM_AUTH);

    let secret = lifecycle_secret();
    let (acct_hi, acct_lo) = split16(&zk_fixture::ACCOUNT);
    let (ctrl_hi, ctrl_lo) = split16(&zk_fixture::CONTROLLER);

    let npass_hash: [u8; 32] = Sha256::digest(zk_fixture::NETWORK_PASSPHRASE.as_bytes()).into();
    let (npass_hi, npass_lo) = split16(&npass_hash);

    // Cancel's `auth_hash` zeroes pk_prefix/pk_x/pk_y/timelock_secs (spec
    // §2.4) -- unlike `print_lifecycle_prover_toml`, no pubkey is derived
    // here at all.
    let pk_x_hi = [0u8; 32];
    let pk_x_lo = [0u8; 32];
    let pk_y_hi = [0u8; 32];
    let pk_y_lo = [0u8; 32];
    let pk_prefix = field_u64(0);
    let timelock_secs = field_u64(0);

    let action = field_u64(zk_fixture::ACTION_CANCEL);
    let nonce = field_u64(zk_fixture::CANCEL_NONCE);

    let zeros = zero_hashes(&env);

    let inner = p2(&env, &[dom_leaf, secret]);
    let stored = p2(&env, &[dom_bind, acct_hi, acct_lo, inner]);

    let mut cur = stored;
    for z in &zeros {
        cur = p2(&env, &[cur, *z]);
    }
    let root = cur;

    let nullifier = p2(&env, &[dom_null, acct_hi, acct_lo, secret]);

    let auth_hash = p2(
        &env,
        &[
            dom_auth,
            action,
            acct_hi,
            acct_lo,
            npass_hi,
            npass_lo,
            ctrl_hi,
            ctrl_lo,
            pk_prefix,
            pk_x_hi,
            pk_x_lo,
            pk_y_hi,
            pk_y_lo,
            nonce,
            timelock_secs,
        ],
    );

    println!("###PROVER_TOML_BEGIN###");
    println!("root = \"{}\"", to_hex(&root));
    println!("nullifier = \"{}\"", to_hex(&nullifier));
    println!("auth_hash = \"{}\"", to_hex(&auth_hash));
    println!("secret = \"{}\"", to_hex(&secret));
    println!("acct_hi = \"{}\"", to_hex(&acct_hi));
    println!("acct_lo = \"{}\"", to_hex(&acct_lo));
    println!("path_bits = [");
    for _ in 0..DEPTH {
        println!("  \"0x00\",");
    }
    println!("]");
    println!("path_siblings = [");
    for z in &zeros {
        println!("  \"{}\",", to_hex(z));
    }
    println!("]");
    println!("action = \"{}\"", to_hex(&action));
    println!("npass_hi = \"{}\"", to_hex(&npass_hi));
    println!("npass_lo = \"{}\"", to_hex(&npass_lo));
    println!("ctrl_hi = \"{}\"", to_hex(&ctrl_hi));
    println!("ctrl_lo = \"{}\"", to_hex(&ctrl_lo));
    println!("pk_prefix = \"{}\"", to_hex(&pk_prefix));
    println!("pk_x_hi = \"{}\"", to_hex(&pk_x_hi));
    println!("pk_x_lo = \"{}\"", to_hex(&pk_x_lo));
    println!("pk_y_hi = \"{}\"", to_hex(&pk_y_hi));
    println!("pk_y_lo = \"{}\"", to_hex(&pk_y_lo));
    println!("nonce = \"{}\"", to_hex(&nonce));
    println!("timelock_secs = \"{}\"", to_hex(&timelock_secs));
    println!("###PROVER_TOML_END###");

    println!("###PROVER_JSON_BEGIN###");
    println!("{{");
    println!("  \"account\": \"{}\",", to_hex(&zk_fixture::ACCOUNT));
    println!("  \"controller\": \"{}\",", to_hex(&zk_fixture::CONTROLLER));
    println!(
        "  \"network_passphrase\": \"{}\",",
        zk_fixture::NETWORK_PASSPHRASE
    );
    println!("  \"nonce\": {},", zk_fixture::CANCEL_NONCE);
    println!("  \"timelock_secs\": 0,");
    println!("  \"action\": {},", zk_fixture::ACTION_CANCEL);
    println!("  \"new_pubkey\": \"0x{}\",", "00".repeat(65));
    println!(
        "  \"secret_label\": \"{}\",",
        String::from_utf8_lossy(zk_fixture::SECRET_LABEL)
    );
    println!("  \"secret\": \"{}\",", to_hex(&secret));
    println!("  \"leaf_stored\": \"{}\",", to_hex(&stored));
    println!("  \"root\": \"{}\",", to_hex(&root));
    println!("  \"nullifier\": \"{}\",", to_hex(&nullifier));
    println!("  \"auth_hash\": \"{}\"", to_hex(&auth_hash));
    println!("}}");
    println!("###PROVER_JSON_END###");
}

/// M1 Task 9: the REVOKE-variant generator, invoked by
/// `circuits/zk_recovery/scripts/gen_lifecycle_revoke_fixture.sh`. Computes
/// the witness for a real `action=3` ("revoke"/burn, spec §2.3) proof over
/// the SAME leaf/secret/root/nullifier as the base lifecycle fixture, with
/// `pk_prefix`/`pk_x`/`pk_y`/`timelock_secs` all ZEROED (same convention as
/// the cancel fixture) and `nonce = zk_fixture::REVOKE_NONCE` (`1` -- this
/// fixture models "burn without a prior initiate", spec §2.3's escape
/// hatch). This mirrors `print_lifecycle_cancel_prover_toml` exactly except
/// for the `action`/`nonce` substitutions.
#[test]
#[ignore = "generator invoked by `circuits/zk_recovery/scripts/gen_lifecycle_revoke_fixture.sh`, \
            not part of the normal suite"]
// Long, linear witness-printing generator; splitting it would obscure the
// 1:1 correspondence with the Prover.toml fields it emits.
#[allow(clippy::too_many_lines)]
// `pk_x_hi`/`pk_x_lo` vs `pk_y_hi`/`pk_y_lo` mirror the circuit's own
// naming convention (see `split16`'s doc comment) and are clearer named
// this way than disambiguated.
#[allow(clippy::similar_names)]
fn print_lifecycle_revoke_prover_toml() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();

    let dom_leaf = hex32(DOM_LEAF);
    let dom_bind = hex32(DOM_BIND);
    let dom_null = hex32(DOM_NULL);
    let dom_auth = hex32(DOM_AUTH);

    let secret = lifecycle_secret();
    let (acct_hi, acct_lo) = split16(&zk_fixture::ACCOUNT);
    let (ctrl_hi, ctrl_lo) = split16(&zk_fixture::CONTROLLER);

    let npass_hash: [u8; 32] = Sha256::digest(zk_fixture::NETWORK_PASSPHRASE.as_bytes()).into();
    let (npass_hi, npass_lo) = split16(&npass_hash);

    // Revoke's `auth_hash` zeroes pk_prefix/pk_x/pk_y/timelock_secs, same
    // convention as the cancel fixture (spec §2.4).
    let pk_x_hi = [0u8; 32];
    let pk_x_lo = [0u8; 32];
    let pk_y_hi = [0u8; 32];
    let pk_y_lo = [0u8; 32];
    let pk_prefix = field_u64(0);
    let timelock_secs = field_u64(0);

    let action = field_u64(zk_fixture::ACTION_REVOKE);
    let nonce = field_u64(zk_fixture::REVOKE_NONCE);

    let zeros = zero_hashes(&env);

    let inner = p2(&env, &[dom_leaf, secret]);
    let stored = p2(&env, &[dom_bind, acct_hi, acct_lo, inner]);

    let mut cur = stored;
    for z in &zeros {
        cur = p2(&env, &[cur, *z]);
    }
    let root = cur;

    let nullifier = p2(&env, &[dom_null, acct_hi, acct_lo, secret]);

    let auth_hash = p2(
        &env,
        &[
            dom_auth,
            action,
            acct_hi,
            acct_lo,
            npass_hi,
            npass_lo,
            ctrl_hi,
            ctrl_lo,
            pk_prefix,
            pk_x_hi,
            pk_x_lo,
            pk_y_hi,
            pk_y_lo,
            nonce,
            timelock_secs,
        ],
    );

    println!("###PROVER_TOML_BEGIN###");
    println!("root = \"{}\"", to_hex(&root));
    println!("nullifier = \"{}\"", to_hex(&nullifier));
    println!("auth_hash = \"{}\"", to_hex(&auth_hash));
    println!("secret = \"{}\"", to_hex(&secret));
    println!("acct_hi = \"{}\"", to_hex(&acct_hi));
    println!("acct_lo = \"{}\"", to_hex(&acct_lo));
    println!("path_bits = [");
    for _ in 0..DEPTH {
        println!("  \"0x00\",");
    }
    println!("]");
    println!("path_siblings = [");
    for z in &zeros {
        println!("  \"{}\",", to_hex(z));
    }
    println!("]");
    println!("action = \"{}\"", to_hex(&action));
    println!("npass_hi = \"{}\"", to_hex(&npass_hi));
    println!("npass_lo = \"{}\"", to_hex(&npass_lo));
    println!("ctrl_hi = \"{}\"", to_hex(&ctrl_hi));
    println!("ctrl_lo = \"{}\"", to_hex(&ctrl_lo));
    println!("pk_prefix = \"{}\"", to_hex(&pk_prefix));
    println!("pk_x_hi = \"{}\"", to_hex(&pk_x_hi));
    println!("pk_x_lo = \"{}\"", to_hex(&pk_x_lo));
    println!("pk_y_hi = \"{}\"", to_hex(&pk_y_hi));
    println!("pk_y_lo = \"{}\"", to_hex(&pk_y_lo));
    println!("nonce = \"{}\"", to_hex(&nonce));
    println!("timelock_secs = \"{}\"", to_hex(&timelock_secs));
    println!("###PROVER_TOML_END###");

    println!("###PROVER_JSON_BEGIN###");
    println!("{{");
    println!("  \"account\": \"{}\",", to_hex(&zk_fixture::ACCOUNT));
    println!("  \"controller\": \"{}\",", to_hex(&zk_fixture::CONTROLLER));
    println!(
        "  \"network_passphrase\": \"{}\",",
        zk_fixture::NETWORK_PASSPHRASE
    );
    println!("  \"nonce\": {},", zk_fixture::REVOKE_NONCE);
    println!("  \"timelock_secs\": 0,");
    println!("  \"action\": {},", zk_fixture::ACTION_REVOKE);
    println!("  \"new_pubkey\": \"0x{}\",", "00".repeat(65));
    println!(
        "  \"secret_label\": \"{}\",",
        String::from_utf8_lossy(zk_fixture::SECRET_LABEL)
    );
    println!("  \"secret\": \"{}\",", to_hex(&secret));
    println!("  \"leaf_stored\": \"{}\",", to_hex(&stored));
    println!("  \"root\": \"{}\",", to_hex(&root));
    println!("  \"nullifier\": \"{}\",", to_hex(&nullifier));
    println!("  \"auth_hash\": \"{}\"", to_hex(&auth_hash));
    println!("}}");
    println!("###PROVER_JSON_END###");
}

/// Deploy a throwaway contract (the M0 stateless `WebAuthn` verifier wasm --
/// zero constructor args, no state) at a chosen contract-id via
/// `env.register_at`, then round-trip the resolved `Address` back to its
/// raw contract-id bytes via `AddressPayload::from_address`. This proves
/// the mechanism the whole M1 lifecycle test depends on: `register_at`
/// really does pin a contract at the caller-chosen id, so deploying the
/// smart account/recovery controller at `zk_fixture::ACCOUNT`/`CONTROLLER`
/// makes their addresses match what the fixture proof's `auth_hash` binds.
#[test]
fn fixture_addresses_pin() {
    let env = Env::default();

    let account_pin =
        AddressPayload::ContractIdHash(BytesN::from_array(&env, &zk_fixture::ACCOUNT))
            .to_address(&env);
    let controller_pin =
        AddressPayload::ContractIdHash(BytesN::from_array(&env, &zk_fixture::CONTROLLER))
            .to_address(&env);

    let resolved_account = env.register_at(
        &account_pin,
        nido_integration_tests::WEBAUTHN_VERIFIER_WASM,
        (Address::generate(&env),),
    );
    let resolved_controller = env.register_at(
        &controller_pin,
        nido_integration_tests::WEBAUTHN_VERIFIER_WASM,
        (Address::generate(&env),),
    );

    assert_contract_id(&resolved_account, zk_fixture::ACCOUNT);
    assert_contract_id(&resolved_controller, zk_fixture::CONTROLLER);
}

fn assert_contract_id(addr: &Address, expected: [u8; 32]) {
    match AddressPayload::from_address(addr) {
        Some(AddressPayload::ContractIdHash(hash)) => {
            assert_eq!(
                hash.to_array(),
                expected,
                "register_at must pin the resolved Address's contract-id"
            );
        }
        other => panic!("expected a ContractIdHash payload, got {other:?}"),
    }
}

/// Registers the M0 `nido-zk-verifier` wasm with the M0 vk and verifies the
/// committed lifecycle fixture proof under `reset_unlimited`. This is the
/// keystone honesty check for M1: the fixture's `proof`/`public_inputs`
/// bytes must be a REAL `bb prove` output that the deployed verifier
/// actually accepts, not fabricated bytes.
#[test]
fn fixture_proof_verifies() {
    mod zk_verifier_contract {
        soroban_sdk::contractimport!(
            file = "../../target/wasm32v1-none/contract/nido_zk_verifier.wasm"
        );
    }

    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();

    let vk_bytes_raw: &[u8] = include_bytes!("../../fixtures/zk/vk");
    let vk_bytes = Bytes::from_slice(&env, vk_bytes_raw);

    let fixture = zk_fixture::lifecycle_fixture(&env);
    let proof_bytes = Bytes::from_slice(&env, &fixture.proof);
    let public_inputs = Bytes::from_slice(&env, &fixture.public_inputs);

    let contract_id = env.register(
        zk_verifier_contract::WASM,
        (Address::generate(&env), vk_bytes),
    );
    let client = zk_verifier_contract::Client::new(&env, &contract_id);

    let result = client.try_verify_proof(&public_inputs, &proof_bytes);
    assert!(
        result.is_ok(),
        "fixture lifecycle proof must verify under the M0 verifier + vk: {result:?}"
    );
}

/// M1 Task 6 sibling of `fixture_proof_verifies`, for the CANCEL
/// (`action=2`) fixture: proves `lifecycle_fixture_cancel`'s `proof`/
/// `public_inputs` bytes are a REAL `bb prove` output the M0 verifier
/// actually accepts, before `zk_recovery_lifecycle.rs` relies on it to
/// exercise `cancel_recovery` end-to-end.
#[test]
fn fixture_cancel_proof_verifies() {
    mod zk_verifier_contract {
        soroban_sdk::contractimport!(
            file = "../../target/wasm32v1-none/contract/nido_zk_verifier.wasm"
        );
    }

    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();

    let vk_bytes_raw: &[u8] = include_bytes!("../../fixtures/zk/vk");
    let vk_bytes = Bytes::from_slice(&env, vk_bytes_raw);

    let fixture = zk_fixture::lifecycle_fixture_cancel(&env);
    let proof_bytes = Bytes::from_slice(&env, &fixture.proof);
    let public_inputs = Bytes::from_slice(&env, &fixture.public_inputs);

    let contract_id = env.register(
        zk_verifier_contract::WASM,
        (Address::generate(&env), vk_bytes),
    );
    let client = zk_verifier_contract::Client::new(&env, &contract_id);

    let result = client.try_verify_proof(&public_inputs, &proof_bytes);
    assert!(
        result.is_ok(),
        "fixture cancel proof must verify under the M0 verifier + vk: {result:?}"
    );
}

/// M1 Task 9 sibling of `fixture_proof_verifies`, for the REVOKE
/// (`action=3`) fixture: proves `lifecycle_fixture_revoke`'s `proof`/
/// `public_inputs` bytes are a REAL `bb prove` output the M0 verifier
/// actually accepts, before `zk_recovery_lifecycle.rs` relies on it to
/// exercise the proof-gated `burn_nullifier` end-to-end.
#[test]
fn fixture_revoke_proof_verifies() {
    mod zk_verifier_contract {
        soroban_sdk::contractimport!(
            file = "../../target/wasm32v1-none/contract/nido_zk_verifier.wasm"
        );
    }

    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();

    let vk_bytes_raw: &[u8] = include_bytes!("../../fixtures/zk/vk");
    let vk_bytes = Bytes::from_slice(&env, vk_bytes_raw);

    let fixture = zk_fixture::lifecycle_fixture_revoke(&env);
    let proof_bytes = Bytes::from_slice(&env, &fixture.proof);
    let public_inputs = Bytes::from_slice(&env, &fixture.public_inputs);

    let contract_id = env.register(
        zk_verifier_contract::WASM,
        (Address::generate(&env), vk_bytes),
    );
    let client = zk_verifier_contract::Client::new(&env, &contract_id);

    let result = client.try_verify_proof(&public_inputs, &proof_bytes);
    assert!(
        result.is_ok(),
        "fixture revoke proof must verify under the M0 verifier + vk: {result:?}"
    );
}
