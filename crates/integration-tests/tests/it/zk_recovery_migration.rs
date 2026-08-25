//! M2 Task 6 end-to-end honesty check: a NEW-wasm account that was deployed
//! WITHOUT a recovery controller (constructor `recovery_controller: None`)
//! can migrate into full ZK recovery capability post-deploy via
//! `enroll_zk_recovery`, followed by a separate, account-authed
//! `pool.insert_for` -- and the resulting account gets the SAME real-proof
//! recovery + in-account guard behavior as an account that had the
//! controller installed at construction (`zk_recovery_guard.rs`).
//!
//! Mirrors `zk_recovery_guard.rs::deploy`, except the account is registered
//! with `recovery_controller: None` and then migrated via
//! `enroll_zk_recovery` instead of getting the rule at construction.

use nido_integration_tests::{zk_fixture, SmartAccountClient, SMART_ACCOUNT_WASM};
use nido_smart_account::contract::NidoSmartAccountError;
use nido_zk_recovery::hash::leaf_inner;
use nido_zk_recovery::pool::{ZkRecovery, ZkRecoveryClient};
use soroban_sdk::address_payload::AddressPayload;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Bytes, BytesN, Env, InvokeError, Map, Val};
use stellar_accounts::smart_account::Signer as AccountSigner;

const DELAY_SECS: u64 = zk_fixture::TIMELOCK_SECS as u64;
const COMPLETION_WINDOW_SECS: u64 = 30 * 24 * 3600;
const MAX_CANCELS: u32 = 2;
const TIMELOCK_FLOOR_SECS: u64 = 7 * 24 * 3600;

fn addr_from(env: &Env, id: &[u8; 32]) -> Address {
    AddressPayload::ContractIdHash(BytesN::from_array(env, id)).to_address(env)
}

fn hex32(s: &str) -> [u8; 32] {
    let s = s.strip_prefix("0x").unwrap_or(s);
    assert_eq!(s.len(), 64, "expected a 32-byte hex string, got {s:?}");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

mod zk_verifier_contract {
    // Path is relative to CARGO_MANIFEST_DIR (crates/integration-tests/).
    soroban_sdk::contractimport!(
        file = "../../target/wasm32v1-none/contract/nido_zk_verifier.wasm"
    );
}

/// Deploys the REAL `ZkRecovery` controller (pinned at `CONTROLLER`) and a
/// NEW-wasm account (pinned at `ACCOUNT`) constructed with
/// `recovery_controller: None` -- i.e. WITHOUT the recovery rule. Does NOT
/// enroll or insert the leaf -- callers drive the migration steps themselves
/// so the test can assert on the pre-migration state first.
fn deploy_unenrolled(env: &Env) -> (SmartAccountClient<'_>, Address, ZkRecoveryClient<'_>) {
    let fixture = zk_fixture::lifecycle_fixture(env);
    env.mock_all_auths();

    // --- The real ZkRecovery controller, pinned at CONTROLLER. ---
    let vk_bytes = Bytes::from_slice(env, include_bytes!("../../fixtures/zk/vk"));
    let verifier_id = env.register(
        zk_verifier_contract::WASM,
        (Address::generate(env), vk_bytes),
    );
    let controller_addr = addr_from(env, &fixture.controller);
    let factory = Address::generate(env);
    let network_passphrase = Bytes::from_slice(env, fixture.network_passphrase.as_bytes());
    let webauthn_verifier = Address::generate(env); // unused by this file's coverage
    env.register_at(
        &controller_addr,
        ZkRecovery,
        (
            factory,
            verifier_id,
            DELAY_SECS,
            COMPLETION_WINDOW_SECS,
            MAX_CANCELS,
            TIMELOCK_FLOOR_SECS,
            network_passphrase,
            webauthn_verifier,
            Address::generate(env), // upgrade admin (unused by this file's coverage)
        ),
    );
    let zk = ZkRecoveryClient::new(env, &controller_addr);

    // --- The account, pinned at ACCOUNT, constructed WITHOUT a recovery
    // controller -- simulates a NEW-wasm account whose deployer chose to
    // skip recovery at construction time. ---
    let account_addr = addr_from(env, &fixture.account);
    let signers = soroban_sdk::vec![env, AccountSigner::Delegated(Address::generate(env))];
    let policies: Map<Address, Val> = Map::new(env);
    env.register_at(
        &account_addr,
        SMART_ACCOUNT_WASM,
        (signers, policies, None::<Address>),
    );
    let account = SmartAccountClient::new(env, &account_addr);

    (account, controller_addr, zk)
}

/// Extracts a contract-error code from a `try_*` client call's `Result`
/// (mirrors `zk_recovery_guard.rs`'s `error_code` helper).
fn error_code<T: core::fmt::Debug, E: core::fmt::Debug>(
    res: &Result<Result<T, E>, Result<soroban_sdk::Error, InvokeError>>,
) -> u32 {
    match res {
        Err(Ok(err)) => err.get_code(),
        other => panic!("expected a contract error, got {other:?}"),
    }
}

/// Step 1 of the honesty check: a NEW-wasm account deployed with `None` has
/// no recovery rule; `enroll_zk_recovery` installs one identical in shape to
/// the constructor's `Some(controller)` path.
#[test]
fn enroll_zk_recovery_migrates_a_none_deployed_account() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let (account, controller_addr, _zk) = deploy_unenrolled(&env);

    assert_eq!(
        account.recovery_rule_id(),
        None,
        "sanity: account deployed with None has no recovery rule"
    );
    assert_eq!(account.recovery_controller(), None);

    account.enroll_zk_recovery(&controller_addr);

    assert_eq!(
        account.recovery_controller(),
        Some(controller_addr),
        "enroll_zk_recovery must store RECOVERY_CONTROLLER"
    );
    assert!(
        account.recovery_rule_id().is_some(),
        "enroll_zk_recovery must install the recovery rule"
    );
}

/// A second `enroll_zk_recovery` call is rejected with
/// `RecoveryAlreadyEnrolled`.
#[test]
fn enroll_zk_recovery_twice_is_rejected() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let (account, controller_addr, _zk) = deploy_unenrolled(&env);

    account.enroll_zk_recovery(&controller_addr);
    let res = account.try_enroll_zk_recovery(&controller_addr);
    assert_eq!(
        error_code(&res),
        NidoSmartAccountError::RecoveryAlreadyEnrolled as u32
    );
}

/// The keystone honesty check: full migration flow --
/// `enroll_zk_recovery` (installs the rule) then `pool.insert_for` (inserts
/// the fixture leaf, account-authed) -- reproduces the exact fixture root,
/// and a REAL fixture proof through `initiate_recovery` then succeeds and
/// makes the in-account guard block `remove_signer` while pending, exactly
/// like an account that had the controller installed at construction
/// (`zk_recovery_guard.rs::real_controller_pending_blocks_remove_signer`).
/// This proves a migrated account gets the FULL recovery capability,
/// including the guard.
#[test]
fn migrated_account_gets_full_recovery_and_guard() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let (account, controller_addr, zk) = deploy_unenrolled(&env);
    let account_addr = account.address.clone();
    let fixture = zk_fixture::lifecycle_fixture(&env);

    // --- Step 1: enroll the rule on the account. ---
    account.enroll_zk_recovery(&controller_addr);

    // --- Step 2: insert the fixture leaf into the pool, SEPARATELY,
    // account-authed -- proves enroll_zk_recovery does NOT itself call
    // insert_for. ---
    let secret = BytesN::from_array(&env, &hex32(fixture.secret_hex));
    let commitment = leaf_inner(&env, &secret);
    let idx = zk.insert_for(&account_addr, &commitment);
    assert_eq!(idx, 0, "first insert must land at index 0");

    let expected_leaf = BytesN::from_array(&env, &fixture.leaf_stored);
    assert_eq!(
        zk.current_root().to_array(),
        fixture.root,
        "on-chain frontier root after the migrated account's insert_for must \
         equal the circuit's independently-computed fixture root"
    );
    let _ = expected_leaf;

    // The Default rule's (only) signer -- the target of the guarded
    // `remove_signer` call below.
    let default_rule = account.get_context_rule(&0);
    let signer_id = default_rule
        .signer_ids
        .first()
        .expect("Default rule must have the one signer just installed");

    // Sanity: no pending yet.
    assert!(
        !zk.has_pending(&account_addr),
        "sanity: no pending before initiate_recovery"
    );

    // --- Drive the REAL fixture proof through initiate_recovery. ---
    let new_pubkey = BytesN::from_array(&env, &fixture.new_pubkey);
    let root = BytesN::from_array(&env, &fixture.root);
    let nullifier = BytesN::from_array(&env, &fixture.nullifier);
    let proof = Bytes::from_slice(&env, &fixture.proof);
    let executable_after = zk.initiate_recovery(
        &account_addr,
        &new_pubkey,
        &fixture.nonce,
        &fixture.timelock_secs,
        &root,
        &nullifier,
        &proof,
    );
    assert!(executable_after > 0);
    assert!(
        zk.has_pending(&account_addr),
        "the real controller must report a live pending after a successful \
         initiate_recovery on a migrated account"
    );

    // --- The guard: remove_signer on the migrated account must now panic
    // RecoveryPendingBlocked -- proving enroll_zk_recovery's stored
    // RECOVERY_CONTROLLER makes the guard apply just like a
    // construction-time-enrolled account. ---
    let res = account.try_remove_signer(&0, &signer_id);
    assert_eq!(
        error_code(&res),
        NidoSmartAccountError::RecoveryPendingBlocked as u32,
        "remove_signer while a REAL pending exists must be blocked by the \
         in-account guard on a MIGRATED account too"
    );

    // And the protected recovery rule, same as the construction-time path.
    let rule_id = account.recovery_rule_id().expect("recovery rule installed");
    let res = account.try_remove_context_rule(&rule_id);
    assert_eq!(
        error_code(&res),
        NidoSmartAccountError::RecoveryRuleProtected as u32
    );
}
