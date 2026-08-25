//! M2 Task 4 end-to-end honesty check: the smart-account in-account guard's
//! cross-call to a REAL, deployed `nido-zk-recovery` controller's
//! `has_pending` view.
//!
//! `contract.rs`'s in-crate tests (`nido-smart-account`'s
//! `StubRecoveryPolicy`) prove the guard's LOGIC -- pending-block, protected
//! recovery rule, announce-then-execute -- against a stub whose
//! `has_pending` is directly settable. That proves the guard reacts
//! correctly to a `has_pending` result, but not that the wire-level
//! cross-call actually reaches a deployed controller. This file closes that
//! gap: it deploys the account (pinned at `zk_fixture::ACCOUNT`, via the
//! constructor's `Some(recovery_controller)` path -- the ONLY path that sets
//! the `RECOVERY_CONTROLLER`/`RECOVERY_RULE_ID` instance-storage keys the
//! guard reads) and the REAL `ZkRecovery` controller (pinned at
//! `zk_fixture::CONTROLLER`), drives the M1 lifecycle fixture's real proof
//! through `initiate_recovery` to create a genuine live pending, and asserts
//! `remove_signer` on the account panics `RecoveryPendingBlocked` --
//! `guard_no_pending`'s `RecoveryControllerClient::new(e,
//! &controller).has_pending(...)` cross-call actually reached the deployed
//! controller and read its real pending state.

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

/// Deploys the account (pinned at `ACCOUNT`, constructor `Some(controller)`)
/// and the real `ZkRecovery` controller (pinned at `CONTROLLER`), and
/// inserts the fixture leaf. Does NOT call `initiate_recovery` -- callers
/// needing a pending call that themselves.
///
/// Deliberately uses a plain `Signer::Delegated` (not a real `WebAuthn`
/// passkey) for the account's Default rule -- this test's whole point is
/// proving the guard's cross-call reaches the real controller, not
/// re-proving `real_proof_completion_rotates_key_via_enforce`'s `WebAuthn`
/// dispatch (`zk_recovery_completion.rs`), so the removal target's
/// signature scheme is irrelevant. The `remove_signer` call under test is
/// authorized via `env.mock_all_auths()`.
fn deploy(env: &Env) -> (SmartAccountClient<'_>, Address, ZkRecoveryClient<'_>, u32) {
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

    // --- The account, pinned at ACCOUNT, constructor installs the
    // recovery rule with the REAL controller as `Some(recovery_controller)`
    // -- this is the only path that sets the `RECOVERY_CONTROLLER` instance
    // key the guard reads. ---
    let account_addr = addr_from(env, &fixture.account);
    let signers = soroban_sdk::vec![env, AccountSigner::Delegated(Address::generate(env))];
    let policies: Map<Address, Val> = Map::new(env);
    env.register_at(
        &account_addr,
        SMART_ACCOUNT_WASM,
        (signers, policies, Some(controller_addr.clone())),
    );
    let account = SmartAccountClient::new(env, &account_addr);

    // --- Insert the fixture leaf; cross-check the on-chain root. ---
    let secret = BytesN::from_array(env, &hex32(fixture.secret_hex));
    let commitment = leaf_inner(env, &secret);
    zk.insert_for(&account_addr, &commitment);
    assert_eq!(
        zk.current_root().to_array(),
        fixture.root,
        "on-chain frontier root after inserting the fixture leaf must equal \
         the circuit's independently-computed root"
    );

    // The Default rule's (only) signer -- the target of the guarded
    // `remove_signer` call below.
    let default_rule = account.get_context_rule(&0);
    let signer_id = default_rule
        .signer_ids
        .first()
        .expect("Default rule must have the one signer just installed");

    (account, account_addr, zk, signer_id)
}

/// Extracts a contract-error code from a `try_*` client call's `Result`
/// (mirrors `zk_recovery_lifecycle.rs`'s `contract_error` helper).
fn error_code<T: core::fmt::Debug, E: core::fmt::Debug>(
    res: &Result<Result<T, E>, Result<soroban_sdk::Error, InvokeError>>,
) -> u32 {
    match res {
        Err(Ok(err)) => err.get_code(),
        other => panic!("expected a contract error, got {other:?}"),
    }
}

/// The keystone honesty check: with a REAL live pending (created by the M1
/// fixture's real proof through the real deployed controller),
/// `remove_signer` on the account panics `RecoveryPendingBlocked` -- proving
/// `guard_no_pending`'s cross-call actually reached the deployed
/// `ZkRecovery` controller's `has_pending` view and gated on its real
/// state, not a stub.
#[test]
fn real_controller_pending_blocks_remove_signer() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let (account, account_addr, zk, signer_id) = deploy(&env);
    let fixture = zk_fixture::lifecycle_fixture(&env);

    // Sanity: no pending yet, remove_signer succeeds freely.
    assert!(
        !zk.has_pending(&account_addr),
        "sanity: no pending before initiate_recovery"
    );

    // Drive the REAL fixture proof through initiate_recovery -- a genuine
    // live pending now exists for `account_addr` in the REAL controller's
    // storage.
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
         initiate_recovery"
    );

    // The guard: remove_signer on the account must now panic
    // RecoveryPendingBlocked, via the REAL cross-call to the deployed
    // controller's has_pending -- not a stub.
    let res = account.try_remove_signer(&0, &signer_id);
    assert_eq!(
        error_code(&res),
        NidoSmartAccountError::RecoveryPendingBlocked as u32,
        "remove_signer while a REAL pending exists at the REAL controller \
         must be blocked by the in-account guard's cross-call"
    );

    // And the protected recovery rule: removing it directly must also be
    // rejected (RecoveryRuleProtected fires before the pending guard even
    // runs, per contract.rs's ordering), regardless of the live pending.
    let rule_id = account.recovery_rule_id().expect("recovery rule installed");
    let res = account.try_remove_context_rule(&rule_id);
    assert_eq!(
        error_code(&res),
        NidoSmartAccountError::RecoveryRuleProtected as u32
    );
}
