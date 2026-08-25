//! M2 Task 8 (FINAL M2 task) Part A: real-metering cost of the in-account
//! guard's cross-call (M2 Task 4's `guard_no_pending` -> `has_live_pending`
//! -> `RecoveryControllerClient::new(e, controller).has_pending(...)`).
//!
//! `zk_recovery_guard.rs` (M2 Task 4) already proves the cross-call reaches
//! a REAL deployed controller and gates correctly -- but that test calls
//! `env.cost_estimate().budget().reset_unlimited()`, which erases the very
//! thing this file exists to measure. This file follows the honest-metering
//! pattern from `crates/zk-bench/tests/budget.rs` and
//! `crates/integration-tests/tests/it/initiate_cost.rs` instead: raise the
//! live budget to a real ceiling (not unlimited) so the call completes, then
//! read `env.cost_estimate().resources().instructions` for the ONE measured
//! call, immediately after it returns.
//!
//! ## Two numbers, and the delta between them
//!
//! 1. [`guard_fires_cost_with_real_pending`]: `remove_signer` on an account
//!    with the recovery rule installed, against a REAL `nido-zk-recovery`
//!    controller (registered from the compiled `nido_zk_recovery.wasm`, not
//!    a native Rust test-contract -- see `initiate_cost.rs`'s module docs
//!    for why raw-Wasm registration is required for honest cross-call
//!    metering) that has a genuine LIVE pending (created by driving the
//!    real M1 lifecycle fixture proof through `initiate_recovery`). The
//!    guard's `has_pending` cross-call returns `true`, so `remove_signer`
//!    panics `RecoveryPendingBlocked` -- the guard's cross-call path,
//!    Wasm-to-Wasm, fully metered.
//! 2. [`no_recovery_configured_baseline_cost`]: `remove_signer` on an
//!    account constructed with `recovery_controller: None` --
//!    `guard_no_pending` is a no-op here (`NidoSmartAccount::
//!    recovery_controller` returns `None`, so `guard_live_pending` and its
//!    cross-call never run at all) -- the removal succeeds outright. This
//!    is the "no guard, no cross-call" baseline.
//!
//! The delta between (1) and (2) is the guard's cross-call overhead in
//! isolation (the `has_pending` invoke-contract dispatch + the controller's
//! own view logic + the panic unwind), separated from `remove_signer`'s own
//! fixed cost (auth check, storage reads for the removal itself). Both
//! numbers are printed; the GO/NO-GO gate below applies to (1), the actual
//! guarded call a real mutating op takes on the hot path.
//!
//! Build the contract Wasms first (not run automatically by `cargo test`):
//! ```sh
//! just build-contracts
//! ```
//! `just bench-zk-guard` does this for you.

use nido_integration_tests::{deploy_smart_account_with_recovery, zk_fixture, SMART_ACCOUNT_WASM};
use nido_smart_account::contract::NidoSmartAccountError;
use nido_zk_recovery::hash::leaf_inner;
use nido_zk_recovery::pool::ZkRecoveryClient;
use soroban_sdk::address_payload::AddressPayload;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Bytes, BytesN, Env, InvokeError, Map, Val};
use stellar_accounts::smart_account::Signer as AccountSigner;

const DELAY_SECS: u64 = zk_fixture::TIMELOCK_SECS as u64;
const COMPLETION_WINDOW_SECS: u64 = 30 * 24 * 3600;
const MAX_CANCELS: u32 = 2;
const TIMELOCK_FLOOR_SECS: u64 = 7 * 24 * 3600;

/// SDF policy-cross-call target: the guard's cross-call path (a
/// mutating op that fires the guard and hits a REAL live pending) must fit
/// in this many CPU instructions. Not the whole-transaction cap (that's
/// `initiate_cost.rs`'s 350M `MAX_INITIATE_CPU`) -- this is specifically
/// the "does calling into another contract to check a policy blow the
/// budget" target for the in-account guard pattern.
const MAX_GUARD_CPU: i64 = 10_000_000;

/// Same mainnet per-invocation ceiling as `budget.rs`/`initiate_cost.rs` --
/// raised from the SDK-testutils 100M/40MB default so the setup calls
/// (`insert_for`, `initiate_recovery`, which alone costs ~168M CPU per
/// DEPLOYED.md) can complete without the harness aborting mid-call on an
/// unrelated SDK default. This does not change what the MEASURED call
/// (`remove_signer`, far cheaper) actually costs -- see `budget.rs`'s
/// module docs for the full honesty rationale.
const MAINNET_CPU_INSN_LIMIT: u64 = 600_000_000;
const MAINNET_MEM_BYTES_LIMIT: u64 = 41_943_040;

const ZK_RECOVERY_WASM: &[u8] =
    include_bytes!("../../../../target/wasm32v1-none/contract/nido_zk_recovery.wasm");

mod zk_verifier_contract {
    // Path is relative to CARGO_MANIFEST_DIR (crates/integration-tests/).
    soroban_sdk::contractimport!(
        file = "../../target/wasm32v1-none/contract/nido_zk_verifier.wasm"
    );
}

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

fn error_code<T: core::fmt::Debug, E: core::fmt::Debug>(
    res: &Result<Result<T, E>, Result<soroban_sdk::Error, InvokeError>>,
) -> u32 {
    match res {
        Err(Ok(err)) => err.get_code(),
        other => panic!("expected a contract error, got {other:?}"),
    }
}

/// GO/NO-GO gate: with a REAL live pending at a REAL (Wasm-registered, not
/// native) `nido-zk-recovery` controller, a single guarded `remove_signer`
/// call -- which fires the cross-call, sees `has_pending == true`, and
/// panics `RecoveryPendingBlocked` -- must cost under the SDF
/// policy-cross-call target.
#[test]
fn guard_fires_cost_with_real_pending() {
    let env = Env::default();
    // Real mainnet ceiling (not unlimited) -- see module docs.
    env.cost_estimate()
        .budget()
        .reset_limits(MAINNET_CPU_INSN_LIMIT, MAINNET_MEM_BYTES_LIMIT);

    let fixture = zk_fixture::lifecycle_fixture(&env);
    env.mock_all_auths();

    // --- The real ZkRecovery controller, pinned at CONTROLLER, registered
    // from the compiled Wasm (not native `ZkRecovery`) -- so the guard's
    // cross-call runs through the metered Wasm VM on BOTH sides, matching
    // `initiate_cost.rs`'s honesty bar. ---
    let vk_bytes = Bytes::from_slice(&env, include_bytes!("../../fixtures/zk/vk"));
    let verifier_id = env.register(
        zk_verifier_contract::WASM,
        (Address::generate(&env), vk_bytes),
    );
    let controller_addr = addr_from(&env, &fixture.controller);
    let factory = Address::generate(&env);
    let network_passphrase = Bytes::from_slice(&env, fixture.network_passphrase.as_bytes());
    let webauthn_verifier = Address::generate(&env); // unused by this file's coverage
    env.register_at(
        &controller_addr,
        ZK_RECOVERY_WASM,
        (
            factory,
            verifier_id,
            DELAY_SECS,
            COMPLETION_WINDOW_SECS,
            MAX_CANCELS,
            TIMELOCK_FLOOR_SECS,
            network_passphrase,
            webauthn_verifier,
            Address::generate(&env), // upgrade admin (unused by this file's coverage)
        ),
    );
    let zk = ZkRecoveryClient::new(&env, &controller_addr);

    // --- The account, pinned at ACCOUNT, constructor installs the recovery
    // rule with the REAL controller as `Some(recovery_controller)`. ---
    let account_addr = addr_from(&env, &fixture.account);
    let extra_signer_addr = Address::generate(&env);
    let signers = soroban_sdk::vec![
        &env,
        AccountSigner::Delegated(Address::generate(&env)),
        AccountSigner::Delegated(extra_signer_addr)
    ];
    let policies: Map<Address, Val> = Map::new(&env);
    env.register_at(
        &account_addr,
        SMART_ACCOUNT_WASM,
        (signers, policies, Some(controller_addr.clone())),
    );
    let account = nido_integration_tests::SmartAccountClient::new(&env, &account_addr);

    // --- Insert the fixture leaf; cross-check the on-chain root. ---
    let secret = BytesN::from_array(&env, &hex32(fixture.secret_hex));
    let commitment = leaf_inner(&env, &secret);
    zk.insert_for(&account_addr, &commitment);
    assert_eq!(
        zk.current_root().to_array(),
        fixture.root,
        "on-chain frontier root after inserting the fixture leaf must equal \
         the circuit's independently-computed root"
    );

    // --- Drive the REAL fixture proof through initiate_recovery -- a
    // genuine live pending now exists at the REAL controller. Unmeasured
    // setup: happens BEFORE the measured call below. ---
    let new_pubkey = BytesN::from_array(&env, &fixture.new_pubkey);
    let root = BytesN::from_array(&env, &fixture.root);
    let nullifier = BytesN::from_array(&env, &fixture.nullifier);
    let proof = Bytes::from_slice(&env, &fixture.proof);
    zk.initiate_recovery(
        &account_addr,
        &new_pubkey,
        &fixture.nonce,
        &fixture.timelock_secs,
        &root,
        &nullifier,
        &proof,
    );
    assert!(
        zk.has_pending(&account_addr),
        "sanity: the real controller must report a live pending before the \
         measured call"
    );

    // --- The measured call: the second (extra) signer on the Default rule
    // is the removal target, so this exercises the exact same
    // `remove_signer` entry point the no-recovery baseline below measures.
    // ---
    let default_rule = account.get_context_rule(&0);
    let signer_id = default_rule
        .signer_ids
        .get(1)
        .expect("Default rule must have the extra signer just installed");

    let res = account.try_remove_signer(&0, &signer_id);

    // Capture the measured cost IMMEDIATELY -- `cost_estimate().resources()`
    // reflects only the LAST top-level invocation.
    let cpu = env.cost_estimate().resources().instructions;
    println!("guard cross-call (fires, real pending) remove_signer cpu_instructions = {cpu}");

    assert_eq!(
        error_code(&res),
        NidoSmartAccountError::RecoveryPendingBlocked as u32,
        "remove_signer while a REAL pending exists at the REAL controller \
         must be blocked by the in-account guard's cross-call -- otherwise \
         the CPU number above does not correspond to the guarded path"
    );

    assert!(
        cpu <= MAX_GUARD_CPU,
        "guard cross-call path {cpu} > SDF policy-cross-call target {MAX_GUARD_CPU}"
    );
}

/// Baseline: `remove_signer` on an account constructed with
/// `recovery_controller: None` -- `guard_no_pending` is a no-op (no
/// cross-call at all), so the removal succeeds outright. Diffing this
/// number against [`guard_fires_cost_with_real_pending`]'s isolates the
/// guard's cross-call overhead from `remove_signer`'s own fixed cost.
#[test]
fn no_recovery_configured_baseline_cost() {
    let env = Env::default();
    env.cost_estimate()
        .budget()
        .reset_limits(MAINNET_CPU_INSN_LIMIT, MAINNET_MEM_BYTES_LIMIT);
    env.mock_all_auths();

    let (account, _account_addr, _verifier_addr, _signing_key) =
        deploy_smart_account_with_recovery(&env, None);

    // Add a second signer (unmeasured) so removing it doesn't trip
    // `NoSignersAndPolicies` -- mirrors the with-pending test's setup.
    let extra_signer_id =
        account.add_signer(&0, &AccountSigner::Delegated(Address::generate(&env)));

    account.remove_signer(&0, &extra_signer_id);

    let cpu = env.cost_estimate().resources().instructions;
    println!("no-recovery-configured (guard no-op) remove_signer cpu_instructions = {cpu}");
}
