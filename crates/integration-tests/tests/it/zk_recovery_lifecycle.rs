//! M1 Task 5: `ZkRecovery::initiate_recovery` end-to-end, against a REAL
//! `bb prove` proof.
//!
//! The recovery circuit's `auth_hash` public input binds the account and
//! controller *contract addresses* (`circuits/zk_recovery/src/main.nr:40-42`),
//! so the committed lifecycle fixture proof
//! (`crates/integration-tests/src/zk_fixture.rs`) is only valid against a
//! deploy that pins the smart account/controller at the EXACT addresses the
//! proof was generated for (`zk_fixture::ACCOUNT`/`CONTROLLER`, via
//! `env.register_at`). Every test below deploys `ZkRecovery` at
//! `CONTROLLER` for this reason.
//!
//! `real_proof_initiates_recovery_with_timelocked_pending` is the keystone
//! honesty check for M1 Task 5: it proves the REAL fixture proof verifies
//! through `initiate_recovery`'s cross-call to the M0 verifier contract,
//! using an `auth_hash` this contract recomputes itself from the call's own
//! arguments -- not one fed to it directly. The `current_root` ==
//! fixture.root assertion inside `setup_with_leaf` cross-checks that this
//! contract's on-chain Merkle frontier agrees with the Noir circuit's own
//! root computation for the identical leaf.

use nido_integration_tests::zk_fixture::{self, LifecycleFixture};
use nido_zk_recovery::hash::leaf_inner;
use nido_zk_recovery::pool::{ZkRecovery, ZkRecoveryClient};
use nido_zk_recovery::types::{
    NullifierBurned, NullifierState, PendingRecovery, RecoveryCanceled, RecoveryError,
    RecoveryInitiated, RecoveryKey,
};
use soroban_sdk::address_payload::AddressPayload;
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::{Address, Bytes, BytesN, Env, Error as SdkError, Event};

mod zk_verifier_contract {
    // Path is relative to CARGO_MANIFEST_DIR (crates/integration-tests/).
    soroban_sdk::contractimport!(
        file = "../../target/wasm32v1-none/contract/nido_zk_verifier.wasm"
    );
}

/// The `ZkRecoveryConfig` fixed for every test below. `DELAY_SECS` must
/// equal `zk_fixture::TIMELOCK_SECS` -- the fixture's proof was generated
/// with `timelock_secs = 1_209_600` bound into `auth_hash`, and
/// `initiate_recovery` requires `timelock_secs == config.delay_secs`
/// exactly (spec §3.3 check 5).
///
/// NOTE: these are the **mainnet production** parameters (delay 14d, completion
/// window 30d, timelock floor 7d -- spec §3.3 "Defaults"), NOT the current
/// testnet pool's tuned-down values (delay 60s). So the full recovery
/// lifecycle proven here and in `zk_recovery_e2e.rs` (initiate -> wait timelock
/// -> complete, plus cancel and revoke) already runs under mainnet timing. The
/// A1 blocker is purely that the LIVE testnet pool was *deployed* with
/// testnet params; the contract logic itself is exercised at mainnet params.
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

/// Deploys the M0 verifier (real wasm + M0 vk) and `ZkRecovery` pinned at
/// `zk_fixture::CONTROLLER` (so `auth_hash`'s `ctrl_hi/lo` binds to this
/// exact address). Does NOT insert the fixture leaf -- callers that need a
/// known root call `insert_fixture_leaf` afterwards.
fn deploy(env: &Env) -> (ZkRecoveryClient<'_>, Address, LifecycleFixture) {
    let fixture = zk_fixture::lifecycle_fixture(env);
    let passphrase = Bytes::from_slice(env, fixture.network_passphrase.as_bytes());
    let client = deploy_with_passphrase(env, &fixture, &passphrase);
    let account = addr_from(env, &fixture.account);
    (client, account, fixture)
}

/// Core of [`deploy`]: registers the M0 verifier (real wasm + M0 vk) and
/// `ZkRecovery` pinned at `fixture.controller`, configured with `passphrase`
/// as the pool's `network_passphrase`. Split out so the cross-network replay
/// test (`wrong_network_passphrase_proof_is_rejected`) can pin a DIFFERENT
/// passphrase than the one the fixture proof was generated against -- every
/// other caller passes the fixture's own passphrase via [`deploy`].
fn deploy_with_passphrase<'a>(
    env: &'a Env,
    fixture: &LifecycleFixture,
    passphrase: &Bytes,
) -> ZkRecoveryClient<'a> {
    let vk_bytes = Bytes::from_slice(env, include_bytes!("../../fixtures/zk/vk"));
    let verifier_id = env.register(
        zk_verifier_contract::WASM,
        (Address::generate(env), vk_bytes),
    );

    let controller_addr = addr_from(env, &fixture.controller);
    let factory = Address::generate(env);
    // Unused by this file's proof-only (`initiate_recovery`/`cancel_recovery`/
    // `burn_nullifier`) coverage -- only `policy.rs::enforce` (M1 Task 7,
    // `zk_recovery_completion.rs`) reads `config.webauthn_verifier`.
    let webauthn_verifier = Address::generate(env);

    let contract_id = env.register_at(
        &controller_addr,
        ZkRecovery,
        (
            factory,
            verifier_id,
            DELAY_SECS,
            COMPLETION_WINDOW_SECS,
            MAX_CANCELS,
            TIMELOCK_FLOOR_SECS,
            passphrase.clone(),
            webauthn_verifier,
            Address::generate(env), // upgrade admin (unused by this file's coverage)
        ),
    );
    ZkRecoveryClient::new(env, &contract_id)
}

/// Inserts the fixture's leaf (`leaf_inner(secret)`, wrapped by the pool
/// under `account`) and asserts the resulting on-chain frontier root equals
/// the circuit-computed `fixture.root` -- the required cross-check proving
/// the on-chain frontier algorithm agrees with the Noir circuit's root for
/// this exact leaf.
fn insert_fixture_leaf(
    env: &Env,
    client: &ZkRecoveryClient<'_>,
    account: &Address,
    fixture: &LifecycleFixture,
) {
    let secret = BytesN::from_array(env, &hex32(fixture.secret_hex));
    let commitment = leaf_inner(env, &secret);

    env.mock_all_auths();
    client.insert_for(account, &commitment);

    let root = client.current_root();
    assert_eq!(
        root.to_array(),
        fixture.root,
        "on-chain frontier root after inserting the fixture leaf must equal \
         the Noir circuit's independently-computed root -- a mismatch here \
         means the on-chain frontier algorithm disagrees with the circuit"
    );
}

/// Full setup: `deploy` + `insert_fixture_leaf`.
fn setup(env: &Env) -> (ZkRecoveryClient<'_>, Address, LifecycleFixture) {
    let (client, account, fixture) = deploy(env);
    insert_fixture_leaf(env, &client, &account, &fixture);
    (client, account, fixture)
}

fn contract_error<T: core::fmt::Debug, E: core::fmt::Debug>(
    res: &Result<Result<T, E>, Result<SdkError, soroban_sdk::InvokeError>>,
) -> RecoveryError {
    match res {
        Err(Ok(err)) => {
            let code = err.get_code();
            for known in [
                RecoveryError::PendingExists,
                RecoveryError::UnknownRoot,
                RecoveryError::NullifierReserved,
                RecoveryError::NullifierSpent,
                RecoveryError::InvalidNonce,
                RecoveryError::TimelockTooShort,
                RecoveryError::TimelockMismatch,
                RecoveryError::RateLimited,
                RecoveryError::VerificationFailed,
                RecoveryError::NoPending,
                RecoveryError::CancelCapReached,
                RecoveryError::CooldownActive,
                RecoveryError::NullifierReservedElsewhere,
            ] {
                if known as u32 == code {
                    return known;
                }
            }
            panic!("unrecognized RecoveryError code {code}");
        }
        other => panic!("expected a contract error, got {other:?}"),
    }
}

/// The keystone honesty check for M1 Task 5: the REAL fixture proof
/// verifies through `initiate_recovery`'s cross-call to the M0 verifier,
/// against an `auth_hash` this contract recomputes itself from the call's
/// own arguments (not fed to it directly).
#[test]
fn real_proof_initiates_recovery_with_timelocked_pending() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let (client, account, fixture) = setup(&env);

    let new_pubkey = BytesN::from_array(&env, &fixture.new_pubkey);
    let root = BytesN::from_array(&env, &fixture.root);
    let nullifier = BytesN::from_array(&env, &fixture.nullifier);
    let proof = Bytes::from_slice(&env, &fixture.proof);

    let now = env.ledger().timestamp();
    let executable_after = client.initiate_recovery(
        &account,
        &new_pubkey,
        &fixture.nonce,
        &fixture.timelock_secs,
        &root,
        &nullifier,
        &proof,
    );

    assert_eq!(
        executable_after,
        now + DELAY_SECS,
        "initiate_recovery must return now + config.delay_secs"
    );

    // `events().all()` (soroban-sdk testutils) only returns events from the
    // LAST contract invocation, so this must be captured before any further
    // client calls (e.g. `get_pending` below) become "the last invocation".
    let new_pubkey_hash = env
        .crypto()
        .sha256(&Bytes::from_array(&env, &new_pubkey.to_array()))
        .to_bytes();
    let expected_event = RecoveryInitiated {
        account: &account,
        new_pubkey_hash: &new_pubkey_hash,
        executable_after: &executable_after,
    };
    assert_eq!(
        env.events().all().filter_by_contract(&client.address),
        [expected_event.to_xdr(&env, &client.address)],
        "RecoveryInitiated must be emitted with account/new_pubkey_hash/executable_after"
    );

    let pending = client
        .get_pending(&account)
        .expect("get_pending must be Some after a successful initiate_recovery");
    assert_eq!(pending.nullifier, nullifier);
    assert_eq!(pending.new_pubkey, new_pubkey);
    assert_eq!(pending.initiated_at, now);
    assert_eq!(pending.executable_after, executable_after);
    assert_eq!(
        pending.expires_at,
        executable_after + COMPLETION_WINDOW_SECS
    );

    // The nullifier must now be Reserved(account).
    let state: Option<NullifierState> = env.as_contract(&client.address, || {
        env.storage()
            .persistent()
            .get(&RecoveryKey::Nullifier(nullifier.clone()))
    });
    assert_eq!(
        state,
        Some(NullifierState::Reserved(account.clone())),
        "nullifier must be reserved to the recovering account"
    );
}

/// An unknown root (never produced by this contract's frontier, since no
/// leaf was ever inserted) must be rejected before any proof verification
/// is attempted.
#[test]
fn unknown_root_is_rejected() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let (client, account, fixture) = deploy(&env); // no leaf inserted

    let new_pubkey = BytesN::from_array(&env, &fixture.new_pubkey);
    let root = BytesN::from_array(&env, &fixture.root); // never produced on-chain here
    let nullifier = BytesN::from_array(&env, &fixture.nullifier);
    let proof = Bytes::from_slice(&env, &fixture.proof);

    let res = client.try_initiate_recovery(
        &account,
        &new_pubkey,
        &fixture.nonce,
        &fixture.timelock_secs,
        &root,
        &nullifier,
        &proof,
    );
    assert_eq!(contract_error(&res), RecoveryError::UnknownRoot);
}

/// Initiating twice for the same account: the second call must fail. With
/// no ledger time advanced between calls, the first initiation's pending
/// record is still live, so the ordered checks reject at `PendingExists`
/// (check 1) before ever reaching the nullifier check -- this still proves
/// the contract does not allow a second concurrent initiation to reuse the
/// same nullifier/account.
#[test]
fn reinitiating_with_a_live_pending_is_rejected() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let (client, account, fixture) = setup(&env);

    let new_pubkey = BytesN::from_array(&env, &fixture.new_pubkey);
    let root = BytesN::from_array(&env, &fixture.root);
    let nullifier = BytesN::from_array(&env, &fixture.nullifier);
    let proof = Bytes::from_slice(&env, &fixture.proof);

    let executable_after = client.initiate_recovery(
        &account,
        &new_pubkey,
        &fixture.nonce,
        &fixture.timelock_secs,
        &root,
        &nullifier,
        &proof,
    );
    assert!(executable_after > 0);

    // Second call, same account/nullifier, nonce bumped (as if a caller
    // tried to race a second initiation): still must fail.
    let res = client.try_initiate_recovery(
        &account,
        &new_pubkey,
        &(fixture.nonce + 1),
        &fixture.timelock_secs,
        &root,
        &nullifier,
        &proof,
    );
    let err = contract_error(&res);
    assert!(
        matches!(
            err,
            RecoveryError::PendingExists | RecoveryError::NullifierReserved
        ),
        "reinitiating over a live pending must fail with PendingExists or \
         NullifierReserved, got {err:?}"
    );
}

/// `nonce != stored_nonce + 1` must be rejected (`InvalidNonce`), before any
/// proof verification is attempted.
#[test]
fn wrong_nonce_is_rejected() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let (client, account, fixture) = setup(&env);

    let new_pubkey = BytesN::from_array(&env, &fixture.new_pubkey);
    let root = BytesN::from_array(&env, &fixture.root);
    let nullifier = BytesN::from_array(&env, &fixture.nullifier);
    let proof = Bytes::from_slice(&env, &fixture.proof);

    let wrong_nonce = fixture.nonce + 1; // stored nonce starts at 0, expects 1
    let res = client.try_initiate_recovery(
        &account,
        &new_pubkey,
        &wrong_nonce,
        &fixture.timelock_secs,
        &root,
        &nullifier,
        &proof,
    );
    assert_eq!(contract_error(&res), RecoveryError::InvalidNonce);
}

/// `timelock_secs < config.timelock_floor_secs` must be rejected
/// (`TimelockTooShort`), before any proof verification is attempted.
#[test]
fn timelock_below_floor_is_rejected() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let (client, account, fixture) = setup(&env);

    let new_pubkey = BytesN::from_array(&env, &fixture.new_pubkey);
    let root = BytesN::from_array(&env, &fixture.root);
    let nullifier = BytesN::from_array(&env, &fixture.nullifier);
    let proof = Bytes::from_slice(&env, &fixture.proof);

    let too_short: u32 = 100; // well under TIMELOCK_FLOOR_SECS (7 days)
    let res = client.try_initiate_recovery(
        &account,
        &new_pubkey,
        &fixture.nonce,
        &too_short,
        &root,
        &nullifier,
        &proof,
    );
    assert_eq!(contract_error(&res), RecoveryError::TimelockTooShort);
}

/// Tampering with `new_pubkey` (any single byte) changes the recomputed
/// `auth_hash`, which no longer matches the proof's `auth_hash` public
/// input -- the real `UltraHonk` verifier cross-call must then reject,
/// surfacing as `VerificationFailed`. This proves `initiate_recovery`
/// genuinely binds the proof to ITS OWN recomputed arguments rather than
/// trusting the caller.
#[test]
fn tampered_new_pubkey_fails_proof_verification() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let (client, account, fixture) = setup(&env);

    let mut tampered_pubkey_bytes = fixture.new_pubkey;
    tampered_pubkey_bytes[1] ^= 0xff; // flip a byte inside the x-coordinate
    let tampered_pubkey = BytesN::from_array(&env, &tampered_pubkey_bytes);

    let root = BytesN::from_array(&env, &fixture.root);
    let nullifier = BytesN::from_array(&env, &fixture.nullifier);
    let proof = Bytes::from_slice(&env, &fixture.proof);

    let res = client.try_initiate_recovery(
        &account,
        &tampered_pubkey,
        &fixture.nonce,
        &fixture.timelock_secs,
        &root,
        &nullifier,
        &proof,
    );
    assert_eq!(contract_error(&res), RecoveryError::VerificationFailed);
}

/// Cross-network replay: a proof generated against the TESTNET passphrase
/// must NOT verify against a pool configured for a DIFFERENT network (here,
/// the Stellar *mainnet* passphrase). `initiate_recovery` folds
/// `sha256(config.network_passphrase)` into the `auth_hash` it recomputes and
/// checks the proof against (`hash::compute_auth_hash`, the `npass_hi/lo`
/// inputs mirroring `main.nr:40-42`), so the real fixture proof -- valid on
/// testnet -- surfaces `VerificationFailed` here. This is the invariant that
/// stops a recovery proof captured on one network from being replayed against
/// a deployment on another (`SECURITY_INVARIANTS`: keccak transcript /
/// `auth_hash` domain binding). Everything BEFORE proof verification
/// (root/nonce/timelock/nullifier) is identical to the happy path and passes
/// -- only the passphrase differs -- so the rejection is attributable solely
/// to the passphrase bind.
#[test]
fn wrong_network_passphrase_proof_is_rejected() {
    // The Stellar *mainnet* passphrase -- differs from the fixture's
    // "Test SDF Network ; September 2015", so sha256(passphrase), and hence
    // the recomputed auth_hash, differ from the proof's committed value.
    const MAINNET_PASS: &[u8] = b"Public Global Stellar Network ; September 2015";

    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();

    let fixture = zk_fixture::lifecycle_fixture(&env);
    assert_ne!(
        fixture.network_passphrase.as_bytes(),
        MAINNET_PASS,
        "sanity: the override passphrase must differ from the fixture's"
    );
    let wrong_pass = Bytes::from_slice(&env, MAINNET_PASS);
    let client = deploy_with_passphrase(&env, &fixture, &wrong_pass);
    let account = addr_from(&env, &fixture.account);
    // Root is a pure function of the leaf (passphrase-independent), so the
    // fixture leaf still reproduces `fixture.root` and the root check passes.
    insert_fixture_leaf(&env, &client, &account, &fixture);

    let new_pubkey = BytesN::from_array(&env, &fixture.new_pubkey);
    let root = BytesN::from_array(&env, &fixture.root);
    let nullifier = BytesN::from_array(&env, &fixture.nullifier);
    let proof = Bytes::from_slice(&env, &fixture.proof);

    let res = client.try_initiate_recovery(
        &account,
        &new_pubkey,
        &fixture.nonce,
        &fixture.timelock_secs,
        &root,
        &nullifier,
        &proof,
    );
    assert_eq!(
        contract_error(&res),
        RecoveryError::VerificationFailed,
        "a proof bound to the testnet passphrase must not verify against a \
         pool configured with the mainnet passphrase"
    );
}

/// Malformed proof bytes (empty, and truncated to a non-empty prefix of a
/// real proof) must NEVER yield a pending recovery. All the pre-verification
/// checks (root/nonce/timelock/nullifier) pass -- the ONLY defect is the
/// proof itself -- so a successful call would mean the verifier accepted
/// garbage. The security property is fail-closed: the call must error and no
/// pending/nullifier state may be written. (Whether the vendored `UltraHonk`
/// verifier surfaces this as a clean `VerificationFailed` contract error or a
/// host-side trap on a length assertion is an implementation detail hardened
/// separately in workstream E -- "return a structured error instead of
/// `assert_eq!` on a truncated proof"; this test pins the invariant that
/// matters for funds either way: no malformed proof ever initiates recovery.)
#[test]
fn malformed_proof_never_initiates_recovery() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let (client, account, fixture) = setup(&env);

    let new_pubkey = BytesN::from_array(&env, &fixture.new_pubkey);
    let root = BytesN::from_array(&env, &fixture.root);
    let nullifier = BytesN::from_array(&env, &fixture.nullifier);

    // A non-empty prefix of the real proof (structurally proof-shaped but
    // truncated) and the empty proof.
    let truncated = Bytes::from_slice(&env, &fixture.proof[..fixture.proof.len() / 2]);
    let empty = Bytes::from_slice(&env, &[]);

    for bad_proof in [truncated, empty] {
        let res = client.try_initiate_recovery(
            &account,
            &new_pubkey,
            &fixture.nonce,
            &fixture.timelock_secs,
            &root,
            &nullifier,
            &bad_proof,
        );
        // Assert the SPECIFIC error, not just "some error": zk-recovery maps any
        // verifier failure -- including the zk-verifier's structured
        // ProofParseError on a bad-length proof -- to VerificationFailed, so a
        // malformed proof is rejected exactly like a well-formed-but-invalid one.
        assert_eq!(
            contract_error(&res),
            RecoveryError::VerificationFailed,
            "a malformed proof must be rejected as VerificationFailed"
        );

        // Fail-closed: no pending record and no nullifier reservation may
        // have been written by the rejected call.
        assert!(
            client.get_pending(&account).is_none(),
            "a rejected malformed-proof initiate must not leave a pending record"
        );
        let state: Option<NullifierState> = env.as_contract(&client.address, || {
            env.storage()
                .persistent()
                .get(&RecoveryKey::Nullifier(nullifier.clone()))
        });
        assert!(
            state.is_none(),
            "a rejected malformed-proof initiate must not reserve the nullifier"
        );
    }
}

/// Regression for the M1 Task 5 liveness bug: `initiate_recovery`'s
/// existing-pending check (step 1) allowed superseding a STALE pending
/// (`now >= expires_at`) without ever releasing that pending's nullifier
/// reservation. Because `nullifier = Poseidon2(DOM_NULL, account, secret)`
/// is deterministic per (account, secret) -- no nonce folded in -- the next
/// `initiate_recovery` for the same account recomputed the SAME nullifier,
/// found it still `Reserved` in step 3, and panicked `NullifierReserved`:
/// the account was permanently bricked for recovery after any single
/// expired attempt.
///
/// This is the PREFERRED regression form (see the fix's task report): a
/// SECOND real proof for the identical witness but `nonce = 2`
/// (`zk_fixture::lifecycle_fixture_nonce2`, generated the same way as the
/// nonce=1 fixture -- see
/// `circuits/zk_recovery/fixtures/lifecycle_nonce2/prover_inputs.json`).
/// This mirrors the real recovery flow exactly: a user re-initiating after
/// an expiry does so with a FRESH proof carrying the incremented nonce (a
/// circuit public input the user controls), so the whole
/// `initiate_recovery` call succeeds end-to-end and the nullifier release
/// persists atomically with the new pending record being stored and the
/// nullifier being re-reserved.
#[test]
fn stale_pending_can_be_superseded_by_a_fresh_nonce_proof() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let (client, account, fixture) = setup(&env);

    let new_pubkey = BytesN::from_array(&env, &fixture.new_pubkey);
    let root = BytesN::from_array(&env, &fixture.root);
    let nullifier = BytesN::from_array(&env, &fixture.nullifier);
    let proof = Bytes::from_slice(&env, &fixture.proof);

    // First initiation (nonce=1), as in the keystone test.
    let first_executable_after = client.initiate_recovery(
        &account,
        &new_pubkey,
        &fixture.nonce,
        &fixture.timelock_secs,
        &root,
        &nullifier,
        &proof,
    );
    let first_pending = client
        .get_pending(&account)
        .expect("get_pending must be Some after the first initiate_recovery");
    assert_eq!(first_pending.executable_after, first_executable_after);

    // The nullifier is reserved to `account` after the first initiation.
    let state_after_first: Option<NullifierState> = env.as_contract(&client.address, || {
        env.storage()
            .persistent()
            .get(&RecoveryKey::Nullifier(nullifier.clone()))
    });
    assert_eq!(
        state_after_first,
        Some(NullifierState::Reserved(account.clone())),
        "nullifier must be reserved to the recovering account after the first initiation"
    );

    // Advance the ledger past the first pending's `expires_at` -- it is now
    // stale/supersedable, not blocking (step 1's documented semantics).
    env.ledger().with_mut(|li| {
        li.timestamp = first_pending.expires_at;
    });

    // Second initiation for the SAME account, using a fresh real proof for
    // nonce=2 (same root/nullifier -- neither depends on nonce; different
    // auth_hash, since nonce is folded into auth_hash). Before the fix this
    // panicked `NullifierReserved` because step 1 never released the stale
    // pending's nullifier reservation; the fix releases it when the pending
    // found in step 1 is stale, so step 3 now sees the nullifier unused
    // again and this call SUCCEEDS -- proving the account is not
    // permanently bricked after a single expired attempt.
    let fixture2 = zk_fixture::lifecycle_fixture_nonce2(&env);
    assert_eq!(
        fixture2.root, fixture.root,
        "sanity: nonce=2 fixture must share the same root as the nonce=1 fixture"
    );
    assert_eq!(
        fixture2.nullifier, fixture.nullifier,
        "sanity: nonce=2 fixture must share the same nullifier as the nonce=1 fixture \
         -- the nullifier does not depend on nonce, which is exactly why the stale \
         reservation must be explicitly released"
    );
    let proof2 = Bytes::from_slice(&env, &fixture2.proof);

    let now = env.ledger().timestamp();
    let second_executable_after = client.initiate_recovery(
        &account,
        &new_pubkey,
        &fixture2.nonce,
        &fixture2.timelock_secs,
        &root,
        &nullifier,
        &proof2,
    );
    assert_eq!(
        second_executable_after,
        now + DELAY_SECS,
        "the superseding initiate_recovery must return now + config.delay_secs"
    );

    let second_pending = client
        .get_pending(&account)
        .expect("get_pending must be Some after the superseding initiate_recovery");
    assert_eq!(second_pending.executable_after, second_executable_after);
    assert!(
        second_pending.initiated_at > first_pending.initiated_at,
        "the second pending record must be a fresh one, not the stale first one"
    );

    // The nullifier is (re-)reserved to `account` after the second
    // initiation -- proving the release-then-reserve round trip left the
    // nullifier usable, not stuck or spent.
    let state_after_second: Option<NullifierState> = env.as_contract(&client.address, || {
        env.storage()
            .persistent()
            .get(&RecoveryKey::Nullifier(nullifier.clone()))
    });
    assert_eq!(
        state_after_second,
        Some(NullifierState::Reserved(account)),
        "nullifier must be reserved to the recovering account after the superseding \
         initiation"
    );
}

// ---------------------------------------------------------------------
// M1 Task 6: `cancel_recovery` + `burn_nullifier` (spec §2.3, §2.4).
// ---------------------------------------------------------------------

/// Reads a nullifier's current state directly from contract storage.
fn nullifier_state(
    env: &Env,
    client: &ZkRecoveryClient<'_>,
    nullifier: &BytesN<32>,
) -> Option<NullifierState> {
    env.as_contract(&client.address, || {
        env.storage()
            .persistent()
            .get(&RecoveryKey::Nullifier(nullifier.clone()))
    })
}

/// The keystone honesty check for M1 Task 6: a REAL `action=2` proof
/// (`zk_fixture::lifecycle_fixture_cancel`) verifies through
/// `cancel_recovery`'s cross-call to the M0 verifier, against a `cancel
/// auth_hash` this contract recomputes itself (zeroed pubkey/timelock, spec
/// §2.4) -- not one fed to it directly. Proves the pending is cleared, the
/// initiate's nullifier RESERVATION is released (the enrollment secret
/// stays usable -- cancel never burns it), `cancels_used` is incremented,
/// and `RecoveryCanceled` is emitted.
#[test]
fn real_cancel_proof_clears_pending_and_releases_nullifier() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let (client, account, fixture) = setup(&env);

    // `setup` already called `env.mock_all_auths()` (via `insert_fixture_leaf`),
    // which persists for the rest of this env -- `account.require_auth()`
    // inside `initiate_recovery`/`cancel_recovery` is satisfied by it.
    let new_pubkey = BytesN::from_array(&env, &fixture.new_pubkey);
    let root = BytesN::from_array(&env, &fixture.root);
    let nullifier = BytesN::from_array(&env, &fixture.nullifier);
    let proof = Bytes::from_slice(&env, &fixture.proof);

    client.initiate_recovery(
        &account,
        &new_pubkey,
        &fixture.nonce,
        &fixture.timelock_secs,
        &root,
        &nullifier,
        &proof,
    );
    assert!(client.get_pending(&account).is_some());
    assert_eq!(
        nullifier_state(&env, &client, &nullifier),
        Some(NullifierState::Reserved(account.clone())),
        "nullifier must be reserved after the initiate"
    );

    let cancel_fixture = zk_fixture::lifecycle_fixture_cancel(&env);
    assert_eq!(
        cancel_fixture.root, fixture.root,
        "sanity: the cancel fixture must share the same root as the base fixture -- \
         cancel does not touch the Merkle tree"
    );
    assert_eq!(
        cancel_fixture.nullifier, fixture.nullifier,
        "sanity: the cancel fixture must share the same nullifier as the base fixture -- \
         cancel releases the SAME reservation the initiate made"
    );
    let cancel_root = BytesN::from_array(&env, &cancel_fixture.root);
    let cancel_nullifier = BytesN::from_array(&env, &cancel_fixture.nullifier);
    let cancel_proof = Bytes::from_slice(&env, &cancel_fixture.proof);

    let cancels_used = client.cancel_recovery(
        &account,
        &cancel_fixture.nonce,
        &cancel_root,
        &cancel_nullifier,
        &cancel_proof,
    );
    assert_eq!(cancels_used, 1);

    // `events().all()` only returns events from the LAST invocation -- must
    // be captured before any further client calls.
    let expected_event = RecoveryCanceled {
        account: &account,
        cancels_used: &1,
    };
    assert_eq!(
        env.events().all().filter_by_contract(&client.address),
        [expected_event.to_xdr(&env, &client.address)],
        "RecoveryCanceled must be emitted with account/cancels_used"
    );

    assert!(
        client.get_pending(&account).is_none(),
        "the pending record must be deleted after a successful cancel"
    );
    assert_eq!(
        nullifier_state(&env, &client, &nullifier),
        None,
        "the initiate's nullifier reservation must be RELEASED (not spent) by a cancel -- \
         the enrollment secret stays usable for a future initiate"
    );
    assert_eq!(client.cancels_used(&account), 1);
}

/// `cancel_recovery` requires `account`'s own auth (the `WebAuthn` passkey
/// signer in production) -- exactly what an attacker who only knows a
/// leaked enrollment secret cannot provide. Mirrors
/// `pool.rs::insert_for_requires_account_auth`'s pattern: no auth mocked at
/// all (not `mock_all_auths`), so `account.require_auth()` -- the very
/// first thing `cancel_recovery` does -- must reject before anything else
/// is even inspected.
#[test]
fn cancel_recovery_requires_account_auth() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let (client, account, _fixture) = deploy(&env); // no leaf, no pending, no auth mocked

    let dummy_root = BytesN::from_array(&env, &[0u8; 32]);
    let dummy_nullifier = BytesN::from_array(&env, &[0u8; 32]);
    let dummy_proof = Bytes::from_slice(&env, &[]);

    let res =
        client.try_cancel_recovery(&account, &1u64, &dummy_root, &dummy_nullifier, &dummy_proof);
    assert!(
        res.is_err(),
        "cancel_recovery without the account's auth must fail"
    );
}

/// Cancel-cap guard, tested directly against the state machine (per the
/// task brief's explicit allowance): the cap check (spec §2.4) runs BEFORE
/// nonce/proof verification, so pre-seeding `Cancels(account) ==
/// config.max_cancels` and a live `Pending` lets this test hit
/// `CancelCapReached` without needing a real proof -- this test does NOT
/// exercise proof verification, unlike
/// `real_cancel_proof_clears_pending_and_releases_nullifier` above (which
/// does, and is the required real-proof coverage).
#[test]
fn cancel_cap_reached_is_rejected_before_proof_verification() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let (client, account, fixture) = deploy(&env);

    let now = env.ledger().timestamp();
    let nullifier = BytesN::from_array(&env, &fixture.nullifier);
    env.as_contract(&client.address, || {
        env.storage().persistent().set(
            &RecoveryKey::Pending(account.clone()),
            &PendingRecovery {
                new_pubkey: BytesN::from_array(&env, &[0u8; 65]),
                nullifier: nullifier.clone(),
                initiated_at: now,
                executable_after: now,
                expires_at: now + 1_000_000,
            },
        );
        // MAX_CANCELS (const above) == 2 -- pre-seed the cap as already hit.
        env.storage()
            .persistent()
            .set(&RecoveryKey::Cancels(account.clone()), &MAX_CANCELS);
    });

    env.mock_all_auths();
    let dummy_root = BytesN::from_array(&env, &[0u8; 32]);
    let dummy_proof = Bytes::from_slice(&env, &[]);
    let res = client.try_cancel_recovery(&account, &1u64, &dummy_root, &nullifier, &dummy_proof);
    assert_eq!(contract_error(&res), RecoveryError::CancelCapReached);
}

/// Cooldown guard, tested directly against the state machine (same
/// rationale as the cap test above): the cooldown check (spec §2.4) runs
/// BEFORE nonce/proof verification, so pre-seeding a live `Pending`, a
/// cancel count under the cap, and a `LastCancel` timestamp less than 24h
/// in the past lets this test hit `CooldownActive` without a real proof.
#[test]
fn cancel_cooldown_active_is_rejected_before_proof_verification() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let (client, account, fixture) = deploy(&env);

    let now = env.ledger().timestamp();
    let nullifier = BytesN::from_array(&env, &fixture.nullifier);
    env.as_contract(&client.address, || {
        env.storage().persistent().set(
            &RecoveryKey::Pending(account.clone()),
            &PendingRecovery {
                new_pubkey: BytesN::from_array(&env, &[0u8; 65]),
                nullifier: nullifier.clone(),
                initiated_at: now,
                executable_after: now,
                expires_at: now + 1_000_000,
            },
        );
        // Under the cap (MAX_CANCELS == 2).
        env.storage()
            .persistent()
            .set(&RecoveryKey::Cancels(account.clone()), &1u32);
        // Last cancel 1 hour ago -- well under the 24h (86_400s) cooldown.
        env.storage().persistent().set(
            &RecoveryKey::LastCancel(account.clone()),
            &now.saturating_sub(3_600),
        );
    });

    env.mock_all_auths();
    let dummy_root = BytesN::from_array(&env, &[0u8; 32]);
    let dummy_proof = Bytes::from_slice(&env, &[]);
    let res = client.try_cancel_recovery(&account, &1u64, &dummy_root, &nullifier, &dummy_proof);
    assert_eq!(contract_error(&res), RecoveryError::CooldownActive);
}

/// `burn_nullifier` happy path (spec §2.3, M1 Task 9 -- proof-gated
/// REVOKE): a REAL `action=3` proof (`zk_fixture::lifecycle_fixture_revoke`)
/// marks the nullifier `Spent`, and a later `initiate_recovery` attempt with
/// that same nullifier is rejected `NullifierSpent` -- even though the
/// root/proof it's paired with are otherwise entirely valid. This is the
/// legitimate owner's escape hatch: proving knowledge of a leaked
/// enrollment secret instantly kills it without waiting out a
/// self-recovery.
#[test]
fn real_revoke_proof_burns_nullifier_and_blocks_later_initiate() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let (client, account, fixture) = setup(&env); // known root, mock_all_auths on

    let nullifier = BytesN::from_array(&env, &fixture.nullifier);
    assert_eq!(nullifier_state(&env, &client, &nullifier), None);

    let revoke_fixture = zk_fixture::lifecycle_fixture_revoke(&env);
    assert_eq!(
        revoke_fixture.root, fixture.root,
        "sanity: the revoke fixture must share the same root as the base fixture -- \
         revoking does not touch the Merkle tree"
    );
    assert_eq!(
        revoke_fixture.nullifier, fixture.nullifier,
        "sanity: the revoke fixture must share the same nullifier as the base fixture"
    );
    let revoke_root = BytesN::from_array(&env, &revoke_fixture.root);
    let revoke_nullifier = BytesN::from_array(&env, &revoke_fixture.nullifier);
    let revoke_proof = Bytes::from_slice(&env, &revoke_fixture.proof);

    client.burn_nullifier(
        &account,
        &revoke_fixture.nonce,
        &revoke_root,
        &revoke_nullifier,
        &revoke_proof,
    );

    // `events().all()` only returns events from the LAST invocation -- must
    // be captured before any further client calls (including read-only
    // storage inspection via `nullifier_state`'s `env.as_contract`).
    let expected_event = NullifierBurned {
        account: &account,
        nullifier: &nullifier,
    };
    assert_eq!(
        env.events().all().filter_by_contract(&client.address),
        [expected_event.to_xdr(&env, &client.address)],
        "NullifierBurned must be emitted with account/nullifier"
    );

    assert_eq!(
        nullifier_state(&env, &client, &nullifier),
        Some(NullifierState::Spent),
        "burn_nullifier must mark the nullifier Spent"
    );

    let new_pubkey = BytesN::from_array(&env, &fixture.new_pubkey);
    let root = BytesN::from_array(&env, &fixture.root);
    let proof = Bytes::from_slice(&env, &fixture.proof);
    let res = client.try_initiate_recovery(
        &account,
        &new_pubkey,
        &fixture.nonce,
        &fixture.timelock_secs,
        &root,
        &nullifier,
        &proof,
    );
    assert_eq!(
        contract_error(&res),
        RecoveryError::NullifierSpent,
        "a burned nullifier must block a later initiate_recovery, even with an \
         otherwise-valid root/proof"
    );
}

/// `burn_nullifier` requires `account`'s own auth -- `account.require_auth()`
/// is the very first check, so it must reject before the (dummy, otherwise
/// nonsense) root/nullifier/proof are even inspected. Mirrors
/// `cancel_recovery_requires_account_auth`: no auth mocked at all.
#[test]
fn burn_nullifier_requires_account_auth() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let (client, account, _fixture) = deploy(&env); // no leaf, no auth mocked

    let dummy_root = BytesN::from_array(&env, &[0u8; 32]);
    let dummy_nullifier = BytesN::from_array(&env, &[0u8; 32]);
    let dummy_proof = Bytes::from_slice(&env, &[]);
    let res =
        client.try_burn_nullifier(&account, &1u64, &dummy_root, &dummy_nullifier, &dummy_proof);
    assert!(
        res.is_err(),
        "burn_nullifier without the account's auth must fail"
    );
}

/// The griefing-closed regression test (spec §2.3, M1 Task 9 -- the whole
/// point of this fix): account `A`'s nullifier is made PUBLIC (revealed as a
/// proof public input by a real `initiate_recovery`) and then RELEASED (by a
/// real `cancel_recovery`) -- exactly the sequence the pre-fix
/// account-auth-only `burn_nullifier` was vulnerable to. A DIFFERENT account
/// `B` then tries to burn that same public nullifier using the ONLY real
/// `action=3` proof that exists for it (`zk_fixture::lifecycle_fixture_revoke`,
/// bound to `A`'s address via `auth_hash`) -- this MUST fail, because `B`
/// calling `burn_nullifier` makes this contract recompute `auth_hash` from
/// `B`'s own address, which no longer matches the triple the fixture proof
/// verifies against. A real griefer (who does not know `A`'s secret) cannot
/// produce ANY valid `action=3` proof binding `B`'s own address to `A`'s
/// leaf/nullifier, so reusing the only proof that exists is the closest a
/// test can get to demonstrating that impossibility. Proves the grief is
/// closed: `B` cannot kill `A`'s enrollment credential.
#[test]
fn burn_nullifier_cannot_grief_a_different_accounts_public_nullifier() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let (client, account, fixture) = setup(&env); // known root, mock_all_auths on

    let new_pubkey = BytesN::from_array(&env, &fixture.new_pubkey);
    let root = BytesN::from_array(&env, &fixture.root);
    let nullifier = BytesN::from_array(&env, &fixture.nullifier);
    let proof = Bytes::from_slice(&env, &fixture.proof);

    // `A` initiates (reveals `nullifier` as a real proof PUBLIC INPUT --
    // it is now public knowledge, exactly as it would be on a real chain).
    client.initiate_recovery(
        &account,
        &new_pubkey,
        &fixture.nonce,
        &fixture.timelock_secs,
        &root,
        &nullifier,
        &proof,
    );
    assert_eq!(
        nullifier_state(&env, &client, &nullifier),
        Some(NullifierState::Reserved(account.clone()))
    );

    // `A` cancels (RELEASES the reservation -- spec §2.3: "a cancel never
    // burns the enrollment", so the nullifier stays usable, but it is
    // already public).
    let cancel_fixture = zk_fixture::lifecycle_fixture_cancel(&env);
    let cancel_root = BytesN::from_array(&env, &cancel_fixture.root);
    let cancel_nullifier = BytesN::from_array(&env, &cancel_fixture.nullifier);
    let cancel_proof = Bytes::from_slice(&env, &cancel_fixture.proof);
    client.cancel_recovery(
        &account,
        &cancel_fixture.nonce,
        &cancel_root,
        &cancel_nullifier,
        &cancel_proof,
    );
    assert_eq!(
        nullifier_state(&env, &client, &nullifier),
        None,
        "the reservation must be released (not spent) by the cancel -- the nullifier is \
         public but unclaimed, exactly the griefing window this fix closes"
    );

    // `B` (a totally different, unrelated account) tries to burn `A`'s now-
    // public nullifier using the only real `action=3` proof that exists --
    // the one bound to `A`. `B`'s own nonce sequence is independent and
    // fresh, so `nonce = 1` is what `B` must pass to clear the replay check
    // and reach proof verification.
    let other = Address::generate(&env);
    let revoke_fixture = zk_fixture::lifecycle_fixture_revoke(&env);
    let revoke_root = BytesN::from_array(&env, &revoke_fixture.root);
    let revoke_proof = Bytes::from_slice(&env, &revoke_fixture.proof);

    let res = client.try_burn_nullifier(&other, &1u64, &revoke_root, &nullifier, &revoke_proof);
    assert_eq!(
        contract_error(&res),
        RecoveryError::VerificationFailed,
        "a foreign account must NOT be able to burn a victim's public nullifier -- \
         the recomputed auth_hash binds THIS call's account, so it cannot match a proof \
         generated for a different account"
    );

    // The grief attempt must leave the nullifier exactly as it was --
    // released, not spent, and still burnable by its rightful owner later.
    assert_eq!(
        nullifier_state(&env, &client, &nullifier),
        None,
        "a failed grief attempt must not change the nullifier's state"
    );
}
