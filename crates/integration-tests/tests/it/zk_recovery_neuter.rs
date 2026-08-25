//! Task 9: the stolen-passkey DIRECT-CALL neuter fix for the controller's
//! `Policy::install`/`Policy::uninstall` (spec §3.1).
//!
//! Before the fix, both entry points gated ONLY on
//! `smart_account.require_auth()`. A thief holding a stolen `WebAuthn` passkey
//! satisfies that (the account's Default rule matches any context), so they
//! could call the controller's `install`/`uninstall` DIRECTLY (top-level, or
//! via the account's `execute`) -- bypassing the M2 in-account guard
//! (`zk_recovery_guard.rs`) and the 7-day removal delay:
//!   - `uninstall(any_rule, account)` cleared `Installed(account)` -> every
//!     future completion `enforce` panics `NotInstalled` -> recovery
//!     permanently neutered.
//!   - `install(params, fabricated_rule, account)` repointed
//!     `Installed(account)` to a bogus id -> completion `enforce` panics
//!     `RuleMismatch`.
//!
//! The fix (reentrancy-free -- see `policy.rs`; the controller CANNOT
//! cross-call back into the account during install/uninstall, as the account
//! is already on the call stack and Soroban bans reentrancy):
//!   - `install`: an `AlreadyInstalled` guard -- the single legitimate
//!     install per account fires exactly once, atomically inside construction
//!     / `enroll_zk_recovery`; any later direct repoint is refused.
//!   - `uninstall`: unconditionally REFUSES (`Unauthorized`). The only
//!     legitimate caller is OZ's `remove_context_rule` via `try_uninstall`,
//!     which SWALLOWS the panic by design, so the account's 7-day-gated
//!     `execute_recovery_rule_removal` still tears the rule down end-to-end;
//!     a thief's direct call earns only the panic and cannot clear `Installed`.
//!
//! These tests use the REAL deployed `ZkRecovery` controller + REAL smart
//! account + the M1 lifecycle fixture proof (mirroring `zk_recovery_e2e.rs`).

use nido_integration_tests::{
    test_key, zk_fixture, SmartAccountClient, SMART_ACCOUNT_WASM, WEBAUTHN_VERIFIER_WASM,
};
use nido_zk_recovery::hash::leaf_inner;
use nido_zk_recovery::pool::{ZkRecovery, ZkRecoveryClient};
use nido_zk_recovery::types::{RecoveryError, RecoveryKey, ZkRecoveryInstallParams};
use soroban_sdk::address_payload::AddressPayload;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::xdr::{
    InvokeContractArgs, ScAddress, ScSymbol, ScVal, SorobanAddressCredentials,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, VecM,
};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, IntoVal, InvokeError, Map, String, TryFromVal, Val, Vec as SVec,
};
use stellar_accounts::smart_account::{AuthPayload, ContextRule, ContextRuleType, Signer};

mod zk_verifier_contract {
    soroban_sdk::contractimport!(
        file = "../../target/wasm32v1-none/contract/nido_zk_verifier.wasm"
    );
}

const DELAY_SECS: u64 = zk_fixture::TIMELOCK_SECS as u64;
const COMPLETION_WINDOW_SECS: u64 = 30 * 24 * 3600;
const MAX_CANCELS: u32 = 2;
const TIMELOCK_FLOOR_SECS: u64 = 7 * 24 * 3600;
const REMOVAL_DELAY_SECS: u64 = 7 * 24 * 3600;

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

/// Reads the controller's `RecoveryKey::Installed(account)` marker (the id
/// this policy recorded it was installed under), or `None` if absent.
fn installed_id(env: &Env, controller: &Address, account: &Address) -> Option<u32> {
    env.as_contract(controller, || {
        env.storage()
            .persistent()
            .get::<_, u32>(&RecoveryKey::Installed(account.clone()))
    })
}

/// A well-formed-but-fabricated `ContextRule` an attacker might pass to
/// `install`/`uninstall`. Shape mimics the real recovery rule (zero signers,
/// `CallContract(self)`, this controller in `policies`) but its `id` is a
/// bogus value the account never assigned.
fn fabricated_rule(
    env: &Env,
    account: &Address,
    controller: &Address,
    bogus_id: u32,
) -> ContextRule {
    ContextRule {
        id: bogus_id,
        context_type: ContextRuleType::CallContract(account.clone()),
        name: String::from_str(env, "fake"),
        signers: SVec::new(env),
        signer_ids: SVec::new(env),
        policies: soroban_sdk::vec![env, controller.clone()],
        policy_ids: soroban_sdk::vec![env, 0u32],
        valid_until: None,
    }
}

fn add_context_rule_args(
    env: &Env,
    context_type: &ContextRuleType,
    name: &String,
    valid_until: Option<u32>,
    signers: &SVec<Signer>,
    policies: &Map<Address, Val>,
) -> SVec<Val> {
    soroban_sdk::vec![
        env,
        context_type.clone().into_val(env),
        name.clone().into_val(env),
        valid_until.into_val(env),
        signers.clone().into_val(env),
        policies.clone().into_val(env),
    ]
}

fn self_call_entry(
    env: &Env,
    account_addr: &Address,
    fn_name: &str,
    args: &SVec<Val>,
    context_rule_ids: SVec<u32>,
) -> SorobanAuthorizationEntry {
    let args_scval: VecM<ScVal> = args
        .iter()
        .map(|v| ScVal::try_from_val(env, &v).unwrap())
        .collect::<std::vec::Vec<_>>()
        .try_into()
        .unwrap();

    let invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::from(account_addr),
            function_name: ScSymbol(fn_name.try_into().unwrap()),
            args: args_scval,
        }),
        sub_invocations: VecM::default(),
    };

    let auth_payload = AuthPayload {
        signers: Map::new(env),
        context_rule_ids,
    };
    let payload_val: Val = auth_payload.into_val(env);
    let signature = ScVal::try_from_val(env, &payload_val).unwrap();

    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: ScAddress::from(account_addr),
            nonce: 0x00C0_FFEE,
            signature_expiration_ledger: 999_999,
            signature,
        }),
        root_invocation: invocation,
    }
}

struct Deployed<'a> {
    account: SmartAccountClient<'a>,
    account_addr: Address,
    controller_addr: Address,
    zk: ZkRecoveryClient<'a>,
    rule_id: u32,
    webauthn_verifier: Address,
}

/// Deploys the real controller (pinned at `CONTROLLER`) + a real smart account
/// (pinned at `ACCOUNT`) via the constructor's `Some(controller)` genesis path,
/// with a real `WebAuthn` passkey signer on the Default rule and the fixture leaf
/// inserted -- i.e. a fully-enrolled account ready for a real-proof recovery.
/// `mock_all_auths` is left ON for setup; completion tests switch to
/// `set_auths` for the completing call.
fn deploy(env: &Env) -> Deployed<'_> {
    let fixture = zk_fixture::lifecycle_fixture(env);
    env.mock_all_auths();

    let vk_bytes = Bytes::from_slice(env, include_bytes!("../../fixtures/zk/vk"));
    let verifier_id = env.register(
        zk_verifier_contract::WASM,
        (Address::generate(env), vk_bytes),
    );
    let controller_addr = addr_from(env, &fixture.controller);
    let factory = Address::generate(env);
    let network_passphrase = Bytes::from_slice(env, fixture.network_passphrase.as_bytes());
    let webauthn_verifier = env.register(WEBAUTHN_VERIFIER_WASM, (Address::generate(env),));
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
            webauthn_verifier.clone(),
            Address::generate(env), // upgrade admin (unused by this file's coverage)
        ),
    );
    let zk = ZkRecoveryClient::new(env, &controller_addr);

    let orig_key = test_key(0xACC0);
    let orig_pubkey = orig_key.verifying_key().to_sec1_bytes();
    let orig_signer = Signer::External(
        webauthn_verifier.clone(),
        Bytes::from_slice(env, &orig_pubkey),
    );
    let signers = soroban_sdk::vec![env, orig_signer];
    let policies: Map<Address, Val> = Map::new(env);
    let account_addr = addr_from(env, &fixture.account);
    env.register_at(
        &account_addr,
        SMART_ACCOUNT_WASM,
        (signers, policies, Some(controller_addr.clone())),
    );
    let account = SmartAccountClient::new(env, &account_addr);
    let rule_id = account
        .recovery_rule_id()
        .expect("constructor Some(controller) installs the recovery rule");

    // A spare signer so a post-recovery remove of the original doesn't leave
    // the Default rule empty (mirrors zk_recovery_e2e.rs).
    account.add_signer(&0, &Signer::Delegated(Address::generate(env)));

    let secret = BytesN::from_array(env, &hex32(fixture.secret_hex));
    let commitment = leaf_inner(env, &secret);
    zk.insert_for(&account_addr, &commitment);

    Deployed {
        account,
        account_addr,
        controller_addr,
        zk,
        rule_id,
        webauthn_verifier,
    }
}

/// Drives the fixture proof through `initiate_recovery`, creating a real live
/// pending for the account.
fn initiate(env: &Env, d: &Deployed<'_>) -> u64 {
    let fixture = zk_fixture::lifecycle_fixture(env);
    let new_pubkey = BytesN::from_array(env, &fixture.new_pubkey);
    let root = BytesN::from_array(env, &fixture.root);
    let nullifier = BytesN::from_array(env, &fixture.nullifier);
    let proof = Bytes::from_slice(env, &fixture.proof);
    d.zk.initiate_recovery(
        &d.account_addr,
        &new_pubkey,
        &fixture.nonce,
        &fixture.timelock_secs,
        &root,
        &nullifier,
        &proof,
    )
}

/// Completes recovery via the REAL host authorization dispatch (no
/// `mock_all_auths` on the completing call) -- `do_check_auth` ->
/// `ZkRecovery::enforce` -> the signer is rotated. Returns whether it
/// succeeded. Must be called after the timelock has elapsed.
fn complete(env: &Env, d: &Deployed<'_>) -> bool {
    let fixture = zk_fixture::lifecycle_fixture(env);
    let context_type = ContextRuleType::Default;
    let name = String::from_str(env, "recovered");
    let new_signer = Signer::External(
        d.webauthn_verifier.clone(),
        Bytes::from_array(env, &fixture.new_pubkey),
    );
    let new_signers = soroban_sdk::vec![env, new_signer];
    let empty_policies: Map<Address, Val> = Map::new(env);

    let args = add_context_rule_args(
        env,
        &context_type,
        &name,
        None,
        &new_signers,
        &empty_policies,
    );
    let entry = self_call_entry(
        env,
        &d.account_addr,
        "add_context_rule",
        &args,
        soroban_sdk::vec![env, d.rule_id],
    );
    env.set_auths(&[entry]);
    d.account
        .try_add_context_rule(&context_type, &name, &None, &new_signers, &empty_policies)
        .is_ok()
}

// -----------------------------------------------------------------------
// Regression tests
// -----------------------------------------------------------------------

/// **Attacker uninstall blocked (no pending) + recovery NOT broken.** A
/// top-level `uninstall(fabricated_rule, account)` while the recovery rule is
/// intact PANICS (`Unauthorized`); `Installed` is untouched; a full real-proof
/// recovery afterwards STILL completes -- proving the direct call could not
/// neuter recovery.
#[test]
fn attacker_uninstall_refused_no_pending_recovery_still_works() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let d = deploy(&env);

    let before = installed_id(&env, &d.controller_addr, &d.account_addr);
    assert_eq!(
        before,
        Some(d.rule_id),
        "sanity: installed under the recovery rule id"
    );

    // Attacker (account auth satisfied via mock_all_auths, standing in for a
    // stolen passkey) calls the controller's uninstall directly.
    let fake = fabricated_rule(&env, &d.account_addr, &d.controller_addr, 999);
    let res = d.zk.try_uninstall(&fake, &d.account_addr);
    assert_eq!(
        error_code(&res),
        RecoveryError::Unauthorized as u32,
        "a direct uninstall must be refused"
    );

    // Installed marker survived the refused call.
    assert_eq!(
        installed_id(&env, &d.controller_addr, &d.account_addr),
        Some(d.rule_id),
        "a refused uninstall must NOT clear Installed"
    );

    // Recovery still works end-to-end.
    let executable_after = initiate(&env, &d);
    env.ledger().with_mut(|li| li.timestamp = executable_after);
    assert!(
        complete(&env, &d),
        "recovery must still complete after a refused attacker uninstall"
    );
}

/// **Attacker install repoint blocked (`AlreadyInstalled`).** With a rule
/// already installed, a direct `install(params, fabricated_rule, account)`
/// PANICS `AlreadyInstalled` and does NOT repoint `Installed`.
#[test]
fn attacker_install_repoint_refused_already_installed() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let d = deploy(&env);

    let params = ZkRecoveryInstallParams { version: 1 };
    let fake = fabricated_rule(&env, &d.account_addr, &d.controller_addr, 424_242);
    let res = d.zk.try_install(&params, &fake, &d.account_addr);
    assert_eq!(
        error_code(&res),
        RecoveryError::AlreadyInstalled as u32,
        "a repoint install must be refused with AlreadyInstalled"
    );
    assert_eq!(
        installed_id(&env, &d.controller_addr, &d.account_addr),
        Some(d.rule_id),
        "Installed must NOT have been repointed to the fabricated id"
    );
}

/// **Both refused while a live recovery is pending, and completion still
/// works.** During a live pending, the attacker's direct `install` (repoint)
/// and `uninstall` (clear) are both refused; the pending survives and the
/// recovery completes normally.
#[test]
fn attacker_install_and_uninstall_refused_while_pending() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let d = deploy(&env);

    let executable_after = initiate(&env, &d);
    assert!(
        d.zk.has_pending(&d.account_addr),
        "sanity: live pending exists"
    );

    let params = ZkRecoveryInstallParams { version: 1 };
    let fake = fabricated_rule(&env, &d.account_addr, &d.controller_addr, 7);
    assert_eq!(
        error_code(&d.zk.try_install(&params, &fake, &d.account_addr)),
        RecoveryError::AlreadyInstalled as u32,
        "install repoint refused while pending"
    );
    assert_eq!(
        error_code(&d.zk.try_uninstall(&fake, &d.account_addr)),
        RecoveryError::Unauthorized as u32,
        "uninstall refused while pending"
    );

    assert_eq!(
        installed_id(&env, &d.controller_addr, &d.account_addr),
        Some(d.rule_id),
        "Installed intact after both refused calls"
    );
    assert!(
        d.zk.has_pending(&d.account_addr),
        "pending survives the refused calls"
    );

    env.ledger().with_mut(|li| li.timestamp = executable_after);
    assert!(
        complete(&env, &d),
        "recovery completes after refused attacker calls"
    );
}

/// **Legitimate teardown still works with the REAL controller.** The M2
/// announce-then-execute removal (`execute_recovery_rule_removal`) drives OZ's
/// `remove_context_rule` -> `try_uninstall` on the real controller (whose
/// `uninstall` now always panics); `try_uninstall` SWALLOWS that panic by
/// design, so the recovery rule is still removed end-to-end and the account's
/// recovery ids are cleared. This is the load-bearing "don't brick the legit
/// removal" check.
#[test]
fn legit_execute_recovery_rule_removal_still_tears_down() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let d = deploy(&env);

    assert_eq!(
        d.account.recovery_rule_id(),
        Some(d.rule_id),
        "sanity: rule installed"
    );

    d.account.initiate_recovery_rule_removal();
    env.ledger()
        .with_mut(|li| li.timestamp += REMOVAL_DELAY_SECS + 1);
    d.account.execute_recovery_rule_removal();

    assert_eq!(
        d.account.recovery_rule_id(),
        None,
        "execute_recovery_rule_removal must remove the recovery rule even though \
         the controller's uninstall panics (try_uninstall swallows it)"
    );
    assert_eq!(
        d.account.recovery_controller(),
        None,
        "recovery controller instance key cleared after removal"
    );
    // The rule really is gone from account storage.
    let res = d.account.try_get_context_rule(&d.rule_id);
    assert!(
        res.is_err(),
        "the recovery ContextRule must no longer exist on the account"
    );
}

/// **Documented reentrancy limitation (fresh-account install).** A genuine
/// rule-EXISTENCE cross-check (proving the account really holds the rule with
/// this controller) is impossible: `install` runs with the account already on
/// the call stack, so cross-calling back into it hits Soroban's reentrancy ban
/// and would trap the whole (legitimate) construction. Hence a direct
/// `install` on a fresh account with a fabricated rule cannot be distinguished
/// from a legitimate enrollment and SUCCEEDS (claiming `Installed`). The
/// residual is low severity: it needs the fresh account's OWN passkey, and the
/// production factory path installs atomically at construction (no pre-install
/// window). The `AlreadyInstalled` guard still makes a SECOND install refuse --
/// this is the reentrancy-free protection that actually closes the critical
/// repoint-of-an-enrolled-account attack.
#[test]
fn fresh_account_fabricated_install_is_a_documented_reentrancy_limitation() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let fixture = zk_fixture::lifecycle_fixture(&env);
    env.mock_all_auths();

    let vk_bytes = Bytes::from_slice(&env, include_bytes!("../../fixtures/zk/vk"));
    let verifier_id = env.register(
        zk_verifier_contract::WASM,
        (Address::generate(&env), vk_bytes),
    );
    let controller_addr = addr_from(&env, &fixture.controller);
    let factory = Address::generate(&env);
    let network_passphrase = Bytes::from_slice(&env, fixture.network_passphrase.as_bytes());
    let webauthn_verifier = env.register(WEBAUTHN_VERIFIER_WASM, (Address::generate(&env),));
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
            Address::generate(&env), // upgrade admin (unused by this file's coverage)
        ),
    );
    let zk = ZkRecoveryClient::new(&env, &controller_addr);

    // A fresh account address that never enrolled -- no Installed marker.
    let fresh = Address::generate(&env);
    assert_eq!(installed_id(&env, &controller_addr, &fresh), None);

    let params = ZkRecoveryInstallParams { version: 1 };
    let fake = fabricated_rule(&env, &fresh, &controller_addr, 5);
    // First fabricated install SUCCEEDS (cannot be blocked reentrancy-free).
    zk.install(&params, &fake, &fresh);
    assert_eq!(
        installed_id(&env, &controller_addr, &fresh),
        Some(5),
        "documented: a fresh fabricated install claims Installed"
    );
    // But a SECOND install is refused by the AlreadyInstalled guard.
    let fake2 = fabricated_rule(&env, &fresh, &controller_addr, 6);
    assert_eq!(
        error_code(&zk.try_install(&params, &fake2, &fresh)),
        RecoveryError::AlreadyInstalled as u32,
        "the AlreadyInstalled guard blocks any second install (the critical repoint)"
    );
}
