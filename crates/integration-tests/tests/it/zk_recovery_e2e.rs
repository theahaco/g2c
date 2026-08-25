//! M2 Task 7: the capstone integration test -- proving the WHOLE stack
//! composes end-to-end via the GENESIS path.
//!
//! Everything below has been proven piecewise already:
//!   - `zk_recovery_completion.rs` drives a REAL fixture proof through
//!     completion (`do_check_auth` -> real `enforce`), but installs the
//!     recovery rule MANUALLY (constructor `recovery_controller: None`, then
//!     a separate `add_context_rule` call) so it can control exactly when
//!     the policy is installed.
//!   - `zk_recovery_guard.rs` proves the in-account guard's cross-call
//!     reaches a REAL deployed controller, using the constructor's
//!     `Some(recovery_controller)` path -- but with a plain `Delegated`
//!     signer and `mock_all_auths()` throughout, never a real proof-backed
//!     completion.
//!   - `contracts/factory`'s own unit tests prove `create_account`/
//!     `create_account_v2` deploy uniformly and insert exactly one genesis
//!     leaf each.
//!
//! Test 1 here is the thing none of those alone prove: the CONSTRUCTOR's
//! `Some(controller)` path (the actual production genesis path a factory
//! deploy takes) driving a REAL fixture proof all the way through
//! `initiate_recovery` -> the in-account guard (blocking mutation while
//! pending) -> the timelock elapsing -> a REAL `do_check_auth` dispatch
//! (`env.set_auths`, no `mock_all_auths` on the completing call) into the
//! controller's `enforce`, which rotates the signer -> the guard releasing
//! afterwards. One continuous chain, no shortcuts.
//!
//! Test 2 proves the complementary privacy property at the account level:
//! an account created via the real-commitment path (`create_account_v2`)
//! and one created via the legacy dummy-commitment path (`create_account`)
//! are indistinguishable from any on-chain-observable state -- the same
//! recovery-rule shape, exactly one genesis leaf each. The only thing that
//! actually differs (whether the account owner knows a secret behind their
//! leaf) never touches the chain.

use nido_integration_tests::{
    test_key, zk_fixture, SmartAccountClient, FACTORY_WASM, SMART_ACCOUNT_WASM,
    WEBAUTHN_VERIFIER_WASM,
};
use nido_smart_account::contract::NidoSmartAccountError;
use nido_zk_recovery::hash::leaf_inner;
use nido_zk_recovery::pool::{ZkRecovery, ZkRecoveryClient};
use nido_zk_recovery::types::{NullifierState, RecoveryCompleted, RecoveryKey};
use soroban_sdk::address_payload::AddressPayload;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::testutils::{Events as _, Ledger as _};
use soroban_sdk::xdr::{
    InvokeContractArgs, ScAddress, ScSymbol, ScVal, SorobanAddressCredentials,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, VecM,
};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, Event, IntoVal, InvokeError, Map, String, TryFromVal, Val,
    Vec as SVec,
};
use stellar_accounts::smart_account::{AuthPayload, ContextRuleType, Signer};

mod zk_verifier_contract {
    // Path is relative to CARGO_MANIFEST_DIR (crates/integration-tests/).
    soroban_sdk::contractimport!(
        file = "../../target/wasm32v1-none/contract/nido_zk_verifier.wasm"
    );
}

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

/// Builds the real `add_context_rule` args in `enforce`'s expected order:
/// `[context_type, name, valid_until, signers, policies]` (mirrors
/// `zk_recovery_completion.rs`'s helper of the same name).
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

/// Builds a `SorobanAuthorizationEntry` for a SELF-authorizing call, with a
/// zero-signer `AuthPayload` selecting `context_rule_ids` -- no cryptographic
/// signature needed, `do_check_auth` defers entirely to the selected rule's
/// policy/`enforce` (mirrors `zk_recovery_completion.rs`'s helper of the
/// same name).
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

/// **Test 1 -- the capstone.** Deploys the smart account at the fixture's
/// pinned `ACCOUNT` via the CONSTRUCTOR's `Some(recovery_controller)` path
/// (the production factory-genesis shape), genesis-inserts the fixture
/// leaf, drives a REAL fixture proof through `initiate_recovery`, proves the
/// in-account guard blocks mutation while pending (via a REAL cross-call
/// into the deployed controller), advances past the timelock, completes via
/// the REAL host authorization dispatch (`do_check_auth` -> real
/// `ZkRecovery::enforce`, no `mock_all_auths` on the completing call) --
/// rotating the signer -- and finally proves the guard releases afterwards.
#[test]
// One continuous end-to-end chain (deploy -> initiate -> guard -> timelock
// -> completion -> post-recovery release); splitting it would break the
// "no shortcuts" property the doc comment above asserts.
#[allow(clippy::too_many_lines)]
fn constructor_installed_rule_drives_real_proof_completion_and_guard() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let fixture = zk_fixture::lifecycle_fixture(&env);

    // --- The M0 zk-verifier + the real ZkRecovery controller, pinned at
    // CONTROLLER. ---
    let vk_bytes = Bytes::from_slice(&env, include_bytes!("../../fixtures/zk/vk"));
    let verifier_id = env.register(
        zk_verifier_contract::WASM,
        (Address::generate(&env), vk_bytes),
    );
    let controller_addr = addr_from(&env, &fixture.controller);
    let factory = Address::generate(&env);
    let network_passphrase = Bytes::from_slice(&env, fixture.network_passphrase.as_bytes());
    let webauthn_verifier = env.register(WEBAUTHN_VERIFIER_WASM, (Address::generate(&env),));

    // `mock_all_auths` covers the setup calls below that are NOT
    // self-invoking (the account's own constructor cross-calling
    // `Policy::install` on itself is covered by invoker-contract auth
    // regardless, per `contracts/factory`'s own genesis-insert tests' doc
    // comment) -- specifically the `insert_for` call below, which the TEST
    // itself calls on the account's behalf. The keystone completion call
    // further down switches to a real `env.set_auths` dispatch instead.
    env.mock_all_auths();
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
            Address::generate(&env), // upgrade admin (unused by this file's coverage)
        ),
    );
    let zk = ZkRecoveryClient::new(&env, &controller_addr);

    // --- The smart account, pinned at ACCOUNT, via the CONSTRUCTOR's
    // `Some(recovery_controller)` path -- this IS the distinct thing this
    // test proves vs `zk_recovery_completion.rs`'s manual
    // `add_context_rule` install. ---
    let orig_key = test_key(0xACC0);
    let orig_pubkey = orig_key.verifying_key().to_sec1_bytes();
    let orig_signer = Signer::External(
        webauthn_verifier.clone(),
        Bytes::from_slice(&env, &orig_pubkey),
    );
    let signers = soroban_sdk::vec![&env, orig_signer];
    let policies: Map<Address, Val> = Map::new(&env);
    let account_addr = addr_from(&env, &fixture.account);
    env.register_at(
        &account_addr,
        SMART_ACCOUNT_WASM,
        (signers, policies, Some(controller_addr.clone())),
    );
    let account = SmartAccountClient::new(&env, &account_addr);

    let rule_id = account
        .recovery_rule_id()
        .expect("constructor with Some(controller) must install the recovery rule");
    assert_eq!(
        account.recovery_controller(),
        Some(controller_addr.clone()),
        "constructor must store the recovery controller"
    );

    // A second, throwaway signer on the Default rule -- purely so the
    // post-recovery guard-release check below can remove the ORIGINAL
    // webauthn signer without leaving the rule with zero signers AND zero
    // policies (which OZ's `add_context_rule`/`remove_signer` rejects with
    // `NoSignersAndPolicies`, unrelated to anything this test is about).
    let spare_signer_addr = Address::generate(&env);
    account.add_signer(&0, &Signer::Delegated(spare_signer_addr));

    // --- Genesis-insert the fixture leaf via the pool. ---
    let secret = BytesN::from_array(&env, &hex32(fixture.secret_hex));
    let commitment = leaf_inner(&env, &secret);
    zk.insert_for(&account_addr, &commitment);
    assert_eq!(
        zk.current_root().to_array(),
        fixture.root,
        "on-chain frontier root after inserting the fixture leaf must equal \
         the circuit's independently-computed root"
    );

    // --- Real-proof initiate_recovery -> pending. ---
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
    assert!(
        zk.has_pending(&account_addr),
        "a real fixture proof through initiate_recovery must create a live pending"
    );

    // --- The guard, during the pending window: remove_signer blocked
    // (REAL cross-call into the deployed controller's has_pending), and the
    // recovery rule itself unremovable directly. ---
    let default_rule = account.get_context_rule(&0);
    let orig_signer_id = default_rule
        .signer_ids
        .first()
        .expect("Default rule must have the one signer just installed");

    let res = account.try_remove_signer(&0, &orig_signer_id);
    assert_eq!(
        error_code(&res),
        NidoSmartAccountError::RecoveryPendingBlocked as u32,
        "remove_signer while a REAL pending exists must be blocked by the in-account guard"
    );

    let res = account.try_remove_context_rule(&rule_id);
    assert_eq!(
        error_code(&res),
        NidoSmartAccountError::RecoveryRuleProtected as u32,
        "the recovery rule can never be removed via remove_context_rule directly"
    );

    // --- Advance the ledger past the timelock. ---
    env.ledger().with_mut(|li| {
        li.timestamp = executable_after;
    });

    // --- Completion: REAL host authorization dispatch, no mock_all_auths
    // on this specific call -- __check_auth -> do_check_auth -> a genuine
    // cross-contract call into ZkRecovery::enforce. ---
    let context_type = ContextRuleType::Default;
    let name = String::from_str(&env, "recovered");
    let new_signer = Signer::External(
        webauthn_verifier.clone(),
        Bytes::from_array(&env, &fixture.new_pubkey),
    );
    let new_signers = soroban_sdk::vec![&env, new_signer];
    let empty_policies: Map<Address, Val> = Map::new(&env);

    let args = add_context_rule_args(
        &env,
        &context_type,
        &name,
        None,
        &new_signers,
        &empty_policies,
    );
    let entry = self_call_entry(
        &env,
        &account_addr,
        "add_context_rule",
        &args,
        soroban_sdk::vec![&env, rule_id],
    );

    env.set_auths(&[entry]);
    let res =
        account.try_add_context_rule(&context_type, &name, &None, &new_signers, &empty_policies);
    assert!(
        res.is_ok(),
        "the real fixture proof's completion must authorize via enforce and \
         install the new rule: {res:?}"
    );
    let new_rule = res.unwrap().unwrap();
    assert_eq!(new_rule.signers, new_signers);

    // `events().all()` only returns events from the LAST contract
    // invocation, so this must be captured before any further client calls.
    let expected_event = RecoveryCompleted {
        account: &account_addr,
        nullifier: &nullifier,
    };
    assert_eq!(
        env.events().all().filter_by_contract(&controller_addr),
        [expected_event.to_xdr(&env, &controller_addr)],
        "RecoveryCompleted must be emitted by the controller"
    );

    assert!(
        zk.get_pending(&account_addr).is_none(),
        "the pending recovery must be consumed by a successful completion"
    );
    let state: Option<NullifierState> = env.as_contract(&controller_addr, || {
        env.storage()
            .persistent()
            .get(&RecoveryKey::Nullifier(nullifier.clone()))
    });
    assert_eq!(
        state,
        Some(NullifierState::Spent),
        "the pending's nullifier must be permanently Spent after completion"
    );

    // --- Post-recovery: the guard releases -- remove_signer on a
    // non-recovery rule now succeeds, proving the account is usable again. ---
    env.mock_all_auths();
    account.remove_signer(&0, &orig_signer_id);
    let default_rule_after = account.get_context_rule(&0);
    assert!(
        !default_rule_after.signer_ids.contains(&orig_signer_id),
        "remove_signer must have actually removed the original signer once no \
         pending recovery remained"
    );
}

// ---------------------------------------------------------------------
// Test 2: dummy-leaf enrollment indistinguishability, at the account
// level, via the real factory deploy paths.
// ---------------------------------------------------------------------

/// Local `#[contractclient]` stub for `contracts/factory`'s public entry
/// points. The factory crate is `crate-type = ["cdylib"]` ONLY (no `rlib`),
/// so it cannot be added as a normal Cargo dependency for its Rust types --
/// this crate embeds only the wasm bytes (`FACTORY_WASM`) and talks to it
/// through a locally-declared client, mirroring the exact pattern
/// `contracts/factory/src/contract.rs`'s own `zk_recovery` module doc
/// comment describes for the smart-account wasm.
#[allow(dead_code)]
#[soroban_sdk::contractclient(name = "FactoryClient")]
trait FactoryInterface {
    fn create_account(env: Env, salt: BytesN<32>, key: BytesN<65>) -> Address;
    fn create_account_v2(
        env: Env,
        salt: BytesN<32>,
        key: BytesN<65>,
        commitment: BytesN<32>,
    ) -> Address;
    fn get_c_address(env: Env, salt: BytesN<32>) -> Address;
}

/// The Stellar Registry testnet contract address the factory's `resolve`
/// hardcodes (`contracts/factory/src/contract.rs`'s private `REGISTRY`
/// const, duplicated here since it isn't `pub`).
const REGISTRY: &str = "CDBL7MNO7UI5OAAIC67UIWKQ4P3S6RVQSFCQXUHUW6TOFCXSYRPNHY4S";

/// Name-aware registry stub standing in for the real Stellar Registry at
/// `REGISTRY` -- `"verifier"` resolves to the webauthn verifier, anything
/// else (in practice only `"zk-recovery"`) resolves to the real
/// `ZkRecovery` controller. Mirrors `contracts/factory/src/contract.rs`'s
/// own `test::NamedRegistry`.
mod named_registry {
    use soroban_sdk::{contract, contractimpl, Address, Env, String, Symbol};

    #[contract]
    pub struct NamedRegistry;

    #[contractimpl]
    impl NamedRegistry {
        // The `#[contractimpl]` macro's generated invoke-wrapper requires
        // owned params for XDR decoding; the body only needs to borrow them,
        // which trips `needless_pass_by_value` outside the macro's control.
        #[allow(clippy::needless_pass_by_value)]
        pub fn __constructor(env: &Env, verifier: Address, zk_recovery: Address) {
            env.storage()
                .instance()
                .set(&Symbol::new(env, "verifier"), &verifier);
            env.storage()
                .instance()
                .set(&Symbol::new(env, "zk_recovery"), &zk_recovery);
        }

        // Same macro-generated-wrapper cause as `__constructor` above.
        #[allow(clippy::needless_pass_by_value)]
        pub fn fetch_contract_id(env: &Env, name: String) -> Address {
            if name == String::from_str(env, "verifier") {
                env.storage()
                    .instance()
                    .get::<_, Address>(&Symbol::new(env, "verifier"))
                    .unwrap()
            } else {
                env.storage()
                    .instance()
                    .get::<_, Address>(&Symbol::new(env, "zk_recovery"))
                    .unwrap()
            }
        }
    }
}

/// Deploys a real factory + real `ZkRecovery` pool/controller (registered
/// under `"zk-recovery"`) and the real `WebAuthn` verifier (registered under
/// `"verifier"`), with the pool's `factory` config set to the deployed
/// factory's own address -- exactly `contracts/factory`'s own
/// `setup_factory_and_pool` dev-test helper, reproduced here since that
/// helper lives in the factory crate's `#[cfg(test)]` module and isn't
/// exported. No `mock_all_auths` needed anywhere: every real auth check
/// along the deploy+insert path is satisfied via invoker-contract auth, the
/// same as production.
fn setup_factory_and_pool(env: &Env) -> (Address, Address) {
    let admin = Address::generate(env);
    let factory_addr = env.register(FACTORY_WASM, (admin,));

    let webauthn_verifier = env.register(WEBAUTHN_VERIFIER_WASM, (Address::generate(env),));
    let pool_proof_verifier = Address::generate(env);
    let network_passphrase = Bytes::from_slice(env, b"Test SDF Network ; September 2015");
    let pool_addr = env.register(
        ZkRecovery,
        (
            factory_addr.clone(),
            pool_proof_verifier,
            DELAY_SECS,
            COMPLETION_WINDOW_SECS,
            MAX_CANCELS,
            TIMELOCK_FLOOR_SECS,
            network_passphrase,
            webauthn_verifier.clone(),
            Address::generate(env), // pool upgrade admin (unused by this file's coverage)
        ),
    );

    let registry_addr = Address::from_str(env, REGISTRY);
    env.register_at(
        &registry_addr,
        named_registry::NamedRegistry,
        (webauthn_verifier, pool_addr.clone()),
    );

    // `deploy_v2` needs the embedded smart-account wasm actually installed
    // under the hash the factory computes at runtime -- both this crate's
    // `SMART_ACCOUNT_WASM` and the factory's embedded copy are the exact
    // same build artifact, so their bytes (and hence hash) match.
    env.deployer().upload_contract_wasm(SMART_ACCOUNT_WASM);

    (factory_addr, pool_addr)
}

/// **Test 2.** Deploys one account via `create_account_v2` (a real,
/// caller-supplied commitment) and one via the legacy `create_account`
/// (the factory's own deterministic dummy commitment), and asserts that
/// nothing observable on-chain distinguishes them: both have a recovery
/// rule installed, same shape (zero signers, one policy pointing at the
/// same controller, same `name/valid_until`), and the pool gained exactly one
/// genesis leaf per account. The one real difference -- whether the
/// account's owner actually knows a secret behind their leaf -- never
/// touches the chain; it lives entirely off-chain in whichever party
/// generated the commitment.
#[test]
fn dummy_and_real_enrollment_are_indistinguishable_on_chain() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let (factory_addr, pool_addr) = setup_factory_and_pool(&env);
    let factory = FactoryClient::new(&env, &factory_addr);
    let pool = ZkRecoveryClient::new(&env, &pool_addr);

    let salt_dummy = BytesN::from_array(&env, &[0x31; 32]);
    let key_dummy = BytesN::from_array(&env, &[0x41; 65]);
    let salt_real = BytesN::from_array(&env, &[0x32; 32]);
    let key_real = BytesN::from_array(&env, &[0x42; 65]);
    let real_secret = BytesN::from_array(&env, &[0x77; 32]);
    let real_commitment = leaf_inner(&env, &real_secret);

    assert_eq!(pool.next_index(), 0, "sanity: pool starts empty");

    let dummy_account_addr = factory.create_account(&salt_dummy, &key_dummy);
    assert_eq!(
        pool.next_index(),
        1,
        "create_account (dummy path) must insert exactly one genesis leaf"
    );

    let real_account_addr = factory.create_account_v2(&salt_real, &key_real, &real_commitment);
    assert_eq!(
        pool.next_index(),
        2,
        "create_account_v2 (real path) must insert exactly one more genesis leaf"
    );

    let dummy_account = SmartAccountClient::new(&env, &dummy_account_addr);
    let real_account = SmartAccountClient::new(&env, &real_account_addr);

    // Both accounts deployed to their deterministic factory addresses.
    assert_eq!(dummy_account_addr, factory.get_c_address(&salt_dummy));
    assert_eq!(real_account_addr, factory.get_c_address(&salt_real));

    // Both must have a recovery rule installed, pointing at the same
    // controller.
    let dummy_rule_id = dummy_account
        .recovery_rule_id()
        .expect("create_account (dummy) must still install the recovery rule");
    let real_rule_id = real_account
        .recovery_rule_id()
        .expect("create_account_v2 (real) must install the recovery rule");
    assert_eq!(
        dummy_rule_id, real_rule_id,
        "both paths install the recovery rule at the same rule id (same construction order)"
    );
    assert_eq!(dummy_account.recovery_controller(), Some(pool_addr.clone()));
    assert_eq!(real_account.recovery_controller(), Some(pool_addr.clone()));

    // Same rule SHAPE: zero signers, exactly one policy (the controller),
    // same name/valid_until. The only thing distinguishing the two
    // `ContextRuleType::CallContract(..)` values is each account's own
    // address (unavoidable self-reference), never anything about
    // enrollment status.
    let dummy_rule = dummy_account.get_context_rule(&dummy_rule_id);
    let real_rule = real_account.get_context_rule(&real_rule_id);
    assert_eq!(dummy_rule.name, real_rule.name);
    assert_eq!(dummy_rule.valid_until, real_rule.valid_until);
    assert!(dummy_rule.signers.is_empty());
    assert!(real_rule.signers.is_empty());
    assert_eq!(dummy_rule.policies.len(), 1);
    assert_eq!(real_rule.policies.len(), 1);
    assert_eq!(dummy_rule.policies, real_rule.policies);
    match (&dummy_rule.context_type, &real_rule.context_type) {
        (ContextRuleType::CallContract(d), ContextRuleType::CallContract(r)) => {
            assert_eq!(*d, dummy_account_addr);
            assert_eq!(*r, real_account_addr);
        }
        other => panic!("expected CallContract(self) rules on both accounts, got {other:?}"),
    }

    // Same Default-rule shape too: one signer each, no policies.
    let dummy_default = dummy_account.get_context_rule(&0);
    let real_default = real_account.get_context_rule(&0);
    assert_eq!(dummy_default.signer_ids.len(), 1);
    assert_eq!(real_default.signer_ids.len(), 1);
    assert!(dummy_default.policies.is_empty());
    assert!(real_default.policies.is_empty());

    // Nothing above depended on the 32-byte commitment values themselves --
    // an on-chain observer sees two structurally identical deploys, each
    // with one opaque leaf. Only the off-chain secret-holder can tell them
    // apart.
    assert_ne!(
        real_commitment,
        BytesN::from_array(&env, &[0u8; 32]),
        "sanity: the real commitment is a genuine Poseidon2 output, not a placeholder"
    );
}
