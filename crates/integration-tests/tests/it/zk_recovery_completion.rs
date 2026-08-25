//! M1 Task 7: `ZkRecovery`'s OZ `Policy::enforce` completion -- the M1 HARD
//! REQUIREMENT (spec §3.1).
//!
//! After `initiate_recovery`'s timelock elapses, a permissionless
//! `add_context_rule` call on the recovering account is authorized purely by
//! `ZkRecovery::enforce` (`contracts/zk-recovery/src/policy.rs`) -- OZ's own
//! `get_validated_context_by_id` (`stellar-accounts` `storage.rs:289-301`,
//! confirmed by the M0 spike `zk_completion_spike.rs`) validates ONLY the
//! target `contract` of the zero-signer `CallContract(self)` recovery rule,
//! not `fn_name` or `args`. So the security property is entirely `enforce`'s
//! own job: permit ONLY the exact intended key rotation, reject everything
//! else with `ContextMismatch`.
//!
//! `real_proof_completion_rotates_key_via_enforce` is the keystone honesty
//! check: it drives the REAL host authorization dispatch (`env.set_auths`
//! with a genuine `SorobanAuthorizationEntry`, no `mock_all_auths` on the
//! completing call) through the account's actual `add_context_rule` entry
//! point -> `__check_auth` -> `do_check_auth` -> a real cross-contract call
//! into `ZkRecovery::enforce` -- against a REAL fixture proof's pending
//! recovery. This mirrors `name_registry_passkey_auth.rs`'s "no
//! `mock_all_auths`" pattern, extended to the self-authorizing
//! `add_context_rule` call shape `zk_completion_spike.rs` proved feasible.
//!
//! The three security-negative tests below instead call `do_check_auth`
//! directly (mirroring `zk_completion_spike.rs`/`multisig_recovery.rs`/
//! `default_rule_threshold.rs`'s established pattern in this repo) with a
//! REAL, correctly-shaped `Context` carrying the exact `add_context_rule`
//! argument layout `enforce` decodes -- changing exactly ONE variable from
//! the passing baseline (`fn_name`, the new-signer set, or the ledger time) so
//! a rejection can only be attributed to the gate under test, not some
//! unrelated failure.

use nido_integration_tests::{
    test_key, zk_fixture, SmartAccountClient, SMART_ACCOUNT_WASM, WEBAUTHN_VERIFIER_WASM,
};
use nido_zk_recovery::hash::leaf_inner;
use nido_zk_recovery::pool::{ZkRecovery, ZkRecoveryClient};
use nido_zk_recovery::types::{
    NullifierState, RecoveryCompleted, RecoveryError, RecoveryKey, ZkRecoveryInstallParams,
};
use soroban_sdk::address_payload::AddressPayload;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::testutils::{Events as _, Ledger as _};
use soroban_sdk::xdr::{
    InvokeContractArgs, ScAddress, ScSymbol, ScVal, SorobanAddressCredentials,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, VecM,
};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, Event, IntoVal, Map, String, Symbol, TryFromVal, Val, Vec as SVec,
};
use stellar_accounts::smart_account::{do_check_auth, AuthPayload, ContextRuleType, Signer};

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

struct CompletionSetup<'a> {
    account: SmartAccountClient<'a>,
    account_addr: Address,
    zk: ZkRecoveryClient<'a>,
    controller_addr: Address,
    webauthn_verifier: Address,
    /// The zero-signer `CallContract(self)` rule id the `ZkRecovery` policy
    /// was installed under.
    rule_id: u32,
    fixture: zk_fixture::LifecycleFixture,
}

/// Deploys the `WebAuthn` verifier + smart account (pinned at
/// `zk_fixture::ACCOUNT`), the M0 zk-verifier + `ZkRecovery` controller
/// (pinned at `zk_fixture::CONTROLLER`, `config.webauthn_verifier` set to the
/// SAME verifier the account's signers use), installs the zero-signer
/// `CallContract(self)` recovery rule with `ZkRecovery` as its policy, and
/// inserts the fixture leaf (cross-checking the resulting root against the
/// circuit's independently-computed `fixture.root`). Does NOT call
/// `initiate_recovery` -- callers that need a pending call [`initiate`]
/// afterwards.
fn deploy(env: &Env) -> CompletionSetup<'_> {
    let fixture = zk_fixture::lifecycle_fixture(env);

    // --- WebAuthn verifier + smart account, pinned at ACCOUNT. ---
    let webauthn_verifier = env.register(WEBAUTHN_VERIFIER_WASM, (Address::generate(env),));
    let orig_key = test_key(0xACC0);
    let orig_pubkey = orig_key.verifying_key().to_sec1_bytes();
    let orig_signer = Signer::External(
        webauthn_verifier.clone(),
        Bytes::from_slice(env, &orig_pubkey),
    );
    let signers = soroban_sdk::vec![env, orig_signer];
    let policies: Map<Address, Val> = Map::new(env);
    let account_addr = addr_from(env, &fixture.account);
    // `recovery_controller: None` — this test installs the zero-signer
    // recovery rule itself below (via `add_context_rule`) so it can control
    // exactly when/how the policy is installed; passing `Some` here would
    // double-install a recovery rule.
    env.register_at(
        &account_addr,
        SMART_ACCOUNT_WASM,
        (signers, policies, None::<Address>),
    );
    let account = SmartAccountClient::new(env, &account_addr);

    // --- M0 zk-verifier + ZkRecovery controller, pinned at CONTROLLER. ---
    let vk_bytes = Bytes::from_slice(env, include_bytes!("../../fixtures/zk/vk"));
    let verifier_id = env.register(
        zk_verifier_contract::WASM,
        (Address::generate(env), vk_bytes),
    );
    let controller_addr = addr_from(env, &fixture.controller);
    let factory = Address::generate(env);
    let network_passphrase = Bytes::from_slice(env, fixture.network_passphrase.as_bytes());
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

    // --- Install the zero-signer recovery rule, policy = ZkRecovery. ---
    env.mock_all_auths();
    let mut policy_map: Map<Address, Val> = Map::new(env);
    policy_map.set(
        controller_addr.clone(),
        ZkRecoveryInstallParams { version: 1 }.into_val(env),
    );
    let rule = account.add_context_rule(
        &ContextRuleType::CallContract(account_addr.clone()),
        &String::from_str(env, "zk-recovery"),
        &None,
        &soroban_sdk::vec![env],
        &policy_map,
    );

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

    CompletionSetup {
        account,
        account_addr,
        zk,
        controller_addr,
        webauthn_verifier,
        rule_id: rule.id,
        fixture,
    }
}

/// Runs the REAL fixture proof through `initiate_recovery`, returning
/// `executable_after`.
fn initiate(env: &Env, setup: &CompletionSetup<'_>) -> u64 {
    let new_pubkey = BytesN::from_array(env, &setup.fixture.new_pubkey);
    let root = BytesN::from_array(env, &setup.fixture.root);
    let nullifier = BytesN::from_array(env, &setup.fixture.nullifier);
    let proof = Bytes::from_slice(env, &setup.fixture.proof);
    setup.zk.initiate_recovery(
        &setup.account_addr,
        &new_pubkey,
        &setup.fixture.nonce,
        &setup.fixture.timelock_secs,
        &root,
        &nullifier,
        &proof,
    )
}

/// The `Signer` a completion call must install to match `pending.new_pubkey`
/// -- `Signer::External(config.webauthn_verifier, pending.new_pubkey)`.
fn expected_new_signer(env: &Env, setup: &CompletionSetup<'_>) -> Signer {
    Signer::External(
        setup.webauthn_verifier.clone(),
        Bytes::from_array(env, &setup.fixture.new_pubkey),
    )
}

/// Builds the real `add_context_rule` args in `enforce`'s expected order:
/// `[context_type, name, valid_until, signers, policies]`.
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

/// Builds the `Context::Contract` for an `add_context_rule` self-call with
/// the given real args -- used by the direct-`do_check_auth` security
/// negatives below.
fn add_context_rule_context(env: &Env, account_addr: &Address, args: SVec<Val>) -> Context {
    Context::Contract(ContractContext {
        contract: account_addr.clone(),
        fn_name: Symbol::new(env, "add_context_rule"),
        args,
    })
}

/// Asserts a caught `do_check_auth` panic is specifically the given
/// `RecoveryError` (and not e.g. an unrelated `require_auth`/decode
/// failure) -- mirrors `spending_limit_policy.rs`'s `assert_limit_exceeded`.
/// The host escalates contract errors via `panic!("{:?}", ...)`; the panic
/// payload is a `String` carrying `Error(Contract, #<code>)`.
fn assert_recovery_error_panic(
    result: std::thread::Result<()>,
    expected: RecoveryError,
    expectation: &str,
) {
    let payload = result.expect_err(expectation);
    let msg = payload
        .downcast_ref::<std::string::String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
        .unwrap_or_default();
    let needle = std::format!("#{}", expected as u32);
    assert!(
        msg.contains(&needle),
        "expected {expected:?} (Error(Contract, {needle})), got: {msg}"
    );
}

/// Builds a `SorobanAuthorizationEntry` for a SELF-authorizing call (the
/// account requiring its own auth from within one of its own entry points,
/// e.g. `add_context_rule`/`remove_signer`), carrying a zero-signer
/// `AuthPayload` selecting `context_rule_ids`. No cryptographic signature is
/// needed -- an empty `AuthPayload.signers` map means `do_check_auth`
/// authenticates nothing and defers entirely to the selected rule's
/// policy/`enforce` (spec §3.1, the M0 spike's finding).
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

/// The keystone honesty check for M1 Task 7: a REAL fixture proof initiates
/// recovery, the timelock elapses, and the completing `add_context_rule`
/// call is driven through the REAL host authorization dispatch (no
/// `mock_all_auths` on this call) -- `__check_auth` -> `do_check_auth` -> a
/// genuine cross-contract call into `ZkRecovery::enforce`, which must permit
/// EXACTLY this call (`fn_name` `add_context_rule`, new-signers ==
/// `[Signer::External(webauthn_verifier, fixture.new_pubkey)]`) and consume
/// the pending.
#[test]
fn real_proof_completion_rotates_key_via_enforce() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let setup = deploy(&env);

    let executable_after = initiate(&env, &setup);
    env.ledger().with_mut(|li| {
        li.timestamp = executable_after;
    });
    assert!(setup.zk.get_pending(&setup.account_addr).is_some());

    let context_type = ContextRuleType::Default;
    let name = String::from_str(&env, "recovered");
    let signers = soroban_sdk::vec![&env, expected_new_signer(&env, &setup)];
    let policies: Map<Address, Val> = Map::new(&env);

    let args = add_context_rule_args(&env, &context_type, &name, None, &signers, &policies);
    let entry = self_call_entry(
        &env,
        &setup.account_addr,
        "add_context_rule",
        &args,
        soroban_sdk::vec![&env, setup.rule_id],
    );

    env.set_auths(&[entry]);
    let res = setup
        .account
        .try_add_context_rule(&context_type, &name, &None, &signers, &policies);
    assert!(
        res.is_ok(),
        "the real fixture proof's completion must authorize via enforce and \
         install the new rule: {res:?}"
    );
    let new_rule = res.unwrap().unwrap();
    assert_eq!(new_rule.signers, signers);

    // `events().all()` (soroban-sdk testutils) only returns events from the
    // LAST contract invocation, so this must be captured before any further
    // client calls (e.g. `get_pending` below) become "the last invocation".
    let nullifier = BytesN::from_array(&env, &setup.fixture.nullifier);
    let expected_event = RecoveryCompleted {
        account: &setup.account_addr,
        nullifier: &nullifier,
    };
    assert_eq!(
        env.events()
            .all()
            .filter_by_contract(&setup.controller_addr),
        [expected_event.to_xdr(&env, &setup.controller_addr)],
        "RecoveryCompleted must be emitted by the controller"
    );

    assert!(
        setup.zk.get_pending(&setup.account_addr).is_none(),
        "the pending recovery must be consumed by a successful completion"
    );

    let state: Option<NullifierState> = env.as_contract(&setup.controller_addr, || {
        env.storage()
            .persistent()
            .get(&RecoveryKey::Nullifier(nullifier.clone()))
    });
    assert_eq!(
        state,
        Some(NullifierState::Spent),
        "the pending's nullifier must be permanently Spent after completion"
    );
}

/// **The `fn_name` gate.** Same rule id, same elapsed timelock as the passing
/// baseline above, and -- critically -- an OTHERWISE-FULLY-VALID
/// `add_context_rule`-shaped context: 5 args, `args[3]` is the EXACT expected
/// new-signer set (`[Signer::External(webauthn_verifier, pending.new_pubkey)]`
/// -- the same one the happy path uses), `args[4]` is empty policies. The
/// ONLY thing that differs from the passing baseline is the completing
/// call's `fn_name` (`remove_signer` instead of `add_context_rule`). Because
/// every other check the gate performs (arg count, new-signer set, policies)
/// would ALSO pass here, the only REACHABLE rejection is the `fn_name` check
/// (`policy.rs:163`) -- so this isolates that check specifically, rather
/// than being satisfiable by the arg-count check alone (a 2-arg
/// `remove_signer`-shaped context, as before, would ALSO trip
/// `args.len() != 5` with the same `ContextMismatch` code, so it wouldn't
/// prove the `fn_name` check does anything).
///
/// This still goes through the direct-`do_check_auth` path (not the
/// `try_add_context_rule` real-host path the other two negatives below use)
/// because there is no REAL account entry point named e.g. `remove_signer`
/// that takes this 5-arg `add_context_rule` shape -- constructing that
/// mismatch requires building the `Context` by hand.
#[test]
fn wrong_fn_name_is_rejected_by_enforce() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let setup = deploy(&env);

    let executable_after = initiate(&env, &setup);
    env.ledger().with_mut(|li| {
        li.timestamp = executable_after;
    });

    let context_type = ContextRuleType::Default;
    let name = String::from_str(&env, "recovered");
    let signers = soroban_sdk::vec![&env, expected_new_signer(&env, &setup)];
    let policies: Map<Address, Val> = Map::new(&env);
    let args = add_context_rule_args(&env, &context_type, &name, None, &signers, &policies);
    assert_eq!(args.len(), 5, "sanity: must carry the real 5-arg arity");
    let context = Context::Contract(ContractContext {
        contract: setup.account_addr.clone(),
        fn_name: Symbol::new(&env, "remove_signer"),
        args,
    });
    let hash = env.crypto().sha256(&Bytes::from_array(&env, &[0xF2; 32]));
    let payload = AuthPayload {
        signers: Map::new(&env),
        context_rule_ids: soroban_sdk::vec![&env, setup.rule_id],
    };

    env.mock_all_auths();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&setup.account_addr, || {
            do_check_auth(&env, &hash, &payload, &soroban_sdk::vec![&env, context]).unwrap();
        });
    }));
    assert_recovery_error_panic(
        result,
        RecoveryError::ContextMismatch,
        "enforce must reject an otherwise-fully-valid completion whose fn_name is \
         remove_signer instead of add_context_rule (fn_name gate) with ContextMismatch",
    );

    // The rejected attempt must not have consumed anything.
    assert!(setup.zk.get_pending(&setup.account_addr).is_some());
    let nullifier = BytesN::from_array(&env, &setup.fixture.nullifier);
    let state: Option<NullifierState> = env.as_contract(&setup.controller_addr, || {
        env.storage()
            .persistent()
            .get(&RecoveryKey::Nullifier(nullifier))
    });
    assert_ne!(state, Some(NullifierState::Spent));
}

/// **The args gate.** Same rule id, same elapsed timelock, same
/// `add_context_rule` `fn_name` as the passing baseline -- the ONLY thing that
/// differs is the new-signer set: a DIFFERENT (attacker-chosen) key instead
/// of `pending.new_pubkey`. `enforce` must reject with `ContextMismatch`,
/// proving it does not just check `fn_name` but the ACTUAL proposed new
/// signer against the proven pending.
///
/// This stays on the direct-`do_check_auth` path rather than the keystone
/// test's real-host `try_add_context_rule` dispatch: empirically, Soroban's
/// host sanitizes errors raised DURING authorization resolution (i.e. inside
/// `__check_auth`/`enforce`, as opposed to the invoked function's own body)
/// down to a generic `Error(Context, InvalidAction)` before they reach the
/// top-level `try_` caller -- losing the specific `RecoveryError` code. The
/// direct `do_check_auth` call (still real `enforce` logic, just invoked
/// without going through the outer auth-sanitizing layer) preserves the
/// original `Error(Contract, #<code>)` in the panic payload, which is what
/// lets this assert the SPECIFIC code below instead of a bare `is_err()`.
#[test]
fn wrong_new_signer_is_rejected_by_enforce() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let setup = deploy(&env);

    let executable_after = initiate(&env, &setup);
    env.ledger().with_mut(|li| {
        li.timestamp = executable_after;
    });

    let attacker_key = test_key(0xBAD);
    let attacker_pubkey = attacker_key.verifying_key().to_sec1_bytes();
    let attacker_signer = Signer::External(
        setup.webauthn_verifier.clone(),
        Bytes::from_slice(&env, &attacker_pubkey),
    );
    assert_ne!(
        attacker_signer,
        expected_new_signer(&env, &setup),
        "sanity: the attacker's key must differ from the fixture's proven new_pubkey"
    );

    let context_type = ContextRuleType::Default;
    let name = String::from_str(&env, "recovered");
    let signers = soroban_sdk::vec![&env, attacker_signer];
    let policies: Map<Address, Val> = Map::new(&env);
    let args = add_context_rule_args(&env, &context_type, &name, None, &signers, &policies);
    let context = add_context_rule_context(&env, &setup.account_addr, args);

    let hash = env.crypto().sha256(&Bytes::from_array(&env, &[0xF3; 32]));
    let payload = AuthPayload {
        signers: Map::new(&env),
        context_rule_ids: soroban_sdk::vec![&env, setup.rule_id],
    };

    env.mock_all_auths();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&setup.account_addr, || {
            do_check_auth(&env, &hash, &payload, &soroban_sdk::vec![&env, context]).unwrap();
        });
    }));
    assert_recovery_error_panic(
        result,
        RecoveryError::ContextMismatch,
        "enforce must reject an add_context_rule call installing a DIFFERENT \
         new-signer set than the pending's proven new_pubkey (args gate) with \
         ContextMismatch",
    );

    assert!(setup.zk.get_pending(&setup.account_addr).is_some());
}

/// **The timelock.** Correct rule id, correct `add_context_rule` `fn_name`,
/// correct new-signer set -- the ONLY thing that differs from the passing
/// baseline is timing: this attempts completion immediately after
/// `initiate_recovery`, before `executable_after`. `enforce` must reject
/// with `TimelockNotElapsed`.
///
/// This stays on the direct-`do_check_auth` path for the same reason
/// `wrong_new_signer_is_rejected_by_enforce` does: the host sanitizes errors
/// raised during authorization resolution to a generic
/// `Error(Context, InvalidAction)` before they reach a top-level `try_`
/// caller, so only the direct `do_check_auth` panic payload preserves the
/// specific `Error(Contract, #<code>)` this test needs to assert against.
#[test]
fn completion_before_timelock_is_rejected() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let setup = deploy(&env);

    let executable_after = initiate(&env, &setup);
    let now = env.ledger().timestamp();
    assert!(
        now < executable_after,
        "sanity: the ledger must not yet have reached executable_after"
    );

    let context_type = ContextRuleType::Default;
    let name = String::from_str(&env, "recovered");
    let signers = soroban_sdk::vec![&env, expected_new_signer(&env, &setup)];
    let policies: Map<Address, Val> = Map::new(&env);
    let args = add_context_rule_args(&env, &context_type, &name, None, &signers, &policies);
    let context = add_context_rule_context(&env, &setup.account_addr, args);

    let hash = env.crypto().sha256(&Bytes::from_array(&env, &[0xF4; 32]));
    let payload = AuthPayload {
        signers: Map::new(&env),
        context_rule_ids: soroban_sdk::vec![&env, setup.rule_id],
    };

    env.mock_all_auths();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&setup.account_addr, || {
            do_check_auth(&env, &hash, &payload, &soroban_sdk::vec![&env, context]).unwrap();
        });
    }));
    assert_recovery_error_panic(
        result,
        RecoveryError::TimelockNotElapsed,
        "enforce must reject completion before executable_after (timelock) with \
         TimelockNotElapsed",
    );

    assert!(setup.zk.get_pending(&setup.account_addr).is_some());
}

/// **Invariant T1 (storage / liveness).** The `Pending` + `Nullifier` +
/// `Nonce` + `RateWindow` entries that `initiate_recovery` writes must remain
/// live across the FULL active window (14d timelock + 30d completion = 44d) so
/// a legitimate recovery can still complete at the last moment. Every recovery
/// write extends the entry's TTL to the network max (`extend_ttl(max, max)` in
/// `controller.rs`/`merkle.rs`/`policy.rs`), and 44 days of ledgers is far below
/// that max, so nothing archives mid-window.
///
/// SCOPE / HONESTY NOTE: the soroban-sdk test env does **not** model archival
/// eviction — a persistent entry stays readable even past its `live_until`
/// (verified). So this test validates the survival PREMISE two ways: (1) it
/// asserts the active window in ledgers sits far under the env's real `max_ttl`
/// (the headroom the extend-to-max writes rely on), and (2) it advances BOTH the
/// ledger timestamp AND sequence across the full window and drives a real
/// completion — proving the state is accessible and the lifecycle works after
/// realistic ledger progression (every other test only advances the timestamp).
/// Fail-closed archival ITSELF is a Soroban PROTOCOL guarantee — an archived
/// persistent entry is inaccessible (a read errors and reverts the tx), never
/// silently readable as `None` — not nido logic, and not modelled by the
/// harness; keeping the window far under `max_ttl` is what ensures it never
/// triggers in the first place.
#[test]
#[allow(clippy::too_many_lines)]
fn recovery_state_survives_full_active_window() {
    // Soroban targets ~5s/ledger; used to convert the active window (seconds)
    // into ledgers for the max_ttl headroom check below.
    const SECS_PER_LEDGER: u64 = 5;
    // Mainnet's `max_entry_ttl` network setting is SMALLER than the test-env
    // `max_ttl` (~6.31M); pin a lower bound of the mainnet value (~3.11M ledgers
    // at time of writing) so this premise is also checked against the number that
    // actually governs archival on mainnet, not just the in-env constant. Confirm
    // the live `max_entry_ttl` >= the active window at cutover (see T1 in
    // MAINNET_READINESS.md).
    const MAINNET_MAX_ENTRY_TTL_LEDGERS: u64 = 3_110_400;

    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let setup = deploy(&env);
    // This test drives time by `window_ledgers` below, not the timelock, so the
    // returned executable-after timestamp is unused here.
    let _ = initiate(&env, &setup);

    // Headroom premise: 44 days of ledgers must sit far under the network max
    // TTL, so the extend-to-max on every write means none of these entries can
    // archive mid-window.
    let window_ledgers = (DELAY_SECS + COMPLETION_WINDOW_SECS) / SECS_PER_LEDGER;
    let (max_ttl, seq0) = env.as_contract(&setup.controller_addr, || {
        (
            u64::from(env.storage().max_ttl()),
            u64::from(env.ledger().sequence()),
        )
    });
    assert!(
        window_ledgers < max_ttl,
        "active window ({window_ledgers} ledgers) must fit under max_ttl ({max_ttl}) \
         with headroom, else recovery state could archive mid-window"
    );
    // The assertion above uses the test-env `max_ttl`; also check the (smaller,
    // pinned) mainnet `max_entry_ttl` lower bound, which is what actually governs
    // archival in production -- this test would otherwise stay green even if the
    // window approached the real mainnet TTL.
    assert!(
        window_ledgers < MAINNET_MAX_ENTRY_TTL_LEDGERS,
        "active window ({window_ledgers} ledgers) must fit under mainnet max_entry_ttl \
         ({MAINNET_MAX_ENTRY_TTL_LEDGERS}), else recovery state could archive mid-window on mainnet"
    );

    // Helpers reading the four persistent entries initiate wrote.
    let nullifier = BytesN::from_array(&env, &setup.fixture.nullifier);
    let read_nullifier = || {
        env.as_contract(&setup.controller_addr, || {
            env.storage()
                .persistent()
                .get::<_, NullifierState>(&RecoveryKey::Nullifier(nullifier.clone()))
        })
    };
    let has_nonce = || {
        env.as_contract(&setup.controller_addr, || {
            env.storage()
                .persistent()
                .has(&RecoveryKey::Nonce(setup.account_addr.clone()))
        })
    };
    let has_rate_window = || {
        env.as_contract(&setup.controller_addr, || {
            env.storage()
                .persistent()
                .has(&RecoveryKey::RateWindow(setup.account_addr.clone()))
        })
    };

    // All four entries are live immediately after initiate.
    let pending = setup
        .zk
        .get_pending(&setup.account_addr)
        .expect("pending exists right after initiate");
    assert_eq!(
        read_nullifier(),
        Some(NullifierState::Reserved(setup.account_addr.clone()))
    );
    assert!(has_nonce(), "nonce written by initiate");
    assert!(has_rate_window(), "rate-window written by initiate");

    // Jump to the LAST moment of the completion window: timestamp just before
    // the pending expires, AND advance the ledger sequence by the full ~44-day
    // ledger count (kept under the auth entry's 999_999 expiration ledger).
    let complete_at = pending.expires_at - 100;
    env.ledger().with_mut(|li| {
        li.timestamp = complete_at;
        li.sequence_number = u32::try_from(seq0 + window_ledgers).unwrap();
    });

    // The entries are still readable at the end of the window.
    assert!(
        setup.zk.get_pending(&setup.account_addr).is_some(),
        "pending must survive the full 44-day active window"
    );
    assert_eq!(
        read_nullifier(),
        Some(NullifierState::Reserved(setup.account_addr.clone())),
        "the reserved nullifier must survive the full active window"
    );
    assert!(
        has_nonce() && has_rate_window(),
        "nonce + rate-window must survive the full active window"
    );

    // A real completion still succeeds at the last moment (drives enforce, same
    // shape as `real_proof_completion_rotates_key_via_enforce`).
    let context_type = ContextRuleType::Default;
    let name = String::from_str(&env, "recovered");
    let signers = soroban_sdk::vec![&env, expected_new_signer(&env, &setup)];
    let policies: Map<Address, Val> = Map::new(&env);
    let args = add_context_rule_args(&env, &context_type, &name, None, &signers, &policies);
    let entry = self_call_entry(
        &env,
        &setup.account_addr,
        "add_context_rule",
        &args,
        soroban_sdk::vec![&env, setup.rule_id],
    );
    env.set_auths(&[entry]);
    let res = setup
        .account
        .try_add_context_rule(&context_type, &name, &None, &signers, &policies);
    assert!(
        res.is_ok(),
        "completion at the end of the survived window must succeed: {res:?}"
    );

    // Post-completion: pending consumed, nullifier permanently Spent.
    assert!(
        setup.zk.get_pending(&setup.account_addr).is_none(),
        "a successful completion consumes the pending"
    );
    assert_eq!(
        read_nullifier(),
        Some(NullifierState::Spent),
        "the nullifier must be permanently Spent after completion"
    );
}
