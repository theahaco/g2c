//! Spending-limit policy integration tests. Installs the spending-limit
//! policy on a session-key context rule scoped to a Stellar Asset Contract
//! and verifies real enforcement through `do_check_auth`: within-limit
//! transfers pass, cumulative over-limit transfers are rejected with
//! `SpendingLimitError::SpendingLimitExceeded` (#3221), and the rolling
//! window frees up budget once old entries age out.

use nido_integration_tests::{
    deploy_smart_account, deploy_spending_limit_policy, one_sig, session_signer,
    spending_limit_install_map, SmartAccountClient,
};
use p256::ecdsa::SigningKey;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{symbol_short, vec, Address, Bytes, Env, IntoVal, String};
use stellar_accounts::policies::spending_limit::SpendingLimitError;
use stellar_accounts::smart_account::{do_check_auth, ContextRule, ContextRuleType, Signer};

const XLM: i128 = 10_000_000; // stroops

/// This rule's id: `deploy_smart_account` creates the passkey Default rule at id
/// 0, so the session-key rule installed second lands at id 1.
const SESSION_RULE_ID: u32 = 1;

#[allow(dead_code)]
#[soroban_sdk::contractclient(name = "SpendingLimitPolicyClient")]
trait SpendingLimitPolicyInterface {
    fn set_spending_limit(
        env: soroban_sdk::Env,
        spending_limit: i128,
        context_rule: ContextRule,
        smart_account: Address,
    );
}

/// The auth context the host produces when the smart account authorizes
/// `SAC.transfer(from = smart account, to, amount)` — the spending-limit
/// policy reads `args[2]` as the i128 amount.
fn transfer_context(
    env: &Env,
    sac: &Address,
    from: &Address,
    to: &Address,
    amount: i128,
) -> Context {
    Context::Contract(ContractContext {
        contract: sac.clone(),
        fn_name: symbol_short!("transfer"),
        args: vec![
            env,
            from.into_val(env),
            to.into_val(env),
            amount.into_val(env),
        ],
    })
}

/// Deploy account + SAC + policy, install a session-key rule scoped to
/// `CallContract(sac)` carrying a spending-limit policy install.
///
/// Starts the ledger at sequence 1000 so the rolling window cutoff
/// (`current - period`, saturating) never coincides with the entries'
/// own ledger sequence.
fn setup(
    env: &Env,
    limit: i128,
    period_ledgers: u32,
) -> (
    SmartAccountClient<'_>,
    Address, // smart account
    Address, // SAC
    Address, // spending-limit policy
    SigningKey,
    Signer,
) {
    env.mock_all_auths();
    env.ledger().set_sequence_number(1000);
    let (client, account_addr, verifier_addr, _passkey) = deploy_smart_account(env);
    let admin = Address::generate(env);
    let sac = env.register_stellar_asset_contract_v2(admin).address();
    let policy_addr = deploy_spending_limit_policy(env);
    let (key, signer) = session_signer(env, &verifier_addr, 2);

    client.add_context_rule(
        &ContextRuleType::CallContract(sac.clone()),
        &String::from_str(env, "session"),
        &None,
        &vec![env, signer.clone()],
        &spending_limit_install_map(env, &policy_addr, limit, period_ledgers),
    );
    (client, account_addr, sac, policy_addr, key, signer)
}

/// Assert a caught `do_check_auth` panic is specifically the policy's
/// `SpendingLimitExceeded` error (and not e.g. a scope or signature failure).
/// The host escalates contract errors via `panic!("{:?}", ...)` — the payload
/// is a String carrying `Error(Contract, #3221)`.
fn assert_limit_exceeded(result: std::thread::Result<()>, expectation: &str) {
    let payload = result.expect_err(expectation);
    let msg = payload
        .downcast_ref::<std::string::String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
        .unwrap_or_default();
    let needle = std::format!("#{}", SpendingLimitError::SpendingLimitExceeded as u32);
    assert!(
        msg.contains(&needle),
        "expected SpendingLimitExceeded (Error(Contract, {needle})), got: {msg}"
    );
}

#[test]
fn within_limit_transfer_authorizes() {
    let env = Env::default();
    let (_client, account_addr, sac, _policy, key, signer) = setup(&env, 5 * XLM, 17280);
    let to = Address::generate(&env);

    let hash = env.crypto().sha256(&Bytes::from_array(&env, &[0x51; 32]));
    let signatures = one_sig(&env, &signer, &key, &hash, SESSION_RULE_ID);
    env.as_contract(&account_addr, || {
        do_check_auth(
            &env,
            &hash,
            &signatures,
            &vec![&env, transfer_context(&env, &sac, &account_addr, &to, XLM)],
        )
        .unwrap();
    });
}

#[test]
fn over_limit_rejected() {
    let env = Env::default();
    let (_client, account_addr, sac, _policy, key, signer) = setup(&env, 5 * XLM, 17280);
    let to = Address::generate(&env);

    let hash = env.crypto().sha256(&Bytes::from_array(&env, &[0x52; 32]));
    let signatures = one_sig(&env, &signer, &key, &hash, SESSION_RULE_ID);

    // 4 XLM is within the 5 XLM limit.
    env.as_contract(&account_addr, || {
        do_check_auth(
            &env,
            &hash,
            &signatures,
            &vec![
                &env,
                transfer_context(&env, &sac, &account_addr, &to, 4 * XLM),
            ],
        )
        .unwrap();
    });

    // A further 2 XLM (cumulative 6 > 5) must be rejected.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&account_addr, || {
            do_check_auth(
                &env,
                &hash,
                &signatures,
                &vec![
                    &env,
                    transfer_context(&env, &sac, &account_addr, &to, 2 * XLM),
                ],
            )
            .unwrap();
        });
    }));
    assert_limit_exceeded(result, "cumulative 6 XLM must exceed the 5 XLM limit");
}

#[test]
fn window_roll_allows_again() {
    let env = Env::default();
    // 5 XLM per 100 ledgers.
    let (_client, account_addr, sac, _policy, key, signer) = setup(&env, 5 * XLM, 100);
    let to = Address::generate(&env);

    let hash = env.crypto().sha256(&Bytes::from_array(&env, &[0x53; 32]));
    let signatures = one_sig(&env, &signer, &key, &hash, SESSION_RULE_ID);

    // Exhaust the whole limit at ledger 1000.
    env.as_contract(&account_addr, || {
        do_check_auth(
            &env,
            &hash,
            &signatures,
            &vec![
                &env,
                transfer_context(&env, &sac, &account_addr, &to, 5 * XLM),
            ],
        )
        .unwrap();
    });

    // Roll the window: entries at ledger <= current - period are evicted.
    let current = env.ledger().sequence();
    env.ledger().set_sequence_number(current + 101);

    // The full limit is available again.
    env.as_contract(&account_addr, || {
        do_check_auth(
            &env,
            &hash,
            &signatures,
            &vec![
                &env,
                transfer_context(&env, &sac, &account_addr, &to, 5 * XLM),
            ],
        )
        .unwrap();
    });
}

#[test]
fn raised_limit_mid_window_keeps_spent_total() {
    let env = Env::default();
    let (client, account_addr, sac, policy_addr, key, signer) = setup(&env, 5 * XLM, 17280);
    let to = Address::generate(&env);

    let hash = env.crypto().sha256(&Bytes::from_array(&env, &[0x54; 32]));
    let signatures = one_sig(&env, &signer, &key, &hash, SESSION_RULE_ID);

    // Spend 4 of the 5 XLM limit.
    env.as_contract(&account_addr, || {
        do_check_auth(
            &env,
            &hash,
            &signatures,
            &vec![
                &env,
                transfer_context(&env, &sac, &account_addr, &to, 4 * XLM),
            ],
        )
        .unwrap();
    });

    // Raise the limit to 10 XLM mid-window through the wrapper's entry point.
    // The lib's `smart_account.require_auth()` is satisfied by mock_all_auths.
    let rule = client.get_context_rule(&1);
    SpendingLimitPolicyClient::new(&env, &policy_addr).set_spending_limit(
        &(10 * XLM),
        &rule,
        &account_addr,
    );

    // 7 XLM must still fail: the 4 XLM already spent survives the raise
    // (4 + 7 = 11 > 10). A window reset would wrongly let this through.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&account_addr, || {
            do_check_auth(
                &env,
                &hash,
                &signatures,
                &vec![
                    &env,
                    transfer_context(&env, &sac, &account_addr, &to, 7 * XLM),
                ],
            )
            .unwrap();
        });
    }));
    assert_limit_exceeded(
        result,
        "4 XLM spent before the raise must still count against the 10 XLM limit",
    );

    // 6 XLM succeeds: 4 + 6 = 10 ≤ 10 — the limit is inclusive.
    env.as_contract(&account_addr, || {
        do_check_auth(
            &env,
            &hash,
            &signatures,
            &vec![
                &env,
                transfer_context(&env, &sac, &account_addr, &to, 6 * XLM),
            ],
        )
        .unwrap();
    });
}
