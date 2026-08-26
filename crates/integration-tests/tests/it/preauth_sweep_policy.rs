//! Preauthorized-sweep policy scoping proof — the deliverable.
//!
//! Each test drives OZ's real `do_check_auth` against a production smart account
//! C (deployed from `SMART_ACCOUNT_WASM`) that has ONE sweep rule installed:
//!   - context type: `CallContract(sac)`  (pins to a single token contract)
//!   - signers:      `[]`  (NONE — the sweep is intentionally permissionless)
//!   - policies:     `[PreauthSweepPolicy { source: G }]`
//!
//! `deploy_smart_account` already creates the passkey Default rule at id 0, so
//! the sweep rule installed second lands at id 1 (see [`SWEEP_RULE_ID`]).
//!
//! ## The headline: permissionless authorization on the real path
//!
//! The sweep rule has NO signers. Every authorization below submits an **empty**
//! `AuthPayload` (zero signatures) selecting the sweep rule, and drives the real
//! `do_check_auth`. Because the rule carries no signers and one policy, OZ's
//! `do_check_auth` authenticates nothing and hands straight to the policy's
//! `enforce`, which authorizes the call purely on the `G -> C` bound. There is
//! no signer to sign, forge, or scope — the security argument is the bound.
//!
//! `mock_all_auths` is used ONLY for setup ops (`add_context_rule`). It plays no
//! part in the sweep authorization: with no signers and no
//! `smart_account.require_auth()` in `enforce`, there is nothing on the sweep
//! path for it to satisfy. [`permissionless_no_signature_authorizes`] is the
//! proof that zero signatures resolve on the real `do_check_auth`.
//!
//! Cases: P (allowed sweep + arbitrary non-negative amounts, all zero-signature),
//! N1 (wrong dest), N2 (wrong source), N (wrong spender), N3a (other function /
//! approve on the same token), N3b (other contract entirely — rejected upstream
//! at the rule scope), plus an auxiliary value-movement check that the SAC
//! `transfer_from` actually moves funds G -> C.

use nido_integration_tests::{deploy_smart_account, PREAUTH_SWEEP_POLICY_WASM};
use nido_preauth_sweep_policy::{PreauthSweepParams, SweepError};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{
    symbol_short, token, vec, Address, Bytes, Env, IntoVal, Map, String, Symbol, Val,
};
use stellar_accounts::smart_account::{do_check_auth, AuthPayload, ContextRuleType};

/// The passkey Default rule is id 0; the sweep rule is installed second, so it
/// lands at id 1.
const SWEEP_RULE_ID: u32 = 1;

/// Deploy the preauthorized-sweep policy contract from its wasm and return its
/// address.
fn deploy_preauth_sweep_policy(env: &Env) -> Address {
    env.register(PREAUTH_SWEEP_POLICY_WASM, ())
}

/// Build the `policies` map for `add_context_rule` with a single
/// preauth-sweep-policy install recording `source_g` as the account this rule
/// may sweep FROM.
fn preauth_sweep_install_map(
    env: &Env,
    policy_addr: &Address,
    source_g: &Address,
) -> Map<Address, Val> {
    let params = PreauthSweepParams {
        source: source_g.clone(),
    };
    let mut m: Map<Address, Val> = Map::new(env);
    m.set(policy_addr.clone(), params.into_val(env));
    m
}

/// The world: the production smart-account address C, the SAC token address the
/// rule is pinned to, the recorded onboarding source G, and an unrelated
/// attacker. There is deliberately NO signer or key — the sweep rule is
/// permissionless.
struct World {
    env: Env,
    account: Address, // C
    sac: Address,     // the token this rule is pinned to
    source_g: Address,
    attacker: Address,
}

/// Deploy account + policy and install the sweep rule scoped to
/// `CallContract(sac)` with an **empty signer set** (permissionless).
fn setup() -> World {
    let env = Env::default();
    env.mock_all_auths();

    let (client, account, _verifier, _passkey) = deploy_smart_account(&env);
    let sac = env
        .register_stellar_asset_contract_v2(Address::generate(&env))
        .address();
    let source_g = Address::generate(&env);
    let attacker = Address::generate(&env);

    let policy_addr = deploy_preauth_sweep_policy(&env);

    // Install the sweep rule with NO signers and one policy. `add_context_rule`
    // accepts an empty signer set as long as at least one policy is present
    // (OZ's `validate_signers_and_policies` only rejects when signers AND
    // policies are both empty).
    client.add_context_rule(
        &ContextRuleType::CallContract(sac.clone()),
        &String::from_str(&env, "onboarding-sweep"),
        &None,
        &vec![&env], // permissionless: zero signers
        &preauth_sweep_install_map(&env, &policy_addr, &source_g),
    );

    World {
        env,
        account,
        sac,
        source_g,
        attacker,
    }
}

/// Build the auth context the host produces for
/// `SAC.transfer_from(spender, from, to, amount)`.
fn transfer_from_ctx(
    env: &Env,
    sac: &Address,
    spender: &Address,
    from: &Address,
    to: &Address,
    amount: i128,
) -> Context {
    Context::Contract(ContractContext {
        contract: sac.clone(),
        fn_name: Symbol::new(env, "transfer_from"),
        args: vec![
            env,
            spender.into_val(env),
            from.into_val(env),
            to.into_val(env),
            amount.into_val(env),
        ],
    })
}

/// Build the auth context for a plain `SAC.transfer(from, to, amount)`.
fn transfer_ctx(env: &Env, sac: &Address, from: &Address, to: &Address, amount: i128) -> Context {
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

/// The fixed signature payload every authorization is checked against. Any
/// 32-byte hash works — with no signers there is nothing to sign, but
/// `do_check_auth` still binds it to the selected rule id.
fn sig_payload(env: &Env) -> soroban_sdk::crypto::Hash<32> {
    env.crypto().sha256(&Bytes::from_array(env, &[0x7A_u8; 32]))
}

/// Build an **empty** `AuthPayload` — zero signers — selecting the sweep rule.
/// This is the permissionless payload: no signatures, just the rule id.
fn empty_auth(env: &Env) -> AuthPayload {
    AuthPayload {
        signers: Map::new(env),
        context_rule_ids: vec![env, SWEEP_RULE_ID],
    }
}

/// Run `do_check_auth` for a single context under the account frame carrying an
/// EMPTY (zero-signature) `AuthPayload`, capturing any panic so negative cases
/// can assert the specific rejection code.
fn run(world: &World, ctx: Context) -> std::thread::Result<()> {
    let env = &world.env;
    let hash = sig_payload(env);
    let auth = empty_auth(env);
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&world.account, || {
            do_check_auth(env, &hash, &auth, &vec![env, ctx]).unwrap();
        });
    }))
}

/// Run `do_check_auth` for TWO contexts bundled under one EMPTY `AuthPayload`.
/// `do_check_auth` must authorize EVERY context, so if either fails the whole
/// authorization fails — this is the composite attack shape a permissionless
/// rule most invites.
fn run_two(world: &World, a: Context, b: Context) -> std::thread::Result<()> {
    let env = &world.env;
    let hash = sig_payload(env);
    // One rule id per context: both contexts are authorized under the sweep rule.
    let auth = AuthPayload {
        signers: Map::new(env),
        context_rule_ids: vec![env, SWEEP_RULE_ID, SWEEP_RULE_ID],
    };
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&world.account, || {
            do_check_auth(env, &hash, &auth, &vec![env, a, b]).unwrap();
        });
    }))
}

/// Extract the panic payload as a `String` (contract errors surface as
/// `Error(Contract, #N)` strings).
fn panic_message(payload: &(dyn std::any::Any + Send)) -> std::string::String {
    payload
        .downcast_ref::<std::string::String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
        .unwrap_or_default()
}

/// Assert a caught panic carries a specific `SweepError` (`Error(Contract, #N)`).
fn assert_sweep_error(result: std::thread::Result<()>, err: SweepError, what: &str) {
    let msg = panic_message(result.expect_err(what).as_ref());
    let needle = std::format!("#{}", err as u32);
    assert!(
        msg.contains(&needle),
        "expected {err:?} (Error(Contract, {needle})) for [{what}], got: {msg}"
    );
}

/// The sweep-policy scope codes. A correctly-scoped call that is rejected must
/// NOT carry any of these — its rejection came from somewhere else (the rule's
/// `CallContract` scope, upstream of the policy).
const SWEEP_SCOPE_CODES: [SweepError; 4] = [
    SweepError::WrongSpender,
    SweepError::WrongSource,
    SweepError::WrongDestination,
    SweepError::NotTransferFrom,
];

/// Assert a caught panic is the smart account's own upstream rejection (the
/// rule's `CallContract` scope refusing a foreign contract) — i.e. the
/// rejection happened UPSTREAM of the policy. Verifies it is a Contract error
/// and NOT any sweep-policy code, proving `enforce` was never reached.
fn assert_unvalidated_context(result: std::thread::Result<()>, what: &str) {
    let msg = panic_message(result.expect_err(what).as_ref());
    assert!(
        msg.contains("Error(Contract"),
        "expected a contract error for [{what}], got: {msg}"
    );
    for code in SWEEP_SCOPE_CODES {
        let sweep_needle = std::format!("#{}", code as u32);
        assert!(
            !msg.contains(&sweep_needle),
            "[{what}] should reject at the rule scope, before the policy, but got sweep code {sweep_needle}: {msg}"
        );
    }
}

// ---------------------------------------------------------------------------
// P (headline) — permissionless: an EMPTY signer set authorizes
// transfer_from(C, G, C, amount) on the real do_check_auth path. This is the
// whole point: zero signatures resolve because the bound is the security
// argument.
// ---------------------------------------------------------------------------
#[test]
fn permissionless_no_signature_authorizes() {
    let w = setup();
    let ctx = transfer_from_ctx(&w.env, &w.sac, &w.account, &w.source_g, &w.account, 42);
    run(&w, ctx).expect(
        "permissionless sweep transfer_from(C, G, C, amount) must authorize with NO signature",
    );
}

// Amount is caller-chosen; any non-negative amount is allowed (the bound is on
// spender/source/dest/function, not magnitude) — still with an empty signer set.
#[test]
fn p_sweep_allows_arbitrary_nonnegative_amount() {
    let w = setup();
    for amt in [0_i128, 1, 1_000_000, i128::MAX] {
        let ctx = transfer_from_ctx(&w.env, &w.sac, &w.account, &w.source_g, &w.account, amt);
        run(&w, ctx).unwrap_or_else(|_| panic!("amount {amt} should be allowed"));
    }
}

// ---------------------------------------------------------------------------
// N1 — wrong destination: transfer_from(C, G, ATTACKER, amount) -> rejected.
// (Correct spender + source, so genuinely the `to` check.)
// ---------------------------------------------------------------------------
#[test]
fn n1_wrong_destination_rejected() {
    let w = setup();
    let ctx = transfer_from_ctx(&w.env, &w.sac, &w.account, &w.source_g, &w.attacker, 42);
    assert_sweep_error(run(&w, ctx), SweepError::WrongDestination, "N1 wrong dest");
}

// ---------------------------------------------------------------------------
// N2 — wrong source: transfer_from(C, OTHER, C, amount) -> rejected.
// (Correct spender + dest, so genuinely the `from` check.)
// ---------------------------------------------------------------------------
#[test]
fn n2_wrong_source_rejected() {
    let w = setup();
    let other = Address::generate(&w.env);
    let ctx = transfer_from_ctx(&w.env, &w.sac, &w.account, &other, &w.account, 42);
    assert_sweep_error(run(&w, ctx), SweepError::WrongSource, "N2 wrong source");
}

// ---------------------------------------------------------------------------
// N (hardening) — wrong spender: transfer_from(ATTACKER, G, C, amount) with a
// perfect from/to but args[0] != C -> rejected by the defense-in-depth spender
// check. Proves the rule can never front C's authority for a pull initiated by
// anyone but C (relevant for a nonstandard token pinned at install).
// ---------------------------------------------------------------------------
#[test]
fn n_wrong_spender_rejected() {
    let w = setup();
    let ctx = transfer_from_ctx(&w.env, &w.sac, &w.attacker, &w.source_g, &w.account, 42);
    assert_sweep_error(run(&w, ctx), SweepError::WrongSpender, "N wrong spender");
}

// ---------------------------------------------------------------------------
// N3a — other function / self-spend: a plain transfer(C, ATTACKER, amount) on
// the SAME token -> rejected by the policy (fn_name != transfer_from). Proves
// the permissionless rule cannot be used to spend C's own funds.
// ---------------------------------------------------------------------------
#[test]
fn n3a_other_function_same_token_rejected() {
    let w = setup();
    let ctx = transfer_ctx(&w.env, &w.sac, &w.account, &w.attacker, 42);
    assert_sweep_error(
        run(&w, ctx),
        SweepError::NotTransferFrom,
        "N3a self-spend via transfer",
    );
}

// approve(C, ATTACKER, ...) — hand an allowance to an attacker — also rejected.
#[test]
fn n3a_approve_rejected() {
    let w = setup();
    let ctx = Context::Contract(ContractContext {
        contract: w.sac.clone(),
        fn_name: symbol_short!("approve"),
        args: vec![
            &w.env,
            w.account.into_val(&w.env),
            w.attacker.into_val(&w.env),
            1_000_000_i128.into_val(&w.env),
            1000_u32.into_val(&w.env),
        ],
    });
    assert_sweep_error(run(&w, ctx), SweepError::NotTransferFrom, "N3a approve");
}

// ---------------------------------------------------------------------------
// N3b — other contract entirely: a transfer_from on a DIFFERENT token contract
// -> rejected UPSTREAM by the rule's CallContract(sac) scope, before the policy
// is ever consulted.
// ---------------------------------------------------------------------------
#[test]
fn n3b_other_contract_rejected_at_scope() {
    let w = setup();
    let other_token = Address::generate(&w.env);
    // Even a perfectly-shaped transfer_from(C, G, C) but on the WRONG contract.
    let ctx = transfer_from_ctx(
        &w.env,
        &other_token,
        &w.account,
        &w.source_g,
        &w.account,
        42,
    );
    assert_unvalidated_context(run(&w, ctx), "N3b foreign contract");
}

// ---------------------------------------------------------------------------
// Composite atomicity — the attack a permissionless rule most invites. Bundle a
// well-formed sweep with a SECOND, diverting context transfer_from(C, G,
// ATTACKER) under ONE empty AuthPayload. do_check_auth authorizes every context,
// so the diverting one panics WrongDestination and the WHOLE authorization
// fails: a caller cannot smuggle a diversion alongside a valid sweep.
// ---------------------------------------------------------------------------
#[test]
fn composite_bundled_bad_context_fails() {
    let w = setup();
    let good = transfer_from_ctx(&w.env, &w.sac, &w.account, &w.source_g, &w.account, 42);
    let bad = transfer_from_ctx(&w.env, &w.sac, &w.account, &w.source_g, &w.attacker, 42);
    assert_sweep_error(
        run_two(&w, good, bad),
        SweepError::WrongDestination,
        "composite: a bundled diverting context must fail the whole auth",
    );
}

// ---------------------------------------------------------------------------
// Self-exfiltration — the tempting case: transfer_from(C, C, ATTACKER) tries to
// move C's OWN funds out. from == C != recorded G, so it rejects at WrongSource;
// the permissionless rule can never pull anything but G's balance.
// ---------------------------------------------------------------------------
#[test]
fn n_self_source_rejected() {
    let w = setup();
    let ctx = transfer_from_ctx(&w.env, &w.sac, &w.account, &w.account, &w.attacker, 42);
    assert_sweep_error(
        run(&w, ctx),
        SweepError::WrongSource,
        "N self-source (C's own funds)",
    );
}

// ---------------------------------------------------------------------------
// Auxiliary value-mechanics check for case P (NOT the scoping proof).
//
// Confirms a real SAC transfer_from(spender = C, from = G, to = C, amount)
// genuinely moves funds G -> C once C holds an allowance from G. Runs under
// mock_all_auths (bypassing do_check_auth) to prove the value movement + the
// spender/from/to argument semantics the policy is built on.
// ---------------------------------------------------------------------------
#[test]
fn p_real_sac_transfer_from_moves_g_to_c() {
    let env = Env::default();
    env.mock_all_auths();

    let sac = env.register_stellar_asset_contract_v2(Address::generate(&env));
    let token = token::TokenClient::new(&env, &sac.address());
    let mint = token::StellarAssetClient::new(&env, &sac.address());

    let c = Address::generate(&env); // the smart account C (spender + dest)
    let g = Address::generate(&env); // the onboarding source G

    // Fund G with 1000 units.
    mint.mint(&g, &1000);
    assert_eq!(token.balance(&g), 1000);
    assert_eq!(token.balance(&c), 0);

    // G grants C an allowance (the "neutralized-G approves C" onboarding step).
    token.approve(&g, &c, &1000, &10_000);
    assert_eq!(token.allowance(&g, &c), 1000);

    // The sweep: C pulls G's full balance into itself.
    token.transfer_from(&c, &g, &c, &1000);

    assert_eq!(token.balance(&g), 0, "G fully swept");
    assert_eq!(token.balance(&c), 1000, "C received the funds");
    assert_eq!(token.allowance(&g, &c), 0, "allowance consumed");
}
