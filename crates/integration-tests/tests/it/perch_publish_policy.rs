//! Perch publish-method policy — a real, runnable end-to-end demonstration.
//!
//! The motivating perch use case (README): a CI key held in GitHub that can
//! publish Wasm releases to the Stellar Registry as a smart account — and do
//! nothing else. This test builds that account and exercises it with real
//! P-256 signatures through OpenZeppelin's real `do_check_auth`.
//!
//! What is REAL here:
//!   - the smart account (`nido_smart_account.wasm`) and OZ `do_check_auth`;
//!   - the CI signer's signatures (verified on-chain by the passkey verifier);
//!   - the constructorless-immutable deploy (perch decision D3): the deployed
//!     address is a pure function of (registry address, wasm hash) and is
//!     resolvable offline — no name is stored.
//!
//! What stands in for not-yet-built perch components:
//!   - `FnScopePolicy` is a hand-written preview of `perch-interpreter`. It
//!     hardcodes what the interpreter will evaluate as an RPN program: a signer
//!     floor (INV-1 defense-in-depth), a function allowlist, and an `is-self`
//!     argument check. The compiler (`perch-compile`) will emit the OZ context
//!     rule + this policy's install params from the `ci-publish` PolicyDoc.
//!   - the CI key is modeled with the passkey verifier the harness provides;
//!     the perch doc uses `ED25519_VERIFIER`. The policy is verifier-agnostic.
//!
//! The policy `ci-publish` mirrors the README document:
//!   r.callContract(REGISTRY).signedBy('ci').func('publish','publish_hash')
//!    .arg(author, isSelf())

use nido_integration_tests::{
    build_contract_assertion, compute_auth_digest, deploy_smart_account, test_key,
    WEBAUTHN_VERIFIER_WASM,
};
use p256::ecdsa::SigningKey;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    contract, contractimpl, contracttype, vec, Address, Bytes, BytesN, Env, IntoVal, Map, String,
    Symbol, TryFromVal, Val, Vec,
};
use stellar_accounts::policies::Policy;
use stellar_accounts::smart_account::{
    do_check_auth, AuthPayload, ContextRule, ContextRuleType, Signer,
};
use stellar_accounts::verifiers::webauthn::WebAuthnSigData;

// ---------------------------------------------------------------------------
// FnScopePolicy — a minimal, faithful preview of `perch-interpreter`.
// ---------------------------------------------------------------------------

/// Install parameters: the function allowlist and, optionally, the argument
/// index that must equal the smart account (`is-self`). `perch-interpreter`
/// stores an RPN program here instead; the enforced semantics are the same.
#[contracttype]
#[derive(Clone)]
pub struct FnScopeParams {
    pub funcs: Vec<Symbol>,
    pub self_arg: Option<u32>,
}

#[contracttype]
pub enum FnScopeKey {
    Params(Address, u32),
}

#[contract]
pub struct FnScopePolicy;

#[contractimpl]
impl Policy for FnScopePolicy {
    type AccountParams = FnScopeParams;

    fn enforce(
        e: &Env,
        context: Context,
        authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        // Multi-tenant safety: one shared policy contract keyed by
        // (account, rule) requires the account to authorize the call.
        smart_account.require_auth();

        // INV-1 defense-in-depth: OZ defers signer sufficiency to policies once
        // any policy is attached, so an empty AuthPayload could otherwise reach
        // a program that never checks the count. Deny when nothing authenticated.
        assert!(
            !authenticated_signers.is_empty(),
            "no authenticated signers (INV-1 floor)"
        );

        // A missing program means the rule still references us after uninstall:
        // degrade to deny, never silently succeed.
        let params: FnScopeParams = e
            .storage()
            .persistent()
            .get(&FnScopeKey::Params(smart_account.clone(), context_rule.id))
            .expect("policy not installed for this (account, rule): deny");

        match context {
            Context::Contract(ContractContext { fn_name, args, .. }) => {
                assert!(
                    params.funcs.iter().any(|f| f == fn_name),
                    "function not in publish allowlist"
                );
                if let Some(idx) = params.self_arg {
                    let arg = args.get(idx).expect("missing is-self argument");
                    let arg_addr =
                        Address::try_from_val(e, &arg).expect("is-self argument is not an address");
                    assert!(
                        arg_addr == smart_account,
                        "is-self argument is not the account"
                    );
                }
            }
            // Creating a contract is not a scoped call — deny.
            _ => panic!("non-contract context denied"),
        }
    }

    fn install(
        e: &Env,
        install_params: Self::AccountParams,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();
        e.storage().persistent().set(
            &FnScopeKey::Params(smart_account, context_rule.id),
            &install_params,
        );
    }

    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        smart_account.require_auth();
        e.storage()
            .persistent()
            .remove(&FnScopeKey::Params(smart_account, context_rule.id));
    }
}

// ---------------------------------------------------------------------------
// RegistryStub — the constructorless-immutable deploy (perch decision D3).
// ---------------------------------------------------------------------------

#[contract]
pub struct RegistryStub;

#[contractimpl]
impl RegistryStub {
    /// Publish a wasm as a hash-addressed ("unnamed") contract. The salt is the
    /// wasm hash, so the deployed address is a pure function of
    /// (registry address, wasm hash) — derivable offline from registry id +
    /// hash, permissionless and idempotent. The published wasm must be
    /// constructorless (no "same address, different init").
    pub fn publish_hash(e: &Env, author: Address, wasm_hash: BytesN<32>) -> Address {
        author.require_auth();
        e.deployer()
            .with_current_contract(wasm_hash.clone())
            .deploy_v2(wasm_hash, ())
    }

    /// A non-publish administrative method. The `ci-publish` policy must block
    /// the CI key from calling this.
    pub fn set_manager(_e: &Env, author: Address, _new_manager: Address) {
        author.require_auth();
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A deterministic CI signer bound to the passkey verifier.
fn ci_signer(env: &Env, verifier: &Address) -> (SigningKey, Signer) {
    let key = test_key(2);
    let pubkey = key.verifying_key().to_sec1_bytes();
    (
        key,
        Signer::External(verifier.clone(), Bytes::from_slice(env, &pubkey)),
    )
}

/// Sign the auth digest (`sha256(payload || rule_ids.to_xdr())`) for rule 1
/// (the `ci-publish` rule; the default rule is 0).
fn ci_sig(
    env: &Env,
    signer: &Signer,
    key: &SigningKey,
    payload: &soroban_sdk::crypto::Hash<32>,
) -> AuthPayload {
    let context_rule_ids = vec![env, 1u32];
    let auth_digest = compute_auth_digest(env, payload, &context_rule_ids);
    let a = build_contract_assertion(key, env, &auth_digest);
    let sd = WebAuthnSigData {
        signature: a.signature,
        authenticator_data: a.authenticator_data,
        client_data: a.client_data,
    };
    let mut m: Map<Signer, Bytes> = Map::new(env);
    m.set(signer.clone(), sd.to_xdr(env));
    AuthPayload {
        signers: m,
        context_rule_ids,
    }
}

/// Build the `ci-publish` account: a passkey admin (the default rule) plus a
/// CI rule scoped to `registry` with the `FnScopePolicy`. Returns the account
/// address, the CI key + signer, and the registry address used in the scope.
fn setup(env: &Env) -> (Address, SigningKey, Signer, Address) {
    let (client, account_addr, verifier_addr, _admin) = deploy_smart_account(env);
    let policy_addr = env.register(FnScopePolicy, ());
    let registry = Address::generate(env);
    let (ci_key, signer) = ci_signer(env, &verifier_addr);

    // ci-publish: only publish/publish_hash, and the author argument (index 0)
    // must be the account itself.
    let params = FnScopeParams {
        funcs: vec![
            env,
            Symbol::new(env, "publish"),
            Symbol::new(env, "publish_hash"),
        ],
        self_arg: Some(0),
    };
    let mut policies: Map<Address, Val> = Map::new(env);
    policies.set(policy_addr, params.into_val(env));

    client.add_context_rule(
        &ContextRuleType::CallContract(registry.clone()),
        &String::from_str(env, "ci-publish"),
        &None,
        &vec![env, signer.clone()],
        &policies,
    );

    (account_addr, ci_key, signer, registry)
}

/// A `registry.publish_hash(author, wasm_hash)` context.
fn publish_context(env: &Env, registry: &Address, author: &Address) -> Context {
    Context::Contract(ContractContext {
        contract: registry.clone(),
        fn_name: Symbol::new(env, "publish_hash"),
        args: vec![
            env,
            author.into_val(env),
            BytesN::from_array(env, &[7u8; 32]).into_val(env),
        ],
    })
}

fn denied(f: impl FnOnce()) {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    assert!(r.is_err(), "expected authorization to be denied");
}

// ---------------------------------------------------------------------------
// The policy in action
// ---------------------------------------------------------------------------

#[test]
fn ci_key_may_publish_as_self() {
    let env = Env::default();
    env.mock_all_auths(); // outer setup plumbing only; the CI signature is real
    let (account_addr, ci_key, signer, registry) = setup(&env);

    let ctx = publish_context(&env, &registry, &account_addr);
    let hash = env.crypto().sha256(&Bytes::from_array(&env, &[0x11; 32]));
    let sig = ci_sig(&env, &signer, &ci_key, &hash);

    env.as_contract(&account_addr, || {
        do_check_auth(&env, &hash, &sig, &vec![&env, ctx]).unwrap();
    });
}

#[test]
fn ci_key_may_not_call_non_publish_method() {
    let env = Env::default();
    env.mock_all_auths();
    let (account_addr, ci_key, signer, registry) = setup(&env);

    // Same registry, same signature machinery — but set_manager, not publish.
    let ctx = Context::Contract(ContractContext {
        contract: registry.clone(),
        fn_name: Symbol::new(&env, "set_manager"),
        args: vec![
            &env,
            account_addr.into_val(&env),
            account_addr.into_val(&env),
        ],
    });
    let hash = env.crypto().sha256(&Bytes::from_array(&env, &[0x22; 32]));
    let sig = ci_sig(&env, &signer, &ci_key, &hash);

    denied(|| {
        env.as_contract(&account_addr, || {
            do_check_auth(&env, &hash, &sig, &vec![&env, ctx]).unwrap();
        });
    });
}

#[test]
fn ci_key_may_not_publish_for_another_account() {
    let env = Env::default();
    env.mock_all_auths();
    let (account_addr, ci_key, signer, registry) = setup(&env);

    // publish_hash, but the author argument is someone else — is-self fails.
    let other = Address::generate(&env);
    let ctx = publish_context(&env, &registry, &other);
    let hash = env.crypto().sha256(&Bytes::from_array(&env, &[0x33; 32]));
    let sig = ci_sig(&env, &signer, &ci_key, &hash);

    denied(|| {
        env.as_contract(&account_addr, || {
            do_check_auth(&env, &hash, &sig, &vec![&env, ctx]).unwrap();
        });
    });
}

#[test]
fn empty_auth_payload_is_denied() {
    // INV-1 regression: a rule with a policy must not authorize with zero
    // signatures. An empty AuthPayload reaches enforce with no authenticated
    // signers; the policy's floor denies it.
    let env = Env::default();
    env.mock_all_auths();
    let (account_addr, _ci_key, _signer, registry) = setup(&env);

    let ctx = publish_context(&env, &registry, &account_addr);
    let hash = env.crypto().sha256(&Bytes::from_array(&env, &[0x44; 32]));
    let empty = AuthPayload {
        signers: Map::new(&env),
        context_rule_ids: vec![&env, 1u32],
    };

    denied(|| {
        env.as_contract(&account_addr, || {
            do_check_auth(&env, &hash, &empty, &vec![&env, ctx]).unwrap();
        });
    });
}

// ---------------------------------------------------------------------------
// The deploy in action: an unnamed (hash-addressed) contract
// ---------------------------------------------------------------------------

#[test]
fn publish_hash_deploys_unnamed_contract_at_a_derivable_address() {
    let env = Env::default();
    env.mock_all_auths();
    let registry = env.register(RegistryStub, ());
    let author = Address::generate(&env);

    // Upload a real constructorless wasm as the release payload.
    let wasm_hash = env.deployer().upload_contract_wasm(WEBAUTHN_VERIFIER_WASM);

    // The address is derivable offline from (registry, wasm hash) with no
    // deploy and no name — this is what "registry id + hash resolves it" means.
    let expected = env.as_contract(&registry, || {
        env.deployer()
            .with_current_contract(wasm_hash.clone())
            .deployed_address()
    });

    let client = RegistryStubClient::new(&env, &registry);
    let deployed = client.publish_hash(&author, &wasm_hash);

    assert_eq!(
        deployed, expected,
        "published address must equal the offline derivation from registry + hash"
    );
}
