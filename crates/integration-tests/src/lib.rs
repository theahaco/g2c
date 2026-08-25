use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};
use soroban_sdk::testutils::Address as _;
use stellar_accounts::policies::simple_threshold::SimpleThresholdAccountParams;
use stellar_accounts::policies::spending_limit::SpendingLimitAccountParams;
use stellar_accounts::smart_account::{ContextRule, ContextRuleType, Signer};

pub mod zk_fixture;

pub const SMART_ACCOUNT_WASM: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/contract/nido_smart_account.wasm");

pub const WEBAUTHN_VERIFIER_WASM: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/contract/nido_webauthn_verifier.wasm");

pub const MULTISIG_POLICY_WASM: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/contract/nido_multisig_policy.wasm");

pub const SPENDING_LIMIT_POLICY_WASM: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/contract/nido_spending_limit_policy.wasm");

pub const PREAUTH_SWEEP_POLICY_WASM: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/contract/nido_preauth_sweep_policy.wasm");

/// M2 Task 5's factory contract wasm — embeds the same smart-account wasm
/// bytes as [`SMART_ACCOUNT_WASM`] internally (see
/// `contracts/factory/src/contract.rs`'s `smart_account` module doc
/// comment), so uploading [`SMART_ACCOUNT_WASM`] via
/// `env.deployer().upload_contract_wasm` before calling the factory's
/// `create_account`/`create_account_v2` satisfies its `deploy_v2` wasm-hash
/// lookup.
pub const FACTORY_WASM: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/contract/nido_factory.wasm");

#[allow(dead_code)]
#[soroban_sdk::contractclient(name = "SmartAccountClient")]
trait SmartAccountInterface {
    fn get_context_rule(env: soroban_sdk::Env, context_rule_id: u32) -> ContextRule;
    fn get_context_rules(
        env: soroban_sdk::Env,
        context_rule_type: ContextRuleType,
    ) -> soroban_sdk::Vec<ContextRule>;
    fn get_context_rules_count(env: soroban_sdk::Env) -> u32;
    fn add_context_rule(
        env: soroban_sdk::Env,
        context_type: ContextRuleType,
        name: soroban_sdk::String,
        valid_until: Option<u32>,
        signers: soroban_sdk::Vec<Signer>,
        policies: soroban_sdk::Map<soroban_sdk::Address, soroban_sdk::Val>,
    ) -> ContextRule;
    fn update_context_rule_valid_until(
        env: soroban_sdk::Env,
        context_rule_id: u32,
        valid_until: Option<u32>,
    ) -> ContextRule;
    fn remove_context_rule(env: soroban_sdk::Env, context_rule_id: u32);
    fn add_signer(env: soroban_sdk::Env, context_rule_id: u32, signer: Signer) -> u32;
    fn remove_signer(env: soroban_sdk::Env, context_rule_id: u32, signer_id: u32);
    fn add_policy(
        env: soroban_sdk::Env,
        context_rule_id: u32,
        policy: soroban_sdk::Address,
        install_param: soroban_sdk::Val,
    ) -> u32;
    fn remove_policy(env: soroban_sdk::Env, context_rule_id: u32, policy_id: u32);
    // M2 Task 4: the in-account recovery guard's views/entry points
    // (`contracts/smart-account/src/contract.rs`).
    fn recovery_rule_id(env: soroban_sdk::Env) -> Option<u32>;
    fn recovery_controller(env: soroban_sdk::Env) -> Option<soroban_sdk::Address>;
    fn initiate_recovery_rule_removal(env: soroban_sdk::Env);
    fn execute_recovery_rule_removal(env: soroban_sdk::Env);
    // M2 Task 6: the migration path for a NEW-wasm account deployed with
    // `recovery_controller: None` (`contract.rs::enroll_zk_recovery`).
    fn enroll_zk_recovery(env: soroban_sdk::Env, recovery_controller: soroban_sdk::Address);
}

/// Create a deterministic P-256 signing key from a `u64` seed.
///
/// The seed is hashed with SHA-256 to produce the 32-byte scalar. This
/// guarantees that seeds 1, 2, 3, 4, … always yield the same key so tests
/// are reproducible. Never reuse seed 1 for friend keys — `deploy_smart_account`
/// internally uses a random key for the primary passkey signer.
///
/// # Panics
/// Panics if the derived scalar bytes fail to produce a valid `SigningKey`.
#[must_use]
pub fn test_key(seed: u64) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"nido-test-key:");
    hasher.update(seed.to_le_bytes());
    let bytes = hasher.finalize();
    SigningKey::from_bytes(&bytes).expect("deterministic key from seed")
}

/// On-chain `WebAuthn` assertion components (soroban-sdk types) suitable for
/// the `WebAuthnVerifier` contract.
pub struct ContractAssertion {
    pub authenticator_data: soroban_sdk::Bytes,
    pub client_data: soroban_sdk::Bytes,
    pub signature: soroban_sdk::BytesN<64>,
    pub key_data: soroban_sdk::Bytes,
}

/// Build a synthetic `WebAuthn` assertion for on-chain verification.
///
/// The `signature_payload` is the 32-byte hash that the Soroban auth framework
/// would produce. The challenge in clientDataJSON is its base64url encoding.
///
/// # Panics
/// Panics if prehash ECDSA signing fails.
#[must_use]
pub fn build_contract_assertion(
    signing_key: &SigningKey,
    env: &soroban_sdk::Env,
    signature_payload: &[u8; 32],
) -> ContractAssertion {
    // Challenge = base64url(signature_payload)
    let challenge_b64 = URL_SAFE_NO_PAD.encode(signature_payload);

    // authenticatorData: 37 bytes minimum (rpIdHash zeroed — the on-chain
    // verifier skips rpIdHash validation).
    // flags = UP(0x01) | UV(0x04) | BE(0x08) | BS(0x10) = 0x1D
    let mut auth_data_raw = [0u8; 37];
    auth_data_raw[32] = 0x1D;
    let authenticator_data = soroban_sdk::Bytes::from_array(env, &auth_data_raw);

    // clientDataJSON
    let client_data_str = std::format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge_b64}","origin":"https://example.com","crossOrigin":false}}"#,
    );
    let client_data = soroban_sdk::Bytes::from_slice(env, client_data_str.as_bytes());

    // message digest = SHA-256(authData || SHA-256(clientData))
    let client_data_hash = env.crypto().sha256(&client_data);
    let mut msg = authenticator_data.clone();
    msg.extend_from_array(&client_data_hash.to_array());
    let digest = env.crypto().sha256(&msg);

    // Prehash sign (we already have the final hash)
    let sig: Signature = signing_key.sign_prehash(&digest.to_array()).unwrap();
    let sig_normalized = sig.normalize_s().unwrap_or(sig);
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&sig_normalized.to_bytes());
    let signature = soroban_sdk::BytesN::<64>::from_array(env, &sig_bytes);

    // SEC1 uncompressed public key (65 bytes)
    let pubkey_sec1 = signing_key.verifying_key().to_sec1_bytes();
    let key_data = soroban_sdk::Bytes::from_slice(env, &pubkey_sec1);

    ContractAssertion {
        authenticator_data,
        client_data,
        signature,
        key_data,
    }
}

/// Deploy the `WebAuthn` verifier and smart account contracts, initialising the
/// account with a single passkey signer. Returns the client, account address,
/// verifier address, and signing key.
///
/// Constructs the account with `recovery_controller: None` — the account gets
/// ONLY the Default rule (unchanged behavior for the many callers of this
/// helper that have nothing to do with zk-recovery). Tests that need the
/// recovery rule installed at construction should use
/// [`deploy_smart_account_with_recovery`] instead.
#[must_use]
pub fn deploy_smart_account(
    env: &soroban_sdk::Env,
) -> (
    SmartAccountClient<'_>,
    soroban_sdk::Address,
    soroban_sdk::Address,
    SigningKey,
) {
    deploy_smart_account_with_recovery(env, None)
}

/// Like [`deploy_smart_account`], but passes `recovery_controller` through to
/// the constructor's 3rd argument. `Some(controller)` installs the
/// zero-signer `CallContract(self)` recovery rule with `controller` as its
/// policy (triggering the controller's `Policy::install`); `None` behaves
/// exactly like [`deploy_smart_account`].
#[must_use]
pub fn deploy_smart_account_with_recovery<'a>(
    env: &'a soroban_sdk::Env,
    recovery_controller: Option<&soroban_sdk::Address>,
) -> (
    SmartAccountClient<'a>,
    soroban_sdk::Address,
    soroban_sdk::Address,
    SigningKey,
) {
    // Deploy the stateless WebAuthn verifier (admin governs upgrade only)
    let verifier_addr = env.register(
        WEBAUTHN_VERIFIER_WASM,
        (soroban_sdk::Address::generate(env),),
    );

    // Generate a passkey (P-256 keypair)
    let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let pubkey_sec1 = signing_key.verifying_key().to_sec1_bytes();

    // Construct the External signer: (verifier_address, public_key_bytes)
    let key_data = soroban_sdk::Bytes::from_slice(env, &pubkey_sec1);
    let signer = Signer::External(verifier_addr.clone(), key_data);

    let signers = soroban_sdk::vec![env, signer];
    let policies: soroban_sdk::Map<soroban_sdk::Address, soroban_sdk::Val> =
        soroban_sdk::Map::new(env);

    // Deploy the smart account with the passkey signer
    let account_addr = env.register(
        SMART_ACCOUNT_WASM,
        (&signers, &policies, recovery_controller.cloned()),
    );

    let client = SmartAccountClient::new(env, &account_addr);
    (client, account_addr, verifier_addr, signing_key)
}

/// Deploy the multisig policy contract and return its address.
#[must_use]
pub fn deploy_multisig_policy(env: &soroban_sdk::Env) -> soroban_sdk::Address {
    env.register(MULTISIG_POLICY_WASM, (soroban_sdk::Address::generate(env),))
}

/// Build the `policies` map for `add_context_rule` containing a single
/// multisig-policy install with the given threshold.
#[must_use]
pub fn multisig_install_map(
    env: &soroban_sdk::Env,
    multisig_policy_addr: &soroban_sdk::Address,
    threshold: u32,
) -> soroban_sdk::Map<soroban_sdk::Address, soroban_sdk::Val> {
    use soroban_sdk::IntoVal;
    let params = SimpleThresholdAccountParams { threshold };
    let mut m: soroban_sdk::Map<soroban_sdk::Address, soroban_sdk::Val> =
        soroban_sdk::Map::new(env);
    m.set(multisig_policy_addr.clone(), params.into_val(env));
    m
}

/// Deploy the spending-limit policy contract and return its address.
#[must_use]
pub fn deploy_spending_limit_policy(env: &soroban_sdk::Env) -> soroban_sdk::Address {
    env.register(
        SPENDING_LIMIT_POLICY_WASM,
        (soroban_sdk::Address::generate(env),),
    )
}

/// Build the `policies` map for `add_context_rule` containing a single
/// spending-limit-policy install with the given limit (stroops) and rolling
/// window (ledgers).
#[must_use]
pub fn spending_limit_install_map(
    env: &soroban_sdk::Env,
    policy_addr: &soroban_sdk::Address,
    spending_limit: i128,
    period_ledgers: u32,
) -> soroban_sdk::Map<soroban_sdk::Address, soroban_sdk::Val> {
    use soroban_sdk::IntoVal;
    let params = SpendingLimitAccountParams {
        spending_limit,
        period_ledgers,
    };
    let mut m: soroban_sdk::Map<soroban_sdk::Address, soroban_sdk::Val> =
        soroban_sdk::Map::new(env);
    m.set(policy_addr.clone(), params.into_val(env));
    m
}

/// Compute the auth digest the smart account's `do_check_auth` will pass to
/// the verifier, given the original signature payload and the chosen
/// context-rule IDs. In OZ v0.7+:
///
///     auth_digest = SHA-256(signature_payload || context_rule_ids.to_xdr())
///
/// Binds the signed message to the rule the caller selected (preventing
/// rule-substitution replay). Use the returned 32 bytes as the
/// `signature_payload` arg to `build_contract_assertion`.
#[must_use]
pub fn compute_auth_digest(
    env: &soroban_sdk::Env,
    signature_payload: &soroban_sdk::crypto::Hash<32>,
    context_rule_ids: &soroban_sdk::Vec<u32>,
) -> [u8; 32] {
    use soroban_sdk::xdr::ToXdr;
    let mut preimage = soroban_sdk::Bytes::from_array(env, &signature_payload.to_array());
    preimage.append(&context_rule_ids.clone().to_xdr(env));
    env.crypto().sha256(&preimage).to_array()
}

/// Build a real External (`WebAuthn`) session signer backed by the deterministic
/// P-256 key [`test_key`]`(seed)`, verified on-chain by the `verifier` contract.
///
/// Returns the signing key (to produce real signatures with [`one_sig`]) and the
/// matching `Signer::External`. Unlike a `Signer::Delegated` (whose auth is a
/// `require_auth_for_args` that `mock_all_auths` satisfies with no real
/// signature), an External signer is authenticated by the verifier contract's
/// actual P-256 check inside `do_check_auth` — which `mock_all_auths` does NOT
/// bypass — so tests using this exercise real signature verification.
#[must_use]
pub fn session_signer(
    env: &soroban_sdk::Env,
    verifier: &soroban_sdk::Address,
    seed: u64,
) -> (SigningKey, Signer) {
    let key = test_key(seed);
    let pubkey = key.verifying_key().to_sec1_bytes();
    (
        key,
        Signer::External(
            verifier.clone(),
            soroban_sdk::Bytes::from_slice(env, &pubkey),
        ),
    )
}

/// Produce a real single-signer `AuthPayload` for rule `rule_id`: sign the auth
/// digest (`sha256(payload || [rule_id].to_xdr())`, see [`compute_auth_digest`])
/// with `key`, wrap it as `WebAuthnSigData`, and map it under `signer`.
///
/// Passing a `key` whose public key does NOT match `signer`'s registered pubkey
/// (or whose digest was signed for a different rule) yields a *forged* payload
/// the `WebAuthn` verifier rejects — the basis of the signature-verification
/// negative tests. All callers here use a single rule id per authorization.
#[must_use]
pub fn one_sig(
    env: &soroban_sdk::Env,
    signer: &Signer,
    key: &SigningKey,
    payload: &soroban_sdk::crypto::Hash<32>,
    rule_id: u32,
) -> stellar_accounts::smart_account::AuthPayload {
    use soroban_sdk::xdr::ToXdr;
    let context_rule_ids = soroban_sdk::vec![env, rule_id];
    let auth_digest = compute_auth_digest(env, payload, &context_rule_ids);
    let assertion = build_contract_assertion(key, env, &auth_digest);
    let sig_data = stellar_accounts::verifiers::webauthn::WebAuthnSigData {
        signature: assertion.signature,
        authenticator_data: assertion.authenticator_data,
        client_data: assertion.client_data,
    };
    let mut signers: soroban_sdk::Map<Signer, soroban_sdk::Bytes> = soroban_sdk::Map::new(env);
    signers.set(signer.clone(), sig_data.to_xdr(env));
    stellar_accounts::smart_account::AuthPayload {
        signers,
        context_rule_ids,
    }
}
