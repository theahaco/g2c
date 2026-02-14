use p256::ecdsa::SigningKey;
use soroban_sdk::{vec, Address, Env, Map, Val};
use stellar_accounts::smart_account::{ContextRuleType, Signer};

use crate::helpers;

/// Deploy the WebAuthn verifier and smart account contracts, initialising the
/// account with a single passkey signer. Returns the client for further
/// assertions.
fn deploy_smart_account(
    env: &Env,
) -> (
    helpers::SmartAccountClient<'_>,
    soroban_sdk::Address,
    SigningKey,
) {
    // Deploy the stateless WebAuthn verifier
    let verifier_addr = env.register(helpers::WEBAUTHN_VERIFIER_WASM, ());

    // Generate a passkey (P-256 keypair)
    let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let pubkey_sec1 = signing_key.verifying_key().to_sec1_bytes();

    // Construct the External signer: (verifier_address, public_key_bytes)
    let key_data = soroban_sdk::Bytes::from_slice(env, &pubkey_sec1);
    let signer = Signer::External(verifier_addr, key_data);

    let signers = vec![env, signer];
    let policies: Map<Address, Val> = Map::new(env);

    // Deploy the smart account with the passkey signer
    let account_addr = env.register(helpers::SMART_ACCOUNT_WASM, (&signers, &policies));

    let client = helpers::SmartAccountClient::new(env, &account_addr);
    (client, account_addr, signing_key)
}

#[test]
fn deploy_with_passkey_signer() {
    let env = Env::default();
    let (client, _account_addr, signing_key) = deploy_smart_account(&env);

    // The constructor creates a default context rule (id = 0)
    let rule = client.get_context_rule(&0u32);

    assert_eq!(rule.signers.len(), 1);
    assert_eq!(rule.policies.len(), 0);

    // Verify the signer contains the correct public key
    let expected_pubkey = signing_key.verifying_key().to_sec1_bytes();
    match rule.signers.get(0).unwrap() {
        Signer::External(_verifier, key_data) => {
            let stored: [u8; 65] = key_data.to_buffer::<65>().as_slice().try_into().unwrap();
            assert_eq!(&stored[..], &expected_pubkey[..]);
        }
        _ => panic!("expected External signer"),
    }
}

#[test]
fn default_context_rule_is_default_type() {
    let env = Env::default();
    let (client, _account_addr, _signing_key) = deploy_smart_account(&env);

    let rule = client.get_context_rule(&0u32);

    assert!(matches!(rule.context_type, ContextRuleType::Default));
    assert_eq!(rule.valid_until, None);
}

#[test]
fn context_rules_count_is_one() {
    let env = Env::default();
    let (client, _account_addr, _signing_key) = deploy_smart_account(&env);

    assert_eq!(client.get_context_rules_count(), 1);
}
