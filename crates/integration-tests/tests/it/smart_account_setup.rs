use g2c_integration_tests::deploy_smart_account;
use soroban_sdk::Env;
use stellar_accounts::smart_account::{ContextRuleType, Signer};

#[test]
fn deploy_with_passkey_signer() {
    let env = Env::default();
    let (client, _account_addr, _verifier_addr, signing_key) = deploy_smart_account(&env);

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
    let (client, _account_addr, _verifier_addr, _signing_key) = deploy_smart_account(&env);

    let rule = client.get_context_rule(&0u32);

    assert!(matches!(rule.context_type, ContextRuleType::Default));
    assert_eq!(rule.valid_until, None);
}

#[test]
fn context_rules_count_is_one() {
    let env = Env::default();
    let (client, _account_addr, _verifier_addr, _signing_key) = deploy_smart_account(&env);

    assert_eq!(client.get_context_rules_count(), 1);
}
