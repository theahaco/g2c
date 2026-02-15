use g2c_integration_tests::{build_contract_assertion, deploy_smart_account};
use p256::ecdsa::SigningKey;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{symbol_short, vec, Bytes, Env, Map};
use stellar_accounts::smart_account::{do_check_auth, Signatures, Signer};
use stellar_accounts::verifiers::webauthn::WebAuthnSigData;

/// Full smart account `__check_auth` flow: deploy account with passkey signer,
/// build a `WebAuthn` assertion, and verify via `do_check_auth`.
#[test]
fn smart_account_check_auth_with_passkey() {
    let env = Env::default();
    let (_client, account_addr, verifier_addr, signing_key) = deploy_smart_account(&env);

    // Simulate a signature payload: hash arbitrary input to get a Hash<32>
    // (Hash<32> can only be constructed via crypto functions).
    let hash = env.crypto().sha256(&Bytes::from_array(&env, &[0xCD; 32]));

    // Build the assertion using the hash bytes as the challenge so the
    // verifier's base64url(signature_payload) == challenge check passes.
    let assertion = build_contract_assertion(&signing_key, &env, &hash.to_array());

    // XDR-encode WebAuthnSigData for the Signatures map
    let sig_data = WebAuthnSigData {
        signature: assertion.signature,
        authenticator_data: assertion.authenticator_data,
        client_data: assertion.client_data,
    };
    let sig_data_bytes = sig_data.to_xdr(&env);

    // Reconstruct the signer (must match what was registered)
    let pubkey_sec1 = signing_key.verifying_key().to_sec1_bytes();
    let key_data = soroban_sdk::Bytes::from_slice(&env, &pubkey_sec1);
    let signer = Signer::External(verifier_addr, key_data);

    // Construct Signatures
    let mut sig_map: Map<Signer, Bytes> = Map::new(&env);
    sig_map.set(signer, sig_data_bytes);
    let signatures = Signatures(sig_map);

    // Auth context: arbitrary contract call (the Default rule matches everything)
    let context = Context::Contract(ContractContext {
        contract: soroban_sdk::Address::generate(&env),
        fn_name: symbol_short!("transfer"),
        args: vec![&env],
    });

    env.as_contract(&account_addr, || {
        do_check_auth(&env, &hash, &signatures, &vec![&env, context]).unwrap();
    });
}

/// `do_check_auth` rejects a `WebAuthn` assertion signed by the wrong key.
#[test]
fn smart_account_check_auth_rejects_wrong_key() {
    let env = Env::default();
    let (_client, account_addr, verifier_addr, signing_key) = deploy_smart_account(&env);

    // Sign with a DIFFERENT key than the one registered
    let wrong_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);

    let hash = env.crypto().sha256(&Bytes::from_array(&env, &[0xEF; 32]));
    let assertion = build_contract_assertion(&wrong_key, &env, &hash.to_array());

    let sig_data = WebAuthnSigData {
        signature: assertion.signature,
        authenticator_data: assertion.authenticator_data,
        client_data: assertion.client_data,
    };
    let sig_data_bytes = sig_data.to_xdr(&env);

    // Use the REGISTERED signer (original key's pubkey + verifier)
    let pubkey_sec1 = signing_key.verifying_key().to_sec1_bytes();
    let key_data = soroban_sdk::Bytes::from_slice(&env, &pubkey_sec1);
    let signer = Signer::External(verifier_addr, key_data);

    let mut sig_map: Map<Signer, Bytes> = Map::new(&env);
    sig_map.set(signer, sig_data_bytes);
    let signatures = Signatures(sig_map);

    let context = Context::Contract(ContractContext {
        contract: soroban_sdk::Address::generate(&env),
        fn_name: symbol_short!("transfer"),
        args: vec![&env],
    });

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&account_addr, || {
            do_check_auth(&env, &hash, &signatures, &vec![&env, context]).unwrap();
        });
    }));

    assert!(
        result.is_err(),
        "should reject assertion signed by wrong key"
    );
}
