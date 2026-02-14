use p256::ecdsa::SigningKey;
use soroban_sdk::Env;
use stellar_accounts::verifiers::webauthn::{self, WebAuthnSigData};

use crate::helpers;

#[test]
fn verify_webauthn_assertion_on_chain() {
    let env = Env::default();

    // Register the verifier contract
    let verifier_addr = env.register(helpers::WEBAUTHN_VERIFIER_WASM, ());

    // Generate a passkey (P-256 keypair)
    let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);

    // Simulate a 32-byte signature payload (the transaction hash the auth
    // framework would produce)
    let payload_bytes: [u8; 32] = [
        0x4b, 0xb7, 0xa8, 0xb9, 0x96, 0x09, 0xb0, 0xb8, 0xb1, 0xd5, 0x34, 0x69, 0x4b, 0xb1, 0xf3,
        0x1f, 0x12, 0x91, 0x38, 0xa2, 0xf2, 0xa1, 0x1f, 0x8e, 0x87, 0x02, 0xee, 0xdb, 0xb7, 0x92,
        0x92, 0x2e,
    ];

    let assertion = helpers::build_contract_assertion(&signing_key, &env, &payload_bytes);

    let sig_data = WebAuthnSigData {
        signature: assertion.signature,
        authenticator_data: assertion.authenticator_data,
        client_data: assertion.client_data,
    };

    // Call the on-chain verify function directly (via env.as_contract to set
    // the executing contract context)
    let signature_payload = soroban_sdk::Bytes::from_array(&env, &payload_bytes);

    env.as_contract(&verifier_addr, || {
        let result = webauthn::verify(
            &env,
            &signature_payload,
            &soroban_sdk::BytesN::<65>::from_array(
                &env,
                &<[u8; 65]>::try_from(assertion.key_data.to_buffer::<65>().as_slice()).unwrap(),
            ),
            &sig_data,
        );
        assert!(result);
    });
}

#[test]
fn reject_wrong_challenge_on_chain() {
    let env = Env::default();

    let verifier_addr = env.register(helpers::WEBAUTHN_VERIFIER_WASM, ());

    let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);

    // Build assertion for one payload but verify with a different one
    let payload_bytes: [u8; 32] = [1u8; 32];
    let assertion = helpers::build_contract_assertion(&signing_key, &env, &payload_bytes);

    let sig_data = WebAuthnSigData {
        signature: assertion.signature,
        authenticator_data: assertion.authenticator_data,
        client_data: assertion.client_data,
    };

    // Use a DIFFERENT payload for verification — challenge won't match
    let wrong_payload = soroban_sdk::Bytes::from_array(&env, &[2u8; 32]);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&verifier_addr, || {
            webauthn::verify(
                &env,
                &wrong_payload,
                &soroban_sdk::BytesN::<65>::from_array(
                    &env,
                    &<[u8; 65]>::try_from(assertion.key_data.to_buffer::<65>().as_slice()).unwrap(),
                ),
                &sig_data,
            );
        });
    }));

    assert!(result.is_err(), "should reject mismatched challenge");
}

#[test]
fn reject_wrong_key_on_chain() {
    let env = Env::default();

    let verifier_addr = env.register(helpers::WEBAUTHN_VERIFIER_WASM, ());

    let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let wrong_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);

    let payload_bytes: [u8; 32] = [3u8; 32];
    let assertion = helpers::build_contract_assertion(&signing_key, &env, &payload_bytes);

    let sig_data = WebAuthnSigData {
        signature: assertion.signature,
        authenticator_data: assertion.authenticator_data,
        client_data: assertion.client_data,
    };

    // Use the WRONG public key
    let wrong_pubkey = wrong_key.verifying_key().to_sec1_bytes();
    let wrong_key_data: [u8; 65] = wrong_pubkey.as_ref().try_into().unwrap();

    let signature_payload = soroban_sdk::Bytes::from_array(&env, &payload_bytes);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&verifier_addr, || {
            webauthn::verify(
                &env,
                &signature_payload,
                &soroban_sdk::BytesN::<65>::from_array(&env, &wrong_key_data),
                &sig_data,
            );
        });
    }));

    assert!(result.is_err(), "should reject wrong public key");
}
