use nido_integration_tests::{build_contract_assertion, WEBAUTHN_VERIFIER_WASM};
use p256::ecdsa::SigningKey;
use soroban_sdk::{testutils::Address as _, Address, Env};
use stellar_accounts::verifiers::webauthn::{self, WebAuthnSigData};

#[test]
fn verify_webauthn_assertion_on_chain() {
    let env = Env::default();

    // Register the verifier contract
    let verifier_addr = env.register(WEBAUTHN_VERIFIER_WASM, (Address::generate(&env),));

    // Generate a passkey (P-256 keypair)
    let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);

    // Simulate a 32-byte signature payload (the transaction hash the auth
    // framework would produce)
    let payload_bytes: [u8; 32] = [
        0x4b, 0xb7, 0xa8, 0xb9, 0x96, 0x09, 0xb0, 0xb8, 0xb1, 0xd5, 0x34, 0x69, 0x4b, 0xb1, 0xf3,
        0x1f, 0x12, 0x91, 0x38, 0xa2, 0xf2, 0xa1, 0x1f, 0x8e, 0x87, 0x02, 0xee, 0xdb, 0xb7, 0x92,
        0x92, 0x2e,
    ];

    let assertion = build_contract_assertion(&signing_key, &env, &payload_bytes);

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

    let verifier_addr = env.register(WEBAUTHN_VERIFIER_WASM, (Address::generate(&env),));

    let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);

    // Build assertion for one payload but verify with a different one
    let payload_bytes: [u8; 32] = [1u8; 32];
    let assertion = build_contract_assertion(&signing_key, &env, &payload_bytes);

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

    let verifier_addr = env.register(WEBAUTHN_VERIFIER_WASM, (Address::generate(&env),));

    let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let wrong_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);

    let payload_bytes: [u8; 32] = [3u8; 32];
    let assertion = build_contract_assertion(&signing_key, &env, &payload_bytes);

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

/// P-256 group order `n`, big-endian. `n - s` maps a canonical low-S
/// signature to its (equally valid, under raw ECDSA) high-S counterpart.
const P256_ORDER_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// Big-endian 256-bit subtraction `a - b`, assuming `a >= b` (true here since
/// `s < n`). Used only to derive the high-S counterpart of a low-S scalar.
// `diff` is held in [0, 0x1FF] by the `0x100 +` bias, so `diff as u8` (its low
// byte) is the exact result digit -- no real truncation.
#[allow(clippy::cast_possible_truncation)]
fn sub_be_32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0u16;
    for i in (0..32).rev() {
        let diff = 0x100u16 + u16::from(a[i]) - u16::from(b[i]) - borrow;
        out[i] = diff as u8;
        borrow = u16::from(diff < 0x100);
    }
    out
}

/// ECDSA signature malleability: for any valid signature `(r, s)`, `(r, n - s)`
/// is an equally valid signature over the same message under raw ECDSA. The
/// wallet's passkey path (soroban host `secp256r1_verify`, via OZ
/// `webauthn::verify`) enforces the canonical LOW-S form (`s < n/2`), so the
/// high-S counterpart must be REJECTED even though it is mathematically valid.
/// Without this, a network attacker could reshape a signature (changing the
/// tx/auth-entry signature bytes, hence its hash) without the passkey. This
/// pins that malleability protection at the verifier boundary: the ONLY change
/// between the accepted and rejected inputs is `s -> n - s`.
#[test]
fn reject_high_s_malleated_signature_on_chain() {
    let env = Env::default();
    let verifier_addr = env.register(WEBAUTHN_VERIFIER_WASM, (Address::generate(&env),));

    let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let payload_bytes: [u8; 32] = [7u8; 32];
    let assertion = build_contract_assertion(&signing_key, &env, &payload_bytes);

    // `build_contract_assertion` normalises to low-S, so split r||s and flip s
    // to its high-S counterpart n - s.
    let low = assertion.signature.to_array();
    let mut r = [0u8; 32];
    r.copy_from_slice(&low[..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&low[32..]);
    let high_s = sub_be_32(&P256_ORDER_BE, &s);
    let mut malleated = [0u8; 64];
    malleated[..32].copy_from_slice(&r);
    malleated[32..].copy_from_slice(&high_s);

    let key = soroban_sdk::BytesN::<65>::from_array(
        &env,
        &<[u8; 65]>::try_from(assertion.key_data.to_buffer::<65>().as_slice()).unwrap(),
    );
    let signature_payload = soroban_sdk::Bytes::from_array(&env, &payload_bytes);

    // Sanity: the ORIGINAL low-S signature verifies -- proving the witness is
    // sound and the only defect introduced below is the S-value.
    let sig_ok = WebAuthnSigData {
        signature: soroban_sdk::BytesN::<64>::from_array(&env, &low),
        authenticator_data: assertion.authenticator_data.clone(),
        client_data: assertion.client_data.clone(),
    };
    env.as_contract(&verifier_addr, || {
        assert!(
            webauthn::verify(&env, &signature_payload, &key, &sig_ok),
            "the canonical low-S signature must verify"
        );
    });

    // The high-S malleated signature must be rejected -- whether the host
    // returns false or traps, both are a rejection (funds safe).
    let sig_high = WebAuthnSigData {
        signature: soroban_sdk::BytesN::<64>::from_array(&env, &malleated),
        authenticator_data: assertion.authenticator_data,
        client_data: assertion.client_data,
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&verifier_addr, || {
            webauthn::verify(&env, &signature_payload, &key, &sig_high)
        })
    }));
    let rejected = matches!(result, Ok(false) | Err(_));
    assert!(
        rejected,
        "high-S malleated signature must be rejected (ECDSA malleability protection)"
    );
}
