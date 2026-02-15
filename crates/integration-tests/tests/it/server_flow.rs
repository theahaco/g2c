use base64::Engine;
use g2c_integration_tests::{build_server_assertion, start_server, TEST_CONTRACT_ID};
use p256::ecdsa::SigningKey;

// ------------------------------------------------------------------
// Happy path
// ------------------------------------------------------------------

#[tokio::test]
async fn full_challenge_verify_flow() {
    let base = start_server().await;
    let client = reqwest::Client::new();

    // Generate a passkey
    let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);

    // Step 1: request a challenge
    let resp = client
        .post(format!("{base}/auth/challenge/{TEST_CONTRACT_ID}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let challenge = body["challenge"].as_str().unwrap();
    let challenge_id = body["challenge_id"].as_str().unwrap();
    let rp_id = body["rp_id"].as_str().unwrap();

    assert_eq!(rp_id, format!("{TEST_CONTRACT_ID}.sorobancontracts.com"));

    // Step 2: build a WebAuthn assertion
    let assertion = build_server_assertion(&signing_key, TEST_CONTRACT_ID, challenge);

    // Step 3: verify the assertion
    let resp = client
        .post(format!("{base}/auth/verify/{TEST_CONTRACT_ID}"))
        .json(&serde_json::json!({
            "challenge_id": challenge_id,
            "authenticator_data": assertion.authenticator_data,
            "client_data_json": assertion.client_data_json,
            "signature": assertion.signature,
            "public_key": assertion.public_key,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let verify_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(verify_body["verified"], true);
}

// ------------------------------------------------------------------
// Error cases
// ------------------------------------------------------------------

#[tokio::test]
async fn challenge_is_one_time_use() {
    let base = start_server().await;
    let client = reqwest::Client::new();
    let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);

    // Get a challenge and verify it once
    let resp = client
        .post(format!("{base}/auth/challenge/{TEST_CONTRACT_ID}"))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let challenge = body["challenge"].as_str().unwrap();
    let challenge_id = body["challenge_id"].as_str().unwrap();

    let assertion = build_server_assertion(&signing_key, TEST_CONTRACT_ID, challenge);

    let verify_body = serde_json::json!({
        "challenge_id": challenge_id,
        "authenticator_data": assertion.authenticator_data,
        "client_data_json": assertion.client_data_json,
        "signature": assertion.signature,
        "public_key": assertion.public_key,
    });

    // First verify succeeds
    let resp = client
        .post(format!("{base}/auth/verify/{TEST_CONTRACT_ID}"))
        .json(&verify_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Replay with the same challenge_id → 404 (already consumed)
    let resp = client
        .post(format!("{base}/auth/verify/{TEST_CONTRACT_ID}"))
        .json(&verify_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn reject_invalid_contract_id() {
    let base = start_server().await;
    let client = reqwest::Client::new();

    // G-addresses are rejected
    let resp = client
        .post(format!(
            "{base}/auth/challenge/GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn reject_wrong_signature() {
    let base = start_server().await;
    let client = reqwest::Client::new();

    let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let wrong_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);

    // Get challenge
    let resp = client
        .post(format!("{base}/auth/challenge/{TEST_CONTRACT_ID}"))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let challenge = body["challenge"].as_str().unwrap();
    let challenge_id = body["challenge_id"].as_str().unwrap();

    // Sign with signing_key but provide wrong_key's public key
    let mut assertion = build_server_assertion(&signing_key, TEST_CONTRACT_ID, challenge);
    let wrong_pubkey = wrong_key.verifying_key().to_sec1_bytes();
    assertion.public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&wrong_pubkey);

    let resp = client
        .post(format!("{base}/auth/verify/{TEST_CONTRACT_ID}"))
        .json(&serde_json::json!({
            "challenge_id": challenge_id,
            "authenticator_data": assertion.authenticator_data,
            "client_data_json": assertion.client_data_json,
            "signature": assertion.signature,
            "public_key": assertion.public_key,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn health_endpoint() {
    let base = start_server().await;
    let client = reqwest::Client::new();

    let resp = client.get(format!("{base}/health")).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
}
