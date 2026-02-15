use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use passkey_core::storage::InMemoryStore;
use passkey_server::build_router;
use sha2::{Digest, Sha256};
use stellar_accounts::smart_account::{ContextRule, Signer};

pub const SMART_ACCOUNT_WASM: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/contract/g2c_smart_account.wasm");

pub const WEBAUTHN_VERIFIER_WASM: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/contract/g2c_webauthn_verifier.wasm");

#[allow(dead_code)]
#[soroban_sdk::contractclient(name = "SmartAccountClient")]
trait SmartAccountInterface {
    fn get_context_rule(env: soroban_sdk::Env, context_rule_id: u32) -> ContextRule;
    fn get_context_rules_count(env: soroban_sdk::Env) -> u32;
}

/// A valid Stellar strkey C-address for testing.
pub const TEST_CONTRACT_ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

/// Start the passkey-server on an OS-assigned port and return the base URL.
pub async fn start_server() -> String {
    let store = Arc::new(InMemoryStore::new());
    let app = build_router(store);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    format!("http://127.0.0.1:{port}")
}

/// Off-chain WebAuthn assertion fields (base64url-encoded strings)
/// suitable for the passkey-server HTTP verify endpoint.
pub struct ServerAssertion {
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
    pub public_key: String,
}

/// Build a synthetic WebAuthn assertion for the off-chain (HTTP server)
/// verification flow. Uses the RP ID and origin derived from the contract ID.
pub fn build_server_assertion(
    signing_key: &SigningKey,
    contract_id: &str,
    challenge_b64: &str,
) -> ServerAssertion {
    let rp_id = passkey_core::rp::rp_id(contract_id);
    let origin = passkey_core::rp::expected_origin(contract_id);

    // authenticatorData: rpIdHash (32) || flags (1) || signCount (4)
    let rp_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    let flags: u8 = 0x05; // UP + UV
    let sign_count: u32 = 1;
    let mut auth_data = Vec::with_capacity(37);
    auth_data.extend_from_slice(&rp_hash);
    auth_data.push(flags);
    auth_data.extend_from_slice(&sign_count.to_be_bytes());

    // clientDataJSON
    let client_data_json_bytes = serde_json::to_vec(&serde_json::json!({
        "type": "webauthn.get",
        "challenge": challenge_b64,
        "origin": origin,
    }))
    .unwrap();

    // signed message = authData || SHA-256(clientDataJSON)
    let client_data_hash: [u8; 32] = Sha256::digest(&client_data_json_bytes).into();
    let mut message = Vec::with_capacity(auth_data.len() + 32);
    message.extend_from_slice(&auth_data);
    message.extend_from_slice(&client_data_hash);

    // P-256 ECDSA sign (RFC 6979 deterministic)
    let signature: Signature = signing_key.sign(&message);

    // SEC1 uncompressed public key (65 bytes)
    let pubkey_bytes = signing_key.verifying_key().to_sec1_bytes();

    ServerAssertion {
        authenticator_data: URL_SAFE_NO_PAD.encode(&auth_data),
        client_data_json: URL_SAFE_NO_PAD.encode(&client_data_json_bytes),
        signature: URL_SAFE_NO_PAD.encode(signature.to_der()),
        public_key: URL_SAFE_NO_PAD.encode(&pubkey_bytes),
    }
}

/// On-chain WebAuthn assertion components (soroban-sdk types) suitable for
/// the WebAuthnVerifier contract.
pub struct ContractAssertion {
    pub authenticator_data: soroban_sdk::Bytes,
    pub client_data: soroban_sdk::Bytes,
    pub signature: soroban_sdk::BytesN<64>,
    pub key_data: soroban_sdk::Bytes,
}

/// Build a synthetic WebAuthn assertion for on-chain verification.
///
/// The `signature_payload` is the 32-byte hash that the Soroban auth framework
/// would produce. The challenge in clientDataJSON is its base64url encoding.
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
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://example.com","crossOrigin":false}}"#,
        challenge_b64,
    );
    let client_data = soroban_sdk::Bytes::from_slice(env, client_data_str.as_bytes());

    // message digest = SHA-256(authData || SHA-256(clientData))
    let client_data_hash = env.crypto().sha256(&client_data);
    let mut msg = authenticator_data.clone();
    msg.extend_from_array(&client_data_hash.to_array());
    let digest = env.crypto().sha256(&msg);

    // Prehash sign (we already have the final hash)
    use p256::ecdsa::signature::hazmat::PrehashSigner;
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

/// Deploy the WebAuthn verifier and smart account contracts, initialising the
/// account with a single passkey signer. Returns the client, account address,
/// verifier address, and signing key.
pub fn deploy_smart_account(
    env: &soroban_sdk::Env,
) -> (
    SmartAccountClient<'_>,
    soroban_sdk::Address,
    soroban_sdk::Address,
    SigningKey,
) {
    // Deploy the stateless WebAuthn verifier
    let verifier_addr = env.register(WEBAUTHN_VERIFIER_WASM, ());

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
    let account_addr = env.register(SMART_ACCOUNT_WASM, (&signers, &policies));

    let client = SmartAccountClient::new(env, &account_addr);
    (client, account_addr, verifier_addr, signing_key)
}
