use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::rp;
use crate::webauthn::authenticator::AuthenticatorData;
use crate::webauthn::client_data::ClientData;

/// Request payload for WebAuthn assertion verification.
#[derive(Debug, serde::Deserialize)]
pub struct VerifyRequest {
    /// Raw authenticatorData bytes, base64url-encoded.
    pub authenticator_data: String,
    /// Raw clientDataJSON bytes, base64url-encoded.
    pub client_data_json: String,
    /// DER-encoded ECDSA signature, base64url-encoded.
    pub signature: String,
    /// SEC1-encoded (uncompressed, 65 bytes) P-256 public key, base64url-encoded.
    /// MVP: client provides the public key directly.
    pub public_key: String,
}

/// Result of a successful verification.
#[derive(Debug, serde::Serialize)]
pub struct VerifyResponse {
    pub verified: bool,
}

/// Verify a WebAuthn assertion.
///
/// Steps:
/// 1. Parse authenticatorData and verify rpIdHash matches the contract's RP ID
/// 2. Verify user presence flag
/// 3. Parse and validate clientDataJSON (type, challenge, origin)
/// 4. Verify P-256 ECDSA signature over `authenticatorData || SHA-256(clientDataJSON)`
pub fn verify_assertion(
    contract_id: &str,
    expected_challenge_b64: &str,
    request: &VerifyRequest,
) -> Result<VerifyResponse, Error> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    // Decode all base64url fields
    let auth_data_bytes = URL_SAFE_NO_PAD
        .decode(&request.authenticator_data)
        .map_err(|e| Error::InvalidAuthenticatorData(e.to_string()))?;
    let client_data_bytes = URL_SAFE_NO_PAD
        .decode(&request.client_data_json)
        .map_err(|e| Error::InvalidClientData(e.to_string()))?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&request.signature)
        .map_err(|e| Error::InvalidSignature(e.to_string()))?;
    let pubkey_bytes = URL_SAFE_NO_PAD
        .decode(&request.public_key)
        .map_err(|e| Error::InvalidPublicKey(e.to_string()))?;

    // 1. Parse authenticatorData
    let auth_data = AuthenticatorData::parse(&auth_data_bytes)?;

    // 2. Verify rpIdHash
    let expected_rp_hash = rp::rp_id_hash(contract_id);
    if auth_data.rp_id_hash != expected_rp_hash {
        return Err(Error::RpIdMismatch);
    }

    // 3. Verify user presence
    if !auth_data.user_present() {
        return Err(Error::UserNotPresent);
    }

    // 4. Parse and validate clientDataJSON
    let client_data = ClientData::parse(&client_data_bytes)?;
    let expected_origin = rp::expected_origin(contract_id);
    client_data.validate(expected_challenge_b64, &expected_origin)?;

    // 5. Construct the signed message: authenticatorData || SHA-256(clientDataJSON)
    let client_data_hash: [u8; 32] = Sha256::digest(&client_data_bytes).into();
    let mut signed_message = Vec::with_capacity(auth_data_bytes.len() + 32);
    signed_message.extend_from_slice(&auth_data_bytes);
    signed_message.extend_from_slice(&client_data_hash);

    // 6. Verify P-256 ECDSA signature
    // p256's VerifyingKey::verify() internally does SHA-256(message) + ECDSA verify
    let verifying_key = VerifyingKey::from_sec1_bytes(&pubkey_bytes)
        .map_err(|e| Error::InvalidPublicKey(e.to_string()))?;

    let signature = Signature::from_der(&signature_bytes)
        .map_err(|e| Error::InvalidSignature(e.to_string()))?;

    verifying_key
        .verify(&signed_message, &signature)
        .map_err(|e| Error::InvalidSignature(e.to_string()))?;

    Ok(VerifyResponse { verified: true })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::ecdsa::{signature::Signer, SigningKey};
    use sha2::{Digest, Sha256};

    const TEST_CONTRACT_ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

    /// Helper: build a synthetic WebAuthn assertion from a P-256 keypair.
    fn build_assertion(
        signing_key: &SigningKey,
        contract_id: &str,
        challenge_b64: &str,
    ) -> VerifyRequest {
        let rp_id = rp::rp_id(contract_id);
        let origin = rp::expected_origin(contract_id);

        // Build authenticatorData
        let rp_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
        let flags: u8 = 0x05; // UP + UV
        let sign_count: u32 = 1;
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&rp_hash);
        auth_data.push(flags);
        auth_data.extend_from_slice(&sign_count.to_be_bytes());

        // Build clientDataJSON
        let client_data_json = serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge_b64,
            "origin": origin,
        }))
        .unwrap();

        // Construct signed message: authData || SHA-256(clientDataJSON)
        let client_data_hash: [u8; 32] = Sha256::digest(&client_data_json).into();
        let mut message = Vec::with_capacity(auth_data.len() + 32);
        message.extend_from_slice(&auth_data);
        message.extend_from_slice(&client_data_hash);

        // Sign with p256
        let signature: Signature = signing_key.sign(&message);

        // Get public key as SEC1 uncompressed
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = verifying_key.to_sec1_bytes();

        VerifyRequest {
            authenticator_data: URL_SAFE_NO_PAD.encode(&auth_data),
            client_data_json: URL_SAFE_NO_PAD.encode(&client_data_json),
            signature: URL_SAFE_NO_PAD.encode(signature.to_der()),
            public_key: URL_SAFE_NO_PAD.encode(&pubkey_bytes),
        }
    }

    #[test]
    fn verify_valid_assertion() {
        let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let challenge_b64 = URL_SAFE_NO_PAD.encode(b"test-challenge-32-bytes-padding!");

        let request = build_assertion(&signing_key, TEST_CONTRACT_ID, &challenge_b64);
        let result = verify_assertion(TEST_CONTRACT_ID, &challenge_b64, &request).unwrap();
        assert!(result.verified);
    }

    #[test]
    fn reject_wrong_challenge() {
        let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let challenge_b64 = URL_SAFE_NO_PAD.encode(b"test-challenge-32-bytes-padding!");

        let request = build_assertion(&signing_key, TEST_CONTRACT_ID, &challenge_b64);
        let err = verify_assertion(TEST_CONTRACT_ID, "wrong-challenge", &request).unwrap_err();
        assert!(matches!(err, Error::ChallengeMismatch));
    }

    #[test]
    fn reject_wrong_contract_id() {
        let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let challenge_b64 = URL_SAFE_NO_PAD.encode(b"test-challenge-32-bytes-padding!");

        let request = build_assertion(&signing_key, TEST_CONTRACT_ID, &challenge_b64);
        let other_contract = "CC53XO53XO53XO53XO53XO53XO53XO53XO53XO53XO53XO53XO53WQD5";
        let err = verify_assertion(other_contract, &challenge_b64, &request).unwrap_err();
        assert!(matches!(err, Error::RpIdMismatch));
    }

    #[test]
    fn reject_wrong_signature() {
        let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let other_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let challenge_b64 = URL_SAFE_NO_PAD.encode(b"test-challenge-32-bytes-padding!");

        // Build assertion with one key but provide the public key from another
        let mut request = build_assertion(&signing_key, TEST_CONTRACT_ID, &challenge_b64);
        let wrong_pubkey = other_key.verifying_key().to_sec1_bytes();
        request.public_key = URL_SAFE_NO_PAD.encode(&wrong_pubkey);

        let err = verify_assertion(TEST_CONTRACT_ID, &challenge_b64, &request).unwrap_err();
        assert!(matches!(err, Error::InvalidSignature(_)));
    }

    #[test]
    fn reject_tampered_authenticator_data() {
        let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let challenge_b64 = URL_SAFE_NO_PAD.encode(b"test-challenge-32-bytes-padding!");

        let mut request = build_assertion(&signing_key, TEST_CONTRACT_ID, &challenge_b64);

        // Tamper with authenticator data (flip a byte)
        let mut auth_bytes = URL_SAFE_NO_PAD.decode(&request.authenticator_data).unwrap();
        auth_bytes[33] ^= 0xFF; // flip flags byte
        request.authenticator_data = URL_SAFE_NO_PAD.encode(&auth_bytes);

        // Should fail either on UP check or signature verification
        let result = verify_assertion(TEST_CONTRACT_ID, &challenge_b64, &request);
        assert!(result.is_err());
    }
}
