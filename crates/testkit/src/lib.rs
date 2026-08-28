//! Rust dapp-author test fixtures for Nido — the contract-test twin of
//! `@nidohq/testkit`'s secp256r1 path.
//!
//! Gives a contract test a deterministic local P-256 key and a WebAuthn-shaped
//! assertion the `webauthn-verifier` accepts, with no authenticator. Mirrors
//! `buildSyntheticAssertion` in the TS testkit and `build_contract_assertion`
//! in `crates/integration-tests`.
//!
//! Pure crypto — no `soroban-sdk` dependency — so it drops into any test.
//! Composing the auth digest (`sha256(payload || xdr(context_rule_ids))`) and
//! deploying the account belong to the soroban-integrated harness; this crate
//! is the signer half every one of those tests needs.

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

/// A WebAuthn assertion built from a raw P-256 key.
#[derive(Clone, Debug)]
pub struct ContractAssertion {
    /// 37 bytes: 32-byte rpIdHash (zero — verifier skips it) + flags + counter.
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    /// 64-byte r‖s, low-S normalized.
    pub signature: Vec<u8>,
}

/// A deterministic P-256 signing key from a seed — reproducible across runs.
#[must_use]
pub fn test_p256_key(seed: u64) -> SigningKey {
    // Hash the seed until the 32 bytes are a valid, non-zero scalar (< n).
    let mut counter = 0u64;
    loop {
        let mut h = Sha256::new();
        h.update(b"nido-testkit:p256:");
        h.update(seed.to_le_bytes());
        h.update(counter.to_le_bytes());
        let bytes = h.finalize();
        if let Ok(key) = SigningKey::from_slice(&bytes) {
            return key;
        }
        counter += 1;
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// URL-safe base64 without padding (RFC 4648 §5), matching the TS testkit.
fn b64url(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let count = chunk.len();
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        if count > 1 {
            out.push(ALPHABET[((n >> 6) & 63) as usize] as char);
        }
        if count > 2 {
            out.push(ALPHABET[(n & 63) as usize] as char);
        }
    }
    out
}

/// Build a WebAuthn assertion over the 32-byte `payload` (the auth digest) with
/// `key`. The verifier reconstructs `sha256(authData || sha256(clientData))` and
/// checks the challenge equals `base64url(payload)`.
#[must_use]
pub fn build_contract_assertion(key: &SigningKey, payload: &[u8; 32]) -> ContractAssertion {
    let challenge = b64url(payload);
    let client_data_json = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge}\",\"origin\":\"https://example.com\",\"crossOrigin\":false}}"
    )
    .into_bytes();

    let mut authenticator_data = vec![0u8; 37];
    authenticator_data[32] = 0x1d; // UP|UV|BE|BS

    let cd_hash = sha256(&client_data_json);
    let mut msg = authenticator_data.clone();
    msg.extend_from_slice(&cd_hash);
    let digest = sha256(&msg);

    let mut sig: Signature = key.sign_prehash(&digest).expect("p256 prehash sign");
    if let Some(normalized) = sig.normalize_s() {
        sig = normalized; // Stellar contract auth requires low-S
    }

    ContractAssertion {
        authenticator_data,
        client_data_json,
        signature: sig.to_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::VerifyingKey;

    #[test]
    fn deterministic_key_is_reproducible() {
        assert_eq!(test_p256_key(7).to_bytes(), test_p256_key(7).to_bytes());
        assert_ne!(test_p256_key(7).to_bytes(), test_p256_key(8).to_bytes());
    }

    #[test]
    fn assertion_verifies_like_the_webauthn_verifier() {
        let key = test_p256_key(42);
        let payload = [0x11u8; 32];
        let a = build_contract_assertion(&key, &payload);

        // Reconstruct the signed digest and verify — what the verifier does.
        let mut msg = a.authenticator_data.clone();
        msg.extend_from_slice(&sha256(&a.client_data_json));
        let digest = sha256(&msg);

        let vk = VerifyingKey::from(&key);
        let sig = Signature::from_slice(&a.signature).unwrap();
        assert!(vk.verify_prehash(&digest, &sig).is_ok());

        // The challenge binds to the payload.
        let cd = String::from_utf8(a.client_data_json).unwrap();
        assert!(cd.contains(&b64url(&payload)));
    }
}
