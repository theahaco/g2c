use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default challenge TTL: 5 minutes.
pub const CHALLENGE_TTL: Duration = Duration::from_secs(300);

/// A WebAuthn challenge with metadata for storage and validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// The raw 32-byte challenge, base64url-encoded.
    pub challenge: String,
    /// Unique identifier for this challenge.
    pub challenge_id: String,
    /// The contract ID this challenge is bound to.
    pub contract_id: String,
    /// Unix timestamp when the challenge was created.
    pub created_at: u64,
}

impl Challenge {
    /// Generates a new random challenge for the given contract ID.
    pub fn new(contract_id: &str) -> Self {
        let mut challenge_bytes = [0u8; 32];
        getrandom::getrandom(&mut challenge_bytes).expect("getrandom failed");

        let mut id_bytes = [0u8; 16];
        getrandom::getrandom(&mut id_bytes).expect("getrandom failed");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs();

        Challenge {
            challenge: URL_SAFE_NO_PAD.encode(challenge_bytes),
            challenge_id: URL_SAFE_NO_PAD.encode(id_bytes),
            contract_id: contract_id.to_string(),
            created_at: now,
        }
    }

    /// Returns the storage key for this challenge.
    pub fn storage_key(&self) -> String {
        format!(
            "challenge:{}:{}",
            self.contract_id, self.challenge_id
        )
    }

    /// Checks whether the challenge has expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs();
        now - self.created_at > CHALLENGE_TTL.as_secs()
    }

    /// Decodes the challenge bytes from the base64url string.
    pub fn challenge_bytes(&self) -> Result<Vec<u8>, base64::DecodeError> {
        URL_SAFE_NO_PAD.decode(&self.challenge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_challenge_has_correct_contract_id() {
        let c = Challenge::new("CABC123");
        assert_eq!(c.contract_id, "CABC123");
    }

    #[test]
    fn challenge_bytes_are_32_bytes() {
        let c = Challenge::new("CABC123");
        let bytes = c.challenge_bytes().unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn challenge_id_is_nonempty() {
        let c = Challenge::new("CABC123");
        assert!(!c.challenge_id.is_empty());
    }

    #[test]
    fn two_challenges_are_different() {
        let c1 = Challenge::new("CABC123");
        let c2 = Challenge::new("CABC123");
        assert_ne!(c1.challenge, c2.challenge);
        assert_ne!(c1.challenge_id, c2.challenge_id);
    }

    #[test]
    fn storage_key_format() {
        let c = Challenge::new("CABC123");
        let key = c.storage_key();
        assert!(key.starts_with("challenge:CABC123:"));
    }

    #[test]
    fn fresh_challenge_is_not_expired() {
        let c = Challenge::new("CABC123");
        assert!(!c.is_expired());
    }

    #[test]
    fn old_challenge_is_expired() {
        let mut c = Challenge::new("CABC123");
        // Set created_at to 10 minutes ago
        c.created_at -= 600;
        assert!(c.is_expired());
    }
}
