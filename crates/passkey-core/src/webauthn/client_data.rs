use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;

use crate::error::Error;

/// Parsed and validated clientDataJSON from a `WebAuthn` assertion.
#[derive(Debug, Deserialize)]
pub struct ClientData {
    /// Must be "webauthn.get" for assertions.
    #[serde(rename = "type")]
    pub typ: String,
    /// Base64url-encoded challenge.
    pub challenge: String,
    /// The origin (scheme + host) the assertion was made from.
    pub origin: String,
    /// Optional cross-origin flag.
    #[serde(rename = "crossOrigin", default)]
    pub cross_origin: bool,
}

impl ClientData {
    /// Parse clientDataJSON from raw bytes.
    ///
    /// # Errors
    /// Returns an error if the JSON is invalid or missing required fields.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        serde_json::from_slice(data).map_err(|e| Error::InvalidClientData(e.to_string()))
    }

    /// Validate the clientDataJSON fields against expected values.
    ///
    /// # Errors
    /// Returns an error if the type, challenge, or origin does not match.
    pub fn validate(
        &self,
        expected_challenge_b64: &str,
        expected_origin: &str,
    ) -> Result<(), Error> {
        // Check type
        if self.typ != "webauthn.get" {
            return Err(Error::InvalidClientData(format!(
                "expected type 'webauthn.get', got '{}'",
                self.typ
            )));
        }

        // Check challenge matches
        if self.challenge != expected_challenge_b64 {
            return Err(Error::ChallengeMismatch);
        }

        // Check origin matches
        if self.origin != expected_origin {
            return Err(Error::OriginMismatch {
                expected: expected_origin.to_string(),
                actual: self.origin.clone(),
            });
        }

        Ok(())
    }

    /// Decode the challenge from base64url to raw bytes.
    ///
    /// # Errors
    /// Returns an error if the base64url decoding fails.
    pub fn challenge_bytes(&self) -> Result<Vec<u8>, Error> {
        URL_SAFE_NO_PAD
            .decode(&self.challenge)
            .map_err(|e| Error::InvalidClientData(format!("invalid challenge encoding: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_client_data_json(typ: &str, challenge: &str, origin: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "type": typ,
            "challenge": challenge,
            "origin": origin,
        }))
        .unwrap()
    }

    #[test]
    fn parse_valid_client_data() {
        let json = make_client_data_json(
            "webauthn.get",
            "dGVzdC1jaGFsbGVuZ2U",
            "https://test.sorobancontracts.com",
        );
        let cd = ClientData::parse(&json).unwrap();
        assert_eq!(cd.typ, "webauthn.get");
        assert_eq!(cd.challenge, "dGVzdC1jaGFsbGVuZ2U");
        assert_eq!(cd.origin, "https://test.sorobancontracts.com");
        assert!(!cd.cross_origin);
    }

    #[test]
    fn validate_correct_fields() {
        let json = make_client_data_json(
            "webauthn.get",
            "dGVzdC1jaGFsbGVuZ2U",
            "https://test.sorobancontracts.com",
        );
        let cd = ClientData::parse(&json).unwrap();
        cd.validate("dGVzdC1jaGFsbGVuZ2U", "https://test.sorobancontracts.com")
            .unwrap();
    }

    #[test]
    fn rejects_wrong_type() {
        let json = make_client_data_json(
            "webauthn.create",
            "dGVzdA",
            "https://test.sorobancontracts.com",
        );
        let cd = ClientData::parse(&json).unwrap();
        let err = cd
            .validate("dGVzdA", "https://test.sorobancontracts.com")
            .unwrap_err();
        assert!(err.to_string().contains("webauthn.get"));
    }

    #[test]
    fn rejects_wrong_challenge() {
        let json = make_client_data_json(
            "webauthn.get",
            "wrong-challenge",
            "https://test.sorobancontracts.com",
        );
        let cd = ClientData::parse(&json).unwrap();
        let err = cd
            .validate("correct-challenge", "https://test.sorobancontracts.com")
            .unwrap_err();
        assert!(matches!(err, Error::ChallengeMismatch));
    }

    #[test]
    fn rejects_wrong_origin() {
        let json = make_client_data_json("webauthn.get", "dGVzdA", "https://evil.example.com");
        let cd = ClientData::parse(&json).unwrap();
        let err = cd
            .validate("dGVzdA", "https://test.sorobancontracts.com")
            .unwrap_err();
        assert!(matches!(err, Error::OriginMismatch { .. }));
    }

    #[test]
    fn rejects_invalid_json() {
        let err = ClientData::parse(b"not json").unwrap_err();
        assert!(err.to_string().contains("invalid client data"));
    }

    #[test]
    fn decode_challenge_bytes() {
        let challenge_b64 = URL_SAFE_NO_PAD.encode(b"hello world");
        let json = make_client_data_json(
            "webauthn.get",
            &challenge_b64,
            "https://test.sorobancontracts.com",
        );
        let cd = ClientData::parse(&json).unwrap();
        assert_eq!(cd.challenge_bytes().unwrap(), b"hello world");
    }
}
