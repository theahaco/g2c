use crate::error::Error;

/// Minimum authenticatorData length: 32 (rpIdHash) + 1 (flags) + 4 (signCount) = 37 bytes.
const MIN_AUTH_DATA_LEN: usize = 37;

/// Flags byte bit positions.
const FLAG_UP: u8 = 0x01; // User Present
const FLAG_UV: u8 = 0x04; // User Verified

/// Parsed authenticatorData from a `WebAuthn` assertion.
#[derive(Debug)]
pub struct AuthenticatorData {
    /// SHA-256 hash of the RP ID (32 bytes).
    pub rp_id_hash: [u8; 32],
    /// Raw flags byte.
    pub flags: u8,
    /// Signature counter (big-endian u32).
    pub sign_count: u32,
}

impl AuthenticatorData {
    /// Parse authenticatorData from raw bytes.
    ///
    /// Layout (per `WebAuthn` spec):
    /// - bytes [0..32]:  rpIdHash (SHA-256 of RP ID)
    /// - byte  [32]:     flags
    /// - bytes [33..37]: signCount (big-endian u32)
    /// - bytes [37..]:   optional extensions (ignored for assertions)
    ///
    /// # Errors
    /// Returns an error if the data is too short or malformed.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() < MIN_AUTH_DATA_LEN {
            return Err(Error::InvalidAuthenticatorData(format!(
                "too short: {} bytes, need at least {}",
                data.len(),
                MIN_AUTH_DATA_LEN,
            )));
        }

        let mut rp_id_hash = [0u8; 32];
        rp_id_hash.copy_from_slice(&data[0..32]);

        let flags = data[32];

        let sign_count = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);

        Ok(AuthenticatorData {
            rp_id_hash,
            flags,
            sign_count,
        })
    }

    /// Returns true if the User Present (UP) flag is set.
    #[must_use]
    pub fn user_present(&self) -> bool {
        self.flags & FLAG_UP != 0
    }

    /// Returns true if the User Verified (UV) flag is set.
    #[must_use]
    pub fn user_verified(&self) -> bool {
        self.flags & FLAG_UV != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn make_auth_data(rp_id: &str, flags: u8, sign_count: u32) -> Vec<u8> {
        let rp_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&rp_hash);
        data.push(flags);
        data.extend_from_slice(&sign_count.to_be_bytes());
        data
    }

    #[test]
    fn parse_valid_auth_data() {
        let rp_id = "test.sorobancontracts.com";
        let data = make_auth_data(rp_id, 0x05, 42); // UP + UV flags

        let parsed = AuthenticatorData::parse(&data).unwrap();

        let expected_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
        assert_eq!(parsed.rp_id_hash, expected_hash);
        assert_eq!(parsed.flags, 0x05);
        assert_eq!(parsed.sign_count, 42);
        assert!(parsed.user_present());
        assert!(parsed.user_verified());
    }

    #[test]
    fn parse_up_only() {
        let data = make_auth_data("test.example.com", 0x01, 0);
        let parsed = AuthenticatorData::parse(&data).unwrap();
        assert!(parsed.user_present());
        assert!(!parsed.user_verified());
    }

    #[test]
    fn parse_no_flags() {
        let data = make_auth_data("test.example.com", 0x00, 0);
        let parsed = AuthenticatorData::parse(&data).unwrap();
        assert!(!parsed.user_present());
        assert!(!parsed.user_verified());
    }

    #[test]
    fn rejects_too_short() {
        let data = vec![0u8; 36]; // one byte too short
        let err = AuthenticatorData::parse(&data).unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn accepts_extra_bytes() {
        // authenticatorData can have extensions appended
        let mut data = make_auth_data("test.example.com", 0x01, 1);
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // extra extension bytes
        let parsed = AuthenticatorData::parse(&data).unwrap();
        assert_eq!(parsed.sign_count, 1);
    }

    #[test]
    fn sign_count_big_endian() {
        let data = make_auth_data("test.example.com", 0x01, 0x0102_0304);
        let parsed = AuthenticatorData::parse(&data).unwrap();
        assert_eq!(parsed.sign_count, 0x0102_0304);
    }
}
