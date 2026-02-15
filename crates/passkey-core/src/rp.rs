use sha2::{Digest, Sha256};

const RP_SUFFIX: &str = "sorobancontracts.com";

/// Generates the `WebAuthn` Relying Party ID for a given contract ID.
///
/// Format: `{contractId}.sorobancontracts.com`
#[must_use]
pub fn rp_id(contract_id: &str) -> String {
    format!("{contract_id}.{RP_SUFFIX}")
}

/// Computes the SHA-256 hash of the RP ID, used for comparing against
/// the rpIdHash in authenticatorData.
#[must_use]
pub fn rp_id_hash(contract_id: &str) -> [u8; 32] {
    let id = rp_id(contract_id);
    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    hasher.finalize().into()
}

/// Returns the expected origin URL for a given contract ID.
///
/// Format: `https://{contractId}.sorobancontracts.com`
#[must_use]
pub fn expected_origin(contract_id: &str) -> String {
    format!("https://{}", rp_id(contract_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rp_id_format() {
        let id = rp_id("CABC123");
        assert_eq!(id, "CABC123.sorobancontracts.com");
    }

    #[test]
    fn rp_id_hash_deterministic() {
        let hash1 = rp_id_hash("CABC123");
        let hash2 = rp_id_hash("CABC123");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn rp_id_hash_differs_for_different_contracts() {
        let hash1 = rp_id_hash("CABC123");
        let hash2 = rp_id_hash("CDEF456");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn rp_id_hash_is_sha256() {
        use sha2::{Digest, Sha256};
        let contract_id = "CABC123";
        let expected = {
            let mut h = Sha256::new();
            h.update(b"CABC123.sorobancontracts.com");
            let result: [u8; 32] = h.finalize().into();
            result
        };
        assert_eq!(rp_id_hash(contract_id), expected);
    }

    #[test]
    fn expected_origin_format() {
        let origin = expected_origin("CABC123");
        assert_eq!(origin, "https://CABC123.sorobancontracts.com");
    }
}
