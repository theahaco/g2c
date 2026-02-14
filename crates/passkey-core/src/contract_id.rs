use crate::error::Error;

/// Validates a Stellar Soroban contract ID (C-address).
///
/// A valid contract ID:
/// - Starts with 'C'
/// - Is exactly 56 characters long
/// - Contains only valid base32 characters (A-Z, 2-7)
pub fn validate_contract_id(contract_id: &str) -> Result<(), Error> {
    if !contract_id.starts_with('C') {
        return Err(Error::InvalidContractId(
            "must start with 'C'".to_string(),
        ));
    }

    if contract_id.len() != 56 {
        return Err(Error::InvalidContractId(format!(
            "must be 56 characters, got {}",
            contract_id.len()
        )));
    }

    // Stellar uses base32 encoding (RFC 4648) for addresses
    if !contract_id[1..].chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7')) {
        return Err(Error::InvalidContractId(
            "contains invalid base32 characters".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_contract_id() {
        // 'C' + 55 valid base32 chars
        let id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(validate_contract_id(id).is_ok());
    }

    #[test]
    fn valid_contract_id_mixed_chars() {
        let id = "CABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVW";
        assert!(validate_contract_id(id).is_ok());
    }

    #[test]
    fn rejects_g_address() {
        let id = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let err = validate_contract_id(id).unwrap_err();
        assert!(err.to_string().contains("must start with 'C'"));
    }

    #[test]
    fn rejects_too_short() {
        let id = "CAAAA";
        let err = validate_contract_id(id).unwrap_err();
        assert!(err.to_string().contains("must be 56 characters"));
    }

    #[test]
    fn rejects_too_long() {
        let id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let err = validate_contract_id(id).unwrap_err();
        assert!(err.to_string().contains("must be 56 characters"));
    }

    #[test]
    fn rejects_invalid_base32_chars() {
        // '0', '1', '8', '9' and lowercase are not valid base32
        let id = "C0000000000000000000000000000000000000000000000000000000";
        let err = validate_contract_id(id).unwrap_err();
        assert!(err.to_string().contains("invalid base32"));
    }

    #[test]
    fn rejects_lowercase() {
        let id = "Caaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let err = validate_contract_id(id).unwrap_err();
        assert!(err.to_string().contains("invalid base32"));
    }
}
