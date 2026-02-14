use stellar_strkey::Contract;

use crate::error::Error;

/// Validates a Stellar Soroban contract ID (C-address) using stellar-strkey.
///
/// Performs full strkey validation: base32 decoding, version byte check,
/// CRC16 checksum verification, and 32-byte payload length check.
pub fn validate_contract_id(contract_id: &str) -> Result<(), Error> {
    Contract::from_string(contract_id)
        .map_err(|_| Error::InvalidContractId(format!("invalid strkey: {contract_id}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valid contract IDs generated from stellar-strkey (with correct checksums)
    const VALID_ZEROS: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
    const VALID_ONES: &str = "CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526";

    #[test]
    fn valid_contract_id() {
        assert!(validate_contract_id(VALID_ZEROS).is_ok());
    }

    #[test]
    fn valid_contract_id_alternate() {
        assert!(validate_contract_id(VALID_ONES).is_ok());
    }

    #[test]
    fn rejects_g_address() {
        // A G-address is a valid strkey but not a contract
        let g_addr = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
        assert!(validate_contract_id(g_addr).is_err());
    }

    #[test]
    fn rejects_too_short() {
        assert!(validate_contract_id("CAAAA").is_err());
    }

    #[test]
    fn rejects_too_long() {
        let long = format!("{}AA", VALID_ZEROS);
        assert!(validate_contract_id(&long).is_err());
    }

    #[test]
    fn rejects_bad_checksum() {
        // Flip last char to break checksum
        let mut bad = VALID_ZEROS.to_string();
        bad.pop();
        bad.push('A');
        assert!(validate_contract_id(&bad).is_err());
    }

    #[test]
    fn rejects_invalid_chars() {
        assert!(
            validate_contract_id("C000000000000000000000000000000000000000000000000000000")
                .is_err()
        );
    }

    #[test]
    fn rejects_lowercase() {
        let lower = VALID_ZEROS.to_lowercase();
        assert!(validate_contract_id(&lower).is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_contract_id("").is_err());
    }
}
