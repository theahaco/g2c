use soroban_sdk::{contract, contractimpl, xdr::FromXdr, Bytes, BytesN, Env};
use stellar_accounts::verifiers::{
    utils::extract_from_bytes,
    webauthn::{self, WebAuthnSigData},
    Verifier,
};

#[contract]
pub struct WebAuthnVerifier;

#[contractimpl]
impl Verifier for WebAuthnVerifier {
    type KeyData = Bytes;
    type SigData = Bytes;

    /// Verify a WebAuthn signature against a message and public key.
    ///
    /// # Arguments
    ///
    /// * `signature_payload` - The message hash that was signed
    /// * `key_data` - Bytes containing:
    ///   - 65-byte secp256r1 public key (uncompressed format)
    ///   - Variable length credential ID (used on the client side)
    /// * `sig_data` - XDR-encoded `WebAuthnSigData` structure containing:
    ///   - Authenticator data
    ///   - Client data JSON
    ///   - Signature components
    ///
    /// # Returns
    ///
    /// * `true` if the signature is valid
    /// * `false` otherwise
    fn verify(
        e: &Env,
        signature_payload: Bytes,
        key_data: Self::KeyData,
        sig_data: Self::SigData,
    ) -> bool {
        let sig_struct =
            WebAuthnSigData::from_xdr(e, &sig_data).expect("WebAuthnSigData with correct format");

        let pub_key: BytesN<65> =
            extract_from_bytes(e, &key_data, 0..65).expect("65-byte public key to be extracted");

        webauthn::verify(e, &signature_payload, &pub_key, &sig_struct)
    }
}
