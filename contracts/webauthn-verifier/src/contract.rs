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

    /// Verify a `WebAuthn` (passkey) signature.
    ///
    /// # Arguments
    ///
    /// * `signature_payload` - The message hash that was signed
    /// * `key_data` - 65-byte uncompressed secp256r1 public key,
    ///   optionally followed by credential ID bytes
    /// * `sig_data` - XDR-encoded `WebAuthnSigData` containing:
    ///   - `signature`: 64-byte secp256r1 signature
    ///   - `authenticator_data`: raw authenticator data bytes
    ///   - `client_data`: raw client data JSON bytes
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
