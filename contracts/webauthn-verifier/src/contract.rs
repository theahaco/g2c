use soroban_sdk::{contract, contractimpl, Bytes, BytesN, Env};
use stellar_accounts::verifiers::{
    webauthn::{self, WebAuthnSigData},
    Verifier,
};

#[contract]
pub struct WebAuthnVerifier;

#[contractimpl]
impl Verifier for WebAuthnVerifier {
    type KeyData = BytesN<65>;
    type SigData = WebAuthnSigData;

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
        webauthn::verify(e, &signature_payload, &key_data, &sig_data)
    }
}
