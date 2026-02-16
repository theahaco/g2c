import type { PasskeyRegistration } from "./types.js";
interface WebAuthnAttestationResponse {
    getPublicKey(): ArrayBuffer | null;
    attestationObject: ArrayBuffer;
}
interface WebAuthnCredential {
    rawId: ArrayBuffer;
    response: WebAuthnAttestationResponse;
}
/**
 * Extract 65-byte uncompressed P-256 public key from an AuthenticatorAttestationResponse.
 *
 * Uses the standard `getPublicKey()` method which returns SPKI-encoded key data.
 * The last 65 bytes are the uncompressed point (0x04 || x || y).
 */
export declare function extractPublicKey(response: WebAuthnAttestationResponse): Uint8Array;
/**
 * Parse the attestationObject (base64url-encoded) to extract the P-256 public key.
 *
 * Fallback for environments where `getPublicKey()` is unavailable
 * (e.g. Capacitor/mobile WebView). Performs minimal inline CBOR parsing of the
 * authData within the attestation object.
 */
export declare function parseAttestationObject(attestationObjectB64u: string): Uint8Array;
/**
 * Compute a deterministic contract salt from a credential ID.
 * Returns SHA-256 hash of the credential ID bytes as a Buffer.
 */
export declare function getContractSalt(credentialId: Uint8Array): Buffer;
/**
 * Full registration helper: extract public key and contract salt from a WebAuthn registration.
 *
 * Tries `getPublicKey()` first, falls back to attestationObject CBOR parsing.
 */
export declare function parseRegistration(credential: WebAuthnCredential): PasskeyRegistration;
export {};
//# sourceMappingURL=webauthn.d.ts.map