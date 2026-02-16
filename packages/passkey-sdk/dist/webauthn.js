import { hash } from "@stellar/stellar-sdk";
/**
 * Extract 65-byte uncompressed P-256 public key from an AuthenticatorAttestationResponse.
 *
 * Uses the standard `getPublicKey()` method which returns SPKI-encoded key data.
 * The last 65 bytes are the uncompressed point (0x04 || x || y).
 */
export function extractPublicKey(response) {
    const publicKeyDer = response.getPublicKey();
    if (!publicKeyDer) {
        throw new Error("No public key in attestation response");
    }
    const spki = new Uint8Array(publicKeyDer);
    // SPKI for P-256 uncompressed: the last 65 bytes are 04 || x (32) || y (32)
    const rawKey = spki.slice(-65);
    if (rawKey[0] !== 0x04) {
        throw new Error("Expected uncompressed P-256 key (0x04 prefix)");
    }
    return rawKey;
}
/**
 * Parse the attestationObject (base64url-encoded) to extract the P-256 public key.
 *
 * Fallback for environments where `getPublicKey()` is unavailable
 * (e.g. Capacitor/mobile WebView). Performs minimal inline CBOR parsing of the
 * authData within the attestation object.
 */
export function parseAttestationObject(attestationObjectB64u) {
    const raw = base64urlToBuffer(attestationObjectB64u);
    const authData = extractAuthDataFromCbor(raw);
    return extractPublicKeyFromAuthData(authData);
}
/**
 * Compute a deterministic contract salt from a credential ID.
 * Returns SHA-256 hash of the credential ID bytes as a Buffer.
 */
export function getContractSalt(credentialId) {
    return hash(Buffer.from(credentialId));
}
/**
 * Full registration helper: extract public key and contract salt from a WebAuthn registration.
 *
 * Tries `getPublicKey()` first, falls back to attestationObject CBOR parsing.
 */
export function parseRegistration(credential) {
    const credentialId = new Uint8Array(credential.rawId);
    let publicKey;
    try {
        publicKey = extractPublicKey(credential.response);
    }
    catch {
        // Fallback: parse attestationObject CBOR (mobile/Capacitor)
        const attestationB64u = bufferToBase64url(new Uint8Array(credential.response.attestationObject));
        publicKey = parseAttestationObject(attestationB64u);
    }
    return { publicKey, credentialId };
}
// --- base64url helpers (no dependencies) ---
function base64urlToBuffer(str) {
    let b64 = str.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4)
        b64 += "=";
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++)
        bytes[i] = binary.charCodeAt(i);
    return bytes;
}
function bufferToBase64url(buf) {
    let binary = "";
    for (const b of buf)
        binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
// --- Minimal CBOR parsing for attestationObject ---
/**
 * Extract authData from a CBOR-encoded attestationObject.
 * Only handles the subset of CBOR needed for WebAuthn attestation objects
 * (map with text keys, byte string values).
 */
function extractAuthDataFromCbor(data) {
    let offset = 0;
    function readByte() {
        return data[offset++];
    }
    function readUint16() {
        const val = (data[offset] << 8) | data[offset + 1];
        offset += 2;
        return val;
    }
    function readUint32() {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        const val = view.getUint32(offset, false);
        offset += 4;
        return val;
    }
    function readLength(additionalInfo) {
        if (additionalInfo < 24)
            return additionalInfo;
        if (additionalInfo === 24)
            return readByte();
        if (additionalInfo === 25)
            return readUint16();
        if (additionalInfo === 26)
            return readUint32();
        throw new Error(`Unsupported CBOR length encoding: ${additionalInfo}`);
    }
    function readString(len) {
        const bytes = data.slice(offset, offset + len);
        offset += len;
        return new TextDecoder().decode(bytes);
    }
    function readBytes(len) {
        const bytes = data.slice(offset, offset + len);
        offset += len;
        return bytes;
    }
    function skipValue() {
        const initial = readByte();
        const majorType = initial >> 5;
        const additionalInfo = initial & 0x1f;
        switch (majorType) {
            case 0: // unsigned int
            case 1: // negative int
                readLength(additionalInfo);
                break;
            case 2: { // byte string
                const len = readLength(additionalInfo);
                offset += len;
                break;
            }
            case 3: { // text string
                const len = readLength(additionalInfo);
                offset += len;
                break;
            }
            case 4: { // array
                const len = readLength(additionalInfo);
                for (let i = 0; i < len; i++)
                    skipValue();
                break;
            }
            case 5: { // map
                const len = readLength(additionalInfo);
                for (let i = 0; i < len; i++) {
                    skipValue();
                    skipValue();
                }
                break;
            }
            case 7: // simple/float
                readLength(additionalInfo);
                break;
            default:
                throw new Error(`Unsupported CBOR major type: ${majorType}`);
        }
    }
    // The attestationObject is a CBOR map at the top level
    const initial = readByte();
    const majorType = initial >> 5;
    const additionalInfo = initial & 0x1f;
    if (majorType !== 5)
        throw new Error("Expected CBOR map for attestationObject");
    const mapLen = readLength(additionalInfo);
    for (let i = 0; i < mapLen; i++) {
        // Read key (expected to be a text string)
        const keyInitial = readByte();
        const keyMajor = keyInitial >> 5;
        const keyAdditional = keyInitial & 0x1f;
        if (keyMajor !== 3) {
            // Not a text string key, skip key and value
            offset--; // re-read
            skipValue();
            skipValue();
            continue;
        }
        const keyLen = readLength(keyAdditional);
        const key = readString(keyLen);
        if (key === "authData") {
            // Read byte string value
            const valInitial = readByte();
            const valAdditional = valInitial & 0x1f;
            const valLen = readLength(valAdditional);
            return readBytes(valLen);
        }
        else {
            skipValue();
        }
    }
    throw new Error("authData not found in attestationObject");
}
/**
 * Extract 65-byte P-256 public key from authData bytes.
 * Parses the attested credential data section within authData.
 */
function extractPublicKeyFromAuthData(authData) {
    const view = new DataView(authData.buffer, authData.byteOffset, authData.byteLength);
    let offset = 0;
    // RP ID Hash (32 bytes)
    offset += 32;
    // Flags (1 byte)
    const flags = authData[offset];
    offset += 1;
    // Sign Count (4 bytes)
    offset += 4;
    // Check AT (attested credential data) flag
    if (!(flags & 0x40)) {
        throw new Error("Attested credential data not present in authData flags");
    }
    // AAGUID (16 bytes)
    offset += 16;
    // Credential ID Length (2 bytes, big-endian)
    const credIdLength = view.getUint16(offset, false);
    offset += 2;
    // Credential ID (variable)
    offset += credIdLength;
    // Credential Public Key (CBOR-encoded COSE key, ~77 bytes for P-256)
    const coseKeyBytes = authData.slice(offset, offset + 77);
    return extractP256FromCoseKey(coseKeyBytes);
}
/**
 * Extract x, y coordinates from a COSE-encoded P-256 public key and return
 * as 65-byte uncompressed point (0x04 || x || y).
 */
function extractP256FromCoseKey(coseBytes) {
    let offset = 0;
    let x;
    let y;
    function readByte() {
        return coseBytes[offset++];
    }
    function readLength(additional) {
        if (additional < 24)
            return additional;
        if (additional === 24)
            return readByte();
        throw new Error("Unexpected CBOR length in COSE key");
    }
    const initial = readByte();
    const majorType = initial >> 5;
    const additionalInfo = initial & 0x1f;
    if (majorType !== 5)
        throw new Error("Expected CBOR map for COSE key");
    const mapLen = readLength(additionalInfo);
    for (let i = 0; i < mapLen; i++) {
        // Read key (COSE keys use negative integers for -2, -3)
        const keyByte = readByte();
        const keyMajor = keyByte >> 5;
        const keyAdditional = keyByte & 0x1f;
        let keyVal;
        if (keyMajor === 0) {
            // Positive integer
            keyVal = readLength(keyAdditional);
        }
        else if (keyMajor === 1) {
            // Negative integer: -1 - n
            keyVal = -1 - readLength(keyAdditional);
        }
        else {
            throw new Error(`Unexpected CBOR key type in COSE key: ${keyMajor}`);
        }
        // Read value
        const valByte = readByte();
        const valMajor = valByte >> 5;
        const valAdditional = valByte & 0x1f;
        if (valMajor === 2) {
            // Byte string
            const len = readLength(valAdditional);
            const bytes = coseBytes.slice(offset, offset + len);
            offset += len;
            if (keyVal === -2)
                x = bytes;
            else if (keyVal === -3)
                y = bytes;
        }
        else if (valMajor === 0) {
            // Positive integer (e.g. kty=2, alg=-7, crv=1)
            readLength(valAdditional);
        }
        else if (valMajor === 1) {
            // Negative integer
            readLength(valAdditional);
        }
        else {
            throw new Error(`Unexpected CBOR value type in COSE key: ${valMajor}`);
        }
    }
    if (!x || !y) {
        throw new Error("Could not extract x, y from COSE key");
    }
    const publicKey = new Uint8Array(65);
    publicKey[0] = 0x04;
    publicKey.set(x, 1);
    publicKey.set(y, 33);
    return publicKey;
}
//# sourceMappingURL=webauthn.js.map