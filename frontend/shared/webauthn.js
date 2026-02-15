// --- Shared WebAuthn utilities ---

function buf2hex(buffer) {
  return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function hex2buf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function buf2base64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64url2buf(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// P-256 curve order
const P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n;
const P256_N_HALF = P256_N / 2n;

function bufToBigInt(buf) {
  return BigInt('0x' + buf2hex(buf));
}

function bigIntToBuf32(n) {
  const hex = n.toString(16).padStart(64, '0');
  return hex2buf(hex);
}

// Convert ASN.1 DER ECDSA signature to compact 64-byte (r || s) with low-S
function derToCompact(derBuf) {
  const der = new Uint8Array(derBuf);
  if (der[0] !== 0x30) throw new Error('Invalid DER signature');

  let offset = 2; // skip 30 <len>

  // Parse r
  if (der[offset] !== 0x02) throw new Error('Expected integer tag for r');
  offset++;
  const rLen = der[offset]; offset++;
  const rRaw = der.slice(offset, offset + rLen); offset += rLen;

  // Parse s
  if (der[offset] !== 0x02) throw new Error('Expected integer tag for s');
  offset++;
  const sLen = der[offset]; offset++;
  const sRaw = der.slice(offset, offset + sLen);

  // Pad/trim to 32 bytes
  const r = new Uint8Array(32);
  const s = new Uint8Array(32);

  if (rRaw.length <= 32) {
    r.set(rRaw, 32 - rRaw.length);
  } else {
    r.set(rRaw.slice(rRaw.length - 32));
  }

  if (sRaw.length <= 32) {
    s.set(sRaw, 32 - sRaw.length);
  } else {
    s.set(sRaw.slice(sRaw.length - 32));
  }

  // Enforce low-S (Stellar requirement)
  let sBigInt = bufToBigInt(s);
  if (sBigInt > P256_N_HALF) {
    sBigInt = P256_N - sBigInt;
    const sLow = bigIntToBuf32(sBigInt);
    const compact = new Uint8Array(64);
    compact.set(r, 0);
    compact.set(sLow, 32);
    return compact;
  }

  const compact = new Uint8Array(64);
  compact.set(r, 0);
  compact.set(s, 32);
  return compact;
}

// Extract 65-byte P-256 public key from AuthenticatorAttestationResponse
function extractPublicKey(response) {
  const spki = new Uint8Array(response.getPublicKey());
  const rawKey = spki.slice(-65);
  if (rawKey[0] !== 0x04) throw new Error('Expected uncompressed P-256 key (0x04 prefix)');
  return rawKey;
}
