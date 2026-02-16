// P-256 curve order
const P256_N =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P256_N_HALF = P256_N / 2n;

/**
 * Convert an ASN.1 DER-encoded ECDSA signature to 64-byte compact form (r || s)
 * with P-256 low-S normalization as required by Stellar.
 *
 * @see https://github.com/stellar/stellar-protocol/discussions/1435#discussioncomment-8809175
 */
export function derToCompact(derSignature: Uint8Array): Uint8Array {
  const der = new Uint8Array(derSignature);
  if (der[0] !== 0x30) throw new Error("Invalid DER signature");

  let offset = 2; // skip SEQUENCE tag + length

  // Parse r
  if (der[offset] !== 0x02) throw new Error("Expected INTEGER tag for r");
  offset++;
  const rLen = der[offset];
  offset++;
  const rRaw = der.slice(offset, offset + rLen);
  offset += rLen;

  // Parse s
  if (der[offset] !== 0x02) throw new Error("Expected INTEGER tag for s");
  offset++;
  const sLen = der[offset];
  offset++;
  const sRaw = der.slice(offset, offset + sLen);

  // Pad/trim to 32 bytes
  const r = padOrTrimTo32(rRaw);
  const s = padOrTrimTo32(sRaw);

  // Enforce low-S (Stellar requirement)
  let sBigInt = bufToBigInt(s);
  const compact = new Uint8Array(64);
  compact.set(r, 0);

  if (sBigInt > P256_N_HALF) {
    sBigInt = P256_N - sBigInt;
    compact.set(bigIntToBuf32(sBigInt), 32);
  } else {
    compact.set(s, 32);
  }

  return compact;
}

function padOrTrimTo32(raw: Uint8Array): Uint8Array {
  const out = new Uint8Array(32);
  if (raw.length <= 32) {
    out.set(raw, 32 - raw.length);
  } else {
    out.set(raw.slice(raw.length - 32));
  }
  return out;
}

function bufToBigInt(buf: Uint8Array): bigint {
  let hex = "";
  for (const b of buf) hex += b.toString(16).padStart(2, "0");
  return BigInt("0x" + hex);
}

function bigIntToBuf32(n: bigint): Uint8Array {
  const hex = n.toString(16).padStart(64, "0");
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}
