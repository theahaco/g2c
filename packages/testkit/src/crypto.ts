// Local keypairs for every verifier a Nido account supports — generated and
// signing entirely in-process, with no WebAuthn passkey. Each algorithm maps to
// a verifier contract: secp256r1 → webauthn-verifier, ed25519 → the ed25519
// verifier path, ml-dsa-65 → the post-quantum verifier (nido#143).
//
// A `sign(digest)` takes the 32-byte auth digest a Nido account would ask a
// signer to sign and returns the raw signature bytes that verifier expects:
//  - ed25519    → 64-byte signature
//  - secp256r1  → 64-byte compact r‖s, low-S normalized (what the verifier wants)
//  - ml-dsa-65  → the ML-DSA-65 signature over the digest

import { ed25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from '@noble/hashes/utils.js';

export type Algorithm = 'ed25519' | 'secp256r1' | 'ml-dsa-65';

export interface RawKeypair {
  readonly algorithm: Algorithm;
  readonly secretKey: Uint8Array;
  /** Public key in the form the verifier canonicalizes: ed25519 32B, secp256r1
   *  65B uncompressed, ml-dsa-65 the encoded public key. */
  readonly publicKey: Uint8Array;
  /** Sign the 32-byte auth digest, returning raw verifier-shaped bytes. */
  sign(digest: Uint8Array): Uint8Array;
}

export function ed25519Keypair(secret?: Uint8Array): RawKeypair {
  const sk = secret ?? ed25519.utils.randomSecretKey();
  return {
    algorithm: 'ed25519',
    secretKey: sk,
    publicKey: ed25519.getPublicKey(sk),
    sign: (digest) => ed25519.sign(digest, sk),
  };
}

export function secp256r1Keypair(secret?: Uint8Array): RawKeypair {
  const sk = secret ?? p256.utils.randomSecretKey();
  return {
    algorithm: 'secp256r1',
    secretKey: sk,
    publicKey: p256.getPublicKey(sk, false), // 65-byte uncompressed, as the webauthn-verifier expects
    sign: (digest) => p256.sign(digest, sk, { prehash: false }), // 64-byte compact r‖s, low-S
  };
}

export function mlDsa65Keypair(seed?: Uint8Array): RawKeypair {
  const s = seed ?? randomBytes(32);
  const { publicKey, secretKey } = ml_dsa65.keygen(s);
  return {
    algorithm: 'ml-dsa-65',
    secretKey,
    publicKey,
    sign: (digest) => ml_dsa65.sign(digest, secretKey), // @noble: sign(message, secretKey)
  };
}

/** Generate a fresh local keypair for the given algorithm. */
export function generateKeypair(algorithm: Algorithm): RawKeypair {
  switch (algorithm) {
    case 'ed25519': return ed25519Keypair();
    case 'secp256r1': return secp256r1Keypair();
    case 'ml-dsa-65': return mlDsa65Keypair();
  }
}
