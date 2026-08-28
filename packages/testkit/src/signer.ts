// A local signer: an in-process keypair bound to a verifier, that can produce
// the auth-payload signature over an account's auth digest — no passkey.

import { bytesToHex } from '@noble/hashes/utils.js';
import { generateKeypair, type Algorithm, type RawKeypair } from './crypto.js';
import { buildSyntheticAssertion } from './auth.js';
import { VERIFIERS, type SignatureData } from './verifiers.js';

export interface LocalSigner {
  readonly id: string;
  readonly algorithm: Algorithm;
  /** verifier contract C-address this signer's key is checked by. */
  readonly verifier: string;
  readonly publicKey: Uint8Array;
  readonly publicKeyHex: string;
  /** Sign the account's 32-byte auth digest, returning the payload signature. */
  signAuth(authDigest: Uint8Array): SignatureData;
}

export interface LocalSignerOptions {
  id: string;
  algorithm: Algorithm;
  /** Override the verifier address (defaults to the algorithm's verifier). */
  verifier?: string;
  /** Reuse an existing keypair instead of generating one. */
  keypair?: RawKeypair;
}

export function localSigner(opts: LocalSignerOptions): LocalSigner {
  const kp = opts.keypair ?? generateKeypair(opts.algorithm);
  const verifier = opts.verifier ?? VERIFIERS[opts.algorithm].address;
  return {
    id: opts.id,
    algorithm: opts.algorithm,
    verifier,
    publicKey: kp.publicKey,
    publicKeyHex: bytesToHex(kp.publicKey),
    signAuth(authDigest) {
      if (opts.algorithm === 'secp256r1') {
        // The webauthn-verifier consumes a WebAuthn assertion, not a raw sig.
        return { kind: 'webauthn', assertion: buildSyntheticAssertion(kp.secretKey, authDigest) };
      }
      return { kind: 'raw', bytes: kp.sign(authDigest) };
    },
  };
}
