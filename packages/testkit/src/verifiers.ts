// The verifier contracts a Nido account's signers point at. Each `Signer` is
// `External(verifier, key)`, and `check_auth` calls `verifier.verify(digest,
// key, sig)`. Only secp256r1 has a deployed verifier today; ed25519 and
// ML-DSA-65 are modelled here ahead of their on-chain contracts (see `onChain`)
// so the testkit can demonstrate the target multi-verifier account.

import { ed25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { StrKey } from '@stellar/stellar-sdk';
import type { Algorithm } from './crypto.js';
import { verifySyntheticAssertion, type SyntheticAssertion } from './auth.js';

/** The data an `External` signer contributes to the auth payload: a raw
 *  signature (ed25519 / ML-DSA) or a WebAuthn assertion (secp256r1). */
export type SignatureData =
  | { kind: 'raw'; bytes: Uint8Array }
  | { kind: 'webauthn'; assertion: SyntheticAssertion };

export interface VerifierInfo {
  algorithm: Algorithm;
  address: string;
  /** Whether a verifier contract for this algorithm is deployed on-chain today.
   *  ed25519 and ML-DSA are simulated ahead of their contracts. */
  onChain: boolean;
  label: string;
  note?: string;
}

/** Deterministic placeholder C-address for a verifier that isn't deployed yet. */
function simAddress(name: string): string {
  return StrKey.encodeContract(Buffer.from(sha256(new TextEncoder().encode(`nido-testkit:${name}`))));
}

export const VERIFIERS: Record<Algorithm, VerifierInfo> = {
  secp256r1: {
    algorithm: 'secp256r1',
    // The real, deployed stateless webauthn-verifier (registry fallback).
    address: 'CACVGSAHYFBXY4LJKWW5B57LAAXHCZVDZOANUTYPLNV6HHQI4Q35EGMY',
    onChain: true,
    label: 'WebAuthn / secp256r1',
    note: 'Deployed webauthn-verifier; here driven by a local P-256 key instead of a passkey.',
  },
  ed25519: {
    algorithm: 'ed25519',
    address: simAddress('ed25519-verifier'),
    onChain: false,
    label: 'ed25519',
    note: 'No External ed25519 verifier on-chain yet; simulated. Classic accounts sign via Delegated today.',
  },
  'ml-dsa-65': {
    algorithm: 'ml-dsa-65',
    address: simAddress('ml-dsa-65-verifier'),
    onChain: false,
    label: 'ML-DSA-65 (post-quantum)',
    note: 'Groundwork in nido#143; simulated here ahead of the guest-wasm verifier contract.',
  },
};

/** Verify a signature the way the algorithm's verifier contract would. */
export function verifySignature(
  algorithm: Algorithm,
  authDigest: Uint8Array,
  publicKey: Uint8Array,
  sig: SignatureData,
): boolean {
  switch (algorithm) {
    case 'ed25519':
      return sig.kind === 'raw' && ed25519.verify(sig.bytes, authDigest, publicKey);
    case 'ml-dsa-65':
      return sig.kind === 'raw' && ml_dsa65.verify(sig.bytes, authDigest, publicKey);
    case 'secp256r1':
      return sig.kind === 'webauthn' && verifySyntheticAssertion(authDigest, publicKey, sig.assertion);
  }
}

// re-export so consumers don't need a second import for the raw p256 type
export { p256 };
