// The authorization digest a Nido account asks its signers to sign, and the
// WebAuthn-shaped assertion a secp256r1 signer produces. Ported from
// @nidohq/passkey-sdk (auth.ts / syntheticAssertion.ts) so the testkit stays
// self-contained and bundles cleanly for a static example.

import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { xdr, hash } from '@stellar/stellar-sdk';

/** A WebAuthn assertion built from a raw P-256 key — no authenticator. The
 *  webauthn-verifier checks `digest == sha256(authData || sha256(clientData))`
 *  and that the clientData challenge equals base64url(the auth digest). */
export interface SyntheticAssertion {
  authenticatorData: Uint8Array; // 37 bytes
  clientDataJSON: Uint8Array;
  signature: Uint8Array; // 64-byte r‖s, low-S
}

/** The digest every signer signs: `sha256(signature_payload || xdr(context_rule_ids))`.
 *  Mirrors OZ `do_check_auth` and the Rust `compute_auth_digest`. Binds the
 *  signature to the specific context rule (rule-substitution replay defense). */
export function computeAuthDigest(
  signaturePayload: Uint8Array,
  contextRuleIds: readonly number[] = [0],
): Uint8Array {
  const ctxIdsXdr = xdr.ScVal.scvVec(contextRuleIds.map((id) => xdr.ScVal.scvU32(id))).toXDR();
  const preimage = new Uint8Array(signaturePayload.length + ctxIdsXdr.length);
  preimage.set(signaturePayload, 0);
  preimage.set(ctxIdsXdr, signaturePayload.length);
  return Uint8Array.from(hash(Buffer.from(preimage)));
}

/** Build a WebAuthn assertion over `payload32` (the auth digest) with a raw
 *  P-256 scalar. Ported verbatim from passkey-sdk's `buildSyntheticAssertion`,
 *  using @noble sha256 so it is synchronous. */
export function buildSyntheticAssertion(privateKeyD: Uint8Array, payload32: Uint8Array): SyntheticAssertion {
  if (payload32.byteLength !== 32) throw new Error('buildSyntheticAssertion: payload must be 32 bytes');

  const challenge = bytesToB64u(payload32);
  const clientDataJSON = new TextEncoder().encode(
    `{"type":"webauthn.get","challenge":"${challenge}","origin":"https://example.com","crossOrigin":false}`,
  );
  const authenticatorData = new Uint8Array(37);
  authenticatorData[32] = 0x1d; // UP|UV|BE|BS flags; rpIdHash left zero (verifier skips it)

  const cdHash = sha256(clientDataJSON);
  const msg = new Uint8Array(authenticatorData.length + cdHash.length);
  msg.set(authenticatorData, 0);
  msg.set(cdHash, authenticatorData.length);
  const digest = sha256(msg);

  const signature = p256.sign(digest, privateKeyD, { prehash: false, lowS: true });
  return { authenticatorData, clientDataJSON, signature };
}

/** Verify a synthetic assertion the way the webauthn-verifier would: the
 *  challenge must equal the auth digest, and the P-256 signature must verify
 *  over `sha256(authData || sha256(clientData))`. */
export function verifySyntheticAssertion(
  authDigest: Uint8Array,
  publicKeySec1: Uint8Array,
  a: SyntheticAssertion,
): boolean {
  const expectedChallenge = bytesToB64u(authDigest);
  const clientData = JSON.parse(new TextDecoder().decode(a.clientDataJSON)) as { challenge?: string };
  if (clientData.challenge !== expectedChallenge) return false;
  const cdHash = sha256(a.clientDataJSON);
  const msg = new Uint8Array(a.authenticatorData.length + cdHash.length);
  msg.set(a.authenticatorData, 0);
  msg.set(cdHash, a.authenticatorData.length);
  const digest = sha256(msg);
  return p256.verify(a.signature, digest, publicKeySec1, { prehash: false, lowS: true });
}

export function bytesToB64u(b: Uint8Array): string {
  const s = btoa(String.fromCharCode(...b));
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
