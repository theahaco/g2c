/**
 * Multi-signer authorization payloads.
 *
 * The OZ v0.7 smart account verifies authorization against an
 * `AuthPayload { signers: Map<Signer, Bytes>, context_rule_ids: Vec<u32> }`.
 * For the primary-passkey flow there is a single `External` signer (see
 * `injectPasskeySignature` in `auth.ts`). Recovery completion needs MULTIPLE
 * signers in the same map:
 *
 *   - zero or one primary `External` passkey, and
 *   - one `Delegated(friend_account)` entry per friend whose signature counts
 *     toward the multisig-policy threshold.
 *
 * On-chain semantics (stellar-accounts `authenticate`):
 *
 *   match signer {
 *     External(verifier, key) => verifier.verify(auth_digest, key, sig_bytes),
 *     Delegated(addr)         => addr.require_auth_for_args((auth_digest,)),
 *   }
 *
 * Note the asymmetry: for a `Delegated` signer the `Bytes` value in the map is
 * IGNORED — authorization happens through a *nested* Soroban auth entry where
 * the friend's own account authorizes the args `(auth_digest,)`. So for
 * delegated signers we still need a map entry (the contract iterates the map
 * and calls `authenticate` on each, which is what triggers `require_auth`),
 * but its byte payload can be empty. The friend's real signature travels in
 * the auth tree's sub-invocation, assembled by `signFriendSubInvocation`.
 *
 * This module isolates the pure ScVal construction so it can be unit-tested
 * without a chain; the auth-tree wiring lives in the frontend's
 * `recoveryActions`.
 */

import { Address, xdr } from '@stellar/stellar-sdk';
import type { PasskeySignature } from './types.js';

/** One signer to include in a multi-signer `AuthPayload`. */
export type SignerSignature =
  | {
      kind: 'external';
      /** WebAuthn verifier contract address. */
      verifierAddress: string;
      /** 65-byte SEC1 uncompressed P-256 public key. */
      publicKey: Uint8Array;
      /** Parsed assertion over the auth digest. */
      passkeySignature: PasskeySignature;
    }
  | {
      kind: 'delegated';
      /** The friend's smart-account address. */
      address: string;
      /**
       * Optional raw signature bytes. Ignored on-chain for `Delegated`
       * signers (authorization flows through the nested auth entry), so this
       * is left empty by default.
       */
      sigData?: Uint8Array;
    };

export interface AuthPayloadSpec {
  /** Per-context rule IDs, aligned by index with the auth contexts. */
  contextRuleIds: readonly number[];
  /** All signers to bundle into the payload's `signers` map. */
  signers: readonly SignerSignature[];
}

/** Encode the `WebAuthnSigData` struct an External signer's bytes carry. */
function webAuthnSigDataBytes(sig: PasskeySignature): Buffer {
  // Soroban struct → ScMap with Symbol keys in alphabetical order.
  const sigDataScVal = xdr.ScVal.scvMap([
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol('authenticator_data'),
      val: xdr.ScVal.scvBytes(Buffer.from(sig.authenticatorData)),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol('client_data'),
      val: xdr.ScVal.scvBytes(Buffer.from(sig.clientDataJson)),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol('signature'),
      val: xdr.ScVal.scvBytes(Buffer.from(sig.signature)),
    }),
  ]);
  return sigDataScVal.toXDR();
}

/** Build the `Signer` enum ScVal key for a single signer. */
function signerScVal(s: SignerSignature): xdr.ScVal {
  if (s.kind === 'external') {
    // Signer::External(verifier_address, public_key)
    // → Vec[Symbol("External"), Address, Bytes]
    return xdr.ScVal.scvVec([
      xdr.ScVal.scvSymbol('External'),
      Address.fromString(s.verifierAddress).toScVal(),
      xdr.ScVal.scvBytes(Buffer.from(s.publicKey)),
    ]);
  }
  // Signer::Delegated(address) → Vec[Symbol("Delegated"), Address]
  return xdr.ScVal.scvVec([
    xdr.ScVal.scvSymbol('Delegated'),
    Address.fromString(s.address).toScVal(),
  ]);
}

/** Build the `Bytes` value stored against a signer in the `signers` map. */
function sigDataScVal(s: SignerSignature): xdr.ScVal {
  if (s.kind === 'external') {
    return xdr.ScVal.scvBytes(webAuthnSigDataBytes(s.passkeySignature));
  }
  // Delegated: bytes are ignored on-chain; emit an empty Bytes (or any
  // provided placeholder) so the map entry exists and `authenticate` runs.
  return xdr.ScVal.scvBytes(Buffer.from(s.sigData ?? new Uint8Array(0)));
}

/**
 * Construct the OZ v0.7 `AuthPayload` ScVal for one or more signers.
 *
 * The result is an `ScMap` with Symbol keys `context_rule_ids` and `signers`
 * (alphabetical order, as Soroban requires for struct encoding). Set it as
 * the credential signature of a `SorobanAddressCredentials` entry.
 */
export function buildAuthPayloadScVal(spec: AuthPayloadSpec): xdr.ScVal {
  if (spec.signers.length === 0) {
    //TODO: fix this? we want to make sure that 0 signers are possible. should this be a different fn altogether? or can we just remove this check
    // throw new Error('buildAuthPayloadScVal: at least one signer required');
  }
  // Soroban requires ScMap entries to be sorted by key. The host orders
  // ScVal keys by their XDR-serialized byte sequence, so sort entries by the
  // signer key's XDR before assembling the map — otherwise multi-signer maps
  // trap on deserialization with a "map keys out of order" error.
  const entries = spec.signers
    .map((s) => ({
      key: signerScVal(s),
      val: sigDataScVal(s),
    }))
    .sort((a, b) =>
      Buffer.compare(a.key.toXDR(), b.key.toXDR()),
    )
    .map((e) => new xdr.ScMapEntry({ key: e.key, val: e.val }));
  const signersMap = xdr.ScVal.scvMap(entries);
  const contextRuleIdsVec = xdr.ScVal.scvVec(
    spec.contextRuleIds.map((id) => xdr.ScVal.scvU32(id)),
  );
  // ScMap with Symbol keys in alphabetical order (context_rule_ids < signers).
  return xdr.ScVal.scvMap([
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol('context_rule_ids'),
      val: contextRuleIdsVec,
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol('signers'),
      val: signersMap,
    }),
  ]);
}
