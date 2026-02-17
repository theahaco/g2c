import { hash, xdr, rpc, Operation } from "@stellar/stellar-sdk";
import { derToCompact } from "./signature.js";
import type { PasskeySignature } from "./types.js";

/** Default ledger offset for signature expiration. */
const DEFAULT_EXPIRATION_OFFSET = 100;

/**
 * Compute the authorization hash for a Soroban auth entry.
 *
 * This hash is what gets signed by the passkey (used as the WebAuthn challenge).
 *
 * @param authEntry - The SorobanAuthorizationEntry from simulation
 * @param networkPassphrase - Stellar network passphrase
 * @param lastLedger - Current ledger sequence number
 * @param expirationLedgerOffset - How many ledgers the signature is valid for (default 100)
 */
export function buildAuthHash(
  authEntry: xdr.SorobanAuthorizationEntry,
  networkPassphrase: string,
  lastLedger: number,
  expirationLedgerOffset: number = DEFAULT_EXPIRATION_OFFSET
): Buffer {
  const creds = authEntry.credentials().address();
  const expirationLedger = lastLedger + expirationLedgerOffset;

  return hash(
    xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
      new xdr.HashIdPreimageSorobanAuthorization({
        networkId: hash(Buffer.from(networkPassphrase, "utf-8")),
        nonce: creds.nonce(),
        signatureExpirationLedger: expirationLedger,
        invocation: authEntry.rootInvocation(),
      })
    ).toXDR()
  );
}

/**
 * Extract the first Soroban auth entry from a simulation result.
 */
export function getAuthEntry(
  simulation: rpc.Api.SimulateTransactionSuccessResponse
): xdr.SorobanAuthorizationEntry {
  const auth = simulation.result?.auth;
  if (!auth || auth.length === 0) {
    throw new Error("No authorization entries in simulation result");
  }
  return auth[0];
}

/**
 * Parse a WebAuthn assertion response into the components needed for Soroban auth.
 *
 * @param assertionResponse - The response from `navigator.credentials.get()`
 */
export function parseAssertionResponse(assertionResponse: {
  authenticatorData: ArrayBuffer;
  clientDataJSON: ArrayBuffer;
  signature: ArrayBuffer;
}): PasskeySignature {
  return {
    authenticatorData: new Uint8Array(assertionResponse.authenticatorData),
    clientDataJson: new Uint8Array(assertionResponse.clientDataJSON),
    signature: derToCompact(new Uint8Array(assertionResponse.signature)),
  };
}

/**
 * Inject a passkey signature into a transaction's Soroban auth credentials.
 *
 * Modifies the transaction's first auth entry in-place, setting the signature
 * expiration ledger and the passkey signature map (authenticator_data, client_data_json, signature).
 *
 * @param transaction - The assembled transaction from simulation
 * @param passkeySignature - Parsed passkey signature components
 * @param lastLedger - Current ledger sequence number
 * @param expirationLedgerOffset - How many ledgers the signature is valid for (default 100)
 */
export function injectPasskeySignature(
  transaction: { operations: readonly Operation[] },
  passkeySignature: PasskeySignature,
  lastLedger: number,
  expirationLedgerOffset: number = DEFAULT_EXPIRATION_OFFSET
): void {
  const op = transaction.operations[0] as Operation.InvokeHostFunction;
  const creds = op.auth?.[0]?.credentials().address();

  if (!creds) {
    throw new Error("No address credentials found in transaction auth");
  }

  creds.signatureExpirationLedger(lastLedger + expirationLedgerOffset);
  creds.signature(
    xdr.ScVal.scvMap([
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("authenticator_data"),
        val: xdr.ScVal.scvBytes(Buffer.from(passkeySignature.authenticatorData)),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("client_data_json"),
        val: xdr.ScVal.scvBytes(Buffer.from(passkeySignature.clientDataJson)),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("signature"),
        val: xdr.ScVal.scvBytes(Buffer.from(passkeySignature.signature)),
      }),
    ])
  );
}
