import { xdr, rpc, Operation } from "@stellar/stellar-sdk";
import type { PasskeySignature } from "./types.js";
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
export declare function buildAuthHash(authEntry: xdr.SorobanAuthorizationEntry, networkPassphrase: string, lastLedger: number, expirationLedgerOffset?: number): Buffer;
/**
 * Extract the first Soroban auth entry from a simulation result.
 */
export declare function getAuthEntry(simulation: rpc.Api.SimulateTransactionSuccessResponse): xdr.SorobanAuthorizationEntry;
/**
 * Parse a WebAuthn assertion response into the components needed for Soroban auth.
 *
 * @param assertionResponse - The response from `navigator.credentials.get()`
 */
export declare function parseAssertionResponse(assertionResponse: {
    authenticatorData: ArrayBuffer;
    clientDataJSON: ArrayBuffer;
    signature: ArrayBuffer;
}): PasskeySignature;
/**
 * Inject a passkey signature into a transaction's Soroban auth credentials.
 *
 * Constructs the OZ smart account `Signatures(Map<Signer, Bytes>)` format:
 * - Key: `Signer::External(verifier_address, public_key)`
 * - Value: `WebAuthnSigData { authenticator_data, client_data, signature }` as native Map ScVal
 *
 * @param transaction - The assembled transaction from simulation
 * @param passkeySignature - Parsed passkey signature components
 * @param verifierAddress - Address of the WebAuthn verifier contract
 * @param publicKey - 65-byte uncompressed P-256 public key
 * @param lastLedger - Current ledger sequence number
 * @param expirationLedgerOffset - How many ledgers the signature is valid for (default 100)
 */
export declare function injectPasskeySignature(transaction: {
    operations: readonly Operation[];
}, passkeySignature: PasskeySignature, verifierAddress: string, publicKey: Uint8Array, lastLedger: number, expirationLedgerOffset?: number): void;
//# sourceMappingURL=auth.d.ts.map