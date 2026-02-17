import { hash, xdr, Address } from "@stellar/stellar-sdk";
import { derToCompact } from "./signature.js";
/** Default ledger offset for signature expiration. */
const DEFAULT_EXPIRATION_OFFSET = 10000;
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
export function buildAuthHash(authEntry, networkPassphrase, lastLedger, expirationLedgerOffset = DEFAULT_EXPIRATION_OFFSET) {
    const creds = authEntry.credentials().address();
    const expirationLedger = lastLedger + expirationLedgerOffset;
    // Convert nonce to BigInt to avoid cross-package instanceof issues
    // when the auth entry originates from a different stellar-sdk copy
    const nonce = xdr.Int64.fromString(creds.nonce().toString());
    let entry = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(new xdr.HashIdPreimageSorobanAuthorization({
        networkId: hash(Buffer.from(networkPassphrase, "utf-8")),
        nonce,
        signatureExpirationLedger: expirationLedger,
        invocation: authEntry.rootInvocation(),
    }));
    return hash(entry.toXDR());
}
/**
 * Extract the first Soroban auth entry from a simulation result.
 */
export function getAuthEntry(simulation) {
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
export function parseAssertionResponse(assertionResponse) {
    return {
        authenticatorData: new Uint8Array(assertionResponse.authenticatorData),
        clientDataJson: new Uint8Array(assertionResponse.clientDataJSON),
        signature: derToCompact(new Uint8Array(assertionResponse.signature)),
    };
}
/**
 * Inject a passkey signature into a transaction's Soroban auth credentials.
 *
 * Constructs the OZ smart account `Signatures(Map<Signer, Bytes>)` format:
 * - Key: `Signer::External(verifier_address, public_key)`
 * - Value: XDR-encoded `WebAuthnSigData { authenticator_data, client_data, signature }`
 *
 * @param transaction - The assembled transaction from simulation
 * @param passkeySignature - Parsed passkey signature components
 * @param verifierAddress - Address of the WebAuthn verifier contract
 * @param publicKey - 65-byte uncompressed P-256 public key
 * @param lastLedger - Current ledger sequence number
 * @param expirationLedgerOffset - How many ledgers the signature is valid for (default 100)
 */
export function injectPasskeySignature(transaction, passkeySignature, verifierAddress, publicKey, lastLedger, expirationLedgerOffset = DEFAULT_EXPIRATION_OFFSET) {
    const op = transaction.operations[0];
    const creds = op.auth?.[0]?.credentials().address();
    if (!creds) {
        throw new Error("No address credentials found in transaction auth");
    }
    creds.signatureExpirationLedger(lastLedger + expirationLedgerOffset);
    // WebAuthnSigData struct (field names must match the contract type)
    const sigDataScVal = xdr.ScVal.scvMap([
        new xdr.ScMapEntry({
            key: xdr.ScVal.scvSymbol("authenticator_data"),
            val: xdr.ScVal.scvBytes(Buffer.from(passkeySignature.authenticatorData)),
        }),
        new xdr.ScMapEntry({
            key: xdr.ScVal.scvSymbol("client_data"),
            val: xdr.ScVal.scvBytes(Buffer.from(passkeySignature.clientDataJson)),
        }),
        new xdr.ScMapEntry({
            key: xdr.ScVal.scvSymbol("signature"),
            val: xdr.ScVal.scvBytes(Buffer.from(passkeySignature.signature)),
        }),
    ]);
    // XDR-encode WebAuthnSigData to raw bytes for the Signatures map value
    const sigDataBytes = sigDataScVal.toXDR();
    // Signer::External(verifier_address, public_key) enum variant
    const signerScVal = xdr.ScVal.scvVec([
        xdr.ScVal.scvSymbol("External"),
        Address.fromString(verifierAddress).toScVal(),
        xdr.ScVal.scvBytes(Buffer.from(publicKey)),
    ]);
    // Signatures tuple struct → Vec([Map<Signer, Bytes>])
    creds.signature(xdr.ScVal.scvVec([
        xdr.ScVal.scvMap([
            new xdr.ScMapEntry({
                key: signerScVal,
                val: xdr.ScVal.scvBytes(sigDataBytes),
            }),
        ]),
    ]));
}
//# sourceMappingURL=auth.js.map