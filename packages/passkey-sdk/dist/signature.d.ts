/**
 * Convert an ASN.1 DER-encoded ECDSA signature to 64-byte compact form (r || s)
 * with P-256 low-S normalization as required by Stellar.
 *
 * @see https://github.com/stellar/stellar-protocol/discussions/1435#discussioncomment-8809175
 */
export declare function derToCompact(derSignature: Uint8Array): Uint8Array;
//# sourceMappingURL=signature.d.ts.map