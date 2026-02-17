export declare function saveCredential(contractId: string, credentialId: Uint8Array, publicKey: Uint8Array): void;
export declare function loadCredential(contractId: string): {
    credentialId: Uint8Array;
    publicKey: string;
} | null;
export declare function saveAccount(contractId: string): void;
export declare function loadAccounts(): string[];
//# sourceMappingURL=storage.d.ts.map