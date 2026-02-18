export declare function saveCredential(contractId: string, credentialId: Uint8Array, publicKey: Uint8Array): void;
export declare function loadCredential(contractId: string): {
    credentialId: Uint8Array;
    publicKey: string;
} | null;
export declare function saveAccount(contractId: string): void;
export declare function loadAccounts(): string[];
export interface PendingAccount {
    contractId: string;
    secretKey: string;
}
export declare function savePendingAccount(contractId: string, secretKey: string): void;
export declare function loadPendingAccounts(): PendingAccount[];
export declare function removePendingAccount(contractId: string): void;
export declare function activateAccount(contractId: string): void;
//# sourceMappingURL=storage.d.ts.map