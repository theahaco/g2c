import { Keypair } from "@stellar/stellar-sdk";
import type { NetworkConfig } from "./types.js";
/**
 * Compute a deterministic contract salt from a credential ID.
 * Returns SHA-256 hash of the credential ID bytes as a Buffer.
 */
export declare function getContractSalt(credentialId: Uint8Array): Buffer;
/**
 * Compute the deterministic smart account address that the factory will deploy to.
 *
 * @param factoryContractId - The factory contract address
 * @param salt - The contract salt (SHA-256 of credential ID)
 * @param networkPassphrase - Stellar network passphrase
 */
export declare function computeAccountAddress(factoryContractId: string, salt: Buffer, networkPassphrase: string): string;
/**
 * Check if a smart account has already been deployed at the expected address.
 *
 * @param config - Network configuration
 * @param salt - The contract salt
 * @returns The contract address if it exists, or null
 */
export declare function lookupExistingAccount(config: NetworkConfig, salt: Buffer): Promise<string | null>;
/**
 * Deploy a new smart account via the factory contract.
 *
 * @param config - Network configuration
 * @param bundlerKeypair - Keypair that pays for the transaction
 * @param salt - The contract salt (SHA-256 of credential ID)
 * @param publicKey - 65-byte uncompressed P-256 public key
 * @returns The deployed contract address
 */
export declare function deploySmartAccount(config: NetworkConfig, bundlerKeypair: Keypair, salt: Buffer, publicKey: Uint8Array): Promise<string>;
//# sourceMappingURL=deploy.d.ts.map