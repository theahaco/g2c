import { Buffer } from "buffer";
import { AssembledTransaction, Client as ContractClient, ClientOptions as ContractClientOptions, MethodOptions } from "@stellar/stellar-sdk/contract";
import type { u32, i128, Option } from "@stellar/stellar-sdk/contract";
export * from "@stellar/stellar-sdk";
export * as contract from "@stellar/stellar-sdk/contract";
export * as rpc from "@stellar/stellar-sdk/rpc";
/**
 * Installation parameters for the simple threshold policy.
 */
export interface SimpleThresholdAccountParams {
    /**
   * The minimum number of signers required for authorization.
   */
    threshold: u32;
}
/**
 * Error codes for simple threshold policy operations.
 */
export declare const SimpleThresholdError: {
    /**
     * The smart account does not have a simple threshold policy installed.
     */
    3200: {
        message: string;
    };
    /**
     * When threshold is 0 or exceeds the number of available signers.
     */
    3201: {
        message: string;
    };
    /**
     * The transaction is not allowed by this policy.
     */
    3202: {
        message: string;
    };
    /**
     * The context rule for the smart account has been already installed.
     */
    3203: {
        message: string;
    };
};
/**
 * Storage keys for simple threshold policy data.
 */
export type SimpleThresholdStorageKey = {
    tag: "AccountContext";
    values: readonly [string, u32];
};
/**
 * Installation parameters for the spending limit policy.
 */
export interface SpendingLimitAccountParams {
    /**
   * The period in ledgers over which the spending limit applies.
   */
    period_ledgers: u32;
    /**
   * The maximum amount that can be spent within the specified period (in
   * stroops).
   */
    spending_limit: i128;
}
/**
 * Internal storage structure for spending limit tracking.
 */
export interface SpendingLimitData {
    /**
   * Cached total of all amounts in spending_history.
   */
    cached_total_spent: i128;
    /**
   * The period in ledgers over which the spending limit applies.
   */
    period_ledgers: u32;
    /**
   * History of spending transactions with their ledger sequences.
   */
    spending_history: Array<SpendingEntry>;
    /**
   * The spending limit for the period.
   */
    spending_limit: i128;
}
/**
 * Individual spending entry for tracking purposes.
 */
export interface SpendingEntry {
    /**
   * The amount spent in this transaction.
   */
    amount: i128;
    /**
   * The ledger sequence when this transaction occurred.
   */
    ledger_sequence: u32;
}
/**
 * Error codes for spending limit policy operations.
 */
export declare const SpendingLimitError: {
    /**
     * The smart account does not have a spending limit policy installed.
     */
    3220: {
        message: string;
    };
    /**
     * The spending limit has been exceeded.
     */
    3221: {
        message: string;
    };
    /**
     * The spending limit or period is invalid.
     */
    3222: {
        message: string;
    };
    /**
     * The transaction is not allowed by this policy.
     */
    3223: {
        message: string;
    };
    /**
     * The spending history has reached maximum capacity.
     */
    3224: {
        message: string;
    };
    /**
     * The context rule for the smart account has been already installed.
     */
    3225: {
        message: string;
    };
};
/**
 * Storage keys for spending limit policy data.
 */
export type SpendingLimitStorageKey = {
    tag: "AccountContext";
    values: readonly [string, u32];
};
/**
 * Installation parameters for the weighted threshold policy.
 */
export interface WeightedThresholdAccountParams {
    /**
   * Mapping of signers to their respective weights.
   */
    signer_weights: Map<Signer, u32>;
    /**
   * The minimum total weight required for authorization.
   */
    threshold: u32;
}
/**
 * Error codes for weighted threshold policy operations.
 */
export declare const WeightedThresholdError: {
    /**
     * The smart account does not have a weighted threshold policy installed.
     */
    3210: {
        message: string;
    };
    /**
     * The threshold value is invalid.
     */
    3211: {
        message: string;
    };
    /**
     * A mathematical operation would overflow.
     */
    3212: {
        message: string;
    };
    /**
     * The transaction is not allowed by this policy.
     */
    3213: {
        message: string;
    };
    /**
     * The context rule for the smart account has been already installed.
     */
    3214: {
        message: string;
    };
};
/**
 * Storage keys for weighted threshold policy data.
 */
export type WeightedThresholdStorageKey = {
    tag: "AccountContext";
    values: readonly [string, u32];
};
/**
 * Storage keys for smart account data.
 */
export type SmartAccountStorageKey = {
    tag: "Signers";
    values: readonly [u32];
} | {
    tag: "Policies";
    values: readonly [u32];
} | {
    tag: "Ids";
    values: readonly [ContextRuleType];
} | {
    tag: "Meta";
    values: readonly [u32];
} | {
    tag: "NextId";
    values: void;
} | {
    tag: "Fingerprint";
    values: readonly [Buffer];
} | {
    tag: "Count";
    values: void;
};
/**
 * Represents different types of signers in the smart account system.
 */
export type Signer = {
    tag: "Delegated";
    values: readonly [string];
} | {
    tag: "External";
    values: readonly [string, Buffer];
};
/**
 * A collection of signatures mapped to their respective signers.
 */
export type Signatures = readonly [Map<Signer, Buffer>];
/**
 * Types of contexts that can be authorized by smart account rules.
 */
export type ContextRuleType = {
    tag: "Default";
    values: void;
} | {
    tag: "CallContract";
    values: readonly [string];
} | {
    tag: "CreateContract";
    values: readonly [Buffer];
};
/**
 * Metadata for a context rule.
 */
export interface Meta {
    /**
   * The type of context this rule applies to.
   */
    context_type: ContextRuleType;
    /**
   * Human-readable name for the context rule.
   */
    name: string;
    /**
   * Optional expiration ledger sequence for the rule.
   */
    valid_until: Option<u32>;
}
/**
 * A complete context rule defining authorization requirements.
 */
export interface ContextRule {
    /**
   * The type of context this rule applies to.
   */
    context_type: ContextRuleType;
    /**
   * Unique identifier for the context rule.
   */
    id: u32;
    /**
   * Human-readable name for the context rule.
   */
    name: string;
    /**
   * List of policy contracts that must be satisfied.
   */
    policies: Array<string>;
    /**
   * List of signers authorized by this rule.
   */
    signers: Array<Signer>;
    /**
   * Optional expiration ledger sequence for the rule.
   */
    valid_until: Option<u32>;
}
/**
 * Error codes for smart account operations.
 */
export declare const SmartAccountError: {
    /**
     * The specified context rule does not exist.
     */
    3000: {
        message: string;
    };
    /**
     * A duplicate context rule already exists.
     */
    3001: {
        message: string;
    };
    /**
     * The provided context cannot be validated against any rule.
     */
    3002: {
        message: string;
    };
    /**
     * External signature verification failed.
     */
    3003: {
        message: string;
    };
    /**
     * Context rule must have at least one signer or policy.
     */
    3004: {
        message: string;
    };
    /**
     * The valid_until timestamp is in the past.
     */
    3005: {
        message: string;
    };
    /**
     * The specified signer was not found.
     */
    3006: {
        message: string;
    };
    /**
     * The signer already exists in the context rule.
     */
    3007: {
        message: string;
    };
    /**
     * The specified policy was not found.
     */
    3008: {
        message: string;
    };
    /**
     * The policy already exists in the context rule.
     */
    3009: {
        message: string;
    };
    /**
     * Too many signers in the context rule.
     */
    3010: {
        message: string;
    };
    /**
     * Too many policies in the context rule.
     */
    3011: {
        message: string;
    };
    /**
     * Too many context rules in the smart account.
     */
    3012: {
        message: string;
    };
};
/**
 * Error types for WebAuthn verification operations.
 */
export declare const WebAuthnError: {
    /**
     * The signature payload is invalid or has incorrect format.
     */
    3110: {
        message: string;
    };
    /**
     * The client data exceeds the maximum allowed length.
     */
    3111: {
        message: string;
    };
    /**
     * Failed to parse JSON from client data.
     */
    3112: {
        message: string;
    };
    /**
     * The type field in client data is not "webauthn.get".
     */
    3113: {
        message: string;
    };
    /**
     * The challenge in client data does not match expected value.
     */
    3114: {
        message: string;
    };
    /**
     * The authenticator data format is invalid or too short.
     */
    3115: {
        message: string;
    };
    /**
     * The User Present (UP) bit is not set in authenticator flags.
     */
    3116: {
        message: string;
    };
    /**
     * The User Verified (UV) bit is not set in authenticator flags.
     */
    3117: {
        message: string;
    };
    /**
     * Invalid relationship between Backup Eligibility and State bits.
     */
    3118: {
        message: string;
    };
};
/**
 * WebAuthn signature data structure containing all components needed for
 * verification.
 *
 * This structure encapsulates the signature and associated data generated
 * during a WebAuthn authentication ceremony.
 */
export interface WebAuthnSigData {
    /**
   * Raw authenticator data from the WebAuthn response.
   */
    authenticator_data: Buffer;
    /**
   * Raw client data JSON from the WebAuthn response.
   */
    client_data: Buffer;
    /**
   * The cryptographic signature (64 bytes for secp256r1).
   */
    signature: Buffer;
}
export interface Client {
    /**
     * Construct and simulate a verify transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
     * Verify a `WebAuthn` (passkey) signature.
     *
     * # Arguments
     *
     * * `signature_payload` - The message hash that was signed
     * * `key_data` - 65-byte uncompressed secp256r1 public key,
     * optionally followed by credential ID bytes
     * * `sig_data` - XDR-encoded `WebAuthnSigData` containing:
     * - `signature`: 64-byte secp256r1 signature
     * - `authenticator_data`: raw authenticator data bytes
     * - `client_data`: raw client data JSON bytes
     */
    verify: ({ signature_payload, key_data, sig_data }: {
        signature_payload: Buffer;
        key_data: Buffer;
        sig_data: WebAuthnSigData;
    }, options?: MethodOptions) => Promise<AssembledTransaction<boolean>>;
}
export declare class Client extends ContractClient {
    readonly options: ContractClientOptions;
    static deploy<T = Client>(
    /** Options for initializing a Client as well as for calling a method, with extras specific to deploying. */
    options: MethodOptions & Omit<ContractClientOptions, "contractId"> & {
        /** The hash of the Wasm blob, which must already be installed on-chain. */
        wasmHash: Buffer | string;
        /** Salt used to generate the contract's ID. Passed through to {@link Operation.createCustomContract}. Default: random. */
        salt?: Buffer | Uint8Array;
        /** The format used to decode `wasmHash`, if it's provided as a string. */
        format?: "hex" | "base64";
    }): Promise<AssembledTransaction<T>>;
    constructor(options: ContractClientOptions);
    readonly fromJSON: {
        verify: (json: string) => AssembledTransaction<boolean>;
    };
}
