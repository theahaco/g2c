import { Buffer } from "buffer";
import { Address } from "@stellar/stellar-sdk";
import {
  AssembledTransaction,
  Client as ContractClient,
  ClientOptions as ContractClientOptions,
  MethodOptions,
  Result,
  Spec as ContractSpec,
} from "@stellar/stellar-sdk/contract";
import type {
  u32,
  i32,
  u64,
  i64,
  u128,
  i128,
  u256,
  i256,
  Option,
  Timepoint,
  Duration,
} from "@stellar/stellar-sdk/contract";

export * from "@stellar/stellar-sdk";
export * as contract from "@stellar/stellar-sdk/contract";
export * as rpc from "@stellar/stellar-sdk/rpc";

if (typeof window !== "undefined") {
  //@ts-ignore Buffer exists
  window.Buffer = window.Buffer || Buffer;
}




/**
 * Error codes. Distinct per rejection reason so callers (and tests) can assert
 * a sweep was blocked for the RIGHT reason, not by an incidental failure.
 */
export const SweepError = {
  /**
   * No sweep policy installed for this (account, rule).
   */
  1: {message:"NotInstalled"},
  /**
   * A sweep policy is already installed for this (account, rule).
   */
  2: {message:"AlreadyInstalled"},
  /**
   * Reserved. Formerly signalled "no signer authenticated". The sweep is now
   * intentionally permissionless (authorized with an empty signer set), so no
   * code path emits this. Kept to freeze the error-code space (`= 3`) so the
   * remaining discriminants below never renumber.
   */
  3: {message:"NoSigner"},
  /**
   * `from` argument != the recorded source G.
   */
  4: {message:"WrongSource"},
  /**
   * `to` argument != the smart account C.
   */
  5: {message:"WrongDestination"},
  /**
   * The invoked function is not `transfer_from`.
   */
  6: {message:"NotTransferFrom"},
  /**
   * Rule is not `CallContract(sac)` — refuse to pin an unscoped rule.
   */
  7: {message:"OnlyCallContract"},
  /**
   * A `transfer_from` argument was missing or the wrong type.
   */
  8: {message:"MalformedArgs"},
  /**
   * Negative amount.
   */
  9: {message:"NegativeAmount"},
  /**
   * `spender` argument != the smart account C.
   */
  10: {message:"WrongSpender"}
}


/**
 * Installation parameters: the single classic account **G** whose balance this
 * rule may sweep FROM. Recorded at install time and immutable thereafter
 * except via uninstall/reinstall (both smart-account-authorized).
 */
export interface PreauthSweepParams {
  /**
 * The onboarding source account G. `transfer_from`'s `from` arg must equal
 * this exactly.
 */
source: string;
}

/**
 * Context of a single authorized call performed by an address.
 * 
 * Custom account contracts that implement `__check_auth` special function
 * receive a list of `Context` values corresponding to all the calls that
 * need to be authorized.
 */
export type Context = {tag: "Contract", values: readonly [ContractContext]} | {tag: "CreateContractHostFn", values: readonly [CreateContractHostFnContext]} | {tag: "CreateContractWithCtorHostFn", values: readonly [CreateContractWithConstructorHostFnContext]};


/**
 * Authorization context of a single contract call.
 * 
 * This struct corresponds to a `require_auth_for_args` call for an address
 * from `contract` function with `fn_name` name and `args` arguments.
 */
export interface ContractContext {
  args: Array<any>;
  contract: string;
  fn_name: string;
}

/**
 * Contract executable used for creating a new contract and used in
 * `CreateContractHostFnContext`.
 */
export type ContractExecutable = {tag: "Wasm", values: readonly [Buffer]};


/**
 * Authorization context for `create_contract` host function that creates a
 * new contract on behalf of authorizer address.
 */
export interface CreateContractHostFnContext {
  executable: ContractExecutable;
  salt: Buffer;
}


/**
 * Authorization context for `create_contract` host function that creates a
 * new contract on behalf of authorizer address.
 * This is the same as `CreateContractHostFnContext`, but also has
 * contract constructor arguments.
 */
export interface CreateContractWithConstructorHostFnContext {
  constructor_args: Array<any>;
  executable: ContractExecutable;
  salt: Buffer;
}

/**
 * Represents different types of signers in the smart account system.
 */
export type Signer = {tag: "Delegated", values: readonly [string]} | {tag: "External", values: readonly [string, Buffer]};


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
 * Global registry IDs for each policy, positionally aligned with
 * `policies`.
 */
policy_ids: Array<u32>;
  /**
 * Global registry IDs for each signer, positionally aligned with
 * `signers`.
 */
signer_ids: Array<u32>;
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
 * Types of contexts that can be authorized by smart account rules.
 */
export type ContextRuleType = {tag: "Default", values: void} | {tag: "CallContract", values: readonly [string]} | {tag: "CreateContract", values: readonly [Buffer]};

export interface Client {
  /**
   * Construct and simulate a enforce transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Enforce the sweep bound. **Permissionless**: this runs with an empty
   * `authenticated_signers` set (the rule carries no signers) and MUST still
   * authorize a correctly-bounded `transfer_from(C, G, C, amount)`. Anyone may
   * trigger it; the security argument is the bound checked below, not a
   * signature.
   * 
   * `authenticated_signers` is intentionally ignored: the sweep requires none.
   * It stays in the signature because the OZ `Policy` trait fixes it.
   * 
   * No `smart_account.require_auth()` here — deliberately. Requiring C to
   * authorize would defeat the permissionless posture (it demands C's own
   * passkey signature, exactly what this design removes). Unlike a stateful
   * policy (e.g. spending-limit, which needs `require_auth` to gate a mutable
   * counter), this `enforce` mutates NO state — it only reads the recorded
   * source and the invocation args — so dropping the guard is safe: there is
   * nothing to protect from an unauthorized caller, and the bound alone
   * constrains the outcome to `G -> C`.
   */
  enforce: ({context, authenticated_signers, context_rule, smart_account}: {context: Context, authenticated_signers: Array<Signer>, context_rule: ContextRule, smart_account: string}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a install transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  install: ({install_params, context_rule, smart_account}: {install_params: PreauthSweepParams, context_rule: ContextRule, smart_account: string}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a uninstall transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  uninstall: ({context_rule, smart_account}: {context_rule: ContextRule, smart_account: string}, options?: MethodOptions) => Promise<AssembledTransaction<null>>

  /**
   * Construct and simulate a get_source transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   * Read the recorded source G for a given (account, rule). `None` if not
   * installed. Lets a relayer/SDK confirm what a rule is pinned to.
   */
  get_source: ({context_rule_id, smart_account}: {context_rule_id: u32, smart_account: string}, options?: MethodOptions) => Promise<AssembledTransaction<Option<string>>>

}
export class Client extends ContractClient {
  static async deploy<T = Client>(
    /** Options for initializing a Client as well as for calling a method, with extras specific to deploying. */
    options: MethodOptions &
      Omit<ContractClientOptions, "contractId"> & {
        /** The hash of the Wasm blob, which must already be installed on-chain. */
        wasmHash: Buffer | string;
        /** Salt used to generate the contract's ID. Passed through to {@link Operation.createCustomContract}. Default: random. */
        salt?: Buffer | Uint8Array;
        /** The format used to decode `wasmHash`, if it's provided as a string. */
        format?: "hex" | "base64";
      }
  ): Promise<AssembledTransaction<T>> {
    return ContractClient.deploy(null, options)
  }
  constructor(public readonly options: ContractClientOptions) {
    super(
      new ContractSpec([ "AAAABAAAAJRFcnJvciBjb2Rlcy4gRGlzdGluY3QgcGVyIHJlamVjdGlvbiByZWFzb24gc28gY2FsbGVycyAoYW5kIHRlc3RzKSBjYW4gYXNzZXJ0CmEgc3dlZXAgd2FzIGJsb2NrZWQgZm9yIHRoZSBSSUdIVCByZWFzb24sIG5vdCBieSBhbiBpbmNpZGVudGFsIGZhaWx1cmUuAAAAAAAAAApTd2VlcEVycm9yAAAAAAAKAAAAM05vIHN3ZWVwIHBvbGljeSBpbnN0YWxsZWQgZm9yIHRoaXMgKGFjY291bnQsIHJ1bGUpLgAAAAAMTm90SW5zdGFsbGVkAAAAAQAAAD1BIHN3ZWVwIHBvbGljeSBpcyBhbHJlYWR5IGluc3RhbGxlZCBmb3IgdGhpcyAoYWNjb3VudCwgcnVsZSkuAAAAAAAAEEFscmVhZHlJbnN0YWxsZWQAAAACAAABCVJlc2VydmVkLiBGb3JtZXJseSBzaWduYWxsZWQgIm5vIHNpZ25lciBhdXRoZW50aWNhdGVkIi4gVGhlIHN3ZWVwIGlzIG5vdwppbnRlbnRpb25hbGx5IHBlcm1pc3Npb25sZXNzIChhdXRob3JpemVkIHdpdGggYW4gZW1wdHkgc2lnbmVyIHNldCksIHNvIG5vCmNvZGUgcGF0aCBlbWl0cyB0aGlzLiBLZXB0IHRvIGZyZWV6ZSB0aGUgZXJyb3ItY29kZSBzcGFjZSAoYD0gM2ApIHNvIHRoZQpyZW1haW5pbmcgZGlzY3JpbWluYW50cyBiZWxvdyBuZXZlciByZW51bWJlci4AAAAAAAAITm9TaWduZXIAAAADAAAAKWBmcm9tYCBhcmd1bWVudCAhPSB0aGUgcmVjb3JkZWQgc291cmNlIEcuAAAAAAAAC1dyb25nU291cmNlAAAAAAQAAAAlYHRvYCBhcmd1bWVudCAhPSB0aGUgc21hcnQgYWNjb3VudCBDLgAAAAAAABBXcm9uZ0Rlc3RpbmF0aW9uAAAABQAAACxUaGUgaW52b2tlZCBmdW5jdGlvbiBpcyBub3QgYHRyYW5zZmVyX2Zyb21gLgAAAA9Ob3RUcmFuc2ZlckZyb20AAAAABgAAAENSdWxlIGlzIG5vdCBgQ2FsbENvbnRyYWN0KHNhYylgIOKAlCByZWZ1c2UgdG8gcGluIGFuIHVuc2NvcGVkIHJ1bGUuAAAAABBPbmx5Q2FsbENvbnRyYWN0AAAABwAAADlBIGB0cmFuc2Zlcl9mcm9tYCBhcmd1bWVudCB3YXMgbWlzc2luZyBvciB0aGUgd3JvbmcgdHlwZS4AAAAAAAANTWFsZm9ybWVkQXJncwAAAAAAAAgAAAAQTmVnYXRpdmUgYW1vdW50LgAAAA5OZWdhdGl2ZUFtb3VudAAAAAAACQAAACpgc3BlbmRlcmAgYXJndW1lbnQgIT0gdGhlIHNtYXJ0IGFjY291bnQgQy4AAAAAAAxXcm9uZ1NwZW5kZXIAAAAK",
        "AAAAAQAAANNJbnN0YWxsYXRpb24gcGFyYW1ldGVyczogdGhlIHNpbmdsZSBjbGFzc2ljIGFjY291bnQgKipHKiogd2hvc2UgYmFsYW5jZSB0aGlzCnJ1bGUgbWF5IHN3ZWVwIEZST00uIFJlY29yZGVkIGF0IGluc3RhbGwgdGltZSBhbmQgaW1tdXRhYmxlIHRoZXJlYWZ0ZXIKZXhjZXB0IHZpYSB1bmluc3RhbGwvcmVpbnN0YWxsIChib3RoIHNtYXJ0LWFjY291bnQtYXV0aG9yaXplZCkuAAAAAAAAAAASUHJlYXV0aFN3ZWVwUGFyYW1zAAAAAAABAAAAVlRoZSBvbmJvYXJkaW5nIHNvdXJjZSBhY2NvdW50IEcuIGB0cmFuc2Zlcl9mcm9tYCdzIGBmcm9tYCBhcmcgbXVzdCBlcXVhbAp0aGlzIGV4YWN0bHkuAAAAAAAGc291cmNlAAAAAAAT",
        "AAAAAAAAA9JFbmZvcmNlIHRoZSBzd2VlcCBib3VuZC4gKipQZXJtaXNzaW9ubGVzcyoqOiB0aGlzIHJ1bnMgd2l0aCBhbiBlbXB0eQpgYXV0aGVudGljYXRlZF9zaWduZXJzYCBzZXQgKHRoZSBydWxlIGNhcnJpZXMgbm8gc2lnbmVycykgYW5kIE1VU1Qgc3RpbGwKYXV0aG9yaXplIGEgY29ycmVjdGx5LWJvdW5kZWQgYHRyYW5zZmVyX2Zyb20oQywgRywgQywgYW1vdW50KWAuIEFueW9uZSBtYXkKdHJpZ2dlciBpdDsgdGhlIHNlY3VyaXR5IGFyZ3VtZW50IGlzIHRoZSBib3VuZCBjaGVja2VkIGJlbG93LCBub3QgYQpzaWduYXR1cmUuCgpgYXV0aGVudGljYXRlZF9zaWduZXJzYCBpcyBpbnRlbnRpb25hbGx5IGlnbm9yZWQ6IHRoZSBzd2VlcCByZXF1aXJlcyBub25lLgpJdCBzdGF5cyBpbiB0aGUgc2lnbmF0dXJlIGJlY2F1c2UgdGhlIE9aIGBQb2xpY3lgIHRyYWl0IGZpeGVzIGl0LgoKTm8gYHNtYXJ0X2FjY291bnQucmVxdWlyZV9hdXRoKClgIGhlcmUg4oCUIGRlbGliZXJhdGVseS4gUmVxdWlyaW5nIEMgdG8KYXV0aG9yaXplIHdvdWxkIGRlZmVhdCB0aGUgcGVybWlzc2lvbmxlc3MgcG9zdHVyZSAoaXQgZGVtYW5kcyBDJ3Mgb3duCnBhc3NrZXkgc2lnbmF0dXJlLCBleGFjdGx5IHdoYXQgdGhpcyBkZXNpZ24gcmVtb3ZlcykuIFVubGlrZSBhIHN0YXRlZnVsCnBvbGljeSAoZS5nLiBzcGVuZGluZy1saW1pdCwgd2hpY2ggbmVlZHMgYHJlcXVpcmVfYXV0aGAgdG8gZ2F0ZSBhIG11dGFibGUKY291bnRlciksIHRoaXMgYGVuZm9yY2VgIG11dGF0ZXMgTk8gc3RhdGUg4oCUIGl0IG9ubHkgcmVhZHMgdGhlIHJlY29yZGVkCnNvdXJjZSBhbmQgdGhlIGludm9jYXRpb24gYXJncyDigJQgc28gZHJvcHBpbmcgdGhlIGd1YXJkIGlzIHNhZmU6IHRoZXJlIGlzCm5vdGhpbmcgdG8gcHJvdGVjdCBmcm9tIGFuIHVuYXV0aG9yaXplZCBjYWxsZXIsIGFuZCB0aGUgYm91bmQgYWxvbmUKY29uc3RyYWlucyB0aGUgb3V0Y29tZSB0byBgRyAtPiBDYC4AAAAAAAdlbmZvcmNlAAAAAAQAAAAAAAAAB2NvbnRleHQAAAAH0AAAAAdDb250ZXh0AAAAAAAAAAAVYXV0aGVudGljYXRlZF9zaWduZXJzAAAAAAAD6gAAB9AAAAAGU2lnbmVyAAAAAAAAAAAADGNvbnRleHRfcnVsZQAAB9AAAAALQ29udGV4dFJ1bGUAAAAAAAAAAA1zbWFydF9hY2NvdW50AAAAAAAAEwAAAAA=",
        "AAAAAAAAAAAAAAAHaW5zdGFsbAAAAAADAAAAAAAAAA5pbnN0YWxsX3BhcmFtcwAAAAAH0AAAABJQcmVhdXRoU3dlZXBQYXJhbXMAAAAAAAAAAAAMY29udGV4dF9ydWxlAAAH0AAAAAtDb250ZXh0UnVsZQAAAAAAAAAADXNtYXJ0X2FjY291bnQAAAAAAAATAAAAAA==",
        "AAAAAAAAAAAAAAAJdW5pbnN0YWxsAAAAAAAAAgAAAAAAAAAMY29udGV4dF9ydWxlAAAH0AAAAAtDb250ZXh0UnVsZQAAAAAAAAAADXNtYXJ0X2FjY291bnQAAAAAAAATAAAAAA==",
        "AAAAAAAAAIVSZWFkIHRoZSByZWNvcmRlZCBzb3VyY2UgRyBmb3IgYSBnaXZlbiAoYWNjb3VudCwgcnVsZSkuIGBOb25lYCBpZiBub3QKaW5zdGFsbGVkLiBMZXRzIGEgcmVsYXllci9TREsgY29uZmlybSB3aGF0IGEgcnVsZSBpcyBwaW5uZWQgdG8uAAAAAAAACmdldF9zb3VyY2UAAAAAAAIAAAAAAAAAD2NvbnRleHRfcnVsZV9pZAAAAAAEAAAAAAAAAA1zbWFydF9hY2NvdW50AAAAAAAAEwAAAAEAAAPoAAAAEw==",
        "AAAAAgAAAONDb250ZXh0IG9mIGEgc2luZ2xlIGF1dGhvcml6ZWQgY2FsbCBwZXJmb3JtZWQgYnkgYW4gYWRkcmVzcy4KCkN1c3RvbSBhY2NvdW50IGNvbnRyYWN0cyB0aGF0IGltcGxlbWVudCBgX19jaGVja19hdXRoYCBzcGVjaWFsIGZ1bmN0aW9uCnJlY2VpdmUgYSBsaXN0IG9mIGBDb250ZXh0YCB2YWx1ZXMgY29ycmVzcG9uZGluZyB0byBhbGwgdGhlIGNhbGxzIHRoYXQKbmVlZCB0byBiZSBhdXRob3JpemVkLgAAAAAAAAAAB0NvbnRleHQAAAAAAwAAAAEAAAAUQ29udHJhY3QgaW52b2NhdGlvbi4AAAAIQ29udHJhY3QAAAABAAAH0AAAAA9Db250cmFjdENvbnRleHQAAAAAAQAAAD1Db250cmFjdCB0aGF0IGhhcyBhIGNvbnN0cnVjdG9yIHdpdGggbm8gYXJndW1lbnRzIGlzIGNyZWF0ZWQuAAAAAAAAFENyZWF0ZUNvbnRyYWN0SG9zdEZuAAAAAQAAB9AAAAAbQ3JlYXRlQ29udHJhY3RIb3N0Rm5Db250ZXh0AAAAAAEAAABEQ29udHJhY3QgdGhhdCBoYXMgYSBjb25zdHJ1Y3RvciB3aXRoIDEgb3IgbW9yZSBhcmd1bWVudHMgaXMgY3JlYXRlZC4AAAAcQ3JlYXRlQ29udHJhY3RXaXRoQ3Rvckhvc3RGbgAAAAEAAAfQAAAAKkNyZWF0ZUNvbnRyYWN0V2l0aENvbnN0cnVjdG9ySG9zdEZuQ29udGV4dAAA",
        "AAAAAQAAAL1BdXRob3JpemF0aW9uIGNvbnRleHQgb2YgYSBzaW5nbGUgY29udHJhY3QgY2FsbC4KClRoaXMgc3RydWN0IGNvcnJlc3BvbmRzIHRvIGEgYHJlcXVpcmVfYXV0aF9mb3JfYXJnc2AgY2FsbCBmb3IgYW4gYWRkcmVzcwpmcm9tIGBjb250cmFjdGAgZnVuY3Rpb24gd2l0aCBgZm5fbmFtZWAgbmFtZSBhbmQgYGFyZ3NgIGFyZ3VtZW50cy4AAAAAAAAAAAAAD0NvbnRyYWN0Q29udGV4dAAAAAADAAAAAAAAAARhcmdzAAAD6gAAAAAAAAAAAAAACGNvbnRyYWN0AAAAEwAAAAAAAAAHZm5fbmFtZQAAAAAR",
        "AAAAAgAAAF9Db250cmFjdCBleGVjdXRhYmxlIHVzZWQgZm9yIGNyZWF0aW5nIGEgbmV3IGNvbnRyYWN0IGFuZCB1c2VkIGluCmBDcmVhdGVDb250cmFjdEhvc3RGbkNvbnRleHRgLgAAAAAAAAAAEkNvbnRyYWN0RXhlY3V0YWJsZQAAAAAAAQAAAAEAAAAAAAAABFdhc20AAAABAAAD7gAAACA=",
        "AAAAAQAAAHZBdXRob3JpemF0aW9uIGNvbnRleHQgZm9yIGBjcmVhdGVfY29udHJhY3RgIGhvc3QgZnVuY3Rpb24gdGhhdCBjcmVhdGVzIGEKbmV3IGNvbnRyYWN0IG9uIGJlaGFsZiBvZiBhdXRob3JpemVyIGFkZHJlc3MuAAAAAAAAAAAAG0NyZWF0ZUNvbnRyYWN0SG9zdEZuQ29udGV4dAAAAAACAAAAAAAAAApleGVjdXRhYmxlAAAAAAfQAAAAEkNvbnRyYWN0RXhlY3V0YWJsZQAAAAAAAAAAAARzYWx0AAAD7gAAACA=",
        "AAAAAQAAANZBdXRob3JpemF0aW9uIGNvbnRleHQgZm9yIGBjcmVhdGVfY29udHJhY3RgIGhvc3QgZnVuY3Rpb24gdGhhdCBjcmVhdGVzIGEKbmV3IGNvbnRyYWN0IG9uIGJlaGFsZiBvZiBhdXRob3JpemVyIGFkZHJlc3MuClRoaXMgaXMgdGhlIHNhbWUgYXMgYENyZWF0ZUNvbnRyYWN0SG9zdEZuQ29udGV4dGAsIGJ1dCBhbHNvIGhhcwpjb250cmFjdCBjb25zdHJ1Y3RvciBhcmd1bWVudHMuAAAAAAAAAAAAKkNyZWF0ZUNvbnRyYWN0V2l0aENvbnN0cnVjdG9ySG9zdEZuQ29udGV4dAAAAAAAAwAAAAAAAAAQY29uc3RydWN0b3JfYXJncwAAA+oAAAAAAAAAAAAAAApleGVjdXRhYmxlAAAAAAfQAAAAEkNvbnRyYWN0RXhlY3V0YWJsZQAAAAAAAAAAAARzYWx0AAAD7gAAACA=",
        "AAAAAgAAAEJSZXByZXNlbnRzIGRpZmZlcmVudCB0eXBlcyBvZiBzaWduZXJzIGluIHRoZSBzbWFydCBhY2NvdW50IHN5c3RlbS4AAAAAAAAAAAAGU2lnbmVyAAAAAAACAAAAAQAAAD1BIGRlbGVnYXRlZCBzaWduZXIgdGhhdCB1c2VzIGJ1aWx0LWluIHNpZ25hdHVyZSB2ZXJpZmljYXRpb24uAAAAAAAACURlbGVnYXRlZAAAAAAAAAEAAAATAAAAAQAAAHJBbiBleHRlcm5hbCBzaWduZXIgd2l0aCBjdXN0b20gdmVyaWZpY2F0aW9uIGxvZ2ljLgpDb250YWlucyB0aGUgdmVyaWZpZXIgY29udHJhY3QgYWRkcmVzcyBhbmQgdGhlIHB1YmxpYyBrZXkgZGF0YS4AAAAAAAhFeHRlcm5hbAAAAAIAAAATAAAADg==",
        "AAAAAQAAADxBIGNvbXBsZXRlIGNvbnRleHQgcnVsZSBkZWZpbmluZyBhdXRob3JpemF0aW9uIHJlcXVpcmVtZW50cy4AAAAAAAAAC0NvbnRleHRSdWxlAAAAAAgAAAApVGhlIHR5cGUgb2YgY29udGV4dCB0aGlzIHJ1bGUgYXBwbGllcyB0by4AAAAAAAAMY29udGV4dF90eXBlAAAH0AAAAA9Db250ZXh0UnVsZVR5cGUAAAAAJ1VuaXF1ZSBpZGVudGlmaWVyIGZvciB0aGUgY29udGV4dCBydWxlLgAAAAACaWQAAAAAAAQAAAApSHVtYW4tcmVhZGFibGUgbmFtZSBmb3IgdGhlIGNvbnRleHQgcnVsZS4AAAAAAAAEbmFtZQAAABAAAAAwTGlzdCBvZiBwb2xpY3kgY29udHJhY3RzIHRoYXQgbXVzdCBiZSBzYXRpc2ZpZWQuAAAACHBvbGljaWVzAAAD6gAAABMAAABKR2xvYmFsIHJlZ2lzdHJ5IElEcyBmb3IgZWFjaCBwb2xpY3ksIHBvc2l0aW9uYWxseSBhbGlnbmVkIHdpdGgKYHBvbGljaWVzYC4AAAAAAApwb2xpY3lfaWRzAAAAAAPqAAAABAAAAElHbG9iYWwgcmVnaXN0cnkgSURzIGZvciBlYWNoIHNpZ25lciwgcG9zaXRpb25hbGx5IGFsaWduZWQgd2l0aApgc2lnbmVyc2AuAAAAAAAACnNpZ25lcl9pZHMAAAAAA+oAAAAEAAAAKExpc3Qgb2Ygc2lnbmVycyBhdXRob3JpemVkIGJ5IHRoaXMgcnVsZS4AAAAHc2lnbmVycwAAAAPqAAAH0AAAAAZTaWduZXIAAAAAADFPcHRpb25hbCBleHBpcmF0aW9uIGxlZGdlciBzZXF1ZW5jZSBmb3IgdGhlIHJ1bGUuAAAAAAAAC3ZhbGlkX3VudGlsAAAAA+gAAAAE",
        "AAAAAgAAAEBUeXBlcyBvZiBjb250ZXh0cyB0aGF0IGNhbiBiZSBhdXRob3JpemVkIGJ5IHNtYXJ0IGFjY291bnQgcnVsZXMuAAAAAAAAAA9Db250ZXh0UnVsZVR5cGUAAAAAAwAAAAAAAAAtRGVmYXVsdCBydWxlcyB0aGF0IGNhbiBhdXRob3JpemUgYW55IGNvbnRleHQuAAAAAAAAB0RlZmF1bHQAAAAAAQAAADBSdWxlcyBzcGVjaWZpYyB0byBjYWxsaW5nIGEgcGFydGljdWxhciBjb250cmFjdC4AAAAMQ2FsbENvbnRyYWN0AAAAAQAAABMAAAABAAAAQlJ1bGVzIHNwZWNpZmljIHRvIGNyZWF0aW5nIGEgY29udHJhY3Qgd2l0aCBhIHBhcnRpY3VsYXIgV0FTTSBoYXNoLgAAAAAADkNyZWF0ZUNvbnRyYWN0AAAAAAABAAAD7gAAACA=" ]),
      options
    )
  }
  public readonly fromJSON = {
    enforce: this.txFromJSON<null>,
        install: this.txFromJSON<null>,
        uninstall: this.txFromJSON<null>,
        get_source: this.txFromJSON<Option<string>>
  }
}