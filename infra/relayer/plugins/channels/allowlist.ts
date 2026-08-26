/**
 * allowlist.ts
 *
 * Host-function allowlist: the security boundary between "anyone can ask the relayer
 * channels path to submit ANY Soroban invoke" and "only the contract calls the nido
 * app legitimately relays" (its account/registry/recovery operations). This is the
 * app's single relayer (PUBLIC_RELAYER_URL) — it fee-sponsors normal wallet actions
 * (name registration, transfers, session keys, social recovery) AND the ZK
 * recovery/genesis path, so the list must cover BOTH. The relayer receives a Soroban
 * invoke as a base64
 * `func` (InvokeHostFunction XDR) + `auth`, per
 * `packages/passkey-sdk/src/relayer.ts::submitSorobanTransaction`, which POSTs
 * `{ params: { func, auth, skipWait } }`.
 *
 * SECURITY: always decode the ACTUAL host function XDR to find the invoked contract
 * function name. Never trust a caller-declared/label field for this decision — a
 * malicious caller could set any string there while the encoded HostFunction invokes
 * something else entirely.
 */
import { xdr } from '@stellar/stellar-sdk';
import { pluginError } from '@openzeppelin/relayer-sdk';

/**
 * Contract functions the relayer channels path is allowed to submit — the full set the
 * nido app relays, grouped below. Auth is always enforced on-chain (the passkey on the
 * signed auth entry); this list only bounds WHICH functions the relayer will
 * fee-sponsor, so it can't be turned into an open drain.
 *
 * `execute` is the smart account's own wrapper (`execute(target, fn, args)`) — it backs
 * every token transfer and is intentionally broad: the account's `require_auth` inside
 * `execute` is the real gate, not this list. Likewise `add_context_rule` covers session
 * keys, social-recovery install, name-passkey, AND the zero-signer recovery-completion
 * shape (mid-recovery the account has no normally-authorizing signer, so completion must
 * be relayer-submittable); the contract enforces that each only succeeds in its valid
 * state.
 *
 * If you add a new user action that the app submits through the relayer, add its
 * top-level invoked function here or the relayer will 403 it (this exact regression).
 */
export const ALLOWED_FUNCTIONS: ReadonlySet<string> = new Set([
  // Ephemeral G
  'approve',
  // Genesis (factory) + ZK recovery ceremony
  'create_account',
  'create_account_v2',
  'insert_for',
  'initiate_recovery',
  'cancel_recovery',
  'burn_nullifier',
  'enroll_zk_recovery',
  // Account operations (session keys, social recovery, transfers, name-passkey)
  'add_context_rule',
  'remove_context_rule',
  'add_signer',
  'remove_signer',
  'execute',
  'transfer_from',
  // Name registry
  'register',
]);

/**
 * Decode an InvokeHostFunction XDR (base64) and return the invoked contract function
 * name, or `null` when it isn't an InvokeContract host function.
 *
 * create-contract / create-contract-v2 / upload-wasm host functions are deliberately
 * NOT client submissions to gate here by name (they're genesis/deploy tooling, not part
 * of the relayer's client-facing recovery path) — returning `null` for them means
 * `isAllowed` treats them as not-allowed, so the relayer rejects them too. If a future
 * flow legitimately needs the relayer to submit one of those host function kinds, it
 * must be handled here explicitly rather than silently falling through.
 */
export function invokedFunctionName(funcXdrBase64: string): string | null {
  let hostFunction: xdr.HostFunction;
  try {
    hostFunction = xdr.HostFunction.fromXDR(funcXdrBase64, 'base64');
  } catch {
    return null;
  }

  if (hostFunction.switch() !== xdr.HostFunctionType.hostFunctionTypeInvokeContract()) {
    return null;
  }

  const fnName = hostFunction.invokeContract().functionName();
  return typeof fnName === 'string' ? fnName : fnName.toString('utf8');
}

/** True iff the decoded, actual invoked function is in {@link ALLOWED_FUNCTIONS}. */
export function isAllowed(funcXdrBase64: string): boolean {
  const name = invokedFunctionName(funcXdrBase64);
  return name !== null && ALLOWED_FUNCTIONS.has(name);
}

/**
 * Pre-submit gate: throws a clear, structured error when the invoked function is not
 * allowed. Call this before the transaction is simulated/submitted.
 */
export function assertAllowedOrReject(funcXdrBase64: string): void {
  const name = invokedFunctionName(funcXdrBase64);
  if (name !== null && ALLOWED_FUNCTIONS.has(name)) {
    return;
  }

  throw pluginError(
    name === null
      ? 'Relayer channels plugin: submitted host function is not an allowed contract invocation'
      : `Relayer channels plugin: function "${name}" is not in the nido relayer allowlist`,
    {
      code: 'FUNCTION_NOT_ALLOWED',
      status: 403,
      details: { function: name },
    },
  );
}
