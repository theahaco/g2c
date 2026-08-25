/**
 * Thin shim over the pure relayer client in @nidohq/passkey-sdk: re-exports the
 * types/error/extractor unchanged and wraps the network calls with this
 * app's `PUBLIC_RELAYER_URL` default (the SDK itself has no env coupling).
 */
import { RELAYER_URL, RELAYER_EXPIRATION_OFFSET } from "./network";
import type { RelayerStatus } from "@nidohq/passkey-sdk";
export {
  RelayerError,
  type RelayerStatus,
  type RelayerTxResponse,
  extractFuncAndAuth,
} from "@nidohq/passkey-sdk";
import {
  submitSorobanTransaction as sdkSubmit,
  getRelayerTransaction as sdkGet,
  waitForConfirmation as sdkWait,
  DEFAULT_EXPIRATION_OFFSET,
} from "@nidohq/passkey-sdk";

export function relayerEnabled(): boolean {
  return RELAYER_URL.length > 0;
}

/** The ledger offset a signing ceremony must use for THIS submit mode — the
 *  single source of truth for the value that MUST be passed IDENTICALLY to
 *  `buildAuthHash` and the signature injector(s) (a mismatch makes `__check_auth`
 *  recompute a different digest and reject). In relayer mode use the tight
 *  `RELAYER_EXPIRATION_OFFSET` (the signed entry leaves the browser to an
 *  external service); otherwise the SDK's `DEFAULT_EXPIRATION_OFFSET` (~14h, fine
 *  when the entry never leaves the browser). Call ONCE per ceremony and thread
 *  the result to both the hash builder and the injector. `relayerActive` defaults
 *  to `relayerEnabled()`; pass it explicitly only where the caller already
 *  computed the relayer decision. */
export function signatureExpirationOffset(relayerActive: boolean = relayerEnabled()): number {
  return relayerActive ? RELAYER_EXPIRATION_OFFSET : DEFAULT_EXPIRATION_OFFSET;
}

export const submitSorobanTransaction = (
  args: { func: string; auth: string[]; skipWait?: boolean },
  baseUrl: string = RELAYER_URL,
) => sdkSubmit(args, baseUrl);

export const getRelayerTransaction = (id: string, baseUrl: string = RELAYER_URL) => sdkGet(id, baseUrl);

export const waitForConfirmation = (
  id: string,
  baseUrl: string = RELAYER_URL,
  opts?: {
    intervalMs?: number;
    maxAttempts?: number;
    onPoll?: (info: { status: RelayerStatus | null; attempt: number; maxAttempts: number }) => void;
  },
) => sdkWait(id, baseUrl, opts);
