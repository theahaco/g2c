/**
 * Pure relayer client for the Channels plugin protocol (OpenZeppelin
 * Relayer behind a Caddy /relay route). No environment coupling: callers
 * supply `baseUrl` explicitly — the frontend's `relayerClient.ts` shim adds
 * its `PUBLIC_RELAYER_URL` default, and dApps pass their own.
 */
import type { Transaction } from "@stellar/stellar-sdk";

/** Statuses emitted by the Channels plugin. */
export type RelayerStatus = "pending" | "sent" | "submitted" | "confirmed" | "failed" | "expired";

export interface RelayerTxResponse {
  transactionId: string | null;
  hash: string | null;
  status: RelayerStatus | null;
}

export class RelayerError extends Error {
  override name = "RelayerError";
  constructor(
    message: string,
    readonly code?: string,
    readonly details?: unknown,
  ) {
    super(message);
  }
}

/** POST {params} to the Caddy /relay route (which forwards to the Channels
 *  plugin with the relayer API key injected server-side — the browser never
 *  holds a key). Handles both response nestings: the plugin README documents
 *  {success, data: {...}}, while the relayer v1.5.0 example README shows
 *  {success, data: {result: {...}}}. */
async function call(params: Record<string, unknown>, baseUrl: string): Promise<RelayerTxResponse> {
  if (!baseUrl) throw new RelayerError("Relayer not configured (PUBLIC_RELAYER_URL is empty)");
  const resp = await fetch(`${baseUrl}/relay`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ params }),
  });
  let body: { success?: boolean; data?: unknown; error?: string | null };
  try {
    body = (await resp.json()) ?? {};
  } catch {
    throw new RelayerError(`Relayer returned non-JSON (HTTP ${resp.status})`);
  }
  if (body.success === false || (!resp.ok && body.error)) {
    const data = body.data as { code?: string; details?: unknown } | undefined;
    throw new RelayerError(body.error ?? `Relayer HTTP ${resp.status}`, data?.code, data?.details);
  }
  if (!resp.ok) throw new RelayerError(`Relayer HTTP ${resp.status}`);
  const data = body.data as ({ result?: RelayerTxResponse } & RelayerTxResponse) | undefined;
  const payload = data?.result ?? data;
  if (!payload || typeof payload !== "object") throw new RelayerError("Relayer returned an empty payload");
  if (!("transactionId" in payload) && !("status" in payload)) {
    throw new RelayerError("Unrecognized relayer payload", undefined, body);
  }
  return payload as RelayerTxResponse;
}

/** Submit host function + pre-signed auth entries (both base64 XDR).
 *  skipWait defaults to true: we poll ourselves rather than holding the
 *  plugin's 30s execution window open. */
export async function submitSorobanTransaction(
  args: { func: string; auth: string[]; skipWait?: boolean },
  baseUrl: string,
): Promise<RelayerTxResponse> {
  return call({ func: args.func, auth: args.auth, skipWait: args.skipWait ?? true }, baseUrl);
}

export async function submitXdrTransaction(
  args: { xdr: string; skipWait?: boolean },
  baseUrl: string,
): Promise<RelayerTxResponse> {
  return call({ xdr: args.xdr, skipWait: args.skipWait ?? true }, baseUrl);
}

export async function getRelayerTransaction(
  transactionId: string,
  baseUrl: string,
): Promise<RelayerTxResponse> {
  return call({ getTransaction: { transactionId } }, baseUrl);
}

export async function waitForConfirmation(
  transactionId: string,
  baseUrl: string,
  opts?: {
    intervalMs?: number;
    maxAttempts?: number;
    /** Fired after every successful poll, so callers can surface a live
     *  status/attempt ticker during the wait. Never fired on a poll failure. */
    onPoll?: (info: { status: RelayerStatus | null; attempt: number; maxAttempts: number }) => void;
  },
): Promise<RelayerTxResponse> {
  const interval = opts?.intervalMs ?? 1500;
  // The channel tx's own validity window is build-time + 60s (the plugin's
  // MAX_TIME_BOUND_OFFSET_SECONDS default). Poll PAST it (~82s) so we almost
  // always land on a terminal status (confirmed/failed/expired) instead of
  // giving up while the tx can still land — WAIT_TIMEOUT invites a retry,
  // and a retry racing a still-valid tx is a double-send.
  const maxAttempts = opts?.maxAttempts ?? 55;
  let last: RelayerTxResponse | undefined;
  let pollFailures = 0;
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const res = await getRelayerTransaction(transactionId, baseUrl);
      last = res;
      pollFailures = 0;
      opts?.onPoll?.({ status: res.status, attempt: i + 1, maxAttempts });
      if (res.status === "confirmed") return res;
      if (res.status === "failed" || res.status === "expired") {
        throw new RelayerError(`Relayer transaction ${res.status}`, "ONCHAIN_FAILED", res);
      }
    } catch (err) {
      if (err instanceof RelayerError && err.code === "ONCHAIN_FAILED") throw err;
      // A transient poll failure (network blip, 5xx) must not abort the wait —
      // the tx is already in flight. Only give up after several in a row.
      if (++pollFailures >= 5) {
        throw new RelayerError("Lost contact with the relayer while waiting", "WAIT_TIMEOUT", last);
      }
    }
    if (i < maxAttempts - 1) await new Promise((r) => setTimeout(r, interval));
  }
  // The tx may still land after we give up (typically still "submitted") —
  // attach the last poll so the UI can surface a hash if one exists.
  throw new RelayerError("Timed out waiting for relayer confirmation", "WAIT_TIMEOUT", last);
}

/** Pull the base64 HostFunction + auth-entry XDRs off a built invoke tx —
 *  exactly the {func, auth} shape the Channels plugin consumes.
 *  Assumes a freshly built v1 single-op Soroban tx; the xdr accessors throw otherwise. */
export function extractFuncAndAuth(tx: Transaction): { func: string; auth: string[] } {
  const op = tx.toEnvelope().v1().tx().operations()[0].body().invokeHostFunctionOp();
  return {
    func: op.hostFunction().toXDR("base64"),
    auth: op.auth().map((a) => a.toXDR("base64")),
  };
}
