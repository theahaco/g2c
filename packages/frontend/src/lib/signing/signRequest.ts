export type OperationDescriptor =
  | { type: "register"; name: string }
  | { type: "transfer"; token: string; to: string; amountRaw: string; decimals?: number; code?: string }
  | {
      type: "add-context-rule";
      target: string;
      signerPublicKeyHex: string;
      verifierAddress: string;
      validUntil: number | null;
      limit?: { stroops: string; periodLedgers: number } | null;
      label?: string;
      /** Human-readable expiry label set by the caller (e.g. "7 days", "Until revoked").
       *  /sign/ uses this instead of computing a date from the ledger sequence. */
      expiryLabel?: string;
    }
  | { type: "remove-context-rule"; ruleId: number; target: string }
  | { type: "raw-xdr"; xdr: string };

export type SignKind =
  | "name-claim" | "transfer" | "session-grant" | "session-revoke" | "dapp-tx" | "generic";

export type SubmitMode = "relayer" | "return-to-dapp";

export type EditableControl = {
  field: "spending-limit";
  initialStroops: string | null;
  initialPeriod: "day" | "week" | "30d";
};

export type ReturnTarget =
  | { type: "route"; url: string }
  // `successQuery` overrides the default submitted-marker query a dApp return
  // appends on success. ADDITIVE: when absent (the dapp-tx path), /sign/ keeps
  // appending `?nido_submitted=<hash>&kind=tx`. The session-grant caller sets
  // it to `?delegation=ok` so the existing `delegationHandover.readDelegationReturn`
  // contract keeps working unchanged.
  | { type: "dapp"; origin: string; returnUrl?: string; successQuery?: string };

export interface SignRequest {
  v: 1;
  kind: SignKind;
  account: string;
  operation: OperationDescriptor;
  title: string;
  subtitle?: string;
  submitMode: SubmitMode;
  editable?: EditableControl[];
  returnTarget: ReturnTarget;
  networkPassphrase?: string;
}

import { stripSubdomain } from "@nidohq/passkey-sdk";

const KEY = (id: string) => `nido:signreq:${id}`;

export function stashSignRequest(req: SignRequest, store: Storage = sessionStorage): string {
  const id = crypto.randomUUID();
  store.setItem(KEY(id), JSON.stringify(req));
  return id;
}

export function loadSignRequest(id: string, store: Storage = sessionStorage): SignRequest | null {
  const raw = store.getItem(KEY(id));
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as SignRequest;
    return parsed && parsed.v === 1 ? parsed : null;
  } catch {
    return null;
  }
}

/** Remove a stashed SignRequest (F3 — back/forward replay hygiene).
 *
 *  Called from /sign/ ONLY after a successful submit, never on load: a failed
 *  attempt must stay retryable. After consumption the entry is gone, so a
 *  back-button to `/sign/?req=<id>` reloads nothing rather than re-submitting
 *  the same request. */
export function clearSignRequest(id: string, store: Storage = sessionStorage): void {
  store.removeItem(KEY(id));
}

/** Strip a trailing `:port` from a host string, yielding the bare hostname.
 *  IPv6 literals aren't used by this app, so a simple last-colon split is fine. */
function hostnameOf(host: string): string {
  const i = host.lastIndexOf(":");
  return i === -1 ? host : host.slice(0, i);
}

/** Validate a route-return URL and normalise it (F1 — XSS / open-redirect guard).
 *
 *  Returns the URL string only when it resolves (against `base`) to an http(s)
 *  location whose hostname is the SAME PARENT DOMAIN as `base` — i.e. the apex
 *  itself, or a subdomain of it. Everything else (including `javascript:`,
 *  `data:`, foreign origins, protocol-relative `//evil`, and userinfo tricks)
 *  is rejected. Used at BOTH the source (reject a hostile `sm-return`) and the
 *  sink (fall back to /account/).
 *
 *  Why not strict same-origin? Nido's multi-subdomain architecture has
 *  legitimate cross-subdomain hops that the unified /sign/ surface depends on:
 *   - name-claim returns from `<contractid>.<apex>` to `<name>.<apex>`
 *     (`/account/?namepasskey=1`, to fire moment-B passkey registration);
 *   - the status-message bridge returns to `status-message.<apex>`.
 *  Both build their destinations with `accountUrl(stripSubdomain(host), …)`, so
 *  the allowlist is derived the SAME way (`stripSubdomain(base.host)`) and thus
 *  matches exactly those destinations and no more.
 *
 *  SECURITY: parse with the WHATWG `URL` so backslash / userinfo / whitespace
 *  tricks are normalised before the hostname check. The apex suffix test
 *  requires a literal leading dot (`"." + apex`), so `evil-nido.fyi` does NOT
 *  match `.nido.fyi`. http is permitted only for localhost/127.0.0.1 (dev).
 *
 *  `base` lets callers resolve relative URLs (e.g. `/account/`) and supplies the
 *  current host whose parent domain forms the allowlist — pass
 *  `window.location.origin` in the browser. */
export function safeRouteUrl(url: string | null | undefined, base: string): string | null {
  if (!url) return null;
  try {
    const u = new URL(url, base);
    const baseUrl = new URL(base);

    // localhost may be served over http during dev; everything else must be https.
    if (u.protocol === "https:") {
      // ok
    } else if (u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1")) {
      // ok (dev)
    } else {
      return null;
    }

    // Same parent domain as the current host. `stripSubdomain` reduces a host to
    // its account-root (apex in prod, the `--<N>` preview root in previews,
    // `localhost:<port>` in dev); the candidate is allowed when it is that apex,
    // a subdomain of it, or reduces to the same root (covers preview siblings
    // like `<name>--24.apex` whose dot-suffix differs from the bare root).
    const apex = hostnameOf(stripSubdomain(baseUrl.host));
    const candidateRoot = hostnameOf(stripSubdomain(u.host));
    if (u.hostname === apex || u.hostname.endsWith("." + apex) || candidateRoot === apex) {
      return u.href;
    }
    return null;
  } catch {
    return null;
  }
}

/** Normalise an absolute URL to its ORIGIN iff it is a usable dApp origin:
 *  https anywhere, or http only for localhost/127.0.0.1 (dev). Returns null for
 *  malformed, relative, or disallowed-scheme (`javascript:`/`data:`/…) inputs.
 *
 *  Unlike `safeRouteUrl`, this deliberately does NOT restrict to the same
 *  parent domain — a dApp is legitimately a FOREIGN origin. It only enforces a
 *  well-formed http(s) scheme, so it is the right check for the cross-app
 *  signing return, where `safeRouteUrl`'s same-parent-domain rule would wrongly
 *  reject every real dApp. */
export function httpOrigin(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    const u = new URL(url);
    if (u.protocol === "https:") return u.origin;
    if (u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1")) {
      return u.origin;
    }
    return null;
  } catch {
    return null;
  }
}

export function signRequestFromParams(params: URLSearchParams, account: string | null): SignRequest | null {
  if (!account) return null;
  const kind = params.get("kind") ?? "tx";
  if (kind !== "tx") return null; // message/authEntry keep their own (non-submitting) path
  const xdr = params.get("xdr");
  const dapp = params.get("dapp");
  if (!xdr || !dapp) return null;
  const ret = params.get("return") ?? undefined;
  const network = params.get("network") ?? undefined;

  // Validate the dApp origin + return at the SOURCE (defence in depth — the
  // /sign/ page re-validates the same way at consume time). A dApp is a foreign
  // origin by design, so `safeRouteUrl` does NOT apply here; instead require:
  //   - `dapp` is a well-formed http(s) origin (rejects javascript:/data:/malformed);
  //   - if a `return` URL is given, it is SAME-ORIGIN as `dapp`.
  // This closes the spoof-origin / exfiltrate-signature vector (a page passing
  // dapp=<trusted>&return=<attacker> so /sign/ displays the trusted name while
  // the signature is posted to the attacker): the mismatch is rejected right
  // here, so a hostile SignRequest is never stashed in the first place. The
  // normalised origin (not the raw param) is what gets displayed downstream.
  const origin = httpOrigin(dapp);
  if (!origin) return null;
  if (ret !== undefined && httpOrigin(ret) !== origin) return null;

  return {
    v: 1, kind: "dapp-tx", account,
    operation: { type: "raw-xdr", xdr },
    title: "Confirm it's you",
    // F8: the /sign/ lead is the fixed sentence "<origin> wants this account to
    // sign a <subtitle>." — so the subtitle must be the bare NOUN, not a full
    // sentence, or the copy doubles ("…sign a <dapp> wants this account to…").
    subtitle: "transaction",
    submitMode: "return-to-dapp",
    returnTarget: { type: "dapp", origin, returnUrl: ret },
    networkPassphrase: network,
  };
}
