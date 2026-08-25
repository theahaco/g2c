// Bare account-location links. An account lives at the root of its own
// subdomain — `alice.nido.fyi` — and that root redirects to `/account/`
// (src/pages/index.astro). So a shareable / navigational link to an account is
// the bare subdomain, with no `/account/` suffix.
import { accountUrl } from "@nidohq/passkey-sdk";
import type { MyNidoRow } from "./myNidoModel";

/** Protocol-relative bare account URL, e.g. `//alice.nido.fyi/`. */
export function accountShareUrl(host: string, nameOrId: string): string {
  return accountUrl(host, nameOrId, "/");
}

/** Display label for a share link, e.g. `alice.nido.fyi` (no scheme, no trailing slash). */
export function accountShareLabel(host: string, nameOrId: string): string {
  return accountShareUrl(host, nameOrId).replace(/^\/\//, "").replace(/\/+$/, "");
}

/** Href for a My Nido switcher row: active rows → bare account URL; pending rows
 *  → resume the setup flow at `/new-account/`.
 *
 *  Note: this passes the RAW `host` (not `stripSubdomain(host)`, unlike the
 *  share-link caller). That is correct — `accountUrl` self-normalizes the apex
 *  (it drops the first label only when the host has >2 labels), so the row href
 *  is right both on the apex landing switcher (`nido.fyi` → `//bob.nido.fyi/`)
 *  and on account subdomains in production; stripping first would wrongly yield
 *  `//bob.fyi/` on the apex. The only shape it cannot self-normalize is a
 *  single-label-apex subdomain like `alice.localhost` in dev (mis-nests to
 *  `//bob.alice.localhost/`); production hosts are unaffected. */
export function nidoRowHref(host: string, row: MyNidoRow): string {
  if (row.status === "pending") {
    // A2: resume key is the setup secret — carry it in the hash, not the query
    // (never sent to the server; kept out of worker/CDN logs + Referer).
    return accountUrl(host, row.contractId, `/new-account/#salt=${encodeURIComponent(row.resumeKey ?? "")}`);
  }
  return accountShareUrl(host, row.name ?? row.contractId);
}
