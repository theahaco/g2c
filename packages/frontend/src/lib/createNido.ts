import { buf2hex, stripSubdomain } from "@nidohq/passkey-sdk";

function setupHost(host: string): string {
  const hostname = host.split(":")[0];
  if (hostname === "localhost" || /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    return host;
  }
  const first = hostname.split(".")[0];
  if (/^\d+$/.test(first) || hostname.split(".").length <= 2) {
    return host;
  }
  const legacyPreview = first.match(/^pr-(\d+)$/);
  if (legacyPreview) {
    return host.replace(/^pr-\d+(?=\.)/, legacyPreview[1]);
  }
  return stripSubdomain(host);
}

export function createNido(host: string): string {
  const salt = new Uint8Array(32);
  crypto.getRandomValues(salt);
  // A2: the salt is a SETUP SECRET — it derives the deterministic account
  // address and whoever holds it can claim the pre-funded account before the
  // owner attaches a passkey. Carry it in the URL HASH, never the query: the
  // fragment is never sent to the server, so it stays out of worker/CDN access
  // logs and cross-origin Referer. `setup=1` is not secret and stays a query
  // param (the receiver reads it before the salt is scrubbed).
  return `//${setupHost(host)}/new-account/?setup=1#salt=${buf2hex(salt)}`;
}
