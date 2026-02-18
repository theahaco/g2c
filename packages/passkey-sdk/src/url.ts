const PREVIEW_SEP = "--pr-";

/**
 * Extract contract ID from a subdomain hostname.
 * Handles both production and preview URLs:
 *   "cabc1234.mysoroban.xyz"             → "CABC1234"
 *   "cabc1234--pr-10.mysoroban.xyz"      → "CABC1234"
 * Returns null if hostname has no subdomain or contract ID.
 */
export function contractIdFromHostname(hostname: string): string | null {
  const parts = hostname.split(".");
  if (parts.length <= 1) return null;

  const sub = parts[0];
  const sepIndex = sub.indexOf(PREVIEW_SEP);
  const raw = sepIndex !== -1 ? sub.slice(0, sepIndex) : sub;
  return raw ? raw.toUpperCase() : null;
}

/**
 * Build a protocol-relative URL with the contract ID as subdomain.
 * In preview environments (hostname contains --pr-<N>), encodes the
 * contract ID into the same subdomain level:
 *   accountUrl("pr-10.mysoroban.xyz", "CABC", "/account/")
 *     → "//cabc--pr-10.mysoroban.xyz/account/"
 *
 * In production:
 *   accountUrl("mysoroban.xyz", "CABC", "/account/")
 *     → "//cabc.mysoroban.xyz/account/"
 *
 * Pass `window.location.host` (includes port) as the host parameter.
 */
export function accountUrl(host: string, contractId: string, path: string = "/"): string {
  const preview = previewPrefix(host);
  if (preview) {
    const base = stripSubdomain(host);
    return `//${contractId.toLowerCase()}${PREVIEW_SEP}${preview}.${base}${path}`;
  }
  return `//${contractId.toLowerCase()}.${host}${path}`;
}

/**
 * Strip the first subdomain segment from a host string.
 * e.g. "cabc1234.example.com" → "example.com"
 *      "cabc1234.localhost:3000" → "localhost:3000"
 */
export function stripSubdomain(host: string): string {
  const dotIndex = host.indexOf(".");
  if (dotIndex === -1) return host;
  return host.slice(dotIndex + 1);
}

/**
 * Extract the preview prefix (e.g. "pr-10") from a hostname, or null if production.
 * Checks the first subdomain segment for the --pr-<N> separator,
 * and also matches bare "pr-<N>" subdomains (the preview root).
 */
function previewPrefix(host: string): string | null {
  const parts = host.split(".");
  if (parts.length <= 1) return null;

  const sub = parts[0];

  // Contract subdomain with preview: "cabc1234--pr-10"
  const sepIndex = sub.indexOf(PREVIEW_SEP);
  if (sepIndex !== -1) {
    return sub.slice(sepIndex + PREVIEW_SEP.length);
  }

  // Bare preview root: "pr-10"
  if (/^pr-\d+$/.test(sub)) {
    return sub;
  }

  return null;
}
