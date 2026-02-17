/**
 * Extract contract ID from a subdomain hostname.
 * e.g. "cabc1234.example.com" → "CABC1234"
 * Returns null if hostname has no subdomain.
 */
export function contractIdFromHostname(hostname: string): string | null {
  const parts = hostname.split(".");
  return parts.length > 1 ? parts[0].toUpperCase() : null;
}

/**
 * Build a protocol-relative URL with the contract ID as subdomain.
 * e.g. accountUrl("example.com", "CABC1234", "/account/") → "//cabc1234.example.com/account/"
 *
 * Pass `window.location.host` (includes port) as the host parameter.
 */
export function accountUrl(host: string, contractId: string, path: string = "/"): string {
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
