/**
 * Extract contract ID from a subdomain hostname.
 * Handles both production and preview URLs:
 *   "cabc1234.mysoroban.xyz"             → "CABC1234"
 *   "cabc1234--pr-10.mysoroban.xyz"      → "CABC1234"
 * Returns null if hostname has no subdomain or contract ID.
 */
export declare function contractIdFromHostname(hostname: string): string | null;
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
export declare function accountUrl(host: string, contractId: string, path?: string): string;
/**
 * Strip the contract ID from a host string, preserving any preview prefix.
 *   "cabc1234.mysoroban.xyz"            → "mysoroban.xyz"
 *   "cabc1234--pr-10.mysoroban.xyz"     → "pr-10.mysoroban.xyz"
 *   "cabc1234.localhost:3000"           → "localhost:3000"
 */
export declare function stripSubdomain(host: string): string;
//# sourceMappingURL=url.d.ts.map