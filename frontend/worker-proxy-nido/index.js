/**
 * nido.fyi wildcard-subdomain proxy. Identical logic to the mysoroban-proxy
 * worker, but the upstream origin is the `nido` Pages project
 * (`nido-1am.pages.dev`) rather than the apex. Bound to `*.nido.fyi/*`.
 *
 * Keep `RESERVED_DAPP_SUBDOMAINS` in sync with `packages/passkey-sdk/src/url.ts`.
 */
const RESERVED_DAPP_SUBDOMAINS = {
  "status-message": "/status-message/",
};

// The Pages production origin for nido (Cloudflare appended "-1am" because the
// bare `nido` project subdomain was taken).
const PAGES = "nido-1am.pages.dev";

function previewSubdomain(sub) {
  const match = sub.match(/^(.*)--(?:pr-)?(\d+)$/);
  return match ? { raw: match[1], pr: match[2] } : { raw: sub, pr: null };
}

function previewRoot(sub) {
  const numeric = sub.match(/^(\d+)$/);
  if (numeric) return numeric[1];
  const legacy = sub.match(/^pr-(\d+)$/);
  return legacy ? legacy[1] : null;
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const parts = url.hostname.split(".");
    const sub = parts[0];

    const preview = previewSubdomain(sub);
    const dappPath = RESERVED_DAPP_SUBDOMAINS[preview.raw.toLowerCase()];

    if (dappPath && url.pathname === "/") {
      url.pathname = dappPath;
    }

    if (preview.pr) {
      const prBranch = "pr-" + preview.pr;
      url.hostname = `${prBranch}.${PAGES}`;
    } else {
      const pr = previewRoot(sub);
      if (pr) {
        url.hostname = `pr-${pr}.${PAGES}`;
      } else {
        url.hostname = PAGES;
      }
    }

    const upstream = await fetch(url.toString(), { headers: request.headers });

    // Attach security headers the Pages origin doesn't set. Cloudflare Response
    // headers are immutable until copied into a fresh Response.
    const response = new Response(upstream.body, upstream);
    // Block MIME-sniffing and framing (this is a signing surface -- no clickjacking).
    response.headers.set("X-Content-Type-Options", "nosniff");
    response.headers.set("X-Frame-Options", "DENY");
    // The account C-address / name is the HOST subdomain (e.g. `Cabc...def.nido.fyi`),
    // NOT the URL path -- so `strict-origin-when-cross-origin` would still leak the
    // active account to every cross-origin request (fonts, price/RPC APIs) via the
    // Origin it keeps in Referer. `no-referrer` sends no Referer at all; nothing in
    // the app relies on it (cross-origin calls are unauthenticated and addressed by URL).
    response.headers.set("Referrer-Policy", "no-referrer");

    // CSP still shipped in *Report-Only* (never blocks) so the enforced flip can
    // be browser-verified first -- but the policy is now TIGHT, not `connect-src
    // https:`. The allowlist below is every host the app actually reaches:
    //   - *.nido.fyi          — sibling account/app subdomains (name resolution, cross-app)
    //   - nido.fly.dev        — OZ relayer (Channels)
    //   - soroban/horizon/friendbot.stellar.org — Stellar RPC / Horizon / testnet funding
    //   - api.refractor.space, api.soroswap.finance — tx-coordination + token/price API
    //   - fonts.googleapis.com (stylesheet) + fonts.gstatic.com (font files) — NidoLayout.astro
    // Keep it identical to packages/frontend/public/_headers (the static-origin
    // copy). style-src still carries 'unsafe-inline' (Astro/Tailwind inline styles);
    // dropping it needs its own verification pass.
    // TODO(mainnet cutover): the Stellar hosts below are TESTNET
    // (soroban-testnet/horizon-testnet/friendbot). At mainnet, swap to
    // soroban.stellar.org + horizon.stellar.org and REMOVE friendbot, in lockstep
    // with the frontend network config AND packages/frontend/public/_headers.
    // TODO(audit E): after a clean report stream in prod, promote to
    // `Content-Security-Policy` (drop `-Report-Only`). See docs/MAINNET_READINESS.md.
    response.headers.set(
      "Content-Security-Policy-Report-Only",
      [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "img-src 'self' data:",
        "font-src 'self' data: https://fonts.gstatic.com",
        "connect-src 'self' https://*.nido.fyi https://nido.fly.dev https://soroban-testnet.stellar.org https://horizon-testnet.stellar.org https://friendbot.stellar.org https://api.refractor.space https://api.soroswap.finance",
        "object-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'none'",
        "form-action 'self'",
      ].join("; "),
    );
    return response;
  },
};
