export default {
  async fetch(request) {
    const url = new URL(request.url);
    const hostParts = url.hostname.split(".");

    // Match: <contract>.pr-<N>.mysoroban.xyz  (4 parts)
    // or:           pr-<N>.mysoroban.xyz       (3 parts, no contract subdomain)
    const prMatch = hostParts.find((p) => /^pr-\d+$/.test(p));

    if (prMatch) {
      // Route to the Cloudflare Pages preview deployment
      url.hostname = `${prMatch}.mysoroban.pages.dev`;
    } else {
      // Production: route to the Pages custom domain
      url.hostname = "mysoroban.xyz";
    }

    return fetch(url.toString(), { headers: request.headers });
  },
};
