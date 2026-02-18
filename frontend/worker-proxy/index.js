const PREVIEW_SEP = "--pr-";

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const parts = url.hostname.split(".");
    const sub = parts[0];

    // Check for preview encoding: "<contract>--pr-<N>.mysoroban.xyz"
    // or bare preview root: "pr-<N>.mysoroban.xyz"
    const sepIndex = sub.indexOf(PREVIEW_SEP);
    if (sepIndex !== -1) {
      // Extract PR number and route to Pages preview
      const prBranch = "pr-" + sub.slice(sepIndex + PREVIEW_SEP.length);
      url.hostname = `${prBranch}.mysoroban.pages.dev`;
    } else if (/^pr-\d+$/.test(sub)) {
      // Bare preview root (no contract subdomain)
      url.hostname = `${sub}.mysoroban.pages.dev`;
    } else {
      // Production: route to the Pages custom domain
      url.hostname = "mysoroban.xyz";
    }

    return fetch(url.toString(), { headers: request.headers });
  },
};
