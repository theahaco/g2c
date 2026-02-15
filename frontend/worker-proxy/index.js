export default {
  async fetch(request) {
    const url = new URL(request.url);
    url.hostname = "mysoroban.xyz";
    return fetch(url.toString(), { headers: request.headers });
  },
};
