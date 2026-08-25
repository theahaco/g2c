import { describe, it, expect, beforeEach } from "vitest";
import {
  stashSignRequest,
  loadSignRequest,
  clearSignRequest,
  safeRouteUrl,
  signRequestFromParams,
  type SignRequest,
} from "./signRequest";

const C1 = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

function fakeStore(): Storage {
  const m = new Map<string, string>();
  return {
    getItem: (k) => m.get(k) ?? null,
    setItem: (k, v) => void m.set(k, v),
    removeItem: (k) => void m.delete(k),
    clear: () => m.clear(),
    key: (i) => [...m.keys()][i] ?? null,
    get length() { return m.size; },
  } as Storage;
}

const sample: SignRequest = {
  v: 1, kind: "name-claim", account: C1,
  operation: { type: "register", name: "alice" },
  title: "Claim alice", submitMode: "relayer",
  returnTarget: { type: "route", url: "https://alice.nido.fyi/account/?namepasskey=1" },
};

describe("stash/load SignRequest", () => {
  let store: Storage;
  beforeEach(() => { store = fakeStore(); });

  it("round-trips a request through the store", () => {
    const id = stashSignRequest(sample, store);
    expect(typeof id).toBe("string");
    expect(loadSignRequest(id, store)).toEqual(sample);
  });
  it("returns null for an unknown id", () => {
    expect(loadSignRequest("nope", store)).toBeNull();
  });
  it("returns null for a wrong-version blob", () => {
    store.setItem("nido:signreq:x", JSON.stringify({ v: 2 }));
    expect(loadSignRequest("x", store)).toBeNull();
  });
  it("returns null for malformed json", () => {
    store.setItem("nido:signreq:y", "{not json");
    expect(loadSignRequest("y", store)).toBeNull();
  });
  it("clearSignRequest removes a stashed request (F3 replay hygiene)", () => {
    const id = stashSignRequest(sample, store);
    expect(loadSignRequest(id, store)).not.toBeNull();
    clearSignRequest(id, store);
    expect(loadSignRequest(id, store)).toBeNull();
  });
});

describe("safeRouteUrl (F1 XSS / open-redirect guard)", () => {
  // The base is a CONTRACT subdomain — the real /sign/ origin. Legitimate
  // returns hop to SIBLING subdomains of the same parent domain (nido.fyi):
  // name-claim → `<name>.nido.fyi`, status-message bridge → `status-message.nido.fyi`.
  const ORIGIN = "https://cabc.nido.fyi";

  it("accepts a same-subdomain https URL", () => {
    expect(safeRouteUrl("https://cabc.nido.fyi/account/?namepasskey=1", ORIGIN))
      .toBe("https://cabc.nido.fyi/account/?namepasskey=1");
  });
  it("accepts a SIBLING subdomain on the same parent domain (name-claim hop)", () => {
    expect(safeRouteUrl("https://alice.nido.fyi/account/?namepasskey=1", ORIGIN))
      .toBe("https://alice.nido.fyi/account/?namepasskey=1");
  });
  it("accepts the status-message sibling subdomain (Set-note bridge)", () => {
    expect(safeRouteUrl("https://status-message.nido.fyi/status-message/?contract=C", ORIGIN))
      .toBe("https://status-message.nido.fyi/status-message/?contract=C");
  });
  it("accepts the bare apex", () => {
    expect(safeRouteUrl("https://nido.fyi/account/", ORIGIN)).toBe("https://nido.fyi/account/");
  });
  it("accepts a relative path (resolved against the origin)", () => {
    expect(safeRouteUrl("/account/", ORIGIN)).toBe("https://cabc.nido.fyi/account/");
  });
  it("rejects a javascript: URI", () => {
    expect(safeRouteUrl("javascript:alert(1)", ORIGIN)).toBeNull();
  });
  it("rejects a JavaScript: URI (case-insensitive scheme)", () => {
    expect(safeRouteUrl("JavaScript:alert(1)", ORIGIN)).toBeNull();
  });
  it("rejects a javascript: URI with leading whitespace", () => {
    expect(safeRouteUrl(" javascript:alert(1)", ORIGIN)).toBeNull();
  });
  it("rejects a data: URI", () => {
    expect(safeRouteUrl("data:text/html,<script>alert(1)</script>", ORIGIN)).toBeNull();
  });
  it("rejects a foreign-origin https URL (open redirect)", () => {
    expect(safeRouteUrl("https://evil.example/steal", ORIGIN)).toBeNull();
    expect(safeRouteUrl("https://evil.com", ORIGIN)).toBeNull();
  });
  it("rejects a protocol-relative //evil.com", () => {
    expect(safeRouteUrl("//evil.com", ORIGIN)).toBeNull();
  });
  it("rejects a backslash-prefixed \\\\evil.com", () => {
    expect(safeRouteUrl("\\\\evil.com", ORIGIN)).toBeNull();
  });
  it("rejects a look-alike subdomain suffix (nido.fyi.evil.com)", () => {
    expect(safeRouteUrl("https://nido.fyi.evil.com/steal", ORIGIN)).toBeNull();
  });
  it("rejects a look-alike prefix host (evil-nido.fyi must NOT match .nido.fyi)", () => {
    expect(safeRouteUrl("https://evil-nido.fyi/steal", ORIGIN)).toBeNull();
  });
  it("rejects a userinfo trick (apex@evil.com → hostname is evil.com)", () => {
    expect(safeRouteUrl("https://nido.fyi@evil.com/steal", ORIGIN)).toBeNull();
  });
  it("rejects http for a non-localhost host", () => {
    expect(safeRouteUrl("http://alice.nido.fyi/account/", ORIGIN)).toBeNull();
  });
  it("allows http for localhost (dev)", () => {
    expect(safeRouteUrl("http://localhost:4321/account/", "http://localhost:4321"))
      .toBe("http://localhost:4321/account/");
  });
  it("allows a dev subdomain hop to the localhost apex", () => {
    expect(safeRouteUrl("http://localhost:4321/account/", "http://cabc.localhost:4321"))
      .toBe("http://localhost:4321/account/");
  });
  it("returns null for empty / nullish input", () => {
    expect(safeRouteUrl("", ORIGIN)).toBeNull();
    expect(safeRouteUrl(null, ORIGIN)).toBeNull();
    expect(safeRouteUrl(undefined, ORIGIN)).toBeNull();
  });
});

describe("signRequestFromParams (legacy dApp entry)", () => {
  it("maps a kind=tx dApp request to a dapp-tx SignRequest", () => {
    const p = new URLSearchParams({
      kind: "tx", xdr: "AAAA==", dapp: "https://app.example",
      return: "https://app.example/cb", network: "Test SDF Network ; September 2015",
    });
    expect(signRequestFromParams(p, C1)).toEqual({
      v: 1, kind: "dapp-tx", account: C1,
      operation: { type: "raw-xdr", xdr: "AAAA==" },
      title: "Confirm it's you",
      subtitle: "transaction",
      submitMode: "return-to-dapp",
      returnTarget: { type: "dapp", origin: "https://app.example", returnUrl: "https://app.example/cb" },
      networkPassphrase: "Test SDF Network ; September 2015",
    });
  });
  it("returns null when xdr is missing", () => {
    expect(signRequestFromParams(new URLSearchParams({ kind: "tx", dapp: "https://x" }), C1)).toBeNull();
  });
  it("returns null when account is null", () => {
    expect(signRequestFromParams(new URLSearchParams({ kind: "tx", xdr: "AAAA==", dapp: "https://x" }), null)).toBeNull();
  });
  it("returns null for non-tx kinds (message/authEntry handled elsewhere)", () => {
    expect(signRequestFromParams(new URLSearchParams({ kind: "message", message: "hi", dapp: "https://x" }), C1)).toBeNull();
  });

  // Source-side origin/return validation (defence in depth vs. the /sign/
  // consumer's own check): the spoof-origin / exfiltrate-signature vector.
  it("rejects a cross-origin return URL (spoof-origin, exfiltrate signature)", () => {
    const p = new URLSearchParams({
      kind: "tx", xdr: "AAAA==", dapp: "https://good.example",
      return: "https://attacker.example/steal",
    });
    expect(signRequestFromParams(p, C1)).toBeNull();
  });
  it("rejects a non-http(s) dapp origin (javascript:)", () => {
    expect(signRequestFromParams(
      new URLSearchParams({ kind: "tx", xdr: "AAAA==", dapp: "javascript:alert(1)" }), C1,
    )).toBeNull();
  });
  it("rejects a malformed / relative dapp origin", () => {
    expect(signRequestFromParams(
      new URLSearchParams({ kind: "tx", xdr: "AAAA==", dapp: "not-a-url" }), C1,
    )).toBeNull();
  });
  it("allows a dApp request with no return URL (posts back to the dapp origin)", () => {
    const p = new URLSearchParams({ kind: "tx", xdr: "AAAA==", dapp: "https://app.example/launch?x=1" });
    const req = signRequestFromParams(p, C1);
    expect(req?.returnTarget).toEqual({ type: "dapp", origin: "https://app.example", returnUrl: undefined });
  });
  it("normalises the dapp param to its bare origin for display", () => {
    const p = new URLSearchParams({
      kind: "tx", xdr: "AAAA==", dapp: "https://app.example/deep/path",
      return: "https://app.example/cb",
    });
    const req = signRequestFromParams(p, C1);
    expect((req?.returnTarget as { origin: string }).origin).toBe("https://app.example");
  });
});
