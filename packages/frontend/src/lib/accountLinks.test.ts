import { describe, it, expect } from "vitest";
import { accountShareUrl, accountShareLabel, nidoRowHref } from "./accountLinks.js";
import type { MyNidoRow } from "./myNidoModel.js";

describe("accountShareUrl", () => {
  it("builds a bare subdomain URL with no /account/ suffix", () => {
    expect(accountShareUrl("nido.fyi", "alice")).toBe("//alice.nido.fyi/");
  });
  it("lowercases a contract-id subdomain and has no /account/ suffix", () => {
    const url = accountShareUrl("nido.fyi", "CABC");
    expect(url).toBe("//cabc.nido.fyi/");
    expect(url).not.toContain("/account/");
  });
});

describe("accountShareLabel", () => {
  it("strips the scheme and trailing slash", () => {
    expect(accountShareLabel("nido.fyi", "alice")).toBe("alice.nido.fyi");
  });
  it("never contains an /account/ suffix", () => {
    expect(accountShareLabel("nido.fyi", "alice")).not.toContain("/account");
  });
});

describe("nidoRowHref", () => {
  it("active row with a name → bare account URL", () => {
    const row: MyNidoRow = { contractId: "CABCDEF", name: "alice", status: "active" };
    expect(nidoRowHref("nido.fyi", row)).toBe("//alice.nido.fyi/");
  });
  it("active row without a name → bare contract subdomain", () => {
    const row: MyNidoRow = { contractId: "CABCDEF", name: null, status: "active" };
    expect(nidoRowHref("nido.fyi", row)).toBe("//cabcdef.nido.fyi/");
  });
  it("pending row → resume setup at /new-account/, no /account/ suffix", () => {
    const row: MyNidoRow = { contractId: "CABCDEF", name: null, status: "pending", resumeKey: "abc123" };
    const href = nidoRowHref("nido.fyi", row);
    expect(href).toContain("/new-account/#salt=abc123");
    expect(href).not.toContain("/account/");
  });
});
