import { describe, expect, it } from "vitest";
import { createNido } from "./createNido.js";

describe("createNido", () => {
  it("keeps apex hosts intact", () => {
    expect(createNido("nido.fyi")).toMatch(/^\/\/nido\.fyi\/new-account\/\?setup=1#salt=[0-9a-f]{64}$/);
  });

  it("keeps numeric preview root hosts intact", () => {
    expect(createNido("85.nido.fyi")).toMatch(/^\/\/85\.nido\.fyi\/new-account\/\?setup=1#salt=[0-9a-f]{64}$/);
  });

  it("normalizes legacy preview root hosts to numeric roots", () => {
    expect(createNido("pr-85.nido.fyi")).toMatch(/^\/\/85\.nido\.fyi\/new-account\/\?setup=1#salt=[0-9a-f]{64}$/);
  });

  it("strips account subdomains before setup", () => {
    expect(createNido("cabc.nido.fyi")).toMatch(/^\/\/nido\.fyi\/new-account\/\?setup=1#salt=[0-9a-f]{64}$/);
  });
});
