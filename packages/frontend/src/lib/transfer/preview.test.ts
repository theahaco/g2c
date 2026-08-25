import { afterEach, describe, expect, it, vi } from "vitest";
import { Account, Operation, StrKey } from "@stellar/stellar-sdk";

// Shared, hoisted state the module mocks read. `simSource` is a getter-backed
// value so each test can vary PUBLIC_RELAYER_SIM_SOURCE.
// Typed as `any` so the fields are both callable (inside the vi.mock factories)
// and assignable to vi.fn() spies + usable with toHaveBeenCalled matchers; a
// Mock type would satisfy the assertions but tsc rejects calling it.
const h = vi.hoisted(() => ({
  relayer: false,
  simSource: "",
  getAccount: null as any,
  getSubmitter: null as any,
}));

vi.mock("../network.js", () => ({
  RPC_URL: "https://rpc.invalid",
  get RELAYER_SIM_SOURCE() {
    return h.simSource;
  },
}));
vi.mock("../relayerClient.js", () => ({
  relayerEnabled: () => h.relayer,
}));
vi.mock("../primaryPasskeySigner.js", () => ({
  getSubmitter: (...args: unknown[]) => h.getSubmitter(...args),
}));
// Keep stellar-sdk real except rpc.Server, whose network calls we stub.
vi.mock("@stellar/stellar-sdk", async (importOriginal) => {
  const orig = (await importOriginal()) as typeof import("@stellar/stellar-sdk");
  return {
    ...orig,
    rpc: {
      ...orig.rpc,
      Server: class {
        getAccount = (addr: string) => h.getAccount(addr);
        // Return a simulation ERROR so previewOperation returns right after the
        // source is chosen — enough to assert WHICH source was used.
        simulateTransaction = async () => ({ error: "stub-sim-error" });
      },
    },
  };
});

import { previewOperation } from "./preview.js";

const op = Operation.manageData({ name: "k", value: "v" });
// Valid G-addresses without an RNG (Keypair.random trips noble-curves under vitest).
const SIM_SOURCE = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 7));
const SUBMITTER_G = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 9));

afterEach(() => {
  vi.restoreAllMocks();
  h.relayer = false;
  h.simSource = "";
});

describe("previewOperation source selection (relayer vs classic)", () => {
  it("relayer mode uses RELAYER_SIM_SOURCE and never mints a submitter key", async () => {
    h.relayer = true;
    h.simSource = SIM_SOURCE;
    h.getAccount = vi.fn(async (addr: string) => new Account(addr, "0"));
    h.getSubmitter = vi.fn();

    await previewOperation({ operation: op });

    expect(h.getSubmitter).not.toHaveBeenCalled();
    expect(h.getAccount).toHaveBeenCalledWith(SIM_SOURCE);
  });

  it("relayer mode with no RELAYER_SIM_SOURCE fails closed (misconfigured)", async () => {
    h.relayer = true;
    h.simSource = "";
    h.getAccount = vi.fn();
    h.getSubmitter = vi.fn();

    const res = await previewOperation({ operation: op });

    expect(res.ok).toBe(false);
    expect(res).toMatchObject({ error: expect.stringContaining("misconfigured") });
    expect(h.getSubmitter).not.toHaveBeenCalled();
    expect(h.getAccount).not.toHaveBeenCalled();
  });

  it("classic mode (relayer disabled) uses the friendbot-funded submitter", async () => {
    h.relayer = false;
    h.getSubmitter = vi.fn(async () => ({ publicKey: () => SUBMITTER_G }));
    h.getAccount = vi.fn(async (addr: string) => new Account(addr, "0"));

    await previewOperation({ operation: op });

    expect(h.getSubmitter).toHaveBeenCalledTimes(1);
    expect(h.getAccount).toHaveBeenCalledWith(SUBMITTER_G);
  });
});
