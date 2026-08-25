# Audit Scope

Scope definition for the third-party security audit of Nido. Give this to the
audit firm(s) with the frozen commit filled in.

> **Freeze commit:** _TBD — record `git rev-parse HEAD` of the audited tree here._
> Reference point at time of writing: `981074ca50d2d7478f1d94c2b729509564e1506d`
> (branch `main`).

The user has scoped the audit to **all four layers**: Soroban contracts, the ZK
circuit + UltraHonk verifier, the off-chain infrastructure, and the TS SDK +
frontend. The ZK layer requires a **specialist auditor** (circuit soundness +
proof-system verification), separate from a general Soroban/Rust reviewer.

## In scope

### 1. Soroban contracts (Rust, `#![no_std]`)

| Contract | Path | Notes |
|---|---|---|
| Factory | `contracts/factory/` | Deterministic account deployment, genesis Merkle insert, verifier lazy-deploy, registry resolution. Has admin/upgrade. |
| Smart account | `contracts/smart-account/` | OZ `CustomAccountInterface` + recovery guard + `execute` entry point + `enroll_zk_recovery` migration. |
| WebAuthn verifier | `contracts/webauthn-verifier/` | Stateless secp256r1/P-256 signature verification (OZ `Verifier`). |
| ZK recovery pool/controller | `contracts/zk-recovery/` | Merkle pool + recovery state machine (initiate/cancel/revoke/complete), nullifiers, timelock, rate-limit, policy. |
| ZK verifier | `contracts/zk-verifier/` | Thin wrapper binding a VK; delegates to the vendored UltraHonk verifier. |
| Multisig policy | `contracts/multisig-policy/` | Threshold policy. |
| Spending-limit policy | `contracts/spending-limit-policy/` | Rolling-window SAC transfer metering. |
| Name registry | `contracts/name-registry/` | Human-readable account names. |
| Status-message (demo) | `contracts/status-message/` | **Demo only.** See out-of-scope note — confirm whether it ships to mainnet. |

### 2. ZK circuit + proof verifier (specialist)

- `circuits/zk_recovery/` — the Noir `zk_recovery` circuit (source, `Prover.toml`,
  build/reproducibility scripts, committed VK/proof fixtures + manifest).
- `contracts/vendor/ultrahonk-soroban-verifier/` — **vendored** UltraHonk verifier
  (see [SUPPLY_CHAIN.md](./SUPPLY_CHAIN.md) for provenance). Verbatim third-party
  code; the audit should confirm soundness of proof verification and that the
  vendored copy matches its declared upstream.

### 3. Off-chain infrastructure

- `infra/relayer/` — tx sponsor/submitter (Fly.io), allowlist plugin, key custody.
- `infra/pool-indexer/`, `infra/nido-resolver/`, `infra/recovery-relay/` — Cloudflare
  workers.

### 4. SDK + frontend

- `packages/passkey-sdk/` — published to npm (`@nidohq/passkey-sdk`).
- `packages/stellar-wallets-kit-module/`, `packages/frontend/`, `frontend/`.

## Out of scope (dependencies relied upon, not authored by Nido)

- **OpenZeppelin `stellar-contracts` / `stellar-accounts`** — pinned dependency at
  an untagged main-branch rev (`ec749c3b`, the merge of OZ PR #816 / soroban-sdk 27;
  see `Cargo.toml`). All core auth logic
  delegates to `do_check_auth` here. The auditor should **verify the pinned rev is
  the intended, uncompromised commit**, but the library itself is OZ's audited code,
  not part of Nido's authored surface. See [SUPPLY_CHAIN.md](./SUPPLY_CHAIN.md).
- **`soroban-sdk` 27.0.2**, `soroban-sdk-tools`, `stellar-registry` — pinned deps.
- **`admin-sep` 0.27.0** (`theahaco/admin-sep`) — pinned crates.io dep providing the
  `Administratable`/`Upgradable` SEP traits (`admin`/`set_admin`/`upgrade`) shared by every
  upgradeable contract. Not Nido-authored, but it is on the governance/upgrade auth path, so
  the auditor should read it in full (it is ~50 LOC) — see [SUPPLY_CHAIN.md](./SUPPLY_CHAIN.md).
- **Stellar Registry contract (AhaLabs smart-deploy)** — an external on-chain contract, not
  authored by Nido. On mainnet Nido runs its **own instance** (owner under the multisig,
  deployed by `scripts/deploy-registry.sh` from the reference registry's exact wasm, hash
  recorded in `DEPLOYED.md`). Trust in it is bounded: once the factory pins `verifier`/
  `zk-recovery` (B2 pin bypass), the registry is off the account-creation critical path and a
  repoint can neither reroute nor block new accounts (invariant F5). It remains authoritative
  only for off-chain discovery and unpinned names.
- **Stellar protocol / consensus / RPC** — trusted platform.

## Explicitly NOT for mainnet (must not be deployed / must be excluded)

The pre-v0.7 contracts listed in `DEPLOYED.md` ("Pre-v0.7 contracts (do not use)")
are on-chain from earlier iterations, incompatible with the current WASM, and
out of scope. They must not be deployed to mainnet.

## What to hand the auditor alongside this file

- [THREAT_MODEL.md](./THREAT_MODEL.md) — assets, adversaries, trust assumptions.
- [SECURITY_INVARIANTS.md](./SECURITY_INVARIANTS.md) — the properties that must hold, with test evidence.
- [SUPPLY_CHAIN.md](./SUPPLY_CHAIN.md) — dependency + toolchain provenance.
- `ARCHITECTURE.md`, `DEPLOYED.md` — system design + deployed addresses/params.
- The design spec under `docs/` (`2026-07-02-zk-recovery-design.md`) for the ZK protocol.
