# Operational Runbooks

Deploy, upgrade, key-rotation, and incident-response procedures for mainnet.
References existing tooling; fill in the multisig/KMS specifics as B1/A4 land.

## 1. Contract deployment (manual, post-audit)

Contract deploys are **manual and gated on audit sign-off** — never automated in CI
(only the frontend + workers deploy from CI). Standard flow:

1. **Approval:** an audit-approved commit + a signed-off change ticket. Record the git
   commit being deployed.
2. **Build reproducibly:** `just build-contracts` on the pinned toolchain (C2). Record the
   `stellar-cli` version and each wasm sha256.
3. **Deploy:** for the factory + smart-account use the deploy scripts
   (`scripts/deploy-zk-recovery.mjs`, `scripts/deploy-policy-builder-v1.sh` pattern). The
   scaffold-built ZK contracts must be deployed via the JS SDK (the `stellar` CLI fails with
   `Missing Entry Context` on their multi-`Address` constructors — see `DEPLOYED.md`).
4. **Verify address + hash:** confirm the deployed C-address and that the on-chain wasm hash
   matches the embedded/expected hash before creating any account.
5. **Preflight params:** run the config-assert script (A1/B2 tooling) — the live
   `delay/floor/window/passphrase/verifier` must match the mainnet spec.
6. **Register:** repoint the registry name (multisig-approved, §2).
7. **Smoke test:** invoke a read (`next_index`, `current_root`) + a full onboarding +
   recovery lifecycle against mainnet RPC.
8. **Record:** update `DEPLOYED.md` with addresses, params, wasm/VK/circuit hashes, deployer,
   and commit.

## 2. Registry repoint & upgrade governance (multisig)

The registry name → address mapping and the factory `set_recovery_pool`/`upgrade`/`set_admin`
knobs are the highest-leverage controls — a repoint silently changes the contract users trust.

- **Keys under multisig.** The registry-owner key, the factory admin, and each contract admin
  (post-B1) are multisig, not a single key.
- **Upgrade timelock.** `upgrade()` is timelocked so users can exit before it lands. Announce
  upgrades publicly with the new wasm hash + diff before the timelock elapses.
- **Change process:** GitHub issue + review → multisig proposal → timelock → execute → verify
  the new address/hash → update `DEPLOYED.md`. Every registry/admin change is monitored and
  alerts on unexpected address changes.
- **Pinning (pin bypass):** once the factory's `verifier`/`zk-recovery` pins are set
  (`set_registry_pins`), `resolve` returns the pinned address **directly and never consults the
  registry** — so a registry repoint can neither redirect **nor block** new-account creation, and
  the factory raises no error (there is **no** `RegistryMismatch`). Detection of a hostile repoint
  therefore relies on the external registry address-change monitor (above), not a factory-level
  revert. Pins change only via the admin multisig.

## 3. Key rotation

- **Deploy identity (`ci-publisher`):** rotate annually and after any team change. Store in
  the shared vault (1Password). Never in CI secrets for contract deploys.
- **Relayer sponsor + channel keys (A4):** managed by KMS/HSM. Rotation = provision new KMS
  key → update relayer signer config → re-fund → retire old key. Test rotation in staging.
- **Multisig signers:** documented roster; rotate a signer via the multisig itself; keep a
  quorum available at all times.

## 4. Relayer incident response

The relayer (`infra/relayer`, Fly.io) sponsors/submits txs. It cannot forge account auth, so
worst case is **censorship** or **sponsor-budget drain**, not theft.

### Defenses in place

- **Per-client fairness (`Caddyfile`):** a per-IP token bucket (`rate_limit`, keyed on
  `Fly-Client-IP`, 30 relays/min/IP) throttles any single source so it cannot burst-drain the
  shared daily budget — the DoS the old single-`x-api-key` + one global `FEE_LIMIT` allowed.
  Layered under the relayer's own global 20 req/s ceiling.
- **Budget cap (`fly.toml` `FEE_LIMIT`):** the Channels plugin caps sponsor spend at 100 XLM
  per `FEE_RESET_PERIOD_SECONDS` (24h). Still a single global bucket; per-IP limiting is what
  makes it fair. True per-*client* fee accounting needs per-client keys (future work).
- **Metrics (`METRICS_ENABLED=true`):** Prometheus on `:8081` (`/debug/metrics/scrape`),
  scraped by Fly's managed Prometheus (`[metrics]` in `fly.toml`); dashboards + alert rules in
  `grafana.fly.dev`. Kept off the public `:8080` listener.

### Alerts (wire in Fly Grafana against the scraped metrics)

| Alert | Condition | Action |
|---|---|---|
| **Relayer down** | `/api/v1/health` failing 3+ consecutive checks (≈45s) | Outage procedure below |
| **Budget ≥80%** | sponsor fee spend ≥ 80% of `FEE_LIMIT` within the reset window | Investigate spend pattern before raising |
| **Error rate** | relayed-tx failure ratio > 5% over 5 min | Check RPC/network + channel health |
| **Rate-limit spike** | sustained 429s from one IP | Confirm abuse vs. legit burst; tighten bucket if abuse |
| **Channel unregistered** | a channel relayer missing/paused | Re-register / unpause via `config.json` |

> Confirm exact metric names against the live `/debug/metrics/scrape` output after the first
> deploy with `METRICS_ENABLED=true` — the alert *conditions* above are the contract; the
> PromQL is filled in once the series names are observed.

### Procedure

1. **Detect** — alert fires (or a user report). Check `grafana.fly.dev` + `fly logs -a nido`.
2. **Triage** — classify: outage (health down), drain (budget alert), abuse (rate-limit spike),
   or suspected key compromise.
3. **Contain** —
   - *Abuse/drain:* the per-IP bucket already throttles; if a distributed drain, lower
     `FEE_LIMIT` (or pause a relayer via `paused: true` in `config.json` + redeploy) to freeze
     spend while investigating. Do **not** raise `FEE_LIMIT` before understanding the pattern —
     a single client exhausting it is exactly the DoS this guards against.
   - *Outage:* redeploy via `deploy-relayer.yml` (GH action, Fly token from 1Password). Health:
     `https://nido.fly.dev/api/v1/health`. If down >30 min, notify affected users.
   - *Key compromise:* rotate immediately (§3), redeploy, re-fund, audit recent sponsored txs.
     Keys in KMS (A4) cannot be exfiltrated from the host.
4. **Recover** — confirm health green, budget/error alerts cleared, a test relay succeeds.
5. **Post-mortem** — record timeline, root cause, and any threshold/bucket changes here.

## 5. ZK circuit / VK change

Changing the circuit (e.g. a new `log_n`) means a **new** `zk-verifier` (VK is immutable) and a
regenerated proof set:
1. Change circuit; bump `REQUIRED_NARGO_VERSION`/`REQUIRED_BB_VERSION` if the toolchain moves.
2. `just gen-zk-fixtures` on the pinned toolchain; the `zk-circuit-repro` CI job (Actions tab)
   confirms reproducibility.
3. Deploy a new `zk-verifier` with the new VK; register it; point the recovery pool at it.
4. Record new circuit/VK hashes in `DEPLOYED.md` + `manifest.json`.
