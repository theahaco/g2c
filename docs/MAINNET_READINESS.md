# Mainnet Readiness — Go / No-Go Checklist

Every box must be checked before mainnet launch. Grouped by the workstreams in the
audit-readiness plan. "Blocker" = launch cannot proceed without it.

## A. Hard blockers

- [ ] **A1 — ZK recovery params (BLOCKER).** Fresh mainnet pool deployed with
  `delay_secs=1_209_600` (14d), `timelock_floor_secs=604_800` (7d),
  `completion_window_secs=2_592_000` (30d). Params are immutable at construction; the
  testnet pool uses 60s/0/604800 and cannot be reused. Tooling in place:
  `scripts/deploy-zk-recovery.mjs --mainnet` presets these values and its mainnet guard
  refuses a sub-day delay/floor or a missing `--admin`; verify the live pool afterward with
  `node scripts/preflight-recovery-config.mjs --contract <POOL>` (reads the on-chain
  `config()` view and exits non-zero on any spec mismatch — the go/no-go gate).
- [ ] **A1 — Mainnet circuit VK regenerated.** VK/proof fixtures regenerated under the
  pinned toolchain against the **mainnet network passphrase** and 14d timelock (both are
  bound into `auth_hash`); testnet proofs/VK do not carry over. Hashes recorded in
  `DEPLOYED.md`.
- [~] **A2 — setup secret off URL query params (BLOCKER).** The setup salt (derives the
  address + lets its holder claim the pre-funded account) is now carried in the URL HASH,
  never the query: `createNido`/`nidoRowHref` **and the apex→subdomain reservation redirect**
  emit `#salt=` (the fragment is never sent to the server, so it stays out of worker/CDN access
  logs + cross-origin Referer; `autopass`/`then` stay in the query). The `/new-account/`
  receiver reads the hash first, still accepts legacy `?salt=`/`?key=` query links but SCRUBS
  them from the URL (`history.replaceState`) on load so a leaked secret doesn't linger.
  Unit-tested (`createNido`/`accountLinks`); a `@fast` Playwright assertion checks the query
  scrub. Remaining: run the Playwright lane to confirm end-to-end (couldn't run browsers here).
- [ ] **A3 — Mainnet registry deployed + wired.** Deploy a Nido-owned `stellar-registry`
  instance on mainnet (registry-owner key under the multisig) and register
  `factory`/`verifier`/`zk-recovery` into it (`scripts/deploy-registry.sh` +
  `just publish-registry`, rehearsed on testnet). Factory `REGISTRY` constant + all client
  fallbacks (`passkey-sdk/src/registry.ts`, `frontend/src/lib/policyChainFetch.ts`) point at
  its contract-id; rebuilt + tested against mainnet RPC. Registry wasm hash + id recorded in
  `DEPLOYED.md`; registry added to the trusted-external set in `AUDIT_SCOPE.md`/`SUPPLY_CHAIN.md`.
  (Later: register this registry's id into the AhaLabs verified registry — additive, not a blocker.)
- [ ] **A4 — Relayer keys in KMS/HSM (BLOCKER).** Sponsor + channel keys no longer live as
  on-disk keystores; migrated to a KMS/HSM signer; testnet keys rotated out.

## B. Architecture freeze (before audit)

- [x] **B1 (code) — admin + upgrade() implemented across the contract set** (issue #26):
  `smart-account` (self-authed; **blocked while a recovery is pending**, and — for a
  recovery-enabled account — the immediate `upgrade` is **refused** (`UpgradeRequiresTimelock`)
  in favour of a 7-day announce-then-execute path (`initiate_upgrade` → `execute_upgrade`), so a
  stolen passkey can't instantly strip the protected recovery rule), `factory`, `zk-verifier`
  (VK stays immutable), `zk-recovery`, `webauthn-verifier`, `multisig-policy`,
  `spending-limit-policy`, `name-registry` — each with `admin`/`set_admin`/`upgrade`, the admin
  set via `__constructor(admin: Address)`. Fresh deploys pass `--admin` (see
  `scripts/deploy-policy-builder-v1.sh`, `scripts/deploy-zk-recovery.mjs`). All contracts except
  `smart-account` (which keeps its bespoke recovery-timelocked upgrade) now source
  `admin`/`set_admin`/`upgrade` from the shared **`admin-sep`** crate (`Administratable` +
  `Upgradable`) rather than per-contract inlined code — see [SUPPLY_CHAIN.md](./SUPPLY_CHAIN.md).
- [ ] **B1 (governance) — admin behind a multisig, `upgrade` behind a timelock.** The mainnet
  `--admin` must be a multisig C-address (not the deploying key). The `smart-account` self-upgrade
  is already timelocked in-code (above); the **singleton** contracts (`zk-verifier`, policies,
  `name-registry`, `factory`) upgrade immediately once admin-authed, so the multisig — ideally
  with its own upgrade timelock so users can exit before an upgrade lands — is the mitigation
  there. `zk-verifier` VK intentionally immutable (a circuit change still means a fresh verifier
  deploy + re-register, never an in-place VK swap).
- [x] **B2 (code) — Registry address pinning implemented (pin bypass).** Factory has
  admin-settable pins (`set_registry_pins(verifier, zk_recovery)`); once pinned it resolves
  `verifier`/`zk-recovery` directly from the pin and never consults the registry, on every
  `create_account`/`create_account_v2` (invariant F5, tested) — so a repointed/broken registry
  can neither reroute nor block new accounts. Unpinned = pre-B2 behavior; the
  `set_recovery_pool` override is checked before the `zk-recovery` pin.
- [ ] **B2 (deploy) — Pins set + keys under multisig.** At cutover, call `set_registry_pins`
  with the mainnet verifier/zk-recovery addresses (from `DEPLOYED.md`); put the registry-owner
  + factory admin (`set_registry_pins`/`set_recovery_pool`) keys under the multisig; add
  change-monitoring/alerts on any registry address change.

## C. Reproducible builds & provenance

- [ ] **C1 — bb pinned + guarded** (done; verify `manifest.json` shows `bbRequired`).
- [ ] **C2 — Rust toolchain + `stellar-cli` pinned**; every deployed wasm hash re-derivable.
- [ ] **C2 — Reproducibility attestation.** One command rebuilds all deployed wasms + circuit
  VK and diffs against `DEPLOYED.md`/`manifest.json`; result is byte-identical.
- [ ] **C3 — Vendor provenance recorded** + drift check extended to the vendor `Cargo.toml`.

## D. Audit-prep documents

- [x] AUDIT_SCOPE.md, THREAT_MODEL.md, SECURITY_INVARIANTS.md, SUPPLY_CHAIN.md,
  MAINNET_READINESS.md, RUNBOOKS.md drafted.
- [ ] Freeze commit recorded in AUDIT_SCOPE.md.
- [ ] OZ repinned to a tagged release, or risk documented + accepted.

## E. Security hardening

- [~] Security headers (frame/content-type/referrer) ENFORCED at both the worker proxy
  (`frontend/worker-proxy-nido/index.js`) and the static Pages origin
  (`packages/frontend/public/_headers`). CSP ships Report-Only with a tightened allowlist
  (explicit connect-src hosts + Google Fonts), identical in both places. Remaining: verify a
  clean report stream in prod, then promote Report-Only → enforced (drop `-Report-Only`) in
  both files, and separately try dropping `style-src 'unsafe-inline'`.
- [x] Legacy query-param sign path validates callback/return origin (no signature exfiltration) —
  `signRequestFromParams` normalises + matches the dApp/return origin at the SignRequest source
  (`signing/signRequest.ts`), with `signRequest.test.ts` covering the phishing case.
- [x] `expirationOffset`/`relayerEnabled` centralized with a parity test — single
  `signatureExpirationOffset()` (`relayerClient.ts`) threaded through walletSign/
  primaryPasskeySigner/zkRecoveryActions; parity asserted in `relayerClient.test.ts`.
- [ ] localStorage credential material encrypted + expiring.
- [x] Relayer per-client fairness (per-IP token bucket in Caddy, 30/min), metrics enabled
  (Prometheus on :8081, Fly-scraped), alert definitions + incident-response playbook in
  RUNBOOKS §4. (Needs a Fly deploy to verify the xcaddy build + confirm live metric names;
  true per-*client* fee accounting via per-client keys remains future work.)
- [x] Structured error on malformed/truncated proofs — the zk-verifier boundary
  (`verify_proof`) length-pre-checks against the VK and returns `ProofParseError` instead of
  letting the vendored parser's `assert_eq!` trap (invariant V3; no vendored edit, no
  drift-guard churn). Curve-point validity delegated to the host BN254 ops.
- [~] Storage TTL/archival validated across the 44-day active window (invariant T1) —
  `recovery_state_survives_full_active_window` proves the window (~760k ledgers) sits far under
  both the in-env `max_ttl` (~6.31M) **and a pinned lower bound of the mainnet `max_entry_ttl`
  (~3.11M)** with every write extending to max, advances the ledger timestamp+sequence
  across the full window, and completes at its end. (Archival eviction is a Soroban protocol
  guarantee, not modelled by the test env — see the invariant's scope note.)
  **At cutover:** confirm the live mainnet `max_entry_ttl` ≥ the active window (~760k ledgers).
- [ ] `status-message` demo typo fixed + redeployed, or explicitly excluded from mainnet.

## F. Test coverage

- [ ] Vendored UltraHonk verifier tests un-excluded from CI (fixtures vendored).
- [ ] Negative tests: forged proof, double-spend nullifier, wrong-network, timelock-not-elapsed,
  unauthorized mutation, malformed proof, `execute` abuse, salt reuse, i128 overflow.
- [ ] Property/fuzz tests for Merkle/Poseidon/low-S.
- [ ] Testnet e2e Playwright lane un-quarantined (or CI-gated).
- [ ] Full recovery-lifecycle test running under mainnet params.

## Cutover sequence (release day)

1. Confirm B/C/D/E/F all green on the frozen, audited commit; audit findings applied.
2. Deploy the Nido-owned `stellar-registry` instance (A3, `deploy-registry.sh`), registry-owner
   key under the multisig. Deploy contracts fresh: pool via `deploy-zk-recovery.mjs --mainnet`
   (A1 params) with a multisig `--admin` (B1); factory rebuilt with the mainnet `REGISTRY`
   constant set to the just-deployed registry id (A3).
3. Register `factory`/`verifier`/`zk-recovery` into the registry; regenerate + register the
   mainnet VK (A1).
4. **Pin the registry (B2):** `factory.set_registry_pins(<verifier>, <zk-recovery>)` with the
   just-deployed mainnet addresses. Once pinned the registry is off the account-creation path
   (pin bypass), so a later repoint cannot reroute or block new accounts.
5. Run `preflight-recovery-config.mjs --contract <POOL>` → must print **GO** before any user
   account is created. (Optionally `--expect-factory/-verifier/-webauthn` to assert the binds.)
6. Relayer on KMS (A4); alerts firing; run the incident-response drill.
7. Frontend on mainnet config (A2/A3); smoke-test onboarding + a full recovery lifecycle.
8. Update `DEPLOYED.md` with mainnet addresses, params, wasm/VK/circuit hashes.
