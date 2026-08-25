# Supply Chain & Toolchain Provenance

Dependency and toolchain inventory for the audit, plus the scanning/attestation
gaps to close. Goal: an auditor can account for every third-party input and
rebuild every deployed artifact.

## Rust dependencies (workspace `Cargo.toml`)

| Dependency | Pin | Kind | Risk |
|---|---|---|---|
| `soroban-sdk` | `27.0.2` (resolves 27.0.5) | crates.io tagged | Low. |
| `stellar-accounts` (OZ `stellar-contracts`) | **git rev `ec749c3b75971f2c35ced1bea3e2a7e536e91cda`** (merge of OZ PR #816 — first main commit on soroban-sdk 27) | git, **untagged main branch** | **Elevated** — see below. Core auth (`do_check_auth`) delegates here. |
| `soroban-sdk-tools` | crates.io **`0.1.3`** (targets soroban-sdk 27) | crates.io | Low — published, versioned release. Previously a `BlaineHeffron` git fork (sdk-26 only); now dropped. Provides `#[contractstorage]`, compiled into factory/name-registry. |
| `soroban-poseidon` (`stellar/rs-soroban-poseidon`) | git **tag `v27.0.0`** | git tag | Low — Stellar org, tagged. Poseidon2 parity is circuit-critical (`host_poseidon2_matches_noir_vectors`); v27.0.0 is a version-only bump over v26.0.0. |
| `admin-sep` (`theahaco/admin-sep`) | crates.io **`0.27.0`** | crates.io | **Medium — on the governance path.** Small crate (~50 LOC, 3 modules) providing the `Administratable`/`Upgradable` SEP traits (`admin`/`set_admin`/`upgrade`) that gate every upgradeable contract. Replaces per-contract inlined boilerplate. `admin()` reads infallibly (assumes the constructor set it); each contract sets `admin` in `__constructor`. Auditor should read it in full and confirm the `require_auth` gating on `set_admin`/`upgrade`. |
| `stellar-registry` | `0.0.10` | crates.io | Medium — `0.0.x`. Macros only (re-exports `stellar-scaffold-macro`); **not** the registry contract. |
| `base64` | `0.22` | crates.io | Low. |

`Cargo.lock` is committed, so transitive versions are reproducible. `cargo-audit`
is **not yet run in CI** (see gaps).

### On-chain Stellar Registry contract (external, not the crate above)

The registry the factory queries/publishes into is an **external on-chain contract** (AhaLabs
smart-deploy), distinct from the `stellar-registry` *crate* (which is macros only). On mainnet
Nido deploys its **own instance** of it via `scripts/deploy-registry.sh`, which
`stellar contract fetch`es the reference registry's exact deployed wasm, records its sha256,
and redeploys that byte-identical bytecode under a Nido owner (multisig). Provenance to record
in `DEPLOYED.md` at cutover: the source registry id + network, the fetched **wasm sha256**, and
the new instance id — so an auditor can confirm the instance runs identical code to the
reference. Residual trust is bounded by the factory pin bypass (invariant F5): once pinned, the
registry cannot reroute or block account creation.

### OZ pinned to an untagged commit — action

Pinning to a main-branch commit means the practice diverges from auditing a tagged release
(git content-addressing prevents silent substitution of the resolved tree, and `Cargo.lock`
records it, but a tag is preferable). The current pin `ec749c3b` is the merge of OZ PR #816
(the soroban-sdk-27 bump); the `stellar-accounts` package there differs from the tagged
`v0.7.x` line only by the sdk-27 adaptation.
- **Preferred:** repin to a tagged `stellar-contracts` release once one lands on soroban-sdk 27.
  The latest tag (`v0.7.2`) is still on soroban-sdk 26.1, so no sdk-27 tag exists yet — track
  the OZ release that includes #816 and repin to it.
- **Until then:** keep the rev pin, recorded here + in `AUDIT_SCOPE.md`, so the firm verifies
  the pinned tree matches audited OZ behavior. `Cargo.lock` + content-addressed git already
  prevent silent substitution of the resolved tree.

## Vendored code

**`contracts/vendor/ultrahonk-soroban-verifier/`** — verbatim copy of an unaudited
third-party UltraHonk verifier.
- Upstream: `https://github.com/yugocabrio/rs-soroban-ultrahonk`, rev
  **`3b031847eb043856cc5bcad45bd5a6512370cd16`** (recorded in the vendor `Cargo.toml`),
  retargeted onto the workspace `soroban-sdk = 27.0.2` (resolves 27.0.5) — matching the
  workspace pin in the table above after the sdk 26→27 bump.
- License: MIT (vendor crate); Apache-2.0 `LICENSE` file also present — **confirm the
  effective license and record it** before mainnet.
- Its own deps: `ark-ff`/`ark-bn254`/`ark-ec` 0.5, `hex`, `once_cell`, `lazy_static`.
- Drift guard: `scripts/check-vendor-drift.sh` (run in CI via `just check-vendor-drift`)
  compares a sha256 manifest of `src/` against the committed `CHECKSUMS.sha256`.

### Drift-guard gaps — action (C3)

- The manifest now covers `src/` **and the vendor `Cargo.toml`** (done, C3), so a
  dependency/feature-flag change can't slip past; the guard also asserts the recorded
  upstream commit (`3b031847…`) so a bump can't silently drop provenance. (`tests/` and
  `circuits/` are still out of the manifest — they aren't compiled into the deployed wasm.)
- The baseline is regenerable by design, so a hand-edit "passes" once its new hash is
  committed. Keep vendor changes to reviewed, commit-referenced upstream bumps only, and
  call them out in PR review. (This is integrity + provenance recording, not an
  authenticity attestation of upstream.)

## ZK circuit toolchain

| Tool | Pin | Enforced |
|---|---|---|
| `nargo` (Noir) | `1.0.0-beta.18` (pre-release) | `gen_artifacts.sh` hard version guard. |
| `bb` (Barretenberg) | `3.0.0-nightly.20260102` | **Now** hard-guarded in `gen_artifacts.sh` (`REQUIRED_BB_VERSION`) + recorded as `bbRequired` in `manifest.json` (C1). |
| Fiat-Shamir oracle | keccak, via `--verifier_target evm-no-zk` | Implicit (bb rejects an explicit `--oracle_hash` alongside `--verifier_target`); documented in `gen_artifacts.sh`. UltraHonk = transparent setup, no toxic waste. |

Deployed VK/proof/circuit hashes are recorded in `DEPLOYED.md` and the circuit
`manifest.json`. **Mainnet VK must be regenerated** under these pins with mainnet params
(blocker A1) and its hashes re-recorded.

## Contract build toolchain

| Tool | Pin | Status |
|---|---|---|
| Rust | `1.96.0` | **Pinned (C2):** workspace-root `rust-toolchain.toml` (channel `1.96.0`, `wasm32v1-none`) + CI `dtolnay/rust-toolchain@1.96.0`, kept in lockstep. |
| `stellar-cli` (+ bundled `wasm-opt`) | _unpinned (`cargo install --locked stellar-cli`)_ | **Gap — pin an exact version (C2)** and record which produced each deployed wasm. |
| `[profile.contract]` | committed (`lto`, `codegen-units=1`, `panic=abort`, `overflow-checks`, `opt-level=z`) | Good for reproducibility. |

## npm packages

Roots with committed lockfiles: `package.json` (repo root), `packages/passkey-sdk`,
`packages/frontend`, `packages/stellar-wallets-kit-module`, and the `infra/*` workers.
`@nidohq/passkey-sdk` is published to npm — API stability + provenance matter for
downstream consumers.

## Gaps to close (tracked)

- [x] `cargo-audit` job in CI (advisory DB) — non-blocking (`continue-on-error`); make gating pre-mainnet.
- [x] `npm audit` across all package roots — non-blocking; make gating pre-mainnet.
- [x] **Dependabot** config for cargo + npm + GitHub Actions (`.github/dependabot.yml`).
- [x] Extend vendor drift check to the vendor `Cargo.toml` (+ upstream-commit provenance assertion).
- [x] Pin Rust toolchain (C2) — `rust-toolchain.toml` @ `1.96.0`.
- [ ] Pin `stellar-cli` to an exact version (C2) and record which produced each deployed wasm.
- [ ] Repin OZ to a tagged release (or document the accepted risk).
- [ ] Generate an **SBOM** at release; publish alongside the audit report.
- [ ] License scan / confirm vendored-verifier effective license.
