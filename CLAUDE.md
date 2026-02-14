# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

g2c facilitates migration from Stellar G-addresses to Soroban Smart Accounts (C-addresses) using WebAuthn/passkey authentication. The backend acts as a dynamic WebAuthn Relying Party for `{contractId}.sorobancontracts.com`, generating challenges and verifying passkey assertions off-chain before transactions hit the network.

## Build & Test Commands

```bash
just test              # cargo test --workspace (all 42 tests)
just test-core         # cargo test -p passkey-core (fastest, core crypto tests)
just build             # cargo build --workspace (native)
just build-wasm        # cargo build -p passkey-worker --target wasm32-unknown-unknown
just build-contracts   # stellar contract build --optimize (Soroban wasm)
just serve             # cargo run -p passkey-server (Axum on :8787)
just dev               # wrangler dev (Cloudflare Workers local)
just check             # cargo fmt --check + cargo clippy -D warnings
just fmt               # cargo fmt --all
```

Run a single test by name: `cargo test -p passkey-core webauthn::verify::tests::verify_valid_assertion`

## Workspace Architecture

Five crates across two directories:

**`crates/passkey-core`** — Platform-agnostic library. All WebAuthn crypto, parsing, and validation lives here. Compiles to both native and wasm32. This is where the bulk of the logic and tests are.

**`crates/passkey-worker`** — Thin Cloudflare Workers wrapper. Routes HTTP requests to passkey-core functions, stores challenges in Workers KV with 5-minute TTL. The `worker` crate (v0.4) distinguishes sync handlers (`.get()`, `.options()`) from async handlers (`.post_async()`) — only use async for KV-accessing endpoints.

**`crates/passkey-server`** — Local dev server (Axum). Same API as the worker but uses InMemoryStore. Calls sync methods on InMemoryStore directly (not the async trait) to avoid `!Send` future issues with Axum's multi-threaded runtime.

**`contracts/smart-account`** — Soroban contract implementing OpenZeppelin's `CustomAccountInterface` + `SmartAccount` + `ExecutionEntryPoint` traits. Delegates auth to `do_check_auth` from stellar-accounts. `#![no_std]`.

**`contracts/webauthn-verifier`** — Soroban contract implementing OZ's `Verifier` trait for secp256r1/P-256 passkey signature verification. Stateless — deploy once, shared across accounts. `#![no_std]`.

## Key Design Patterns

**Storage abstraction**: `ChallengeStore` trait uses `#[async_trait(?Send)]` for wasm single-threaded executor compatibility. `InMemoryStore` has both sync methods (for Axum) and an async trait impl (for wasm). The worker uses `WorkersKvStore` with native KV TTL.

**WebAuthn verification chain** (in `passkey-core/src/webauthn/verify.rs`):
1. Decode base64url fields → parse authenticatorData binary → verify rpIdHash matches SHA-256 of RP ID → check UP flag → parse/validate clientDataJSON (type, challenge, origin) → verify P-256 ECDSA signature over `authenticatorData || SHA-256(clientDataJSON)`

**RP ID generation**: `{contractId}.sorobancontracts.com` with expected origin `https://{contractId}.sorobancontracts.com`. Each contract gets a unique RP ID via wildcard DNS.

**Contract ID validation**: Uses `stellar-strkey` crate for full strkey validation (base32 + version byte + CRC16 checksum), not manual char checks.

**Challenge lifecycle**: Generate 32-byte random challenge → store with 5-min TTL → retrieve-and-delete on verify (one-time use) → app-level expiry check as belt-and-suspenders.

## API Endpoints

- `GET /health` — `{ "status": "ok", "version": "0.1.0" }`
- `POST /auth/challenge/{contractId}` — generates and stores challenge, returns `{ challenge, rp_id, challenge_id }`
- `POST /auth/verify/{contractId}` — consumes challenge, verifies WebAuthn assertion, returns `{ verified: true/false }`. Body: `{ challenge_id, authenticator_data, client_data_json, signature, public_key }` (all base64url)

## Testing Notes

Tests use synthetic P-256 keypairs (`SigningKey::random()`) to construct full WebAuthn assertions without a browser. Test contract IDs must be valid stellar-strkey encoded (e.g., `CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4`) — invalid checksums will fail.

## Dependency Version Constraints

- `stellar-accounts` is pinned to a git rev of OpenZeppelin/stellar-contracts to match `soroban-sdk` 25.x
- `getrandom` needs the `js` feature for wasm32 builds
- `worker` crate v0.4 is the Cloudflare Workers SDK
