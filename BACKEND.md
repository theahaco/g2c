# Stateless Passkey Backend

## Project Structure
```
g2c/
  Cargo.toml                         # Workspace root
  crates/
    passkey-core/                     # Platform-agnostic library (40 tests)
      src/
        lib.rs
        error.rs                      # Error types (thiserror)
        contract_id.rs                # C-address validation (base32, 56 chars)
        rp.rs                         # RP ID generation & SHA-256 hashing
        challenge.rs                  # Challenge generation (32-byte random, 5min TTL)
        storage.rs                    # ChallengeStore trait + InMemoryStore
        webauthn/
          mod.rs
          authenticator.rs            # Binary parser (rpIdHash + flags + signCount)
          client_data.rs              # clientDataJSON parser & validator
          verify.rs                   # P-256 ECDSA signature verification
    passkey-worker/                   # Cloudflare Worker (wasm32 verified)
      wrangler.toml
      src/
        lib.rs                        # Router + CORS
        handlers.rs                   # /health, /auth/challenge, /auth/verify
        kv_store.rs                   # Workers KV ChallengeStore impl (5min TTL)
    passkey-server/                   # Local Axum server (port 8787)
      src/
        main.rs                       # Same API, InMemoryStore backend
```

## API Endpoints

### `GET /health`
Returns `{ "status": "ok", "version": "0.1.0" }`.

### `POST /auth/challenge/{contractId}`
1. Validate contractId (starts with `C`, 56 chars, valid base32)
2. Generate RP ID: `{contractId}.sorobancontracts.com`
3. Generate 32-byte random challenge
4. Store in KV with 5-minute TTL
5. Return `{ challenge, rp_id, challenge_id }`

### `POST /auth/verify/{contractId}`
1. Retrieve & consume stored challenge (one-time use)
2. Parse authenticatorData binary (rpIdHash[32] + flags[1] + signCount[4])
3. Verify rpIdHash == SHA-256(`{contractId}.sorobancontracts.com`)
4. Verify user_present flag is set
5. Parse clientDataJSON — check `type == "webauthn.get"`, challenge matches, origin matches
6. Verify P-256 ECDSA signature over `authenticatorData || SHA-256(clientDataJSON)`
7. Return `{ verified: true/false }`

**MVP simplification**: Client provides public key in verify request (full system would fetch from Soroban contract state).

## Key Design Decisions

- **`async_trait(?Send)`** on `ChallengeStore` for wasm single-threaded executor compatibility
- **Sync methods** on `InMemoryStore` alongside the async trait impl, so the Axum server avoids `!Send` future issues
- Worker uses `get`/`options` (sync) for non-KV handlers, `post_async` for KV-accessing handlers
- Full WebAuthn assertion verification chain: authenticatorData parse → rpIdHash check → UP flag check → clientDataJSON validate → P-256 ECDSA over `authData || SHA-256(clientDataJSON)`

## Local Development

- **Unit tests**: `cargo test -p passkey-core` — all crypto tested with synthetic P-256 keypairs
- **Cloudflare local**: `wrangler dev` in `crates/passkey-worker/` — emulates Workers runtime + KV
- **Axum local**: `cargo run -p passkey-server` — plain HTTP server on localhost:8787

## Verification

- `cargo test --workspace` — 40 tests pass
- `cargo build -p passkey-worker --target wasm32-unknown-unknown` — wasm compilation confirmed
