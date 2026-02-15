# List available recipes
default:
    @just --list

# Run all workspace tests
test:
    cargo test --workspace

# Run passkey-core tests only
test-core:
    cargo test -p passkey-core

# Build all crates (native)
build:
    cargo build --workspace

# Build worker for wasm32
build-wasm:
    cargo build -p passkey-worker --target wasm32-unknown-unknown

# Build and optimize Soroban contracts
build-contracts:
    stellar contract build --optimize --profile contract

# Run the local Axum dev server on :8787
serve:
    cargo run -p passkey-server

# Start Cloudflare Workers local dev
dev:
    cd crates/passkey-worker && wrangler dev

# Check formatting and clippy
check:
    cargo fmt --all -- --check
    cargo clippy  --all --tests -- -Dclippy::pedantic

# Format all code
fmt:
    cargo fmt --all

# Clean build artifacts
clean:
    cargo clean
