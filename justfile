# List available recipes
default:
    @just --list

# Run all workspace tests
test:
    cargo test --workspace

# Build all crates (native)
build:
    cargo build --workspace

# Build and optimize Soroban contracts
build-contracts:
    stellar contract build --optimize --profile contract

build-ts:
    npx tsc -p ./packages/passkey-sdk/tsconfig.json

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

check-astro:
    npx astro check --root ./packages/frontend

build-astro:
    npx astro build --root ./packages/frontend

cloudflare-deploy: build-astro
    npx wrangler pages deploy packages/frontend/dist/ --project-name mysoroban --branch main

dev: build-ts
    (cd packages/frontend; npm run dev)
