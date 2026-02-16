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

cloudflare-deploy:
    npm run build -w @g2c/frontend
    npx wrangler pages deploy packages/frontend/dist/ --project-name mysoroban
