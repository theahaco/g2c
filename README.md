# g2c

Migrate Stellar G-addresses to Soroban Smart Accounts (C-addresses) with passkey authentication.

g2c provides smart contracts, a web wallet, and an onboarding SDK that let users create passkey-secured C-addresses funded from any G-address or CEX withdrawal — in a single atomic transaction.

## How It Works

1. User opens the g2c wallet and funds an ephemeral G-address
2. Wallet prompts passkey creation via WebAuthn
3. Wallet submits one atomic transaction: Factory deploys the Smart Account + funds move from G to C
4. User now has a passkey-secured C-address — the G-address is discarded

After onboarding, dApps send unsigned transactions to the wallet (via URL or [refractor.space](https://refractor.space)). The user signs with their passkey, and the wallet submits — optionally via the OZ Relayer for gas abstraction.

All passkey verification is on-chain.

## Contracts

| Contract | Description |
|----------|-------------|
| `g2c-factory` | Deploys Smart Accounts with a WebAuthn signer. `create_account(funder, key)` + `get_c_address(funder)`. Lazy-deploys a shared verifier. |
| `g2c-smart-account` | OZ `SmartAccount` + `CustomAccountInterface` + `ExecutionEntryPoint`. Context rules for scoped session keys and policies. |
| `g2c-webauthn-verifier` | Stateless secp256r1/P-256 `Verifier`. Deploy once, shared across all accounts. |

All contracts build on [OpenZeppelin's stellar-accounts](https://docs.openzeppelin.com/stellar-contracts/accounts/smart-account).

## Build & Test

Requires [just](https://github.com/casey/just), [Rust](https://rustup.rs/), and the [Stellar CLI](https://developers.stellar.org/docs/tools/developer-tools/cli/install-cli).

```bash
just build-contracts   # Build and optimize Soroban WASM
just build             # Build all workspace crates (native)
just test              # Run all workspace tests
just check             # cargo fmt --check + cargo clippy
just fmt               # Format all code
```

## Project Structure

```
contracts/
  factory/             # Account deployment orchestrator
  smart-account/       # Passkey-authenticated smart account
  webauthn-verifier/   # On-chain P-256 signature verifier
crates/
  integration-tests/   # Cross-crate integration tests
frontend/              # Wallet web app
```

## Documentation

- [ARCHITECTURE.md](./ARCHITECTURE.md) — Technical architecture, data flows, and security model
- [APPLICATION.md](./APPLICATION.md) — SCF Build Award application

## License

MIT
