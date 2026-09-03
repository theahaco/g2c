<div align="center">
  <img
    src="packages/frontend/public/favicon.svg"
    alt="Nido nest ring logo"
    width="96"
    height="96"
  />

  <h1>Nido</h1>

  <p><strong>A safe place for everything you own: money, identity, and access.</strong></p>

  <p>
    Create your Nido in seconds with a passkey. Nothing to memorize, no browser
    extension to install, and every approval is verified by Stellar smart contracts.
  </p>

  <p>
    <a href="https://nido.fyi"><strong>Launch testnet wallet</strong></a>
    |
    <a href="./docs/USAGE.md">Usage guide</a>
    |
    <a href="./ARCHITECTURE.md">Architecture</a>
    |
    <a href="./DEPLOYED.md">Deployments</a>
    |
    <a href="./examples/status-message-dapp/README.md">Example dApp</a>
  </p>

  <p>
    <img alt="Network: Stellar testnet" src="https://img.shields.io/badge/network-Stellar%20testnet-0E9AA8" />
    <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-F25C2A" />
  </p>

  <p><sub>The hosted wallet currently targets Stellar testnet. Do not use it for real funds.</sub></p>
</div>

## Why Nido

| For users | For developers |
| --- | --- |
| Create an account with a passkey instead of a seed phrase or browser extension. | Add Nido to a Stellar dApp through the Wallets Kit module. |
| Own a Stellar smart account that can hold money, identity, and access. | Use TypeScript helpers for WebAuthn, Soroban auth, deployment, recovery, and session keys. |
| Recover access and add rules without relying on a custodial backend. | Build on Soroban contracts that verify passkey approvals on-chain. |

## How It Works

1. **Create your Nido:** The wallet reserves a deterministic smart-account
   C-address and prepares the setup flow.
2. **Confirm with a passkey:** The browser runs a WebAuthn ceremony and extracts
   the user's P-256 public key.
3. **Publish to Stellar:** The factory deploys a Soroban smart account, installs
   the passkey signer, and moves testnet funds into the new account.
4. **Use it with dApps:** dApps request signatures through Nido, the Stellar
   Wallets Kit module, or direct handoff URLs.
5. **Verify on-chain:** The smart account calls the WebAuthn verifier contract
   during `__check_auth`, then applies context rules and policy checks before
   the transaction executes.

This keeps private key material out of the app, binds passkeys to account
subdomains, and gives each account an extensible policy layer for recovery and
limited-scope signing.

## What's Included

| Area | Path | Description |
| --- | --- | --- |
| Wallet frontend | `packages/frontend/` | Astro app for Nido account creation, signing, sending, security, and activity views |
| Passkey SDK | `packages/passkey-sdk/` | WebAuthn, Soroban auth, deployment, storage, policy, recovery, and session-key helpers |
| Wallets Kit module | `packages/stellar-wallets-kit-module/` | `@creit.tech/stellar-wallets-kit` module for dApp wallet selectors |
| Contract bindings | `packages/contract-bindings/` | Generated TypeScript clients for the Soroban contracts |
| Smart contracts | `contracts/` | Factory, smart account, WebAuthn verifier, name registry, status message, and policy contracts |
| Integration tests | `crates/integration-tests/` | Cross-contract Rust tests with synthetic WebAuthn assertions |
| End-to-end tests | `tests/` | Browser, support, and testnet test harnesses |
| Example dApp | `examples/status-message-dapp/` | React/Vite dApp showing wallet selector integration |

## Smart Contracts

| Contract | Purpose |
| --- | --- |
| Factory | Deploys smart accounts, resolves shared policy/verifier contracts, and computes deterministic C-addresses |
| Smart Account | OpenZeppelin-based account contract with passkey auth, execution entry point, context rules, and policy enforcement |
| WebAuthn Verifier | Stateless P-256/WebAuthn verifier shared by smart accounts |
| Name Registry | Human-readable account name registry |
| Multisig Policy | Threshold-based recovery and delegated policy support |
| Spending Limit Policy | Scoped spending-limit policy for smart-account calls |
| Status Message | Small demo contract used by the example dApp |

All account contracts build on
[OpenZeppelin Stellar Contracts](https://docs.openzeppelin.com/stellar-contracts/accounts/smart-account)
and Soroban's native authorization model.

## Quick Start

### Prerequisites

- Node.js 20+
- Rust and Cargo
- [`just`](https://github.com/casey/just)
- [Stellar CLI](https://developers.stellar.org/docs/tools/developer-tools/cli/install-cli)
- `stellar-scaffold` for scaffold-based contract workflows

Install dependencies from the repo root:

```bash
npm install
```

### Common Commands

```bash
just dev              # Build the SDK, then run the Nido frontend locally
just build-astro      # Build the Astro frontend
just build-ts         # Build the passkey SDK
just build-contracts  # Build and optimize Soroban contracts
just test             # Run Rust workspace tests
just check            # cargo fmt --check + clippy
just fmt              # Format Rust code
```

Package-level checks are also available through npm workspaces:

```bash
npm run build -w packages/passkey-sdk
npm test -w packages/passkey-sdk
npm run build -w packages/stellar-wallets-kit-module
npm test -w packages/stellar-wallets-kit-module
npm run test -w packages/frontend
```

## Run the Example dApp

The status-message example demonstrates a third-party dApp connecting through
the Stellar Wallets Kit picker with Nido listed as a wallet option.

```bash
cd examples/status-message-dapp
cp .env.example .env
npm start
```

See [examples/status-message-dapp/README.md](./examples/status-message-dapp/README.md)
for local network, testnet, and GitHub Pages deployment details.

## Security Model

- **No custody:** The wallet does not hold a server-side signing key.
- **Passkeys verified on-chain:** WebAuthn assertions are checked by the
  verifier contract during Soroban authorization.
- **Origin-bound accounts:** Account subdomains scope WebAuthn RP IDs so a
  passkey for one account cannot approve another account.
- **Ephemeral G-address funding:** The onboarding G-key is used to fund and
  deploy the smart account, then discarded.
- **Recovery and policy controls:** Context rules, recovery policies, session
  keys, and spending limits are enforced by the smart account and policy
  contracts.

For deeper implementation details, read [ARCHITECTURE.md](./ARCHITECTURE.md).

## Documentation

- [Usage guide](./docs/USAGE.md)
- [Architecture](./ARCHITECTURE.md)
- [Current deployments](./DEPLOYED.md)
- [SCF application notes](./docs/APPLICATION.md)
- [SCF requirements](./docs/REQUIREMENTS.md)
- [Status Message dApp guide](./examples/status-message-dapp/README.md)
- [Wallets Kit module guide](./packages/stellar-wallets-kit-module/README.md)

## License

Apache-2.0
