# Nido Usage Guide

Nido has three main ways to use it:

- Use the hosted testnet wallet at [nido.fyi](https://nido.fyi).
- Add Nido to a Stellar dApp through the Wallets Kit module.
- Run the wallet and example dApp locally from this repo.

The hosted wallet currently targets Stellar testnet. Do not use it for real
funds.

## Use the Hosted Wallet

1. Open [nido.fyi](https://nido.fyi).
2. Choose **Get started**.
3. Create a passkey when the browser asks.
4. Wait for the setup flow to publish the smart account to Stellar testnet.
5. Use the account page to copy the C-address, receive testnet XLM, send assets,
   claim a name, or manage recovery and session-key security.

Each account has its own subdomain. A named account can be opened as
`alice.nido.fyi`; an unnamed account can be opened as
`<c-address>.nido.fyi`. The passkey ceremony runs on that account subdomain so
the browser binds the passkey to the account that is signing.

Passkeys require a secure context. Use HTTPS in deployed environments or
`localhost` during development.

## Connect a dApp

Nido is exposed to dApps through
[`@nidohq/stellar-wallets-kit-module`](../packages/stellar-wallets-kit-module/README.md).
The module adds Nido to `@creit.tech/stellar-wallets-kit` as a hosted wallet:

- `connect` opens the Nido account picker at the deployment apex.
- `signTransaction` opens the selected account subdomain and asks for passkey
  approval.
- The dApp receives the signed XDR and submits it.

Install the module and the wallet kit:

```bash
npm install @nidohq/stellar-wallets-kit-module @creit.tech/stellar-wallets-kit
```

Initialize the kit with Nido. Add your normal Stellar wallet modules around it
as needed; the minimal Nido-only shape is:

```ts
import { StellarWalletsKit } from '@creit.tech/stellar-wallets-kit';
import {
  ACCOUNT_SWITCH_REQUESTED,
  NidoModule,
} from '@nidohq/stellar-wallets-kit-module';

const TESTNET_PASSPHRASE = 'Test SDF Network ; September 2015';

StellarWalletsKit.init({
  modules: [
    new NidoModule({
      base: 'https://nido.fyi',
      networkPassphrase: TESTNET_PASSPHRASE,
    }),
  ],
});

const { address } = await StellarWalletsKit.authModal();

try {
  const { signedTxXdr } = await StellarWalletsKit.signTransaction(tx.toXDR(), {
    address,
    networkPassphrase: TESTNET_PASSPHRASE,
  });

  // Submit signedTxXdr with your Stellar RPC client.
} catch (err) {
  if (err instanceof Error && err.name === ACCOUNT_SWITCH_REQUESTED) {
    const { address: nextAddress } = await StellarWalletsKit.authModal();
    // Rebuild the transaction for nextAddress, then ask Nido to sign again.
  } else {
    throw err;
  }
}
```

Nido accounts are smart-account C-addresses. They can sign Soroban transactions,
messages, and Soroban auth entries through the module. They cannot sign classic
Stellar operations as the source account because a C-address is a contract, not a
classic account keypair.

## Configure the Nido Base

The `base` passed to `NidoModule` is the Nido deployment apex:

| Environment | `base` value |
| --- | --- |
| Hosted testnet wallet | `https://nido.fyi` |
| Local wallet dev server | `http://localhost:4321` |
| Custom deployment | `https://your-nido-domain.example` |

For a dApp that reads Vite environment variables, keep the base configurable:

```dotenv
PUBLIC_NIDO_BASE="https://nido.fyi"
```

Then pass that value into `new NidoModule({ base })`.

## Run the Wallet Locally

From the repo root:

```bash
npm install
just dev
```

`just dev` builds the SDK and starts the Astro wallet app. Astro's default dev
server is `http://localhost:4321`.

During local development, account pages use `*.localhost` subdomains such as
`<c-address>.localhost:4321`. Keep the wallet base as
`http://localhost:4321` when a local dApp connects to the local wallet.

Useful repo-level commands:

```bash
just build-astro      # build the wallet frontend
just build-ts         # build the passkey SDK
just build-contracts  # build and optimize Soroban contracts
just test             # run Rust workspace tests
```

Package-level checks:

```bash
npm run build -w @nidohq/passkey-sdk
npm test -w @nidohq/passkey-sdk
npm run build -w @nidohq/stellar-wallets-kit-module
npm test -w @nidohq/stellar-wallets-kit-module
npm run test -w @nidohq/frontend
```

## Run the Example dApp

The example dApp shows Nido in a Stellar Wallets Kit picker and signs a Soroban
status-message transaction.

```bash
cd examples/status-message-dapp
cp .env.example .env
npm start
```

The default `.env.example` points the dApp at the hosted testnet wallet:

```dotenv
PUBLIC_NIDO_BASE="https://nido.fyi"
```

To test against a local wallet, change it to:

```dotenv
PUBLIC_NIDO_BASE="http://localhost:4321"
```

Then run the wallet dev server from the repo root in another terminal:

```bash
just dev
```

For the full example setup, see
[examples/status-message-dapp/README.md](../examples/status-message-dapp/README.md).

## Use the Packages

The public package names on this branch use the `@nidohq` scope:

| Package | Purpose |
| --- | --- |
| `@nidohq/passkey-sdk` | WebAuthn parsing, Soroban auth helpers, smart-account deployment, recovery, session keys, and policy helpers |
| `@nidohq/stellar-wallets-kit-module` | Wallets Kit module that adds Nido to a dApp wallet picker |
| `@nidohq/factory` | Generated TypeScript client for the factory contract |
| `@nidohq/smart-account` | Generated TypeScript client for the smart-account contract |
| `@nidohq/webauthn-verifier` | Generated TypeScript client for the WebAuthn verifier |
| `@nidohq/multisig-policy` | Generated TypeScript client for multisig recovery policy |
| `@nidohq/spending-limit-policy` | Generated TypeScript client for spending-limit policy |
| `@nidohq/status-message` | Generated TypeScript client for the demo status-message contract |

Within this repo, `npm install` links these packages through npm workspaces. In
an external app, install the published versions and import from the same package
names.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| The Nido popup does not open | Allow popups for the dApp origin. Connect and sign flows use a popup plus `postMessage`. |
| The browser says passkeys are unavailable | Use HTTPS or `localhost`. Plain HTTP on a non-loopback hostname is not a secure context. |
| The connect picker shows no accounts | Create a Nido account on the same device/browser profile first, then reconnect from the dApp. |
| Signing asks to switch accounts | Re-run connect, rebuild the transaction for the newly selected C-address, then request signing again. |
| A classic Stellar transaction fails to sign | Build a Soroban transaction or auth entry instead. Nido smart accounts are C-address contracts. |
| Local account subdomains do not resolve | Use `*.localhost` URLs, for example `<c-address>.localhost:4321`, and configure dApps with `PUBLIC_NIDO_BASE="http://localhost:4321"`. |
