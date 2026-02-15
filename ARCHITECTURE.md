# Technical Architecture

## 1. System Overview

This system facilitates migration from traditional Stellar accounts ("G-addresses") to Soroban Smart Accounts ("C-addresses") using WebAuthn/passkey authentication. It consists of a standalone web wallet, a set of on-chain smart contracts (built on OpenZeppelin's stellar-accounts), and gas abstraction via the OZ Relayer. All passkey verification happens on-chain — there is no off-chain backend.

### High-Level Flow
1. **Onboarding:** User opens wallet → creates passkey → wallet constructs atomic TX: Factory deploys C-address + migrates funds from temporary G-address.
2. **Operation:** dApp constructs unsigned TX → sends to wallet via URL embedding or refractor.space → user signs with passkey → wallet submits (directly or via OZ Relayer) → C-address executes.

## 2. Components

### A. Client: Standalone Web Wallet
A browser-based wallet application for managing Soroban Smart Accounts with passkey authentication.

- **Passkey Client:** Interacts with the WebAuthn/FIDO2 browser API to create credentials (onboarding) and sign assertions (transaction authorization).
- **Smart Account Client:** Constructs transactions targeting the user's SmartAccount, encoding calls to `execute` and signer/policy management functions.
- **Transaction Protocol:** Two modes for receiving transactions from dApps:
  - **URL-embedded:** TX XDR encoded directly in the wallet URL (suitable for small transactions).
  - **refractor.space:** dApp stores unsigned TX → receives an ID → redirects user to wallet with that ID → wallet fetches TX, displays for review, signs → returns TX hash to dApp.
- **Session Scope UI:** Interface for granting scoped session keys via OZ context rules (e.g., restrict a signer to specific contracts, spending limits, or time windows).

### B. Infrastructure: OZ Relayer
Gas abstraction service so users don't need XLM to transact.

- **Gas Abstraction:** Pays XLM fees on behalf of users, enabling zero-balance C-address interactions.
- **Submission Queue:** Manages sequence numbers and transaction submission retries.

### C. Smart Contracts (Soroban)

All contracts delegate core logic to OpenZeppelin's `stellar-accounts` library.

| Contract | Source | Description |
|----------|--------|-------------|
| `g2c-factory` | `contracts/factory/src/contract.rs` | Deployment orchestrator. `create_account(funder, key)` deploys a SmartAccount with a WebAuthn signer. `get_c_address(funder)` pre-computes the deterministic C-address (enabling pre-funding). Lazy-deploys a shared WebAuthn verifier singleton. Uses hardcoded WASM hashes for deterministic deployment. |
| `g2c-smart-account` | `contracts/smart-account/src/contract.rs` | Implements OZ `CustomAccountInterface` + `SmartAccount` + `ExecutionEntryPoint`. `__check_auth` delegates to `do_check_auth` from stellar-accounts. Context rules manage signers (with RP hash binding) and policies (spending limits, contract restrictions). `execute` provides a generic entry point for arbitrary contract calls. |
| `g2c-webauthn-verifier` | `contracts/webauthn-verifier/src/contract.rs` | Stateless OZ `Verifier` for secp256r1/P-256 passkey signatures. Receives `WebAuthnSigData` (signature, authenticator_data, client_data) and a 65-byte uncompressed public key. Deploy once, shared across all smart accounts. |

#### Contract Interaction Diagram

```
┌─────────┐   create_account()   ┌─────────────┐   deploys    ┌───────────────┐
│  Wallet  │ ──────────────────→ │   Factory    │ ──────────→ │ SmartAccount  │
└─────────┘                      └─────────────┘              └───────────────┘
                                       │                            │
                                  lazy-deploys                 __check_auth
                                       ↓                            │
                                ┌──────────────┐                    ↓
                                │   WebAuthn   │ ←─── verify() ────┘
                                │   Verifier   │
                                └──────────────┘
```

## 3. Data Flows

### Flow 1: Onboarding (G → C Migration)

This flow is atomic. If any part fails, the user retains funds in the G-address.

1. **User** opens the g2c wallet web app.
2. **Wallet** generates an ephemeral G-address (`G_temp`) and displays it for funding.
3. **User** funds `G_temp` (from a CEX withdrawal, another wallet, fiat on-ramp, etc.).
4. **Wallet** detects funds and prompts the user to create a passkey (`PK_Admin`).
5. **Wallet** constructs an atomic transaction signed by `G_temp`:
   - **Op 1: Invoke `Factory.create_account(G_temp, PK_Admin_pubkey)`**
     - Factory lazy-deploys the shared WebAuthn verifier (if not yet deployed).
     - Factory deploys a new SmartAccount with `PK_Admin` as the initial signer.
   - **Op 2: Payment from `G_temp` → computed C-address**
     - Amount: balance of `G_temp` minus estimated fees.
6. **Wallet** submits transaction to the Stellar network.
7. **Result:** SmartAccount is live at the deterministic C-address, `PK_Admin` is the owner, and funds are migrated.

### Flow 2: dApp Interaction

1. **dApp** constructs an unsigned transaction targeting the user's C-address.
2. **dApp** sends the transaction to the wallet via one of two methods:
   - **URL embedding:** Encodes TX XDR in a wallet URL and redirects the user.
   - **refractor.space:** Stores the TX, receives an ID, redirects user to wallet with that ID.
3. **Wallet** fetches or decodes the transaction and displays it for user review.
4. **User** approves and signs with their passkey (WebAuthn assertion).
5. **Submission** — one of two paths:
   - **Direct:** Wallet submits the signed transaction to the network and returns the TX hash to the dApp.
   - **Relayed:** Wallet sends the signed transaction to the OZ Relayer, which pays fees and submits. TX hash returned to dApp.
6. **On-chain execution:**
   - SmartAccount's `__check_auth` invokes the WebAuthn verifier to validate the passkey signature.
   - Context rules enforce signer scope (target contracts, spending limits, time windows).
   - Transaction proceeds if all checks pass.

## 4. Security Considerations

- **G-Key Ephemerality:** The `G_temp` private key is held only in memory and discarded after the migration transaction confirms. It serves no further purpose once funds reach the C-address.
- **On-Chain Verification:** All passkey signature verification happens on-chain via the WebAuthn verifier contract. There is no off-chain validation step that could be bypassed.
- **Passkey Recovery:** SmartAccount supports multiple admin signers via context rules. Users should add a backup device (e.g., phone) immediately after onboarding.
- **Replay Protection:** SmartAccount nonce tracking (via OZ stellar-accounts) prevents replay of signed transactions. Each WebAuthn assertion includes a challenge bound to the specific transaction payload.
- **RP Hash Binding:** Each signer's context rule records the RP ID hash, preventing cross-origin passkey reuse. The WebAuthn verifier checks `rpIdHash` in `authenticatorData` against the expected value.
- **Scoped Sessions:** Context rules restrict session signers to specific contracts, functions, spending limits, and time windows — enforced on-chain by the SmartAccount before execution proceeds.
