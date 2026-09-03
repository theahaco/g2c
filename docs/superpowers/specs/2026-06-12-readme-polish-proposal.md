# README polish proposal

_Date: 2026-06-12 - Status: proposed_

## 1. Goal

Make `README.md` feel like the front door for Nido, not just a technical
inventory. The first screen should quickly answer:

- What is Nido?
- Why should someone care?
- Where do they go next?
- Is this safe to try with real funds?

The strongest visual change should be a centered, branded top section.

## 2. Current issue

The current README is accurate and useful, but the opening is plain and
developer-first:

- The title and tagline are left-aligned, so the top does not feel like a
  polished public project page.
- The first paragraph introduces account abstraction, Stellar addresses,
  Soroban contracts, and tooling before the reader gets a simple product
  promise.
- The testnet warning is correct, but it reads as a blockquote after the
  technical intro instead of as clear launch-state metadata.
- The best Nido brand language already exists elsewhere in the repo:
  "A safe place for everything you own - money, identity, and access."

## 3. Proposed top section

Replace the current title, tagline, intro paragraphs, and blockquote warning
with a centered hero block. GitHub-flavored Markdown does not support centering
directly, so this should intentionally use a small amount of HTML.

```md
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
```

Why this works:

- It makes the top visibly branded by reusing the existing Nest Ring favicon.
- It keeps the core product promise above the technical details.
- It gives readers immediate next actions without needing to scan the whole file.
- It keeps the testnet warning visible without making the README feel defensive.

## 4. Proposed README structure

After the centered hero, keep the README mostly technical, but make the flow
more engaging:

1. **Why Nido**
   - Three short bullets or a compact table:
     - Set up with a passkey.
     - Own an account that can hold money, identity, and access.
     - Recover and add rules without relying on a custodial backend.

2. **How It Works**
   - Keep the existing numbered flow, but start in user language:
     "Create your Nido", "Confirm with a passkey", "Use it with dApps".
   - Put G-address, C-address, Soroban, and `__check_auth` details in the
     supporting sentences, not the step titles.

3. **What's Included**
   - Keep the current package table. It is useful and already clear.
   - Consider renaming "Nido wallet app" to "Wallet frontend" for consistency
     with the table.

4. **Smart Contracts**
   - Keep this section as-is with light copy edits only. Readers who reach this
     point want the technical detail.

5. **Quick Start**
   - Move before or after "What's Included" depending on audience priority:
     - If README is primarily for developers, put Quick Start earlier.
     - If README is primarily for funders/users/reviewers, keep the product
       explanation first.

6. **Security Model**
   - Keep the existing bullets, but make the labels slightly more reader-friendly:
     "No custody", "Passkeys verified on-chain", "Origin-bound accounts",
     "Recovery and policy controls".

7. **Documentation**
   - Keep the current link list.

## 5. Copy direction

Use the Nido brand voice at the top, then become increasingly technical as the
reader moves down the README.

Recommended changes:

- Lead with "Nido" and "A safe place for everything you own" instead of
  "Passkey-native smart accounts for Stellar."
- Avoid `G-address`, `C-address`, `Soroban`, and `account abstraction` in the
  first screen unless they are inside a later technical sentence.
- Use "Create your Nido" for onboarding language.
- Keep "Stellar", "Soroban", and "smart contracts" present enough that
  technical readers understand what the project is.
- Keep the testnet warning near the top and in plain language.

## 6. Optional polish

These are not required for the first README pass, but they would make the page
feel more finished:

- Add a short screenshot or product preview from `packages/frontend/public/og-image.png`
  below the centered header if the image renders well in the README.
- Add a compact table of links under the hero instead of the current "Live Links"
  section, then remove the duplicate section.
- Add package badges only if they reflect maintained checks or published packages.
  Decorative badges should stay limited.
- Add a two-column "Users" / "Developers" path so different audiences can find
  their next step quickly.

## 7. Acceptance criteria

- The README top is centered on GitHub.
- The Nido mark renders from a repo-local asset.
- The first screen communicates the product promise before implementation details.
- The testnet-only status is visible without scrolling far.
- All existing technical content remains available.
- Existing links still resolve.
- The README does not overpromise production readiness or mainnet support.
