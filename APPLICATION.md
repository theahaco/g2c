> Make a unique title that's different from your project name and reflects what you're asking funding for. Max 40 characters

## Project Title
Passkey-Native C-Address Onboarding Kit

> Use less than 130 characters to describe the products/services you're planning to build in your submission, how it works, and your target audience. This is your opportunity to capture the attention of your reader and gain buy-in! A frequently used format is: "Develops/Offers/Gives/etc. _(a defined offering)_ to help/support _(a defined audience)_ _(solve a problem)_ with _(secret sauce)_". Read more about this format and see examples in this blog post.

## One Sentence Description:
Delivers smart contracts, a passkey wallet web app, and an onboarding SDK to migrate users from G-addresses to C-addresses seamlessly.

> Enter a relevant URL for this submission. This can be, for example, a front-end interface or any part of the project already developed — particularly relevant if the project is already live on another blockchain.

## Project URL


> Enter the URL of the relevant github page.

## Code URL
https://github.com/theahaco/g2c

> This is your elevator pitch: keep it short (<3 min), powerful, and clearly demonstrate the project's features and functionality. Upload your demo video on Youtube or Vimeo with a 16:9 aspect ratio (ideally 1920px by 1080px).

## Video URL


## Soroban


> Briefly describe the to be added / improved products and services by this submission. Keep it succinct, and for each feature add how Stellar is used and how the improvements will impact your project.

## Product and Services

**1. g2c Smart Contracts (Soroban)**
Three Soroban contracts that handle the full lifecycle of C-address creation and passkey-based authentication:
- **Factory** (`g2c-factory`): Deterministic deployment of Smart Accounts. A single `create_account(funder, key)` call deploys the account and registers the user's passkey as the initial signer, while lazy-deploying a shared WebAuthn verifier. `get_c_address(funder)` lets wallets pre-compute the C-address before deployment, enabling pre-funding flows. Built on Stellar's `deployer_with_address` for deterministic addresses.
- **Smart Account** (`g2c-smart-account`): Implements OpenZeppelin's `CustomAccountInterface`, `SmartAccount`, and `ExecutionEntryPoint` traits. Handles passkey-authenticated transaction execution, context rules for scoped session keys, and policy enforcement — all on-chain. Uses Stellar's native `__check_auth` hook for account abstraction.
- **WebAuthn Verifier** (`g2c-webauthn-verifier`): Stateless secp256r1/P-256 signature verifier implementing OZ's `Verifier` trait. Deployed once and shared across all smart accounts, keeping per-account deployment costs low.

**2. g2c Wallet (Web App)**
A standalone browser-based wallet for managing Soroban Smart Accounts with passkey authentication. Key capabilities:
- Passkey-based account creation and transaction signing via the WebAuthn browser API.
- G→C onboarding flow: generate ephemeral G-address, detect funding, create passkey, deploy C-address — all in one atomic transaction on Stellar.
- Transaction receiving from dApps via URL-embedded XDR or refractor.space (store-and-redirect protocol).
- Session key management UI for granting dApps scoped permissions via OZ context rules.
- Gas abstraction via OZ Relayer integration, so users can transact without holding XLM.
- Token balances and transfer history display, at parity with existing Stellar wallets.

**3. Onboarding SDK**
An open-source JavaScript/TypeScript SDK that any Stellar wallet or dApp can integrate to offer C-address onboarding:
- Pre-built UI components for the G→C migration flow (funding, passkey creation, deployment).
- Transaction construction helpers for factory interactions and Smart Account operations.
- refractor.space integration for cross-app transaction signing.
- Documentation and example integrations showing how to add C-address support to an existing wallet.

> Provide evidence of prior traction or validation. Include users, community size, partnerships, KPIs (TVL...), beta testers to demonstrate adoption, market interest, and project credibility.

## Traction Evidence


> Add an accessible link to your technical architecture of the to be added / improved product/services. The technical architecture should go into the specifics on the Stellar integration, demonstrating you have sufficient insight to start building immediately.
>
> To help you:
> Framework: Scaffold Stellar
> Wallet integration (Xbull, Freighter to focus) : https://stellarwalletskit.dev/
> Building a Poc : https://lab.stellar.org/
>
> Technical architectures exemples:
> - Blindpay
> - FrankSzendzielarz/SorobanRPCSDK
> - Sorobanhooks TA

## Technical Architecture
See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full technical architecture, covering the contract interaction model, data flows for onboarding and dApp interaction, and security considerations. The smart contracts are implemented and available in the repository under `contracts/`.

> Depending on the scope of your project, importance to the ecosystem, and team, you can request up to $XXX in XLM for ~4 months to cover costs directly related to development of the product itself with the final goal being to launch on mainnet or equivalent. Take a close look at the Budget Guidelines to determine your total budget request.
>
> You should divide your deliverables into 3 main milestones: The final milestone should be your Mainnet launch, but you'll set the other two for yourself.
>
> Your award will be distributed in 4 tranches using the following structure:
> Tranche #0: 10% of total budget (upon approval)
> Tranche #1: 20% of total budget
> Tranche #2: 30% of total budget
> Tranche #3: 40% of total budget + professional user testing (upon mainnet launch)
>
> Common issues:
> 1. SCF funding may not be used for marketing or promotion. Do not include these items in your budget.
> 2. Security audit credits are provided as part of the tranche #3 completion. Audit costs should not be included in your budget.
>
> IMPORTANT
> - 2 to 3 Deliverables by Tranches
> - How to measure completion: You must stick to what you write. Do not provide precise numbers; if you want to mention a project, write "e.g., XXX".
> - Budget: Announce amounts rounded to hundreds (e.g., prefer $9,600 to $10,000).

## SCF Build Tranche Deliverables

### Tranche 0 — Approval
$15,000 (10% of total)

Disbursed upon approval to bootstrap development infrastructure and finalize contract design.

---

## Tranche 1 - MVP
$30,000 (20% of total)

**Deliverable 1: Smart Contracts — Feature Complete**
- Factory, Smart Account, and WebAuthn Verifier contracts finalized with full test suite.
- Factory supports `create_account` and `get_c_address`; Smart Account implements OZ `SmartAccount` + `CustomAccountInterface` + `ExecutionEntryPoint` with context rules.
- Completion: All contracts compile, pass unit/integration tests, and deploy to Stellar testnet. Test suite covers onboarding flow, passkey auth, and session key scoping.
- Estimated completion: 4 weeks after approval.
- Budget: $18,000

**Deliverable 2: Basic Wallet Web App**
- Passkey creation and transaction signing via WebAuthn browser API.
- G→C onboarding flow: ephemeral G-address generation, fund detection, passkey registration, atomic deployment + fund transfer.
- Completion: User can create a passkey, fund a G-address, and migrate to a C-address on testnet via the web app.
- Estimated completion: 6 weeks after approval.
- Budget: $12,000

---

## Tranche 2 - Testnet
$45,000 (30% of total)

**Deliverable 1: Full dApp Interaction Flow**
- Transaction receiving via URL-embedded XDR and refractor.space integration.
- Transaction review UI with human-readable operation display.
- Completion: A sample dApp can send an unsigned transaction to the wallet (via both methods), wallet displays it for review, user signs with passkey, and the signed transaction executes on testnet.
- Estimated completion: 10 weeks after approval.
- Budget: $15,000

**Deliverable 2: OZ Relayer Integration + Session Keys**
- Gas abstraction: wallet can submit transactions via OZ Relayer so users transact without holding XLM.
- Session key UI: users can grant dApps scoped signing permissions (contract restrictions, spending limits, time windows) via context rules.
- Completion: Demonstrate gas-abstracted transaction on testnet. Session key can be created with scope restrictions and used by a dApp to execute a scoped transaction.
- Estimated completion: 13 weeks after approval.
- Budget: $18,000

**Deliverable 3: Wallet Feature Parity**
- Token balance display (all assets held by the C-address).
- Transfer history view.
- Completion: Wallet shows token balances and recent transfer history on testnet, comparable to existing Stellar wallets (e.g., Freighter).
- Estimated completion: 14 weeks after approval.
- Budget: $12,000

---

## Tranche 3 - Mainnet
$60,000 (40% of total)

**Deliverable 1: Mainnet Deployment + Audit Fixes**
- Deploy all contracts to Stellar mainnet.
- Address findings from the SCF-provided security audit.
- Completion: Contracts deployed to mainnet, all critical and high audit findings resolved, audit report published.
- Estimated completion: 17 weeks after approval.
- Budget: $24,000

**Deliverable 2: Onboarding SDK + Documentation**
- Open-source JavaScript/TypeScript SDK with pre-built components for G→C onboarding, factory interactions, and refractor.space integration.
- Developer documentation covering SDK usage, contract ABIs, and integration guides.
- Completion: SDK published to npm, documentation site live, SDK can be used to add C-address onboarding to an existing app.
- Estimated completion: 19 weeks after approval.
- Budget: $21,600

**Deliverable 3: Example Integrations**
- Reference integrations demonstrating how existing wallets and dApps can adopt C-address support using the SDK.
- Completion: At least two example integrations published (e.g., a simple dApp using refractor.space, and a wallet adding C-address onboarding via the SDK).
- Estimated completion: 20 weeks after approval.
- Budget: $14,400

---

> Please note: submission with budgets amounts exceeding the maximum will be denied without review. Find budget guidelines for each award in the SCF Handbook.

## Budget Total
$150,000

> After finishing the submission, what's your plan to go-to-market ?

## Go-To-Market Plan
- **Open Source First:** All contracts, wallet, and SDK are MIT-licensed and publicly available from day one. Developers can inspect, fork, and contribute.
- **Ecosystem Wallet Integrations:** Engage with existing Stellar wallets (e.g., Freighter, xBull, Lobstr) during development to gather input on the onboarding SDK and ensure it fits their integration needs. The SDK is designed to drop into existing wallet codebases with minimal friction.
- **Developer Documentation:** Publish comprehensive guides covering contract deployment, SDK integration, and the G→C onboarding flow. Host on the project repository and Stellar developer channels.
- **Testnet Playground:** Provide a hosted testnet instance of the wallet and a sample dApp so developers can try the full flow before integrating.
- **Community Feedback Loop:** Share progress in Stellar developer Discord and forums throughout development, incorporating feedback into the SDK API and onboarding UX.

> What does success and impact look like? You can mention output (e.g. number of new users) but also what the impact of that output is (e.g. expanding financial access).

## Success Criteria
- **C-Address Adoption:** Meaningful number of C-addresses created via the factory contract on mainnet within the first months after launch, demonstrating that the G→C migration path works for real users.
- **Wallet Integrations:** At least one ecosystem wallet (beyond the g2c wallet itself) integrates the onboarding SDK, validating the kit's utility for the broader Stellar ecosystem.
- **Developer Adoption:** SDK downloads and GitHub engagement (stars, forks, issues) indicate active developer interest in building on C-address infrastructure.
- **Transaction Flow Validation:** dApps successfully use the refractor.space and URL-embedding protocols to request transaction signatures from C-address wallets, proving the cross-app interaction model works in practice.
- **Gas Abstraction Usage:** Transactions submitted via OZ Relayer on mainnet, demonstrating that users can interact with Soroban contracts without holding XLM — lowering a key barrier to Stellar adoption.
- **Security Posture:** Clean audit report with all critical findings resolved before mainnet launch. No loss of user funds.
