#### 📋 Requirements

* Your submission must address an [open RFP](#current-open-rfps) from the current quarter—read the RFP carefully and respond directly to its needs.
* You must clearly show:
  * Why you’re a good fit to solve this (provide examples of past dev-focused work if possible)
  * What makes your solution technically strong
  * Clear, testable milestones&#x20;
  * How your tool will be maintained post-launch

#### Current Open RFPs

RFPs are sourced from ideas submitted by the Stellar ecosystem, selected by Delegates through the [SCF Quarterly Process](https://stellar.gitbook.io/scf-handbook/scf-awards/build-award/quarterly-governance-process), and published here at the start of each quarter:

### C-Address Tooling & Onboarding


#### 1. Scope of Work

Well-researched approach with reference/example implementation with onboarding flow on how to easily fund a C-address (Soroban Smart Account) without first using a traditional G-address.

#### 2. Background & Context

The shift to C-addresses (Soroban smart accounts) is critical for next-generation dApps on Stellar, but two major adoption blockers persist: 1) the inability to easily fund a C-address without first using a traditional G-address, and a2) a lack of core, modern mobile tooling around the [Smart Account standard by OpenZeppelin](https://docs.openzeppelin.com/stellar-contracts/accounts/smart-account). This technical friction limits the utility of C-addresses for end-users and exchanges.

#### 3. Requirements

* C-Address Onboarding/Funding Solution with G-to-C Seamless Bridge: A protocol or service that enables the direct funding of a C-address using G-addresses, CEX withdrawals, and  possibly off-ramp solutions (e.g., a proxy service routing from credit card to G-address to C-address). The goal is to make the G-address step transparent or unnecessary for the end-user.
* Viable C-Address Wallet: A reference implementation of a production level wallet to showcase the tooling and standard at parity with the [Freighter wallet](https://www.freighter.app/), including support showing all tokens held, history of transfers.&#x20;
* Onboarding Kit/UX Flow: Develop a standard, open-source "onboarding kit" that creates a standard user experience flow for wallet providers/Stellar wallets. This kit should encompass:
* A seamless flow for C-address creation, asset bridging, adding assets, and funding with XLM for fees.
* Easy integrations with existing bridges when selecting a Stellar wallet.
* An onboarding flow that supports funding a C-address from a standard G-address or CEX withdrawal.
* Wishlist Item: The onboarding flow should allow users to sign in with other ecosystem wallets (e.g., Metamask, Phantom, Rabby, etc.), derive a new address, and then proceed through the funding flow, potentially funding their account/adding assets based on policies like address activity.
* Associated tooling for building on and with C-address wallets as part of the reference implementation on the web and on mobile
* Approach and structure needs to be designed with input from potential users (such as Ecosystem wallets)
* The implementation should be fully Open Source

#### 4. Evaluation Criteria

* High technical capability and proven experience building on both Stellar operations and Soroban smart contracts
* Ecosystem alignment and demonstrated ability and willingness to connect with the existing ecosystem (wallets) as they’d be the potential users of this
* Coherent integration plan and timeline

#### 5. Expected Deliverables

* Smart contracts
* SDKs or libraries
* Documentation
* Test suite
* Audit fixes
* Production-ready version
* Example integrations
