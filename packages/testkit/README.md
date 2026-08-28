# @nidohq/testkit

Dapp-author testing tools for Nido: create and exercise a smart account from
**local keys** — no WebAuthn passkey, no live network — and simulate
authorization locally.

Tracking issue + request intake: **nidohq/nido#188**.

## Why

The production way to stand up a Nido account is a passkey ceremony: a real
browser, a user gesture, an authenticator. That's impossible in a unit test or a
CI job. This package gives you a Nido account from an in-process keypair, so a
test can answer *"does this call authorize under this account's policy?"* with a
plain assertion.

## Quick start

```ts
import { localSigner, createLocalAccount, simulateCheckAuth, contract, isSelf, rule } from '@nidohq/testkit';

// A CI key (ed25519) and an admin (secp256r1 — same curve the webauthn-verifier
// checks, but from a local key instead of a passkey).
const admin = localSigner({ id: 'admin', algorithm: 'secp256r1' });
const ci    = localSigner({ id: 'ci',    algorithm: 'ed25519' });

const account = createLocalAccount({
  signers: [admin, ci],
  rules: [
    rule({ name: 'admin-root', scope: { type: 'self-admin' }, signedBy: ['admin'] }),
    rule({ name: 'ci-publish', scope: contract(REGISTRY), signedBy: ['ci'],
           functions: ['publish', 'publish_hash'], args: [{ index: 1, pred: isSelf() }] }),
  ],
});

account.address;  // derived C-address (real deployer+salt derivation)
account.docHash;  // the perch policy's real doc_hash

// The ci key may publish as self...
simulateCheckAuth(account, { contract: REGISTRY, fn: 'publish', args: [/* … */] }, ['ci']).verdict; // 'allow'
// ...but not call anything else.
simulateCheckAuth(account, { contract: REGISTRY, fn: 'set_admin', args: [/* … */] }, ['ci']).verdict; // 'deny'
```

## Verifiers

A signer's `algorithm` maps to the verifier its key is checked by:

| algorithm    | verifier                    | on-chain today |
|--------------|-----------------------------|----------------|
| `secp256r1`  | `webauthn-verifier`         | ✅ (driven by a local P-256 key here) |
| `ed25519`    | ed25519 verifier            | ⚠️ simulated — no `External` ed25519 verifier yet |
| `ml-dsa-65`  | post-quantum verifier (#143)| ⚠️ simulated — groundwork in nido#143 |

The ed25519 and ML-DSA verifiers, and perch policies themselves, are modelled
**ahead of their on-chain contracts** so the testkit can demonstrate the target
multi-verifier, perch-policied account. The simulator *is* the perch interpreter
until perch is integrated on-chain.

## Roadmap — from simulation to a real VM, still offline

`simulateCheckAuth` is a faithful TS model today. The endgame, behind the same
call so your test code never changes:

1. Run the real **`soroban-env` in the browser** — it's `wasmi`, so it compiles
   to wasm and runs the same host functions the network does.
2. Back it with **[stellar/rs-soroban-sdk#1657](https://github.com/stellar/rs-soroban-sdk/pull/1657)**'s
   local-storage cache, so the env lazily pulls ledger entries from testnet and
   caches them — fork-testnet-locally.

Result: tests run fully local by default, touch the network only for state they
read, and are real-VM-accurate.

## API

- `localSigner({ id, algorithm, verifier?, keypair? })` → `LocalSigner`
- `createLocalAccount({ signers, network?, factory?, salt?, rules? })` → `LocalAccount`
- `simulateCheckAuth(account, context, signedBy[])` → `{ verdict, authDigest, matchedRule, reasons, signerChecks }`
- `reachableCalls(policy)`, `isNarrowing(parent, child)` — perch reachable-call + attenuation analysis
- `computeAuthDigest`, `buildSyntheticAssertion`, `verifySignature`, `VERIFIERS`
- perch policy: `rule`, `contract`, `selfAdmin`, `isSelf`, `addressEq`, `stringIn`, `stringPrefix`, `u32Eq`, `docHash`

See `examples/perch-authz-console/` for a full dapp built on this.
