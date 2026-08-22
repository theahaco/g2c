# Scope a key with perch — a Nido guided tour

A guided, six-act tour that takes one job — **"give your CI pipeline a key that
ships releases but can never touch admin or move funds — and prove it"** — from a
raw keypair all the way to a policy the chain enforces, then adds a **multi-sig
quorum**. It teaches, in order, what a smart account is, the OpenZeppelin model,
what Nido adds, **how perch makes authorization easier and safer**, and **how a
rule can require M-of-N signatures** — each ending in a live testnet demonstration.

Styled in Nido's own "Warm Nest" design language.

## The six acts

1. **One key, total power** — a Stellar G-address is all-or-nothing; handing it
   to CI hands over the treasury. *The problem.*
2. **The account becomes a program** — a smart account (C-address) runs your
   `__check_auth`; authorization is now code.
3. **OZ gives you the vocabulary** — `Signer` + `ContextRule` + **policies** —
   but policies are contracts you write, deploy, and audit (with an INV-2
   footgun that can brick your admin).
4. **Nido makes it human** — passkeys, a factory, recovery; connect a real
   account and see its **signers across verifiers** — secp256r1 (live), a
   **post-quantum ML-DSA-65** key, and a **Delegated → another account**
   (a co-signer / treasury). But scoping the CI key is still on you.
5. **perch: describe · prove · enforce** — first, the account's **full policy**:
   several rules where perch (the CI rule) **composes with OZ-native policies**
   (policy-free admin, an OZ spending-limit cap, a post-quantum co-signer). Then,
   on the CI rule:
   - **build** the policy as data → a live **policy builder**: toggle the
     functions the key may call, the `args[1] = self` author guard, and an
     `not-after-ledger` expiry, and watch the wire `PolicyDoc`, its `doc_hash`,
     the **reachable calls**, and a safety read all re-derive on every change;
   - **narrow** it safely → attenuation is a *machine-checked subset* (perch
     accepts a narrowing, refuses a widening);
   - **enforce** it on real testnet → the CI key `post`s (allowed) but cannot
     `clear` (denied by perch), with real tx links.
6. **Add signers · M-of-N** — the same account model also holds **several
   co-signers** and can require a **quorum**. The **policy panel** (the signers ×
   rules matrix from Act 5) gains a `2-of-3` rule via Nido's **OZ multisig
   policy** — perch scopes *what* a key may do; the threshold policy governs *how
   many* must sign, **composed on one account**. Proven live: `post` signed by
   **2 of 3** succeeds, signed by **1** is denied on-chain.

Closes on why perch is easier *and* safer: one interpreter audited once,
INV-1/INV-2, machine-checked attenuation, and `doc_hash` = exactly what enforces —
and both perch and the multisig policy are just policies on ContextRules, no
bespoke account code.

## Run it

```sh
npm install                 # from the repo root (workspaces)
npm run dev -w perch-status-onchain
```

Click through the acts. In Act 5, **build** the CI grant with the toggles (watch
the `PolicyDoc`, `doc_hash`, and reachable calls update live), **Narrow →
publish-only** (accepted), **Try to widen** (refused), then **Publish** (allowed
on-chain) and **Wipe** (denied on-chain). In Act 6, **Sign with 2** (allowed —
quorum met) and **Sign with 1** (denied on-chain — below threshold). Fees are
paid by an ephemeral friendbot account funded on demand.

## Verify (browser snapshots)

```sh
npx playwright install chromium
npm run test:e2e -w perch-status-onchain   # LIVE testnet — funds + submits real txs
```

Walks all six acts, exercises attenuation, drives real `post`/`clear`
transactions, and proves the 2-of-3 quorum live; writes `artifacts/*.png`. Needs
network + testnet, so it is **not** in the offline CI lane — run it explicitly.

## Deployed testnet pieces

| contract | address |
|---|---|
| perch interpreter (OZ Policy) | `CBO4FIGR2LP242IKWDME6NPFGCFAT5R7CSLKYLOOJFVXCCIGKVF6O44G` |
| status board (`post`/`clear`/`get`) | `CBVXSCMALSZBF32OGUXIXFAFMPYFOJM4BOA27PBCMJPR6ZNUREX5ELWM` |
| WebAuthn verifier (secp256r1) | `CACVGSAHYFBXY4LJKWW5B57LAAXHCZVDZOANUTYPLNV6HHQI4Q35EGMY` |
| perch-governed Nido account (Act 5) | `CAZSVYNP52AGK66S3XIAW6HJDFLMXHH3IQECRNCWKHSPIXKMD4RBNMPV` |
| Nido multisig policy (Act 6) | `CCSDKJYOFCPTCCGQZPF73RJNHFC7TPO532Q36N3M2VBYZFWQOTDB7J7G` |
| 2-of-3 quorum account (Act 6) | `CCJLM2X6SDBX5QXFI7QCZ42Q3TAYWBWYA2IG56IUHLXRNQIKP4OU3GQL` |

`interpreter wasm hash d0f93aac… · account wasm hash 5bb9f585… · doc_hash 7e6b00a4…`

The Act-6 quorum is proven live — `post` on the 2-of-3 account signed by **2 of 3**
co-signers is [allowed](https://stellar.expert/explorer/testnet/tx/21302c3eab6037c8c2f562a69b57ce42940fb161cb264da5c28a69722ddcb34b)
(`21302c3e…`); signed by **1** it is [denied on-chain](https://stellar.expert/explorer/testnet/tx/6f0265f978ab48fafc9753bd8a892351e701fc67f6183b40acea7fb5da45dde4)
(`6f0265f9…`, `FAILED`). `scripts/prove-threshold.ts` deploys the account and
reproduces both.

## How the policy gets on-chain

The RPN lowering (`PolicyDoc → InstallParams`) is Rust-only, so the policy is
compiled by the `perch-plan` CLI (perch repo) and installed as the account's
Default-rule policy at construction. `scripts/deploy-and-prove.ts` does the whole
thing (compile → deploy → prove allow+deny) and is the source of truth for the
addresses above. `src/perchOnchain.ts` holds the invoke flow used by Acts 5–6.

Act 6's quorum account is orthogonal: no perch policy, just Nido's **multisig
policy** (`SimpleThresholdAccountParams { threshold: 2 }`) on the Default rule
over three secp256r1 co-signers. `scripts/prove-threshold.ts` deploys it and the
browser drives the multi-signer ceremony live — M assertions over one auth digest
land in a single `AuthPayload` via `injectSignedAuthPayload`. perch scopes *what*
a key may do; the threshold policy governs *how many* must sign — composed on one
account, no bespoke account code either way.

### The footprint gotcha

Recording `simulateTransaction` never runs `__check_auth`, so its footprint
omits what the account's auth check touches — the verifier code, the interpreter
code, and the read-**write** `Program(account, rule_id)` entry perch `extend_ttl`s
— failing with `scecExceededLimit`. Fixed by **re-simulating the signed tx**
(enforcing mode) and submitting with that footprint. Every OZ/perch/nido test
mocks auth, so this path was untested until here.

## Roadmap — v2: author policies in the browser

Today the policy is fixed (compiled by the Rust CLI at deploy time). Next: a
WebAssembly build of the perch compiler so a policy built in Act 5 can be
compiled in-browser (byte-identical to Rust) and deployed live.
