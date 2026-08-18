# Scope a key with perch — a Nido guided tour

A guided, five-act tour that takes one job — **"give your CI pipeline a key that
ships releases but can never touch admin or move funds — and prove it"** — from a
raw keypair all the way to a policy the chain enforces. It teaches, in order,
what a smart account is, the OpenZeppelin model, what Nido adds, and **how perch
makes authorization easier and safer** — ending in a live testnet demonstration.

Styled in Nido's own "Warm Nest" design language.

## The five acts

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

Closes on why perch is easier *and* safer: one interpreter audited once,
INV-1/INV-2, machine-checked attenuation, and `doc_hash` = exactly what enforces.

## Run it

```sh
npm install                 # from the repo root (workspaces)
npm run dev -w perch-status-onchain
```

Click through the acts. In Act 5, **build** the CI grant with the toggles (watch
the `PolicyDoc`, `doc_hash`, and reachable calls update live), **Narrow →
publish-only** (accepted), **Try to widen** (refused), then **Publish** (allowed
on-chain) and **Wipe** (denied on-chain). Fees are paid by an ephemeral
friendbot account funded on demand.

## Verify (browser snapshots)

```sh
npx playwright install chromium
npm run test:e2e -w perch-status-onchain   # LIVE testnet — funds + submits real txs
```

Walks all five acts, exercises attenuation, and drives real `post`/`clear`
transactions; writes `artifacts/*.png`. Needs network + testnet, so it is **not**
in the offline CI lane — run it explicitly.

## Deployed testnet pieces

| contract | address |
|---|---|
| perch interpreter (OZ Policy) | `CBO4FIGR2LP242IKWDME6NPFGCFAT5R7CSLKYLOOJFVXCCIGKVF6O44G` |
| status board (`post`/`clear`/`get`) | `CBVXSCMALSZBF32OGUXIXFAFMPYFOJM4BOA27PBCMJPR6ZNUREX5ELWM` |
| WebAuthn verifier (secp256r1) | `CACVGSAHYFBXY4LJKWW5B57LAAXHCZVDZOANUTYPLNV6HHQI4Q35EGMY` |
| perch-governed Nido account | `CAZSVYNP52AGK66S3XIAW6HJDFLMXHH3IQECRNCWKHSPIXKMD4RBNMPV` |

`interpreter wasm hash d0f93aac… · account wasm hash 5bb9f585… · doc_hash 7e6b00a4…`

## How the policy gets on-chain

The RPN lowering (`PolicyDoc → InstallParams`) is Rust-only, so the policy is
compiled by the `perch-plan` CLI (perch repo) and installed as the account's
Default-rule policy at construction. `scripts/deploy-and-prove.ts` does the whole
thing (compile → deploy → prove allow+deny) and is the source of truth for the
addresses above. `src/perchOnchain.ts` holds the invoke flow used by Act 5.

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
