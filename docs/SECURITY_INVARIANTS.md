# Security Invariants

The properties that must always hold, each with the test/bench evidence that
guards it. This is the checklist an auditor uses to confirm the system behaves as
claimed, and the regression net the team must keep green. IDs are stable
references (used from [THREAT_MODEL.md](./THREAT_MODEL.md)).

Test paths are under `crates/integration-tests/tests/it/` unless noted. Run the
whole set with `just test`; cost gates with `just bench-zk`, `just bench-zk-initiate`,
`just bench-zk-guard`.

## Factory & deployment

- **F1 — Deterministic address.** `create_account`/`create_account_v2` deploy at the
  address `get_c_address(salt)` predicts; the recovery-controller argument does not
  affect the address. Evidence: factory unit tests (`contracts/factory/src/contract.rs`).
- **F1a — Salt anti-collision.** A salt can mint only ONE account: a second
  `create_account_v2` with the same salt targets the already-occupied deterministic address
  and the host rejects the re-deploy (atomically — no second genesis leaf), so an existing
  account cannot be hijacked/reset by replaying its salt. Evidence:
  `create_account_v2_twice_with_same_salt_is_rejected`.
- **F2 — Atomic deploy + genesis insert.** An account is never created without its
  genesis Merkle leaf, nor a leaf without its account; any insert failure reverts the
  whole tx. Evidence: `create_account_reverts_atomically_when_pool_factory_mismatched`.
- **F3 — Enrollment indistinguishability.** Real vs. deterministic-dummy commitments are
  indistinguishable on-chain, keeping the anonymity set uniform. Evidence:
  `dummy_and_real_enrollment_are_indistinguishable_on_chain`,
  `create_account_and_create_account_v2_are_uniform_except_commitment`.
- **F4 — Cross-crate param shape parity.** `ZkRecoveryInstallParams` (smart-account copy)
  round-trips against the real controller struct. Evidence: `drift.rs`.
- **F5 — Registry pinning (pin bypass).** Once the admin pins the expected addresses
  (`set_registry_pins(verifier, zk_recovery)`), the factory resolves `verifier`/`zk-recovery`
  DIRECTLY from the pin and never consults the registry — on EVERY
  `create_account`/`create_account_v2`. This takes the registry off the runtime critical path
  for pinned names: a compromised, repointed, broken, or unreachable registry can neither
  route new accounts to attacker contracts NOR block their creation. Unpinned (the default)
  preserves the pre-B2 behavior (resolve from the registry, trust the result). The
  `set_recovery_pool` override is checked before the `zk-recovery` pin and is a separate,
  explicit admin path. Evidence: `create_account_v2_uses_pins_when_registry_repointed`
  (a registry repointed to garbage is ignored), `pinned_resolve_never_consults_registry` (a
  registry that panics on any lookup is never called), `create_account_v2_succeeds_when_pins_match_registry`,
  `set_registry_pins_requires_admin_auth` (`contracts/factory/src/contract.rs`). The mainnet
  registry is a Nido-owned `stellar-registry` instance (blocker A3, deploy-time); the pins
  make the factory safe against a wrong/hostile registry regardless.

## Smart account & guard

- **S1 — Auth on every mutation.** `add/remove_context_rule`, `remove_signer`,
  `remove_policy`, `update_context_rule_valid_until`, `enroll_zk_recovery`, and `execute`
  all require the account's own auth. Evidence: `smart_account_auth.rs`,
  `smart_account_setup.rs`.
- **S2 — Recovery guard blocks eviction while pending.** With a live pending recovery,
  signer/rule/policy-mutating ops are blocked (`RecoveryPendingBlocked`) via the
  controller `has_pending` cross-call. Evidence: `zk_recovery_guard.rs`, smart-account
  unit tests. The cross-call is **fail-secure**: any controller error traps and blocks
  the mutation (documented at `contract.rs::has_live_pending`).
- **S3 — Recovery rule protection + announce-then-execute.** The recovery rule cannot be
  silently removed/modified (`RecoveryRuleProtected`); removal requires the
  announce-then-execute delay (`RECOVERY_REMOVAL_DELAY_SECS`). Evidence: smart-account
  unit tests.
- **S4 — No double-enroll.** `enroll_zk_recovery` panics `RecoveryAlreadyEnrolled` if a
  rule is already installed. Evidence: `zk_recovery_migration.rs`.

## ZK recovery state machine

- **R1 — Proof binds all mutation parameters.** `initiate/cancel/burn` recompute
  `auth_hash` from the call's own `(action, account, network_passphrase, controller,
  new_pubkey, nonce, timelock)` and verify the proof against it — a caller cannot swap any
  field without invalidating the proof. Evidence: tampered-field tests in
  `zk_recovery_lifecycle.rs`.
- **R2 — Nullifier no double-spend.** A nullifier moves Reserved→(released|Spent); Spent is
  permanent; check-then-set is atomic within one invocation. Evidence:
  `zk_recovery_lifecycle.rs::real_revoke_proof_burns_nullifier_and_blocks_later_initiate`,
  `zk_recovery_completion.rs`.
- **R3 — Monotonic nonce replay protection.** Every proof requires `nonce == stored+1`;
  nonce is bound into `auth_hash`. Evidence: `zk_recovery_lifecycle.rs`.
- **R4 — Timelock cannot be bypassed.** `initiate` requires `timelock_secs == cfg.delay_secs`
  exactly; completion blocked until `now >= executable_after`. Evidence:
  `zk_recovery_lifecycle.rs`, `zk_recovery_completion.rs`. The lifecycle + e2e suites run at
  the **mainnet** params (14d/7d/30d); only the LIVE testnet pool is still deployed with
  testnet params (blocker A1).
- **R5 — Cross-network / cross-controller replay prevented.** `network_passphrase` and
  controller address are bound into `auth_hash`. Evidence:
  `zk_recovery_lifecycle.rs::wrong_network_passphrase_proof_is_rejected` (a testnet-passphrase
  proof rejected by a mainnet-passphrase pool) + the controller-address bind pinned by
  `auth_hash_matches_fixture` (`hash.rs`).
- **R6 — Rate limit + cancel bounds.** ≤3 initiations / rolling 90d; cancel cap (2 mainnet)
  + 24h cooldown bound grief. Evidence: `zk_recovery_lifecycle.rs`.
- **R7 — Passkey alone cannot grief recovery.** `cancel_recovery` and `burn_nullifier` require
  BOTH account auth AND a fresh `action=2/3` proof of secret knowledge. Evidence:
  `zk_recovery_neuter.rs`, `zk_recovery_lifecycle.rs`.
- **R8 — Completion gated to exactly the pending key rotation.** `Policy::enforce` inspects
  the context and rejects anything other than the pending `add_context_rule`/signer set (OZ
  only validates the self-target, not fn/args). Evidence: `zk_recovery_completion.rs`,
  `zk_completion_spike.rs`.
- **R9 — Stolen-passkey neuter closed.** `AlreadyInstalled` guard + unconditional uninstall
  refusal prevent repointing/removing the recovery policy to disable recovery. Evidence:
  `zk_recovery_neuter.rs`.
- **R10 — Leaf is account-bound on-chain.** The stored leaf is `wrap_leaf(account, secret)`
  computed on-chain at insert (after auth), so a client cannot pre-wrap a leaf binding a
  victim account. Evidence: pool tests (`contracts/zk-recovery/src/pool.rs`),
  `zk_recovery_lifecycle.rs`.

## Circuit & cryptography

- **C1 — Circuit fully constrained.** All three public inputs (`root`, `nullifier`,
  `auth_hash`) are outputs of in-circuit Poseidon2 hashes; no under-constrained witness
  signals. Evidence: `circuits/zk_recovery/src/tests.nr`; build script asserts public-input
  count == 3.
- **C2 — Poseidon2 host/circuit parity.** On-chain Poseidon2 (arities 2/4/15) matches the
  circuit at every arity and domain constant used. Evidence: `zk_vectors.rs`, circuit
  `vector_parity_*` tests; identical domain constants in `contracts/zk-recovery/src/hash.rs`
  and `circuits/zk_recovery/src/main.nr`.
- **C3 — Merkle membership tight.** Depth-24 membership uses tight bit-range constraints and
  DOM_BIND-tagged leaves (no leaf/interior collision). Evidence: circuit tests; Merkle
  frontier tests in `contracts/zk-recovery/src/merkle.rs`.
- **C4 — Commitment canonicalization.** Non-canonical (≥ field order) leaves are rejected
  on-chain. Evidence: `pool.rs` canonicalization tests.
- **C5 — Transparent setup.** UltraHonk with keccak Fiat-Shamir (`--verifier_target
  evm-no-zk`) has no trusted setup / no toxic waste. Evidence: documented in
  `circuits/zk_recovery/scripts/gen_artifacts.sh` + SUPPLY_CHAIN.md.

## Proof verifier

- **V1 — VK immutable + bound.** The VK is set once at construction and hashed into the
  Fiat-Shamir transcript, so it cannot be swapped without invalidating all proofs. Evidence:
  `contract_verifier.rs`; `contracts/vendor/.../transcript.rs`.
- **V2 — All public inputs checked; exact size.** Verification binds and requires the exact
  `root||nullifier||auth_hash` (96 bytes). Evidence: `contract_verifier.rs`;
  `verifier_smoke.rs::verify_with_tampered_public_inputs_fails`.
- **V3 — Malformed proofs fail closed, with a structured error.** An empty or truncated proof
  never yields a pending recovery and writes no pending/nullifier state (the rejection is
  atomic). The zk-verifier boundary (`contracts/zk-verifier/src/lib.rs::verify_proof`)
  pre-checks the proof length (`expected_proof_fields(log_n) * 32`, a pure function of the
  immutable VK) and returns a typed `ProofParseError` *before* the vendored parser's length
  `assert_eq!` can panic — so a bad-length proof is rejected legibly, not via an opaque host
  trap. Curve-point validity for a correct-length proof (on-curve, subgroup, canonical
  coordinates) is delegated to the Soroban host BN254 functions (`env.crypto().bn254()`
  msm/pairing in `contracts/vendor/.../ec.rs::SorobanEc`), which reject invalid points; the
  controller's `try_invoke_contract` catches any such host rejection and fails closed.
  Evidence: `verifier_smoke.rs::verify_with_truncated_proof_returns_parse_error`,
  `zk_recovery_lifecycle.rs::malformed_proof_never_initiates_recovery`.
- **V4 — Cross-network replay rejected.** A proof bound to one network's passphrase (via
  `sha256(passphrase)` folded into `auth_hash`) does not verify against a pool configured for a
  different network — a testnet proof cannot be replayed on mainnet. Evidence:
  `zk_recovery_lifecycle.rs::wrong_network_passphrase_proof_is_rejected`.

### Vendored verifier coverage

The vendored UltraHonk crate (`contracts/vendor/ultrahonk-soroban-verifier`) is excluded from
`cargo test --workspace` because its upstream suite reads fixtures (`circuits/*/target/`)
generated by the nargo+bb toolchain, which we don't vendor. This is **documented indirect
coverage, not a gap**: the vendored crate's own known-answer test is the `simple_circuit` proof,
and nido runs those byte-identical `vk`/`proof`/`public_inputs` fixtures through the same
`UltraHonkVerifier::new(vk).verify(..)` code path at the contract boundary
(`contracts/zk-verifier/tests/verifier_smoke.rs`), plus 14 real-`bb prove` `zk_recovery_*`
integration tests against the production circuit. Vendoring the upstream `fib_chain` blobs would
add a toolchain dependency for ~zero marginal coverage of the same code; editing the vendored
crate to be self-contained would trip the vendor-drift guard (`scripts/check-vendor-drift.sh`).

## Policies

- **P1 — Spending-limit rolling window.** Meters SAC `transfer` over a rolling window; the
  over-limit path is rejected. Evidence: `spending_limit_policy.rs::over_limit_rejected`. The
  `i128` window arithmetic is the OZ `policies::spending_limit` library's (saturating), not
  nido code, and is exercised by the over-limit gate; a dedicated `i128::MAX` overflow edge
  test would test third-party arithmetic and is intentionally out of scope.
- **P2 — Multisig threshold + rotation.** Threshold enforced; rotation threshold policy.
  Evidence: `multisig_recovery.rs`, `default_rule_threshold.rs`.
- **P3 — Scoped session keys.** Context rules restrict contract/fn/limit/time window.
  Evidence: `scoped_session_key.rs`.

## Cost / DoS budgets (Stellar mainnet `tx_max_instructions = 400M`)

- **B1 — `verify_proof` ≤ 250M CPU** (measured ~159M). Gate: `just bench-zk`
  (`crates/zk-bench/tests/budget.rs`).
- **B2 — full `initiate_recovery` ≤ 350M CPU** (measured ~168M). Gate: `just bench-zk-initiate`
  (`initiate_cost.rs`).
- **B3 — guard cross-call ≤ 10M CPU** (measured ~1.17M). Gate: `just bench-zk-guard`
  (`guard_cost.rs`).

## Storage / liveness

- **T1 — Recovery state survives the active window.** The `Pending` + `Nullifier` + `Nonce`
  + `RateWindow` entries `initiate_recovery` writes must remain live across the full 14d
  timelock + 30d completion window (~44d) so a legitimate recovery can complete at the last
  moment. Every recovery write extends the entry's TTL to the network max
  (`extend_ttl(max, max)` in `controller.rs`/`merkle.rs`/`policy.rs`), and 44 days of ledgers
  (~760k at ~5s/ledger) sits far under `max_ttl` (~6.31M in-env), so nothing archives
  mid-window. Evidence: `zk_recovery_completion.rs::recovery_state_survives_full_active_window`
  — asserts the window-in-ledgers is far below the env's real `max_ttl`, advances BOTH the
  ledger timestamp and sequence across the full window, asserts all four entries are still
  readable, and drives a real completion at the end of the window. Scope note: the soroban-sdk
  test env does not model archival eviction, so the test validates the *survival premise*
  (window ≪ `max_ttl` + extend-to-max on every write); fail-closed archival itself is a Soroban
  **protocol** guarantee — an archived persistent entry is inaccessible (a read errors and
  reverts), never silently readable as `None` — which is exactly why staying under `max_ttl`
  matters.
