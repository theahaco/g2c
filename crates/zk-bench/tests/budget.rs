//! GO/NO-GO gate for the ZK-recovery design: measures the *real*,
//! metered on-chain CPU-instruction cost of `verify_proof` against the
//! depth-24 recovery circuit's actual proof artifacts (not a toy circuit),
//! and asserts it stays under the 250M gate, leaving ≥150M headroom within
//! the real per-transaction CPU limit (400M, protocol 27) for the rest of
//! the `initiate_recovery` transaction (auth checks, storage writes, etc.).
//!
//! Deliberately does NOT call `env.cost_estimate().budget().reset_unlimited()`
//! — that would erase the very thing this test exists to measure. The
//! verifier is registered from a real compiled Wasm module
//! (`contractimport!`), not a native Rust test-contract, so `verify_proof`
//! runs through the metered Wasm VM/host-function path, not host-native
//! code — this is the real on-chain cost, not a Rust-native underestimate.
//!
//! ## Why the CPU limit is raised to 600M before the call
//!
//! `Env::default()` does *not* run with the real chain's per-invocation
//! resource ceiling. Its live `Budget` (the object that actually aborts
//! execution mid-call with `Error(Budget, ExceededLimit)` once exceeded)
//! defaults to `DEFAULT_CPU_INSN_LIMIT = 100_000_000` /
//! `DEFAULT_MEM_BYTES_LIMIT = 40MB`
//! (soroban-env-host-26.1.3/src/budget/limits.rs) — an arbitrary SDK
//! testutils convenience default with no correspondence to a real network.
//! Separately, `Env::default()` also calls
//! `set_invocation_resource_limits(InvocationResourceLimits::mainnet())`
//! (600M instructions / 40MB), but that is a *different*, softer,
//! post-invocation check (surfaced via `cost_estimate().enforce_resource_limits`),
//! not the live budget that gates execution as it runs.
//!
//! Measured `verify_proof` cost (~159M CPU insns, see task-4-report.md) is
//! above the 100M SDK-testutils default, so under `Env::default()` as-is
//! the call aborts mid-verification (inside a `bn254_g1_add` host call)
//! before completing — we can't read a real number at all, let alone
//! compare it to our gate. To actually observe the true total, we raise the
//! *live* budget's CPU/mem limits high enough that the call completes, via
//! `budget().reset_limits(...)` — replacing the arbitrary 100M SDK default
//! with a headroom value that exceeds the measured cost, not with `u64::MAX`.
//! This does not change how many instructions the computation actually takes;
//! it only stops the harness from aborting early on an SDK-internal default
//! that has nothing to do with the real network, so the true total consumed
//! can be measured and then checked against our project gate below. The real
//! per-transaction ceiling is `tx_max_instructions = 400,000,000` (live
//! testnet/mainnet config, protocol 27); the 250M gate below leaves headroom
//! under it for the rest of the `initiate_recovery` transaction.
//!
//! If `verify_proof`'s real cost were ever to exceed 600M, that would be an
//! even harder failure (can't run in one invocation on mainnet at all,
//! full stop) — this codepath would then need `reset_limits` raised
//! further purely to get a diagnostic number for the report, and the
//! assertion below would still fail loudly against `MAX_VERIFY_CPU`.

use soroban_sdk::{testutils::Address as _, Address, Bytes, Env};

mod v {
    // Path is relative to CARGO_MANIFEST_DIR (crates/zk-bench/). The wasm is
    // produced by `just build-contracts` (stellar-scaffold), which lands
    // optimized contract wasms under target/wasm32v1-none/contract/, not
    // target/wasm32v1-none/release/ (release/ is stellar-scaffold's
    // intermediate, pre-optimize build dir for non-contract crates).
    soroban_sdk::contractimport!(
        file = "../../target/wasm32v1-none/contract/nido_zk_verifier.wasm"
    );
}

/// GO/NO-GO gate: `verify_proof` must fit in this many CPU instructions.
/// Real per-transaction CPU limit on Stellar Mainnet (protocol 27):
/// `tx_max_instructions = 400_000_000`. `verify_proof` runs inside the
/// `initiate_recovery` transaction alongside auth checks, root-ring check
/// (128 entries), Poseidon2 host hashes, and storage writes. Measured
/// `verify_proof` cost: ~159M CPU instructions. The 250M gate leaves
/// ≥150M headroom for the rest of `initiate_recovery` plus safety margin.
/// Full `initiate_recovery` measurement deferred to M1 (live testnet simulate).
const MAX_VERIFY_CPU: i64 = 250_000_000;

// Real Stellar Mainnet per-invocation resource ceiling, mirrored from
// `NetworkInvocationResourceLimits::mainnet()`
// (soroban-sdk-26.0.1/src/testutils/cost_estimate.rs). The concrete
// `InvocationResourceLimits` type that method returns isn't reachable
// through soroban-sdk's public API (it lives behind a private `mod env`),
// so the two fields we need are mirrored here as plain constants instead.
const MAINNET_CPU_INSN_LIMIT: u64 = 600_000_000;
const MAINNET_MEM_BYTES_LIMIT: u64 = 41_943_040;

#[test]
fn verify_proof_within_budget() {
    let env = Env::default();

    // Replace the SDK-testutils-only 100M/40MB live-budget default with
    // the real mainnet per-invocation ceiling so verify_proof can actually
    // run to completion under real metering (see module docs above). This
    // is the real network limit, not an unlimited/dodge value.
    env.cost_estimate()
        .budget()
        .reset_limits(MAINNET_CPU_INSN_LIMIT, MAINNET_MEM_BYTES_LIMIT);

    let vk = Bytes::from_slice(
        &env,
        include_bytes!("../../integration-tests/fixtures/zk/vk"),
    );
    let proof = Bytes::from_slice(
        &env,
        include_bytes!("../../integration-tests/fixtures/zk/proof"),
    );
    let pubs = Bytes::from_slice(
        &env,
        include_bytes!("../../integration-tests/fixtures/zk/public_inputs"),
    );

    // Register the real compiled Wasm module (not a native test-contract),
    // so verify_proof runs through the metered Wasm VM / host-function
    // path -- this measures the real on-chain cost.
    let id = env.register(v::WASM, (Address::generate(&env), vk));
    let client = v::Client::new(&env, &id);

    client.verify_proof(&pubs, &proof);

    // `cost_estimate().resources()` reports the resources metered during
    // the *last top-level contract invocation* only (reset before every
    // top-level call -- see soroban-sdk-26.0.1/src/testutils/cost_estimate.rs),
    // so this reflects exactly the one `verify_proof` call above and
    // nothing from `env.register()` (the constructor call) or fixture
    // setup.
    let cpu = env.cost_estimate().resources().instructions;
    println!("verify_proof cpu_instructions = {cpu}");

    assert!(
        cpu <= MAX_VERIFY_CPU,
        "verify_proof {cpu} > gate {MAX_VERIFY_CPU}"
    );
}
