//! M1 Task 8 (FINAL M1 task): GO/NO-GO gate for the *whole*
//! `initiate_recovery` transaction's real, metered on-chain CPU-instruction
//! cost -- not just `verify_proof` in isolation (that was M0's
//! `crates/zk-bench/tests/budget.rs`, ~159M CPU insns, gated at 250M).
//!
//! `initiate_recovery` runs `verify_proof` PLUS: the pending/nullifier
//! existence checks, `is_known_root` root-ring scan, nonce check+bump,
//! timelock checks, rate-limit prune/push, the `compute_auth_hash`
//! Poseidon2 recompute (`P2_15` + splits + sha256), the nullifier reservation
//! write, the pending-record write, and the `RecoveryInitiated` event
//! emit. M0 explicitly deferred measuring that whole flow to M1 (see
//! `budget.rs`'s module docs: "Full `initiate_recovery` measurement
//! deferred to M1 (live testnet simulate)") -- this test is that
//! measurement.
//!
//! ## Why this lives in `crates/integration-tests/tests/it/`, not
//! `crates/zk-bench/`
//!
//! `crates/zk-bench` deliberately has zero non-`soroban-sdk` dependencies
//! (see its `Cargo.toml`) so the M0 `verify_proof`-only gate stays a
//! minimal, fast, single-purpose crate. Measuring the *full*
//! `initiate_recovery` flow needs the M1 lifecycle fixture (the pinned
//! account/controller addresses + real `bb prove` proof bound to them,
//! `nido_integration_tests::zk_fixture`) and the `nido-zk-recovery` Wasm
//! contract -- both already wired up as this crate's dev-dependencies and
//! reused by `zk_recovery_lifecycle.rs`/`zk_recovery_completion.rs`. Adding
//! that whole dependency graph to `zk-bench` just to duplicate fixture
//! plumbing that already exists here would be pure churn for no isolation
//! benefit; this crate is where "the fixture harness + both wasms are
//! reachable" (per the task brief), so the gate lives here instead.
//!
//! ## Honesty bar: real Wasm, real metering, one real call
//!
//! Unlike `zk_recovery_lifecycle.rs` (which registers `ZkRecovery` as a
//! **native** Rust contract type via `env.register_at(&addr, ZkRecovery,
//! ..)`, appropriate for its purpose -- exercising business logic, not
//! measuring cost), this test registers the REAL COMPILED
//! `nido_zk_recovery.wasm` BYTES at `CONTROLLER` (`env.register_at(&addr,
//! ZK_RECOVERY_WASM, ..)`), so `initiate_recovery` runs through the metered
//! Wasm VM/host-function path for BOTH the controller contract itself and
//! its cross-call into the verifier, not a host-native Rust shortcut for
//! either -- the on-chain-equivalent path, exactly as `budget.rs` registers
//! `nido_zk_verifier.wasm`.
//!
//! This deliberately does NOT use `soroban_sdk::contractimport!` for the
//! recovery contract (unlike the verifier below, and unlike
//! `budget.rs`'s own verifier import): `contractimport!` regenerates a
//! mirror `Client` from the Wasm's embedded spec, and the generated
//! per-method "Args" helper types derive `Debug + Eq + Ord` in bulk across
//! every exported function -- including `Policy::enforce(env, context:
//! Context, ..)` (M1 Task 7's OZ `Policy` impl), whose `Context` parameter
//! (`soroban_sdk::auth::Context`) only derives `Clone` upstream. That
//! combination fails to compile (`Context` doesn't implement
//! `Debug`/`Eq`/`Ord`) -- a `contractimport!` limitation for any
//! Policy-implementing contract, not specific to this crate. Registering
//! the raw Wasm bytes directly and calling through the crate's OWN
//! `#[contractimpl]`-generated `ZkRecoveryClient`
//! (`nido_zk_recovery::pool::ZkRecoveryClient`, already used natively by
//! the sibling lifecycle/completion tests) sidesteps this entirely: that
//! `Client` type only performs typed `invoke_contract` calls against
//! whatever is registered at the target address -- it does not care, and
//! cannot tell, whether that address holds a native contract or a
//! registered Wasm module. Since `ZK_RECOVERY_WASM` (not the native
//! `ZkRecovery` struct) is what gets registered at `CONTROLLER` below, every
//! call through this `ZkRecoveryClient` still runs through the real,
//! metered Wasm VM -- the honesty property this test exists to guarantee.
//!
//! Build the contract Wasm first (not run automatically by `cargo test`):
//! ```sh
//! SOROBAN_SDK_BUILD_SYSTEM_SUPPORTS_SPEC_SHAKING_V2=1 \
//!     cargo build -p nido-zk-recovery --target wasm32v1-none --profile contract
//! ```
//! (or `just build-contracts`, which builds every contract crate the same
//! way). `just bench-zk-initiate` does this for you.

use nido_integration_tests::zk_fixture::{self, LifecycleFixture};
use nido_zk_recovery::hash::leaf_inner;
use nido_zk_recovery::pool::ZkRecoveryClient;
use soroban_sdk::address_payload::AddressPayload;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Bytes, BytesN, Env};

mod zk_verifier_contract {
    // Path is relative to CARGO_MANIFEST_DIR (crates/integration-tests/).
    // The verifier's interface (just `verify_proof`) has no `Context`-typed
    // arguments, so `contractimport!` works fine here -- see this file's
    // module docs for why the recovery contract below is imported
    // differently.
    soroban_sdk::contractimport!(
        file = "../../target/wasm32v1-none/contract/nido_zk_verifier.wasm"
    );
}

/// The REAL compiled `nido-zk-recovery` contract Wasm bytes -- registered
/// (below) as Wasm at `CONTROLLER`, not the native `ZkRecovery` struct, so
/// `initiate_recovery`'s own instructions are metered through the Wasm VM,
/// matching what the on-chain network actually runs. Calls against the
/// registered contract go through `nido_zk_recovery::pool::ZkRecoveryClient`
/// (see module docs for why not `contractimport!`).
const ZK_RECOVERY_WASM: &[u8] =
    include_bytes!("../../../../target/wasm32v1-none/contract/nido_zk_recovery.wasm");

/// GO/NO-GO gate: the full `initiate_recovery` transaction must fit in this
/// many CPU instructions. Real per-transaction CPU limit on Stellar
/// Mainnet/testnet (protocol 27): `tx_max_instructions = 400_000_000`. The
/// 350M gate leaves >=50M headroom under that real cap for whatever the
/// wrapping transaction envelope itself costs beyond this one contract
/// invocation. If the measured number exceeds 350M, that is a genuine
/// gating finding (needs optimization or splitting the flow across
/// transactions) -- NOT a signal to raise this constant.
const MAX_INITIATE_CPU: i64 = 350_000_000;

/// Real Stellar Mainnet per-invocation resource ceiling, mirrored from
/// `NetworkInvocationResourceLimits::mainnet()` -- see `budget.rs` for full
/// provenance of these two constants. Used only to raise the SDK-testutils
/// `Env::default()` live budget (100M CPU / 40MB, an arbitrary testutils
/// convenience default, NOT a network limit) high enough that the real
/// ~159M-CPU `verify_proof` cross-call plus the rest of
/// `initiate_recovery`'s work can complete without the harness aborting
/// mid-call on that unrelated SDK default -- exactly `budget.rs`'s
/// reasoning, applied to the larger whole-transaction flow measured here.
const MAINNET_CPU_INSN_LIMIT: u64 = 600_000_000;
const MAINNET_MEM_BYTES_LIMIT: u64 = 41_943_040;

const DELAY_SECS: u64 = zk_fixture::TIMELOCK_SECS as u64;
const COMPLETION_WINDOW_SECS: u64 = 30 * 24 * 3600;
const MAX_CANCELS: u32 = 2;
const TIMELOCK_FLOOR_SECS: u64 = 7 * 24 * 3600;

fn addr_from(env: &Env, id: &[u8; 32]) -> Address {
    AddressPayload::ContractIdHash(BytesN::from_array(env, id)).to_address(env)
}

fn hex32(s: &str) -> [u8; 32] {
    let s = s.strip_prefix("0x").unwrap_or(s);
    assert_eq!(s.len(), 64, "expected a 32-byte hex string, got {s:?}");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

/// Real full `initiate_recovery` cost gate: registers the REAL compiled
/// `nido_zk_verifier.wasm` + `nido_zk_recovery.wasm` artifacts (not native
/// Rust contracts), deploys `ZkRecovery` at the pinned lifecycle fixture's
/// `CONTROLLER` address, inserts the fixture leaf so the on-chain root
/// matches the proof's `root` public input, then measures the CPU of a
/// SINGLE real `initiate_recovery(...)` call against the real fixture
/// proof.
#[test]
fn initiate_recovery_within_budget() {
    let env = Env::default();

    // Same rationale as budget.rs: replace the SDK-testutils-only 100M/40MB
    // live-budget default with the real mainnet per-invocation ceiling so
    // the full initiate_recovery flow can actually run to completion under
    // real metering, without changing how many instructions it actually
    // takes.
    env.cost_estimate()
        .budget()
        .reset_limits(MAINNET_CPU_INSN_LIMIT, MAINNET_MEM_BYTES_LIMIT);

    let fixture: LifecycleFixture = zk_fixture::lifecycle_fixture(&env);

    // --- Deploy the real verifier Wasm (M0 artifact, unchanged). ---
    let vk_bytes = Bytes::from_slice(&env, include_bytes!("../../fixtures/zk/vk"));
    let verifier_id = env.register(
        zk_verifier_contract::WASM,
        (Address::generate(&env), vk_bytes),
    );

    // --- Deploy the real ZkRecovery controller Wasm, pinned at CONTROLLER
    // (auth_hash's ctrl_hi/lo binds to this exact address; see
    // zk_fixture.rs). Registered as WASM, not native -- the whole point of
    // this test. ---
    let controller_addr = addr_from(&env, &fixture.controller);
    let factory = Address::generate(&env);
    let network_passphrase = Bytes::from_slice(&env, fixture.network_passphrase.as_bytes());
    // Unused by the initiate_recovery path measured here (only
    // policy.rs::enforce / completion reads config.webauthn_verifier) --
    // still required by the constructor signature.
    let webauthn_verifier = Address::generate(&env);

    let contract_id = env.register_at(
        &controller_addr,
        ZK_RECOVERY_WASM,
        (
            factory,
            verifier_id,
            DELAY_SECS,
            COMPLETION_WINDOW_SECS,
            MAX_CANCELS,
            TIMELOCK_FLOOR_SECS,
            network_passphrase,
            webauthn_verifier,
            Address::generate(&env), // upgrade admin (unused by this file's coverage)
        ),
    );
    let client = ZkRecoveryClient::new(&env, &contract_id);

    // --- Insert the fixture leaf; cross-check the on-chain root against
    // the circuit's independently-computed root (same cross-check as
    // zk_recovery_lifecycle.rs). This happens BEFORE the measured call, so
    // its cost does not pollute the measurement. ---
    let account = addr_from(&env, &fixture.account);
    let secret = BytesN::from_array(&env, &hex32(fixture.secret_hex));
    // `leaf_inner` (Poseidon2(DOM_LEAF, secret) -- a pure host-hash helper,
    // not contract logic) computes the unwrapped commitment the same way
    // `zk_recovery_lifecycle.rs::insert_fixture_leaf` does. Using the
    // `nido-zk-recovery` crate here (already a dev-dependency of this
    // crate) only computes an input value on the test-code side; it does
    // NOT affect what gets measured below -- `insert_for` itself still runs
    // entirely through the real registered Wasm's `wrap_leaf`.
    let commitment = leaf_inner(&env, &secret);

    env.mock_all_auths();
    client.insert_for(&account, &commitment);

    let root = client.current_root();
    assert_eq!(
        root.to_array(),
        fixture.root,
        "on-chain frontier root after inserting the fixture leaf must equal \
         the Noir circuit's independently-computed root"
    );

    // --- The measured call: a SINGLE real initiate_recovery, real proof. ---
    let new_pubkey = BytesN::from_array(&env, &fixture.new_pubkey);
    let root_arg = BytesN::from_array(&env, &fixture.root);
    let nullifier = BytesN::from_array(&env, &fixture.nullifier);
    let proof = Bytes::from_slice(&env, &fixture.proof);

    let now = env.ledger().timestamp();
    let executable_after = client.initiate_recovery(
        &account,
        &new_pubkey,
        &fixture.nonce,
        &fixture.timelock_secs,
        &root_arg,
        &nullifier,
        &proof,
    );

    // Capture the measured cost IMMEDIATELY -- `cost_estimate().resources()`
    // reflects only the LAST top-level invocation, so any further client
    // call before this line would silently measure the wrong thing.
    let cpu = env.cost_estimate().resources().instructions;
    println!("initiate_recovery cpu_instructions = {cpu}");

    // Correctness sanity (not the point of this test, but a real call that
    // silently no-op'd or errored would make the CPU number meaningless).
    assert_eq!(
        executable_after,
        now + DELAY_SECS,
        "initiate_recovery must return now + config.delay_secs -- if this \
         fails, the CPU number above does not correspond to a real \
         successful initiate_recovery"
    );

    assert!(
        cpu <= MAX_INITIATE_CPU,
        "initiate_recovery {cpu} > gate {MAX_INITIATE_CPU} (real tx_max_instructions cap: \
         400,000,000)"
    );
}
