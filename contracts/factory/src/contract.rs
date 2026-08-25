use admin_sep::{Administratable, Upgradable};
use soroban_sdk::{
    contract, contractimpl, deploy::DeployerWithAddress, Address, Bytes, BytesN, Env, String,
    Symbol, U256,
};
use soroban_sdk_tools::{contractstorage, InstanceItem};
use stellar_accounts::smart_account::Signer;

// The factory defines no custom error type. Under registry pinning (plan B2)
// a pinned name is resolved DIRECTLY from the pin without consulting the
// registry (`Self::resolve`), so there is no "registry disagrees with the
// pin" condition to report -- the pin is authoritative by construction. The
// factory's remaining failure modes (unresolvable registry name for an
// UNPINNED name, tree full, non-canonical commitment, ...) originate in the
// registry or the pool cross-call and surface as those contracts' own
// traps/errors, which is what an operator debugging a failed `create_account`
// wants to see.

mod smart_account {
    //! Embeds the smart-account contract wasm so the factory no longer
    //! hardcodes its wasm hash. The mechanism:
    //!
    //!  1. `build.rs` stages the `just build-contracts` output
    //!     (`nido_smart_account.wasm`) and emits `STELLAR_ACCOUNT_WASM` pointing
    //!     at it.
    //!  2. `include_bytes!(env!("STELLAR_ACCOUNT_WASM"))` embeds those exact
    //!     bytes into the factory wasm as `WASM` below.
    //!  3. At runtime the factory computes `sha256(WASM)` (see
    //!     `super::Contract::account_wasm_hash`) and passes that hash to
    //!     `deploy_v2`. So the deploy hash tracks the embedded bytes
    //!     automatically — no more hand-recomputed `ACCOUNT_HASH`.
    //!
    //! For `deploy_v2` to resolve, those same bytes must already be installed
    //! on-chain. The deploy script's smart-account publish step
    //! (`scripts/deploy-policy-builder-v1.sh`) installs the locally-built wasm
    //! and asserts its sha256 matches what the factory embeds, so the
    //! embed==installed invariant holds.
    //!
    //! NOTE: an earlier approach used
    //! `stellar_registry::import_contract_client!("unverified/smart-account@0.1.0")`,
    //! which expands to `soroban_sdk::contractimport!` and also generates a
    //! typed contract `Client`. The smart-account's
    //! `__check_auth(..., auth_contexts: Vec<Context>)` signature makes the
    //! generator emit a bare `Context` type that it neither defines nor imports
    //! (the same soroban-spec gap `scripts/fix-bindings.sh` patches for the TS
    //! bindings), so the generated client fails to compile inside the
    //! macro-created module — which we cannot edit. We therefore embed only the
    //! wasm bytes (no client), avoiding the gap while still eliminating the
    //! hardcoded hash. The registry `ACCOUNT_VERSION` is now just a label under
    //! which the bytes are published; nothing enforces it equals the embedded
    //! wasm — the sha256 comparison in the deploy script does that.
    //!
    //! `STELLAR_ACCOUNT_WASM` is an absolute path emitted by `build.rs`; the
    //! built-in `include_bytes!` macro expands `env!` eagerly.

    /// Raw smart-account contract wasm, embedded at build time. `sha256` of
    /// these bytes is the hash the factory hands to `deploy_v2`.
    pub const WASM: &[u8] = include_bytes!(env!("STELLAR_ACCOUNT_WASM"));
}

/// Stellar Registry "unverified" testnet contract — the one that holds
/// bare-name → contract-id mappings. The verified registry's address is
/// `CAMLHKQHNZO2IOIBFUF5BGZ2V62BMS5QCWFFGRCB4NOB3G5OMDA7SGZN`; it doesn't
/// dispatch prefixed names natively (the CLI does that client-side). Calling
/// `fetch_contract_id("verifier")` directly on the unverified registry
/// returns the registered contract id; that's what `resolve` below relies on.
///
/// For mainnet or an alternate registry build, change this constant and
/// redeploy the factory.
const REGISTRY: &str = "CDBL7MNO7UI5OAAIC67UIWKQ4P3S6RVQSFCQXUHUW6TOFCXSYRPNHY4S";

mod registry {
    use soroban_sdk::*;
    #[contractclient(name = "RegistryClient")]
    pub trait RegistryInterface {
        fn fetch_contract_id(name: String) -> Address;
    }
}

/// Minimal cross-call stub for `nido-zk-recovery`'s pool `insert` (the
/// GENESIS entry point, `contracts/zk-recovery/src/pool.rs::insert`).
///
/// This crate deliberately does NOT depend on `nido-zk-recovery` as a normal
/// Cargo dependency: both are `#[contract]` crates, and linking one into the
/// other's cdylib would collide their identically-named `#[no_mangle]`
/// exports (`__constructor`, `install`, `enforce`, …) at wasm link time.
/// `#[contractclient]` on a local trait, by contrast, generates ONLY a
/// caller stub (a struct wrapping `invoke_contract` calls) — no exported
/// symbols — so it does not collide. Mirrors the exact pattern
/// `contracts/smart-account/src/contract.rs`'s `RecoveryControllerClient`
/// uses for the same reason (M2 Task 4).
mod zk_recovery {
    use soroban_sdk::*;
    #[contractclient(name = "ZkRecoveryClient")]
    pub trait ZkRecoveryInterface {
        fn insert(e: Env, account: Address, commitment: BytesN<32>) -> u32;
    }
}

#[contractstorage]
pub struct Config {
    account: InstanceItem<BytesN<32>>,
    passkey: InstanceItem<Address>,
    // The upgrade `admin` is no longer stored here: admin/set_admin/upgrade
    // come from the shared `admin-sep` crate, which owns its own `ADMIN`
    // storage key (see the `Administratable`/`Upgradable` impls below).
    /// Admin-settable override for the recovery-pool/controller resolution
    /// (see `Contract::set_recovery_pool`/`Contract::resolve_recovery`).
    /// `None` (the default, unset state) means "no override" -- production
    /// factories never set this, so `resolve_recovery` falls through to
    /// resolving `"zk-recovery"` from the registry exactly as before this
    /// field existed.
    recovery_pool: InstanceItem<Address>,
    /// Admin-pinned address for the `"verifier"` registry name (plan B2).
    /// `None` (default) = unpinned, i.e. resolve from the registry and trust
    /// whatever it returns (the pre-B2 behavior, kept for existing testnet
    /// factories). Once set (via `set_registry_pins`), `resolve("verifier")`
    /// returns this address DIRECTLY and never consults the registry -- so a
    /// repointed, broken, or unreachable registry can neither swap the passkey
    /// verifier under new accounts nor even block their creation. Set at
    /// mainnet cutover, before any account is created.
    pinned_verifier: InstanceItem<Address>,
    /// Admin-pinned address for the `"zk-recovery"` registry name (plan B2).
    /// Same semantics as `pinned_verifier`: `None` = unpinned; once set,
    /// `resolve("zk-recovery")` returns this address directly (registry
    /// bypassed), so the recovery controller installed into every new account
    /// (and handed the genesis `insert`) is fixed to the pin and cannot be
    /// swapped -- or knocked out -- by a registry repoint.
    pinned_zk_recovery: InstanceItem<Address>,
}

#[contract]
pub struct Contract;

// Governance (issue #26): admin/set_admin/upgrade come from the shared
// `admin-sep` crate (`Administratable` + `Upgradable`), replacing the inlined
// boilerplate. The factory is the only contract that was already
// upgrade-capable before this workstream; it now shares the same SEP admin
// surface as the rest of the set. Internal admin-gated entry points
// (`set_recovery_pool`, `set_registry_pins`) call `Self::admin(e)` /
// `Self::require_admin(e)` from these traits. Mainnet intent (plan B1):
// `admin` is a multisig, ideally behind an upgrade timelock.
#[contractimpl(contracttrait)]
impl Administratable for Contract {}

#[contractimpl(contracttrait)]
impl Upgradable for Contract {}

#[contractimpl]
impl Contract {
    // `admin: Address` is not consumed by-ref in the body, but this is a
    // `#[contractimpl]` entry point: the SDK's XDR-based ABI takes owned
    // `Address` by value, so the signature cannot change (precedent:
    // contracts/smart-account/src/contract.rs). `set_admin` on first call (no
    // admin yet) skips the auth check.
    #[allow(clippy::needless_pass_by_value)]
    pub fn __constructor(e: &Env, admin: Address) {
        Self::set_admin(e, admin);
    }

    /// Set (or rotate) an admin-only override for the recovery-pool/
    /// controller address, bypassing the registry's `"zk-recovery"`
    /// resolution (see `resolve_recovery`). Intended for a preview/staging
    /// factory instance that needs to point at an isolated preview pool
    /// without touching the production registry mapping every other factory
    /// instance shares. Requires the current admin's auth -- this is a
    /// powerful knob: it changes which contract becomes every newly-created
    /// account's recovery controller, and which contract receives the
    /// genesis `insert` cross-call in `deploy_and_insert`.
    // `#[contractimpl]` entry point; SDK ABI requires owned `Address`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn set_recovery_pool(e: &Env, pool: Address) {
        Self::admin(e).require_auth();
        Config::set_recovery_pool(e, &pool);
    }

    /// The current recovery-pool override, or `None` if unset. `None` is the
    /// default and production state: with no override, `resolve_recovery`
    /// resolves `"zk-recovery"` from the registry exactly as before this
    /// override existed.
    pub fn recovery_pool(e: &Env) -> Option<Address> {
        Config::get_recovery_pool(e)
    }

    /// Pin the `verifier` and `zk-recovery` addresses (plan B2). After this,
    /// every `resolve("verifier")` / `resolve("zk-recovery")` (i.e. every
    /// `create_account`/`create_account_v2`) returns exactly these addresses
    /// DIRECTLY, without consulting the registry at all -- taking the registry
    /// off the runtime critical path and closing the "compromised/repointed
    /// registry silently routes new accounts to attacker contracts" hole
    /// (`resolve` trusted the registry unconditionally before this). Because
    /// the registry is bypassed, a later repoint cannot reroute NOR block new
    /// accounts; the registry remains authoritative only for unpinned names
    /// and for off-chain discovery. Both are set together because a cutover
    /// pins both at once from `DEPLOYED.md`; call again to re-pin after a
    /// deliberate verifier/controller upgrade. Requires the current admin's
    /// auth. NOTE: the `zk-recovery` pin is superseded by the admin-set
    /// `set_recovery_pool` override, which is checked first (an explicit,
    /// separately-audited admin choice -- see `resolve_recovery`).
    // `#[contractimpl]` entry point; SDK ABI requires owned `Address`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn set_registry_pins(e: &Env, verifier: Address, zk_recovery: Address) {
        Self::admin(e).require_auth();
        let cfg = Config::new(e);
        cfg.pinned_verifier.set(&verifier);
        cfg.pinned_zk_recovery.set(&zk_recovery);
    }

    /// The pinned `verifier` address, or `None` if unpinned. `None` is the
    /// default (pre-B2 / testnet) state: `resolve("verifier")` resolves from
    /// the registry. When `Some`, the registry is bypassed for that name.
    pub fn pinned_verifier(e: &Env) -> Option<Address> {
        Config::get_pinned_verifier(e)
    }

    /// The pinned expected `zk-recovery` address, or `None` if unpinned.
    pub fn pinned_zk_recovery(e: &Env) -> Option<Address> {
        Config::get_pinned_zk_recovery(e)
    }

    /// Deploy an account contract and add its initial passkey signer. Legacy
    /// entry point, kept for existing callers -- routes through the exact
    /// same deploy+genesis-insert path as `create_account_v2`, using a
    /// DETERMINISTIC DUMMY commitment (`dummy_commitment`) instead of a real
    /// one. This is the anonymity-set property (M2 Task 5): every account
    /// this factory creates gets exactly one genesis leaf inserted into the
    /// recovery pool, atomically with its own deployment, whether or not its
    /// owner actually enrolled in ZK recovery -- so an observer of the pool
    /// (or of the factory's transaction shapes) cannot distinguish an
    /// enrolled account from a non-enrolled one.
    // `#[contractimpl]` entry point; SDK ABI requires owned `BytesN<65>`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn create_account(e: &Env, salt: &BytesN<32>, key: BytesN<65>) -> Address {
        let dummy = Self::dummy_commitment(e, salt);
        Self::deploy_and_insert(e, salt, key.to_bytes(), &dummy)
    }

    /// Deploy an account contract, add its initial passkey signer, AND
    /// insert `commitment` as its genesis leaf in the recovery pool --
    /// atomically with the deploy, in the same transaction (M2 Task 5). If
    /// the insert fails (pool unresolvable, tree full, wrong `commitment`,
    /// ...) the whole call reverts, so there is never an account without a
    /// leaf, nor a leaf without an account. Returns the deployed account's
    /// address, which is always `get_c_address(salt)` -- the deterministic
    /// address depends only on the deployer (this factory) and `salt`, never
    /// on the constructor args or the genesis insert added here.
    // `#[contractimpl]` entry point; SDK ABI requires owned `BytesN<65>`/
    // `BytesN<32>`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn create_account_v2(
        e: &Env,
        salt: &BytesN<32>,
        key: BytesN<65>,
        commitment: BytesN<32>,
    ) -> Address {
        Self::deploy_and_insert(e, salt, key.to_bytes(), &commitment)
    }

    pub fn get_c_address(e: &Env, salt: &BytesN<32>) -> Address {
        Self::deployer(e, salt).deployed_address()
    }

    fn deployer(e: &Env, salt: &BytesN<32>) -> DeployerWithAddress {
        e.deployer().with_current_contract(salt.clone())
    }

    /// Builds the `Symbol` cache key for `resolve`'s instance-storage cache.
    /// Registry names may contain `-` (e.g. `"zk-recovery"`), which `Symbol`
    /// rejects (its charset is `[a-zA-Z0-9_]` only, no hyphen) -- this maps
    /// `-` -> `_` for the CACHE KEY ONLY; the registry lookup itself still
    /// uses `name` unchanged (`fetch_contract_id` takes a plain `String`, no
    /// charset restriction), so this changes nothing about which name is
    /// resolved, only what the resulting address is cached under. No `alloc`
    /// needed (this crate is `#![no_std]`): names are short static literals,
    /// comfortably under the 32-byte stack buffer.
    fn cache_key(env: &Env, name: &str) -> Symbol {
        const MAX: usize = 32;
        let bytes = name.as_bytes();
        assert!(bytes.len() <= MAX, "resolve() name too long for cache key");
        let mut buf = [0u8; MAX];
        for (i, &b) in bytes.iter().enumerate() {
            buf[i] = if b == b'-' { b'_' } else { b };
        }
        let s = core::str::from_utf8(&buf[..bytes.len()])
            .unwrap_or_else(|_| panic!("resolve() name must be valid UTF-8"));
        Symbol::new(env, s)
    }

    fn resolve(env: &Env, name: &str) -> Address {
        // Pin bypass (plan B2): once the admin has pinned an address for
        // `name`, the pin is AUTHORITATIVE -- return it directly and never
        // touch the registry. This takes the registry off the runtime critical
        // path for pinned names entirely: a repointed, broken, or unreachable
        // registry can no longer reroute new accounts to an attacker's
        // verifier/controller *nor even block their creation*. Only unpinned
        // names (the pre-B2 default) fall through to the registry lookup below,
        // where there is nothing to disagree with; the registry also remains
        // the source for off-chain discovery (the SDK's `fetch_contract_id`).
        if let Some(pinned) = Self::pinned_for(env, name) {
            return pinned;
        }
        let key = Self::cache_key(env, name);
        if let Some(addr) = env.storage().instance().get::<_, Address>(&key) {
            return addr;
        }
        let client = registry::RegistryClient::new(env, &Address::from_str(env, REGISTRY));
        let addr = client.fetch_contract_id(&String::from_str(env, name));
        env.storage().instance().set(&key, &addr);
        addr
    }

    /// The admin-pinned address for `name`, or `None` if that name is unpinned.
    /// Only `"verifier"` and `"zk-recovery"` are pinnable (the only two names
    /// `resolve` looks up); any other name is always unpinned. A `Some` result
    /// short-circuits `resolve` before the registry is ever consulted.
    fn pinned_for(env: &Env, name: &str) -> Option<Address> {
        match name {
            "verifier" => Config::get_pinned_verifier(env),
            "zk-recovery" => Config::get_pinned_zk_recovery(env),
            _ => None,
        }
    }

    /// Resolves the recovery-pool/controller address for newly-deployed
    /// accounts: the admin-set override (`set_recovery_pool`) if one has
    /// been set, otherwise the registry-resolved `"zk-recovery"` entry --
    /// the default, unchanged production path. Since no factory has ever
    /// called `set_recovery_pool` in production, `Config::get_recovery_pool`
    /// is always `None` there, so this is behaviorally identical to the old
    /// `Self::resolve(e, "zk-recovery")` call it replaces.
    fn resolve_recovery(e: &Env) -> Address {
        if let Some(pool) = Config::get_recovery_pool(e) {
            return pool;
        }
        Self::resolve(e, "zk-recovery")
    }

    /// Deploys the account contract at `get_c_address(salt)`, installing the
    /// resolved recovery controller as its recovery rule. Returns
    /// `(account_address, recovery_controller_address)` so callers can
    /// immediately cross-call the controller's genesis `insert` (M2 Task 5)
    /// without re-resolving "zk-recovery" a second time.
    fn deploy_account_contract(e: &Env, salt: &BytesN<32>, key: Bytes) -> (Address, Address) {
        let verifier_addr = Self::resolve(e, "verifier");
        let signer = Signer::External(verifier_addr, key);
        let signers = soroban_sdk::vec![e, signer];
        let policies: soroban_sdk::Map<soroban_sdk::Address, soroban_sdk::Val> =
            soroban_sdk::Map::new(e);
        // Production deploys always install the M1 zk-recovery controller as
        // the account's recovery rule policy (uniform across the anonymity
        // set) — resolved via `resolve_recovery`, which defaults to the same
        // cached registry lookup as "verifier" unless a preview instance has
        // set an override via `set_recovery_pool`.
        let recovery_controller = Self::resolve_recovery(e);
        let account = Self::deployer(e, salt).deploy_v2(
            Self::account_wasm_hash(e),
            (&signers, &policies, &Some(recovery_controller.clone())),
        );
        (account, recovery_controller)
    }

    /// Shared tail of `create_account`/`create_account_v2` (M2 Task 5):
    /// deploy the account contract, then -- in the SAME transaction --
    /// cross-call the resolved recovery controller's genesis `insert` to
    /// bind `commitment` to the freshly deployed account. `insert` requires
    /// the pool's configured `factory` to authorize; since this factory
    /// contract is the direct caller, that auth is satisfied via "invoker
    /// contract auth" (no signature needed) as long as the pool was
    /// configured with THIS factory's address. If the insert fails for any
    /// reason (wrong factory configured, non-canonical commitment, tree
    /// full, ...) the whole call -- including the just-deployed account --
    /// reverts atomically: there is never an account without a leaf.
    fn deploy_and_insert(
        e: &Env,
        salt: &BytesN<32>,
        key: Bytes,
        commitment: &BytesN<32>,
    ) -> Address {
        let (account, controller) = Self::deploy_account_contract(e, salt, key);
        zk_recovery::ZkRecoveryClient::new(e, &controller).insert(&account, commitment);
        account
    }

    /// The BN254 scalar field order `r`, identical to
    /// `contracts/zk-recovery/src/pool.rs::FIELD_ORDER_BE` -- duplicated
    /// here (rather than imported) for the same reason
    /// `zk_recovery::ZkRecoveryInterface` above is a local stub trait rather
    /// than a real dependency on `nido-zk-recovery`: this crate must not
    /// link that crate's `#[contract]` exports into its own cdylib. Value:
    /// `21888242871839275222246405745257275088548364400416034343698204186575808495617`.
    const DUMMY_FIELD_ORDER_BE: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
    ];

    /// Deterministic dummy commitment for the legacy `create_account` path
    /// (M2 Task 5): `sha256("nido-zk-dummy" || salt) mod r`. Reducing mod
    /// `r` (rather than rejecting like the pool's own `require_canonical`
    /// does for real commitments) guarantees this always lands as a
    /// canonical `< r` value the pool accepts, without ever needing the
    /// caller to retry -- there is no security property riding on this
    /// value's exact bits, only that it is present, canonical, and
    /// indistinguishable in shape from a real commitment.
    fn dummy_commitment(e: &Env, salt: &BytesN<32>) -> BytesN<32> {
        let mut preimage = Bytes::from_slice(e, b"nido-zk-dummy");
        preimage.extend_from_array(&salt.to_array());
        let digest = e.crypto().sha256(&preimage).to_bytes();
        let value = U256::from_be_bytes(e, &Bytes::from_array(e, &digest.to_array()));
        let field_order =
            U256::from_be_bytes(e, &Bytes::from_array(e, &Self::DUMMY_FIELD_ORDER_BE));
        let reduced = value.rem_euclid(&field_order);
        let mut out = [0u8; 32];
        reduced.to_be_bytes().copy_into_slice(&mut out);
        BytesN::from_array(e, &out)
    }

    /// SHA-256 of the embedded smart-account wasm — equal to the installed
    /// wasm hash that `deploy_v2` expects. Derived from `smart_account::WASM`
    /// (embedded at build time) so it tracks the wasm automatically instead of
    /// a hand-maintained constant.
    ///
    /// Hashing the full ~33 KB wasm inside the host is not free, so the result
    /// is cached in instance storage (`Config::account`) and computed only on
    /// the first call. Subsequent `create_account` calls read the cached value.
    fn account_wasm_hash(e: &Env) -> BytesN<32> {
        if let Some(cached) = Config::get_account(e) {
            return cached;
        }
        let hash = Self::compute_account_wasm_hash(e);
        Config::set_account(e, &hash);
        hash
    }

    /// Freshly compute `sha256(smart_account::WASM)` without consulting the
    /// cache. Used to populate the cache and as the source of truth in tests.
    fn compute_account_wasm_hash(e: &Env) -> BytesN<32> {
        e.crypto()
            .sha256(&Bytes::from_slice(e, smart_account::WASM))
            .to_bytes()
    }
}

#[cfg(test)]
mod test {
    // Several trait-required params below (e.g. `StubController`'s `Policy`
    // impl, `MockRegistry`/`NamedRegistry`'s stub entry points) are prefixed
    // `_` because the method bodies never read them. Clippy still flags them
    // as "used underscore-prefixed binding" -- the `#[contractimpl]` macro's
    // generated invoke-wrapper code binds each non-`Env` param to a
    // same-named local before forwarding it to the real method, which counts
    // as a "use" even though our source never reads it, and that generated
    // code sits outside the scope any function- or impl-level `#[allow]`
    // here can reach. Scoped to this test module only (precedent:
    // contracts/smart-account/src/contract.rs).
    #![allow(clippy::used_underscore_binding)]

    use super::*;
    use soroban_sdk::auth::Context;
    use soroban_sdk::testutils::{Address as _, Events as _};
    use soroban_sdk::{
        contract, contractclient, contractimpl, contracttype, Env, Event, IntoVal, TryFromVal,
    };
    use stellar_accounts::policies::Policy;
    use stellar_accounts::smart_account::ContextRule;

    // Minimal mock: every `fetch_contract_id` call returns a fixed address.
    #[contract]
    struct MockRegistry;

    #[contractimpl]
    impl MockRegistry {
        // `#[contractimpl]` entry point; SDK ABI requires owned `Address`.
        #[allow(clippy::needless_pass_by_value)]
        pub fn __constructor(env: &Env, fixed: Address) {
            env.storage()
                .instance()
                .set(&Symbol::new(env, "fixed"), &fixed);
        }
        pub fn fetch_contract_id(env: &Env, _name: String) -> Address {
            env.storage()
                .instance()
                .get::<_, Address>(&Symbol::new(env, "fixed"))
                .unwrap()
        }
    }

    /// Install-param shape matching `nido_zk_recovery::types::
    /// ZkRecoveryInstallParams` structurally (a single `version: u32` field)
    /// without adding a real dependency on that crate here — `#[contracttype]`
    /// structs encode purely by field name/order on the ledger, so this
    /// decodes identically to the real type's `Val`.
    #[contracttype]
    #[derive(Clone)]
    struct StubInstallParams {
        pub version: u32,
    }

    /// Minimal stub implementing OZ's `Policy`, standing in for the real
    /// `nido-zk-recovery` controller so `deploy_account_contract`'s
    /// `add_context_rule` cross-call into `Policy::install` has somewhere
    /// real to land. ALSO doubles as the "verifier" `fetch_contract_id`
    /// result in `get_c_address_unaffected_by_recovery_controller_arg` below
    /// -- registering an `External` signer (the Default rule's passkey
    /// signer) cross-calls the verifier's `batch_canonicalize_key`
    /// (`stellar-accounts` `storage.rs::validate_no_canonical_duplicates`),
    /// so this contract implements that entry point too (trivially, via the
    /// inherent-method `impl` block below -- not the real `Verifier` trait,
    /// which needs an associated `KeyData`/`SigData` type this test doesn't
    /// care about). ALSO stands in for the pool's genesis `insert` (M2 Task
    /// 5): `deploy_and_insert` now cross-calls it unconditionally, so this
    /// trivial `insert` (below, no auth/canonicality checks -- this test
    /// doesn't exercise pool security, only the deterministic-address
    /// invariant) gives that cross-call somewhere real to land too.
    #[contract]
    struct StubController;

    #[contractimpl]
    impl Policy for StubController {
        type AccountParams = StubInstallParams;

        fn install(
            _e: &Env,
            _install_params: Self::AccountParams,
            _context_rule: ContextRule,
            smart_account: Address,
        ) {
            smart_account.require_auth();
        }

        fn enforce(
            _e: &Env,
            _context: Context,
            _authenticated_signers: soroban_sdk::Vec<stellar_accounts::smart_account::Signer>,
            _context_rule: ContextRule,
            smart_account: Address,
        ) {
            smart_account.require_auth();
        }

        fn uninstall(_e: &Env, _context_rule: ContextRule, smart_account: Address) {
            smart_account.require_auth();
        }
    }

    #[contractimpl]
    impl StubController {
        /// Trivial "canonicalization": returns the raw key bytes unchanged.
        /// Good enough for a single-signer registration (this test's Default
        /// rule has exactly one signer, so `validate_no_canonical_duplicates`
        /// never compares two canonical outputs against each other).
        // `#[contractimpl]` entry point; SDK ABI requires owned `Vec<Val>`.
        #[allow(clippy::needless_pass_by_value)]
        pub fn batch_canonicalize_key(
            e: &Env,
            key_data: soroban_sdk::Vec<soroban_sdk::Val>,
        ) -> soroban_sdk::Vec<Bytes> {
            let mut out = soroban_sdk::Vec::new(e);
            for k in key_data.iter() {
                out.push_back(Bytes::try_from_val(e, &k).unwrap_or_else(|_| Bytes::new(e)));
            }
            out
        }

        /// Trivial genesis-insert stub: no factory auth check, no
        /// canonicality check, no actual Merkle pool. Just gives
        /// `deploy_and_insert`'s `ZkRecoveryClient::insert` cross-call
        /// somewhere real to land in tests that don't care about pool
        /// security (see the `insert`-specific tests below for that).
        pub fn insert(_e: &Env, _account: Address, _commitment: BytesN<32>) -> u32 {
            0
        }
    }

    #[test]
    fn resolve_caches_after_first_lookup() {
        let env = Env::default();
        env.mock_all_auths();

        // Deploy MockRegistry at the exact address `REGISTRY` points at so
        // the factory's hardcoded constant resolves to the mock during the
        // test.
        let registry_addr = Address::from_str(&env, REGISTRY);
        let expected = Address::generate(&env);
        env.register_at(&registry_addr, MockRegistry, (expected.clone(),));

        let admin = Address::generate(&env);
        let factory_addr = env.register(Contract, (admin,));
        let first = env.as_contract(&factory_addr, || Contract::resolve(&env, "verifier"));
        let second = env.as_contract(&factory_addr, || Contract::resolve(&env, "verifier"));
        assert_eq!(first, expected);
        assert_eq!(first, second);
    }

    #[test]
    fn get_c_address_uses_random_salt() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let factory_addr = env.register(Contract, (admin,));
        let salt_a = BytesN::from_array(&env, &[1; 32]);
        let salt_b = BytesN::from_array(&env, &[2; 32]);

        let first = env.as_contract(&factory_addr, || Contract::get_c_address(&env, &salt_a));
        let second = env.as_contract(&factory_addr, || Contract::get_c_address(&env, &salt_b));
        let first_again = env.as_contract(&factory_addr, || Contract::get_c_address(&env, &salt_a));

        assert_ne!(first, second);
        assert_eq!(first, first_again);
    }

    /// The deterministic-address invariant: threading the new
    /// `recovery_controller` argument through `deploy_account_contract` into
    /// the smart-account constructor must NOT change the deployer-derived
    /// address. `get_c_address` (== `deployed_address()`) is a pure function
    /// of deployer + salt + wasm-hash, computed before the constructor ever
    /// runs, so it must equal the address `create_account` (which now passes
    /// a resolved `Some(controller)`) actually deploys to.
    #[test]
    fn get_c_address_unaffected_by_recovery_controller_arg() {
        let env = Env::default();
        env.mock_all_auths();

        // "verifier" and "zk-recovery" both resolve to the same stub
        // controller (a real `Policy` implementer, so the constructor's
        // `add_context_rule` -> `Policy::install` cross-call has somewhere
        // real to land; never actually invoked as a verifier here).
        let controller_addr = env.register(StubController, ());

        // Install the embedded smart-account wasm on-chain at its own
        // sha256, mirroring `account_wasm_hash_equals_uploaded_wasm_hash` --
        // `deploy_v2` needs the wasm actually installed at the hash
        // `account_wasm_hash` derives, which the real deploy script (not
        // this unit test) is normally responsible for.
        env.deployer().upload_contract_wasm(smart_account::WASM);

        let registry_addr = Address::from_str(&env, REGISTRY);
        env.register_at(&registry_addr, MockRegistry, (controller_addr.clone(),));

        let admin = Address::generate(&env);
        let factory_addr = env.register(Contract, (admin,));
        let salt = BytesN::from_array(&env, &[9; 32]);
        let key = BytesN::from_array(&env, &[3; 65]);

        let predicted = env.as_contract(&factory_addr, || Contract::get_c_address(&env, &salt));
        let deployed =
            env.as_contract(&factory_addr, || Contract::create_account(&env, &salt, key));

        assert_eq!(
            predicted, deployed,
            "recovery_controller ctor arg must not affect the deployer-derived address"
        );
    }

    /// The property that actually matters: the hash the factory hands to
    /// `deploy_v2` must equal the hash the host assigns when the *same* bytes
    /// are installed/uploaded on-chain. `upload_contract_wasm` returns exactly
    /// the hash `deploy_v2` later demands, so proving they're equal proves the
    /// embedded wasm will resolve at deploy time (not just that we recomputed
    /// our own function body).
    #[test]
    fn account_wasm_hash_equals_uploaded_wasm_hash() {
        let env = Env::default();
        env.mock_all_auths();

        // The embedded wasm is staged by build.rs and must be non-empty
        // (catches a mis-staged / empty file).
        assert!(
            !smart_account::WASM.is_empty(),
            "embedded smart-account wasm is empty"
        );

        // Hash the host assigns when these exact bytes are installed on-chain —
        // i.e. the hash `deploy_v2` will look up.
        let uploaded = env.deployer().upload_contract_wasm(smart_account::WASM);

        // The admin arg is irrelevant here; this test only exercises the
        // wasm-hash derivation, but the constructor requires one.
        let factory_addr = env.register(Contract, (Address::generate(&env),));
        let derived = env.as_contract(&factory_addr, || Contract::account_wasm_hash(&env));

        assert_eq!(
            derived, uploaded,
            "factory deploy hash must match the installed-wasm hash"
        );
        assert_eq!(derived.to_array().len(), 32);
    }

    /// The cached hash (read back from instance storage on the second call)
    /// must equal the freshly-computed hash. Guards the lazy-cache path added
    /// to avoid rehashing the ~33 KB wasm on every `create_account`.
    #[test]
    fn account_wasm_hash_caches_first_computation() {
        let env = Env::default();
        env.mock_all_auths();
        // The admin arg is irrelevant here; this test only exercises the
        // wasm-hash cache, but the constructor requires one.
        let factory_addr = env.register(Contract, (Address::generate(&env),));

        env.as_contract(&factory_addr, || {
            // Nothing cached yet.
            assert!(Config::get_account(&env).is_none());

            let fresh = Contract::compute_account_wasm_hash(&env);

            // First call computes and caches.
            let first = Contract::account_wasm_hash(&env);
            assert_eq!(first, fresh);
            assert_eq!(Config::get_account(&env), Some(fresh.clone()));

            // Second call reads the cache and returns the identical value.
            let second = Contract::account_wasm_hash(&env);
            assert_eq!(second, fresh);
        });
    }

    /// The admin passed to `__constructor` is stored and returned by `admin`.
    /// (`mock_all_auths` is needed because the constructor registers the XLM
    /// SAC and mints, which requires auth.)
    #[test]
    fn admin_is_set_at_construct_time() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let id = env.register(Contract, (admin.clone(),));
        let client = ContractClient::new(&env, &id);
        assert_eq!(client.admin(), admin);
    }

    /// `set_admin` rotates the admin (requires the current admin's auth).
    #[test]
    fn set_admin_rotates_admin() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let new_admin = Address::generate(&env);
        let id = env.register(Contract, (admin.clone(),));
        let client = ContractClient::new(&env, &id);

        client.set_admin(&new_admin);
        assert_eq!(client.admin(), new_admin);
    }

    /// `set_admin` requires the current admin's authorization. With auth
    /// cleared the call must fail.
    #[test]
    fn set_admin_requires_auth() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let new_admin = Address::generate(&env);
        let id = env.register(Contract, (admin.clone(),));
        let client = ContractClient::new(&env, &id);

        // Clear all authorizations: the require_auth on the current admin
        // must now reject, and the admin must be unchanged.
        env.set_auths(&[]);
        assert!(client.try_set_admin(&new_admin).is_err());
        assert_eq!(client.admin(), admin);
    }

    /// `set_admin` checks the *current* admin specifically — auth from a
    /// non-admin address is not sufficient.
    #[test]
    fn set_admin_requires_current_admin_auth() {
        use soroban_sdk::testutils::{MockAuth, MockAuthInvoke};

        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let imposter = Address::generate(&env);
        let new_admin = Address::generate(&env);
        let id = env.register(Contract, (admin.clone(),));
        let client = ContractClient::new(&env, &id);

        // Only the imposter authorizes — the contract requires `admin`.
        let res = client
            .mock_auths(&[MockAuth {
                address: &imposter,
                invoke: &MockAuthInvoke {
                    contract: &id,
                    fn_name: "set_admin",
                    args: (new_admin.clone(),).into_val(&env),
                    sub_invokes: &[],
                },
            }])
            .try_set_admin(&new_admin);
        assert!(res.is_err());
        assert_eq!(client.admin(), admin);
    }

    /// `upgrade` requires admin auth and (with auth mocked + an installed wasm)
    /// succeeds. We install the embedded smart-account wasm to obtain a valid,
    /// already-uploaded wasm hash for `update_current_contract_wasm`.
    #[test]
    fn upgrade_requires_admin_auth_and_succeeds() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let id = env.register(Contract, (admin.clone(),));
        let client = ContractClient::new(&env, &id);

        // A valid, installed wasm hash for the host to upgrade to.
        let wasm_hash = env
            .deployer()
            .upload_contract_wasm(Bytes::from_slice(&env, smart_account::WASM));

        // With auth cleared the upgrade is rejected.
        env.set_auths(&[]);
        assert!(client.try_upgrade(&wasm_hash).is_err());

        // With the admin's auth mocked it goes through.
        env.mock_all_auths();
        client.upgrade(&wasm_hash);
    }

    /// `set_recovery_pool` requires the current admin's authorization, same
    /// pattern as `set_admin`/`upgrade`. With auth cleared the call must
    /// fail, and no override must be recorded.
    #[test]
    fn set_recovery_pool_requires_admin_auth() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let pool = Address::generate(&env);
        let id = env.register(Contract, (admin,));
        let client = ContractClient::new(&env, &id);

        env.set_auths(&[]);
        assert!(client.try_set_recovery_pool(&pool).is_err());
        assert_eq!(
            client.recovery_pool(),
            None,
            "a failed set_recovery_pool call must not record an override"
        );
    }

    /// Before any call, `recovery_pool` is `None` (the default, unset
    /// state). After `set_recovery_pool(P)`, `recovery_pool` returns
    /// `Some(P)`.
    #[test]
    fn set_recovery_pool_then_recovery_pool_returns_override() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let pool = Address::generate(&env);
        let id = env.register(Contract, (admin,));
        let client = ContractClient::new(&env, &id);

        assert_eq!(client.recovery_pool(), None, "no override has been set yet");
        client.set_recovery_pool(&pool);
        assert_eq!(client.recovery_pool(), Some(pool));
    }

    // ---------------------------------------------------------------------
    // M2 Task 5: factory genesis-insert tests. These deploy a REAL
    // `nido-zk-recovery` pool/controller (a dev-dependency, see
    // `Cargo.toml`'s note) rather than a stub, so assertions can check the
    // pool's actual `next_index`/`LeafInserted` event/`wrap_leaf` output --
    // not just that some cross-call landed somewhere.
    // ---------------------------------------------------------------------

    /// Name-aware mock registry: `"verifier"` resolves to `verifier`;
    /// anything else (in practice only `"zk-recovery"`) resolves to
    /// `zk_recovery`. Needed because the tests below (unlike the earlier
    /// ones) require TWO DIFFERENT resolved addresses in the same test.
    #[contract]
    struct NamedRegistry;

    #[contractimpl]
    impl NamedRegistry {
        // `#[contractimpl]` entry point; SDK ABI requires owned `Address`.
        #[allow(clippy::needless_pass_by_value)]
        pub fn __constructor(env: &Env, verifier: Address, zk_recovery: Address) {
            env.storage()
                .instance()
                .set(&Symbol::new(env, "verifier"), &verifier);
            env.storage()
                .instance()
                .set(&Symbol::new(env, "zk_recovery"), &zk_recovery);
        }

        // `#[contractimpl]` entry point; SDK ABI requires owned `String`.
        #[allow(clippy::needless_pass_by_value)]
        pub fn fetch_contract_id(env: &Env, name: String) -> Address {
            if name == String::from_str(env, "verifier") {
                env.storage()
                    .instance()
                    .get::<_, Address>(&Symbol::new(env, "verifier"))
                    .unwrap()
            } else {
                env.storage()
                    .instance()
                    .get::<_, Address>(&Symbol::new(env, "zk_recovery"))
                    .unwrap()
            }
        }
    }

    /// Minimal probe client for the smart account's `recovery_rule_id` view
    /// (`contracts/smart-account/src/contract.rs`), used only to prove "no
    /// contract landed at this address" in the atomicity test below: calling
    /// ANY entry point against an address with no contract deployed fails.
    #[contractclient(name = "ProbeClient")]
    trait Probe {
        fn recovery_rule_id(e: Env) -> Option<u32>;
    }

    /// Deploys a factory + a REAL `nido-zk-recovery` pool/controller,
    /// registered under `"zk-recovery"`, alongside a trivial `"verifier"`
    /// stub (`StubController`, reused purely for its
    /// `batch_canonicalize_key`). The pool's configured `factory` authority
    /// is the deployed factory's own address UNLESS `wrong_factory` is
    /// `true`, in which case it's an unrelated generated address -- used by
    /// the atomicity test to prove `insert`'s factory-auth check actually
    /// gates the genesis insert (rather than everything just being mocked
    /// through). No `mock_all_auths()`/`mock_auths` is used anywhere in this
    /// block of tests: every real auth check along the deploy+insert path
    /// (the recovery policy's `install`, the pool's genesis `insert`) is
    /// satisfied purely via "invoker contract auth" (the direct caller IS
    /// the address being auth'd), exactly as it will be on a real network --
    /// so these tests double as proof that no signature/mock is needed for
    /// the happy path, and that the auth check is real (not vacuously
    /// mocked-through) in the failure path.
    ///
    /// Returns `(factory_addr, pool_addr)`.
    fn setup_factory_and_pool(env: &Env, wrong_factory: bool) -> (Address, Address) {
        let admin = Address::generate(env);
        let factory_addr = env.register(Contract, (admin,));

        let configured_factory = if wrong_factory {
            Address::generate(env)
        } else {
            factory_addr.clone()
        };

        // The pool's OWN "verifier" (for real recovery proofs, unrelated to
        // the smart-account's passkey verifier below) and webauthn verifier
        // are never exercised by `insert` -- placeholder addresses suffice.
        let pool_proof_verifier = Address::generate(env);
        let webauthn_verifier = Address::generate(env);
        let network_passphrase = Bytes::from_slice(env, b"Test SDF Network ; September 2015");
        let pool_addr = env.register(
            nido_zk_recovery::pool::ZkRecovery,
            (
                configured_factory,
                pool_proof_verifier,
                3u64 * 24 * 3600,
                7u64 * 24 * 3600,
                3u32,
                24u64 * 3600,
                network_passphrase,
                webauthn_verifier,
                Address::generate(env), // pool upgrade admin (unused by this test)
            ),
        );

        let verifier_stub = env.register(StubController, ());
        let registry_addr = Address::from_str(env, REGISTRY);
        env.register_at(
            &registry_addr,
            NamedRegistry,
            (verifier_stub, pool_addr.clone()),
        );

        env.deployer().upload_contract_wasm(smart_account::WASM);

        (factory_addr, pool_addr)
    }

    /// A canonical (`< r`) 32-byte commitment with the given low byte --
    /// trivially satisfies `require_canonical` for any test that just needs
    /// *some* valid, distinguishable real commitment.
    fn small_commitment(env: &Env, low_byte: u8) -> BytesN<32> {
        let mut bytes = [0u8; 32];
        bytes[31] = low_byte;
        BytesN::from_array(env, &bytes)
    }

    /// `create_account_v2` deploys to `get_c_address(salt)`, and -- in the
    /// SAME transaction -- inserts `wrap_leaf(account, commitment)` as the
    /// pool's genesis leaf (index 0, `next_index` now `1`).
    #[test]
    fn create_account_v2_inserts_real_genesis_leaf_at_deterministic_address() {
        let env = Env::default();
        let (factory_addr, pool_addr) = setup_factory_and_pool(&env, false);
        let client = ContractClient::new(&env, &factory_addr);
        let pool_client = nido_zk_recovery::pool::ZkRecoveryClient::new(&env, &pool_addr);

        let salt = BytesN::from_array(&env, &[11; 32]);
        let key = BytesN::from_array(&env, &[4; 65]);
        let commitment = small_commitment(&env, 42);

        let predicted = client.get_c_address(&salt);
        let account = client.create_account_v2(&salt, &key, &commitment);

        // Captured immediately after the call under test -- `Env::events()`
        // reflects only the MOST RECENT top-level invocation, so any
        // further client calls (`next_index`, `is_known_root`, ...) below
        // would otherwise clobber it before we get to inspect it.
        let pool_events = env.events().all().filter_by_contract(&pool_addr);

        assert_eq!(
            account, predicted,
            "create_account_v2 must deploy to get_c_address(salt) -- the commitment/insert \
             must not affect the deployer-derived address"
        );
        assert_eq!(pool_client.next_index(), 1);

        let expected_leaf = nido_zk_recovery::hash::wrap_leaf(&env, &account, &commitment);
        let expected_event = nido_zk_recovery::types::LeafInserted {
            index: &0,
            leaf: &expected_leaf,
        };
        assert_eq!(
            pool_events,
            [expected_event.to_xdr(&env, &pool_addr)],
            "create_account_v2 must insert wrap_leaf(account, real commitment) as the \
             genesis leaf"
        );
        assert!(pool_client.is_known_root(&pool_client.current_root()));
    }

    /// Salt-reuse / double-deploy: a salt deterministically fixes the account
    /// address (`get_c_address(salt)` = hash of deployer + salt + wasm-hash),
    /// so a second `create_account_v2` with the SAME salt targets an
    /// already-occupied address and the host rejects the re-deploy. This is
    /// the anti-collision invariant -- a salt can only ever mint ONE account,
    /// so an attacker cannot re-deploy over (and thus hijack / reset) an
    /// existing account by replaying its salt. The first account's genesis
    /// leaf must also remain the pool's only leaf (the rejected second call is
    /// atomic: no extra leaf inserted).
    #[test]
    fn create_account_v2_twice_with_same_salt_is_rejected() {
        let env = Env::default();
        let (factory_addr, pool_addr) = setup_factory_and_pool(&env, false);
        let client = ContractClient::new(&env, &factory_addr);
        let pool_client = nido_zk_recovery::pool::ZkRecoveryClient::new(&env, &pool_addr);

        let salt = BytesN::from_array(&env, &[7; 32]);
        let key = BytesN::from_array(&env, &[4; 65]);
        let commitment = small_commitment(&env, 13);

        // First deploy succeeds and inserts the genesis leaf (index 0).
        let account = client.create_account_v2(&salt, &key, &commitment);
        assert_eq!(pool_client.next_index(), 1);

        // Second deploy at the SAME salt -> same deterministic address ->
        // host rejects the re-deploy. A different key/commitment is used to
        // prove the rejection is about the ADDRESS collision, not the args.
        let other_key = BytesN::from_array(&env, &[5; 65]);
        let other_commitment = small_commitment(&env, 99);
        let res = client.try_create_account_v2(&salt, &other_key, &other_commitment);
        assert!(
            res.is_err(),
            "re-deploying an account at an already-used salt must be rejected"
        );

        // Atomicity: the rejected second call inserted no extra leaf, and the
        // original account is still the one resolvable at that salt.
        assert_eq!(
            pool_client.next_index(),
            1,
            "the rejected re-deploy must not have inserted a second genesis leaf"
        );
        assert_eq!(
            client.get_c_address(&salt),
            account,
            "the salt must still resolve to the original account address"
        );
    }

    /// Deploys a second REAL `nido-zk-recovery` pool, configured with
    /// `factory_addr` as its authority (same as the registry-registered pool
    /// `setup_factory_and_pool` sets up), but registered NOWHERE in the
    /// registry -- reachable only via `set_recovery_pool`'s override. Used to
    /// prove `resolve_recovery` prefers an admin-set override over the
    /// registry-resolved `"zk-recovery"` entry.
    fn deploy_unregistered_pool(env: &Env, factory_addr: &Address) -> Address {
        let pool_proof_verifier = Address::generate(env);
        let webauthn_verifier = Address::generate(env);
        let network_passphrase = Bytes::from_slice(env, b"Test SDF Network ; September 2015");
        env.register(
            nido_zk_recovery::pool::ZkRecovery,
            (
                factory_addr.clone(),
                pool_proof_verifier,
                3u64 * 24 * 3600,
                7u64 * 24 * 3600,
                3u32,
                24u64 * 3600,
                network_passphrase,
                webauthn_verifier,
                Address::generate(env), // pool upgrade admin (unused by this test)
            ),
        )
    }

    /// With an admin-set override in place, `create_account_v2` cross-calls
    /// the OVERRIDE pool's genesis `insert` -- NOT the registry-resolved
    /// `"zk-recovery"` pool `setup_factory_and_pool` registers. This is the
    /// property the whole override exists for: a preview factory instance
    /// can be pointed at an isolated preview pool without touching the
    /// shared production registry mapping.
    #[test]
    fn create_account_v2_uses_recovery_pool_override_when_set() {
        let env = Env::default();
        let (factory_addr, registry_pool_addr) = setup_factory_and_pool(&env, false);
        let client = ContractClient::new(&env, &factory_addr);

        let override_pool_addr = deploy_unregistered_pool(&env, &factory_addr);

        // Admin sets the override. `mock_all_auths` is used only for this
        // call (auth details are covered by the dedicated
        // `set_recovery_pool_requires_admin_auth` test above); the
        // subsequent deploy+insert still succeeds via plain invoker-contract
        // auth, exactly as in the other pool tests in this section.
        env.mock_all_auths();
        client.set_recovery_pool(&override_pool_addr);
        assert_eq!(client.recovery_pool(), Some(override_pool_addr.clone()));

        let salt = BytesN::from_array(&env, &[31; 32]);
        let key = BytesN::from_array(&env, &[9; 65]);
        let commitment = small_commitment(&env, 7);

        client.create_account_v2(&salt, &key, &commitment);

        let override_pool_client =
            nido_zk_recovery::pool::ZkRecoveryClient::new(&env, &override_pool_addr);
        let registry_pool_client =
            nido_zk_recovery::pool::ZkRecoveryClient::new(&env, &registry_pool_addr);

        assert_eq!(
            override_pool_client.next_index(),
            1,
            "the override pool must receive the genesis insert"
        );
        assert_eq!(
            registry_pool_client.next_index(),
            0,
            "the registry-resolved zk-recovery pool must NOT receive the insert once an \
             override is set"
        );
    }

    /// Legacy `create_account` routes through the exact same deploy+insert
    /// path, but with the deterministic DUMMY commitment
    /// (`sha256("nido-zk-dummy" || salt) mod r`) instead of a caller-supplied
    /// real one. Same shape: deploys to `get_c_address(salt)`, inserts
    /// exactly one genesis leaf.
    #[test]
    fn create_account_inserts_dummy_genesis_leaf_at_deterministic_address() {
        let env = Env::default();
        let (factory_addr, pool_addr) = setup_factory_and_pool(&env, false);
        let client = ContractClient::new(&env, &factory_addr);
        let pool_client = nido_zk_recovery::pool::ZkRecoveryClient::new(&env, &pool_addr);

        let salt = BytesN::from_array(&env, &[12; 32]);
        let key = BytesN::from_array(&env, &[5; 65]);

        let predicted = client.get_c_address(&salt);
        let account = client.create_account(&salt, &key);

        // Captured immediately -- see the note in the `create_account_v2`
        // test above on why this must happen before any further client call.
        let pool_events = env.events().all().filter_by_contract(&pool_addr);

        assert_eq!(
            account, predicted,
            "legacy create_account must still deploy to get_c_address(salt)"
        );
        assert_eq!(pool_client.next_index(), 1);

        let dummy = Contract::dummy_commitment(&env, &salt);
        let field_order = U256::from_be_bytes(
            &env,
            &Bytes::from_array(&env, &Contract::DUMMY_FIELD_ORDER_BE),
        );
        let dummy_value = U256::from_be_bytes(&env, &Bytes::from_array(&env, &dummy.to_array()));
        assert!(
            dummy_value < field_order,
            "dummy commitment must be canonical (< r), or the real pool would reject it"
        );

        let expected_leaf = nido_zk_recovery::hash::wrap_leaf(&env, &account, &dummy);
        let expected_event = nido_zk_recovery::types::LeafInserted {
            index: &0,
            leaf: &expected_leaf,
        };
        assert_eq!(
            pool_events,
            [expected_event.to_xdr(&env, &pool_addr)],
            "legacy create_account must insert wrap_leaf(account, dummy) as the genesis leaf"
        );
    }

    /// `dummy_commitment` is a pure function of `salt`: deterministic for
    /// the same salt, different across salts, and always canonical (`< r`)
    /// -- checked directly, independent of any deploy.
    #[test]
    fn dummy_commitment_is_canonical_and_deterministic() {
        let env = Env::default();
        let salt_a = BytesN::from_array(&env, &[1; 32]);
        let salt_b = BytesN::from_array(&env, &[2; 32]);

        let a1 = Contract::dummy_commitment(&env, &salt_a);
        let a2 = Contract::dummy_commitment(&env, &salt_a);
        let b = Contract::dummy_commitment(&env, &salt_b);

        assert_eq!(
            a1, a2,
            "dummy_commitment must be deterministic for the same salt"
        );
        assert_ne!(
            a1, b,
            "dummy_commitment must differ across salts (salt is part of the sha256 preimage)"
        );

        let field_order = U256::from_be_bytes(
            &env,
            &Bytes::from_array(&env, &Contract::DUMMY_FIELD_ORDER_BE),
        );
        for d in [&a1, &b] {
            let value = U256::from_be_bytes(&env, &Bytes::from_array(&env, &d.to_array()));
            assert!(
                value < field_order,
                "dummy commitment must be canonical (< r)"
            );
        }
    }

    /// Byte-shape uniformity (M2 Task 5's whole point): `create_account`
    /// (dummy) and `create_account_v2` (real) both deploy an account and
    /// insert EXACTLY one genesis leaf via the identical `wrap_leaf(account,
    /// commitment)` construction -- the only thing that differs between the
    /// two calls is the 32-byte commitment value itself, not the shape of
    /// what happens on-chain (one deploy, one insert, one `LeafInserted`
    /// event each).
    #[test]
    fn create_account_and_create_account_v2_are_uniform_except_commitment() {
        let env = Env::default();
        let (factory_addr, pool_addr) = setup_factory_and_pool(&env, false);
        let client = ContractClient::new(&env, &factory_addr);

        let salt_dummy = BytesN::from_array(&env, &[21; 32]);
        let key_dummy = BytesN::from_array(&env, &[7; 65]);
        let salt_real = BytesN::from_array(&env, &[22; 32]);
        let key_real = BytesN::from_array(&env, &[8; 65]);
        let real_commitment = small_commitment(&env, 99);

        // Each call's events are captured immediately, before the next
        // top-level client call -- `Env::events()` reflects only the most
        // recent invocation (see the note in the tests above).
        let dummy_account = client.create_account(&salt_dummy, &key_dummy);
        let dummy_events = env.events().all().filter_by_contract(&pool_addr);

        let real_account = client.create_account_v2(&salt_real, &key_real, &real_commitment);
        let real_events = env.events().all().filter_by_contract(&pool_addr);

        let dummy_commitment = Contract::dummy_commitment(&env, &salt_dummy);
        let dummy_leaf = nido_zk_recovery::hash::wrap_leaf(&env, &dummy_account, &dummy_commitment);
        let real_leaf = nido_zk_recovery::hash::wrap_leaf(&env, &real_account, &real_commitment);

        assert_eq!(
            dummy_events,
            [nido_zk_recovery::types::LeafInserted {
                index: &0,
                leaf: &dummy_leaf,
            }
            .to_xdr(&env, &pool_addr)],
            "create_account (dummy) must emit exactly one LeafInserted event, shaped \
             identically to create_account_v2's"
        );
        assert_eq!(
            real_events,
            [nido_zk_recovery::types::LeafInserted {
                index: &1,
                leaf: &real_leaf,
            }
            .to_xdr(&env, &pool_addr)],
            "create_account_v2 (real) must emit exactly one LeafInserted event, shaped \
             identically to create_account's -- the only difference between the two \
             calls' effect on the pool is the commitment byte value inside `leaf`"
        );
    }

    /// Task 11 (M2 residual): literal-pinning half of the cross-crate
    /// drift guard. `DUMMY_FIELD_ORDER_BE` cannot be compared directly
    /// against `nido_zk_recovery::pool`'s `FIELD_ORDER_BE` (private to that
    /// module, unreachable even via the real dev-dependency this crate
    /// already has) -- so this pins it against the SAME literal bytes that
    /// `nido_zk_recovery::pool::tests::field_order_and_merkle_depth_match_canonical`
    /// pins its own copy against. If either copy's bytes drift, whichever
    /// test still embeds the old literal is the one that keeps passing, but
    /// the other one -- guarding the crate whose constant actually moved --
    /// fails. See `dummy_field_order_matches_pool_behavior` below for a
    /// second, behavioral check that doesn't rely on keeping two literals
    /// in sync by hand.
    #[test]
    fn dummy_field_order_matches_canonical() {
        // Same 32 bytes as `nido_zk_recovery::pool`'s
        // `CANONICAL_FIELD_ORDER_BE` -- keep both literals identical.
        const CANONICAL_FIELD_ORDER_BE: [u8; 32] = [
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81,
            0x58, 0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93,
            0xf0, 0x00, 0x00, 0x01,
        ];
        assert_eq!(
            Contract::DUMMY_FIELD_ORDER_BE,
            CANONICAL_FIELD_ORDER_BE,
            "factory's DUMMY_FIELD_ORDER_BE drifted from the canonical BN254 scalar order r"
        );
    }

    /// Task 11 (M2 residual): behavioral half of the cross-crate drift
    /// guard -- stronger than the literal comparison above because it
    /// doesn't just re-check a hand-copied constant, it exercises the REAL
    /// `nido-zk-recovery` pool's `require_canonical` check (this crate's
    /// existing dev-dependency, see `setup_factory_and_pool`) against
    /// boundary values derived from `Contract::DUMMY_FIELD_ORDER_BE`. If the
    /// factory's copy of `r` has drifted from the pool's real `r`, one of
    /// the two assertions below flips: either `r - 1` (factory's) is no
    /// longer canonical per the real pool, or `r` (factory's) has become
    /// canonical per the real pool (i.e. `< real_r`).
    #[test]
    fn dummy_field_order_matches_pool_behavior() {
        let env = Env::default();
        let (_factory_addr, pool_addr) = setup_factory_and_pool(&env, false);
        env.mock_all_auths();
        let pool_client = nido_zk_recovery::pool::ZkRecoveryClient::new(&env, &pool_addr);
        let account = Address::generate(&env);

        let r = Contract::DUMMY_FIELD_ORDER_BE;
        let mut r_minus_1 = r;
        r_minus_1[31] = r_minus_1[31].wrapping_sub(1);

        let r_bytes = BytesN::from_array(&env, &r);
        let r_minus_1_bytes = BytesN::from_array(&env, &r_minus_1);

        assert!(
            pool_client
                .try_insert_for(&account, &r_minus_1_bytes)
                .is_ok(),
            "factory's DUMMY_FIELD_ORDER_BE - 1 must be canonical (< r) per the REAL pool's \
             FIELD_ORDER_BE -- if this fails, the two crates' field orders have drifted apart"
        );
        assert!(
            pool_client.try_insert_for(&account, &r_bytes).is_err(),
            "factory's DUMMY_FIELD_ORDER_BE itself must be rejected (== r, non-canonical) by \
             the REAL pool -- if this fails, the two crates' field orders have drifted apart"
        );
    }

    /// Atomicity: if the pool is configured with a DIFFERENT factory than
    /// the one actually calling it, the genesis `insert`'s
    /// `config.factory.require_auth()` fails (no invoker-auth match, no
    /// mocked signature) -- and because that failure happens inside the
    /// SAME top-level `create_account` invocation as the account deploy,
    /// the WHOLE call reverts: no account is left behind at
    /// `get_c_address(salt)` either.
    #[test]
    fn create_account_reverts_atomically_when_pool_factory_mismatched() {
        let env = Env::default();
        let (factory_addr, _pool_addr) = setup_factory_and_pool(&env, true);
        let client = ContractClient::new(&env, &factory_addr);

        let salt = BytesN::from_array(&env, &[13; 32]);
        let key = BytesN::from_array(&env, &[6; 65]);
        let predicted = client.get_c_address(&salt);

        let result = client.try_create_account(&salt, &key);
        assert!(
            result.is_err(),
            "create_account must revert when the pool's configured factory != this factory"
        );

        // No contract landed at the predicted address: any cross-call into
        // it fails.
        let probe = ProbeClient::new(&env, &predicted);
        assert!(
            probe.try_recovery_rule_id().is_err(),
            "no account should be deployed at get_c_address(salt) after the reverted call"
        );
    }

    // ---------------------------------------------------------------------
    // B2: registry pinning + pin bypass. `resolve` trusted the registry
    // unconditionally -- a compromised/repointed registry could route new
    // accounts to an attacker's verifier/controller (or, by returning a dead
    // address, block account creation). `set_registry_pins` lets the admin pin
    // the expected addresses; once pinned, `resolve` returns the pin DIRECTLY
    // and never consults the registry, so a repoint can neither reroute nor
    // block new accounts. Invariant F5 in docs/SECURITY_INVARIANTS.md.
    // ---------------------------------------------------------------------

    /// A registry whose `fetch_contract_id` always panics. Registering it at
    /// `REGISTRY` and then creating an account proves the pin bypass takes the
    /// registry entirely off the resolution path: if `resolve` consulted it
    /// for a pinned name the panic would abort the test.
    #[contract]
    struct PanicRegistry;

    #[contractimpl]
    impl PanicRegistry {
        // `#[contractimpl]` entry point; SDK ABI requires owned `String`.
        #[allow(clippy::needless_pass_by_value)]
        pub fn fetch_contract_id(_env: &Env, _name: String) -> Address {
            panic!("registry must not be consulted for a pinned name");
        }
    }

    /// A fresh factory is unpinned (both pins `None`): pre-B2 / testnet
    /// behavior, trusting whatever the registry returns.
    #[test]
    fn registry_pins_default_to_none() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let id = env.register(Contract, (admin,));
        let client = ContractClient::new(&env, &id);
        assert_eq!(client.pinned_verifier(), None);
        assert_eq!(client.pinned_zk_recovery(), None);
    }

    /// `set_registry_pins` stores both pins and the getters read them back.
    #[test]
    fn set_registry_pins_then_getters_return_pins() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let verifier = Address::generate(&env);
        let zk_recovery = Address::generate(&env);
        let id = env.register(Contract, (admin,));
        let client = ContractClient::new(&env, &id);

        client.set_registry_pins(&verifier, &zk_recovery);
        assert_eq!(client.pinned_verifier(), Some(verifier));
        assert_eq!(client.pinned_zk_recovery(), Some(zk_recovery));
    }

    /// `set_registry_pins` requires the current admin's auth. With auth cleared
    /// the call fails and no pins are recorded.
    #[test]
    fn set_registry_pins_requires_admin_auth() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let verifier = Address::generate(&env);
        let zk_recovery = Address::generate(&env);
        let id = env.register(Contract, (admin,));
        let client = ContractClient::new(&env, &id);

        env.set_auths(&[]);
        assert!(client
            .try_set_registry_pins(&verifier, &zk_recovery)
            .is_err());
        assert_eq!(
            client.pinned_verifier(),
            None,
            "a failed set_registry_pins must not record a pin"
        );
        assert_eq!(client.pinned_zk_recovery(), None);
    }

    /// Happy path: with pins set to exactly what the registry resolves,
    /// `create_account_v2` still deploys normally -- pinning is transparent
    /// when the registry agrees.
    #[test]
    fn create_account_v2_succeeds_when_pins_match_registry() {
        let env = Env::default();
        let (factory_addr, pool_addr) = setup_factory_and_pool(&env, false);
        let client = ContractClient::new(&env, &factory_addr);

        // Capture the address the registry currently resolves "verifier" to,
        // pre-pin (this resolve is a no-op for the pin check while unpinned).
        let verifier = env.as_contract(&factory_addr, || Contract::resolve(&env, "verifier"));

        env.mock_all_auths();
        client.set_registry_pins(&verifier, &pool_addr);

        let salt = BytesN::from_array(&env, &[41; 32]);
        let key = BytesN::from_array(&env, &[4; 65]);
        let commitment = small_commitment(&env, 5);
        let account = client.create_account_v2(&salt, &key, &commitment);
        assert_eq!(
            account,
            client.get_c_address(&salt),
            "pins matching the registry must not change deploy behavior"
        );
    }

    /// Pin bypass, repoint case: with the correct addresses pinned, the factory
    /// ignores a registry that has since been repointed to attacker/garbage
    /// addresses. If `resolve` still consulted the registry, `"zk-recovery"`
    /// would now resolve to a non-pool address and the genesis-insert cross-call
    /// would trap; instead creation succeeds against the pins.
    #[test]
    fn create_account_v2_uses_pins_when_registry_repointed() {
        let env = Env::default();
        let (factory_addr, pool_addr) = setup_factory_and_pool(&env, false);
        let client = ContractClient::new(&env, &factory_addr);

        // The correct addresses the registry resolves today (a real verifier
        // stub + the real pool) -- captured before repointing.
        let verifier = env.as_contract(&factory_addr, || Contract::resolve(&env, "verifier"));
        env.mock_all_auths();
        client.set_registry_pins(&verifier, &pool_addr);

        // Repoint the registry to bogus addresses for BOTH names.
        let registry_addr = Address::from_str(&env, REGISTRY);
        let bogus_v = Address::generate(&env);
        let bogus_zk = Address::generate(&env);
        env.register_at(&registry_addr, NamedRegistry, (bogus_v, bogus_zk));

        let salt = BytesN::from_array(&env, &[42; 32]);
        let key = BytesN::from_array(&env, &[6; 65]);
        let commitment = small_commitment(&env, 9);
        let account = client.create_account_v2(&salt, &key, &commitment);
        assert_eq!(
            account,
            client.get_c_address(&salt),
            "a pinned name must resolve from the pin, bypassing the repointed registry"
        );
    }

    /// Pin bypass, dead-registry case: the strongest form. With both names
    /// pinned, `resolve` never constructs the registry client, so a registry
    /// that panics on any lookup is unreachable and `create_account` (the
    /// legacy dummy-commitment path, which also resolves both names) still
    /// succeeds -- proving the registry is fully off the critical path.
    #[test]
    fn pinned_resolve_never_consults_registry() {
        let env = Env::default();
        let (factory_addr, pool_addr) = setup_factory_and_pool(&env, false);
        let client = ContractClient::new(&env, &factory_addr);

        let verifier = env.as_contract(&factory_addr, || Contract::resolve(&env, "verifier"));
        env.mock_all_auths();
        client.set_registry_pins(&verifier, &pool_addr);

        // Replace the registry with one that panics on ANY lookup.
        let registry_addr = Address::from_str(&env, REGISTRY);
        env.register_at(&registry_addr, PanicRegistry, ());

        let salt = BytesN::from_array(&env, &[43; 32]);
        let key = BytesN::from_array(&env, &[7; 65]);
        let account = client.create_account(&salt, &key);
        assert_eq!(
            account,
            client.get_c_address(&salt),
            "pinned names must resolve without ever calling the (panicking) registry"
        );
    }
}
