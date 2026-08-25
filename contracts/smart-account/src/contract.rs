// The `ref_option` lint is triggered by Soroban SDK macro-generated code
// (contractclient/contractargs) for `Option<u32>` parameters, not by our code.
#![allow(clippy::ref_option)]

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractclient, contracterror, contractimpl, contracttype,
    crypto::Hash,
    panic_with_error, symbol_short, Address, BytesN, Env, IntoVal, Map, String, Symbol, Val, Vec,
};
use stellar_accounts::policies::simple_threshold::SimpleThresholdAccountParams;
use stellar_accounts::smart_account::{
    add_context_rule, add_policy, add_signer, do_check_auth, get_context_rule,
    get_context_rules_count, remove_context_rule, remove_policy, remove_signer,
    update_context_rule_name, update_context_rule_valid_until, AuthPayload, ContextRule,
    ContextRuleType, ExecutionEntryPoint, Signer, SmartAccount, SmartAccountError,
};

/// Nido-specific errors for the in-account recovery guard (M2 Task 4).
/// Separate from OZ's `SmartAccountError` (which this crate does not own
/// and cannot append to) -- these are raised via `panic_with_error!` from
/// the `SmartAccount` trait methods below, which return concrete types
/// (`ContextRule`/`u32`/`()`), not `Result`, exactly like
/// `nido-zk-recovery`'s `RecoveryError` is raised from `controller.rs`'s
/// non-`Result`-returning entry points.
#[contracterror]
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NidoSmartAccountError {
    /// A mutating op (`remove_signer`/`remove_context_rule`/`remove_policy`/
    /// `update_context_rule_valid_until`) was attempted while a LIVE
    /// recovery is pending for this account (spec §3.2) -- blocks a thief
    /// holding a stolen passkey from evicting the recovery mechanism or the
    /// legitimate signer mid-recovery.
    RecoveryPendingBlocked = 1,
    /// A direct `remove_context_rule(recovery_rule_id)`,
    /// `add_policy(recovery_rule_id, ..)`, `remove_policy(recovery_rule_id,
    /// ..)`, or `update_context_rule_valid_until(recovery_rule_id, ..)` was
    /// attempted -- the recovery rule's existence AND its policy set and
    /// validity window can only change via
    /// `initiate_recovery_rule_removal`/`execute_recovery_rule_removal`
    /// (the announce-then-execute path below). Applies unconditionally,
    /// even with no pending, so a thief cannot delete the rule outright, nor
    /// neuter it in place (expire it via `valid_until`, or poison/strip its
    /// policies) to bypass the removal delay.
    RecoveryRuleProtected = 2,
    /// `execute_recovery_rule_removal` was called without a prior
    /// `initiate_recovery_rule_removal`.
    RemovalNotAnnounced = 3,
    /// `execute_recovery_rule_removal` was called before the announced
    /// 7-day delay elapsed.
    RemovalDelayNotElapsed = 4,
    /// `initiate_recovery_rule_removal`/`execute_recovery_rule_removal` was
    /// called on an account constructed with `recovery_controller: None` --
    /// there is no recovery rule to remove.
    NoRecoveryConfigured = 5,
    /// `enroll_zk_recovery` (M2 Task 6's migration path) was called on an
    /// account that already has a recovery rule installed -- either from
    /// construction (`Some(recovery_controller)`) or a prior
    /// `enroll_zk_recovery` call. To swap controllers, remove the existing
    /// rule first via `initiate_recovery_rule_removal`/
    /// `execute_recovery_rule_removal`, then enroll again.
    RecoveryAlreadyEnrolled = 6,
    /// `upgrade` (the immediate path) was called on an account that HAS a
    /// recovery rule installed. Such accounts must upgrade via the
    /// announce-then-execute path (`initiate_upgrade` -> 7-day delay ->
    /// `execute_upgrade`), for the same reason `remove_context_rule` on the
    /// recovery rule is `RecoveryRuleProtected`: otherwise `upgrade` would be a
    /// zero-delay escape hatch letting a stolen passkey swap in a wasm with no
    /// recovery rule and permanently lock out the owner, bypassing both the
    /// 7-day removal timelock and the unconditional rule-protection checks.
    /// Accounts with NO recovery rule keep the immediate `upgrade` path.
    UpgradeRequiresTimelock = 7,
    /// `execute_upgrade` was called without a prior `initiate_upgrade` (or it
    /// was already consumed by a successful execute).
    UpgradeNotAnnounced = 8,
    /// `execute_upgrade` was called before the announced 7-day delay elapsed.
    UpgradeDelayNotElapsed = 9,
}

/// Minimal cross-call stub for `nido-zk-recovery`'s `has_pending` view.
///
/// This crate deliberately does NOT depend on `nido-zk-recovery` as a
/// normal Cargo dependency (see `Cargo.toml`'s note and
/// `ZkRecoveryInstallParams`'s doc comment above): both are `#[contract]`
/// crates, and linking one into the other's cdylib collides their
/// identically-named `#[no_mangle]` exports (`__constructor`, `install`,
/// `enforce`, …) at wasm link time. `#[contractclient]` on a local trait,
/// by contrast, generates ONLY a caller stub (a struct wrapping
/// `invoke_contract` calls) -- no exported symbols -- so it does not
/// collide. Mirrors the exact pattern OZ's own `stellar_accounts::policies`
/// module uses for its `PolicyClient` (a private `#[contractclient]` trait
/// alongside the real, associated-type-bearing `Policy` trait, because
/// `#[contractclient]` doesn't support associated types).
#[contractclient(name = "RecoveryControllerClient")]
trait RecoveryController {
    fn has_pending(e: Env, account: Address) -> bool;
}

/// Cross-calls `controller`'s `has_pending` view for this account. Pure
/// passthrough of the boolean -- callers decide what to do with `true`/`false`.
///
/// FAIL-SECURE (invariant S2): this uses the NON-`try_` client, so it only ever
/// returns on a clean `bool`. If the controller cross-call itself fails -- the
/// controller address is wrong/uninstalled, the contract traps, or `has_pending`
/// errors -- the call does NOT return `false`; it TRAPS, unwinding the entire
/// enclosing mutation (`remove_signer`/`remove_context_rule`/`remove_policy`/
/// `update_context_rule_valid_until`, or `execute_recovery_rule_removal`) and
/// reverting the transaction atomically. So an unreachable or misbehaving
/// controller BLOCKS eviction rather than silently permitting it -- the guard
/// fails closed. (A `try_`-based variant that mapped errors to `false` would be
/// the opposite: it would let a controller outage disable the recovery guard.)
fn has_live_pending(e: &Env, controller: &Address) -> bool {
    RecoveryControllerClient::new(e, controller).has_pending(&e.current_contract_address())
}

/// Panics `RecoveryPendingBlocked` if a recovery is currently pending for
/// this account, per `controller`'s `has_pending` cross-call.
fn guard_live_pending(e: &Env, controller: &Address) {
    if has_live_pending(e, controller) {
        panic_with_error!(e, NidoSmartAccountError::RecoveryPendingBlocked);
    }
}

/// The guard used by the four mutating `SmartAccount` ops
/// (`remove_signer`/`remove_context_rule`/`remove_policy`/
/// `update_context_rule_valid_until`, spec §3.2): a no-op if this account
/// was constructed with `recovery_controller: None` (accounts without
/// recovery are entirely unaffected -- no regression for non-recovery
/// deploys), otherwise panics `RecoveryPendingBlocked` if a recovery is
/// currently pending. Deliberately NOT applied to `add_context_rule` (the
/// completion path needs it) or `add_signer` (harmless during a pending,
/// blocking it could interfere with unrelated concurrent account setup).
fn guard_no_pending(e: &Env) {
    if let Some(controller) = NidoSmartAccount::recovery_controller(e) {
        guard_live_pending(e, &controller);
    }
}

/// `recovery_controller(e)`, or panics `NoRecoveryConfigured` if this
/// account has no recovery rule installed. Used by the announce-then-
/// execute rule-removal entry points, which are meaningless without a
/// recovery rule to remove.
fn recovery_controller_or_panic(e: &Env) -> Address {
    NidoSmartAccount::recovery_controller(e)
        .unwrap_or_else(|| panic_with_error!(e, NidoSmartAccountError::NoRecoveryConfigured))
}

/// Instance storage key for the `u32` id of the zero-signer recovery
/// `ContextRule` installed at construction (`Some(recovery_controller)`
/// path only). Absent when the account was constructed with `None`.
const RECOVERY_RULE_ID: Symbol = symbol_short!("RCVR_ID");

/// Instance storage key for the recovery controller `Address` the recovery
/// rule's policy points at. Absent when the account was constructed with
/// `None`.
const RECOVERY_CONTROLLER: Symbol = symbol_short!("RCVR_CTRL");

/// Instance storage key for the announced execute-after timestamp set by
/// `initiate_recovery_rule_removal`. Present only between a successful
/// `initiate_recovery_rule_removal` call and either a successful
/// `execute_recovery_rule_removal` (which clears it) or a fresh
/// `initiate_recovery_rule_removal` call (which overwrites it).
const RECOVERY_REMOVAL_AT: Symbol = symbol_short!("RCVR_RM");

/// Instance storage key for the wasm hash announced by `initiate_upgrade`,
/// pending its 7-day delay. Present only between a successful `initiate_upgrade`
/// and a successful `execute_upgrade` (which clears it) or a fresh
/// `initiate_upgrade` (which overwrites it). Recovery-enabled accounts only --
/// accounts with no recovery rule upgrade immediately via `upgrade`.
const PENDING_UPGRADE_HASH: Symbol = symbol_short!("UPG_HASH");

/// Instance storage key for the announced execute-after timestamp set by
/// `initiate_upgrade`; mirrors `RECOVERY_REMOVAL_AT`.
const PENDING_UPGRADE_AT: Symbol = symbol_short!("UPG_AT");

/// Announce-then-execute delay (spec §3.2) for
/// `initiate_recovery_rule_removal` -> `execute_recovery_rule_removal`: 7
/// days, in seconds. Long enough that a thief who stole the passkey and
/// announces removal gives the legitimate owner -- or anyone/anything
/// monitoring -- a real window to react (e.g. by initiating a genuine
/// recovery first, which then blocks `execute_recovery_rule_removal` via
/// the same live-pending guard as the four mutating ops).
const RECOVERY_REMOVAL_DELAY_SECS: u64 = 7 * 24 * 3600;

/// Install-param shape for the M1 `nido-zk-recovery` controller's `Policy`
/// impl, reconstructed inline rather than imported.
///
/// This crate deliberately does NOT depend on `nido-zk-recovery` (see the
/// note in `Cargo.toml`): both are `#[contract]` crates, and linking one
/// into the other's cdylib collides their identically-named `#[no_mangle]`
/// exports (`__constructor`, `install`, `enforce`, …) at wasm link time.
/// `#[contracttype]` structs are encoded on the ledger purely structurally
/// (an `ScMap` keyed by field-name symbols, sorted) — there is no nominal
/// type tag — so this MUST stay byte-for-byte structurally identical to
/// `contracts/zk-recovery/src/types.rs::ZkRecoveryInstallParams` (currently
/// just `{ version: u32 }`) for the real controller's `Policy::install` to
/// decode it via `FromVal`. If that type ever changes shape, this must
/// change with it.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkRecoveryInstallParams {
    pub version: u32,
}

/// Installs the zero-signer `CallContract(self)` recovery `ContextRule` with
/// `controller` as its sole policy (via `add_context_rule`, triggering the
/// controller's `Policy::install` cross-call), and stores
/// `RECOVERY_RULE_ID`/`RECOVERY_CONTROLLER`. Returns the new rule's id.
///
/// Shared by the constructor's `Some(recovery_controller)` path (M2 Task 3)
/// and `enroll_zk_recovery` (M2 Task 6's post-deploy migration path, below)
/// -- both must install exactly the same rule shape, so this is the single
/// place that shape is defined.
fn install_recovery_rule(e: &Env, controller: &Address) -> u32 {
    let install: Val = ZkRecoveryInstallParams { version: 1 }.into_val(e);
    let mut recovery_policies: Map<Address, Val> = Map::new(e);
    recovery_policies.set(controller.clone(), install);

    let no_signers: Vec<Signer> = Vec::new(e);
    let rule = add_context_rule(
        e,
        &ContextRuleType::CallContract(e.current_contract_address()),
        &String::from_str(e, "zk-recovery"),
        None,
        &no_signers,
        &recovery_policies,
    );

    e.storage().instance().set(&RECOVERY_RULE_ID, &rule.id);
    e.storage().instance().set(&RECOVERY_CONTROLLER, controller);
    rule.id
}

#[contract]
pub struct NidoSmartAccount;

#[contractimpl]
impl NidoSmartAccount {
    /// Initialize the smart account with a default context rule.
    ///
    /// Typically called with a single `WebAuthn` passkey signer during
    /// the Nido account creation flow.
    ///
    /// # Arguments
    ///
    /// * `signers` - Initial signers (e.g., passkey via `WebAuthn` verifier)
    /// * `policies` - Optional policies (e.g., spending limits)
    /// * `recovery_controller` - When `Some`, the M1 `nido-zk-recovery`
    ///   controller to install as this account's zero-signer
    ///   `CallContract(self)` recovery rule's policy (production factory
    ///   deploys always pass `Some`, keeping the anonymity set uniform).
    ///   `None` skips the recovery rule entirely — used by unrelated test
    ///   deploys and non-factory construction paths that don't want the
    ///   extra rule.
    #[allow(clippy::needless_pass_by_value)]
    pub fn __constructor(
        e: &Env,
        signers: Vec<Signer>,
        policies: Map<Address, Val>,
        recovery_controller: Option<Address>,
    ) {
        add_context_rule(
            e,
            &ContextRuleType::Default,
            &String::from_str(e, "default"),
            None,
            &signers,
            &policies,
        );

        if let Some(controller) = recovery_controller {
            install_recovery_rule(e, &controller);
        }
    }

    /// The `u32` id of the zero-signer recovery `ContextRule` installed at
    /// construction, or `None` if the account was constructed with
    /// `recovery_controller: None`.
    #[must_use]
    pub fn recovery_rule_id(e: &Env) -> Option<u32> {
        e.storage().instance().get(&RECOVERY_RULE_ID)
    }

    /// The recovery controller `Address` installed as the recovery rule's
    /// policy at construction, or `None` if the account was constructed with
    /// `recovery_controller: None`.
    #[must_use]
    pub fn recovery_controller(e: &Env) -> Option<Address> {
        e.storage().instance().get(&RECOVERY_CONTROLLER)
    }

    /// Step 1 of opting out of recovery: announces intent to remove the
    /// protected recovery rule and starts a 7-day timer
    /// (`RECOVERY_REMOVAL_DELAY_SECS`) that `execute_recovery_rule_removal`
    /// must wait out. This is the ONLY way to remove the recovery rule --
    /// `remove_context_rule(recovery_rule_id)` always panics
    /// `RecoveryRuleProtected` (see the `SmartAccount` impl below).
    ///
    /// Requires this account's own auth (the `WebAuthn` passkey signer in
    /// production). A thief holding a stolen passkey COULD call this, but
    /// the 7-day delay is the defense: it gives the legitimate owner (or
    /// anything monitoring the account) a real window to notice and react,
    /// e.g. by initiating a genuine recovery, which then blocks
    /// `execute_recovery_rule_removal` via the same live-pending guard the
    /// four mutating ops use.
    ///
    /// Panics `NoRecoveryConfigured` if this account has no recovery rule.
    /// Panics `RecoveryPendingBlocked` if a recovery is currently pending
    /// (announcing removal mid-recovery would let a thief race the
    /// legitimate owner's in-flight recovery).
    pub fn initiate_recovery_rule_removal(e: &Env) {
        e.current_contract_address().require_auth();
        let controller = recovery_controller_or_panic(e);
        guard_live_pending(e, &controller);
        let at = e.ledger().timestamp() + RECOVERY_REMOVAL_DELAY_SECS;
        e.storage().instance().set(&RECOVERY_REMOVAL_AT, &at);
    }

    /// Step 2: actually removes the recovery rule, once announced and the
    /// 7-day delay has elapsed. Requires this account's own auth again.
    ///
    /// Panics `RemovalNotAnnounced` if `initiate_recovery_rule_removal` was
    /// never called (or was already consumed by a prior successful
    /// execute). Panics `RemovalDelayNotElapsed` if called before the
    /// announced timestamp. Panics `RecoveryPendingBlocked` if a recovery
    /// became pending during the delay window (re-checked here, not just at
    /// announce time). On success: removes the recovery `ContextRule` via
    /// the raw OZ removal (bypassing this contract's own
    /// `RecoveryRuleProtected` self-check, which only guards the
    /// `SmartAccount::remove_context_rule` entry point below) and clears the
    /// recovery instance-storage keys.
    pub fn execute_recovery_rule_removal(e: &Env) {
        e.current_contract_address().require_auth();

        let announced_at: u64 = e
            .storage()
            .instance()
            .get(&RECOVERY_REMOVAL_AT)
            .unwrap_or_else(|| panic_with_error!(e, NidoSmartAccountError::RemovalNotAnnounced));
        if e.ledger().timestamp() < announced_at {
            panic_with_error!(e, NidoSmartAccountError::RemovalDelayNotElapsed);
        }

        let controller = recovery_controller_or_panic(e);
        guard_live_pending(e, &controller);

        let rule_id = NidoSmartAccount::recovery_rule_id(e)
            .unwrap_or_else(|| panic_with_error!(e, NidoSmartAccountError::NoRecoveryConfigured));
        // Raw OZ removal: calls the free `remove_context_rule` function
        // directly, NOT `<Self as SmartAccount>::remove_context_rule`, so
        // the `RecoveryRuleProtected` self-check below never fires for this
        // legitimate, delay-gated path.
        remove_context_rule(e, rule_id);

        e.storage().instance().remove(&RECOVERY_RULE_ID);
        e.storage().instance().remove(&RECOVERY_CONTROLLER);
        e.storage().instance().remove(&RECOVERY_REMOVAL_AT);
    }

    /// M2 Task 6 migration path: lets an account that was deployed WITHOUT a
    /// recovery controller (constructor `recovery_controller: None`) opt
    /// into ZK recovery afterwards, as a self-authorized, VISIBLE call --
    /// unlike the invisible factory-genesis path (constructor
    /// `Some(recovery_controller)`, which installs the rule inside the
    /// deploy transaction itself, before the account address is ever
    /// observed on-chain).
    ///
    /// Requires this account's own auth
    /// (`e.current_contract_address().require_auth()`) -- the same
    /// self-auth model as `add_multisig_recovery`/
    /// `initiate_recovery_rule_removal`: the account opts itself in, nobody
    /// else can enroll it on the account's behalf.
    ///
    /// Panics `RecoveryAlreadyEnrolled` if a recovery rule is already
    /// installed (`recovery_rule_id()` is `Some`) -- either from
    /// construction or a prior `enroll_zk_recovery` call. To swap
    /// controllers, first remove the existing rule via
    /// `initiate_recovery_rule_removal`/`execute_recovery_rule_removal`,
    /// then enroll again.
    ///
    /// On success, delegates to the same [`install_recovery_rule`] helper
    /// the constructor's `Some(recovery_controller)` path uses: installs the
    /// zero-signer `CallContract(self)` recovery `ContextRule` with
    /// `recovery_controller` as its policy (triggering the controller's
    /// `Policy::install` cross-call) and stores `RECOVERY_RULE_ID`/
    /// `RECOVERY_CONTROLLER` -- the exact same state the constructor path
    /// leaves behind, so the in-account guard (`guard_no_pending`, which
    /// reads `RECOVERY_CONTROLLER`) applies identically to a migrated
    /// account from this point on.
    ///
    /// # Two-step flow
    ///
    /// This method ONLY installs the rule on THIS account. It deliberately
    /// does NOT also call the pool's `insert_for(account, commitment)` --
    /// that is a separate, distinct, account-authed call against the
    /// `nido-zk-recovery` POOL contract (a different contract from this
    /// account), driven by the SDK/off-chain flow once it has generated a
    /// fresh commitment/secret for this account. A fully enrolled account
    /// requires BOTH steps:
    ///
    ///   1. `account.enroll_zk_recovery(recovery_controller)` (this method)
    ///      -- installs the rule on the account.
    ///   2. `pool.insert_for(account, commitment)` -- inserts the account's
    ///      recovery leaf into the pool's Merkle tree, visibly bound to
    ///      `account` (see `nido_zk_recovery::pool`'s `insert_for` doc
    ///      comment).
    ///
    /// The two steps can be separate transactions or bundled into one --
    /// both are independently account-authed, so ordering between them
    /// doesn't matter for correctness. But a real `initiate_recovery` proof
    /// only verifies once BOTH have completed: the rule must exist for the
    /// completion path (`add_context_rule` cross-check), and the leaf must
    /// be in the tree for the Merkle-membership proof.
    ///
    /// # Degraded mode -- what this does NOT retrofit
    ///
    /// Be honest about the scope: this is a migration path for a NEW-wasm
    /// account -- one whose deployed bytecode already contains this
    /// `enroll_zk_recovery` entry point and the in-account guard -- that
    /// happened to be constructed with `recovery_controller: None`. It is
    /// NOT a way to retrofit a genuinely OLD-wasm account (one deployed
    /// before this code existed). Soroban contract wasm is immutable once
    /// deployed: an old account has no `enroll_zk_recovery` entry point (nor
    /// the guard) to call in the first place -- there is no mechanism here
    /// to add a new exported function to already-deployed bytecode. A truly
    /// old account would first have to migrate to this new wasm by some
    /// OTHER means entirely outside this method's scope (e.g. moving to a
    /// freshly deployed account) before `enroll_zk_recovery` becomes
    /// reachable at all. Do not read this method as a general legacy-account
    /// migration story -- it only covers the "deployed with the new code,
    /// but skipped recovery at construction time" case.
    #[allow(clippy::needless_pass_by_value)]
    pub fn enroll_zk_recovery(e: &Env, recovery_controller: Address) {
        e.current_contract_address().require_auth();
        if NidoSmartAccount::recovery_rule_id(e).is_some() {
            panic_with_error!(e, NidoSmartAccountError::RecoveryAlreadyEnrolled);
        }
        install_recovery_rule(e, &recovery_controller);
    }

    /// Install a social-recovery rule scoped to calls on this account, gated
    /// by an M-of-N multisig policy.
    ///
    /// Typed wrapper around `add_context_rule` that constructs the policies
    /// map for the caller — the SDK doesn't need to wrestle with the
    /// `Map<Address, Val>` install-param encoding (the generated TS bindings
    /// would otherwise erase the install param to `any`).
    ///
    /// The rule is scoped to `CallContract(self)` so it authorises calls
    /// against the account's own methods (e.g. `add_signer`, `remove_signer`,
    /// `add_context_rule`) — not external transfers.
    ///
    /// # Arguments
    ///
    /// * `name` - Human-readable rule name.
    /// * `valid_until` - Optional expiration ledger sequence.
    /// * `friends` - The signers authorised by the recovery rule.
    /// * `multisig_policy` - Address of the deployed multisig policy contract.
    /// * `threshold` - Number of `friends` signatures required (M).
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn add_multisig_recovery(
        e: &Env,
        name: String,
        valid_until: Option<u32>,
        friends: Vec<Signer>,
        multisig_policy: Address,
        threshold: u32,
    ) -> ContextRule {
        e.current_contract_address().require_auth();
        let install: Val = SimpleThresholdAccountParams { threshold }.into_val(e);
        let mut policies: Map<Address, Val> = Map::new(e);
        policies.set(multisig_policy, install);
        add_context_rule(
            e,
            &ContextRuleType::CallContract(e.current_contract_address()),
            &name,
            valid_until,
            &friends,
            &policies,
        )
    }

    /// Upgrade this account's own wasm to `new_wasm_hash` (an
    /// already-installed wasm hash). Governed by the account's OWN auth --
    /// the same `current_contract_address().require_auth()` gate as every
    /// other account mutation, so it is subject to the account's signing
    /// policy exactly like `add_signer`/`remove_signer`/etc. (no separate
    /// admin key: the account IS its own admin).
    ///
    /// TWO guards, both defending the recovery mechanism against a stolen
    /// passkey:
    ///  - `guard_no_pending`: an upgrade is BLOCKED while a recovery is
    ///    pending.
    ///  - If a recovery rule is installed, the IMMEDIATE path is REFUSED
    ///    (`UpgradeRequiresTimelock`). Otherwise `upgrade` would be a
    ///    zero-delay escape hatch around the protected recovery rule: a thief
    ///    could `upgrade` to a wasm that omits the rule and permanently lock
    ///    out the owner, bypassing the 7-day `initiate/execute_recovery_rule_removal`
    ///    timelock and the unconditional `RecoveryRuleProtected` checks
    ///    (`remove_signer`/`remove_context_rule`/`remove_policy`/
    ///    `update_context_rule_valid_until` are all guarded for the same
    ///    reason). Recovery-enabled accounts must instead go
    ///    `initiate_upgrade` -> 7-day delay -> `execute_upgrade`. Accounts with
    ///    NO recovery rule are unaffected and upgrade immediately here.
    // `#[contractimpl]` entry point; SDK ABI requires an owned `BytesN`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn upgrade(e: &Env, new_wasm_hash: BytesN<32>) {
        e.current_contract_address().require_auth();
        guard_no_pending(e);
        if NidoSmartAccount::recovery_rule_id(e).is_some() {
            panic_with_error!(e, NidoSmartAccountError::UpgradeRequiresTimelock);
        }
        e.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    /// Step 1 of upgrading a RECOVERY-ENABLED account: announces the target
    /// wasm hash and starts the same 7-day timer (`RECOVERY_REMOVAL_DELAY_SECS`)
    /// that recovery-rule removal uses. Mirrors `initiate_recovery_rule_removal`:
    /// a thief holding a stolen passkey COULD announce a malicious upgrade, but
    /// the delay is the defense -- it gives the legitimate owner (or a monitor)
    /// a real window to react, e.g. by initiating a genuine recovery, which then
    /// blocks `execute_upgrade` via the same live-pending guard, or by
    /// overwriting the announcement.
    ///
    /// Requires this account's own auth. Panics `NoRecoveryConfigured` if the
    /// account has no recovery rule (use the immediate `upgrade` instead), and
    /// `RecoveryPendingBlocked` if a recovery is currently pending.
    // `#[contractimpl]` entry point; SDK ABI requires an owned `BytesN`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn initiate_upgrade(e: &Env, new_wasm_hash: BytesN<32>) {
        e.current_contract_address().require_auth();
        let controller = recovery_controller_or_panic(e);
        guard_live_pending(e, &controller);
        let at = e.ledger().timestamp() + RECOVERY_REMOVAL_DELAY_SECS;
        e.storage()
            .instance()
            .set(&PENDING_UPGRADE_HASH, &new_wasm_hash);
        e.storage().instance().set(&PENDING_UPGRADE_AT, &at);
    }

    /// Step 2: performs the announced upgrade once the 7-day delay has elapsed.
    /// Requires this account's own auth again. Panics `UpgradeNotAnnounced` if
    /// `initiate_upgrade` was never called (or was already consumed),
    /// `UpgradeDelayNotElapsed` before the announced timestamp, and
    /// `RecoveryPendingBlocked` if a recovery became pending during the delay
    /// window (re-checked here, not just at announce time -- so an owner's
    /// genuine in-flight recovery blocks a thief's announced upgrade). Mirrors
    /// `execute_recovery_rule_removal`.
    pub fn execute_upgrade(e: &Env) {
        e.current_contract_address().require_auth();

        let announced_at: u64 = e
            .storage()
            .instance()
            .get(&PENDING_UPGRADE_AT)
            .unwrap_or_else(|| panic_with_error!(e, NidoSmartAccountError::UpgradeNotAnnounced));
        if e.ledger().timestamp() < announced_at {
            panic_with_error!(e, NidoSmartAccountError::UpgradeDelayNotElapsed);
        }

        // Re-check live-pending at execute time (mirrors
        // execute_recovery_rule_removal): a genuine recovery initiated during
        // the delay window blocks the announced upgrade.
        let controller = recovery_controller_or_panic(e);
        guard_live_pending(e, &controller);

        let new_wasm_hash: BytesN<32> = e
            .storage()
            .instance()
            .get(&PENDING_UPGRADE_HASH)
            .unwrap_or_else(|| panic_with_error!(e, NidoSmartAccountError::UpgradeNotAnnounced));

        e.storage().instance().remove(&PENDING_UPGRADE_HASH);
        e.storage().instance().remove(&PENDING_UPGRADE_AT);
        e.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}

#[contractimpl]
impl CustomAccountInterface for NidoSmartAccount {
    type Error = SmartAccountError;
    // OZ v0.7+ replaced the `Signatures` struct with `AuthPayload`
    // (which adds `context_rule_ids` aligned by index with `auth_contexts`).
    type Signature = AuthPayload;

    fn __check_auth(
        e: Env,
        signature_payload: Hash<32>,
        signatures: AuthPayload,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Self::Error> {
        do_check_auth(&e, &signature_payload, &signatures, &auth_contexts)
    }
}

#[contractimpl]
impl SmartAccount for NidoSmartAccount {
    fn get_context_rule(e: &Env, context_rule_id: u32) -> ContextRule {
        get_context_rule(e, context_rule_id)
    }

    fn get_context_rules_count(e: &Env) -> u32 {
        get_context_rules_count(e)
    }

    fn add_context_rule(
        e: &Env,
        context_type: ContextRuleType,
        name: String,
        valid_until: Option<u32>,
        signers: Vec<Signer>,
        policies: Map<Address, Val>,
    ) -> ContextRule {
        e.current_contract_address().require_auth();
        add_context_rule(e, &context_type, &name, valid_until, &signers, &policies)
    }

    fn update_context_rule_name(e: &Env, context_rule_id: u32, name: String) -> ContextRule {
        e.current_contract_address().require_auth();
        update_context_rule_name(e, context_rule_id, &name)
    }

    fn update_context_rule_valid_until(
        e: &Env,
        context_rule_id: u32,
        valid_until: Option<u32>,
    ) -> ContextRule {
        e.current_contract_address().require_auth();
        // Same unconditional `RecoveryRuleProtected` check as
        // `remove_context_rule` below: a thief with a live passkey must not
        // be able to shrink the recovery rule's `valid_until` window (e.g.
        // to the current ledger sequence, which OZ accepts and which
        // expires the rule as of the very next ledger) to silently disarm
        // recovery instead of removing it outright.
        if NidoSmartAccount::recovery_rule_id(e) == Some(context_rule_id) {
            panic_with_error!(e, NidoSmartAccountError::RecoveryRuleProtected);
        }
        guard_no_pending(e);
        update_context_rule_valid_until(e, context_rule_id, valid_until)
    }

    fn remove_context_rule(e: &Env, context_rule_id: u32) {
        e.current_contract_address().require_auth();
        // The `RecoveryRuleProtected` check runs BEFORE the pending guard,
        // and unconditionally (even with no pending): the recovery rule can
        // ONLY be removed via `initiate_recovery_rule_removal` /
        // `execute_recovery_rule_removal` (the announce-then-execute path),
        // never through this entry point directly.
        if NidoSmartAccount::recovery_rule_id(e) == Some(context_rule_id) {
            panic_with_error!(e, NidoSmartAccountError::RecoveryRuleProtected);
        }
        guard_no_pending(e);
        remove_context_rule(e, context_rule_id);
    }

    fn add_signer(e: &Env, context_rule_id: u32, signer: Signer) -> u32 {
        e.current_contract_address().require_auth();
        add_signer(e, context_rule_id, &signer)
    }

    fn remove_signer(e: &Env, context_rule_id: u32, signer_id: u32) {
        e.current_contract_address().require_auth();
        guard_no_pending(e);
        remove_signer(e, context_rule_id, signer_id);
    }

    fn add_policy(e: &Env, context_rule_id: u32, policy: Address, install_param: Val) -> u32 {
        e.current_contract_address().require_auth();
        // Same unconditional `RecoveryRuleProtected` check as
        // `remove_context_rule` below: OZ enforces ALL policies on a rule
        // (AND-semantics), so attaching even one always-failing policy to
        // the recovery rule is enough to make the completion
        // `add_context_rule` cross-check against it fail forever -- a
        // thief could otherwise neuter recovery without ever removing the
        // rule, including while a recovery is already pending.
        if NidoSmartAccount::recovery_rule_id(e) == Some(context_rule_id) {
            panic_with_error!(e, NidoSmartAccountError::RecoveryRuleProtected);
        }
        guard_no_pending(e);
        add_policy(e, context_rule_id, &policy, install_param)
    }

    fn remove_policy(e: &Env, context_rule_id: u32, policy_id: u32) {
        e.current_contract_address().require_auth();
        // Same unconditional `RecoveryRuleProtected` check as
        // `remove_context_rule` below: stripping the recovery rule's
        // controller policy (e.g. after adding a filler policy to dodge an
        // "empty policy set" edge case) would leave the rule unenforced,
        // so it must be blocked regardless of pending state, same as
        // removing the rule itself.
        if NidoSmartAccount::recovery_rule_id(e) == Some(context_rule_id) {
            panic_with_error!(e, NidoSmartAccountError::RecoveryRuleProtected);
        }
        guard_no_pending(e);
        remove_policy(e, context_rule_id, policy_id);
    }
}

#[contractimpl]
impl ExecutionEntryPoint for NidoSmartAccount {
    fn execute(e: &Env, target: Address, target_fn: Symbol, target_args: Vec<Val>) {
        e.current_contract_address().require_auth();
        e.invoke_contract::<Val>(&target, &target_fn, target_args);
    }
}

#[cfg(test)]
mod test {
    // `StubRecoveryPolicy`'s `Policy` impl below (used only to test-double
    // the real `nido-zk-recovery` controller) has several trait-required
    // params prefixed `_` because the method bodies never read them. Clippy
    // still flags them as "used underscore-prefixed binding" -- the
    // `#[contractimpl]` macro's generated invoke-wrapper code binds each
    // non-`Env` param to a same-named local before forwarding it to the
    // real method, which counts as a "use" even though our source never
    // reads it, and that generated code sits outside the scope any
    // function- or impl-level `#[allow]` here can reach. Scoped to this
    // test module only.
    #![allow(clippy::used_underscore_binding)]

    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger as _};
    use stellar_accounts::policies::Policy;

    /// Minimal stub implementing OZ's `Policy` for `ZkRecoveryInstallParams`
    /// — stands in for the real `nido-zk-recovery` controller (which needs a
    /// full `RecoveryConfig` deploy) so these constructor-level tests can
    /// register a lightweight in-crate contract instead. Mirrors the real
    /// controller's `install`/`enforce`/`uninstall` auth shape
    /// (`contracts/zk-recovery/src/policy.rs`) but does no bookkeeping.
    #[contract]
    struct StubRecoveryPolicy;

    // See the module-level `#[allow(clippy::used_underscore_binding)]`
    // above for why the underscore-prefixed params below are flagged.
    #[contractimpl]
    impl Policy for StubRecoveryPolicy {
        type AccountParams = ZkRecoveryInstallParams;

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
            _authenticated_signers: Vec<Signer>,
            _context_rule: ContextRule,
            smart_account: Address,
        ) {
            smart_account.require_auth();
        }

        fn uninstall(_e: &Env, _context_rule: ContextRule, smart_account: Address) {
            smart_account.require_auth();
        }
    }

    /// Test-only cross-call surface: `StubRecoveryPolicy` ALSO plays the
    /// role of a `RecoveryController` (the `has_pending` view the guard
    /// cross-calls), controllable per-account via `set_pending`. A second,
    /// independent `#[contractimpl]` block on the same `#[contract]` struct
    /// -- exactly like `NidoSmartAccount` itself has multiple
    /// `#[contractimpl]` blocks (inherent, `CustomAccountInterface`,
    /// `SmartAccount`, `ExecutionEntryPoint`) all extending one generated
    /// `Client`.
    #[contractimpl]
    impl StubRecoveryPolicy {
        #[allow(clippy::needless_pass_by_value)]
        pub fn set_pending(e: Env, account: Address, pending: bool) {
            e.storage()
                .instance()
                .set(&(symbol_short!("PEND"), account), &pending);
        }

        #[allow(clippy::needless_pass_by_value)]
        pub fn has_pending(e: Env, account: Address) -> bool {
            e.storage()
                .instance()
                .get(&(symbol_short!("PEND"), account))
                .unwrap_or(false)
        }
    }

    /// A single delegated signer for the Default rule — a rule needs at
    /// least one signer or policy (`SmartAccountError::NoSignersAndPolicies`,
    /// `storage.rs` #3004), so the tests below can't pass an empty vec here
    /// the way the (unrelated) zero-signer recovery rule does.
    fn one_signer(e: &Env) -> Vec<Signer> {
        soroban_sdk::vec![e, Signer::Delegated(Address::generate(e))]
    }

    fn empty_policies(e: &Env) -> Map<Address, Val> {
        Map::new(e)
    }

    /// `Some(controller)`: exactly two context rules exist, the second is
    /// `CallContract(self)` with zero signers and one policy == the
    /// controller, and both view methods return `Some`.
    #[test]
    fn some_controller_installs_recovery_rule() {
        let e = Env::default();
        e.mock_all_auths();

        let controller = e.register(StubRecoveryPolicy, ());
        let account_addr = e.register(
            NidoSmartAccount,
            (one_signer(&e), empty_policies(&e), Some(controller.clone())),
        );

        e.as_contract(&account_addr, || {
            assert_eq!(get_context_rules_count(&e), 2);

            let default_rule = get_context_rule(&e, 0);
            assert_eq!(default_rule.context_type, ContextRuleType::Default);

            let recovery_rule = get_context_rule(&e, 1);
            assert_eq!(
                recovery_rule.context_type,
                ContextRuleType::CallContract(account_addr.clone())
            );
            assert!(recovery_rule.signers.is_empty());
            assert_eq!(recovery_rule.policies.len(), 1);
            assert_eq!(recovery_rule.policies.get(0), Some(controller.clone()));

            assert_eq!(
                NidoSmartAccount::recovery_rule_id(&e),
                Some(recovery_rule.id)
            );
            assert_eq!(
                NidoSmartAccount::recovery_controller(&e),
                Some(controller.clone())
            );
        });
    }

    /// `None`: only the Default rule exists; both view methods return
    /// `None`. Existing (non-recovery) test deploys must be unaffected.
    #[test]
    fn none_skips_recovery_rule() {
        let e = Env::default();
        e.mock_all_auths();

        let account_addr = e.register(
            NidoSmartAccount,
            (one_signer(&e), empty_policies(&e), None::<Address>),
        );

        e.as_contract(&account_addr, || {
            assert_eq!(get_context_rules_count(&e), 1);
            let default_rule = get_context_rule(&e, 0);
            assert_eq!(default_rule.context_type, ContextRuleType::Default);

            assert_eq!(NidoSmartAccount::recovery_rule_id(&e), None);
            assert_eq!(NidoSmartAccount::recovery_controller(&e), None);
        });
    }

    // ---------------------------------------------------------------
    // M2 Task 4: the in-account guard (pending-block + protected
    // recovery rule + announce-then-execute removal), against the
    // `StubRecoveryPolicy` controller (its `has_pending` is directly
    // settable via `set_pending`, so these tests control the guard's
    // cross-call input precisely without needing a real ZK proof). The
    // real-controller end-to-end proof lives in
    // `crates/integration-tests/tests/it/zk_recovery_guard.rs`.
    // ---------------------------------------------------------------

    struct GuardSetup {
        account_addr: Address,
        controller: Address,
        default_rule_id: u32,
        recovery_rule_id: u32,
    }

    /// Deploys an account with `Some(StubRecoveryPolicy)` as the recovery
    /// controller and returns the ids the guard tests need.
    fn deploy_with_stub(e: &Env) -> GuardSetup {
        let controller = e.register(StubRecoveryPolicy, ());
        let account_addr = e.register(
            NidoSmartAccount,
            (one_signer(e), empty_policies(e), Some(controller.clone())),
        );
        let (default_rule_id, recovery_rule_id) = e.as_contract(&account_addr, || {
            (
                get_context_rule(e, 0).id,
                NidoSmartAccount::recovery_rule_id(e).expect("recovery rule installed"),
            )
        });
        GuardSetup {
            account_addr,
            controller,
            default_rule_id,
            recovery_rule_id,
        }
    }

    /// Extracts the `NidoSmartAccountError` code from a `try_*` client
    /// call's `Result` (mirrors `zk_recovery_lifecycle.rs`'s
    /// `contract_error` helper in the integration-tests crate) and asserts
    /// it matches `expected`. Panics with a descriptive message if the call
    /// instead succeeded or failed some other way (e.g. a host trap not
    /// carrying a contract error), so a wrong-error assertion can't
    /// silently pass.
    fn assert_account_error<T: core::fmt::Debug, E: core::fmt::Debug>(
        res: Result<Result<T, E>, Result<soroban_sdk::Error, soroban_sdk::InvokeError>>,
        expected: NidoSmartAccountError,
    ) {
        match res {
            Err(Ok(err)) => assert_eq!(
                err.get_code(),
                expected as u32,
                "expected {expected:?}, got contract error code {}",
                err.get_code()
            ),
            other => panic!("expected contract error {expected:?}, got {other:?}"),
        }
    }

    /// Guard blocks: with `has_pending == true`, each of the four guarded
    /// ops (`remove_signer`/`remove_context_rule`/`remove_policy`/
    /// `update_context_rule_valid_until`) panics `RecoveryPendingBlocked`,
    /// even against a NON-recovery rule/signer/policy (proving the guard,
    /// not the rule-protection check, is what fires here).
    #[test]
    fn guard_blocks_four_ops_while_pending() {
        let e = Env::default();
        e.mock_all_auths();
        let setup = deploy_with_stub(&e);
        let client = NidoSmartAccountClient::new(&e, &setup.account_addr);
        let stub = StubRecoveryPolicyClient::new(&e, &setup.controller);

        // Set up removable targets on the Default rule BEFORE marking a
        // pending (these adds are unguarded) -- a rule needs >= 1
        // signer/policy, so we add an extra one rather than remove the
        // original.
        let extra_signer_id = client.add_signer(
            &setup.default_rule_id,
            &Signer::Delegated(Address::generate(&e)),
        );
        let install: Val = ZkRecoveryInstallParams { version: 1 }.into_val(&e);
        let extra_policy_id =
            client.add_policy(&setup.default_rule_id, &setup.controller, &install);
        let extra_rule = client.add_context_rule(
            &ContextRuleType::CallContract(setup.account_addr.clone()),
            &String::from_str(&e, "extra"),
            &None,
            &one_signer(&e),
            &empty_policies(&e),
        );

        stub.set_pending(&setup.account_addr, &true);

        assert_account_error(
            client.try_remove_signer(&setup.default_rule_id, &extra_signer_id),
            NidoSmartAccountError::RecoveryPendingBlocked,
        );
        assert_account_error(
            client.try_remove_policy(&setup.default_rule_id, &extra_policy_id),
            NidoSmartAccountError::RecoveryPendingBlocked,
        );
        assert_account_error(
            client.try_update_context_rule_valid_until(&setup.default_rule_id, &Some(1_000)),
            NidoSmartAccountError::RecoveryPendingBlocked,
        );
        assert_account_error(
            client.try_remove_context_rule(&extra_rule.id),
            NidoSmartAccountError::RecoveryPendingBlocked,
        );
    }

    /// The guard also blocks `upgrade` while a recovery is pending: without
    /// it a thief who can authorize as the account could swap in a wasm that
    /// ignores the recovery rule and disarm recovery mid-timelock, bypassing
    /// the whole guard set. `guard_no_pending` fires BEFORE
    /// `update_current_contract_wasm`, so the placeholder hash is never
    /// reached (no real wasm needs to be installed for this test).
    #[test]
    fn guard_blocks_upgrade_while_pending() {
        let e = Env::default();
        e.mock_all_auths();
        let setup = deploy_with_stub(&e);
        let client = NidoSmartAccountClient::new(&e, &setup.account_addr);
        let stub = StubRecoveryPolicyClient::new(&e, &setup.controller);

        stub.set_pending(&setup.account_addr, &true);

        let placeholder = soroban_sdk::BytesN::from_array(&e, &[0u8; 32]);
        assert_account_error(
            client.try_upgrade(&placeholder),
            NidoSmartAccountError::RecoveryPendingBlocked,
        );
    }

    /// The previously-unguarded case: even with NO recovery pending, the
    /// immediate `upgrade` path is refused on a recovery-enabled account --
    /// otherwise a stolen passkey could swap in a wasm with no recovery rule
    /// and permanently disarm recovery with zero delay. Must go through the
    /// announce-then-execute timelock instead.
    #[test]
    fn immediate_upgrade_refused_when_recovery_installed() {
        let e = Env::default();
        e.mock_all_auths();
        let setup = deploy_with_stub(&e);
        let client = NidoSmartAccountClient::new(&e, &setup.account_addr);
        // has_pending defaults to false -- this is the steady state a thief
        // exploits, and the case the old `guard_no_pending`-only check missed.
        let placeholder = soroban_sdk::BytesN::from_array(&e, &[0u8; 32]);
        assert_account_error(
            client.try_upgrade(&placeholder),
            NidoSmartAccountError::UpgradeRequiresTimelock,
        );
    }

    /// `execute_upgrade` with nothing announced is rejected.
    #[test]
    fn execute_upgrade_without_announce_is_rejected() {
        let e = Env::default();
        e.mock_all_auths();
        let setup = deploy_with_stub(&e);
        let client = NidoSmartAccountClient::new(&e, &setup.account_addr);
        assert_account_error(
            client.try_execute_upgrade(),
            NidoSmartAccountError::UpgradeNotAnnounced,
        );
    }

    /// `execute_upgrade` before the announced 7-day delay elapses is rejected.
    #[test]
    fn execute_upgrade_before_delay_is_rejected() {
        let e = Env::default();
        e.mock_all_auths();
        let setup = deploy_with_stub(&e);
        let client = NidoSmartAccountClient::new(&e, &setup.account_addr);
        let placeholder = soroban_sdk::BytesN::from_array(&e, &[0u8; 32]);
        client.initiate_upgrade(&placeholder);
        // Same ledger time -> now < announced_at (now + 7d).
        assert_account_error(
            client.try_execute_upgrade(),
            NidoSmartAccountError::UpgradeDelayNotElapsed,
        );
    }

    /// Announcing an upgrade is blocked while a recovery is already pending
    /// (a thief can't race an in-flight recovery).
    #[test]
    fn initiate_upgrade_blocked_while_recovery_pending() {
        let e = Env::default();
        e.mock_all_auths();
        let setup = deploy_with_stub(&e);
        let client = NidoSmartAccountClient::new(&e, &setup.account_addr);
        let stub = StubRecoveryPolicyClient::new(&e, &setup.controller);
        stub.set_pending(&setup.account_addr, &true);
        let placeholder = soroban_sdk::BytesN::from_array(&e, &[0u8; 32]);
        assert_account_error(
            client.try_initiate_upgrade(&placeholder),
            NidoSmartAccountError::RecoveryPendingBlocked,
        );
    }

    /// Even after the delay elapses, `execute_upgrade` is blocked if a genuine
    /// recovery became pending during the window -- the owner's in-flight
    /// recovery wins the race against a thief's announced upgrade.
    #[test]
    fn execute_upgrade_blocked_by_recovery_pending_after_delay() {
        let e = Env::default();
        e.mock_all_auths();
        let setup = deploy_with_stub(&e);
        let client = NidoSmartAccountClient::new(&e, &setup.account_addr);
        let stub = StubRecoveryPolicyClient::new(&e, &setup.controller);
        let placeholder = soroban_sdk::BytesN::from_array(&e, &[0u8; 32]);
        client.initiate_upgrade(&placeholder);
        let now = e.ledger().timestamp();
        e.ledger()
            .with_mut(|li| li.timestamp = now + RECOVERY_REMOVAL_DELAY_SECS + 1);
        stub.set_pending(&setup.account_addr, &true);
        assert_account_error(
            client.try_execute_upgrade(),
            NidoSmartAccountError::RecoveryPendingBlocked,
        );
    }

    /// Guard doesn't over-block: with `has_pending == false`, the same four
    /// ops succeed against a non-recovery rule.
    #[test]
    fn guard_allows_four_ops_when_not_pending() {
        let e = Env::default();
        e.mock_all_auths();
        let setup = deploy_with_stub(&e);
        let client = NidoSmartAccountClient::new(&e, &setup.account_addr);
        // `has_pending` defaults to `false` (never called `set_pending`).

        let extra_signer_id = client.add_signer(
            &setup.default_rule_id,
            &Signer::Delegated(Address::generate(&e)),
        );
        let install: Val = ZkRecoveryInstallParams { version: 1 }.into_val(&e);
        let extra_policy_id =
            client.add_policy(&setup.default_rule_id, &setup.controller, &install);
        let extra_rule = client.add_context_rule(
            &ContextRuleType::CallContract(setup.account_addr.clone()),
            &String::from_str(&e, "extra"),
            &None,
            &one_signer(&e),
            &empty_policies(&e),
        );

        client.remove_signer(&setup.default_rule_id, &extra_signer_id);
        client.remove_policy(&setup.default_rule_id, &extra_policy_id);
        client.update_context_rule_valid_until(&setup.default_rule_id, &Some(1_000));
        client.remove_context_rule(&extra_rule.id);
    }

    /// `add_context_rule` (the completion path) is NOT blocked by the guard
    /// even while `has_pending == true`.
    #[test]
    fn add_context_rule_allowed_while_pending() {
        let e = Env::default();
        e.mock_all_auths();
        let setup = deploy_with_stub(&e);
        let client = NidoSmartAccountClient::new(&e, &setup.account_addr);
        let stub = StubRecoveryPolicyClient::new(&e, &setup.controller);
        stub.set_pending(&setup.account_addr, &true);

        let rule = client.add_context_rule(
            &ContextRuleType::CallContract(setup.account_addr.clone()),
            &String::from_str(&e, "completion"),
            &None,
            &one_signer(&e),
            &empty_policies(&e),
        );
        assert_ne!(rule.id, setup.recovery_rule_id);
    }

    /// `remove_context_rule(recovery_rule_id)` always panics
    /// `RecoveryRuleProtected`, regardless of whether a recovery is
    /// pending -- the recovery rule can only be removed via
    /// `initiate_recovery_rule_removal`/`execute_recovery_rule_removal`.
    #[test]
    fn remove_context_rule_on_recovery_rule_is_protected_regardless_of_pending() {
        let e = Env::default();
        e.mock_all_auths();
        let setup = deploy_with_stub(&e);
        let client = NidoSmartAccountClient::new(&e, &setup.account_addr);
        let stub = StubRecoveryPolicyClient::new(&e, &setup.controller);

        // Not pending.
        assert_account_error(
            client.try_remove_context_rule(&setup.recovery_rule_id),
            NidoSmartAccountError::RecoveryRuleProtected,
        );

        // Pending.
        stub.set_pending(&setup.account_addr, &true);
        assert_account_error(
            client.try_remove_context_rule(&setup.recovery_rule_id),
            NidoSmartAccountError::RecoveryRuleProtected,
        );
    }

    /// Bypass A: `update_context_rule_valid_until(recovery_rule_id, ..)`
    /// always panics `RecoveryRuleProtected`, regardless of pending state.
    /// Without this check, a thief could set `valid_until` to the current
    /// ledger sequence (OZ accepts `valid_until == sequence`) and expire the
    /// recovery rule as of the very next ledger, killing recovery in one
    /// call without ever removing the rule.
    #[test]
    fn update_valid_until_on_recovery_rule_is_protected_regardless_of_pending() {
        let e = Env::default();
        e.mock_all_auths();
        let setup = deploy_with_stub(&e);
        let client = NidoSmartAccountClient::new(&e, &setup.account_addr);
        let stub = StubRecoveryPolicyClient::new(&e, &setup.controller);

        let now = e.ledger().sequence();

        // Not pending.
        assert_account_error(
            client.try_update_context_rule_valid_until(&setup.recovery_rule_id, &Some(now)),
            NidoSmartAccountError::RecoveryRuleProtected,
        );

        // Pending.
        stub.set_pending(&setup.account_addr, &true);
        assert_account_error(
            client.try_update_context_rule_valid_until(&setup.recovery_rule_id, &Some(now)),
            NidoSmartAccountError::RecoveryRuleProtected,
        );
    }

    /// Bypass B: `add_policy(recovery_rule_id, ..)` always panics
    /// `RecoveryRuleProtected`, regardless of pending state -- this is the
    /// critical case, since OZ's AND-semantics over a rule's policies mean a
    /// single always-failing policy attached to the recovery rule makes the
    /// completion cross-check fail forever, and (unlike the other three
    /// guarded ops) this previously worked even DURING a live pending
    /// recovery, since `add_policy` had no guard of any kind.
    #[test]
    fn add_policy_on_recovery_rule_is_protected_regardless_of_pending() {
        let e = Env::default();
        e.mock_all_auths();
        let setup = deploy_with_stub(&e);
        let client = NidoSmartAccountClient::new(&e, &setup.account_addr);
        let stub = StubRecoveryPolicyClient::new(&e, &setup.controller);
        let install: Val = ZkRecoveryInstallParams { version: 1 }.into_val(&e);

        // Not pending.
        assert_account_error(
            client.try_add_policy(&setup.recovery_rule_id, &setup.controller, &install),
            NidoSmartAccountError::RecoveryRuleProtected,
        );

        // Pending -- this is Bypass B: it worked while pending before the
        // fix, since `add_policy` had no `guard_no_pending` call either.
        stub.set_pending(&setup.account_addr, &true);
        assert_account_error(
            client.try_add_policy(&setup.recovery_rule_id, &setup.controller, &install),
            NidoSmartAccountError::RecoveryRuleProtected,
        );
    }

    /// Bypass C: `remove_policy(recovery_rule_id, ..)` always panics
    /// `RecoveryRuleProtected`, regardless of pending state -- previously a
    /// thief could add a filler policy (unguarded) then remove the original
    /// controller policy, stripping enforcement from the rule entirely.
    #[test]
    fn remove_policy_on_recovery_rule_is_protected_regardless_of_pending() {
        let e = Env::default();
        e.mock_all_auths();
        let setup = deploy_with_stub(&e);
        let client = NidoSmartAccountClient::new(&e, &setup.account_addr);
        let stub = StubRecoveryPolicyClient::new(&e, &setup.controller);

        // Not pending. Policy id 0 is the controller policy installed at
        // construction (the recovery rule has exactly one policy).
        assert_account_error(
            client.try_remove_policy(&setup.recovery_rule_id, &0),
            NidoSmartAccountError::RecoveryRuleProtected,
        );

        // Pending.
        stub.set_pending(&setup.account_addr, &true);
        assert_account_error(
            client.try_remove_policy(&setup.recovery_rule_id, &0),
            NidoSmartAccountError::RecoveryRuleProtected,
        );
    }

    /// Guard doesn't over-block: the same three newly-guarded ops still
    /// succeed against a NON-recovery rule (the Default rule) when not
    /// pending -- proves the `RecoveryRuleProtected` check is scoped to the
    /// recovery rule id, not a blanket lockdown of these ops.
    #[test]
    fn newly_guarded_ops_allowed_on_non_recovery_rule_when_not_pending() {
        let e = Env::default();
        e.mock_all_auths();
        let setup = deploy_with_stub(&e);
        let client = NidoSmartAccountClient::new(&e, &setup.account_addr);

        client.update_context_rule_valid_until(&setup.default_rule_id, &Some(1_000_000));

        let install: Val = ZkRecoveryInstallParams { version: 1 }.into_val(&e);
        let policy_id = client.add_policy(&setup.default_rule_id, &setup.controller, &install);
        client.remove_policy(&setup.default_rule_id, &policy_id);
    }

    /// Announce-then-execute: executing without announcing fails
    /// `RemovalNotAnnounced`; announcing then executing immediately fails
    /// `RemovalDelayNotElapsed`; announcing then advancing the ledger past
    /// the 7-day delay lets execute succeed (clearing the recovery ids);
    /// announcing while a recovery is pending fails `RecoveryPendingBlocked`.
    #[test]
    fn announce_then_execute_removal_flow() {
        let e = Env::default();
        e.mock_all_auths();
        let setup = deploy_with_stub(&e);
        let client = NidoSmartAccountClient::new(&e, &setup.account_addr);

        assert_account_error(
            client.try_execute_recovery_rule_removal(),
            NidoSmartAccountError::RemovalNotAnnounced,
        );

        client.initiate_recovery_rule_removal();
        assert_account_error(
            client.try_execute_recovery_rule_removal(),
            NidoSmartAccountError::RemovalDelayNotElapsed,
        );

        // 7 days, in seconds, +1 to be strictly past the boundary --
        // mirrors `RECOVERY_REMOVAL_DELAY_SECS` (kept as a literal here so
        // this test would catch an accidental change to that constant).
        e.ledger().with_mut(|l| l.timestamp += 7 * 24 * 3600 + 1);
        client.execute_recovery_rule_removal();

        e.as_contract(&setup.account_addr, || {
            assert_eq!(NidoSmartAccount::recovery_rule_id(&e), None);
            assert_eq!(NidoSmartAccount::recovery_controller(&e), None);
        });

        // A fresh deploy: announcing while a recovery is pending must be
        // rejected outright (a thief can't announce removal mid-recovery
        // to race the legitimate owner).
        let setup2 = deploy_with_stub(&e);
        let client2 = NidoSmartAccountClient::new(&e, &setup2.account_addr);
        let stub2 = StubRecoveryPolicyClient::new(&e, &setup2.controller);
        stub2.set_pending(&setup2.account_addr, &true);
        assert_account_error(
            client2.try_initiate_recovery_rule_removal(),
            NidoSmartAccountError::RecoveryPendingBlocked,
        );
    }

    /// `recovery_controller: None`: the guard is a complete no-op (accounts
    /// without recovery configured are unaffected) -- `remove_signer`
    /// succeeds freely, and the announce-then-execute entry points reject
    /// with `NoRecoveryConfigured`/`RemovalNotAnnounced` (there is no
    /// recovery rule to remove).
    #[test]
    fn none_controller_guard_is_noop() {
        let e = Env::default();
        e.mock_all_auths();
        let account_addr = e.register(
            NidoSmartAccount,
            (one_signer(&e), empty_policies(&e), None::<Address>),
        );
        let client = NidoSmartAccountClient::new(&e, &account_addr);
        let default_rule_id = e.as_contract(&account_addr, || get_context_rule(&e, 0).id);

        let extra_signer_id =
            client.add_signer(&default_rule_id, &Signer::Delegated(Address::generate(&e)));
        // No panic -- proves the guard doesn't even attempt a cross-call
        // (there is no controller address to call) for a non-recovery
        // account.
        client.remove_signer(&default_rule_id, &extra_signer_id);

        assert_account_error(
            client.try_initiate_recovery_rule_removal(),
            NidoSmartAccountError::NoRecoveryConfigured,
        );
        assert_account_error(
            client.try_execute_recovery_rule_removal(),
            NidoSmartAccountError::RemovalNotAnnounced,
        );
    }

    // ---------------------------------------------------------------
    // M2 Task 6: `enroll_zk_recovery`, the post-deploy migration path for
    // a NEW-wasm account constructed with `recovery_controller: None`.
    // The end-to-end version (real fixture proof + guard, after a real
    // `pool.insert_for`) lives in
    // `crates/integration-tests/tests/it/zk_recovery_migration.rs`.
    // ---------------------------------------------------------------

    /// An account deployed with `recovery_controller: None` has no recovery
    /// rule (`recovery_rule_id()` is `None`). Calling `enroll_zk_recovery`
    /// installs the exact same shape the constructor's `Some(controller)`
    /// path would: exactly two context rules, the second `CallContract(self)`
    /// with zero signers and one policy == the controller, and both view
    /// methods now return `Some`.
    #[test]
    fn enroll_zk_recovery_installs_rule_on_none_account() {
        let e = Env::default();
        e.mock_all_auths();

        let controller = e.register(StubRecoveryPolicy, ());
        let account_addr = e.register(
            NidoSmartAccount,
            (one_signer(&e), empty_policies(&e), None::<Address>),
        );
        let client = NidoSmartAccountClient::new(&e, &account_addr);

        e.as_contract(&account_addr, || {
            assert_eq!(NidoSmartAccount::recovery_rule_id(&e), None);
            assert_eq!(NidoSmartAccount::recovery_controller(&e), None);
        });

        client.enroll_zk_recovery(&controller);

        e.as_contract(&account_addr, || {
            assert_eq!(get_context_rules_count(&e), 2);

            let recovery_rule = get_context_rule(&e, 1);
            assert_eq!(
                recovery_rule.context_type,
                ContextRuleType::CallContract(account_addr.clone())
            );
            assert!(recovery_rule.signers.is_empty());
            assert_eq!(recovery_rule.policies.len(), 1);
            assert_eq!(recovery_rule.policies.get(0), Some(controller.clone()));

            assert_eq!(
                NidoSmartAccount::recovery_rule_id(&e),
                Some(recovery_rule.id)
            );
            assert_eq!(
                NidoSmartAccount::recovery_controller(&e),
                Some(controller.clone())
            );
        });
    }

    /// A second `enroll_zk_recovery` call, once a rule already exists
    /// (whether from construction or a prior enroll), panics
    /// `RecoveryAlreadyEnrolled` rather than installing a second rule.
    #[test]
    fn enroll_zk_recovery_twice_is_rejected() {
        let e = Env::default();
        e.mock_all_auths();

        let controller = e.register(StubRecoveryPolicy, ());
        let account_addr = e.register(
            NidoSmartAccount,
            (one_signer(&e), empty_policies(&e), None::<Address>),
        );
        let client = NidoSmartAccountClient::new(&e, &account_addr);

        client.enroll_zk_recovery(&controller);
        assert_account_error(
            client.try_enroll_zk_recovery(&controller),
            NidoSmartAccountError::RecoveryAlreadyEnrolled,
        );

        // Also rejected against an account that already had a controller
        // installed AT CONSTRUCTION (not just via a prior enroll).
        let setup = deploy_with_stub(&e);
        let client2 = NidoSmartAccountClient::new(&e, &setup.account_addr);
        assert_account_error(
            client2.try_enroll_zk_recovery(&setup.controller),
            NidoSmartAccountError::RecoveryAlreadyEnrolled,
        );
    }

    /// `enroll_zk_recovery` requires the account's own auth: without any
    /// authorization mocked, it fails; with only an UNRELATED address's auth
    /// mocked (not the account itself), it still fails, proving the check is
    /// specifically the account's `require_auth`, not just "someone
    /// authorized". Mirrors `nido-zk-recovery`'s
    /// `insert_for_requires_account_auth` `MockAuth` pattern.
    #[test]
    fn enroll_zk_recovery_requires_account_auth() {
        use soroban_sdk::testutils::{MockAuth, MockAuthInvoke};

        let e = Env::default();

        let controller = e.register(StubRecoveryPolicy, ());
        // Registration itself needs no auth from the account (the
        // constructor path with `None` never calls `require_auth`).
        let account_addr = e.register(
            NidoSmartAccount,
            (one_signer(&e), empty_policies(&e), None::<Address>),
        );
        let client = NidoSmartAccountClient::new(&e, &account_addr);

        // No authorizations mocked at all -- must fail.
        assert!(
            client.try_enroll_zk_recovery(&controller).is_err(),
            "enroll_zk_recovery without the account's auth must fail"
        );

        // Only an unrelated address authorizes (not the account) -- still
        // must fail.
        let other = Address::generate(&e);
        let res = client
            .mock_auths(&[MockAuth {
                address: &other,
                invoke: &MockAuthInvoke {
                    contract: &account_addr,
                    fn_name: "enroll_zk_recovery",
                    args: (controller.clone(),).into_val(&e),
                    sub_invokes: &[],
                },
            }])
            .try_enroll_zk_recovery(&controller);
        assert!(
            res.is_err(),
            "enroll_zk_recovery authorized only by an unrelated address must fail"
        );

        e.as_contract(&account_addr, || {
            assert_eq!(
                NidoSmartAccount::recovery_rule_id(&e),
                None,
                "a failed enroll_zk_recovery must not install a rule"
            );
        });
    }

    // The deterministic-address invariant (constructor args, including the
    // new `recovery_controller`, must not affect the deployer-derived
    // address) is checked at the factory level — see
    // `contracts/factory/src/contract.rs`'s
    // `get_c_address_unaffected_by_recovery_controller_arg`, which is where
    // the actual deployer/salt/`deploy_v2` machinery this account is
    // deployed through lives.
}
