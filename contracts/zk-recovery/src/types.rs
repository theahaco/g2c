//! Storage types, error codes, and events for `contracts/zk-recovery`
//! (`docs/superpowers/specs/2026-07-02-zk-recovery-design.md` §3.3).
//!
//! M1 Task 2 only scaffolds these -- they are consumed by `merkle.rs`,
//! `pool.rs`, `controller.rs`, and `policy.rs` in later M1 tasks.

use soroban_sdk::{contracterror, contractevent, contracttype, Address, Bytes, BytesN};

/// Immutable-at-deploy configuration for the pool + controller (spec §3.3,
/// §3.4). `factory` is the only caller allowed to bind an arbitrary account
/// on `insert` (genesis authority); `verifier` is the `zk-verifier`
/// contract's address; `network_passphrase` is the raw (not pre-hashed)
/// network passphrase bytes -- `hash::compute_auth_hash` sha256's it
/// internally, exactly mirroring the circuit's `npass_hi`/`npass_lo`
/// derivation (`main.nr:40-42`), so `initiate_recovery` must recompute
/// `auth_hash` using the SAME passphrase bytes a proof's witness was
/// generated against; the remaining fields are the timelock/rate-limit
/// defaults (spec §3.3 "Defaults"). `webauthn_verifier` is appended by M1
/// Task 7 (`policy.rs`): the `WebAuthnVerifier` contract address that a
/// completed recovery's new signer must be `Signer::External`-bound to --
/// `PendingRecovery::new_pubkey` (spec §3.1) is only the raw P-256 public key
/// bytes, not a full `Signer`, so `Policy::enforce`'s args-gate needs this to
/// reconstruct the exact `Signer` it must match against the completing
/// `add_context_rule` call's new-signers argument. Appended (not inserted)
/// so existing `RecoveryConfig`/`__constructor` field/argument ordinals are
/// preserved for earlier M1 tasks' callers.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryConfig {
    pub factory: Address,
    pub verifier: Address,
    pub delay_secs: u64,
    pub completion_window_secs: u64,
    pub max_cancels: u32,
    pub timelock_floor_secs: u64,
    pub network_passphrase: Bytes,
    pub webauthn_verifier: Address,
}

/// Install parameters for the `ZkRecovery` completion `Policy` (spec §3.1,
/// M1 Task 7). The policy's enforcement behavior is fully determined by the
/// shared `RecoveryConfig` and the account's own `PendingRecovery` state, so
/// this carries no real configuration today -- `version` exists only to
/// mirror `multisig-policy`'s `AccountParams` shape (a non-trivial,
/// `FromVal`-decodable install-params type) and to leave room for future
/// versioning without changing the `Policy::install` signature.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkRecoveryInstallParams {
    pub version: u32,
}

/// A live timelocked recovery in flight for one account (spec §3.3
/// `initiate_recovery`). `new_pubkey` is staged, not yet installed; the
/// account's own `nullifier` reservation lives in `NullifierState`, not
/// here, so a cancel can release it without losing the pending record's
/// audit trail.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRecovery {
    pub new_pubkey: BytesN<65>,
    pub nullifier: BytesN<32>,
    pub initiated_at: u64,
    pub executable_after: u64,
    pub expires_at: u64,
}

/// Lifecycle state of a nullifier (spec §2.3). Absent from storage means
/// "unused"; `Reserved(account)` means an `initiate_recovery` has revealed
/// it and it is bound to that account's pending record; `Spent` means a
/// `complete_recovery` or `burn_nullifier` has permanently consumed it.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NullifierState {
    Reserved(Address),
    Spent,
}

/// Persistent storage key space. `Frontier`/`RootRing`/`RingHead`/
/// `NextIndex` are the depth-24 incremental-Merkle pool state (spec §3.4,
/// adapted from `mixer.rs`); `Nullifier`/`Pending`/`Cancels` are per-account
/// recovery state; `Installed` records which `ContextRule` id this
/// contract's `Policy` was installed under for a given account (spec §3.1);
/// `Config` is the immutable `RecoveryConfig`.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryKey {
    Frontier,
    NextIndex,
    RootRing,
    RingHead,
    Nullifier(BytesN<32>),
    Pending(Address),
    Installed(Address),
    Cancels(Address),
    Config,
    // Added by M1 Task 5 (`controller.rs::initiate_recovery`) -- appended
    // at the end so existing variants keep their XDR ordinals.
    Nonce(Address),
    RateWindow(Address),
    // Added by M1 Task 6 (`controller.rs::cancel_recovery`) -- appended at
    // the end so existing variants keep their XDR ordinals. Stores the
    // ledger timestamp of an account's most recent successful cancel, for
    // the 24h cooldown check (spec §2.4).
    LastCancel(Address),
    // Upgradability (issue #26). RETAINED FOR XDR-ORDINAL STABILITY ONLY: the
    // admin/upgrade governance key is now owned by the `admin-sep` crate, which
    // stores the admin under its own `ADMIN` symbol key -- this variant is no
    // longer read or written. Kept (not deleted) so every later variant keeps
    // its XDR ordinal.
    Admin,
}

/// Contract error codes (spec §3.3 interface/checks, §3.1 completion
/// authority, §2.2/§2.3 leaf/nullifier invariants). Grouped by the module
/// that raises them; later M1 tasks will exercise most of these -- only the
/// enum shape is exercised by M1 Task 2's scaffold.
#[contracterror]
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RecoveryError {
    // merkle.rs (spec §3.4 `insert_leaf` depth-24 capacity)
    TreeFull = 21,

    // pool.rs (spec §2.2, §3.3 `insert`/`insert_for`)
    NonCanonicalCommitment = 1,

    // controller.rs `initiate_recovery` (spec §3.3, ordered checks)
    PendingExists = 2,
    UnknownRoot = 3,
    NullifierReserved = 4,
    NullifierSpent = 5,
    InvalidNonce = 6,
    TimelockTooShort = 7,
    TimelockMismatch = 8,
    RateLimited = 9,
    VerificationFailed = 10,

    // controller.rs `cancel_recovery` / `burn_nullifier` (spec §2.3)
    NoPending = 11,
    CancelCapReached = 12,
    CooldownActive = 13,
    RecoveryExpired = 14,

    // policy.rs `Policy::enforce` (spec §3.1, the M1 hard requirement)
    TimelockNotElapsed = 15,
    ContextMismatch = 16,
    RuleMismatch = 17,
    NotInstalled = 18,
    AlreadyInstalled = 19,
    Unauthorized = 20,

    // Formerly raised by controller.rs `burn_nullifier`'s pre-fix
    // account-only guard (spec §2.3, M1 Task 6). That guard is no longer
    // reachable -- the fixed, proof-gated `burn_nullifier` (M1 Task 9)
    // enforces ownership entirely via its `action=3` ZK proof instead of
    // reserved-by-whom state (see `controller.rs::burn_nullifier`'s doc
    // comment). Kept, unused, so this variant's explicit discriminant is
    // never renumbered/reassigned.
    NullifierReservedElsewhere = 22,

    // pool.rs upgradability (issue #26). RETAINED FOR ERROR-CODE STABILITY
    // ONLY: admin/upgrade now come from `admin-sep`, which reads the admin
    // infallibly, so no code path returns this anymore. Kept (not deleted) so
    // the explicit discriminant is never renumbered/reassigned.
    AdminNotSet = 23,
}

/// `insert`/`insert_for` (pool.rs, later task): a new leaf entered the tree.
/// `leaf` is the on-chain-wrapped `stored` value, not the client-supplied
/// commitment (spec §2.2).
#[contractevent(topics = ["leaf_inserted"], data_format = "map")]
pub struct LeafInserted<'a> {
    #[topic]
    pub index: &'a u32,
    pub leaf: &'a BytesN<32>,
}

/// `initiate_recovery` (controller.rs, later task). Wallets surface this as
/// the cancel-or-lose alarm (spec §3.3); the new pubkey itself is not
/// emitted in the clear, only its hash.
#[contractevent(topics = ["recovery_initiated"], data_format = "map")]
pub struct RecoveryInitiated<'a> {
    #[topic]
    pub account: &'a Address,
    pub new_pubkey_hash: &'a BytesN<32>,
    pub executable_after: &'a u64,
}

/// `cancel_recovery` (controller.rs, later task).
#[contractevent(topics = ["recovery_canceled"], data_format = "map")]
pub struct RecoveryCanceled<'a> {
    #[topic]
    pub account: &'a Address,
    pub cancels_used: &'a u32,
}

/// `Policy::enforce` completion (policy.rs, later task): the nullifier is
/// now permanently `Spent`.
#[contractevent(topics = ["recovery_completed"], data_format = "map")]
pub struct RecoveryCompleted<'a> {
    #[topic]
    pub account: &'a Address,
    pub nullifier: &'a BytesN<32>,
}

/// `burn_nullifier` (controller.rs): proof-gated REVOKE (an `action=3` ZK
/// proof of knowledge of the nullifier's secret, plus account auth) that
/// spends a (possibly leaked) enrollment secret's nullifier without waiting
/// out a self-recovery -- proof-gating (not account-auth alone) is what
/// prevents a third party from burning a victim's PUBLIC nullifier after a
/// legitimate cancel (spec §2.3).
#[contractevent(topics = ["nullifier_burned"], data_format = "map")]
pub struct NullifierBurned<'a> {
    #[topic]
    pub account: &'a Address,
    pub nullifier: &'a BytesN<32>,
}
