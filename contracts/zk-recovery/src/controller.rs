//! `initiate_recovery` (spec §3.3): verifies a REAL ZK proof end-to-end by
//! cross-calling the deployed `zk-verifier` contract, runs the ordered
//! validity checks, reserves the nullifier, and stores a timelocked
//! `PendingRecovery` record.
//!
//! Permissionless by design (no `require_auth` anywhere in this module) --
//! the entire security property comes from the proof verifying against an
//! `auth_hash` this contract recomputes itself from the call's own
//! arguments (`hash::compute_auth_hash`), not from trusting the caller's
//! identity. A caller cannot swap `new_pubkey`/`nonce`/`timelock_secs`/etc.
//! without invalidating the proof's `auth_hash` public input (proven by
//! this module's `tampered_new_pubkey_fails_proof_verification`-style
//! coverage in `crates/integration-tests/tests/it/zk_recovery_lifecycle.rs`).
//!
//! This file adds a second `#[contractimpl] impl ZkRecovery` block
//! alongside `pool.rs`'s -- `soroban_sdk::contractimpl`'s macro expansion
//! only generates the `ZkRecoveryClient` *type* once (from the `#[contract]`
//! struct declaration in `pool.rs`); every `#[contractimpl]` block
//! (`impl_only`) merely adds an `impl ZkRecoveryClient { ... }` extending
//! that same client with its methods. So `ZkRecoveryClient` ends up with
//! `insert`/`insert_for`/... from `pool.rs` AND `initiate_recovery`/
//! `get_pending`/`next_nonce` from here, on one client type.

use crate::hash::compute_auth_hash;
use crate::merkle::is_known_root;
#[allow(unused_imports)] // ZkRecoveryArgs/ZkRecoveryClient are referenced by
// the `#[contractimpl]` macro expansion below, not
// directly by name in this file's source.
use crate::pool::{config, ZkRecovery, ZkRecoveryArgs, ZkRecoveryClient};
use crate::types::{
    NullifierBurned, NullifierState, PendingRecovery, RecoveryCanceled, RecoveryError,
    RecoveryInitiated, RecoveryKey,
};
use soroban_sdk::{
    contractimpl, panic_with_error, Address, Bytes, BytesN, Env, IntoVal, InvokeError, Symbol, Val,
    Vec as SorobanVec,
};

/// `action = 1` means "initiate recovery" in the `zk_recovery` circuit's
/// protocol (`circuits/zk_recovery/src/main.nr`).
const ACTION_INITIATE: u32 = 1;

/// `action = 2` means "cancel recovery" in the `zk_recovery` circuit's
/// protocol (`circuits/zk_recovery/src/main.nr`), spec §2.4. A cancel
/// proof's `auth_hash` ZEROES the pubkey/timelock fields (see
/// `cancel_recovery` below) -- a cancel proves the owner authorizes
/// stopping THIS pending recovery, not installing any particular new key.
const ACTION_CANCEL: u32 = 2;

/// `action = 3` means "revoke" (burn a nullifier) in the `zk_recovery`
/// circuit's protocol (`circuits/zk_recovery/src/main.nr`), spec §2.3. Like
/// a cancel proof, a revoke proof's `auth_hash` ZEROES the pubkey/timelock
/// fields (see `burn_nullifier` below) -- a revoke proves "I know the
/// secret behind this nullifier and want it dead", not "install this key".
/// This is what closes the public-nullifier grief: `nullifier` becomes
/// PUBLIC the moment any `initiate_recovery` reveals it as a proof public
/// input, and a `cancel_recovery` releases its reservation while it stays
/// public -- so account-auth alone (the pre-fix shape) let ANY third party
/// `burn_nullifier(their_own_account, victim_nullifier)` and permanently
/// kill the victim's enrollment credential. Only PROVING knowledge of the
/// secret (via the SAME `acct_hi`/`acct_lo` witness the circuit uses for
/// the Merkle leaf, the nullifier, AND `auth_hash`) distinguishes the
/// legitimate owner from a griefer once `nullifier` is public.
const ACTION_REVOKE: u32 = 3;

/// Rolling rate-limit window: 90 days, in seconds (spec §3.3).
const RATE_WINDOW_SECS: u64 = 90 * 24 * 3600;
/// Max initiations allowed per account within `RATE_WINDOW_SECS` (spec §3.3).
const RATE_LIMIT_MAX: u32 = 3;

/// Minimum time between two successful cancels for the same account (spec
/// §2.4): 24 hours, in seconds.
const CANCEL_COOLDOWN_SECS: u64 = 24 * 3600;

/// Extends a persistent entry's TTL to the network max, mirroring
/// `merkle.rs::extend_persistent_max` (duplicated rather than made `pub` --
/// this module's keys are unrelated to the Merkle frontier's).
fn extend_persistent_max(env: &Env, key: &RecoveryKey) {
    let max = env.storage().max_ttl();
    env.storage().persistent().extend_ttl(key, max, max);
}

fn stored_nonce(env: &Env, account: &Address) -> u64 {
    env.storage()
        .persistent()
        .get(&RecoveryKey::Nonce(account.clone()))
        .unwrap_or(0)
}

fn bump_nonce(env: &Env, account: &Address, nonce: u64) {
    let key = RecoveryKey::Nonce(account.clone());
    env.storage().persistent().set(&key, &nonce);
    extend_persistent_max(env, &key);
}

fn cancels_used(env: &Env, account: &Address) -> u32 {
    env.storage()
        .persistent()
        .get(&RecoveryKey::Cancels(account.clone()))
        .unwrap_or(0)
}

/// If `nullifier_key` is currently `Reserved(account)`, releases it
/// (removes the entry, making the nullifier usable again). A `Spent`
/// reservation, a reservation held by a DIFFERENT account, or no entry at
/// all are all left untouched. Shared by `initiate_recovery`'s
/// stale-pending-supersede path and `cancel_recovery`'s release-on-cancel
/// step -- both release exactly one pending's own reservation, never
/// another account's.
fn release_reservation_if_owned(env: &Env, nullifier: &BytesN<32>, account: &Address) {
    let key = RecoveryKey::Nullifier(nullifier.clone());
    if let Some(NullifierState::Reserved(reserved_for)) =
        env.storage().persistent().get::<_, NullifierState>(&key)
    {
        if &reserved_for == account {
            env.storage().persistent().remove(&key);
        }
    }
}

/// Prunes timestamps older than `RATE_WINDOW_SECS`, panics
/// `RateLimited` if `>= RATE_LIMIT_MAX` remain, otherwise appends `now` and
/// persists.
fn check_rate_limit(env: &Env, account: &Address, now: u64) {
    let key = RecoveryKey::RateWindow(account.clone());
    let window: SorobanVec<u64> = env
        .storage()
        .persistent()
        .get(&key)
        .unwrap_or_else(|| SorobanVec::new(env));

    let cutoff = now.saturating_sub(RATE_WINDOW_SECS);
    let mut pruned: SorobanVec<u64> = SorobanVec::new(env);
    for ts in window.iter() {
        if ts >= cutoff {
            pruned.push_back(ts);
        }
    }
    if pruned.len() >= RATE_LIMIT_MAX {
        panic_with_error!(env, RecoveryError::RateLimited);
    }
    pruned.push_back(now);
    env.storage().persistent().set(&key, &pruned);
    extend_persistent_max(env, &key);
}

/// `root(32) || nullifier(32) || auth_hash(32)`, the `UltraHonk` verifier's
/// expected `public_inputs` encoding for this circuit.
fn assemble_public_inputs(
    env: &Env,
    root: &BytesN<32>,
    nullifier: &BytesN<32>,
    auth_hash: &BytesN<32>,
) -> Bytes {
    let mut buf = [0u8; 96];
    buf[0..32].copy_from_slice(&root.to_array());
    buf[32..64].copy_from_slice(&nullifier.to_array());
    buf[64..96].copy_from_slice(&auth_hash.to_array());
    Bytes::from_array(env, &buf)
}

/// Cross-calls `verifier.verify_proof(public_inputs, proof)` (pattern:
/// `../zk/rs-soroban-ultrahonk/tornado_classic/contracts/src/mixer.rs:87-99`).
/// `try_invoke_contract` is used (not a typed client) so a verifier-side
/// panic/error surfaces as an `Err` here instead of aborting this contract's
/// whole invocation before we can map it to `RecoveryError::VerificationFailed`.
fn verify_proof(
    env: &Env,
    verifier: &Address,
    public_inputs: &Bytes,
    proof: &Bytes,
) -> Result<(), ()> {
    let mut args: SorobanVec<Val> = SorobanVec::new(env);
    args.push_back(public_inputs.into_val(env));
    args.push_back(proof.into_val(env));
    env.try_invoke_contract::<(), InvokeError>(verifier, &Symbol::new(env, "verify_proof"), args)
        .map_err(|_| ())?
        .map_err(|_| ())
}

#[contractimpl]
impl ZkRecovery {
    /// Starts a timelocked recovery for `account` (spec §3.3, ordered
    /// checks). Permissionless -- no `require_auth`. Returns
    /// `executable_after`.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    // `env`/`account`/`new_pubkey`/`root` are conventionally by-value for
    // `#[contractimpl]` entry points in this codebase; changing them would
    // touch the contract's exported ABI.
    #[allow(clippy::needless_pass_by_value)]
    pub fn initiate_recovery(
        env: Env,
        account: Address,
        new_pubkey: BytesN<65>,
        nonce: u64,
        timelock_secs: u32,
        root: BytesN<32>,
        nullifier: BytesN<32>,
        proof: Bytes,
    ) -> u64 {
        let cfg = config(&env);
        let now = env.ledger().timestamp();

        // 1. No live pending -- a pending past its `expires_at` is
        // stale/supersedable, not blocking. Superseding a stale pending must
        // also release its nullifier reservation: `N = Poseidon2(DOM_NULL,
        // account, secret)` is deterministic per (account, secret) with no
        // nonce, so without this release the next `initiate_recovery` for
        // this account would recompute the SAME `N`, find it still
        // `Reserved` in step 3 below, and panic `NullifierReserved` --
        // permanently bricking recovery for the account after any single
        // expired attempt. Only release on the STALE path (a LIVE pending
        // still panics `PendingExists`, unchanged), and only when the
        // reservation is still `Reserved(account)` -- a `Spent` nullifier
        // (already permanently consumed by a completion) is deliberately
        // left untouched.
        let pending_key = RecoveryKey::Pending(account.clone());
        if let Some(existing) = env
            .storage()
            .persistent()
            .get::<_, PendingRecovery>(&pending_key)
        {
            if now < existing.expires_at {
                panic_with_error!(&env, RecoveryError::PendingExists);
            }
            release_reservation_if_owned(&env, &existing.nullifier, &account);
        }

        // 2. `root` must be a currently-known Merkle root.
        if !is_known_root(&env, &root) {
            panic_with_error!(&env, RecoveryError::UnknownRoot);
        }

        // 3. `nullifier` must not already be reserved or spent.
        let nullifier_key = RecoveryKey::Nullifier(nullifier.clone());
        if let Some(state) = env
            .storage()
            .persistent()
            .get::<_, NullifierState>(&nullifier_key)
        {
            match state {
                NullifierState::Reserved(_) => {
                    panic_with_error!(&env, RecoveryError::NullifierReserved)
                }
                NullifierState::Spent => panic_with_error!(&env, RecoveryError::NullifierSpent),
            }
        }

        // 4. `nonce` must be exactly one past the stored value; bump it.
        let expected_nonce = stored_nonce(&env, &account) + 1;
        if nonce != expected_nonce {
            panic_with_error!(&env, RecoveryError::InvalidNonce);
        }
        bump_nonce(&env, &account, nonce);

        // 5. `timelock_secs` must meet the floor and match the configured
        // delay exactly.
        if u64::from(timelock_secs) < cfg.timelock_floor_secs {
            panic_with_error!(&env, RecoveryError::TimelockTooShort);
        }
        if u64::from(timelock_secs) != cfg.delay_secs {
            panic_with_error!(&env, RecoveryError::TimelockMismatch);
        }

        // 6. Rate limit: <= 3 initiations per rolling 90-day window.
        check_rate_limit(&env, &account, now);

        // 7. Recompute auth_hash from THIS call's own arguments (not
        // trusted from the caller) and verify the real proof against it --
        // this is what binds the proof to these exact arguments.
        let expected_auth_hash = compute_auth_hash(
            &env,
            ACTION_INITIATE,
            &account,
            &cfg.network_passphrase,
            &env.current_contract_address(),
            &new_pubkey,
            nonce,
            timelock_secs,
        );
        let public_inputs = assemble_public_inputs(&env, &root, &nullifier, &expected_auth_hash);
        if verify_proof(&env, &cfg.verifier, &public_inputs, &proof).is_err() {
            panic_with_error!(&env, RecoveryError::VerificationFailed);
        }

        // 8. Reserve the nullifier and store the pending record.
        env.storage()
            .persistent()
            .set(&nullifier_key, &NullifierState::Reserved(account.clone()));
        extend_persistent_max(&env, &nullifier_key);

        let executable_after = now + cfg.delay_secs;
        let expires_at = executable_after + cfg.completion_window_secs;
        let pending = PendingRecovery {
            new_pubkey: new_pubkey.clone(),
            nullifier,
            initiated_at: now,
            executable_after,
            expires_at,
        };
        env.storage().persistent().set(&pending_key, &pending);
        extend_persistent_max(&env, &pending_key);

        let new_pubkey_hash = env
            .crypto()
            .sha256(&Bytes::from_array(&env, &new_pubkey.to_array()))
            .to_bytes();
        RecoveryInitiated {
            account: &account,
            new_pubkey_hash: &new_pubkey_hash,
            executable_after: &executable_after,
        }
        .publish(&env);

        // 9. Return `executable_after`.
        executable_after
    }

    /// View: the live-or-stale pending recovery record for `account`, if
    /// any. Callers wanting strictly-live semantics should compare
    /// `expires_at` against the current ledger timestamp themselves.
    #[must_use]
    // `env` is conventionally by-value for `#[contractimpl]` entry points.
    #[allow(clippy::needless_pass_by_value)]
    pub fn get_pending(env: Env, account: Address) -> Option<PendingRecovery> {
        env.storage()
            .persistent()
            .get(&RecoveryKey::Pending(account))
    }

    /// View: `true` iff a LIVE pending recovery exists for `account` (has
    /// NOT yet crossed `expires_at`). This is the cheap boolean signal the
    /// smart-account in-account guard (spec §3.2,
    /// `contracts/smart-account/src/contract.rs::guard_no_pending`)
    /// cross-calls before allowing `remove_signer`/`remove_context_rule`/
    /// `remove_policy`/`update_context_rule_valid_until` -- a plain `bool`
    /// avoids needing to decode the full `PendingRecovery` struct
    /// cross-contract just to check liveness. A pending past `expires_at` is
    /// stale/supersedable (see `initiate_recovery`'s step 1 comment above)
    /// and this returns `false` for it, exactly as if there were no pending
    /// at all -- callers wanting the stale-or-live record itself should use
    /// `get_pending` and compare `expires_at` themselves.
    #[must_use]
    // `env` is conventionally by-value for `#[contractimpl]` entry points.
    #[allow(clippy::needless_pass_by_value)]
    pub fn has_pending(env: Env, account: Address) -> bool {
        let now = env.ledger().timestamp();
        env.storage()
            .persistent()
            .get::<_, PendingRecovery>(&RecoveryKey::Pending(account))
            .is_some_and(|pending| now < pending.expires_at)
    }

    /// View: the next nonce `initiate_recovery` will accept for `account`.
    #[must_use]
    // `env`/`account` are conventionally by-value for `#[contractimpl]`
    // entry points.
    #[allow(clippy::needless_pass_by_value)]
    pub fn next_nonce(env: Env, account: Address) -> u64 {
        stored_nonce(&env, &account) + 1
    }

    /// View: how many cancels `account` has used against its `max_cancels`
    /// cap (spec §2.4).
    #[must_use]
    // `env`/`account` are conventionally by-value for `#[contractimpl]`
    // entry points.
    #[allow(clippy::needless_pass_by_value)]
    pub fn cancels_used(env: Env, account: Address) -> u32 {
        cancels_used(&env, &account)
    }

    /// The legitimate owner's defense against a malicious/stale recovery in
    /// flight (spec §2.4, §3.3): stops the pending recovery during its
    /// timelock. Requires `account`'s own auth (the `WebAuthn` passkey signer
    /// in production) -- exactly what an attacker who only knows a leaked
    /// enrollment secret CANNOT provide, since a cancel does not consume
    /// that secret's nullifier (it stays usable, only the pending record and
    /// its nullifier RESERVATION are cleared).
    ///
    /// Ordered checks, mirroring `initiate_recovery`'s style: (1) account
    /// auth, (2) a live pending must exist, (3) the per-account cancel cap
    /// must not be reached, (4) a 24h cooldown since the last successful
    /// cancel must have elapsed, (5) `nonce` must be exactly one past the
    /// stored value (bumped on success), (6) a REAL `action=2` proof -- with
    /// the pubkey/timelock fields ZEROED per spec §2.4 -- must verify
    /// against this call's own recomputed `auth_hash` and a known root.
    #[must_use]
    // `env`/`account`/`root`/`nullifier`/`proof` are conventionally by-value
    // for `#[contractimpl]` entry points in this codebase; changing them
    // would touch the contract's exported ABI.
    #[allow(clippy::needless_pass_by_value)]
    pub fn cancel_recovery(
        env: Env,
        account: Address,
        nonce: u64,
        root: BytesN<32>,
        nullifier: BytesN<32>,
        proof: Bytes,
    ) -> u32 {
        account.require_auth();

        let cfg = config(&env);
        let now = env.ledger().timestamp();

        // 1. A live pending must exist -- a stale one (now >= expires_at) is
        // nothing left to cancel.
        let pending_key = RecoveryKey::Pending(account.clone());
        let pending = env
            .storage()
            .persistent()
            .get::<_, PendingRecovery>(&pending_key)
            .filter(|p| now < p.expires_at)
            .unwrap_or_else(|| panic_with_error!(&env, RecoveryError::NoPending));

        // 2. Cancel cap.
        let used = cancels_used(&env, &account);
        if used >= cfg.max_cancels {
            panic_with_error!(&env, RecoveryError::CancelCapReached);
        }

        // 3. Cooldown since the last successful cancel (first cancel has no
        // prior, always allowed).
        let last_cancel_key = RecoveryKey::LastCancel(account.clone());
        if let Some(last) = env.storage().persistent().get::<_, u64>(&last_cancel_key) {
            if now.saturating_sub(last) < CANCEL_COOLDOWN_SECS {
                panic_with_error!(&env, RecoveryError::CooldownActive);
            }
        }

        // 4. `nonce` must be exactly one past the stored value; bump it (a
        // fresh proof per cancel, replay-protected exactly like
        // `initiate_recovery`).
        let expected_nonce = stored_nonce(&env, &account) + 1;
        if nonce != expected_nonce {
            panic_with_error!(&env, RecoveryError::InvalidNonce);
        }
        bump_nonce(&env, &account, nonce);

        // 5. `root` must be known, and a REAL proof must verify against the
        // CANCEL auth_hash this call recomputes itself: `action=2`, pubkey
        // and timelock ZEROED per spec §2.4 (a cancel proves "I authorize
        // stopping this recovery", not "install this key").
        if !is_known_root(&env, &root) {
            panic_with_error!(&env, RecoveryError::UnknownRoot);
        }
        let zero_pubkey = BytesN::from_array(&env, &[0u8; 65]);
        let expected_auth_hash = compute_auth_hash(
            &env,
            ACTION_CANCEL,
            &account,
            &cfg.network_passphrase,
            &env.current_contract_address(),
            &zero_pubkey,
            nonce,
            0,
        );
        let public_inputs = assemble_public_inputs(&env, &root, &nullifier, &expected_auth_hash);
        if verify_proof(&env, &cfg.verifier, &public_inputs, &proof).is_err() {
            panic_with_error!(&env, RecoveryError::VerificationFailed);
        }

        // 6. Success: release the pending's nullifier reservation (the
        // enrollment secret stays usable -- cancel never burns it), delete
        // the pending record, bump the cancel counter + cooldown timestamp,
        // and emit.
        release_reservation_if_owned(&env, &pending.nullifier, &account);
        env.storage().persistent().remove(&pending_key);

        let new_used = used + 1;
        let cancels_key = RecoveryKey::Cancels(account.clone());
        env.storage().persistent().set(&cancels_key, &new_used);
        extend_persistent_max(&env, &cancels_key);
        env.storage().persistent().set(&last_cancel_key, &now);
        extend_persistent_max(&env, &last_cancel_key);

        RecoveryCanceled {
            account: &account,
            cancels_used: &new_used,
        }
        .publish(&env);

        new_used
    }

    /// The legitimate owner's proof-gated REVOKE for a (possibly leaked)
    /// enrollment secret (spec §2.3): a REAL `action=3` proof of knowledge of
    /// the secret behind `nullifier`'s Merkle leaf permanently spends it, so
    /// a later `initiate_recovery` attempt with the same nullifier fails
    /// `NullifierSpent` -- even one from an attacker who legitimately knows
    /// the leaked secret. Requires BOTH `account`'s own auth AND the proof,
    /// analogous to how `cancel_recovery` requires an `action=2` proof.
    ///
    /// Why account-auth alone is not enough (the pre-fix shape of this
    /// function): `nullifier` becomes PUBLIC the moment any
    /// `initiate_recovery` reveals it as a proof public input, and a
    /// `cancel_recovery` RELEASES its reservation while it stays public. So
    /// after a legitimate cancel, ANY third party could call
    /// `burn_nullifier(their_own_account, victim_nullifier)` and permanently
    /// kill the victim's enrollment credential -- violating spec §2.3 ("a
    /// cancel never burns the enrollment"). Since `nullifier` is public,
    /// only PROVING knowledge of the secret behind it distinguishes the
    /// legitimate owner from a griefer, exactly like `cancel_recovery`
    /// proof-gates stopping a pending recovery.
    ///
    /// Ordered checks: (1) account auth, (2) `root` must be a currently-
    /// known Merkle root (the leaf must be in the tree -- proves an enrolled
    /// credential), (3) `nonce` must be exactly one past the stored value
    /// (bumped on success -- shared nonce counter with
    /// `initiate_recovery`/`cancel_recovery`), (4) the nullifier must not
    /// already be `Spent` (burning twice is a no-op error -- a nullifier
    /// currently `Reserved`, by this account or any other, is still a valid
    /// burn TARGET at this state-check step, because step 5's proof is what
    /// actually enforces ownership), (5) a REAL `action=3` proof -- with the
    /// pubkey/timelock fields ZEROED, same convention as `cancel_recovery`'s
    /// `action=2` proof (spec §2.4) -- must verify against this call's own
    /// recomputed `auth_hash`.
    ///
    /// Note on the removed `NullifierReservedElsewhere` guard (spec §2.3, M1
    /// Task 6): the circuit's `acct_hi`/`acct_lo` witness is the SAME value
    /// used to derive the Merkle leaf, the nullifier, AND `auth_hash`
    /// (`circuits/zk_recovery/src/main.nr`). A verifying proof is bound to
    /// the exact `(root, nullifier, auth_hash)` triple it was generated
    /// for, and `auth_hash` here is recomputed from THIS call's `account`
    /// argument -- so a caller cannot swap in a foreign `account` and reuse
    /// someone else's public `nullifier`/`root`: the recomputed `auth_hash`
    /// no longer matches the one the proof was generated against (a
    /// griefer would additionally need to find a different secret whose
    /// nullifier collides with the victim's under a fresh proof of their
    /// own, a Poseidon2 preimage attack, not a real capability). The state
    /// guard is therefore no longer load-bearing and is not reinstated
    /// here -- ownership is enforced entirely by the proof, exactly like
    /// `cancel_recovery`.
    ///
    /// On success: also clears `account`'s `Pending` record if it was
    /// reserving exactly this nullifier -- revoking aborts an in-flight
    /// recovery for that credential too, since there is nothing left to
    /// complete once its enrollment secret is dead.
    // `env`/`account`/`root`/`nullifier`/`proof` are conventionally by-value
    // for `#[contractimpl]` entry points in this codebase; changing them
    // would touch the contract's exported ABI.
    #[allow(clippy::needless_pass_by_value)]
    pub fn burn_nullifier(
        env: Env,
        account: Address,
        nonce: u64,
        root: BytesN<32>,
        nullifier: BytesN<32>,
        proof: Bytes,
    ) {
        account.require_auth();

        let cfg = config(&env);

        // 2. `root` must be a currently-known Merkle root.
        if !is_known_root(&env, &root) {
            panic_with_error!(&env, RecoveryError::UnknownRoot);
        }

        // 3. `nonce` must be exactly one past the stored value; bump it (a
        // fresh proof per revoke, replay-protected exactly like
        // `initiate_recovery`/`cancel_recovery`, sharing the same counter).
        let expected_nonce = stored_nonce(&env, &account) + 1;
        if nonce != expected_nonce {
            panic_with_error!(&env, RecoveryError::InvalidNonce);
        }
        bump_nonce(&env, &account, nonce);

        // 4. Already-`Spent` is a no-op error; `Reserved` (by anyone) or
        // absent are both valid burn targets at this state-check step --
        // ownership is enforced by step 5's proof, not by state here.
        let nullifier_key = RecoveryKey::Nullifier(nullifier.clone());
        if let Some(NullifierState::Spent) = env
            .storage()
            .persistent()
            .get::<_, NullifierState>(&nullifier_key)
        {
            panic_with_error!(&env, RecoveryError::NullifierSpent);
        }

        // 5. A REAL proof must verify against the REVOKE auth_hash this call
        // recomputes itself: `action=3`, pubkey and timelock ZEROED per the
        // same convention as `cancel_recovery`'s `action=2` proof (spec
        // §2.4). This is what actually proves ownership of the nullifier's
        // secret -- see the note above.
        let zero_pubkey = BytesN::from_array(&env, &[0u8; 65]);
        let expected_auth_hash = compute_auth_hash(
            &env,
            ACTION_REVOKE,
            &account,
            &cfg.network_passphrase,
            &env.current_contract_address(),
            &zero_pubkey,
            nonce,
            0,
        );
        let public_inputs = assemble_public_inputs(&env, &root, &nullifier, &expected_auth_hash);
        if verify_proof(&env, &cfg.verifier, &public_inputs, &proof).is_err() {
            panic_with_error!(&env, RecoveryError::VerificationFailed);
        }

        // 6. Success: revoking also aborts an in-flight recovery for this
        // credential -- if `account`'s Pending was reserving exactly this
        // nullifier, clear it (there is nothing left to complete once the
        // reserved secret's nullifier is permanently `Spent`).
        let pending_key = RecoveryKey::Pending(account.clone());
        if let Some(pending) = env
            .storage()
            .persistent()
            .get::<_, PendingRecovery>(&pending_key)
        {
            if pending.nullifier == nullifier {
                env.storage().persistent().remove(&pending_key);
            }
        }

        env.storage()
            .persistent()
            .set(&nullifier_key, &NullifierState::Spent);
        extend_persistent_max(&env, &nullifier_key);

        NullifierBurned {
            account: &account,
            nullifier: &nullifier,
        }
        .publish(&env);
    }
}

#[cfg(test)]
mod has_pending_tests {
    //! `has_pending` in isolation (no real proof needed): a `PendingRecovery`
    //! is written directly into persistent storage, sidestepping
    //! `initiate_recovery`'s proof-verification cross-call entirely --
    //! `has_pending` itself doesn't care how the record got there, only
    //! whether `now < expires_at`.
    use super::*;
    use crate::pool::{ZkRecovery, ZkRecoveryClient};
    use soroban_sdk::testutils::{Address as _, Ledger as _};
    use soroban_sdk::{Address, Bytes, Env};

    fn deploy(env: &Env) -> Address {
        let factory = Address::generate(env);
        let verifier = Address::generate(env);
        let webauthn_verifier = Address::generate(env);
        env.register(
            ZkRecovery,
            (
                factory,
                verifier,
                3 * 24 * 3600_u64,
                7 * 24 * 3600_u64,
                3_u32,
                24 * 3600_u64,
                Bytes::from_slice(env, b"Test SDF Network ; September 2015"),
                webauthn_verifier,
                Address::generate(env), // upgrade admin (unused by this file's coverage)
            ),
        )
    }

    fn store_pending(env: &Env, id: &Address, account: &Address, expires_at: u64) {
        let now = env.ledger().timestamp();
        let pending = PendingRecovery {
            new_pubkey: BytesN::from_array(env, &[0u8; 65]),
            nullifier: BytesN::from_array(env, &[0u8; 32]),
            initiated_at: now,
            executable_after: now,
            expires_at,
        };
        env.as_contract(id, || {
            env.storage()
                .persistent()
                .set(&RecoveryKey::Pending(account.clone()), &pending);
        });
    }

    /// No pending record at all -> `false`.
    #[test]
    fn no_pending_is_false() {
        let env = Env::default();
        let id = deploy(&env);
        let account = Address::generate(&env);
        let client = ZkRecoveryClient::new(&env, &id);

        assert!(!client.has_pending(&account));
    }

    /// A pending whose `expires_at` is still in the future -> `true`.
    #[test]
    fn live_pending_is_true() {
        let env = Env::default();
        let id = deploy(&env);
        let account = Address::generate(&env);
        let client = ZkRecoveryClient::new(&env, &id);

        let now = env.ledger().timestamp();
        store_pending(&env, &id, &account, now + 1_000);

        assert!(client.has_pending(&account));
    }

    /// A pending whose `expires_at` has already passed -> `false` (a stale
    /// pending is supersedable, not a live/active recovery -- mirrors
    /// `initiate_recovery`'s own `now < existing.expires_at` liveness
    /// check).
    #[test]
    fn expired_pending_is_false() {
        let env = Env::default();
        let id = deploy(&env);
        let account = Address::generate(&env);
        let client = ZkRecoveryClient::new(&env, &id);

        let now = env.ledger().timestamp();
        store_pending(&env, &id, &account, now + 1_000);
        assert!(client.has_pending(&account), "sanity: starts live");

        env.ledger().with_mut(|l| l.timestamp = now + 1_001);

        assert!(!client.has_pending(&account));
    }
}
