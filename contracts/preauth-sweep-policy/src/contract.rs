//! # Preauthorized-sweep policy (permissionless)
//!
//! A minimal `OpenZeppelin` `Policy` that authorizes *exactly one thing* on a
//! Nido smart account **C** and nothing else: pulling a recorded onboarding
//! account **G**'s balance into C via a Stellar Asset Contract (SAC)
//! `transfer_from(spender = C, from = G, to = C, amount)`.
//!
//! ## Intentionally permissionless — the bound IS the security argument
//!
//! The sweep rule is installed with **NO signers**. The policy authorizes the
//! sweep with an empty signer set, so **anyone** (typically an off-chain
//! watcher/relayer) may invoke it with **zero signatures**. This is deliberate
//! and maximizes liveness: no sweep key exists to lose, leak, or wire wrong.
//!
//! Permissionlessness is safe because the call is *provably bounded* to
//! `G -> C`. Whoever triggers the sweep, funds can only ever move FROM the one
//! recorded G INTO C — no other source, destination, spender, or function is
//! reachable. The security guarantee is the bound below, not a signature.
//!
//! ## Why a policy rather than a native account method
//!
//! OZ's context-rule machinery scopes a rule to a whole *contract*
//! (`ContextRuleType::CallContract(sac)`), never to a single *function*. A bare
//! `CallContract(sac)` rule would therefore permit ANY SAC method (`transfer`,
//! `approve`, `burn`, or `transfer_from` with any `to`). Function- and
//! argument-level narrowing is only achievable inside a policy's `enforce`,
//! which DOES receive the invocation `Context` (contract, `fn_name`, `args`).
//! This contract reads `transfer_from`'s `(spender, from, to, amount)` arguments
//! straight out of that Context and panics unless
//! `spender == C && from == recorded G && to == C`. It leaves the core
//! smart-account and factory contracts completely untouched, and is
//! independently deployable.
//!
//! ## The bound (the entire security claim)
//!
//! The rule is created with no signers and one policy (this one), scoped to
//! `CallContract(sac)`. Two independent layers combine so the *only* thing this
//! rule can authorize — for anyone, with no signature — is exactly the sweep:
//!
//! 1. **Rule scope** — the rule is `CallContract(sac)`, so `do_check_auth`
//!    rejects any other contract *before* this policy runs
//!    (`UnvalidatedContext`).
//! 2. **Policy `enforce`** — panics unless the call is precisely
//!    `transfer_from(spender = C, from = stored G, to = C)`:
//!    - wrong spender (`spender != C`)  -> [`SweepError::WrongSpender`]
//!    - wrong source  (`from != G`)     -> [`SweepError::WrongSource`]
//!    - wrong destination (`to != C`)   -> [`SweepError::WrongDestination`]
//!    - any other function              -> [`SweepError::NotTransferFrom`]
//!
//! ## Deployer wiring invariants (NOT enforced on-chain here)
//!
//! These are the caller's responsibility when constructing the context rule; the
//! policy cannot verify them from inside `enforce`:
//!
//! - The context rule MUST be `CallContract(sac)` for the specific token being
//!   swept (`install` refuses any other rule type — see
//!   [`SweepError::OnlyCallContract`]). Use one rule per SAC, each with its own
//!   recorded source.
//! - The rule SHOULD carry no signers (the permissionless posture). The empty
//!   signer set is what makes the sweep triggerable by any party; it is safe
//!   only because the bound above pins every degree of freedom.
//! - `context_rule.valid_until` SHOULD be set by the caller to the allowance's
//!   expiry ledger so a stale sweep capability cannot outlive the allowance
//!   window. This is a rule-construction responsibility; `enforce` does not
//!   inspect `valid_until` (OZ's `do_check_auth` already rejects an expired
//!   rule upstream).
//!
//! ## Amount is uncapped by the policy
//!
//! `enforce` requires only `amount >= 0`; the transferable magnitude is capped
//! entirely off-chain by the allowance C holds over G. Whatever the amount,
//! funds can only ever land in C (`to == C`). "Sweep the full balance only" is
//! an off-chain (relayer) choice, not a guarantee this policy makes.

use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, Address, Env, Symbol,
    TryFromVal, Vec,
};
use stellar_accounts::policies::Policy;
use stellar_accounts::smart_account::{ContextRule, ContextRuleType, Signer};

/// Installation parameters: the single classic account **G** whose balance this
/// rule may sweep FROM. Recorded at install time and immutable thereafter
/// except via uninstall/reinstall (both smart-account-authorized).
#[contracttype]
#[derive(Clone)]
pub struct PreauthSweepParams {
    /// The onboarding source account G. `transfer_from`'s `from` arg must equal
    /// this exactly.
    pub source: Address,
}

/// Per-(account, rule) storage key holding the recorded source G.
#[contracttype]
pub enum SweepStorageKey {
    /// `(smart_account, context_rule_id) -> source G`
    AccountContext(Address, u32),
}

/// Error codes. Distinct per rejection reason so callers (and tests) can assert
/// a sweep was blocked for the RIGHT reason, not by an incidental failure.
#[contracterror]
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SweepError {
    /// No sweep policy installed for this (account, rule).
    NotInstalled = 1,
    /// A sweep policy is already installed for this (account, rule).
    AlreadyInstalled = 2,
    /// Reserved. Formerly signalled "no signer authenticated". The sweep is now
    /// intentionally permissionless (authorized with an empty signer set), so no
    /// code path emits this. Kept to freeze the error-code space (`= 3`) so the
    /// remaining discriminants below never renumber.
    NoSigner = 3,
    /// `from` argument != the recorded source G.
    WrongSource = 4,
    /// `to` argument != the smart account C.
    WrongDestination = 5,
    /// The invoked function is not `transfer_from`.
    NotTransferFrom = 6,
    /// Rule is not `CallContract(sac)` — refuse to pin an unscoped rule.
    OnlyCallContract = 7,
    /// A `transfer_from` argument was missing or the wrong type.
    MalformedArgs = 8,
    /// Negative amount.
    NegativeAmount = 9,
    /// `spender` argument != the smart account C.
    WrongSpender = 10,
}

#[contract]
pub struct PreauthSweepPolicy;

#[contractimpl]
impl PreauthSweepPolicy {
    /// Read the recorded source G for a given (account, rule). `None` if not
    /// installed. Lets a relayer/SDK confirm what a rule is pinned to.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn get_source(e: &Env, context_rule_id: u32, smart_account: Address) -> Option<Address> {
        e.storage()
            .persistent()
            .get(&SweepStorageKey::AccountContext(
                smart_account,
                context_rule_id,
            ))
    }
}

#[contractimpl]
impl Policy for PreauthSweepPolicy {
    type AccountParams = PreauthSweepParams;

    /// Enforce the sweep bound. **Permissionless**: this runs with an empty
    /// `authenticated_signers` set (the rule carries no signers) and MUST still
    /// authorize a correctly-bounded `transfer_from(C, G, C, amount)`. Anyone may
    /// trigger it; the security argument is the bound checked below, not a
    /// signature.
    ///
    /// `authenticated_signers` is intentionally ignored: the sweep requires none.
    /// It stays in the signature because the OZ `Policy` trait fixes it.
    ///
    /// No `smart_account.require_auth()` here — deliberately. Requiring C to
    /// authorize would defeat the permissionless posture (it demands C's own
    /// passkey signature, exactly what this design removes). Unlike a stateful
    /// policy (e.g. spending-limit, which needs `require_auth` to gate a mutable
    /// counter), this `enforce` mutates NO state — it only reads the recorded
    /// source and the invocation args — so dropping the guard is safe: there is
    /// nothing to protect from an unauthorized caller, and the bound alone
    /// constrains the outcome to `G -> C`.
    #[allow(clippy::needless_pass_by_value)]
    fn enforce(
        e: &Env,
        context: Context,
        authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        // Permissionless: the rule carries no signers, so this is expected to be
        // empty. We neither require nor inspect it — the bound is the barrier.
        let _ = authenticated_signers;

        let source: Address = e
            .storage()
            .persistent()
            .get(&SweepStorageKey::AccountContext(
                smart_account.clone(),
                context_rule.id,
            ))
            .unwrap_or_else(|| panic_with_error!(e, SweepError::NotInstalled));

        match context {
            Context::Contract(ContractContext { fn_name, args, .. }) => {
                // GOTCHA: "transfer_from" is 13 chars; `symbol_short!` caps at 9
                // and would not compile. Must use `Symbol::new`.
                if fn_name != Symbol::new(e, "transfer_from") {
                    panic_with_error!(e, SweepError::NotTransferFrom);
                }

                // SAC transfer_from(spender, from, to, amount):
                //   args[0]=spender(==C), args[1]=from, args[2]=to, args[3]=amount
                let spender = args
                    .get(0)
                    .and_then(|v| Address::try_from_val(e, &v).ok())
                    .unwrap_or_else(|| panic_with_error!(e, SweepError::MalformedArgs));
                let from = args
                    .get(1)
                    .and_then(|v| Address::try_from_val(e, &v).ok())
                    .unwrap_or_else(|| panic_with_error!(e, SweepError::MalformedArgs));
                let to = args
                    .get(2)
                    .and_then(|v| Address::try_from_val(e, &v).ok())
                    .unwrap_or_else(|| panic_with_error!(e, SweepError::MalformedArgs));
                let amount = args
                    .get(3)
                    .and_then(|v| i128::try_from_val(e, &v).ok())
                    .unwrap_or_else(|| panic_with_error!(e, SweepError::MalformedArgs));

                // Defense-in-depth: for a standard SAC only the spender is
                // `require_auth`'d, so `enforce` runs only when C is the spender
                // and this is unreachable. It hardens against a nonstandard
                // token (pinned at install) that authorizes a different party,
                // guaranteeing this rule can never front C's authority for a
                // pull initiated by anyone but C.
                if spender != smart_account {
                    panic_with_error!(e, SweepError::WrongSpender);
                }
                if from != source {
                    panic_with_error!(e, SweepError::WrongSource);
                }
                if to != smart_account {
                    panic_with_error!(e, SweepError::WrongDestination);
                }
                if amount < 0 {
                    panic_with_error!(e, SweepError::NegativeAmount);
                }
                // pass: exactly transfer_from(spender = C, from = G, to = C),
                // amount >= 0.
            }
            _ => panic_with_error!(e, SweepError::NotTransferFrom),
        }
    }

    fn install(
        e: &Env,
        install_params: Self::AccountParams,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();

        // Pin the rule to a single token contract. A Default rule would let the
        // sweep signer's rule match every contract; refuse it.
        if !matches!(context_rule.context_type, ContextRuleType::CallContract(_)) {
            panic_with_error!(e, SweepError::OnlyCallContract);
        }

        let key = SweepStorageKey::AccountContext(smart_account.clone(), context_rule.id);
        if e.storage().persistent().has(&key) {
            panic_with_error!(e, SweepError::AlreadyInstalled);
        }
        e.storage().persistent().set(&key, &install_params.source);
    }

    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        smart_account.require_auth();
        let key = SweepStorageKey::AccountContext(smart_account, context_rule.id);
        if !e.storage().persistent().has(&key) {
            panic_with_error!(e, SweepError::NotInstalled);
        }
        e.storage().persistent().remove(&key);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Env, String};

    /// Build a `ContextRule` literal the way the smart account would pass one
    /// in. All fields are required on the pinned OZ rev (v0.7 added the
    /// index-aligned `signer_ids`/`policy_ids`).
    fn rule(env: &Env, id: u32, context_type: ContextRuleType) -> ContextRule {
        let mut signers = Vec::new(env);
        signers.push_back(Signer::Delegated(Address::generate(env)));
        let mut signer_ids = Vec::new(env);
        signer_ids.push_back(0u32);
        ContextRule {
            id,
            context_type,
            name: String::from_str(env, "onboarding-sweep"),
            signers,
            signer_ids,
            policies: Vec::new(env),
            policy_ids: Vec::new(env),
            valid_until: None,
        }
    }

    #[test]
    fn install_stores_source_per_account_rule() {
        let env = Env::default();
        env.mock_all_auths();
        let policy_addr = env.register(PreauthSweepPolicy, ());
        let account = Address::generate(&env);
        let source_g = Address::generate(&env);
        let sac = Address::generate(&env);
        let rule_id = 1u32;
        let r = rule(&env, rule_id, ContextRuleType::CallContract(sac));

        env.as_contract(&policy_addr, || {
            assert_eq!(
                PreauthSweepPolicy::get_source(&env, rule_id, account.clone()),
                None
            );
            PreauthSweepPolicy::install(
                &env,
                PreauthSweepParams {
                    source: source_g.clone(),
                },
                r.clone(),
                account.clone(),
            );
            assert_eq!(
                PreauthSweepPolicy::get_source(&env, rule_id, account.clone()),
                Some(source_g)
            );
        });

        // Separate frame: a second require_auth in the same frame is rejected
        // by the host ("frame is already authorized").
        env.as_contract(&policy_addr, || {
            PreauthSweepPolicy::uninstall(&env, r, account.clone());
            assert_eq!(PreauthSweepPolicy::get_source(&env, rule_id, account), None);
        });
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #7)")]
    fn install_rejects_non_callcontract_rule() {
        let env = Env::default();
        env.mock_all_auths();
        let policy_addr = env.register(PreauthSweepPolicy, ());
        let account = Address::generate(&env);
        let source_g = Address::generate(&env);
        let r = rule(&env, 1u32, ContextRuleType::Default);

        env.as_contract(&policy_addr, || {
            PreauthSweepPolicy::install(&env, PreauthSweepParams { source: source_g }, r, account);
        });
    }
}
