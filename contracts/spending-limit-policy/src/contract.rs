//! Spending-limit policy contract — thin wrapper around `OpenZeppelin`'s
//! `spending_limit` library. Stateless per-deployment; per-`(account,
//! rule_id)` limit + rolling spending window live in this contract's
//! persistent storage as managed by the library. Meters SAC `transfer`
//! calls within `CallContract` contexts only.

use admin_sep::{Administratable, Upgradable};
use soroban_sdk::auth::Context;
use soroban_sdk::{contract, contractimpl, Address, Env, Vec};
use stellar_accounts::policies::spending_limit::{
    self, SpendingLimitAccountParams, SpendingLimitData, SpendingLimitStorageKey,
};
use stellar_accounts::policies::Policy;
use stellar_accounts::smart_account::{ContextRule, Signer};

#[contract]
pub struct SpendingLimitPolicy;

// Governance (issue #26): admin/set_admin/upgrade come from the shared
// `admin-sep` crate (`Administratable` + `Upgradable`), replacing the inlined
// boilerplate. The `enforce`/`install`/`uninstall` paths never read admin, so
// per-account limit state and gas are unaffected. Mainnet intent (plan B1):
// `admin` is a multisig, ideally behind an upgrade timelock.
#[contractimpl(contracttrait)]
impl Administratable for SpendingLimitPolicy {}

#[contractimpl(contracttrait)]
impl Upgradable for SpendingLimitPolicy {}

#[contractimpl]
impl SpendingLimitPolicy {
    /// Record the `admin` (mainnet: multisig, ideally behind an upgrade
    /// timelock) authorized to rotate the admin or upgrade this policy (issue
    /// #26). `set_admin` on first call (no admin yet) skips the auth check.
    #[allow(clippy::needless_pass_by_value)]
    pub fn __constructor(e: Env, admin: Address) {
        Self::set_admin(&e, admin);
    }

    /// Read the installed params for a given account + rule. Returns None if
    /// not installed. (The OZ lib's `get_spending_limit_data` panics when
    /// uninstalled; read its storage key directly instead. Archived entries
    /// fail at simulation and need restore.)
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn get_spending_limit(
        e: &Env,
        context_rule_id: u32,
        smart_account: Address,
    ) -> Option<SpendingLimitAccountParams> {
        spending_limit_params_for(e, context_rule_id, &smart_account)
    }

    /// Change the spending limit for an installed rule. Auth is enforced by
    /// the OZ lib (`smart_account.require_auth()`). Changing the limit this
    /// way preserves the rolling spending window, unlike uninstall/re-install
    /// which resets it.
    #[allow(clippy::needless_pass_by_value)]
    pub fn set_spending_limit(
        e: &Env,
        spending_limit: i128,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        spending_limit::set_spending_limit(e, spending_limit, &context_rule, &smart_account);
    }
}

#[contractimpl]
impl Policy for SpendingLimitPolicy {
    type AccountParams = SpendingLimitAccountParams;

    fn enforce(
        e: &Env,
        context: Context,
        authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        spending_limit::enforce(
            e,
            &context,
            &authenticated_signers,
            &context_rule,
            &smart_account,
        );
    }

    fn install(
        e: &Env,
        install_params: Self::AccountParams,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        spending_limit::install(e, &install_params, &context_rule, &smart_account);
    }

    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        spending_limit::uninstall(e, &context_rule, &smart_account);
    }
}

/// Read the OZ library's storage entry
/// (`SpendingLimitStorageKey::AccountContext(account, rule_id)` →
/// `SpendingLimitData`) and project it down to the install params. Both
/// types are `pub` at the pinned rev, so no parallel bookkeeping is needed.
/// Re-verify storage class/key construction in `spending_limit.rs` when
/// bumping the stellar-accounts rev (the one drift mode the compiler can't
/// catch).
fn spending_limit_params_for(
    e: &Env,
    context_rule_id: u32,
    smart_account: &Address,
) -> Option<SpendingLimitAccountParams> {
    let key = SpendingLimitStorageKey::AccountContext(smart_account.clone(), context_rule_id);
    e.storage()
        .persistent()
        .get::<_, SpendingLimitData>(&key)
        .map(|data| SpendingLimitAccountParams {
            spending_limit: data.spending_limit,
            period_ledgers: data.period_ledgers,
        })
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;
    use soroban_sdk::String;
    use stellar_accounts::smart_account::{ContextRuleType, Signer};

    /// Upgradability (issue #26): the constructor stores the `admin`, and
    /// `set_admin` rotates it under the current admin's auth.
    #[test]
    fn admin_is_stored_and_rotatable() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let id = env.register(SpendingLimitPolicy, (admin.clone(),));
        let client = SpendingLimitPolicyClient::new(&env, &id);

        assert_eq!(client.admin(), admin);

        let new_admin = Address::generate(&env);
        client.set_admin(&new_admin);
        assert_eq!(client.admin(), new_admin);
    }

    #[test]
    fn install_stores_params_per_account_rule() {
        let env = Env::default();
        let policy_addr = env.register(SpendingLimitPolicy, (Address::generate(&env),));
        let account = Address::generate(&env);
        let rule_id = 7u32;
        let params = SpendingLimitAccountParams {
            spending_limit: 50_000_000,
            period_ledgers: 17280,
        };

        env.mock_all_auths();

        // Synthesize a ContextRule (the smart account would pass one in real
        // use). The library only accepts `CallContract` context types — the
        // policy is pinned to a specific token contract.
        let mut signers = Vec::new(&env);
        signers.push_back(Signer::Delegated(Address::generate(&env)));
        // OZ v0.7 added signer_ids/policy_ids vectors aligned by index with
        // signers/policies. Synthetic IDs are fine — install doesn't read them.
        let mut signer_ids = Vec::new(&env);
        signer_ids.push_back(0u32);
        let rule = ContextRule {
            id: rule_id,
            context_type: ContextRuleType::CallContract(Address::generate(&env)),
            name: String::from_str(&env, "test"),
            signers,
            signer_ids,
            policies: Vec::new(&env),
            policy_ids: Vec::new(&env),
            valid_until: None,
        };

        env.as_contract(&policy_addr, || {
            assert_eq!(
                SpendingLimitPolicy::get_spending_limit(&env, rule_id, account.clone()),
                None
            );
            SpendingLimitPolicy::install(&env, params.clone(), rule.clone(), account.clone());
            let stored = SpendingLimitPolicy::get_spending_limit(&env, rule_id, account.clone());
            assert_eq!(stored, Some(params));
        });

        // Separate frame: a second require_auth in the same frame is rejected
        // by the host ("frame is already authorized").
        env.as_contract(&policy_addr, || {
            SpendingLimitPolicy::uninstall(&env, rule, account.clone());
            assert_eq!(
                SpendingLimitPolicy::get_spending_limit(&env, rule_id, account),
                None
            );
        });
    }
}
