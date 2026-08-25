//! Multisig policy contract — thin wrapper around `OpenZeppelin`'s
//! `simple_threshold` library. Stateless per-deployment; per-`(account,
//! rule_id)` threshold lives in the contract's persistent storage as managed
//! by the library.

use admin_sep::{Administratable, Upgradable};
use soroban_sdk::auth::Context;
use soroban_sdk::{contract, contractimpl, Address, Env, Vec};
use stellar_accounts::policies::simple_threshold::{self, SimpleThresholdAccountParams};
use stellar_accounts::policies::Policy;
use stellar_accounts::smart_account::{ContextRule, Signer};

#[contract]
pub struct MultisigPolicy;

// Governance (issue #26): admin/set_admin/upgrade come from the shared
// `admin-sep` crate (`Administratable` + `Upgradable`), replacing the inlined
// boilerplate. The `enforce`/`install`/`uninstall` paths never read admin, so
// per-account policy state and gas are unaffected. Mainnet intent (plan B1):
// `admin` is a multisig, ideally behind an upgrade timelock.
#[contractimpl(contracttrait)]
impl Administratable for MultisigPolicy {}

#[contractimpl(contracttrait)]
impl Upgradable for MultisigPolicy {}

#[contractimpl]
impl MultisigPolicy {
    /// Record the `admin` (mainnet: multisig, ideally behind an upgrade
    /// timelock) authorized to rotate the admin or upgrade this policy (issue
    /// #26). `set_admin` on first call (no admin yet) skips the auth check.
    #[allow(clippy::needless_pass_by_value)]
    pub fn __constructor(e: Env, admin: Address) {
        Self::set_admin(&e, admin);
    }

    /// Read the installed M-of-N threshold for a given account + rule.
    /// Returns 0 if not installed.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn get_threshold(e: &Env, context_rule_id: u32, smart_account: Address) -> u32 {
        simple_threshold::get_threshold(e, context_rule_id, &smart_account)
    }
}

#[contractimpl]
impl Policy for MultisigPolicy {
    type AccountParams = SimpleThresholdAccountParams;

    // OZ v0.7+ removed `can_enforce` from the Policy trait; `enforce` is now
    // the only validation step (it panics on threshold-not-met).
    fn enforce(
        e: &Env,
        context: Context,
        authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        simple_threshold::enforce(
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
        simple_threshold::install(e, &install_params, &context_rule, &smart_account);
    }

    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        simple_threshold::uninstall(e, &context_rule, &smart_account);
    }
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
        let id = env.register(MultisigPolicy, (admin.clone(),));
        let client = MultisigPolicyClient::new(&env, &id);

        assert_eq!(client.admin(), admin);

        let new_admin = Address::generate(&env);
        client.set_admin(&new_admin);
        assert_eq!(client.admin(), new_admin);
    }

    #[test]
    fn install_stores_threshold_per_account_rule() {
        let env = Env::default();
        let policy_addr = env.register(MultisigPolicy, (Address::generate(&env),));
        let account = Address::generate(&env);
        let rule_id = 7u32;
        let threshold = 2u32;

        env.mock_all_auths();

        // Synthesize a ContextRule (the smart account would pass one in real use).
        // The library validates threshold <= signers.len(), so we need enough signers.
        let mut signers = Vec::new(&env);
        signers.push_back(Signer::Delegated(Address::generate(&env)));
        signers.push_back(Signer::Delegated(Address::generate(&env)));
        signers.push_back(Signer::Delegated(Address::generate(&env)));
        // OZ v0.7 added signer_ids/policy_ids vectors aligned by index with
        // signers/policies. Synthetic IDs are fine — install doesn't read them.
        let mut signer_ids = Vec::new(&env);
        signer_ids.push_back(0u32);
        signer_ids.push_back(1u32);
        signer_ids.push_back(2u32);
        let rule = ContextRule {
            id: rule_id,
            context_type: ContextRuleType::Default,
            name: String::from_str(&env, "test"),
            signers,
            signer_ids,
            policies: Vec::new(&env),
            policy_ids: Vec::new(&env),
            valid_until: None,
        };

        env.as_contract(&policy_addr, || {
            MultisigPolicy::install(
                &env,
                SimpleThresholdAccountParams { threshold },
                rule.clone(),
                account.clone(),
            );
            let stored = MultisigPolicy::get_threshold(&env, rule_id, account);
            assert_eq!(stored, threshold);
        });
    }
}
