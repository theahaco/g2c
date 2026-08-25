use admin_sep::{Administratable, Upgradable};
use soroban_sdk::{contract, contractimpl, Address, Env, String};
use soroban_sdk_tools::{contractstorage, PersistentMap};

#[contractstorage]
pub struct Registry {
    names: PersistentMap<String, Address>,
    owners: PersistentMap<Address, String>,
}

#[contract]
pub struct Contract;

// Governance (issue #26): admin/set_admin/upgrade come from the shared
// `admin-sep` crate (`Administratable` + `Upgradable`), replacing the inlined
// boilerplate. Name records are untouched by admin storage. Mainnet intent
// (plan B1): `admin` is a multisig, ideally behind an upgrade timelock.
#[contractimpl(contracttrait)]
impl Administratable for Contract {}

#[contractimpl(contracttrait)]
impl Upgradable for Contract {}

fn validate_name(e: &Env, name: &String) {
    let len = name.len() as usize;
    assert!((1..=15).contains(&len), "name must be 1-15 characters");

    let mut buf = [0u8; 15];
    name.copy_into_slice(&mut buf[..len]);

    assert!(buf[0].is_ascii_lowercase(), "name must start with a letter");

    for &b in &buf[..len] {
        assert!(
            b.is_ascii_lowercase() || b.is_ascii_digit(),
            "name must contain only a-z and 0-9"
        );
    }

    let _ = e;
}

#[contractimpl]
impl Contract {
    /// Record the `admin` (mainnet: multisig, ideally behind an upgrade
    /// timelock) authorized to rotate the admin or upgrade this registry
    /// (issue #26). Name records are untouched by admin storage. `set_admin`
    /// on first call (no admin yet) skips the auth check.
    #[allow(clippy::needless_pass_by_value)]
    pub fn __constructor(e: Env, admin: Address) {
        Self::set_admin(&e, admin);
    }

    /// Register a human-readable name for a smart account.
    /// The owner (smart account address) must authorize the call.
    pub fn register(e: &Env, owner: &Address, name: &String) {
        owner.require_auth();
        validate_name(e, name);

        let registry = Registry::new(e);

        assert!(registry.names.get(name).is_none(), "name already claimed");
        assert!(
            registry.owners.get(owner).is_none(),
            "address already has a name"
        );

        registry.names.set(name, owner);
        registry.owners.set(owner, name);
    }

    /// Release the name held by the owner, freeing it for others.
    pub fn release(e: &Env, owner: &Address) {
        owner.require_auth();

        let registry = Registry::new(e);
        let name = registry.owners.get(owner).expect("address has no name");

        registry.names.remove(&name);
        registry.owners.remove(owner);
    }

    /// Transfer the name from the current owner to a new address.
    /// Both addresses must authorize.
    pub fn transfer(e: &Env, owner: &Address, new_owner: &Address) {
        owner.require_auth();
        new_owner.require_auth();

        let registry = Registry::new(e);
        let name = registry.owners.get(owner).expect("address has no name");

        assert!(
            registry.owners.get(new_owner).is_none(),
            "new owner already has a name"
        );

        registry.names.set(&name, new_owner);
        registry.owners.remove(owner);
        registry.owners.set(new_owner, &name);
    }

    /// Resolve a name to its owner address. Returns `None` if unregistered.
    pub fn resolve(e: &Env, name: &String) -> Option<Address> {
        Registry::new(e).names.get(name)
    }

    /// Reverse lookup: get the name for a given address. Returns `None` if
    /// the address has no registered name.
    pub fn lookup(e: &Env, owner: &Address) -> Option<String> {
        Registry::new(e).owners.get(owner)
    }

    /// Extend the TTL of a name's storage entries. Can be called by anyone.
    pub fn extend_ttl(e: &Env, name: &String) {
        let registry = Registry::new(e);
        if let Some(owner) = registry.names.get(name) {
            registry.names.extend_ttl(name, 518_400, 518_400);
            registry.owners.extend_ttl(&owner, 518_400, 518_400);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;

    fn setup() -> (Env, ContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register(Contract, (Address::generate(&env),));
        let client = ContractClient::new(&env, &id);
        (env, client)
    }

    /// Upgradability (issue #26): the constructor stores the `admin`, and
    /// `set_admin` rotates it under the current admin's auth.
    #[test]
    fn admin_is_stored_and_rotatable() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let id = env.register(Contract, (admin.clone(),));
        let client = ContractClient::new(&env, &id);

        assert_eq!(client.admin(), admin);

        let new_admin = Address::generate(&env);
        client.set_admin(&new_admin);
        assert_eq!(client.admin(), new_admin);
    }

    #[test]
    fn register_and_resolve() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let name = String::from_str(&env, "alice");

        client.register(&owner, &name);

        assert_eq!(client.resolve(&name), Some(owner.clone()));
        assert_eq!(client.lookup(&owner), Some(name));
    }

    #[test]
    #[should_panic(expected = "name already claimed")]
    fn duplicate_name_rejected() {
        let (env, client) = setup();
        let a = Address::generate(&env);
        let b = Address::generate(&env);
        let name = String::from_str(&env, "alice");

        client.register(&a, &name);
        client.register(&b, &name);
    }

    #[test]
    #[should_panic(expected = "address already has a name")]
    fn duplicate_owner_rejected() {
        let (env, client) = setup();
        let owner = Address::generate(&env);

        client.register(&owner, &String::from_str(&env, "alice"));
        client.register(&owner, &String::from_str(&env, "bob"));
    }

    #[test]
    #[should_panic(expected = "name must be 1-15 characters")]
    fn empty_name_rejected() {
        let (env, client) = setup();
        client.register(&Address::generate(&env), &String::from_str(&env, ""));
    }

    #[test]
    #[should_panic(expected = "name must be 1-15 characters")]
    fn too_long_name_rejected() {
        let (env, client) = setup();
        client.register(
            &Address::generate(&env),
            &String::from_str(&env, "abcdefghijklmnop"), // 16 chars
        );
    }

    #[test]
    #[should_panic(expected = "name must start with a letter")]
    fn starts_with_digit_rejected() {
        let (env, client) = setup();
        client.register(&Address::generate(&env), &String::from_str(&env, "1alice"));
    }

    #[test]
    #[should_panic(expected = "name must start with a letter")]
    fn uppercase_rejected() {
        let (env, client) = setup();
        client.register(&Address::generate(&env), &String::from_str(&env, "Alice"));
    }

    #[test]
    #[should_panic(expected = "name must contain only a-z and 0-9")]
    fn uppercase_mid_rejected() {
        let (env, client) = setup();
        client.register(&Address::generate(&env), &String::from_str(&env, "aLice"));
    }

    #[test]
    #[should_panic(expected = "name must contain only a-z and 0-9")]
    fn hyphen_rejected() {
        let (env, client) = setup();
        client.register(
            &Address::generate(&env),
            &String::from_str(&env, "alice-bob"),
        );
    }

    #[test]
    fn release_frees_name() {
        let (env, client) = setup();
        let a = Address::generate(&env);
        let b = Address::generate(&env);
        let name = String::from_str(&env, "alice");

        client.register(&a, &name);
        client.release(&a);

        assert_eq!(client.resolve(&name), None);
        assert_eq!(client.lookup(&a), None);

        // Another address can now claim the same name.
        client.register(&b, &name);
        assert_eq!(client.resolve(&name), Some(b));
    }

    #[test]
    fn transfer_updates_both_maps() {
        let (env, client) = setup();
        let a = Address::generate(&env);
        let b = Address::generate(&env);
        let name = String::from_str(&env, "alice");

        client.register(&a, &name);
        client.transfer(&a, &b);

        assert_eq!(client.resolve(&name), Some(b.clone()));
        assert_eq!(client.lookup(&a), None);
        assert_eq!(client.lookup(&b), Some(name));
    }

    #[test]
    #[should_panic(expected = "new owner already has a name")]
    fn transfer_fails_if_target_has_name() {
        let (env, client) = setup();
        let a = Address::generate(&env);
        let b = Address::generate(&env);

        client.register(&a, &String::from_str(&env, "alice"));
        client.register(&b, &String::from_str(&env, "bob"));
        client.transfer(&a, &b);
    }

    #[test]
    fn resolve_nonexistent_returns_none() {
        let (env, client) = setup();
        assert_eq!(client.resolve(&String::from_str(&env, "nobody")), None);
    }

    #[test]
    fn lookup_nonexistent_returns_none() {
        let (env, client) = setup();
        assert_eq!(client.lookup(&Address::generate(&env)), None);
    }

    #[test]
    fn name_with_digits() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let name = String::from_str(&env, "alice42");

        client.register(&owner, &name);
        assert_eq!(client.resolve(&name), Some(owner));
    }

    #[test]
    fn single_char_name() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let name = String::from_str(&env, "a");

        client.register(&owner, &name);
        assert_eq!(client.resolve(&name), Some(owner));
    }

    #[test]
    fn max_length_name() {
        let (env, client) = setup();
        let owner = Address::generate(&env);
        let name = String::from_str(&env, "abcdefghijklmno"); // 15 chars

        client.register(&owner, &name);
        assert_eq!(client.resolve(&name), Some(owner));
    }
}
