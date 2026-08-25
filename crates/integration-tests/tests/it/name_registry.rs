use nido_integration_tests::deploy_smart_account;
use soroban_sdk::{testutils::Address as _, Address, Env, String};

const NAME_REGISTRY_WASM: &[u8] =
    include_bytes!("../../../../target/wasm32v1-none/contract/nido_name_registry.wasm");

#[allow(dead_code)]
#[soroban_sdk::contractclient(name = "NameRegistryClient")]
trait NameRegistryInterface {
    fn register(env: soroban_sdk::Env, owner: Address, name: String);
    fn resolve(env: soroban_sdk::Env, name: String) -> Option<Address>;
    fn lookup(env: soroban_sdk::Env, owner: Address) -> Option<String>;
    fn release(env: soroban_sdk::Env, owner: Address);
}

#[test]
fn register_name_via_smart_account() {
    let env = Env::default();
    env.mock_all_auths();

    let (_sa_client, account_addr, _verifier_addr, _signing_key) = deploy_smart_account(&env);

    let registry_addr = env.register(NAME_REGISTRY_WASM, (Address::generate(&env),));
    let registry = NameRegistryClient::new(&env, &registry_addr);

    let name = String::from_str(&env, "alice");
    registry.register(&account_addr, &name);

    assert_eq!(registry.resolve(&name), Some(account_addr.clone()));
    assert_eq!(registry.lookup(&account_addr), Some(name));
}

#[test]
fn resolve_unregistered_returns_none() {
    let env = Env::default();

    let registry_addr = env.register(NAME_REGISTRY_WASM, (Address::generate(&env),));
    let registry = NameRegistryClient::new(&env, &registry_addr);

    assert_eq!(registry.resolve(&String::from_str(&env, "nobody")), None);
}

#[test]
fn release_name_via_smart_account() {
    let env = Env::default();
    env.mock_all_auths();

    let (_sa_client, account_addr, _verifier_addr, _signing_key) = deploy_smart_account(&env);

    let registry_addr = env.register(NAME_REGISTRY_WASM, (Address::generate(&env),));
    let registry = NameRegistryClient::new(&env, &registry_addr);

    let name = String::from_str(&env, "bob");
    registry.register(&account_addr, &name);
    registry.release(&account_addr);

    assert_eq!(registry.resolve(&name), None);
    assert_eq!(registry.lookup(&account_addr), None);

    // Another account can now claim the released name.
    let other = Address::generate(&env);
    registry.register(&other, &name);
    assert_eq!(registry.resolve(&name), Some(other));
}
