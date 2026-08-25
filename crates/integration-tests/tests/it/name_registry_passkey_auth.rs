//! Full-stack auth test for the name-registry claim flow — NO `mock_all_auths`.
//!
//! The other name-registry tests (`name_registry.rs`) call `env.mock_all_auths()`,
//! which bypasses the smart account's `__check_auth` entirely. That is exactly
//! why "bug #3" escaped to the testnet e2e: nothing in-process exercised the real
//! authorization path for `register`.
//!
//! This test builds a genuine `SorobanAuthorizationEntry` carrying a synthetic
//! `WebAuthn` passkey assertion, computes the host's `signature_payload` from the
//! real `HashIdPreimage`, and drives `register` through the host via
//! `env.set_auths` (enforcing mode). The host derives the invocation `Context`,
//! computes the payload, and dispatches the account's `__check_auth` — the same
//! sequence the chain runs.
//!
//! It proves the contract auth-model authorizes the external `registry.register`
//! context under the Default rule (id 0) — refuting the earlier hypothesis that
//! bug #3 was a contract-side `UnvalidatedContext`. (The real cause was the
//! frontend finalize step; see `tests/e2e/testnet/account-lifecycle.testnet.spec.ts`.)

use nido_integration_tests::{build_contract_assertion, compute_auth_digest, deploy_smart_account};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::xdr::ToXdr as _;
use soroban_sdk::xdr::{
    Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Limits,
    ScAddress, ScSymbol, ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, VecM, WriteXdr,
};
use soroban_sdk::{Bytes, Env, IntoVal, Map, String, TryFromVal, Val};
use stellar_accounts::smart_account::{AuthPayload, Signer};
use stellar_accounts::verifiers::webauthn::WebAuthnSigData;

const NAME_REGISTRY_WASM: &[u8] =
    include_bytes!("../../../../target/wasm32v1-none/contract/nido_name_registry.wasm");

#[allow(dead_code)]
#[soroban_sdk::contractclient(name = "NameRegistryClient")]
trait NameRegistryInterface {
    fn register(env: soroban_sdk::Env, owner: soroban_sdk::Address, name: String);
    fn resolve(env: soroban_sdk::Env, name: String) -> Option<soroban_sdk::Address>;
}

/// Claim a name via the smart account, authorizing through the real host auth
/// path (no `mock_all_auths`). This is the in-process analogue of the testnet
/// passkey round-trip.
#[test]
fn register_name_with_real_passkey_auth() {
    let env = Env::default();
    let (_sa_client, account_addr, verifier_addr, signing_key) = deploy_smart_account(&env);

    let registry_addr = env.register(NAME_REGISTRY_WASM, (soroban_sdk::Address::generate(&env),));
    let registry = NameRegistryClient::new(&env, &registry_addr);

    let name = String::from_str(&env, "alice");

    // --- Build the authorized invocation: registry.register(account, name) ---
    let owner_scval = ScVal::Address(ScAddress::from(&account_addr));
    let name_val: Val = name.clone().into_val(&env);
    let name_scval = ScVal::try_from_val(&env, &name_val).unwrap();
    let args: VecM<ScVal> = std::vec![owner_scval, name_scval].try_into().unwrap();

    let invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::from(&registry_addr),
            function_name: ScSymbol("register".try_into().unwrap()),
            args,
        }),
        sub_invocations: VecM::default(),
    };

    // --- Compute the host's signature_payload from the real HashIdPreimage ---
    let nonce: i64 = 0xCAFE;
    let signature_expiration_ledger: u32 = 999_999;
    let network_id = Hash(env.ledger().network_id().to_array());

    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id,
        nonce,
        signature_expiration_ledger,
        invocation: invocation.clone(),
    });
    let preimage_bytes = preimage.to_xdr(Limits::none()).unwrap();
    let signature_payload = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, &preimage_bytes));

    // --- Sign the OZ v0.7 auth digest (binds context_rule_ids) with the passkey ---
    let context_rule_ids = soroban_sdk::vec![&env, 0u32]; // Default rule
    let auth_digest = compute_auth_digest(&env, &signature_payload, &context_rule_ids);
    let assertion = build_contract_assertion(&signing_key, &env, &auth_digest);

    let sig_data = WebAuthnSigData {
        signature: assertion.signature,
        authenticator_data: assertion.authenticator_data,
        client_data: assertion.client_data,
    };
    let pubkey_sec1 = signing_key.verifying_key().to_sec1_bytes();
    let signer = Signer::External(
        verifier_addr,
        soroban_sdk::Bytes::from_slice(&env, &pubkey_sec1),
    );
    let mut sig_map: Map<Signer, Bytes> = Map::new(&env);
    sig_map.set(signer, sig_data.to_xdr(&env));
    let auth_payload = AuthPayload {
        signers: sig_map,
        context_rule_ids,
    };

    // --- Assemble the SorobanAuthorizationEntry and enforce it on-chain ---
    let payload_val: Val = auth_payload.into_val(&env);
    let signature = ScVal::try_from_val(&env, &payload_val).unwrap();
    let entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: ScAddress::from(&account_addr),
            nonce,
            signature_expiration_ledger,
            signature,
        }),
        root_invocation: invocation,
    };

    env.set_auths(&[entry]);
    registry.register(&account_addr, &name);

    assert_eq!(registry.resolve(&name), Some(account_addr));
}
