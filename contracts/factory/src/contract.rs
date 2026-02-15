// The `ref_option` lint is triggered by Soroban SDK macro-generated code
// (contractclient/contractargs) for `Option<u32>` parameters, not by our code.
#![allow(clippy::ref_option)]

use soroban_sdk::{
    contract, contractimpl, deploy::DeployerWithAddress, symbol_short, vec, Address, Bytes, BytesN,
    Env, InvokeError,
};
use soroban_sdk_tools::{contractstorage, InstanceItem};
use stellar_accounts::smart_account::Signer;

const ACCOUNT_HASH: &[u8; 32] = b"\xb9\x4b\x29\x9f\x8c\x53\x04\xf1\x63\xdf\x15\x2e\x0d\xcf\x1a\xb8\x06\x63\xed\x03\x7c\xa1\xa3\x85\xd4\xec\x7b\xee\x7f\x3e\xcc\xf3";
const VERIFIER: &[u8; 32] = b"\x68\xe3\x4e\x48\x6c\xd9\xdf\xc9\xa2\x73\x8a\xef\x07\x4a\xc9\xff\xb1\x4f\x71\x01\x02\xa2\x4e\x7c\x63\x81\xd7\xb1\x02\xa3\x26\x93";

#[contractstorage]
pub struct Config {
    account: InstanceItem<BytesN<32>>,
    passkey: InstanceItem<Address>,
}

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    ///Deploy an account contract and add a passkey to it. Lastly transfer funds to the contract's account.
    ///
    pub fn create_account(e: &Env, funder: &Address, key: BytesN<65>) -> Address {
        funder.require_auth();
        Self::deploy_account_contract(e, funder, key.to_bytes())
    }

    pub fn get_c_address(e: &Env, funder: &Address) -> Address {
        Self::deployer(e, funder).deployed_address()
    }

    fn deployer(e: &Env, funder: &Address) -> DeployerWithAddress {
        e.deployer()
            .with_address(funder.clone(), BytesN::from_array(e, &[0; 32]))
    }

    fn deploy_account_contract(e: &Env, funder: &Address, key: Bytes) -> Address {
        let verifier_addr = Self::verifier_address(e);
        let signer = Signer::External(verifier_addr, key);
        let signers = soroban_sdk::vec![e, signer];
        let policies: soroban_sdk::Map<soroban_sdk::Address, soroban_sdk::Val> =
            soroban_sdk::Map::new(e);
        Self::deployer(e, funder)
            .deploy_v2(BytesN::from_array(e, ACCOUNT_HASH), (&signers, &policies))
    }

    fn verifier_address(e: &Env) -> Address {
        let bytes: BytesN<32> = BytesN::from_array(e, VERIFIER);
        let deployer = e.deployer().with_current_contract(bytes.clone());
        let address = deployer.deployed_address();
        if let Err(_) = e.try_invoke_contract::<bool, InvokeError>(
            &address,
            &symbol_short!("verify"),
            vec![e, bytes.to_val(), bytes.to_val(), bytes.to_val()],
        ) {
            deployer.deploy_v2(bytes, ())
        } else {
            address
        }
    }
}
