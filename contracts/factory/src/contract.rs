use soroban_sdk::{
    contract, contractimpl, deploy::DeployerWithAddress, Address, Bytes, BytesN, Env,
};
use soroban_sdk_tools::{contractstorage, InstanceItem};
use stellar_accounts::smart_account::Signer;

use crate::xlm;

const ACCOUNT_HASH: &[u8; 32] = b"\xb9\x4b\x29\x9f\x8c\x53\x04\xf1\x63\xdf\x15\x2e\x0d\xcf\x1a\xb8\x06\x63\xed\x03\x7c\xa1\xa3\x85\xd4\xec\x7b\xee\x7f\x3e\xcc\xf3";
const VERIFIER: &[u8; 32] = b"\xb9\x39\x33\x11\xf9\x7b\x49\x8f\xbb\x89\x76\xec\x50\xdd\x85\x85\xdd\x99\xad\x44\x3b\x8f\x13\xec\x5f\x75\x19\x86\x72\x9f\x99\xbe";

#[contractstorage]
pub struct Config {
    account: InstanceItem<BytesN<32>>,
    passkey: InstanceItem<Address>,
}

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn __constructor(e: &Env) {
        xlm::register(e, &e.current_contract_address());
    }

    ///Deploy an account contract and add a passkey to it. Lastly transfer funds to the contract's account.
    ///
    pub fn create_account(e: &Env, funder: &Address, key: BytesN<65>) -> Address {
        funder.require_auth();
        let new_account = Self::deploy_account_contract(e, funder, key.to_bytes());
        let xlm_sac = xlm::stellar_asset_client(e);
        let amount = xlm_sac.balance(funder);
        xlm_sac.transfer(funder, &new_account, &amount);
        new_account
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

        if address.executable().is_none() {
            deployer.deploy_v2(bytes, ())
        } else {
            address
        }
    }
}
