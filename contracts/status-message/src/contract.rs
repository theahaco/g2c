use soroban_sdk::{contract, contractimpl, Address, Env, String};
use soroban_sdk_tools::{contractstorage, PersistentMap};

#[contractstorage]
pub struct Config {
    messages: PersistentMap<Address, String>,
}

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn udpate_message(e: &Env, message: &String, author: &Address) {
        author.require_auth();
        let messages = Config::new(e).messages;
        messages.set(author, message);
    }

    pub fn get_message(e: &Env, author: &Address) -> Option<String> {
        Config::new(e).messages.get(author)
    }
}
