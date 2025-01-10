// Find all our documentation at https://docs.near.org
use near_sdk::{env, ext_contract, log, near, AccountId, Gas, NearToken, Promise, PromiseError, PanicOnDefault, require};
use near_sdk::json_types::U128;
use near_sdk::serde_json::{self,json};
use near_contract_standards::fungible_token::FungibleToken;
use near_contract_standards::storage_management::StorageBalance;
use ed25519_dalek::{PublicKey, Signature, Verifier, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use base64;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::UnorderedMap;
use near_sdk::serde::{Deserialize, Serialize};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
#[derive(Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct ClaimInput {
    pub task: u16,
    pub reward: u128,
}

#[derive(Serialize, Deserialize, Clone, BorshDeserialize, BorshSerialize, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct RewardItem {
    pub user: AccountId,
    pub task: u16,
    pub reward: u128,
    pub times: u16,
}

#[derive(BorshDeserialize, BorshSerialize)]
pub struct Pool {
    pub total: u128,
    pub claimed: u128,
    pub pool: UnorderedMap<AccountId, RewardItem>,
}

// Define the contract structure
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    owner: AccountId,
    signer: Vec<u8>,
    total_claimed: u128,
    pools: UnorderedMap<u16, Pool>,
}

#[ext_contract(ft_contract)]
trait FT {
    fn ft_transfer(&self, receiver_id: AccountId, amount: U128);
    fn storage_deposit(
        &mut self,
        account_id: Option<AccountId>,
        registration_only: Option<bool>,
    ) -> StorageBalance;
}

// Implement the contract structure
#[near]
impl Contract {
    #[init]
    #[private] // only callable by the contract's account
    pub fn init(signer: Vec<u8>) -> Self {
        require!(signer.len() == 32, "Signer pubkey error");
        Self {
            owner: env::predecessor_account_id(),
            signer,
            total_claimed: 0,
            pools: UnorderedMap::new(b"m"),
        }
    }

    pub fn get_signer(&self) -> Vec<u8> {
        self.signer.clone()
    }

    pub fn get_owner(&self) -> AccountId {
        self.owner.clone()
    }

    pub fn set_signer(&mut self, new_signer: Vec<u8>) ->bool {
        require!(env::predecessor_account_id() == self.owner, "Owner's method");
        require!(new_signer.len() == 32, "Signer pubkey error");
        self.signer = new_signer;
        true
    }

    pub fn register_pool(&mut self, task: u16, reward: u128) {
        require!(env::predecessor_account_id() == self.owner, "Owner's method");
        let item = self.pools.get(&task);

        if item.is_none(){
            let pool = Pool{
                total: reward,
                claimed: 0,
                pool: UnorderedMap::new(format!("i:{}", task).as_bytes()),
            };
            self.pools.insert(&task, &pool);
        }
    }

    pub fn get_pool(&self, task: u16) -> Option<Pool> {
        self.pools.get(&task)
    }

    pub fn get_reward(&self, task: u16) -> Option<RewardItem> {
        match self.pools.get(&task) {
            Some(pool)=> pool.pool.get(&env::predecessor_account_id()),
            None => None
        }
    }

    pub fn claim(&mut self, message: String, signature: String) -> bool{
        let signature_bytes = match base64::decode(signature) {
            Ok(bytes) => bytes,
            Err(_) => {
                env::panic_str("Failed to decode signature");
            }
        };
        let signature = match Signature::from_bytes(&signature_bytes) {
            Ok(sig) => sig,
            Err(_) => {
                env::panic_str("Invalid signature");
            }
        };
        let public_key = match PublicKey::from_bytes(&self.signer) {
            Ok(pk) => pk,
            Err(_) => {
                env::panic_str("Invalid public key");
            }
        };
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let message_bytes = hasher.finalize();
        // Verify the signature
        if let Err(_) = public_key.verify(&message_bytes, &signature) {
            return  false;
        }
        let claim_input:Result<ClaimInput,_> = serde_json::from_str(&message);
        require!(claim_input.is_ok(), "Claim info error!");
        let claim = claim_input.ok().unwrap();
        let task = claim.task;
        let reward = claim.reward;
        if let Some(mut pool) = self.pools.get(&task) {
            // Update the total and claimed fields
            pool.claimed = pool.claimed.checked_add(reward).expect("Overflow in claimed");
            let account = env::predecessor_account_id();
            // Retrieve the reward item
            if let Some(mut reward_item) = pool.pool.get(&account) {
                // Update the reward item
                reward_item.reward = reward_item.reward.checked_add(reward).expect("Overflow in claimed");
                reward_item.times += 1;

                // Insert the updated reward item back into the pool
                pool.pool.insert(&account, &reward_item);
            } else {
                let new_reward_item = RewardItem{
                    user: account.clone(),
                    task,
                    reward,
                    times: 1,
                };
                pool.pool.insert(&account, &new_reward_item);
            }
            // Insert the updated pool back into the contract's pools
            self.pools.insert(&claim.task, &pool);
        } else {
            env::panic_str("Claim pool not exist");
        }
        true
    }

    pub fn verify_signature(&self, message: String, signature: String, public_key: String) -> bool {
        // Base64 decode the inputs
        let message_bytes = match base64::decode(message) {
            Ok(bytes) => bytes,
            Err(_) => {
                env::log_str("Failed to decode message");
                return false;
            }
        };

        let signature_bytes = match base64::decode(signature) {
            Ok(bytes) => bytes,
            Err(_) => {
                env::log_str("Failed to decode signature");
                return false;
            }
        };

        let public_key_bytes = match base64::decode(public_key) {
            Ok(bytes) => bytes,
            Err(_) => {
                env::log_str("Failed to decode public key");
                return false;
            }
        };

        // Check lengths
        if public_key_bytes.len() != 32 || signature_bytes.len() != 64 {
            env::log_str("Invalid public key or signature length");
            return false;
        }

        // Create PublicKey and Signature objects
        let public_key = match PublicKey::from_bytes(&public_key_bytes) {
            Ok(pk) => pk,
            Err(_) => {
                env::log_str("Invalid public key");
                return false;
            }
        };

        let signature = match Signature::from_bytes(&signature_bytes) {
            Ok(sig) => sig,
            Err(_) => {
                env::log_str("Invalid signature");
                return false;
            }
        };

        // Verify the signature
        match public_key.verify(&message_bytes, &signature) {
            Ok(_) => true,
            Err(_) => {
                env::log_str("Signature verification failed");
                false
            }
        }
    }
    #[payable]
    pub fn get_usdt_balance(&mut self, receiver_id: AccountId, amount: U128) -> U128 {
        let usdt_contract_id = "usdt.fakes.testnet".parse::<AccountId>().unwrap();
        assert_eq!(env::attached_deposit(), NearToken::from_yoctonear(1), "Requires attached deposit of exactly 1 yoctoNEAR");
        ft_contract::ext(usdt_contract_id.clone())
            .with_attached_deposit(NearToken::from_yoctonear(1_250_000_000_000_000_000_000))
            .with_static_gas(Gas::from_gas(5_000_000_000_000))
            .storage_deposit(Some(receiver_id.clone()), Some(true))
            .then(
                ft_contract::ext(usdt_contract_id)
                    .with_attached_deposit(NearToken::from_yoctonear(1))
                    .with_static_gas(Gas::from_gas(10_000_000_000_000))
                    .ft_transfer(receiver_id, amount),
            );
        U128(0)
    }
}

/*
 * The rest of this file holds the inline tests for the code above
 * Learn more about Rust tests: https://doc.rust-lang.org/book/ch11-01-writing-tests.html
 */
#[cfg(test)]
mod tests {
    use ed25519_dalek::{Keypair, Signer};
    use ed25519_dalek::ed25519::signature::Signature;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{bs58, testing_env};
    use super::*;

    #[test]
    fn init_contract() {
        let mut csprng = OsRng{};
        let keypair = Keypair::generate(&mut csprng);
        let alice = keypair.public.as_bytes().to_vec();
        let contract = Contract::init(alice.clone());
        assert_eq!(contract.get_signer(), alice);
        assert_eq!(contract.get_owner(), env::predecessor_account_id());
    }

    #[test]
    fn set_signer() {
        let mut csprng = OsRng{};
        let keypair = Keypair::generate(&mut csprng);
        let alice = keypair.public.as_bytes().to_vec();
        let keypair = Keypair::generate(&mut csprng);
        let bob = keypair.public.as_bytes().to_vec();
        let mut contract = Contract::init(alice.clone());
        contract.set_signer(bob.clone());
        assert_eq!(contract.get_signer(), bob);
    }

    #[test]
    fn register_pool() {
        let mut csprng = OsRng{};
        let keypair = Keypair::generate(&mut csprng);
        let alice = keypair.public.as_bytes().to_vec();
        let mut contract = Contract::init(alice);
        let task = 1;
        let reward = 50000;
        contract.register_pool(task, reward);
        let op_pool = contract.get_pool(task);
        assert!(op_pool.is_some());
        let pool = op_pool.unwrap();
        assert_eq!(pool.total, reward);
        assert_eq!(pool.claimed, 0);
        assert_eq!(pool.pool.len(), 0);
    }
    fn keypair_to_account_id(keypair: &Keypair) -> Result<AccountId, String> {
        let public_key: PublicKey = keypair.public;
        let mut public_key_str = bs58::encode(public_key.as_bytes()).into_string();

        public_key_str = public_key_str.to_lowercase();
        if public_key_str.chars().next().unwrap().is_numeric() {
            public_key_str = format!("a{}", public_key_str);
        }
        if public_key_str.len() > 64 {
            public_key_str.truncate(64);
        }
        AccountId::try_from(public_key_str).map_err(|e| e.to_string())
    }
    #[test]
    fn claim() {
        let mut csprng = OsRng{};
        let keypair = Keypair::generate(&mut csprng);
        let signer = keypair.public.as_bytes().to_vec();
        let mut contract = Contract::init(signer.clone());
        assert_eq!(contract.get_signer(), signer.clone());
        let task = 1;
        let reward = 50000;
        contract.register_pool(task, reward);
        let claim_input = ClaimInput{
            task,
            reward,
        };
        let str_claim_input = serde_json::to_string(&claim_input).unwrap();
        // Sign and verify
        let mut hasher = Sha256::new();
        hasher.update(str_claim_input.as_bytes());
        let result = hasher.finalize();
        let signature = keypair.sign(result.as_slice());
        let verify_result = keypair.verify(result.as_slice(), &signature);
        assert!(verify_result.is_ok());
        let sig_str = base64::encode(signature);
        contract.claim(str_claim_input.clone(), sig_str);
        let reward_item = contract.get_reward(task).unwrap();
        assert_eq!(reward_item.reward, reward);
        assert_eq!(reward_item.times, 1);
        assert_eq!(reward_item.task, task);
    }

}
