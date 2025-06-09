// Find all our documentation at https://docs.near.org
use near_sdk::{env, ext_contract, near, AccountId, Gas, NearToken, PanicOnDefault, require};
use near_sdk::json_types::U128;
use near_sdk::serde_json;
use near_contract_standards::storage_management::StorageBalance;
use ed25519_dalek::{PublicKey, Signature, Verifier};
use base64;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::UnorderedMap;
use near_sdk::serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

#[derive(Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct ClaimInput {
    pub task: u16,
    pub nonce: u16,
    pub reward: u128,
    pub receiver: AccountId,
}

#[near(serializers=[json,borsh])]
pub struct RewardItem {
    pub user: AccountId,
    pub task: u16,
    pub reward: u128,
    pub times: u16,
}

#[near(serializers=[json,borsh])]
pub struct PoolInfo {
    pub total: u128,
    pub claimed: u128,
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
    signer: String,
    total_claimed: u128,
    pools: UnorderedMap<u16, Pool>,
    token: AccountId,
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
    pub fn init(signer: String, token: AccountId) -> Self {
        require!(signer.len() == 64, "Signer pubkey error");
        Self {
            owner: env::predecessor_account_id(),
            signer,
            total_claimed: 0,
            pools: UnorderedMap::new(b"m"),
            token
        }
    }

    pub fn get_signer(&self) -> String {
        self.signer.clone()
    }

    pub fn get_total_claimed(&self) -> u128 {
        self.total_claimed.clone()
    }

    pub fn get_owner(&self) -> AccountId {
        self.owner.clone()
    }

    pub fn set_signer(&mut self, new_signer: String) ->bool {
        require!(env::predecessor_account_id() == self.owner, "Owner's method");
        require!(new_signer.len() == 64, "Signer pubkey error");
        self.signer = new_signer;
        true
    }

    pub fn get_token(&self) -> AccountId {
        self.token.clone()
    }

    pub fn set_token(&mut self, new_token: AccountId) ->bool {
        require!(env::predecessor_account_id() == self.owner, "Owner's method");
        self.token = new_token;
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

    pub fn get_pool(&self, task: u16) -> Option<PoolInfo> {
        let pool = self.pools.get(&task);
        if let Some(pool) = pool {
            Some(PoolInfo{
                total: pool.total,
                claimed: pool.claimed,
            })
        } else{
            None
        }
    }

    pub fn get_reward(&self, task: u16, user: AccountId) -> Option<RewardItem> {
        match self.pools.get(&task) {
            Some(pool)=> pool.pool.get(&user),
            None => None
        }
    }

    pub fn claim_nonce(&self, task: u16, user: AccountId) -> u16 {
        let reward_item = match self.pools.get(&task) {
            Some(pool)=> pool.pool.get(&user),
            None => None
        };
        if let Some(reward_item) =  reward_item {
            reward_item.times
        } else{
            0
        }
    }

    pub fn get_account_id(&self) -> AccountId {
        env::current_account_id()
    }

    #[payable]
    pub fn withdraw(&mut self, balance: U128) {
        let receiver = env::predecessor_account_id();
        require!(receiver == self.owner, "Owner's method");
        let usdt_contract_id = self.token.clone();
        assert_eq!(env::attached_deposit(), NearToken::from_yoctonear(1), "Requires attached deposit of exactly 1 yoctoNEAR");
        ft_contract::ext(usdt_contract_id.clone())
        .with_attached_deposit(NearToken::from_yoctonear(1))
        .with_static_gas(Gas::from_gas(10_000_000_000_000))
        .ft_transfer(receiver, balance);
    }

    #[payable]
    pub fn claim(&mut self, message: String, signature: String) -> bool{
        let signature_bytes = base64::decode(signature).expect("Failed to decode signature");
        let signature = Signature::from_bytes(&signature_bytes).expect("Invalid signature");
        let decoded_public_key = hex::decode(self.signer.clone()).expect("Failed to decode public key");
        let public_key = PublicKey::from_bytes(&decoded_public_key).expect("Invalid public key");

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
        let nonce = claim.nonce;
        if let Some(mut pool) = self.pools.get(&task) {
            // Update the total and claimed fields
            pool.claimed = pool.claimed.checked_add(reward).expect("Overflow in claimed");
            self.total_claimed = self.total_claimed.checked_add(reward).expect("Overflow in claimed");
            let account = env::predecessor_account_id();
            // Retrieve the reward item
            if let Some(mut reward_item) = pool.pool.get(&account) {
                if reward_item.times != nonce {
                    env::panic_str("Claim failed");
                }
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
        let usdt_contract_id = self.token.clone();
        let receiver = env::predecessor_account_id();
        assert_eq!(receiver, claim.receiver, "Unauthorized account");
        assert_eq!(env::attached_deposit(), NearToken::from_yoctonear(1), "Requires attached deposit of exactly 1 yoctoNEAR");
        ft_contract::ext(usdt_contract_id.clone())
            .with_attached_deposit(NearToken::from_yoctonear(1_250_000_000_000_000_000_000))
            // .with_static_gas(Gas::from_gas(5_500_000_000_000))
            .storage_deposit(Some(receiver.clone()), Some(true))
            .then(
                ft_contract::ext(usdt_contract_id)
                    .with_attached_deposit(NearToken::from_yoctonear(1))
                    // .with_static_gas(Gas::from_gas(10_000_000_000_000))
                    .ft_transfer(receiver, U128::from(reward)),
            );
        true
    }
}

/*
 * The rest of this file holds the inline tests for the code above
 * Learn more about Rust tests: https://doc.rust-lang.org/book/ch11-01-writing-tests.html
 */
#[cfg(test)]
mod tests {
    use ed25519_dalek::{Keypair, Signer};
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{bs58, testing_env, VMContext};
    use super::*;
    use near_contract_standards::fungible_token::FungibleToken;
    use near_contract_standards::fungible_token::FungibleTokenCore;
    use rand::rngs::OsRng;
    #[test]
    fn init_contract() {
        let mut csprng = OsRng{};
        let keypair = Keypair::generate(&mut csprng);
        let alice = hex::encode(keypair.public);
        let token = "usdt.fakes.testnet".parse::<AccountId>().unwrap();
        let contract = Contract::init(alice.clone(), token);
        assert_eq!(contract.get_signer(), alice);
        assert_eq!(contract.get_owner(), env::predecessor_account_id());
    }

    #[test]
    fn set_signer() {
        let mut csprng = OsRng{};
        let keypair = Keypair::generate(&mut csprng);
        let alice = hex::encode(keypair.public);
        let keypair = Keypair::generate(&mut csprng);
        let bob = hex::encode(keypair.public);
        let token = "usdt.fakes.testnet".parse::<AccountId>().unwrap();
        let mut contract = Contract::init(alice.clone(), token);
        contract.set_signer(bob.clone());
        assert_eq!(contract.get_signer(), bob);
    }
    #[test]
    fn set_token() {
        let mut csprng = OsRng{};
        let keypair = Keypair::generate(&mut csprng);
        let alice = hex::encode(keypair.public);
        let token = "usdt.fakes.testnet".parse::<AccountId>().unwrap();
        let new_token = "usdt2.fakes.testnet".parse::<AccountId>().unwrap();
        let mut contract = Contract::init(alice.clone(), token);
        contract.set_token(new_token.clone());
        assert_eq!(contract.get_token(), new_token);
    }
    #[test]
    fn register_pool() {
        let mut csprng = OsRng{};
        let keypair = Keypair::generate(&mut csprng);
        let alice = hex::encode(keypair.public);
        let token = "usdt.fakes.testnet".parse::<AccountId>().unwrap();
        let mut contract = Contract::init(alice.clone(), token);
        let task = 1;
        let reward = 50000;
        contract.register_pool(task, reward);
        // let op_pool = contract.get_pool(task);
        // assert!(op_pool.is_some());
        // let pool = op_pool.unwrap();
        // assert_eq!(pool.total, reward);
        // assert_eq!(pool.claimed, 0);
        // assert_eq!(pool.pool.len(), 0);
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
    fn get_context(current_account_id: AccountId, signer_account_id: AccountId, is_view: bool) -> VMContext {
        VMContextBuilder::new()
            .current_account_id(current_account_id)
            .signer_account_id(signer_account_id)
            .is_view(is_view)
            .build()
    }

    #[test]
    fn claim() {
        let mut csprng = OsRng{};
        let keypair = Keypair::generate(&mut csprng);
        let signer = hex::encode(keypair.public);
        let mut ft = FungibleToken::new(b"usdt.fakes.testnet".to_vec());
        let token = "usdt.fakes.testnet".parse::<AccountId>().unwrap();
        let mut contract = Contract::init(signer.clone(), token);
        let contract_account_id = contract.get_account_id();
        let receiver = "bob.near".parse::<AccountId>().unwrap();
        let mut context = get_context(contract_account_id.clone(), receiver.clone(), false);
        context.attached_deposit = NearToken::from_yoctonear(1);
        testing_env!(context);
        ft.internal_register_account(&contract_account_id);
        let total = NearToken::from_near(1).as_yoctonear();
        ft.internal_deposit(&contract_account_id, total);
        assert_eq!(ft.total_supply, total);
        assert_eq!(contract.get_signer(), signer.clone());
        let task = 1;
        let reward = 50000;
        let nonce = 0;
        contract.register_pool(task, reward);
        let claim_input = ClaimInput{
            task,
            nonce,
            reward,
            receiver:receiver.clone(),
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
        let reward_item = contract.get_reward(task, receiver).unwrap();
        assert_eq!(reward_item.reward, reward);
        assert_eq!(reward_item.times, 1);
        assert_eq!(reward_item.task, task);
        // assert_eq!(ft.ft_balance_of(receiver).0, reward);
    }

    #[test]
    #[should_panic]
    fn claim_panic() {
        let mut csprng = OsRng{};
        let keypair = Keypair::generate(&mut csprng);
        let signer = hex::encode(keypair.public);
        let mut ft = FungibleToken::new(b"usdt.fakes.testnet".to_vec());
        let token = "usdt.fakes.testnet".parse::<AccountId>().unwrap();
        let mut contract = Contract::init(signer.clone(), token);
        let contract_account_id = contract.get_account_id();
        let receiver = "dbd867364750bf6e2353ffd9abd065f14679cd61a60f0de598abc2fe49740059".parse::<AccountId>().unwrap();
        let mut context = get_context(contract_account_id.clone(), receiver.clone(), false);
        context.attached_deposit = NearToken::from_yoctonear(1);
        testing_env!(context);
        ft.internal_register_account(&contract_account_id);
        ft.internal_deposit(&contract_account_id, NearToken::from_near(1).as_yoctonear());
        assert_eq!(contract.get_signer(), signer.clone());
        let task = 1;
        let reward = 50000;
        let nonce = 0;
        // contract.register_pool(task, reward);
        let claim_input = ClaimInput{
            task,
            nonce,
            reward,
            receiver:receiver.clone(),
        };
        let str_claim_input = serde_json::to_string(&claim_input).unwrap();
        println!("{}",str_claim_input);
        // Sign and verify
        let mut hasher = Sha256::new();
        hasher.update(str_claim_input.as_bytes());
        let result = hasher.finalize();
        let signature = keypair.sign(result.as_slice());
        let verify_result = keypair.verify(result.as_slice(), &signature);
        assert!(verify_result.is_ok());
        let sig_str = base64::encode(signature);
        contract.claim(str_claim_input.clone(), sig_str);
        let reward_item = contract.get_reward(task, receiver).unwrap();
        assert_eq!(reward_item.reward, reward);
        assert_eq!(reward_item.times, 1);
        assert_eq!(reward_item.task, task);
        // assert_eq!(ft.ft_balance_of(receiver).0, reward);
    }
}
