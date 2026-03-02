use std::collections::{BTreeMap, HashMap, btree_map::Entry};

use anyhow::Result;
use key_protocol::{
    key_management::{
        key_tree::{KeyTreePrivate, KeyTreePublic, chain_index::ChainIndex},
        secret_holders::SeedHolder,
    },
    key_protocol_core::NSSAUserData,
};
use log::debug;
use nssa::program::Program;

use crate::config::{InitialAccountData, Label, PersistentAccountData, WalletConfig};

pub struct WalletChainStore {
    pub user_data: NSSAUserData,
    pub wallet_config: WalletConfig,
    pub labels: HashMap<String, Label>,
}

impl WalletChainStore {
    pub fn new(
        config: WalletConfig,
        persistent_accounts: Vec<PersistentAccountData>,
        labels: HashMap<String, Label>,
    ) -> Result<Self> {
        if persistent_accounts.is_empty() {
            anyhow::bail!("Roots not found; please run setup beforehand");
        }

        let mut public_init_acc_map = BTreeMap::new();
        let mut private_init_acc_map = BTreeMap::new();

        let public_root = persistent_accounts
            .iter()
            .find(|data| match data {
                &PersistentAccountData::Public(data) => data.chain_index == ChainIndex::root(),
                _ => false,
            })
            .cloned()
            .expect("Malformed persistent account data, must have public root");

        let private_root = persistent_accounts
            .iter()
            .find(|data| match data {
                &PersistentAccountData::Private(data) => data.chain_index == ChainIndex::root(),
                _ => false,
            })
            .cloned()
            .expect("Malformed persistent account data, must have private root");

        let mut public_tree = KeyTreePublic::new_from_root(match public_root {
            PersistentAccountData::Public(data) => data.data,
            _ => unreachable!(),
        });
        let mut private_tree = KeyTreePrivate::new_from_root(match private_root {
            PersistentAccountData::Private(data) => data.data,
            _ => unreachable!(),
        });

        for pers_acc_data in persistent_accounts {
            match pers_acc_data {
                PersistentAccountData::Public(data) => {
                    public_tree.insert(data.account_id, data.chain_index, data.data);
                }
                PersistentAccountData::Private(data) => {
                    private_tree.insert(data.account_id, data.chain_index, data.data);
                }
                PersistentAccountData::Preconfigured(acc_data) => match acc_data {
                    InitialAccountData::Public(data) => {
                        public_init_acc_map.insert(data.account_id, data.pub_sign_key);
                    }
                    InitialAccountData::Private(data) => {
                        private_init_acc_map
                            .insert(data.account_id, (data.key_chain, data.account));
                    }
                },
            }
        }

        Ok(Self {
            user_data: NSSAUserData::new_with_accounts(
                public_init_acc_map,
                private_init_acc_map,
                public_tree,
                private_tree,
            )?,
            wallet_config: config,
            labels,
        })
    }

    pub fn new_storage(config: WalletConfig, password: String) -> Result<Self> {
        let mut public_init_acc_map = BTreeMap::new();
        let mut private_init_acc_map = BTreeMap::new();

        for init_acc_data in config.initial_accounts.clone() {
            match init_acc_data {
                InitialAccountData::Public(data) => {
                    public_init_acc_map.insert(data.account_id, data.pub_sign_key);
                }
                InitialAccountData::Private(data) => {
                    let mut account = data.account;
                    // TODO: Program owner is only known after code is compiled and can't be set in
                    // the config. Therefore we overwrite it here on startup. Fix this when program
                    // id can be fetched from the node and queried from the wallet.
                    account.program_owner = Program::authenticated_transfer_program().id();
                    private_init_acc_map.insert(data.account_id, (data.key_chain, account));
                }
            }
        }

        let public_tree = KeyTreePublic::new(&SeedHolder::new_mnemonic(password.clone()));
        let private_tree = KeyTreePrivate::new(&SeedHolder::new_mnemonic(password));

        Ok(Self {
            user_data: NSSAUserData::new_with_accounts(
                public_init_acc_map,
                private_init_acc_map,
                public_tree,
                private_tree,
            )?,
            wallet_config: config,
            labels: HashMap::new(),
        })
    }

    pub fn insert_private_account_data(
        &mut self,
        account_id: nssa::AccountId,
        account: nssa_core::account::Account,
    ) {
        debug!("inserting at address {account_id}, this account {account:?}");

        let entry = self
            .user_data
            .default_user_private_accounts
            .entry(account_id)
            .and_modify(|data| data.1 = account.clone());

        if matches!(entry, Entry::Vacant(_)) {
            self.user_data
                .private_key_tree
                .account_id_map
                .get(&account_id)
                .map(|chain_index| {
                    self.user_data
                        .private_key_tree
                        .key_map
                        .entry(chain_index.clone())
                        .and_modify(|data| data.value.1 = account)
                });
        }
    }
}

#[cfg(test)]
mod tests {
    use key_protocol::key_management::key_tree::{
        keys_private::ChildKeysPrivate, keys_public::ChildKeysPublic, traits::KeyNode,
    };

    use super::*;
    use crate::config::{
        InitialAccountData, PersistentAccountDataPrivate, PersistentAccountDataPublic,
    };

    fn create_initial_accounts() -> Vec<InitialAccountData> {
        let initial_acc1 = serde_json::from_str(
            r#"{
            "Public": {
                "account_id": "CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r",
                "pub_sign_key": [
                    3,
                    217,
                    68,
                    59,
                    58,
                    39,
                    27,
                    77,
                    102,
                    214,
                    182,
                    35,
                    220,
                    146,
                    92,
                    88,
                    125,
                    120,
                    95,
                    92,
                    96,
                    132,
                    73,
                    53,
                    44,
                    6,
                    28,
                    190,
                    203,
                    155,
                    196,
                    56
                ]
            }
        }"#,
        )
        .unwrap();

        let initial_acc2 = serde_json::from_str(
            r#"{
            "Public": {
                "account_id": "2RHZhw9h534Zr3eq2RGhQete2Hh667foECzXPmSkGni2",
                "pub_sign_key": [
                    167,
                    65,
                    139,
                    108,
                    159,
                    127,
                    141,
                    227,
                    127,
                    252,
                    137,
                    193,
                    25,
                    65,
                    127,
                    143,
                    27,
                    203,
                    56,
                    226,
                    251,
                    60,
                    32,
                    143,
                    195,
                    225,
                    39,
                    160,
                    29,
                    20,
                    135,
                    232
                ]
            }
        }"#,
        )
        .unwrap();

        let initial_accounts = vec![initial_acc1, initial_acc2];

        initial_accounts
    }

    fn create_sample_wallet_config() -> WalletConfig {
        WalletConfig {
            override_rust_log: None,
            sequencer_addr: "http://127.0.0.1".parse().unwrap(),
            seq_poll_timeout: std::time::Duration::from_secs(12),
            seq_tx_poll_max_blocks: 5,
            seq_poll_max_retries: 10,
            seq_block_poll_max_amount: 100,
            initial_accounts: create_initial_accounts(),
            basic_auth: None,
        }
    }

    fn create_sample_persistent_accounts() -> Vec<PersistentAccountData> {
        let public_data = ChildKeysPublic::root([42; 64]);
        let private_data = ChildKeysPrivate::root([47; 64]);

        vec![
            PersistentAccountData::Public(PersistentAccountDataPublic {
                account_id: public_data.account_id(),
                chain_index: ChainIndex::root(),
                data: public_data,
            }),
            PersistentAccountData::Private(PersistentAccountDataPrivate {
                account_id: private_data.account_id(),
                chain_index: ChainIndex::root(),
                data: private_data,
            }),
        ]
    }

    #[test]
    fn test_new_initializes_correctly() {
        let config = create_sample_wallet_config();
        let accs = create_sample_persistent_accounts();

        let _ = WalletChainStore::new(config.clone(), accs, HashMap::new()).unwrap();
    }
}
