use std::collections::{BTreeMap, HashMap, btree_map::Entry};

use anyhow::Result;
use bip39::Mnemonic;
use key_protocol::{
    key_management::{
        key_tree::{KeyTreePrivate, KeyTreePublic, chain_index::ChainIndex},
        secret_holders::SeedHolder,
    },
    key_protocol_core::{NSSAUserData, UserPrivateAccountData},
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
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "We perform search for specific variants only"
    )]
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
                    let npk = data.data.value.0.nullifier_public_key;
                    let chain_index = data.chain_index;
                    for identifier in &data.identifiers {
                        let account_id = nssa::AccountId::from((&npk, *identifier));
                        private_tree.account_id_map.insert(account_id, chain_index.clone());
                    }
                    private_tree.key_map.insert(chain_index, data.data);
                }
                PersistentAccountData::Preconfigured(acc_data) => match acc_data {
                    InitialAccountData::Public(data) => {
                        public_init_acc_map.insert(data.account_id, data.pub_sign_key);
                    }
                    InitialAccountData::Private(data) => {
                        private_init_acc_map.insert(
                            data.account_id,
                            UserPrivateAccountData {
                                key_chain: data.key_chain,
                                accounts: vec![(data.identifier, data.account)],
                            },
                        );
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

    pub fn new_storage(config: WalletConfig, password: &str) -> Result<(Self, Mnemonic)> {
        let mut public_init_acc_map = BTreeMap::new();
        let mut private_init_acc_map = BTreeMap::new();

        let initial_accounts = config
            .initial_accounts
            .clone()
            .unwrap_or_else(InitialAccountData::create_initial_accounts_data);

        for init_acc_data in initial_accounts {
            match init_acc_data {
                InitialAccountData::Public(data) => {
                    public_init_acc_map.insert(data.account_id, data.pub_sign_key);
                }
                InitialAccountData::Private(data) => {
                    let mut account = data.account;
                    // TODO: Program owner is only known after code is compiled and can't be set
                    // in the config. Therefore we overwrite it here on
                    // startup. Fix this when program id can be fetched
                    // from the node and queried from the wallet.
                    account.program_owner = Program::authenticated_transfer_program().id();
                    private_init_acc_map.insert(
                        data.account_id,
                        UserPrivateAccountData {
                            key_chain: data.key_chain,
                            accounts: vec![(data.identifier, account)],
                        },
                    );
                }
            }
        }

        // TODO: Use password for storage encryption
        let _ = password;
        let (seed_holder, mnemonic) = SeedHolder::new_mnemonic("");
        let public_tree = KeyTreePublic::new(&seed_holder);
        let private_tree = KeyTreePrivate::new(&seed_holder);

        Ok((
            Self {
                user_data: NSSAUserData::new_with_accounts(
                    public_init_acc_map,
                    private_init_acc_map,
                    public_tree,
                    private_tree,
                )?,
                wallet_config: config,
                labels: HashMap::new(),
            },
            mnemonic,
        ))
    }

    /// Restore storage from an existing mnemonic phrase.
    pub fn restore_storage(
        config: WalletConfig,
        mnemonic: &Mnemonic,
        password: &str,
    ) -> Result<Self> {
        // TODO: Use password for storage encryption
        let _ = password;
        let seed_holder = SeedHolder::from_mnemonic(mnemonic, "");
        let public_tree = KeyTreePublic::new(&seed_holder);
        let private_tree = KeyTreePrivate::new(&seed_holder);

        Ok(Self {
            user_data: NSSAUserData::new_with_accounts(
                BTreeMap::new(),
                BTreeMap::new(),
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
        identifier: nssa_core::Identifier,
        account: nssa_core::account::Account,
    ) {
        debug!("inserting at address {account_id}, this account {account:?}");

        // Update default accounts if present
        if let Entry::Occupied(mut entry) = self
            .user_data
            .default_user_private_accounts
            .entry(account_id)
        {
            let entry = entry.get_mut();
            if let Some((_, acc)) = entry.accounts.iter_mut().find(|(id, _)| *id == identifier) {
                *acc = account;
            } else {
                entry.accounts.push((identifier, account));
            }
            return;
        }

        // Otherwise update the private key tree

        // Find the node by iterating all tree nodes for this account_id
        let chain_index = self
            .user_data
            .private_key_tree
            .account_id_map
            .get(&account_id)
            .cloned();

        if let Some(chain_index) = chain_index {
            // Node already in account_id_map — update its entry
            if let Some(node) = self
                .user_data
                .private_key_tree
                .key_map
                .get_mut(&chain_index)
            {
                if let Some((_, acc)) = node.value.1.iter_mut().find(|(id, _)| *id == identifier) {
                    *acc = account;
                } else {
                    node.value.1.push((identifier, account));
                }
            }
        } else {
            // Node not yet in account_id_map — find it by checking all nodes
            for (ci, node) in &mut self.user_data.private_key_tree.key_map {
                let expected_id =
                    nssa::AccountId::from((&node.value.0.nullifier_public_key, identifier));
                if expected_id == account_id {
                    if let Some((_, acc)) =
                        node.value.1.iter_mut().find(|(id, _)| *id == identifier)
                    {
                        *acc = account;
                    } else {
                        node.value.1.push((identifier, account));
                    }
                    // Register in account_id_map
                    self.user_data
                        .private_key_tree
                        .account_id_map
                        .insert(account_id, ci.clone());
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use key_protocol::key_management::key_tree::{
        keys_private::ChildKeysPrivate, keys_public::ChildKeysPublic,
    };

    use super::*;
    use crate::config::{PersistentAccountDataPrivate, PersistentAccountDataPublic};

    fn create_sample_wallet_config() -> WalletConfig {
        WalletConfig {
            sequencer_addr: "http://127.0.0.1".parse().unwrap(),
            seq_poll_timeout: std::time::Duration::from_secs(12),
            seq_tx_poll_max_blocks: 5,
            seq_poll_max_retries: 10,
            seq_block_poll_max_amount: 100,
            basic_auth: None,
            initial_accounts: None,
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
            PersistentAccountData::Private(Box::new(PersistentAccountDataPrivate {
                identifiers: vec![],
                chain_index: ChainIndex::root(),
                data: private_data,
            })),
        ]
    }

    #[test]
    fn new_initializes_correctly() {
        let config = create_sample_wallet_config();
        let accs = create_sample_persistent_accounts();

        let _ = WalletChainStore::new(config, accs, HashMap::new()).unwrap();
    }
}
