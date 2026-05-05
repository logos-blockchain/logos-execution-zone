use core::panic;
use std::collections::{BTreeMap, btree_map::Entry};

use anyhow::{Context as _, Result, anyhow};
use key_protocol::key_management::{
    KeyChain,
    group_key_holder::GroupKeyHolder,
    key_tree::{KeyTreePrivate, KeyTreePublic, chain_index::ChainIndex, traits::KeyTreeNode as _},
    secret_holders::SeedHolder,
};
use log::{debug, warn};
use nssa::{Account, AccountId};
use nssa_core::Identifier;
use testnet_initial_state::{PrivateAccountPrivateInitialData, PublicAccountPrivateInitialData};

use crate::{
    account::AccountIdWithPrivacy,
    storage::persistent::{
        PersistentAccountData, PersistentAccountDataPrivate, PersistentAccountDataPublic,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ImportedPrivateAccountKey {
    pub key_chain: KeyChain,
    /// We need to keep chain index even though it's not a generated account, because
    /// it may have been generated in another wallet with some chain index and we need it for
    /// decoding cyphertexts.
    pub chain_index: Option<ChainIndex>,
}

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct ImportedPrivateAccountData {
    pub accounts: BTreeMap<Identifier, Account>,
}

#[derive(Debug)]
pub struct FoundPrivateAccount<'acc> {
    pub account: &'acc Account,
    pub key_chain: &'acc KeyChain,
    pub identifier: Identifier,
    pub chain_index: Option<ChainIndex>,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct UserKeyChain {
    /// Imported public accounts.
    imported_public_accounts: BTreeMap<AccountId, nssa::PrivateKey>,
    /// Imported private accounts.
    imported_private_accounts: BTreeMap<ImportedPrivateAccountKey, ImportedPrivateAccountData>,
    /// Tree of public account keys.
    public_key_tree: KeyTreePublic,
    /// Tree of private account keys.
    private_key_tree: KeyTreePrivate,
    /// Group key holders for private PDA groups, keyed by a human-readable label.
    group_key_holders: BTreeMap<String, GroupKeyHolder>,
    /// Cached plaintext state of private PDA accounts, keyed by `AccountId`.
    /// Updated after each private PDA transaction by decrypting the circuit output.
    /// The sequencer only stores encrypted commitments, so this local cache is the
    /// only source of plaintext state for private PDAs.
    private_pda_accounts: BTreeMap<AccountId, nssa_core::account::Account>,
}

impl UserKeyChain {
    #[must_use]
    pub const fn new_with_accounts(
        public_key_tree: KeyTreePublic,
        private_key_tree: KeyTreePrivate,
    ) -> Self {
        Self {
            imported_public_accounts: BTreeMap::new(),
            imported_private_accounts: BTreeMap::new(),
            public_key_tree,
            private_key_tree,
            group_key_holders: BTreeMap::new(),
            private_pda_accounts: BTreeMap::new(),
        }
    }

    /// Generate new trees for public and private keys up to given depth.
    ///
    /// See [`key_protocol::key_management::key_tree::KeyTree::generate_tree_for_depth()`] for more
    /// details.
    pub fn generate_trees_for_depth(&mut self, depth: u32) {
        self.public_key_tree.generate_tree_for_depth(depth);
        self.private_key_tree.generate_tree_for_depth(depth);
    }

    /// Cleanup non-initialized accounts from the trees up to given depth.
    ///
    /// For more details see
    /// [`key_protocol::key_management::key_tree::KeyTreePublic::cleanup_tree_remove_uninit_layered()`]
    /// and [`key_protocol::key_management::key_tree::KeyTreePrivate::cleanup_tree_remove_uninit_layered()`].
    pub async fn cleanup_trees_remove_uninit_layered<F: Future<Output = Result<nssa::Account>>>(
        &mut self,
        depth: u32,
        get_account: impl Fn(AccountId) -> F,
    ) -> Result<()> {
        self.public_key_tree
            .cleanup_tree_remove_uninit_layered(depth, get_account)
            .await?;
        self.private_key_tree
            .cleanup_tree_remove_uninit_layered(depth);
        Ok(())
    }

    /// Generated new private key for public transaction signatures.
    ///
    /// Returns the `account_id` of new account.
    pub fn generate_new_public_transaction_private_key(
        &mut self,
        parent_cci: Option<ChainIndex>,
    ) -> (AccountId, ChainIndex) {
        match parent_cci {
            Some(parent_cci) => self
                .public_key_tree
                .generate_new_public_node(&parent_cci)
                .expect("Parent must be present in a tree"),
            None => self
                .public_key_tree
                .generate_new_public_node_layered()
                .expect("Search for new node slot failed"),
        }
    }

    /// Returns the signing key for public transaction signatures.
    #[must_use]
    pub fn pub_account_signing_key(&self, account_id: AccountId) -> Option<&nssa::PrivateKey> {
        self.imported_public_accounts
            .get(&account_id)
            .or_else(|| self.public_key_tree.get_node(account_id).map(Into::into))
    }

    /// Generated new private key for privacy preserving transactions.
    ///
    /// Returns the `account_id` of new account.
    pub fn generate_new_privacy_preserving_transaction_key_chain(
        &mut self,
        parent_cci: Option<ChainIndex>,
    ) -> (AccountId, ChainIndex) {
        let chain_index = self.create_private_accounts_key(parent_cci);
        let entry = self.private_key_tree.key_map.entry(chain_index.clone());

        let Entry::Occupied(occupied) = entry else {
            panic!("Newly created chain index must be present in a tree");
        };
        let node = occupied.get();

        let npk = node.value.0.nullifier_public_key;
        let (identifier, _) = node
            .value
            .1
            .first_key_value()
            .expect("Newly created key chain node must have at least one account");
        let account_id = AccountId::from((&npk, *identifier));
        (account_id, chain_index)
    }

    /// Creates a new receiving key node and returns its [`ChainIndex`].
    pub fn create_private_accounts_key(&mut self, parent_cci: Option<ChainIndex>) -> ChainIndex {
        match parent_cci {
            Some(parent_cci) => self
                .private_key_tree
                .create_private_accounts_key_node(&parent_cci)
                .expect("Parent must be present in a tree"),
            None => self
                .private_key_tree
                .create_private_accounts_key_node_layered()
                .expect("Search for new node slot failed"),
        }
    }

    /// Registers an additional identifier on an existing private key node, deriving and recording
    /// the corresponding [`AccountId`]. Returns [`None`] if the node does not exist or the
    /// identifier is already registered.
    pub fn register_identifier_on_private_key_chain(
        &mut self,
        cci: &ChainIndex,
        identifier: Identifier,
    ) -> Option<nssa::AccountId> {
        self.private_key_tree
            .register_identifier_on_node(cci, identifier)
    }

    /// Returns private account for given `account_id`. Doesn't search in pda accounts cache.
    #[must_use]
    pub fn private_account(&self, account_id: AccountId) -> Option<FoundPrivateAccount<'_>> {
        self.imported_private_accounts
            .iter()
            .flat_map(|(key, data)| {
                data.accounts
                    .iter()
                    .map(|(identifier, account)| FoundPrivateAccount {
                        account,
                        key_chain: &key.key_chain,
                        identifier: *identifier,
                        chain_index: key.chain_index.clone(),
                    })
            })
            .chain(
                self.private_key_tree
                    .key_map
                    .iter()
                    .flat_map(|(chain_index, data)| {
                        data.value
                            .1
                            .iter()
                            .map(|(identifier, account)| FoundPrivateAccount {
                                account,
                                key_chain: &data.value.0,
                                identifier: *identifier,
                                chain_index: Some(chain_index.clone()),
                            })
                    }),
            )
            .find_map(|found| {
                let expected_id =
                    AccountId::from((&found.key_chain.nullifier_public_key, found.identifier));
                (expected_id == account_id).then_some(found)
            })
    }

    /// Returns the cached plaintext state of a private PDA account, if it exists.
    #[must_use]
    pub fn private_pda_account(&self, account_id: AccountId) -> Option<&Account> {
        self.private_pda_accounts.get(&account_id)
    }

    #[must_use]
    pub fn private_account_key_chain_by_index(
        &self,
        chain_index: &ChainIndex,
    ) -> Option<&KeyChain> {
        self.private_key_tree
            .key_map
            .get(chain_index)
            .map(|data| &data.value.0)
    }

    pub fn private_account_key_chains(
        &self,
    ) -> impl Iterator<Item = (AccountId, &KeyChain, Option<&ChainIndex>)> {
        self.imported_private_accounts
            .iter()
            .flat_map(|(key, data)| {
                data.accounts.keys().map(|identifier| {
                    let account_id =
                        AccountId::from((&key.key_chain.nullifier_public_key, *identifier));
                    (account_id, &key.key_chain, key.chain_index.as_ref())
                })
            })
            .chain(
                self.private_key_tree
                    .key_map
                    .iter()
                    .flat_map(|(chain_index, keys_node)| {
                        keys_node.account_ids().map(move |account_id| {
                            (account_id, &keys_node.value.0, Some(chain_index))
                        })
                    }),
            )
    }

    pub fn add_imported_public_account(&mut self, private_key: nssa::PrivateKey) {
        let account_id = AccountId::from(&nssa::PublicKey::new_from_private_key(&private_key));

        self.imported_public_accounts
            .insert(account_id, private_key);
    }

    pub fn add_imported_private_account(
        &mut self,
        key_chain: KeyChain,
        chain_index: Option<ChainIndex>,
        identifier: Identifier,
        account: Account,
    ) {
        let key = ImportedPrivateAccountKey {
            key_chain,
            chain_index,
        };
        let entry = self.imported_private_accounts.entry(key.clone());
        match entry {
            Entry::Occupied(mut occupied) => {
                let data = occupied.get_mut();
                let per_id_entry = data.accounts.entry(identifier);
                if let Entry::Occupied(per_id_occupied) = &per_id_entry {
                    let existing_account = per_id_occupied.get();
                    if existing_account != &account {
                        warn!(
                            "Overwriting existing imported private account for key {key:?}. \
                            Existing account: {existing_account:?}, new account: {account:?}",
                        );
                    }
                }
                per_id_entry.insert_entry(account);
            }
            Entry::Vacant(vacant) => {
                vacant.insert_entry(ImportedPrivateAccountData {
                    accounts: BTreeMap::from_iter([(identifier, account)]),
                });
            }
        }
    }

    pub fn insert_private_account(
        &mut self,
        account_id: AccountId,
        identifier: Identifier,
        account: nssa_core::account::Account,
    ) -> Result<()> {
        // First try to update imported account
        for (key, data) in &mut self.imported_private_accounts {
            for (imported_identifier, imported_account) in &mut data.accounts {
                let expected_id =
                    AccountId::from((&key.key_chain.nullifier_public_key, *imported_identifier));
                if expected_id == account_id {
                    debug!("Updating imported private account {account_id}");
                    *imported_account = account;
                    return Ok(());
                }
            }
        }

        // Otherwise update the private key tree

        let chain_index = self.private_key_tree.account_id_map.get(&account_id);

        if let Some(chain_index) = chain_index {
            // Node already in account_id_map — update its entry
            let node = self
                .private_key_tree
                .key_map
                .get_mut(chain_index)
                .expect("Node must be present in a tree");

            match node.value.1.entry(identifier) {
                Entry::Occupied(mut occupied) => {
                    debug!("Updating generated private account {account_id}");
                    occupied.insert(account);
                }
                Entry::Vacant(vacant) => {
                    debug!("Inserting new private account identity {account_id}");
                    vacant.insert(account);
                }
            }

            return Ok(());
        }

        // Node not yet in account_id_map — find it by checking all nodes
        for (ci, node) in &mut self.private_key_tree.key_map {
            let expected_id =
                nssa::AccountId::from((&node.value.0.nullifier_public_key, identifier));
            if expected_id == account_id {
                match node.value.1.entry(identifier) {
                    Entry::Occupied(mut occupied) => {
                        debug!("Updating generated private account {account_id}");
                        occupied.insert(account);
                    }
                    Entry::Vacant(vacant) => {
                        debug!("Inserting new private account identity {account_id}");
                        vacant.insert(account);
                    }
                }
                // Register in account_id_map
                self.private_key_tree
                    .account_id_map
                    .insert(account_id, ci.clone());
                return Ok(());
            }
        }

        Err(anyhow!("Account ID {account_id} not found in key chain"))
    }

    pub fn account_ids(&self) -> impl Iterator<Item = (AccountIdWithPrivacy, Option<&ChainIndex>)> {
        self.public_account_ids()
            .map(|(account_id, chain_index)| {
                (AccountIdWithPrivacy::Public(account_id), chain_index)
            })
            .chain(self.private_account_ids().map(|(account_id, chain_index)| {
                (AccountIdWithPrivacy::Private(account_id), chain_index)
            }))
    }

    pub fn public_account_ids(&self) -> impl Iterator<Item = (AccountId, Option<&ChainIndex>)> {
        self.imported_public_accounts
            .keys()
            .map(|account_id| (*account_id, None))
            .chain(
                self.public_key_tree
                    .account_id_map
                    .iter()
                    .map(|(account_id, chain_index)| (*account_id, Some(chain_index))),
            )
    }

    pub fn private_account_ids(&self) -> impl Iterator<Item = (AccountId, Option<&ChainIndex>)> {
        self.imported_private_accounts
            .iter()
            .flat_map(|(key, data)| {
                data.accounts.keys().map(|identifier| {
                    let account_id =
                        AccountId::from((&key.key_chain.nullifier_public_key, *identifier));
                    (account_id, key.chain_index.as_ref())
                })
            })
            .chain(
                self.private_key_tree
                    .key_map
                    .iter()
                    .flat_map(|(chain_index, keys_node)| {
                        keys_node
                            .account_ids()
                            .map(move |account_id| (account_id, Some(chain_index)))
                    }),
            )
    }

    /// Returns the `GroupKeyHolder` for the given label, if it exists.
    #[must_use]
    pub fn group_key_holder(&self, label: &str) -> Option<&GroupKeyHolder> {
        self.group_key_holders.get(label)
    }

    /// Inserts or replaces a `GroupKeyHolder` under the given label.
    ///
    /// If a holder already exists under this label, it is silently replaced and the old
    /// GMS is lost. Callers must ensure label uniqueness across groups.
    pub fn insert_group_key_holder(&mut self, label: String, holder: GroupKeyHolder) {
        self.group_key_holders.insert(label, holder);
    }

    pub(super) fn to_persistent(&self) -> Vec<PersistentAccountData> {
        let Self {
            imported_public_accounts,
            imported_private_accounts,
            public_key_tree,
            private_key_tree,
            // TODO: Properly persist and restore group key holders and PDA accounts
            group_key_holders: _,
            private_pda_accounts: _,
        } = self;

        let mut vec_for_storage = vec![];

        for (account_id, chain_index) in &public_key_tree.account_id_map {
            if let Some(data) = public_key_tree.key_map.get(chain_index) {
                vec_for_storage.push(PersistentAccountData::Public(PersistentAccountDataPublic {
                    account_id: *account_id,
                    chain_index: chain_index.clone(),
                    data: data.clone(),
                }));
            }
        }

        for (account_id, key) in &private_key_tree.account_id_map {
            if let Some(data) = private_key_tree.key_map.get(key) {
                vec_for_storage.push(PersistentAccountData::Private(Box::new(
                    PersistentAccountDataPrivate {
                        account_id: *account_id,
                        chain_index: key.clone(),
                        data: data.clone(),
                    },
                )));
            }
        }

        for (account_id, key) in imported_public_accounts {
            vec_for_storage.push(PersistentAccountData::ImportedPublic(
                PublicAccountPrivateInitialData {
                    account_id: *account_id,
                    pub_sign_key: key.clone(),
                },
            ));
        }

        for (key, data) in imported_private_accounts {
            let ImportedPrivateAccountKey {
                key_chain,
                chain_index,
            } = key;
            let ImportedPrivateAccountData { accounts } = data;
            for (identifier, account) in accounts {
                vec_for_storage.push(PersistentAccountData::ImportedPrivate(Box::new(
                    PrivateAccountPrivateInitialData {
                        account: account.clone(),
                        key_chain: key_chain.clone(),
                        chain_index: chain_index.clone(),
                        identifier: *identifier,
                    },
                )));
            }
        }

        vec_for_storage
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "We perform search for specific variants only"
    )]
    pub(super) fn from_persistent(persistent_accounts: Vec<PersistentAccountData>) -> Result<Self> {
        let mut imported_public_accounts = BTreeMap::new();
        let mut imported_private_accounts = BTreeMap::new();

        let public_root = persistent_accounts
            .iter()
            .find(|data| match data {
                &PersistentAccountData::Public(data) => data.chain_index == ChainIndex::root(),
                _ => false,
            })
            .cloned()
            .context("Malformed persistent account data, must have public root")?;

        let private_root = persistent_accounts
            .iter()
            .find(|data| match data {
                &PersistentAccountData::Private(data) => data.chain_index == ChainIndex::root(),
                _ => false,
            })
            .cloned()
            .context("Malformed persistent account data, must have private root")?;

        let mut public_key_tree = KeyTreePublic::new_from_root(match public_root {
            PersistentAccountData::Public(data) => data.data,
            _ => unreachable!(),
        });
        let mut private_key_tree = KeyTreePrivate::new_from_root(match private_root {
            PersistentAccountData::Private(data) => data.data,
            _ => unreachable!(),
        });

        for pers_acc_data in persistent_accounts {
            match pers_acc_data {
                PersistentAccountData::Public(data) => {
                    public_key_tree.insert(data.account_id, data.chain_index, data.data);
                }
                PersistentAccountData::Private(data) => {
                    private_key_tree.insert(data.account_id, data.chain_index, data.data);
                }
                PersistentAccountData::ImportedPublic(data) => {
                    imported_public_accounts.insert(data.account_id, data.pub_sign_key);
                }
                PersistentAccountData::ImportedPrivate(data) => {
                    imported_private_accounts
                        .entry(ImportedPrivateAccountKey {
                            key_chain: data.key_chain,
                            chain_index: data.chain_index,
                        })
                        .or_insert_with(|| ImportedPrivateAccountData {
                            accounts: BTreeMap::new(),
                        })
                        .accounts
                        .insert(data.identifier, data.account);
                }
            }
        }

        Ok(Self {
            public_key_tree,
            private_key_tree,
            imported_public_accounts,
            imported_private_accounts,
            // TODO: Properly persist and restore group key holders and PDA accounts
            group_key_holders: BTreeMap::new(),
            private_pda_accounts: BTreeMap::new(),
        })
    }
}

impl Default for UserKeyChain {
    fn default() -> Self {
        let (seed_holder, _mnemonic) = SeedHolder::new_mnemonic("");
        Self::new_with_accounts(
            KeyTreePublic::new(&seed_holder),
            KeyTreePrivate::new(&seed_holder),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_account() {
        let mut user_data = UserKeyChain::default();

        let (account_id_private, _) = user_data
            .generate_new_privacy_preserving_transaction_key_chain(Some(ChainIndex::root()));

        let is_key_chain_generated = user_data.private_account(account_id_private).is_some();

        assert!(is_key_chain_generated);

        let account_id_private_str = account_id_private.to_string();
        println!("{account_id_private_str:#?}");
        let account = &user_data.private_account(account_id_private).unwrap();
        println!("{account:#?}");
    }

    #[test]
    fn add_imported_public_account() {
        let mut user_data = UserKeyChain::default();

        let private_key = nssa::PrivateKey::new_os_random();
        let account_id = AccountId::from(&nssa::PublicKey::new_from_private_key(&private_key));

        user_data.add_imported_public_account(private_key);

        let is_account_added = user_data.pub_account_signing_key(account_id).is_some();

        assert!(is_account_added);
    }

    #[test]
    fn add_imported_private_account() {
        let mut user_data = UserKeyChain::default();

        let key_chain = KeyChain::new_os_random();
        let account_id = AccountId::from((&key_chain.nullifier_public_key, 0));
        let account = nssa_core::account::Account::default();

        user_data.add_imported_private_account(key_chain, None, 0, account);

        let is_account_added = user_data.private_account(account_id).is_some();

        assert!(is_account_added);
    }

    #[test]
    fn insert_private_imported_account() {
        let mut user_data = UserKeyChain::default();

        let key_chain = KeyChain::new_os_random();
        let account_id = AccountId::from((&key_chain.nullifier_public_key, 0));
        let account = nssa_core::account::Account::default();

        user_data.add_imported_private_account(key_chain, None, 0, account.clone());

        let new_account = nssa_core::account::Account {
            balance: 100,
            ..account
        };

        user_data
            .insert_private_account(account_id, 0, new_account)
            .unwrap();

        let retrieved_account = &user_data.private_account(account_id).unwrap();

        assert_eq!(retrieved_account.account.balance, 100);
    }

    #[test]
    fn insert_private_non_imported_account() {
        let mut user_data = UserKeyChain::default();

        let (account_id, _chain_index) = user_data
            .generate_new_privacy_preserving_transaction_key_chain(Some(ChainIndex::root()));

        let new_account = nssa_core::account::Account {
            balance: 100,
            ..nssa_core::account::Account::default()
        };

        user_data
            .insert_private_account(account_id, 0, new_account)
            .unwrap();

        let retrieved_account = &user_data.private_account(account_id).unwrap();

        assert_eq!(retrieved_account.account.balance, 100);
    }

    #[test]
    fn insert_private_non_existent_account() {
        let mut user_data = UserKeyChain::default();

        let key_chain = KeyChain::new_os_random();
        let account_id = AccountId::from((&key_chain.nullifier_public_key, 0));

        let new_account = nssa_core::account::Account {
            balance: 100,
            ..nssa_core::account::Account::default()
        };

        let result = user_data.insert_private_account(account_id, 0, new_account);

        assert!(result.is_err());
    }

    #[test]
    fn private_key_chain_iteration() {
        let mut user_data = UserKeyChain::default();

        let key_chain = KeyChain::new_os_random();
        let account_id1 = AccountId::from((&key_chain.nullifier_public_key, 0));
        let account = nssa_core::account::Account::default();
        user_data.add_imported_private_account(key_chain, None, 0, account);

        let (account_id2, chain_index2) = user_data
            .generate_new_privacy_preserving_transaction_key_chain(Some(ChainIndex::root()));
        let (account_id3, chain_index3) = user_data
            .generate_new_privacy_preserving_transaction_key_chain(Some(chain_index2.clone()));

        let key_chains: Vec<(AccountId, &KeyChain, Option<&ChainIndex>)> =
            user_data.private_account_key_chains().collect();

        assert_eq!(key_chains.len(), 4); // 1 default + 1 imported + 2 generated accounts
        // Imported account first
        assert_eq!(key_chains[0].0, account_id1);
        assert_eq!(key_chains[0].2, None);
        // Skip key_chains[1] as it's default root account
        // Then goes generated accounts
        assert_eq!(key_chains[2].0, account_id2);
        assert_eq!(key_chains[2].2, Some(&chain_index2));
        assert_eq!(key_chains[3].0, account_id3);
        assert_eq!(key_chains[3].2, Some(&chain_index3));
    }

    #[test]
    fn group_key_holder_storage_round_trip() {
        let mut user_data = UserKeyChain::default();
        assert!(user_data.group_key_holder("test-group").is_none());

        let holder = GroupKeyHolder::from_gms([42_u8; 32]);
        user_data.insert_group_key_holder(String::from("test-group"), holder.clone());

        let retrieved = user_data
            .group_key_holder("test-group")
            .expect("should exist");
        assert_eq!(retrieved.dangerous_raw_gms(), holder.dangerous_raw_gms());
    }

    #[test]
    fn group_key_holders_default_empty() {
        let user_data = UserKeyChain::default();
        assert!(user_data.group_key_holders.is_empty());
    }
}
