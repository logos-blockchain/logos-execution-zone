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
use nssa_core::{Identifier, PrivateAccountKind};
use serde::{Deserialize, Serialize};
use testnet_initial_state::{PrivateAccountPrivateInitialData, PublicAccountPrivateInitialData};

use crate::{
    account::{AccountIdWithPrivacy, Label},
    storage::persistent::{
        KeyChainPersistentData, PersistentAccountData, PersistentAccountDataPrivate,
        PersistentAccountDataPublic,
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
    pub accounts: BTreeMap<PrivateAccountKind, Account>,
}

#[derive(Debug)]
pub struct FoundPrivateAccount<'acc> {
    pub account: &'acc Account,
    pub key_chain: &'acc KeyChain,
    pub kind: &'acc PrivateAccountKind,
    pub chain_index: Option<ChainIndex>,
}

/// Metadata for a shared account (GMS-derived), stored alongside the cached plaintext state.
/// The group label and identifier (or PDA seed) are needed to re-derive keys during sync.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct SharedAccountEntry {
    pub group_label: Label,
    pub identifier: Identifier,
    /// For PDA accounts, the seed and program ID used to derive keys via `derive_keys_for_pda`.
    /// `None` for regular shared accounts (keys derived from identifier via derivation seed).
    pub pda_seed: Option<nssa_core::program::PdaSeed>,
    pub pda_program_id: Option<nssa_core::program::ProgramId>,
    pub account: Account,
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
    /// Cached plaintext state of shared private accounts (PDAs and regular shared accounts),
    /// keyed by `AccountId`. Each entry stores the group label and identifier needed
    /// to re-derive keys during sync.
    shared_private_accounts: BTreeMap<nssa::AccountId, SharedAccountEntry>,
    /// Group key holders for shared account management, keyed by a human-readable label.
    group_key_holders: BTreeMap<Label, GroupKeyHolder>,
    /// Dedicated sealing secret key for GMS distribution. Generated once via
    /// `wallet group new-sealing-key`. The corresponding public key is shared with
    /// group members so they can seal GMS for this wallet.
    sealing_secret_key: Option<nssa_core::encryption::Scalar>,
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
            shared_private_accounts: BTreeMap::new(),
            sealing_secret_key: None,
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
        let (kind, _) = node
            .value
            .1
            .first_key_value()
            .expect("Newly created key chain node must have at least one account");
        let account_id = AccountId::for_private_account(&npk, kind);
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
    /// Does not cover shared private accounts — use [`UserKeyChain::shared_private_account()`] for
    /// those.
    #[must_use]
    pub fn private_account(&self, account_id: AccountId) -> Option<FoundPrivateAccount<'_>> {
        self.imported_private_accounts
            .iter()
            .flat_map(|(key, data)| {
                data.accounts
                    .iter()
                    .map(|(kind, account)| FoundPrivateAccount {
                        account,
                        key_chain: &key.key_chain,
                        kind,
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
                            .map(|(kind, account)| FoundPrivateAccount {
                                account,
                                key_chain: &data.value.0,
                                kind,
                                chain_index: Some(chain_index.clone()),
                            })
                    }),
            )
            .find_map(|found| {
                let expected_id = AccountId::for_private_account(
                    &found.key_chain.nullifier_public_key,
                    found.kind,
                );
                (expected_id == account_id).then_some(found)
            })
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
                data.accounts.keys().map(|kind| {
                    let account_id =
                        AccountId::for_private_account(&key.key_chain.nullifier_public_key, kind);
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
        let kind = PrivateAccountKind::Regular(identifier);
        let entry = self.imported_private_accounts.entry(key.clone());
        match entry {
            Entry::Occupied(mut occupied) => {
                let data = occupied.get_mut();
                let per_id_entry = data.accounts.entry(kind);
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
                    accounts: BTreeMap::from_iter([(kind, account)]),
                });
            }
        }
    }

    pub fn insert_private_account(
        &mut self,
        account_id: AccountId,
        kind: PrivateAccountKind,
        account: nssa_core::account::Account,
    ) -> Result<()> {
        // Try to find in shared accounts
        if let Some(entry) = self.shared_private_accounts.get_mut(&account_id) {
            debug!("Updating shared private account {account_id}");
            entry.account = account;
            return Ok(());
        }

        // Then try to update imported account
        for (key, data) in &mut self.imported_private_accounts {
            for (kind, imported_account) in &mut data.accounts {
                let expected_id =
                    AccountId::for_private_account(&key.key_chain.nullifier_public_key, kind);
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

            match node.value.1.entry(kind) {
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
                nssa::AccountId::for_private_account(&node.value.0.nullifier_public_key, &kind);
            if expected_id == account_id {
                match node.value.1.entry(kind) {
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
                data.accounts.keys().map(|kind| {
                    let account_id =
                        AccountId::for_private_account(&key.key_chain.nullifier_public_key, kind);
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
            .chain(self.shared_private_accounts.keys().map(|id| (*id, None)))
    }

    /// Returns the cached account for a shared private account, if it exists.
    #[must_use]
    pub fn shared_private_account(
        &self,
        account_id: nssa::AccountId,
    ) -> Option<&SharedAccountEntry> {
        self.shared_private_accounts.get(&account_id)
    }

    /// Inserts or replaces a shared private account entry.
    pub fn insert_shared_private_account(
        &mut self,
        account_id: nssa::AccountId,
        entry: SharedAccountEntry,
    ) {
        self.shared_private_accounts.insert(account_id, entry);
    }

    /// Updates the cached account state for a shared private account.
    pub fn update_shared_private_account_state(
        &mut self,
        account_id: &nssa::AccountId,
        account: nssa_core::account::Account,
    ) {
        if let Some(entry) = self.shared_private_accounts.get_mut(account_id) {
            entry.account = account;
        }
    }

    /// Inserts or replaces a `GroupKeyHolder` under the given label.
    ///
    /// If a holder already exists under this label, it is silently replaced and the old
    /// GMS is lost. Callers must ensure label uniqueness across groups.
    pub fn insert_group_key_holder(&mut self, label: Label, holder: GroupKeyHolder) {
        self.group_key_holders.insert(label, holder);
    }

    /// Removes the `GroupKeyHolder` under the given label, if it exists.
    pub fn remove_group_key_holder(&mut self, label: &Label) -> Option<GroupKeyHolder> {
        self.group_key_holders.remove(label)
    }

    /// Returns the `GroupKeyHolder` for the given label, if it exists.
    #[must_use]
    pub fn group_key_holder(&self, label: &Label) -> Option<&GroupKeyHolder> {
        self.group_key_holders.get(label)
    }

    /// Iterates over all group key holders.
    pub fn group_key_holders_iter(&self) -> impl Iterator<Item = (&Label, &GroupKeyHolder)> {
        self.group_key_holders.iter()
    }

    /// Iterates over all shared private accounts.
    pub fn shared_private_accounts_iter(
        &self,
    ) -> impl Iterator<Item = (&nssa::AccountId, &SharedAccountEntry)> {
        self.shared_private_accounts.iter()
    }

    /// Returns the sealing secret key for GMS distribution, if it exists.
    #[must_use]
    pub const fn sealing_secret_key(&self) -> Option<nssa_core::encryption::Scalar> {
        self.sealing_secret_key
    }

    /// Sets the sealing secret key for GMS distribution.
    pub const fn set_sealing_secret_key(&mut self, key: nssa_core::encryption::Scalar) {
        self.sealing_secret_key = Some(key);
    }

    pub(super) fn to_persistent(&self) -> KeyChainPersistentData {
        let Self {
            imported_public_accounts,
            imported_private_accounts,
            public_key_tree,
            private_key_tree,
            shared_private_accounts,
            group_key_holders,
            sealing_secret_key,
        } = self;

        let mut accounts = vec![];

        for (account_id, chain_index) in &public_key_tree.account_id_map {
            if let Some(data) = public_key_tree.key_map.get(chain_index) {
                accounts.push(PersistentAccountData::Public(PersistentAccountDataPublic {
                    account_id: *account_id,
                    chain_index: chain_index.clone(),
                    data: data.clone(),
                }));
            }
        }

        for (account_id, key) in &private_key_tree.account_id_map {
            if let Some(data) = private_key_tree.key_map.get(key) {
                accounts.push(PersistentAccountData::Private(Box::new(
                    PersistentAccountDataPrivate {
                        account_id: *account_id,
                        chain_index: key.clone(),
                        data: data.clone().into(),
                    },
                )));
            }
        }

        for (account_id, key) in imported_public_accounts {
            accounts.push(PersistentAccountData::ImportedPublic(
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
            let ImportedPrivateAccountData {
                accounts: imported_accounts,
            } = data;
            for (kind, account) in imported_accounts {
                accounts.push(PersistentAccountData::ImportedPrivate(Box::new(
                    PrivateAccountPrivateInitialData {
                        account: account.clone(),
                        key_chain: key_chain.clone(),
                        chain_index: chain_index.clone(),
                        identifier: kind.identifier(),
                    },
                )));
            }
        }

        KeyChainPersistentData {
            accounts,
            sealing_secret_key: *sealing_secret_key,
            group_key_holders: group_key_holders.clone(),
            shared_private_accounts: shared_private_accounts.clone(),
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "We perform search for specific variants only"
    )]
    pub(super) fn from_persistent(key_chain_data: KeyChainPersistentData) -> Result<Self> {
        let KeyChainPersistentData {
            accounts: persistent_accounts,
            sealing_secret_key,
            group_key_holders,
            shared_private_accounts,
        } = key_chain_data;

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
            PersistentAccountData::Private(data) => data.data.into(),
            _ => unreachable!(),
        });

        for pers_acc_data in persistent_accounts {
            match pers_acc_data {
                PersistentAccountData::Public(data) => {
                    public_key_tree.insert(data.account_id, data.chain_index, data.data);
                }
                PersistentAccountData::Private(data) => {
                    private_key_tree.insert(data.account_id, data.chain_index, data.data.into());
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
                        .insert(PrivateAccountKind::Regular(data.identifier), data.account);
                }
            }
        }

        Ok(Self {
            imported_public_accounts,
            imported_private_accounts,
            public_key_tree,
            private_key_tree,
            shared_private_accounts,
            group_key_holders,
            sealing_secret_key,
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
            .insert_private_account(account_id, PrivateAccountKind::Regular(0), new_account)
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
            .insert_private_account(account_id, PrivateAccountKind::Regular(0), new_account)
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

        let result = user_data.insert_private_account(
            account_id,
            PrivateAccountKind::Regular(0),
            new_account,
        );

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
        assert!(
            user_data
                .group_key_holder(&Label::new("test-group"))
                .is_none()
        );

        let holder = GroupKeyHolder::from_gms([42_u8; 32]);
        user_data.insert_group_key_holder(Label::new("test-group"), holder.clone());

        let retrieved = user_data
            .group_key_holder(&Label::new("test-group"))
            .expect("should exist");
        assert_eq!(retrieved.dangerous_raw_gms(), holder.dangerous_raw_gms());
    }

    #[test]
    fn group_key_holders_default_empty() {
        let user_data = UserKeyChain::default();
        assert!(user_data.group_key_holders.is_empty());
        assert!(user_data.shared_private_accounts.is_empty());
    }

    #[test]
    fn shared_account_entry_serde_round_trip() {
        use nssa_core::program::PdaSeed;

        let entry = SharedAccountEntry {
            group_label: Label::new("test-group"),
            identifier: 42,
            pda_seed: None,
            pda_program_id: None,
            account: nssa_core::account::Account::default(),
        };
        let encoded = bincode::serialize(&entry).expect("serialize");
        let decoded: SharedAccountEntry = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(decoded.group_label, Label::new("test-group"));
        assert_eq!(decoded.identifier, 42);
        assert!(decoded.pda_seed.is_none());

        let pda_entry = SharedAccountEntry {
            group_label: Label::new("pda-group"),
            identifier: u128::MAX,
            pda_seed: Some(PdaSeed::new([7_u8; 32])),
            pda_program_id: Some([9; 8]),
            account: nssa_core::account::Account::default(),
        };
        let pda_encoded = bincode::serialize(&pda_entry).expect("serialize pda");
        let pda_decoded: SharedAccountEntry =
            bincode::deserialize(&pda_encoded).expect("deserialize pda");
        assert_eq!(pda_decoded.group_label, Label::new("pda-group"));
        assert_eq!(pda_decoded.identifier, u128::MAX);
        assert_eq!(pda_decoded.pda_seed.unwrap(), PdaSeed::new([7_u8; 32]));
    }

    #[test]
    fn shared_account_entry_none_pda_seed_round_trips() {
        // Verify that an entry with pda_seed=None serializes and deserializes correctly,
        // confirming the #[serde(default)] attribute works for backward compatibility.
        let entry = SharedAccountEntry {
            group_label: Label::new("old"),
            identifier: 1,
            pda_seed: None,
            pda_program_id: None,
            account: nssa_core::account::Account::default(),
        };
        let encoded = bincode::serialize(&entry).expect("serialize");
        let decoded: SharedAccountEntry = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(decoded.group_label, Label::new("old"));
        assert_eq!(decoded.identifier, 1);
        assert!(decoded.pda_seed.is_none());
    }

    #[test]
    fn shared_account_derives_consistent_keys_from_group() {
        use nssa_core::program::PdaSeed;

        let mut user_data = UserKeyChain::default();
        let gms_holder = GroupKeyHolder::from_gms([42_u8; 32]);
        user_data.insert_group_key_holder(Label::new("my-group"), gms_holder);

        let holder = user_data.group_key_holder(&Label::new("my-group")).unwrap();

        // Regular shared account: derive via tag
        let tag = [1_u8; 32];
        let keys_a = holder.derive_keys_for_shared_account(&tag);
        let keys_b = holder.derive_keys_for_shared_account(&tag);
        assert_eq!(
            keys_a.generate_nullifier_public_key(),
            keys_b.generate_nullifier_public_key(),
        );

        // PDA shared account: derive via seed
        let seed = PdaSeed::new([2_u8; 32]);
        let pda_keys_a = holder.derive_keys_for_pda(&[9; 8], &seed);
        let pda_keys_b = holder.derive_keys_for_pda(&[9; 8], &seed);
        assert_eq!(
            pda_keys_a.generate_nullifier_public_key(),
            pda_keys_b.generate_nullifier_public_key(),
        );

        // PDA and shared derivations don't collide
        assert_ne!(
            keys_a.generate_nullifier_public_key(),
            pda_keys_a.generate_nullifier_public_key(),
        );
    }
}
