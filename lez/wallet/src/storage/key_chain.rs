use core::panic;
use std::collections::{BTreeMap, HashMap, HashSet, btree_map::Entry};

use anyhow::{Context as _, Result, anyhow};
use key_protocol::key_management::{
    KeyChain,
    group_key_holder::GroupKeyHolder,
    key_tree::{KeyTreePrivate, KeyTreePublic, chain_index::ChainIndex, traits::KeyTreeNode as _},
    secret_holders::{PrivateKeyHolder, SeedHolder, ViewingSecretKey},
};
use lee::{Account, AccountId, privacy_preserving_transaction::message::Message};
use lee_core::{
    Commitment, Identifier, Nullifier, NullifierSecretKey, PrivateAccountKind, SharedSecretKey,
};
use log::{debug, warn};
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
    pub pda_seed: Option<lee_core::program::PdaSeed>,
    pub authority_program_id: Option<lee_core::program::ProgramId>,
    pub account: Account,
}

/// Maps each owned or shared private account to the nullifier its next update will publish,
/// so sync can spot updates by nullifier rather than view tag.
#[derive(Default)]
pub struct NullifierIndex(HashMap<Nullifier, AccountId>);

impl NullifierIndex {
    fn next_update_nullifier(
        account_id: AccountId,
        account: &Account,
        nsk: &NullifierSecretKey,
    ) -> Nullifier {
        Nullifier::for_account_update(&Commitment::new(&account_id, account), nsk)
    }

    /// Returns the account whose next update would publish `nullifier`.
    #[must_use]
    pub fn account_for(&self, nullifier: &Nullifier) -> Option<AccountId> {
        self.0.get(nullifier).copied()
    }

    /// Indexes `account_id` by the nullifier its next update will publish.
    pub fn track(&mut self, account_id: AccountId, account: &Account, nsk: &NullifierSecretKey) {
        self.0.insert(
            Self::next_update_nullifier(account_id, account, nsk),
            account_id,
        );
    }

    /// Indexes `account_id` by the nullifier its initialization publishes.
    pub fn track_initialization(&mut self, account_id: AccountId) {
        self.0.insert(
            Nullifier::for_account_initialization(&account_id),
            account_id,
        );
    }

    /// Replaces a spent nullifier with the account's `next` one.
    pub fn update(&mut self, spent: &Nullifier, next: Nullifier, account_id: AccountId) {
        self.0.remove(spent);
        self.0.insert(next, account_id);
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct UserKeyChain {
    /// Imported public accounts.
    imported_public_accounts: BTreeMap<AccountId, lee::PrivateKey>,
    /// Imported private accounts.
    imported_private_accounts: BTreeMap<ImportedPrivateAccountKey, ImportedPrivateAccountData>,
    /// Tree of public account keys.
    public_key_tree: KeyTreePublic,
    /// Tree of private account keys.
    private_key_tree: KeyTreePrivate,
    /// Cached plaintext state of shared private accounts (PDAs and regular shared accounts),
    /// keyed by `AccountId`. Each entry stores the group label and identifier needed
    /// to re-derive keys during sync.
    shared_private_accounts: BTreeMap<lee::AccountId, SharedAccountEntry>,
    /// Group key holders for shared account management, keyed by a human-readable label.
    group_key_holders: BTreeMap<Label, GroupKeyHolder>,
    /// Dedicated sealing secret key for GMS distribution. Generated once via
    /// `wallet group new-sealing-key`. The corresponding public key is shared with
    /// group members so they can seal GMS for this wallet.
    sealing_secret_key: Option<ViewingSecretKey>,
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
    pub async fn cleanup_trees_remove_uninit_layered<F: Future<Output = Result<lee::Account>>>(
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
    pub fn pub_account_signing_key(&self, account_id: AccountId) -> Option<&lee::PrivateKey> {
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
        let account_id =
            AccountId::for_private_account(&npk, &node.value.0.viewing_public_key, kind);
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
    ) -> Option<lee::AccountId> {
        self.private_key_tree
            .register_identifier_on_node(cci, identifier)
    }

    /// Returns private account for given `account_id`. Doesn't search in pda accounts cache.
    /// Does not cover shared private accounts — use [`UserKeyChain::shared_private_account()`] for
    /// those.
    #[must_use]
    pub fn private_account(&self, account_id: AccountId) -> Option<FoundPrivateAccount<'_>> {
        self.private_accounts().find_map(|found| {
            let expected_id = AccountId::for_private_account(
                &found.key_chain.nullifier_public_key,
                &found.key_chain.viewing_public_key,
                found.kind,
            );
            (expected_id == account_id).then_some(found)
        })
    }

    /// Iterates every owned private account (imported and generated), one
    /// [`FoundPrivateAccount`] per identity. Excludes shared accounts.
    pub fn private_accounts(&self) -> impl Iterator<Item = FoundPrivateAccount<'_>> {
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
                    let account_id = AccountId::for_private_account(
                        &key.key_chain.nullifier_public_key,
                        &key.key_chain.viewing_public_key,
                        kind,
                    );
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

    /// Re-derives the [`PrivateKeyHolder`] for a shared account `entry`, dispatching on PDA vs
    /// regular. `None` if the group key holder is absent or a PDA entry lacks its program id.
    #[must_use]
    pub fn derive_shared_account_keys(
        &self,
        entry: &SharedAccountEntry,
    ) -> Option<PrivateKeyHolder> {
        let holder = self.group_key_holder(&entry.group_label)?;
        Some(match (&entry.pda_seed, &entry.authority_program_id) {
            (Some(pda_seed), Some(program_id)) => holder.derive_keys_for_pda(program_id, pda_seed),
            (Some(_), None) => return None,
            _ => holder.derive_regular_shared_account_keys_from_identifier(entry.identifier),
        })
    }

    /// Maps each owned and shared account's current-state update nullifier to its `account_id`,
    /// so co-owner updates are found during sync by nullifier rather than view tag.
    #[must_use]
    pub fn build_latest_nullifier_index(&self) -> NullifierIndex {
        let mut index = NullifierIndex::default();

        // For each (regular) found account the user owns, compute its nullifier and put
        // into the map. This is the next nullifier it will look for.
        for found in self.private_accounts() {
            let account_id = AccountId::for_private_account(
                &found.key_chain.nullifier_public_key,
                &found.key_chain.viewing_public_key,
                found.kind,
            );
            let nsk = found.key_chain.private_key_holder.nullifier_secret_key;
            index.track(account_id, found.account, &nsk);
        }

        // Same for the shared accounts.
        for (&account_id, entry) in self.shared_private_accounts_iter() {
            let Some(keys) = self.derive_shared_account_keys(entry) else {
                continue;
            };
            let nsk = keys.nullifier_secret_key;
            index.track(account_id, &entry.account, &nsk);
        }

        index
    }

    /// Applies every watched nullifier the `message` publishes: decrypts the position-aligned
    /// note, stores the new state, and rolls the index to the account's next nullifier. Returns
    /// the output slots handled, so the view-tag pass can skip them.
    pub fn sync_updates_via_nullifiers(
        &mut self,
        message: &Message,
        index: &mut NullifierIndex,
    ) -> HashSet<usize> {
        let mut handled = HashSet::new();
        for (i, action) in message.private_actions.iter().enumerate() {
            // Get the nullifier information if awaiting the nullifier.
            let Some(account_id) = index.account_for(&action.nullifier) else {
                continue;
            };
            // Try decrypting the commitment connected to the nullifier and get the next
            // nullifier to await.
            if let Some(new_nullifier) = self.apply_nullifier_update(account_id, message, i) {
                // Update the index to await for the new state of the account, i.e.
                // the new nullifier.
                index.update(&action.nullifier, new_nullifier, account_id);
                // Record that this nullifier's position can be skipped for scanning.
                handled.insert(i);
            }
        }
        handled
    }

    /// Decrypts the note at slot `i` for `account_id`, stores the new state, and returns the
    /// account's next update nullifier. `None` if keys or decryption fail.
    fn apply_nullifier_update(
        &mut self,
        account_id: AccountId,
        message: &Message,
        i: usize,
    ) -> Option<Nullifier> {
        let encrypted = &message.private_actions[i].encrypted_post_state;

        let (nsk, secret, is_shared) = if let Some(entry) = self.shared_private_account(account_id)
        {
            let keys = self.derive_shared_account_keys(entry)?;
            let secret = SharedSecretKey::decapsulate(
                &encrypted.epk,
                &keys.viewing_secret_key.d,
                &keys.viewing_secret_key.z,
            )?;
            (keys.nullifier_secret_key, secret, true)
        } else {
            let found = self.private_account(account_id)?;
            let secret = found
                .key_chain
                .calculate_shared_secret_receiver(&encrypted.epk)?;
            (
                found.key_chain.private_key_holder.nullifier_secret_key,
                secret,
                false,
            )
        };

        let (kind, new_account) = crate::decrypt_note_at(message, i, &secret)?;
        let new_nullifier = NullifierIndex::next_update_nullifier(account_id, &new_account, &nsk);

        if is_shared {
            self.update_shared_private_account_state(&account_id, new_account);
        } else {
            self.insert_private_account(account_id, kind, new_account)
                .ok()?;
        }
        Some(new_nullifier)
    }

    #[must_use]
    pub fn locate_spend(&self, account_id: AccountId, message: &Message) -> Option<usize> {
        let init = Nullifier::for_account_initialization(&account_id);
        let update = self.private_account(account_id).map(|acc| {
            Nullifier::for_account_update(
                &Commitment::new(&account_id, acc.account),
                &acc.key_chain.private_key_holder.nullifier_secret_key,
            )
        });
        message.private_actions.iter().position(|action| {
            action.nullifier == init || Some(&action.nullifier) == update.as_ref()
        })
    }

    pub fn add_imported_public_account(&mut self, private_key: lee::PrivateKey) {
        let account_id = AccountId::from(&lee::PublicKey::new_from_private_key(&private_key));

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
        account: lee_core::account::Account,
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
                let expected_id = AccountId::for_private_account(
                    &key.key_chain.nullifier_public_key,
                    &key.key_chain.viewing_public_key,
                    kind,
                );
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
            let expected_id = lee::AccountId::for_private_account(
                &node.value.0.nullifier_public_key,
                &node.value.0.viewing_public_key,
                &kind,
            );
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
                    let account_id = AccountId::for_private_account(
                        &key.key_chain.nullifier_public_key,
                        &key.key_chain.viewing_public_key,
                        kind,
                    );
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
        account_id: lee::AccountId,
    ) -> Option<&SharedAccountEntry> {
        self.shared_private_accounts.get(&account_id)
    }

    /// Inserts or replaces a shared private account entry.
    pub fn insert_shared_private_account(
        &mut self,
        account_id: lee::AccountId,
        entry: SharedAccountEntry,
    ) {
        self.shared_private_accounts.insert(account_id, entry);
    }

    /// Updates the cached account state for a shared private account.
    pub fn update_shared_private_account_state(
        &mut self,
        account_id: &lee::AccountId,
        account: lee_core::account::Account,
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
    ) -> impl Iterator<Item = (&lee::AccountId, &SharedAccountEntry)> {
        self.shared_private_accounts.iter()
    }

    /// Returns the sealing secret key for GMS distribution, if it exists.
    #[must_use]
    pub const fn sealing_secret_key(&self) -> Option<&ViewingSecretKey> {
        self.sealing_secret_key.as_ref()
    }

    /// Sets the sealing secret key for GMS distribution.
    pub const fn set_sealing_secret_key(&mut self, key: ViewingSecretKey) {
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
            sealing_secret_key: sealing_secret_key.clone(),
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
    use lee_core::{EncryptionScheme, PrivateAction, encryption::EncryptedAccountData};

    use super::*;

    #[test]
    fn nullifier_sync_updates_sole_owned_account() {
        let mut kc = UserKeyChain::default();

        let key_chain = KeyChain::new_os_random();
        let nsk = key_chain.private_key_holder.nullifier_secret_key;
        let identifier = 0;
        let account_id = AccountId::for_private_account(
            &key_chain.nullifier_public_key,
            &key_chain.viewing_public_key,
            &PrivateAccountKind::Regular(identifier),
        );

        let old_account = Account::default();
        kc.add_imported_private_account(key_chain.clone(), None, identifier, old_account.clone());

        let old_nullifier =
            Nullifier::for_account_update(&Commitment::new(&account_id, &old_account), &nsk);
        let mut index = kc.build_latest_nullifier_index();
        assert_eq!(index.account_for(&old_nullifier), Some(account_id));

        let new_account = Account {
            balance: 150,
            ..Account::default()
        };
        let new_commitment = Commitment::new(&account_id, &new_account);
        let (sender_ss, epk) = SharedSecretKey::encapsulate(&key_chain.viewing_public_key);
        let ciphertext = EncryptionScheme::encrypt(
            &new_account,
            &PrivateAccountKind::Regular(identifier),
            &sender_ss,
            &old_nullifier,
        );
        let note = EncryptedAccountData::new(
            ciphertext,
            &key_chain.nullifier_public_key,
            &key_chain.viewing_public_key,
            epk,
        );

        let message = Message {
            private_actions: vec![PrivateAction {
                nullifier: old_nullifier,
                commitment: new_commitment,
                encrypted_post_state: note,
                ..Default::default()
            }],
            ..Default::default()
        };

        let handled = kc.sync_updates_via_nullifiers(&message, &mut index);

        assert_eq!(handled, HashSet::from([0]));
        assert_eq!(
            kc.private_account(account_id).unwrap().account,
            &new_account
        );
        let new_nullifier =
            Nullifier::for_account_update(&Commitment::new(&account_id, &new_account), &nsk);
        assert_eq!(index.account_for(&new_nullifier), Some(account_id));
        assert!(index.account_for(&old_nullifier).is_none());
    }

    #[test]
    fn nullifier_sync_updates_shared_account() {
        let mut kc = UserKeyChain::default();

        let label = Label::new("group");
        let holder = GroupKeyHolder::new();
        let identifier = 0;
        let keys = holder.derive_regular_shared_account_keys_from_identifier(identifier);
        let npk = keys.generate_nullifier_public_key();
        let vpk = keys.generate_viewing_public_key();
        let nsk = keys.nullifier_secret_key;
        let account_id = AccountId::from((&npk, &vpk, identifier));

        kc.insert_group_key_holder(label.clone(), holder);
        let old_account = Account::default();
        kc.insert_shared_private_account(
            account_id,
            SharedAccountEntry {
                group_label: label,
                identifier,
                pda_seed: None,
                authority_program_id: None,
                account: old_account.clone(),
            },
        );

        let old_nullifier =
            Nullifier::for_account_update(&Commitment::new(&account_id, &old_account), &nsk);
        let mut index = kc.build_latest_nullifier_index();
        assert_eq!(index.account_for(&old_nullifier), Some(account_id));

        let new_account = Account {
            balance: 250,
            ..Account::default()
        };
        let new_commitment = Commitment::new(&account_id, &new_account);
        let (sender_ss, epk) = SharedSecretKey::encapsulate(&vpk);
        let ciphertext = EncryptionScheme::encrypt(
            &new_account,
            &PrivateAccountKind::Regular(identifier),
            &sender_ss,
            &old_nullifier,
        );
        let note = EncryptedAccountData::new(ciphertext, &npk, &vpk, epk);
        let message = Message {
            private_actions: vec![PrivateAction {
                nullifier: old_nullifier,
                commitment: new_commitment,
                encrypted_post_state: note,
                ..Default::default()
            }],
            ..Default::default()
        };

        let handled = kc.sync_updates_via_nullifiers(&message, &mut index);

        assert_eq!(handled, HashSet::from([0]));
        assert_eq!(
            kc.shared_private_account(account_id).unwrap().account,
            new_account
        );
        let new_nullifier =
            Nullifier::for_account_update(&Commitment::new(&account_id, &new_account), &nsk);
        assert_eq!(index.account_for(&new_nullifier), Some(account_id));
        assert!(index.account_for(&old_nullifier).is_none());
    }

    // The genesis catch-up seeds only the init nullifier and lets the nullifier pass decode the
    // init note and every subsequent (randomly-tagged) update. Verify a shared account rolls from
    // default through its init to a later update purely by nullifier — the path the catch-up runs.
    #[test]
    fn nullifier_sync_catches_up_shared_account_from_init() {
        let mut kc = UserKeyChain::default();

        let label = Label::new("group");
        let holder = GroupKeyHolder::new();
        let identifier = 0;
        let keys = holder.derive_regular_shared_account_keys_from_identifier(identifier);
        let npk = keys.generate_nullifier_public_key();
        let vpk = keys.generate_viewing_public_key();
        let nsk = keys.nullifier_secret_key;
        let account_id = AccountId::from((&npk, &vpk, identifier));

        kc.insert_group_key_holder(label.clone(), holder);
        kc.insert_shared_private_account(
            account_id,
            SharedAccountEntry {
                group_label: label,
                identifier,
                pda_seed: None,
                authority_program_id: None,
                account: Account::default(),
            },
        );

        let mut index = NullifierIndex::default();
        index.track_initialization(account_id);

        // A note publishing `spent` and carrying the state `next`.
        let make_message = |spent: Nullifier, next: &Account| {
            let commitment = Commitment::new(&account_id, next);
            let (sender_ss, epk) = SharedSecretKey::encapsulate(&vpk);
            let ciphertext = EncryptionScheme::encrypt(
                next,
                &PrivateAccountKind::Regular(identifier),
                &sender_ss,
                &spent,
            );
            let note = EncryptedAccountData::new(ciphertext, &npk, &vpk, epk);
            Message {
                private_actions: vec![PrivateAction {
                    nullifier: spent,
                    commitment,
                    encrypted_post_state: note,
                    ..Default::default()
                }],
                ..Default::default()
            }
        };

        // Init: default -> initialized, discovered via the seeded init nullifier.
        let initialized = Account {
            balance: 250,
            ..Account::default()
        };
        let init_msg = make_message(
            Nullifier::for_account_initialization(&account_id),
            &initialized,
        );
        assert_eq!(
            kc.sync_updates_via_nullifiers(&init_msg, &mut index),
            HashSet::from([0])
        );
        assert_eq!(
            kc.shared_private_account(account_id).unwrap().account,
            initialized
        );

        // Update: initialized -> updated, discovered via the now-tracked update nullifier.
        let updated = Account {
            balance: 500,
            ..Account::default()
        };
        let update_spent =
            Nullifier::for_account_update(&Commitment::new(&account_id, &initialized), &nsk);
        let update_msg = make_message(update_spent, &updated);
        assert_eq!(
            kc.sync_updates_via_nullifiers(&update_msg, &mut index),
            HashSet::from([0])
        );
        assert_eq!(
            kc.shared_private_account(account_id).unwrap().account,
            updated
        );
    }

    #[test]
    fn nullifier_sync_ignores_unindexed_nullifier() {
        let mut kc = UserKeyChain::default();

        let key_chain = KeyChain::new_os_random();
        let identifier = 0;
        let account_id = AccountId::for_private_account(
            &key_chain.nullifier_public_key,
            &key_chain.viewing_public_key,
            &PrivateAccountKind::Regular(identifier),
        );
        let account = Account::default();
        kc.add_imported_private_account(key_chain, None, identifier, account.clone());

        let mut index = kc.build_latest_nullifier_index();
        let unindexed = Nullifier::for_account_update(
            &Commitment::new(&AccountId::new([9; 32]), &Account::default()),
            &[9; 32],
        );
        let message = Message {
            private_actions: vec![PrivateAction {
                nullifier: unindexed,
                ..Default::default()
            }],
            ..Default::default()
        };

        let handled = kc.sync_updates_via_nullifiers(&message, &mut index);

        assert!(handled.is_empty());
        assert_eq!(kc.private_account(account_id).unwrap().account, &account);
    }

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

        let private_key = lee::PrivateKey::new_os_random();
        let account_id = AccountId::from(&lee::PublicKey::new_from_private_key(&private_key));

        user_data.add_imported_public_account(private_key);

        let is_account_added = user_data.pub_account_signing_key(account_id).is_some();

        assert!(is_account_added);
    }

    #[test]
    fn add_imported_private_account() {
        let mut user_data = UserKeyChain::default();

        let key_chain = KeyChain::new_os_random();
        let account_id = AccountId::from((
            &key_chain.nullifier_public_key,
            &key_chain.viewing_public_key,
            0,
        ));
        let account = lee_core::account::Account::default();

        user_data.add_imported_private_account(key_chain, None, 0, account);

        let is_account_added = user_data.private_account(account_id).is_some();

        assert!(is_account_added);
    }

    #[test]
    fn insert_private_imported_account() {
        let mut user_data = UserKeyChain::default();

        let key_chain = KeyChain::new_os_random();
        let account_id = AccountId::from((
            &key_chain.nullifier_public_key,
            &key_chain.viewing_public_key,
            0,
        ));
        let account = lee_core::account::Account::default();

        user_data.add_imported_private_account(key_chain, None, 0, account.clone());

        let new_account = lee_core::account::Account {
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

        let new_account = lee_core::account::Account {
            balance: 100,
            ..lee_core::account::Account::default()
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
        let account_id = AccountId::from((
            &key_chain.nullifier_public_key,
            &key_chain.viewing_public_key,
            0,
        ));

        let new_account = lee_core::account::Account {
            balance: 100,
            ..lee_core::account::Account::default()
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
        let account_id1 = AccountId::from((
            &key_chain.nullifier_public_key,
            &key_chain.viewing_public_key,
            0,
        ));
        let account = lee_core::account::Account::default();
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
        use lee_core::program::PdaSeed;

        let entry = SharedAccountEntry {
            group_label: Label::new("test-group"),
            identifier: 42,
            pda_seed: None,
            authority_program_id: None,
            account: lee_core::account::Account::default(),
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
            authority_program_id: Some([9; 8]),
            account: lee_core::account::Account::default(),
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
            authority_program_id: None,
            account: lee_core::account::Account::default(),
        };
        let encoded = bincode::serialize(&entry).expect("serialize");
        let decoded: SharedAccountEntry = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(decoded.group_label, Label::new("old"));
        assert_eq!(decoded.identifier, 1);
        assert!(decoded.pda_seed.is_none());
    }

    #[test]
    fn shared_account_derives_consistent_keys_from_group() {
        use lee_core::program::PdaSeed;

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
