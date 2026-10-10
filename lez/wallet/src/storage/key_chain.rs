use core::panic;
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap, HashSet, btree_map::Entry},
};

use anyhow::{Context as _, Result, anyhow, ensure};
use common::{block::Block, transaction::LeeTransaction};
use futures::{Stream, TryStreamExt as _};
use key_protocol::key_management::{
    KeyChain,
    group_key_holder::GroupKeyHolder,
    key_tree::{KeyTreePrivate, KeyTreePublic, chain_index::ChainIndex, traits::KeyTreeNode as _},
    secret_holders::{PrivateKeyHolder, SeedHolder, ViewingSecretKey},
};
use lee::{
    Account, AccountId, EncryptedNote, Recipient, privacy_preserving_transaction::message::Message,
};
use lee_core::{
    BlockId, Commitment, Nullifier, NullifierPublicKey, NullifierSecretKey, PrivateAccountKind,
    SealedCast, SharedSecretKey, encryption::ViewingPublicKey, program::MessageBody,
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

pub struct ManagedPrivateAccount<'acc> {
    pub account: &'acc Account,
    pub kind: &'acc PrivateAccountKind,
    pub keys: Cow<'acc, PrivateKeyHolder>,
    pub vpk: ViewingPublicKey,
}

/// Metadata for a shared account (GMS-derived), stored alongside the cached plaintext state.
/// The group label and derivation are needed to re-derive keys during sync.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct SharedAccountEntry {
    pub group_label: Label,
    pub derivation: SharedAccountDerivation,
    pub kind: PrivateAccountKind,
    pub account: Account,
}

/// How a shared account's keys derive from its group's GMS.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum SharedAccountDerivation {
    /// A regular account, selected by a wallet-local id its co-owners agree on.
    Regular { derivation_id: [u8; 32] },
    /// A private PDA, keyed by its program and seed via `derive_keys_for_pda`.
    Pda {
        seed: lee_core::program::PdaSeed,
        program_id: lee_core::program::ProgramId,
    },
}

/// Maps each owned or shared private account to the nullifier its next transition spends; an
/// account not yet initialized waits on its empty predecessor's.
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
    /// keyed by `AccountId`. Each entry stores the group label and derivation needed
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
        awaited: &HashSet<AccountId>,
    ) -> Result<()> {
        self.public_key_tree
            .cleanup_tree_remove_uninit_layered(depth, get_account)
            .await?;
        self.private_key_tree
            .cleanup_tree_remove_uninit_layered(depth, awaited);
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

    // The recipient a recovery note for `address` names, with the nullifier key that receives
    // for it, if one of this wallet's key pairs owns it, whether or not an account is recorded
    // under it yet.
    #[must_use]
    pub fn recover(
        &self,
        address: AccountId,
        note: &EncryptedNote,
    ) -> Option<(Recipient, NullifierSecretKey)> {
        self.key_pairs().find_map(|(npk, vsk, nsk)| {
            Recipient::recover(address, note, &vsk.d, &vsk.z)
                .filter(|recipient| recipient.npk == npk)
                .map(|recipient| (recipient, nsk))
        })
    }

    // A sealed Cast's body, recipient and commitment randomness, with the nullifier key that
    // receives it, if one of this wallet's key pairs opens it.
    #[must_use]
    pub fn open(
        &self,
        sealed: &SealedCast,
    ) -> Option<(MessageBody, Recipient, [u8; 32], NullifierSecretKey)> {
        self.key_pairs().find_map(|(npk, vsk, nsk)| {
            sealed
                .open(npk, &vsk.d, &vsk.z)
                .map(|(body, recipient, rho)| (body, recipient, rho, nsk))
        })
    }

    fn owned_key_chains(&self) -> impl Iterator<Item = &KeyChain> {
        self.imported_private_accounts
            .keys()
            .map(|key| &key.key_chain)
            .chain(
                self.private_key_tree
                    .key_map
                    .values()
                    .map(|node| &node.value.0),
            )
    }

    fn key_pairs(
        &self,
    ) -> impl Iterator<Item = (NullifierPublicKey, ViewingSecretKey, NullifierSecretKey)> + '_ {
        self.owned_key_chains()
            .map(|key_chain| {
                (
                    key_chain.nullifier_public_key,
                    key_chain.private_key_holder.viewing_secret_key.clone(),
                    key_chain.private_key_holder.nullifier_secret_key(),
                )
            })
            .chain(self.shared_private_accounts.values().filter_map(|entry| {
                let keys = self.derive_shared_account_keys(entry)?;
                let nsk = keys.nullifier_secret_key();
                Some((NullifierPublicKey::from(&nsk), keys.viewing_secret_key, nsk))
            }))
    }

    /// Re-derives the [`PrivateKeyHolder`] for a shared account `entry`, dispatching on PDA vs
    /// regular. `None` if the group key holder is absent.
    #[must_use]
    pub fn derive_shared_account_keys(
        &self,
        entry: &SharedAccountEntry,
    ) -> Option<PrivateKeyHolder> {
        let holder = self.group_key_holder(&entry.group_label)?;
        Some(match &entry.derivation {
            SharedAccountDerivation::Regular { derivation_id } => {
                holder.derive_regular_shared_account_keys(derivation_id)
            }
            SharedAccountDerivation::Pda { seed, program_id } => {
                holder.derive_keys_for_pda(program_id, seed)
            }
        })
    }

    #[must_use]
    pub fn managed_private_account(
        &self,
        account_id: AccountId,
    ) -> Option<ManagedPrivateAccount<'_>> {
        if let Some(found) = self.private_account(account_id) {
            return Some(ManagedPrivateAccount {
                account: found.account,
                kind: found.kind,
                keys: Cow::Borrowed(&found.key_chain.private_key_holder),
                vpk: found.key_chain.viewing_public_key.clone(),
            });
        }
        let entry = self.shared_private_account(account_id)?;
        let keys = self.derive_shared_account_keys(entry)?;
        Some(ManagedPrivateAccount {
            account: &entry.account,
            kind: &entry.kind,
            vpk: keys.generate_viewing_public_key(),
            keys: Cow::Owned(keys),
        })
    }

    /// Maps each owned and shared account's current-state update nullifier to its `account_id`,
    /// so sync finds every account's next transition, its initialization included, by nullifier.
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
            let nsk = found.key_chain.private_key_holder.nullifier_secret_key();
            index.track(account_id, found.account, &nsk);
        }

        // Same for the shared accounts.
        for (&account_id, entry) in self.shared_private_accounts_iter() {
            let Some(keys) = self.derive_shared_account_keys(entry) else {
                continue;
            };
            let nsk = keys.nullifier_secret_key();
            index.track(account_id, &entry.account, &nsk);
        }

        index
    }

    /// Applies every watched nullifier the `message` publishes: decrypts the note in that
    /// nullifier's action, stores the new state, and rolls the index to the account's next
    /// nullifier. Returns the action slots it followed.
    pub fn sync_updates_via_nullifiers(
        &mut self,
        message: &Message,
        index: &mut NullifierIndex,
    ) -> HashSet<usize> {
        let mut followed = HashSet::new();
        for (i, action) in message.execution.private_actions.iter().enumerate() {
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
                followed.insert(i);
            }
        }
        followed
    }

    /// Trial-decrypts each note of `message` outside the `followed` slots with every owned key
    /// pair. An account whose decrypted state the message commits is recorded and followed by its
    /// next nullifier, as restoration needs for the private PDAs under its keys.
    pub fn discover_unfollowed(
        &mut self,
        message: &Message,
        followed: &HashSet<usize>,
        index: &mut NullifierIndex,
    ) {
        let commitments: HashSet<Commitment> =
            message.execution.commitments().into_iter().collect();
        let found: Vec<_> = (0..message.execution.private_actions.len())
            .filter(|slot| !followed.contains(slot))
            .flat_map(|slot| {
                let epk = &message.execution.private_actions[slot]
                    .encrypted_post_state
                    .epk;
                self.owned_key_chains().filter_map(move |key_chain| {
                    let secret = key_chain.calculate_shared_secret_receiver(epk)?;
                    let (kind, account) = crate::decrypt_note_at(message, slot, &secret)?;
                    let account_id = AccountId::for_private_account(
                        &key_chain.nullifier_public_key,
                        &key_chain.viewing_public_key,
                        &kind,
                    );
                    let nsk = key_chain.private_key_holder.nullifier_secret_key();
                    Some((account_id, kind, account, nsk))
                })
            })
            .filter(|(account_id, _, account, _)| {
                commitments.contains(&Commitment::new(account_id, account))
            })
            .collect();
        for (account_id, kind, account, nsk) in found {
            index.track(account_id, &account, &nsk);
            self.insert_private_account(account_id, kind, account)
                .expect("an owned key pair derives the account");
        }
    }

    /// Records the account a received message names, at its empty state, under the key pair that
    /// holds its nullifier key: an owned one, or a shared one whose derivation the new entry keeps.
    pub fn record_received(&mut self, recipient: &Recipient) -> Result<()> {
        let account_id = recipient.account_id();
        let Some(shared) = self
            .shared_private_accounts
            .values()
            .find(|entry| {
                self.derive_shared_account_keys(entry)
                    .is_some_and(|keys| keys.generate_nullifier_public_key() == recipient.npk)
            })
            .cloned()
        else {
            return self.insert_private_account(
                account_id,
                recipient.kind.clone(),
                Account::default(),
            );
        };
        self.insert_shared_private_account(
            account_id,
            SharedAccountEntry {
                kind: recipient.kind.clone(),
                account: Account::default(),
                ..shared
            },
        );
        Ok(())
    }

    /// Records an account through `record`, at the state the history from genesis through `tip`
    /// brings it to from its empty predecessor, or not at all: a failed, short or gapped history
    /// leaves the key chain as it was.
    pub async fn record_caught_up(
        &mut self,
        record: impl FnOnce(&mut Self) -> Result<()>,
        account_id: AccountId,
        nsk: &NullifierSecretKey,
        tip: BlockId,
        blocks: impl Stream<Item = Result<Block>>,
    ) -> Result<()> {
        let mut recorded = self.clone();
        record(&mut recorded)?;
        let mut index = NullifierIndex::default();
        index.track(account_id, &Account::default(), nsk);
        let mut expected = 1..=tip;
        let mut blocks = std::pin::pin!(blocks);
        while let Some(block) = blocks.try_next().await? {
            ensure!(
                expected.next() == Some(block.header.block_id),
                "History reaches block {} out of sequence",
                block.header.block_id
            );
            for tx in &block.body.transactions {
                // Sync updates while watching only the init nullifier.
                if let LeeTransaction::PrivacyPreserving(pp_tx) = tx {
                    recorded.sync_updates_via_nullifiers(&pp_tx.message, &mut index);
                }
            }
        }
        ensure!(expected.next().is_none(), "History ends before block {tip}");
        *self = recorded;
        Ok(())
    }

    /// Decrypts the note at slot `i` for `account_id`, stores the new state, and returns the
    /// account's next update nullifier. `None` if keys or decryption fail.
    fn apply_nullifier_update(
        &mut self,
        account_id: AccountId,
        message: &Message,
        i: usize,
    ) -> Option<Nullifier> {
        let epk = &message.execution.private_actions[i]
            .encrypted_post_state
            .epk;
        let keys = self.managed_private_account(account_id)?.keys;
        let secret = SharedSecretKey::decapsulate(
            epk,
            &keys.viewing_secret_key.d,
            &keys.viewing_secret_key.z,
        )?;
        let nsk = keys.nullifier_secret_key();

        let (kind, new_account) = crate::decrypt_note_at(message, i, &secret)?;
        // The note is the sender's claim: follow it only to a state the message commits.
        if !message
            .execution
            .commitments()
            .contains(&Commitment::new(&account_id, &new_account))
        {
            return None;
        }
        let new_nullifier = NullifierIndex::next_update_nullifier(account_id, &new_account, &nsk);
        self.insert_private_account(account_id, kind, new_account)
            .ok()?;
        Some(new_nullifier)
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
        account: Account,
    ) {
        let key = ImportedPrivateAccountKey {
            key_chain,
            chain_index,
        };
        let kind = PrivateAccountKind::Regular;
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

        // Then try an imported key pair, which may receive at a kind it has not recorded yet
        for (key, data) in &mut self.imported_private_accounts {
            let expected_id = AccountId::for_private_account(
                &key.key_chain.nullifier_public_key,
                &key.key_chain.viewing_public_key,
                &kind,
            );
            if expected_id == account_id {
                debug!("Updating imported private account {account_id}");
                data.accounts.insert(kind, account);
                return Ok(());
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
                        kind: kind.clone(),
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
                        .insert(data.kind, data.account);
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
pub(crate) mod tests {

    use futures::executor::block_on;
    use lee::{
        RecipientEncryption, RecoveryBinding,
        privacy_preserving_transaction::{
            PrivacyPreservingTransaction, WitnessSet, circuit::Proof,
        },
    };
    use lee_core::{
        EncryptionScheme, EphemeralSecretKey, PrivateAction, ProvenExecution,
        account::Actor,
        encryption::{EncryptedNote, ViewingPublicKey},
        program::PdaSeed,
    };

    use super::*;

    // A block whose one transaction carries `message`.
    pub fn block_of(id: u64, message: Message) -> Block {
        let witness_set = WitnessSet::for_message(&message, Proof::from_inner(Vec::new()), &[]);
        common::test_utils::produce_dummy_block(
            id,
            None,
            vec![LeeTransaction::PrivacyPreserving(
                PrivacyPreservingTransaction::new(message, witness_set),
            )],
        )
    }

    // A message whose one action spends `spent` and carries `next` as `account_id`'s state,
    // encrypted to `vpk`.
    pub fn transition_message(
        account_id: AccountId,
        kind: &PrivateAccountKind,
        vpk: &ViewingPublicKey,
        spent: Nullifier,
        next: &Account,
    ) -> Message {
        let (secret, epk) = SharedSecretKey::encapsulate(vpk);
        Message {
            execution: ProvenExecution {
                private_actions: vec![PrivateAction {
                    nullifier: spent,
                    commitment: Commitment::new(&account_id, next),
                    encrypted_post_state: EncryptedNote {
                        ciphertext: EncryptionScheme::encrypt(next, kind, &secret, &spent, None),
                        epk,
                    },
                    ..Default::default()
                }],
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn a_key_node_opens_only_recovery_notes_naming_its_nullifier_key() {
        let mut kc = UserKeyChain::default();
        let chain_index = kc.create_private_accounts_key(None);
        let key_chain = kc.private_key_tree.key_map[&chain_index].value.0.clone();
        let recipient = Recipient {
            npk: key_chain.nullifier_public_key,
            vpk: key_chain.viewing_public_key,
            kind: PrivateAccountKind::Regular,
            opening: Some([4; 32]),
        };
        let bind = |recipient| {
            RecipientEncryption {
                recipient,
                esk: EphemeralSecretKey([5; 32]),
            }
            .bind_recovery()
        };

        let RecoveryBinding { address, note } = bind(recipient.clone());
        assert_eq!(
            kc.recover(address, &note),
            Some((
                recipient.clone(),
                key_chain.private_key_holder.nullifier_secret_key()
            ))
        );

        let RecoveryBinding { address, note } = bind(Recipient {
            npk: NullifierPublicKey([6; 32]),
            ..recipient
        });
        assert_eq!(kc.recover(address, &note), None);
    }

    #[test]
    fn a_key_node_opens_only_casts_sealed_to_its_keys() {
        let mut kc = UserKeyChain::default();
        let chain_index = kc.create_private_accounts_key(None);
        let key_chain = kc.private_key_tree.key_map[&chain_index].value.0.clone();
        let recipient = Recipient {
            npk: key_chain.nullifier_public_key,
            vpk: key_chain.viewing_public_key,
            kind: PrivateAccountKind::Regular,
            opening: Some([4; 32]),
        };
        let seal = |recipient: Recipient| {
            let body = MessageBody {
                from: Actor::new(AccountId::new([5; 32]), AccountId::new([6; 32])),
                to: Actor::new(recipient.address(), AccountId::new([7; 32])),
                message: vec![8; 2],
            };
            RecipientEncryption {
                recipient,
                esk: EphemeralSecretKey([9; 32]),
            }
            .seal_message(&body, None)
            .unwrap()
        };

        let (_, opened, _, nsk) = kc.open(&seal(recipient.clone())).unwrap();
        assert_eq!(
            (opened, nsk),
            (
                recipient.clone(),
                key_chain.private_key_holder.nullifier_secret_key()
            )
        );
        assert!(
            kc.open(&seal(Recipient {
                npk: NullifierPublicKey([10; 32]),
                ..recipient
            }))
            .is_none()
        );
    }

    #[test]
    fn nullifier_sync_updates_sole_owned_account() {
        let mut kc = UserKeyChain::default();
        let key_chain = KeyChain::new_os_random();
        let nsk = key_chain.private_key_holder.nullifier_secret_key();
        let account_id = AccountId::for_private_account(
            &key_chain.nullifier_public_key,
            &key_chain.viewing_public_key,
            &PrivateAccountKind::Regular,
        );
        kc.add_imported_private_account(key_chain.clone(), None, Account::default());
        let mut index = kc.build_latest_nullifier_index();
        let spent = Nullifier::for_account_initialization(&account_id, &nsk);
        let new_account = Account::funded(150);

        kc.sync_updates_via_nullifiers(
            &transition_message(
                account_id,
                &PrivateAccountKind::Regular,
                &key_chain.viewing_public_key,
                spent,
                &new_account,
            ),
            &mut index,
        );

        assert_eq!(
            kc.private_account(account_id).unwrap().account,
            &new_account
        );
        let new_nullifier =
            Nullifier::for_account_update(&Commitment::new(&account_id, &new_account), &nsk);
        assert_eq!(index.account_for(&new_nullifier), Some(account_id));
        assert!(index.account_for(&spent).is_none());
    }

    #[test]
    fn a_shared_account_is_followed_from_its_first_nullifier_through_each_update() {
        let mut kc = UserKeyChain::default();
        let label = Label::new("group");
        let holder = GroupKeyHolder::new();
        let derivation_id = [0; 32];
        let keys = holder.derive_regular_shared_account_keys(&derivation_id);
        let vpk = keys.generate_viewing_public_key();
        let nsk = keys.nullifier_secret_key();
        let account_id = AccountId::from((&keys.generate_nullifier_public_key(), &vpk));
        kc.insert_group_key_holder(label.clone(), holder);
        kc.insert_shared_private_account(
            account_id,
            SharedAccountEntry {
                group_label: label,
                derivation: SharedAccountDerivation::Regular { derivation_id },
                kind: PrivateAccountKind::Regular,
                account: Account::default(),
            },
        );
        let mut index = kc.build_latest_nullifier_index();

        let initialized = Account::funded(250);
        let updated = Account::funded(500);
        for (spent, next) in [
            (
                Nullifier::for_account_initialization(&account_id, &nsk),
                &initialized,
            ),
            (
                Nullifier::for_account_update(&Commitment::new(&account_id, &initialized), &nsk),
                &updated,
            ),
        ] {
            kc.sync_updates_via_nullifiers(
                &transition_message(account_id, &PrivateAccountKind::Regular, &vpk, spent, next),
                &mut index,
            );
            assert_eq!(
                &kc.shared_private_account(account_id).unwrap().account,
                next
            );
        }
    }

    #[test]
    fn an_allocated_key_node_is_followed_from_its_first_nullifier_through_each_update() {
        let mut kc = UserKeyChain::default();
        let (account_id, chain_index) =
            kc.generate_new_privacy_preserving_transaction_key_chain(None);
        let key_chain = kc
            .private_account_key_chain_by_index(&chain_index)
            .unwrap()
            .clone();
        let nsk = key_chain.private_key_holder.nullifier_secret_key();
        let mut index = kc.build_latest_nullifier_index();

        let initialized = Account::funded(250);
        let updated = Account::funded(500);
        for (spent, next) in [
            (
                Nullifier::for_account_initialization(&account_id, &nsk),
                &initialized,
            ),
            (
                Nullifier::for_account_update(&Commitment::new(&account_id, &initialized), &nsk),
                &updated,
            ),
        ] {
            kc.sync_updates_via_nullifiers(
                &transition_message(
                    account_id,
                    &PrivateAccountKind::Regular,
                    &key_chain.viewing_public_key,
                    spent,
                    next,
                ),
                &mut index,
            );
            assert_eq!(kc.private_account(account_id).unwrap().account, next);
        }
    }

    #[test]
    fn sync_takes_each_note_from_its_nullifiers_action_whatever_the_commitment_order() {
        let mut kc = UserKeyChain::default();
        let accounts: Vec<_> = std::iter::repeat_with(|| {
            let (account_id, chain_index) =
                kc.generate_new_privacy_preserving_transaction_key_chain(None);
            let key_chain = kc
                .private_account_key_chain_by_index(&chain_index)
                .unwrap()
                .clone();
            (account_id, key_chain)
        })
        .take(2)
        .collect();
        let states = [Account::funded(1), Account::funded(2)];
        let mut actions: Vec<_> = accounts
            .iter()
            .zip(&states)
            .flat_map(|((account_id, key_chain), next)| {
                transition_message(
                    *account_id,
                    &PrivateAccountKind::Regular,
                    &key_chain.viewing_public_key,
                    Nullifier::for_account_initialization(
                        account_id,
                        &key_chain.private_key_holder.nullifier_secret_key(),
                    ),
                    next,
                )
                .execution
                .private_actions
            })
            .collect();
        // Output obfuscation permutes commitments independently of nullifiers and their notes.
        let (first, second) = actions.split_at_mut(1);
        std::mem::swap(&mut first[0].commitment, &mut second[0].commitment);
        let message = Message {
            execution: ProvenExecution {
                private_actions: actions,
                ..Default::default()
            },
            ..Default::default()
        };

        kc.sync_updates_via_nullifiers(&message, &mut kc.build_latest_nullifier_index());

        for ((account_id, _), next) in accounts.iter().zip(&states) {
            assert_eq!(kc.private_account(*account_id).unwrap().account, next);
        }
    }

    #[test]
    fn a_private_pda_the_wallet_did_not_create_is_recognized_from_its_funding_publication() {
        let mut kc = UserKeyChain::default();
        let (_, chain_index) = kc.generate_new_privacy_preserving_transaction_key_chain(None);
        let key_chain = kc
            .private_account_key_chain_by_index(&chain_index)
            .unwrap()
            .clone();
        let recipient = Recipient {
            npk: key_chain.nullifier_public_key,
            vpk: key_chain.viewing_public_key,
            kind: PrivateAccountKind::Pda {
                account_id: AccountId::new([4; 32]),
                seed: PdaSeed::new([5; 32]),
            },
            opening: None,
        };
        let RecoveryBinding { address, note } = RecipientEncryption {
            recipient: recipient.clone(),
            esk: EphemeralSecretKey([6; 32]),
        }
        .bind_recovery();
        let (recognized, nsk) = kc
            .recover(address, &note)
            .expect("the publication names a destination under the node's keys");
        assert_eq!(recognized, recipient);
        let pda_id = recognized.account_id();
        let funded = Account::funded(70);
        let receipt = transition_message(
            pda_id,
            &recognized.kind,
            &recognized.vpk,
            Nullifier::for_account_initialization(&pda_id, &nsk),
            &funded,
        );

        kc.sync_updates_via_nullifiers(&receipt, &mut kc.build_latest_nullifier_index());
        assert!(kc.private_account(pda_id).is_none());

        kc.insert_private_account(pda_id, recognized.kind, Account::default())
            .unwrap();
        kc.sync_updates_via_nullifiers(&receipt, &mut kc.build_latest_nullifier_index());
        assert_eq!(kc.private_account(pda_id).unwrap().account, &funded);
    }

    #[test]
    fn sync_follows_a_nullifier_only_to_a_state_its_message_commits() {
        let mut kc = UserKeyChain::default();
        let (account_id, chain_index) =
            kc.generate_new_privacy_preserving_transaction_key_chain(None);
        let key_chain = kc
            .private_account_key_chain_by_index(&chain_index)
            .unwrap()
            .clone();
        let mut index = kc.build_latest_nullifier_index();
        let initialized = Account::funded(250);
        let committed = transition_message(
            account_id,
            &PrivateAccountKind::Regular,
            &key_chain.viewing_public_key,
            Nullifier::for_account_initialization(
                &account_id,
                &key_chain.private_key_holder.nullifier_secret_key(),
            ),
            &initialized,
        );
        let mut uncommitted = committed.clone();
        uncommitted.execution.private_actions[0].commitment =
            Commitment::new(&account_id, &Account::funded(1_000));

        assert!(
            kc.sync_updates_via_nullifiers(&uncommitted, &mut index)
                .is_empty()
        );
        assert_eq!(
            kc.private_account(account_id).unwrap().account,
            &Account::default()
        );

        kc.sync_updates_via_nullifiers(&committed, &mut index);
        assert_eq!(
            kc.private_account(account_id).unwrap().account,
            &initialized
        );
    }

    #[test]
    fn restoration_discovers_a_private_pda_under_its_keys_only_from_a_committed_note() {
        let mut kc = UserKeyChain::default();
        let (_, chain_index) = kc.generate_new_privacy_preserving_transaction_key_chain(None);
        let key_chain = kc
            .private_account_key_chain_by_index(&chain_index)
            .unwrap()
            .clone();
        let nsk = key_chain.private_key_holder.nullifier_secret_key();
        let kind = PrivateAccountKind::Pda {
            account_id: AccountId::new([4; 32]),
            seed: PdaSeed::new([5; 32]),
        };
        let pda_id = AccountId::for_private_account(
            &key_chain.nullifier_public_key,
            &key_chain.viewing_public_key,
            &kind,
        );
        let mut index = kc.build_latest_nullifier_index();
        let restore = |kc: &mut UserKeyChain, index: &mut NullifierIndex, message: &Message| {
            let followed = kc.sync_updates_via_nullifiers(message, index);
            kc.discover_unfollowed(message, &followed, index);
        };
        let initialized = Account::funded(70);
        let funding = transition_message(
            pda_id,
            &kind,
            &key_chain.viewing_public_key,
            Nullifier::for_account_initialization(&pda_id, &nsk),
            &initialized,
        );
        let mut uncommitted = funding.clone();
        uncommitted.execution.private_actions[0].commitment =
            Commitment::new(&pda_id, &Account::funded(1_000));

        restore(&mut kc, &mut index, &uncommitted);
        assert!(kc.private_account(pda_id).is_none());

        restore(&mut kc, &mut index, &funding);
        let updated = Account::funded(90);
        kc.sync_updates_via_nullifiers(
            &transition_message(
                pda_id,
                &kind,
                &key_chain.viewing_public_key,
                Nullifier::for_account_update(&Commitment::new(&pda_id, &initialized), &nsk),
                &updated,
            ),
            &mut index,
        );
        assert_eq!(kc.private_account(pda_id).unwrap().account, &updated);
    }

    #[test]
    fn a_recovery_records_its_destination_only_once_its_whole_history_arrives() {
        let mut kc = UserKeyChain::default();
        let (_, chain_index) = kc.generate_new_privacy_preserving_transaction_key_chain(None);
        let key_chain = kc
            .private_account_key_chain_by_index(&chain_index)
            .unwrap()
            .clone();
        let nsk = key_chain.private_key_holder.nullifier_secret_key();
        let recipient = Recipient {
            npk: key_chain.nullifier_public_key,
            vpk: key_chain.viewing_public_key,
            kind: PrivateAccountKind::Pda {
                account_id: AccountId::new([4; 32]),
                seed: PdaSeed::new([5; 32]),
            },
            opening: None,
        };
        let pda_id = recipient.account_id();
        let initialized = Account::funded(70);
        let initialization = block_of(
            1,
            transition_message(
                pda_id,
                &recipient.kind,
                &recipient.vpk,
                Nullifier::for_account_initialization(&pda_id, &nsk),
                &initialized,
            ),
        );
        let tip = common::test_utils::produce_dummy_block(2, None, Vec::new());
        let recover = |kc: &mut UserKeyChain, history: Vec<Result<Block>>| {
            block_on(kc.record_caught_up(
                |kc| kc.record_received(&recipient),
                pda_id,
                &nsk,
                2,
                futures::stream::iter(history),
            ))
        };
        let before = kc.clone();

        for history in [
            vec![Ok(initialization.clone()), Err(anyhow!("unavailable"))],
            vec![Ok(initialization.clone())],
            vec![Ok(tip.clone())],
        ] {
            assert!(recover(&mut kc, history).is_err());
            assert_eq!(kc, before);
        }

        recover(&mut kc, vec![Ok(initialization), Ok(tip)]).unwrap();
        assert_eq!(kc.private_account(pda_id).unwrap().account, &initialized);
    }

    #[test]
    fn a_kind_received_under_shared_keys_is_recorded_under_their_derivation() {
        let mut kc = UserKeyChain::default();
        let label = Label::new("group");
        kc.insert_group_key_holder(label.clone(), GroupKeyHolder::from_gms([0; 32]));
        let regular = SharedAccountEntry {
            group_label: label,
            derivation: SharedAccountDerivation::Regular {
                derivation_id: [1; 32],
            },
            kind: PrivateAccountKind::Regular,
            account: Account::default(),
        };
        let keys = kc.derive_shared_account_keys(&regular).unwrap();
        let (npk, vpk) = (
            keys.generate_nullifier_public_key(),
            keys.generate_viewing_public_key(),
        );
        kc.insert_shared_private_account(AccountId::from((&npk, &vpk)), regular.clone());
        let recipient = Recipient {
            npk,
            vpk,
            kind: PrivateAccountKind::Pda {
                account_id: AccountId::new([4; 32]),
                seed: PdaSeed::new([5; 32]),
            },
            opening: None,
        };

        kc.record_received(&recipient).unwrap();

        assert_eq!(
            kc.shared_private_account(recipient.account_id()),
            Some(&SharedAccountEntry {
                kind: recipient.kind.clone(),
                ..regular
            })
        );
    }

    #[test]
    fn a_private_pda_recorded_beside_its_key_nodes_account_stays_followed_once_persisted() {
        let mut kc = UserKeyChain::default();
        let (account_id, chain_index) =
            kc.generate_new_privacy_preserving_transaction_key_chain(None);
        let key_chain = kc
            .private_account_key_chain_by_index(&chain_index)
            .unwrap()
            .clone();
        let kind = PrivateAccountKind::Pda {
            account_id: AccountId::new([4; 32]),
            seed: PdaSeed::new([5; 32]),
        };
        let pda_id = AccountId::for_private_account(
            &key_chain.nullifier_public_key,
            &key_chain.viewing_public_key,
            &kind,
        );
        let recorded = Account::funded(70);
        kc.insert_private_account(pda_id, kind, recorded.clone())
            .unwrap();

        let restored = UserKeyChain::from_persistent(kc.to_persistent()).unwrap();

        assert!(restored.private_account(account_id).is_some());
        assert_eq!(restored.private_account(pda_id).unwrap().account, &recorded);
        assert_eq!(
            restored
                .build_latest_nullifier_index()
                .account_for(&Nullifier::for_account_update(
                    &Commitment::new(&pda_id, &recorded),
                    &key_chain.private_key_holder.nullifier_secret_key(),
                )),
            Some(pda_id)
        );
    }

    #[test]
    fn nullifier_sync_ignores_unindexed_nullifier() {
        let mut kc = UserKeyChain::default();

        let key_chain = KeyChain::new_os_random();
        let account_id = AccountId::for_private_account(
            &key_chain.nullifier_public_key,
            &key_chain.viewing_public_key,
            &PrivateAccountKind::Regular,
        );
        let account = Account::default();
        kc.add_imported_private_account(key_chain, None, account.clone());

        let mut index = kc.build_latest_nullifier_index();
        let unindexed = Nullifier::for_account_update(
            &Commitment::new(&AccountId::new([9; 32]), &Account::default()),
            &[9; 32],
        );
        let message = Message {
            execution: ProvenExecution {
                private_actions: vec![PrivateAction {
                    nullifier: unindexed,
                    ..Default::default()
                }],
                ..Default::default()
            },
            ..Default::default()
        };

        kc.sync_updates_via_nullifiers(&message, &mut index);

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
        ));
        let account = lee_core::account::Account::default();

        user_data.add_imported_private_account(key_chain, None, account);

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
        ));
        let account = lee_core::account::Account::default();

        user_data.add_imported_private_account(key_chain, None, account.clone());

        let new_account = lee_core::account::Account {
            nonce: account.nonce,
            ..lee_core::account::Account::funded(100)
        };

        user_data
            .insert_private_account(account_id, PrivateAccountKind::Regular, new_account)
            .unwrap();

        let retrieved_account = &user_data.private_account(account_id).unwrap();

        assert_eq!(
            retrieved_account.account.data.native_balance().unwrap(),
            100
        );
    }

    #[test]
    fn insert_and_restore_private_imported_accounts_of_unknown_kinds() {
        let mut user_data = UserKeyChain::default();

        let key_chain = KeyChain::new_os_random();
        let kinds = [5, 6].map(|seed| PrivateAccountKind::Pda {
            account_id: AccountId::new([4; 32]),
            seed: lee_core::program::PdaSeed::new([seed; 32]),
        });
        let account_ids = kinds.clone().map(|kind| {
            AccountId::for_private_account(
                &key_chain.nullifier_public_key,
                &key_chain.viewing_public_key,
                &kind,
            )
        });
        user_data.add_imported_private_account(
            key_chain,
            None,
            lee_core::account::Account::default(),
        );

        for ((account_id, kind), balance) in account_ids.into_iter().zip(kinds).zip([100, 200]) {
            user_data
                .insert_private_account(
                    account_id,
                    kind,
                    lee_core::account::Account::funded(balance),
                )
                .unwrap();
        }
        let restored = UserKeyChain::from_persistent(user_data.to_persistent()).unwrap();

        for (account_id, balance) in account_ids.into_iter().zip([100, 200]) {
            assert_eq!(
                restored
                    .private_account(account_id)
                    .unwrap()
                    .account
                    .data
                    .native_balance()
                    .unwrap(),
                balance
            );
        }
    }

    #[test]
    fn insert_private_non_imported_account() {
        let mut user_data = UserKeyChain::default();

        let (account_id, _chain_index) = user_data
            .generate_new_privacy_preserving_transaction_key_chain(Some(ChainIndex::root()));

        let new_account = lee_core::account::Account::funded(100);

        user_data
            .insert_private_account(account_id, PrivateAccountKind::Regular, new_account)
            .unwrap();

        let retrieved_account = &user_data.private_account(account_id).unwrap();

        assert_eq!(
            retrieved_account.account.data.native_balance().unwrap(),
            100
        );
    }

    #[test]
    fn insert_private_non_existent_account() {
        let mut user_data = UserKeyChain::default();

        let key_chain = KeyChain::new_os_random();
        let account_id = AccountId::from((
            &key_chain.nullifier_public_key,
            &key_chain.viewing_public_key,
        ));

        let new_account = lee_core::account::Account::funded(100);

        let result =
            user_data.insert_private_account(account_id, PrivateAccountKind::Regular, new_account);

        assert!(result.is_err());
    }

    #[test]
    fn private_key_chain_iteration() {
        let mut user_data = UserKeyChain::default();

        let key_chain = KeyChain::new_os_random();
        let account_id1 = AccountId::from((
            &key_chain.nullifier_public_key,
            &key_chain.viewing_public_key,
        ));
        let account = lee_core::account::Account::default();
        user_data.add_imported_private_account(key_chain, None, account);

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
    fn distinct_derivation_ids_select_distinct_shared_regular_accounts() {
        let label = Label::new("group");
        let mut kc = UserKeyChain::default();
        kc.insert_group_key_holder(label.clone(), GroupKeyHolder::new());
        let account_id = |derivation_id| {
            let keys = kc
                .derive_shared_account_keys(&SharedAccountEntry {
                    group_label: label.clone(),
                    derivation: SharedAccountDerivation::Regular { derivation_id },
                    kind: PrivateAccountKind::Regular,
                    account: Account::default(),
                })
                .expect("the group is held");
            AccountId::from((
                &keys.generate_nullifier_public_key(),
                &keys.generate_viewing_public_key(),
            ))
        };

        assert_eq!(account_id([1; 32]), account_id([1; 32]));
        assert_ne!(account_id([1; 32]), account_id([2; 32]));
    }

    #[test]
    fn shared_account_entry_serde_round_trip() {
        use lee_core::program::PdaSeed;

        for (derivation, kind) in [
            (
                SharedAccountDerivation::Regular {
                    derivation_id: [42; 32],
                },
                PrivateAccountKind::Regular,
            ),
            (
                SharedAccountDerivation::Pda {
                    seed: PdaSeed::new([7_u8; 32]),
                    program_id: [9; 8],
                },
                PrivateAccountKind::Pda {
                    account_id: AccountId::from_builtin_program([9; 8]),
                    seed: PdaSeed::new([7_u8; 32]),
                },
            ),
        ] {
            let entry = SharedAccountEntry {
                group_label: Label::new("test-group"),
                derivation,
                kind,
                account: lee_core::account::Account::default(),
            };
            let encoded = bincode::serialize(&entry).expect("serialize");
            let decoded: SharedAccountEntry = bincode::deserialize(&encoded).expect("deserialize");
            assert_eq!(decoded, entry);
        }
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
