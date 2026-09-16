use std::{
    collections::{BTreeMap, btree_map::Entry},
    io::{BufReader, Write as _},
    path::Path,
};

use anyhow::{Context as _, Result};
use bip39::Mnemonic;
use key_chain::UserKeyChain;
use key_protocol::key_management::{
    key_tree::{KeyTreePrivate, KeyTreePublic},
    secret_holders::SeedHolder,
};
use lee_core::BlockId;

use crate::{
    account::{AccountIdWithPrivacy, Label},
    storage::{persistent::PersistentStorage, referral::ReferralStore},
};

pub mod key_chain;
mod persistent;
pub mod referral;

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Storage {
    key_chain: UserKeyChain,
    labels: BTreeMap<Label, AccountIdWithPrivacy>,
    last_synced_block: BlockId,
    referral: ReferralStore,
}

impl Storage {
    pub fn new(password: &str) -> Result<(Self, Mnemonic)> {
        // TODO: Use password for storage encryption
        // Question by @Arjentix: We probably want to encrypt file, not in-memory data?
        let _ = password;
        let (seed_holder, mnemonic) = SeedHolder::new_mnemonic("");
        let public_tree = KeyTreePublic::new(&seed_holder);
        let private_tree = KeyTreePrivate::new(&seed_holder);

        Ok((
            Self {
                key_chain: UserKeyChain::new_with_accounts(public_tree, private_tree),
                labels: BTreeMap::new(),
                last_synced_block: 0,
                referral: ReferralStore::default(),
            },
            mnemonic,
        ))
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "We want to provide a specific error message for not found case"
        )]
        match std::fs::File::open(path) {
            Ok(file) => {
                let storage_content = BufReader::new(file);
                let persistent: persistent::PersistentStorage =
                    serde_json::from_reader(storage_content)
                        .context("Failed to parse storage file")?;
                Self::from_persistent(persistent)
            }
            Err(err) => match err.kind() {
                std::io::ErrorKind::NotFound => {
                    anyhow::bail!(
                        "Storage not found, please setup roots from config command beforehand"
                    );
                }
                _ => {
                    anyhow::bail!("IO error {err:#?}");
                }
            },
        }
    }

    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        let persistent = self.to_persistent();
        let storage_serialized = serde_json::to_vec_pretty(&persistent)?;
        let mut file = std::fs::File::create(path).context("Failed to create file")?;
        file.write_all(&storage_serialized)
            .context("Failed to write to file")?;
        file.sync_all().context("Failed to sync file")?;

        Ok(())
    }

    /// Restore storage from an existing mnemonic phrase.
    pub fn restore(&mut self, mnemonic: &Mnemonic, password: &str) -> Result<()> {
        // TODO: Use password for storage encryption
        let _ = password;
        let seed_holder = SeedHolder::from_mnemonic(mnemonic, "");
        let public_tree = KeyTreePublic::new(&seed_holder);
        let private_tree = KeyTreePrivate::new(&seed_holder);

        self.key_chain = UserKeyChain::new_with_accounts(public_tree, private_tree);
        self.labels = BTreeMap::new();
        self.last_synced_block = 0;
        self.referral = ReferralStore::default();

        Ok(())
    }

    #[must_use]
    pub const fn referral(&self) -> &ReferralStore {
        &self.referral
    }

    pub const fn referral_mut(&mut self) -> &mut ReferralStore {
        &mut self.referral
    }

    #[must_use]
    pub const fn key_chain(&self) -> &UserKeyChain {
        &self.key_chain
    }

    pub const fn key_chain_mut(&mut self) -> &mut UserKeyChain {
        &mut self.key_chain
    }

    pub fn check_label_availability(&self, label: &Label) -> Result<()> {
        if self.labels.contains_key(label) {
            Err(anyhow::anyhow!("Label `{label}` is already in use"))
        } else {
            Ok(())
        }
    }

    pub fn add_label(&mut self, label: Label, account_id: AccountIdWithPrivacy) -> Result<()> {
        // Creating error beforehand to avoid cloning label.
        let err = anyhow::anyhow!("Label `{label}` is already in use");

        match self.labels.entry(label) {
            Entry::Occupied(_) => Err(err),
            Entry::Vacant(entry) => {
                entry.insert(account_id);
                Ok(())
            }
        }
    }

    #[must_use]
    pub fn resolve_label(&self, label: &Label) -> Option<AccountIdWithPrivacy> {
        self.labels.get(label).copied()
    }

    // TODO: Slow implementation, consider maintaining reverse mapping if needed.
    pub fn labels_for_account(
        &self,
        account_id: AccountIdWithPrivacy,
    ) -> impl Iterator<Item = &Label> {
        self.labels
            .iter()
            .filter(move |(_, id)| **id == account_id)
            .map(|(label, _)| label)
    }

    pub const fn set_last_synced_block(&mut self, block_id: BlockId) {
        self.last_synced_block = block_id;
    }

    #[must_use]
    pub const fn last_synced_block(&self) -> BlockId {
        self.last_synced_block
    }

    fn to_persistent(&self) -> PersistentStorage {
        let Self {
            key_chain,
            last_synced_block,
            labels,
            referral,
        } = self;
        let key_chain_data = key_chain.to_persistent();

        PersistentStorage {
            key_chain: key_chain_data,
            last_synced_block: *last_synced_block,
            labels: labels.clone(),
            referral: referral.clone(),
        }
    }

    fn from_persistent(persistent: PersistentStorage) -> Result<Self> {
        let PersistentStorage {
            key_chain,
            last_synced_block,
            labels,
            referral,
        } = persistent;

        Ok(Self {
            key_chain: UserKeyChain::from_persistent(key_chain)?,
            last_synced_block,
            labels,
            referral,
        })
    }
}

