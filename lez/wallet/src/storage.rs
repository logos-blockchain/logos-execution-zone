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

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn save_load_roundtrip() {
        let (mut storage, _) = Storage::new("test_pass").unwrap();

        let (account_id, _) = storage
            .key_chain_mut()
            .generate_new_public_transaction_private_key(None);

        let label = Label::new("test_label");
        storage
            .add_label(label, AccountIdWithPrivacy::Public(account_id))
            .unwrap();

        let _ = storage
            .key_chain_mut()
            .generate_new_privacy_preserving_transaction_key_chain(None);

        let private_key = lee::PrivateKey::new_os_random();
        storage
            .key_chain_mut()
            .add_imported_public_account(private_key);

        let key_chain = key_protocol::key_management::KeyChain::new_os_random();
        let account = lee::Account::default();
        storage
            .key_chain_mut()
            .add_imported_private_account(key_chain, None, 0, account);

        storage.set_last_synced_block(42);

        let program_account = lee::AccountId::new([9; 32]);
        let participant = lee::AccountId::new([5; 32]);
        let reference = [7; 32];
        let mut intent = referral::ReferralIntent::new(program_account);
        intent.registration = Some(referral::PendingRegistration {
            node: referral_core::NodeId::new([7; 32]),
            referrer: Some(referral_core::NodeId::new([8; 32])),
            signature: Some(referral_core::ed25519_dalek::Signature::from_bytes(
                &[3; 64],
            )),
        });
        intent.record_credit(referral::random_seed());
        intent.invitation = Some(referral_core::Invitation::new(
            program_account,
            referral_core::NodeId::new([8; 32]),
            lee_core::NullifierPublicKey([1; 32]),
            lee_core::encryption::ViewingPublicKey::from_seed(&[2; 32], &[3; 32]),
        ));
        storage.referral_mut().intents.insert(participant, intent);
        storage
            .referral_mut()
            .record_operation(grant_operation(reference, program_account));

        let temp_dir = tempfile::tempdir().unwrap();
        let storage_path = temp_dir.path().join("storage.json");

        storage.save_to_path(&storage_path).unwrap();
        let loaded_store = Storage::from_path(&storage_path).unwrap();

        assert_eq!(loaded_store, storage);
        let restored = &loaded_store.referral().intents[&participant];
        assert_eq!(restored.pending_credits.len(), 1);
        assert!(restored.registration().is_some());
        assert!(restored.invitation.is_some());
        assert_eq!(
            loaded_store
                .referral()
                .operation(reference)
                .map(|operation| operation.status),
            Some(referral::SubmissionStatus::Pending)
        );
    }

    fn grant_operation(
        reference: [u8; 32],
        program_account: lee::AccountId,
    ) -> referral::PendingOperation {
        let key = lee::PrivateKey::new_os_random();
        let message = lee::public_transaction::Message::try_new(
            program_account,
            vec![lee::ProgramShardSelector::balance(lee::AccountId::new(
                [4; 32],
            ))],
            vec![lee_core::account::Nonce::default()],
            referral_core::Instruction::Grant {
                node: referral_core::NodeId::new([8; 32]),
                amount: 5,
            },
        )
        .unwrap();
        let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[&key]);
        let transaction = common::transaction::LeeTransaction::Public(lee::PublicTransaction::new(
            message,
            witness_set,
        ));

        referral::PendingOperation {
            reference,
            program_account,
            operation: referral::OperationKind::Grant {
                node: referral_core::NodeId::new([8; 32]),
                amount: 5,
            },
            transaction,
            pinned_public_views: Vec::new(),
            pinned_private_inputs: Vec::new(),
            destination: None,
            status: referral::SubmissionStatus::Pending,
        }
    }

    #[test]
    fn resolve_label_works() {
        let (mut storage, _) = Storage::new("test_pass").unwrap();

        let label = Label::new("test_label");
        let account_id = AccountIdWithPrivacy::Public(lee::AccountId::default());

        storage.add_label(label.clone(), account_id).unwrap();
        assert_eq!(storage.resolve_label(&label), Some(account_id));
    }

    #[test]
    fn resolve_label_returns_none_for_unknown_label() {
        let (storage, _) = Storage::new("test_pass").unwrap();

        let label = Label::new("test_label");
        assert_eq!(storage.resolve_label(&label), None);
    }

    #[test]
    fn labels_for_account_works() {
        let (mut storage, _) = Storage::new("test_pass").unwrap();

        let label = Label::new("test_label");
        let account_id = AccountIdWithPrivacy::Public(lee::AccountId::default());

        storage.add_label(label.clone(), account_id).unwrap();
        let another_label = Label::new("another_label");
        storage
            .add_label(another_label.clone(), account_id)
            .unwrap();
        assert_eq!(
            storage.labels_for_account(account_id).collect::<Vec<_>>(),
            vec![&another_label, &label]
        );
    }

    #[test]
    fn check_label_availability_works() {
        let (mut storage, _) = Storage::new("test_pass").unwrap();

        let label = Label::new("test_label");
        let account_id = AccountIdWithPrivacy::Public(lee::AccountId::default());

        assert!(storage.check_label_availability(&label).is_ok());
        storage.add_label(label.clone(), account_id).unwrap();
        assert!(storage.check_label_availability(&label).is_err());
    }
}
