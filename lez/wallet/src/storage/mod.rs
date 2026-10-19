use std::{
    collections::{BTreeMap, btree_map::Entry},
    io::Write as _,
    path::Path,
};

use anyhow::{Context as _, Result, bail};
use bip39::Mnemonic;
use key_chain::UserKeyChain;
use key_protocol::key_management::{
    key_tree::{KeyTreePrivate, KeyTreePublic},
    secret_holders::SeedHolder,
};
use lee_core::BlockId;

pub use crate::storage::encryption::StorageKey;
use crate::{
    account::{AccountIdWithPrivacy, Label},
    storage::{encryption::EncryptedFile, persistent::PersistentStorage},
};

mod encryption;
pub mod key_chain;
mod persistent;
pub mod spent_nullifiers;

/// The password does not open the storage file.
#[derive(Debug, thiserror::Error)]
#[error("Wrong password, or the storage file is corrupted")]
pub struct WrongPassword;

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Storage {
    key_chain: UserKeyChain,
    labels: BTreeMap<Label, AccountIdWithPrivacy>,
    last_synced_block: BlockId,
}

impl Storage {
    #[must_use]
    pub fn new() -> (Self, Mnemonic) {
        let (seed_holder, mnemonic) = SeedHolder::new_mnemonic("");
        let public_tree = KeyTreePublic::new(&seed_holder);
        let private_tree = KeyTreePrivate::new(&seed_holder);

        (
            Self {
                key_chain: UserKeyChain::new_with_accounts(public_tree, private_tree),
                labels: BTreeMap::new(),
                last_synced_block: 0,
            },
            mnemonic,
        )
    }

    /// Loads the storage at `path`, decrypting it with `password`; an unencrypted storage takes
    /// an empty password.
    pub fn from_path(path: &Path, password: &str) -> Result<(Self, Option<StorageKey>)> {
        match read_storage_file(path)? {
            StorageFile::Encrypted(file) => {
                if password.is_empty() {
                    return Err(WrongPassword.into());
                }
                let (plaintext, key) = file.open(password)?;
                let persistent =
                    serde_json::from_slice(&plaintext).context("Failed to parse storage")?;
                Ok((Self::from_persistent(persistent)?, Some(key)))
            }
            StorageFile::Plaintext(persistent) => {
                if !password.is_empty() {
                    return Err(WrongPassword.into());
                }
                Ok((Self::from_persistent(persistent)?, None))
            }
        }
    }

    /// Whether the storage file at `path` is encrypted.
    pub fn is_encrypted(path: &Path) -> Result<bool> {
        Ok(is_encrypted(&read_storage_json(path)?))
    }

    /// Replaces the file at `path` with the storage, sealed under `key` if there is one.
    ///
    /// Each save writes a file of its own beside `path` and renames it over it, so a crash or a
    /// concurrent save leaves one whole storage, never a truncated or mixed one.
    pub fn save_to_path(&self, path: &Path, key: Option<&StorageKey>) -> Result<()> {
        let persistent = self.to_persistent();
        let storage_serialized = match key {
            Some(key) => {
                let plaintext = zeroize::Zeroizing::new(serde_json::to_vec(&persistent)?);
                serde_json::to_vec_pretty(&key.seal(&plaintext)?)?
            }
            None => serde_json::to_vec_pretty(&persistent)?,
        };

        replace_synced(path, &storage_serialized)
            .with_context(|| format!("Failed to save the storage to {}", path.display()))
    }

    /// Restore storage from an existing mnemonic phrase.
    pub fn restore(&mut self, mnemonic: &Mnemonic) {
        let seed_holder = SeedHolder::from_mnemonic(mnemonic, "");
        let public_tree = KeyTreePublic::new(&seed_holder);
        let private_tree = KeyTreePrivate::new(&seed_holder);

        self.key_chain = UserKeyChain::new_with_accounts(public_tree, private_tree);
        self.labels = BTreeMap::new();
        self.last_synced_block = 0;
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
        } = self;
        let key_chain_data = key_chain.to_persistent();

        PersistentStorage {
            key_chain: key_chain_data,
            last_synced_block: *last_synced_block,
            labels: labels.clone(),
        }
    }

    fn from_persistent(persistent: PersistentStorage) -> Result<Self> {
        let PersistentStorage {
            key_chain,
            last_synced_block,
            labels,
        } = persistent;

        Ok(Self {
            key_chain: UserKeyChain::from_persistent(key_chain)?,
            last_synced_block,
            labels,
        })
    }
}

enum StorageFile {
    Encrypted(EncryptedFile),
    Plaintext(PersistentStorage),
}

/// The key to encrypt the storage under `password`, or none for an empty one.
pub fn storage_key_for(password: &str) -> Result<Option<StorageKey>> {
    (!password.is_empty())
        .then(|| StorageKey::new(password))
        .transpose()
}

/// Writes `content` to a new owner-only file with a random name beside `path`, syncs it and
/// renames it over `path`; the new file is removed if any step fails.
fn replace_synced(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let mut prefix = path.file_name().unwrap_or_default().to_owned();
    prefix.push(".");
    let dir = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let mut builder = tempfile::Builder::new();
    builder.prefix(&prefix).suffix(".tmp");
    #[cfg(unix)]
    builder.permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600));
    let mut file = builder.tempfile_in(dir)?;
    file.write_all(content)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    Ok(())
}

fn read_storage_file(path: &Path) -> Result<StorageFile> {
    let file = read_storage_json(path)?;
    if is_encrypted(&file) {
        Ok(StorageFile::Encrypted(
            serde_json::from_value(file).context("Failed to parse storage file")?,
        ))
    } else {
        Ok(StorageFile::Plaintext(
            serde_json::from_value(file).context("Failed to parse storage file")?,
        ))
    }
}

fn read_storage_json(path: &Path) -> Result<serde_json::Value> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "We want to provide a specific error message for not found case"
    )]
    let content = match std::fs::read(path) {
        Ok(content) => content,
        Err(err) => match err.kind() {
            std::io::ErrorKind::NotFound => {
                bail!(
                    "Storage not found at {}, please setup roots from config command beforehand",
                    path.display()
                );
            }
            _ => {
                bail!("IO error {err:#?}");
            }
        },
    };
    serde_json::from_slice(&content).context("Failed to parse storage file")
}

fn is_encrypted(file: &serde_json::Value) -> bool {
    file.get("ciphertext").is_some()
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn save_load_roundtrip() {
        let (mut storage, _) = Storage::new();

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
            .add_imported_private_account(key_chain, None, account);

        storage.set_last_synced_block(42);

        let temp_dir = tempfile::tempdir().unwrap();
        let storage_path = temp_dir.path().join("storage.json");

        for password in ["test_pass", ""] {
            storage
                .save_to_path(&storage_path, storage_key_for(password).unwrap().as_ref())
                .unwrap();
            let (loaded_store, _) = Storage::from_path(&storage_path, password).unwrap();

            assert_eq!(loaded_store, storage);
        }
    }

    #[test]
    fn saved_file_holds_no_plaintext_and_rejects_a_wrong_password() {
        let (storage, _) = Storage::new();
        let temp_dir = tempfile::tempdir().unwrap();
        let storage_path = temp_dir.path().join("storage.json");

        storage
            .save_to_path(&storage_path, Some(&StorageKey::new("test_pass").unwrap()))
            .unwrap();

        let file = std::fs::read_to_string(&storage_path).unwrap();
        assert!(!file.contains("key_chain"));
        assert!(Storage::is_encrypted(&storage_path).unwrap());
        for wrong_password in ["wrong_pass", ""] {
            assert!(
                Storage::from_path(&storage_path, wrong_password)
                    .err()
                    .unwrap()
                    .is::<WrongPassword>()
            );
        }
    }

    #[test]
    fn a_save_leaves_no_temporary_file_even_when_it_fails() {
        let (storage, _) = Storage::new();
        let temp_dir = tempfile::tempdir().unwrap();
        let storage_path = temp_dir.path().join("storage.json");
        let file_names = || {
            std::fs::read_dir(temp_dir.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect::<Vec<_>>()
        };

        storage.save_to_path(&storage_path, None).unwrap();
        assert_eq!(file_names(), ["storage.json"]);

        std::fs::remove_file(&storage_path).unwrap();
        std::fs::create_dir_all(&storage_path).unwrap();
        let err = storage.save_to_path(&storage_path, None).unwrap_err();
        assert!(err.to_string().contains("storage.json"));
        assert_eq!(file_names(), ["storage.json"]);
    }

    #[test]
    fn an_empty_password_makes_no_key() {
        assert!(storage_key_for("").unwrap().is_none());
        assert!(StorageKey::new("").is_err());
    }

    #[test]
    fn an_unencrypted_file_opens_only_with_an_empty_password() {
        let (storage, _) = Storage::new();
        let temp_dir = tempfile::tempdir().unwrap();
        let storage_path = temp_dir.path().join("storage.json");

        storage.save_to_path(&storage_path, None).unwrap();

        assert!(!Storage::is_encrypted(&storage_path).unwrap());
        assert!(
            Storage::from_path(&storage_path, "test_pass")
                .err()
                .unwrap()
                .is::<WrongPassword>()
        );
        let (loaded, key) = Storage::from_path(&storage_path, "").unwrap();
        assert_eq!(loaded, storage);
        assert!(key.is_none());
    }

    #[test]
    fn resolve_label_works() {
        let (mut storage, _) = Storage::new();

        let label = Label::new("test_label");
        let account_id = AccountIdWithPrivacy::Public(lee::AccountId::default());

        storage.add_label(label.clone(), account_id).unwrap();
        assert_eq!(storage.resolve_label(&label), Some(account_id));
    }

    #[test]
    fn resolve_label_returns_none_for_unknown_label() {
        let (storage, _) = Storage::new();

        let label = Label::new("test_label");
        assert_eq!(storage.resolve_label(&label), None);
    }

    #[test]
    fn labels_for_account_works() {
        let (mut storage, _) = Storage::new();

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
        let (mut storage, _) = Storage::new();

        let label = Label::new("test_label");
        let account_id = AccountIdWithPrivacy::Public(lee::AccountId::default());

        assert!(storage.check_label_availability(&label).is_ok());
        storage.add_label(label.clone(), account_id).unwrap();
        assert!(storage.check_label_availability(&label).is_err());
    }
}
