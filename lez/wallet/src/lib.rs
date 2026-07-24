#![expect(
    clippy::print_stdout,
    reason = "This is a CLI application, printing to stdout and stderr is expected and convenient"
)]
#![expect(
    clippy::shadow_unrelated,
    reason = "Most of the shadows come from args parsing which is ok"
)]

use std::{collections::HashSet, path::PathBuf};

pub use account_manager::AccountIdentity;
use anyhow::{Context as _, Result};
use bip39::Mnemonic;
use common::{HashType, transaction::LeeTransaction};
use config::WalletConfig;
use key_protocol::key_management::key_tree::chain_index::ChainIndex;
use lee::{
    Account, AccountId, PrivacyPreservingTransaction, ProgramId,
    privacy_preserving_transaction::{
        circuit::ProgramWithDependencies,
        message::{EncryptedAccountData, Message},
    },
};
use lee_core::{
    Commitment, CommitmentSetDigest, MembershipProof, SharedSecretKey, account::Nonce,
    program::InstructionData,
};
use log::info;
use sequencer_service_rpc::{RpcClient as _, SequencerClient, SequencerClientBuilder};
use storage::Storage;
use tokio::io::AsyncWriteExt as _;

use crate::{
    account::{AccountIdWithPrivacy, Label},
    config::WalletConfigOverrides,
    poller::TxPoller,
    storage::key_chain::{NullifierIndex, SharedAccountEntry},
};

pub mod account;
mod account_manager;
pub mod cli;
pub mod config;
pub mod helperfunctions;
pub mod poller;
pub mod program_facades;
pub mod signing;
pub mod storage;

pub const HOME_DIR_ENV_VAR: &str = "LEE_WALLET_HOME_DIR";

pub enum AccDecodeData {
    Skip,
    Decode(lee_core::SharedSecretKey, AccountId),
}

/// Info returned when creating a shared account.
pub struct SharedAccountInfo {
    pub account_id: AccountId,
    pub npk: lee_core::NullifierPublicKey,
    pub vpk: lee_core::encryption::ViewingPublicKey,
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutionFailureKind {
    #[error("Failed to get data from sequencer")]
    SequencerError(#[source] anyhow::Error),
    #[error("Inputs amounts does not match outputs")]
    AmountMismatchError,
    #[error("Accounts key not found")]
    KeyNotFoundError,
    #[error("Sequencer client error")]
    SequencerClientError(#[from] sequencer_service_rpc::ClientError),
    #[error("Can not pay for operation")]
    InsufficientFundsError,
    #[error("Account {0} data is invalid")]
    AccountDataError(AccountId),
    #[error("Failed to build transaction: {0}")]
    TransactionBuildError(#[from] lee::error::LeeError),
    #[error("Failed to sign transaction: {0}")]
    SignError(anyhow::Error),
    #[error(transparent)]
    KeycardError(#[from] pyo3::PyErr),
}

#[expect(clippy::partial_pub_fields, reason = "TODO: make all fields private")]
pub struct WalletCore {
    config_path: PathBuf,
    config_overrides: Option<WalletConfigOverrides>,
    config: WalletConfig,

    storage: Storage,
    storage_path: PathBuf,

    poller: TxPoller,
    pub sequencer_client: SequencerClient,
}

impl WalletCore {
    /// Construct wallet using [`HOME_DIR_ENV_VAR`] env var for paths or user home dir if not set.
    pub fn from_env() -> Result<Self> {
        let config_path = helperfunctions::fetch_config_path()?;
        let storage_path = helperfunctions::fetch_persistent_storage_path()?;

        Self::new_update_chain(config_path, storage_path, None)
    }

    pub fn new_update_chain(
        config_path: PathBuf,
        storage_path: PathBuf,
        config_overrides: Option<WalletConfigOverrides>,
    ) -> Result<Self> {
        let storage = Storage::from_path(&storage_path)
            .with_context(|| format!("Failed to load storage from {}", storage_path.display()))?;

        Self::new(config_path, storage_path, config_overrides, storage)
    }

    pub fn new_init_storage(
        config_path: PathBuf,
        storage_path: PathBuf,
        config_overrides: Option<WalletConfigOverrides>,
        password: &str,
    ) -> Result<(Self, Mnemonic)> {
        let (storage, mnemonic) = Storage::new(password).context("Failed to create storage")?;
        let wallet = Self::new(config_path, storage_path, config_overrides, storage)?;

        Ok((wallet, mnemonic))
    }

    fn new(
        config_path: PathBuf,
        storage_path: PathBuf,
        config_overrides: Option<WalletConfigOverrides>,
        storage: Storage,
    ) -> Result<Self> {
        let mut config =
            WalletConfig::from_path_or_initialize_default(&config_path).with_context(|| {
                format!(
                    "Failed to deserialize wallet config at {}",
                    config_path.display()
                )
            })?;
        if let Some(config_overrides) = config_overrides.clone() {
            config.apply_overrides(config_overrides);
        }

        let sequencer_client = {
            let mut builder = SequencerClientBuilder::default();
            if let Some(basic_auth) = &config.basic_auth {
                builder = builder.set_headers(
                    std::iter::once((
                        "Authorization".parse().expect("Header name is valid"),
                        format!("Basic {basic_auth}")
                            .parse()
                            .context("Invalid basic auth format")?,
                    ))
                    .collect(),
                );
            }
            builder
                .build(config.sequencer_addr.clone())
                .context("Failed to create sequencer client")?
        };

        let tx_poller = TxPoller::new(&config, sequencer_client.clone());

        Ok(Self {
            config_path,
            config_overrides,
            config,
            storage_path,
            storage,
            poller: tx_poller,
            sequencer_client,
        })
    }

    /// Get configuration with applied overrides.
    #[must_use]
    pub const fn config(&self) -> &WalletConfig {
        &self.config
    }

    pub fn set_config(&mut self, config: WalletConfig) {
        self.config = config;
    }

    /// Get storage.
    #[must_use]
    pub const fn storage(&self) -> &Storage {
        &self.storage
    }

    /// Get mutable reference to storage.
    #[must_use]
    pub const fn storage_mut(&mut self) -> &mut Storage {
        &mut self.storage
    }

    /// Restore storage from an existing mnemonic phrase.
    pub fn restore_storage(&mut self, mnemonic: &Mnemonic, password: &str) -> Result<()> {
        self.storage.restore(mnemonic, password)
    }

    /// Store persistent data at home.
    pub fn store_persistent_data(&self) -> Result<()> {
        self.storage
            .save_to_path(&self.storage_path)
            .with_context(|| {
                format!(
                    "Failed to store persistent accounts at {}",
                    self.storage_path.display()
                )
            })?;

        println!(
            "Stored persistent accounts at {}",
            self.storage_path.display()
        );

        Ok(())
    }

    /// Store persistent data at home.
    pub async fn store_config_changes(&self) -> Result<()> {
        let config = serde_json::to_vec_pretty(&self.config)?;

        let mut config_file = tokio::fs::File::create(&self.config_path).await?;
        config_file.write_all(&config).await?;
        // Ensure data is flushed to disk before returning to prevent race conditions
        config_file.sync_all().await?;

        info!("Stored data at {}", self.config_path.display());

        Ok(())
    }

    pub fn create_new_account_public(
        &mut self,
        chain_index: Option<ChainIndex>,
    ) -> (AccountId, ChainIndex) {
        self.storage
            .key_chain_mut()
            .generate_new_public_transaction_private_key(chain_index)
    }

    pub fn create_private_accounts_key(&mut self, chain_index: Option<ChainIndex>) -> ChainIndex {
        self.storage
            .key_chain_mut()
            .create_private_accounts_key(chain_index)
    }

    pub fn create_new_account_private(
        &mut self,
        chain_index: Option<ChainIndex>,
    ) -> (AccountId, ChainIndex) {
        self.storage
            .key_chain_mut()
            .generate_new_privacy_preserving_transaction_key_chain(chain_index)
    }

    /// Insert a group key holder into storage.
    pub fn insert_group_key_holder(
        &mut self,
        name: Label,
        holder: key_protocol::key_management::group_key_holder::GroupKeyHolder,
    ) {
        self.storage
            .key_chain_mut()
            .insert_group_key_holder(name, holder);
    }

    /// Set the wallet's dedicated sealing secret key.
    pub const fn set_sealing_secret_key(
        &mut self,
        key: key_protocol::key_management::secret_holders::ViewingSecretKey,
    ) {
        self.storage.key_chain_mut().set_sealing_secret_key(key);
    }

    /// Resolve an `AccountId` to the appropriate `AccountIdentity` variant.
    /// Checks the key tree first, then shared private accounts.
    #[must_use]
    pub fn resolve_private_account(&self, account_id: lee::AccountId) -> Option<AccountIdentity> {
        // Check key tree first
        if self
            .storage
            .key_chain()
            .private_account(account_id)
            .is_some()
        {
            return Some(AccountIdentity::PrivateOwned(account_id));
        }

        // Check shared private accounts
        let entry = self
            .storage
            .key_chain()
            .shared_private_account(account_id)?;
        let keys = self.storage.key_chain().derive_shared_account_keys(entry)?;
        let nsk = keys.nullifier_secret_key;
        let ask = keys.authorization_secret_key;
        let npk = keys.generate_nullifier_public_key();
        let vpk = keys.generate_viewing_public_key();
        let identifier = entry.identifier;

        if entry.pda_seed.is_some() {
            Some(AccountIdentity::PrivatePdaShared {
                account_id,
                nsk,
                ask,
                npk,
                vpk,
                identifier,
            })
        } else {
            Some(AccountIdentity::PrivateShared {
                nsk,
                ask,
                npk,
                vpk,
                identifier,
            })
        }
    }

    /// Remove a group key holder from storage. Returns the removed holder if it existed.
    pub fn remove_group_key_holder(
        &mut self,
        name: &Label,
    ) -> Option<key_protocol::key_management::group_key_holder::GroupKeyHolder> {
        self.storage.key_chain_mut().remove_group_key_holder(name)
    }

    /// Register a shared account in storage for sync tracking.
    fn register_shared_account(
        &mut self,
        account_id: AccountId,
        group_label: Label,
        identifier: lee_core::Identifier,
        pda_seed: Option<lee_core::program::PdaSeed>,
        authority_program_id: Option<lee_core::program::ProgramId>,
    ) {
        self.storage.key_chain_mut().insert_shared_private_account(
            account_id,
            SharedAccountEntry {
                group_label,
                identifier,
                pda_seed,
                authority_program_id,
                account: Account::default(),
            },
        );
    }

    /// Create a shared PDA account from a group's GMS. Returns the `AccountId` and derived keys.
    pub fn create_shared_pda_account(
        &mut self,
        group_name: Label,
        pda_seed: lee_core::program::PdaSeed,
        program_id: lee_core::program::ProgramId,
        identifier: lee_core::Identifier,
    ) -> Result<SharedAccountInfo> {
        let holder = self
            .storage
            .key_chain()
            .group_key_holder(&group_name)
            .context(format!("Group '{group_name}' not found"))?;

        let keys = holder.derive_keys_for_pda(&program_id, &pda_seed);
        let npk = keys.generate_nullifier_public_key();
        let apk = keys.generate_authorization_public_key();
        let vpk = keys.generate_viewing_public_key();
        let account_id =
            AccountId::for_private_pda(&program_id, &pda_seed, &npk, &apk, &vpk, identifier);

        self.register_shared_account(
            account_id,
            group_name,
            identifier,
            Some(pda_seed),
            Some(program_id),
        );

        Ok(SharedAccountInfo {
            account_id,
            npk,
            vpk,
        })
    }

    /// Create a shared regular private account from a group's GMS. Returns the `AccountId` and
    /// derived keys. The derivation seed is computed deterministically from a random identifier.
    pub fn create_shared_regular_account(
        &mut self,
        group_name: Label,
    ) -> Result<SharedAccountInfo> {
        let identifier: lee_core::Identifier = rand::random();

        let holder = self
            .storage
            .key_chain()
            .group_key_holder(&group_name)
            .context(format!("Group '{group_name}' not found"))?;

        let keys = holder.derive_regular_shared_account_keys_from_identifier(identifier);
        let npk = keys.generate_nullifier_public_key();
        let apk = keys.generate_authorization_public_key();
        let vpk = keys.generate_viewing_public_key();
        let account_id = AccountId::for_regular_private_account(&npk, &apk, &vpk, identifier);

        self.register_shared_account(account_id, group_name, identifier, None, None);

        Ok(SharedAccountInfo {
            account_id,
            npk,
            vpk,
        })
    }

    /// Get account balance.
    pub async fn get_account_balance(&self, acc: AccountId) -> Result<u128> {
        Ok(self.sequencer_client.get_account_balance(acc).await?)
    }

    /// Get accounts nonces.
    pub async fn get_accounts_nonces(&self, accs: Vec<AccountId>) -> Result<Vec<Nonce>> {
        Ok(self.sequencer_client.get_accounts_nonces(accs).await?)
    }

    pub async fn get_account(&self, account_id: AccountIdWithPrivacy) -> Result<Account> {
        match account_id {
            AccountIdWithPrivacy::Public(acc_id) => self.get_account_public(acc_id).await,
            AccountIdWithPrivacy::Private(acc_id) => {
                if let Some(account) = self.get_account_private(acc_id) {
                    Ok(account)
                } else {
                    anyhow::bail!("Private account with id {acc_id} not found in storage")
                }
            }
        }
    }

    /// Get public account.
    pub async fn get_account_public(&self, account_id: AccountId) -> Result<Account> {
        Ok(self.sequencer_client.get_account(account_id).await?)
    }

    #[must_use]
    pub fn get_account_public_signing_key(
        &self,
        account_id: AccountId,
    ) -> Option<&lee::PrivateKey> {
        self.storage.key_chain().pub_account_signing_key(account_id)
    }

    #[must_use]
    pub fn get_account_private(&self, account_id: AccountId) -> Option<Account> {
        self.storage
            .key_chain()
            .private_account(account_id)
            .map(|acc| acc.account.clone())
    }

    #[must_use]
    pub fn get_private_account_commitment(&self, account_id: AccountId) -> Option<Commitment> {
        let account = self
            .storage
            .key_chain()
            .private_account(account_id)
            .map(|acc| acc.account)
            .or_else(|| {
                self.storage
                    .key_chain()
                    .shared_private_account(account_id)
                    .map(|entry| &entry.account)
            })?;
        Some(Commitment::new(&account_id, account))
    }

    pub async fn get_proofs_and_root(
        &self,
        commitments: Vec<Commitment>,
    ) -> Result<(Vec<Option<MembershipProof>>, CommitmentSetDigest)> {
        self.sequencer_client
            .get_proofs_and_root(commitments)
            .await
            .map_err(Into::into)
    }

    pub fn decode_insert_privacy_preserving_transaction_results(
        &mut self,
        tx: &lee::privacy_preserving_transaction::PrivacyPreservingTransaction,
        acc_decode_mask: &[AccDecodeData],
    ) -> Result<()> {
        let note_count = tx.message.validate_note_lengths()?;
        anyhow::ensure!(
            note_count >= acc_decode_mask.len(),
            "Decode mask has {} entries but the transaction has {note_count} notes",
            acc_decode_mask.len(),
        );
        for (output_index, acc_decode_data) in acc_decode_mask.iter().enumerate() {
            match acc_decode_data {
                AccDecodeData::Decode(secret, acc_account_id) => {
                    let acc_ead = tx.message.encrypted_private_post_states[output_index].clone();
                    let acc_comm = tx.message.new_commitments[output_index].clone();

                    let (kind, res_acc) = lee_core::EncryptionScheme::decrypt(
                        &acc_ead.ciphertext,
                        secret,
                        &acc_comm,
                        output_index
                            .try_into()
                            .expect("Output index is expected to fit in u32"),
                    )
                    .unwrap();

                    println!("Received new acc {res_acc:#?}");

                    self.storage
                        .key_chain_mut()
                        .insert_private_account(*acc_account_id, kind, res_acc)
                        .expect("Account Id should exist");
                }
                AccDecodeData::Skip => {}
            }
        }

        Ok(())
    }

    pub(crate) async fn poll_and_finalize_public_transaction(
        &self,
        tx_hash: HashType,
    ) -> Result<cli::SubcommandReturnValue> {
        println!("Transaction hash is {tx_hash}");
        let (tx, block_id) = self.poller.poll_tx(tx_hash).await?;
        println!("Transaction is included in block {block_id}");
        println!("Transaction data is {tx:?}");
        self.store_persistent_data()?;
        Ok(cli::SubcommandReturnValue::TransactionExecuted { tx_hash })
    }

    /// Pass an empty slice when the recipient is foreign and no accounts need decoding.
    pub(crate) async fn poll_and_finalize_pp_transaction(
        &mut self,
        tx_hash: HashType,
        acc_decode_data: &[AccDecodeData],
    ) -> Result<cli::SubcommandReturnValue> {
        println!("Transaction hash is {tx_hash}");
        let (tx, block_id) = self.poller.poll_tx(tx_hash).await?;
        println!("Transaction is included in block {block_id}");
        println!("Transaction data is {tx:?}");
        if let common::transaction::LeeTransaction::PrivacyPreserving(private_tx) = tx {
            self.decode_insert_privacy_preserving_transaction_results(
                &private_tx,
                acc_decode_data,
            )?;
        }
        self.store_persistent_data()?;
        Ok(cli::SubcommandReturnValue::TransactionExecuted { tx_hash })
    }

    pub async fn send_privacy_preserving_tx(
        &self,
        accounts: Vec<AccountIdentity>,
        instruction_data: InstructionData,
        program: &ProgramWithDependencies,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        self.send_privacy_preserving_tx_with_pre_check(accounts, instruction_data, program, |_| {
            Ok(())
        })
        .await
    }

    pub async fn send_privacy_preserving_tx_with_pre_check(
        &self,
        accounts: Vec<AccountIdentity>,
        instruction_data: InstructionData,
        program: &ProgramWithDependencies,
        tx_pre_check: impl FnOnce(&[&Account]) -> Result<(), ExecutionFailureKind>,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let acc_manager = account_manager::AccountManager::new(self, accounts).await?;

        let pre_states = acc_manager.pre_states();

        tx_pre_check(
            &pre_states
                .iter()
                .map(|pre| &pre.account)
                .collect::<Vec<_>>(),
        )?;

        let private_account_keys = acc_manager.private_account_keys();
        let (output, proof) = lee::privacy_preserving_transaction::circuit::execute_and_prove(
            pre_states,
            instruction_data,
            acc_manager.account_identities(),
            &program.to_owned(),
        )?;

        let message =
            lee::privacy_preserving_transaction::message::Message::try_from_circuit_output(
                acc_manager.public_account_ids(),
                acc_manager.public_account_nonces(),
                output,
            )?;

        let message_hash = message.hash();
        let signatures_public_keys = acc_manager
            .sign_message(message_hash)
            .map_err(ExecutionFailureKind::SignError)?;

        let witness_set =
            lee::privacy_preserving_transaction::witness_set::WitnessSet::from_raw_parts(
                signatures_public_keys,
                proof,
            );

        let tx = PrivacyPreservingTransaction::new(message, witness_set);

        let shared_secrets: Vec<_> = private_account_keys
            .into_iter()
            .map(|keys| keys.ssk)
            .collect();

        Ok((
            self.sequencer_client
                .send_transaction(LeeTransaction::PrivacyPreserving(tx))
                .await?,
            shared_secrets,
        ))
    }

    pub async fn send_pub_tx(
        &self,
        accounts: Vec<AccountIdentity>,
        instruction_data: InstructionData,
        program_id: ProgramId,
    ) -> Result<HashType, ExecutionFailureKind> {
        self.send_pub_tx_with_pre_check(accounts, instruction_data, program_id, |_| Ok(()))
            .await
    }

    pub async fn send_pub_tx_with_pre_check(
        &self,
        accounts: Vec<AccountIdentity>,
        instruction_data: InstructionData,
        program_id: ProgramId,
        tx_pre_check: impl FnOnce(&[&Account]) -> Result<(), ExecutionFailureKind>,
    ) -> Result<HashType, ExecutionFailureKind> {
        // Public transaction, all accounts must be public
        if accounts.iter().any(AccountIdentity::is_private) {
            return Err(ExecutionFailureKind::TransactionBuildError(
                lee::error::LeeError::InvalidInput(
                    "Private accounts are not allowed in public transactions".to_owned(),
                ),
            ));
        }

        let acc_manager = account_manager::AccountManager::new(self, accounts).await?;

        let pre_states = acc_manager.pre_states();
        tx_pre_check(
            &pre_states
                .iter()
                .map(|pre| &pre.account)
                .collect::<Vec<_>>(),
        )?;

        let account_ids = acc_manager.public_account_ids();
        let nonces = acc_manager.public_account_nonces();

        let message = lee::public_transaction::Message::new_preserialized(
            program_id,
            account_ids,
            nonces,
            instruction_data,
        );

        let message_hash = message.hash();
        let signatures_public_keys = acc_manager
            .sign_message(message_hash)
            .map_err(ExecutionFailureKind::SignError)?;

        let witness_set =
            lee::public_transaction::WitnessSet::from_raw_parts(signatures_public_keys);

        let tx = lee::public_transaction::PublicTransaction::new(message, witness_set);

        Ok(self
            .sequencer_client
            .send_transaction(LeeTransaction::Public(tx))
            .await?)
    }

    pub async fn sync_to_latest_block(&mut self) -> Result<u64> {
        let latest_block_id = self.sequencer_client.get_last_block_id().await?;
        println!("Latest block is {latest_block_id}");
        self.sync_to_block(latest_block_id).await?;
        Ok(latest_block_id)
    }

    pub async fn sync_to_block(&mut self, block_id: u64) -> Result<()> {
        use futures::TryStreamExt as _;

        let last_synced_block = self.storage.last_synced_block();
        if last_synced_block >= block_id {
            return Ok(());
        }

        let before_polling = std::time::Instant::now();
        let num_of_blocks = block_id.saturating_sub(last_synced_block);
        if num_of_blocks == 0 {
            return Ok(());
        }

        println!("Syncing to block {block_id}. Blocks to sync: {num_of_blocks}");

        let poller = self.poller.clone();
        let mut blocks =
            std::pin::pin!(poller.poll_block_range(last_synced_block.saturating_add(1)..=block_id));

        // Get the latest nullifiers for all owned accounts.
        let mut index = self.storage.key_chain().build_latest_nullifier_index();
        let bar = indicatif::ProgressBar::new(num_of_blocks);
        while let Some(block) = blocks.try_next().await? {
            for tx in block.body.transactions {
                let LeeTransaction::PrivacyPreserving(pp_tx) = &tx else {
                    continue;
                };
                pp_tx.message.validate_note_lengths()?;
                // Eagerly decrypt note updates using expected nullifiers.
                let handled = self
                    .storage
                    .key_chain_mut()
                    .sync_updates_via_nullifiers(&pp_tx.message, &mut index);
                self.sync_private_accounts_with_message(&pp_tx.message, &mut index, &handled);
            }

            self.storage.set_last_synced_block(block.header.block_id);
            self.store_persistent_data()?;
            bar.inc(1);
        }
        bar.finish();

        println!(
            "Synced to block {block_id} in {:?}",
            before_polling.elapsed()
        );

        Ok(())
    }

    fn sync_private_accounts_with_message(
        &mut self,
        message: &Message,
        index: &mut NullifierIndex,
        handled: &HashSet<usize>,
    ) {
        let affected_accounts = self
            .storage
            .key_chain()
            .private_account_key_chains()
            .flat_map(|(_account_id, key_chain, _index)| {
                let view_tag = EncryptedAccountData::compute_view_tag(
                    &key_chain.nullifier_public_key,
                    &key_chain.viewing_public_key,
                );
                let new_commitments = &message.new_commitments;

                message
                    .encrypted_private_post_states
                    .iter()
                    .enumerate()
                    .filter(move |(ciph_id, encrypted_data)| {
                        // If we have not decrypted the update using the nullifiers,
                        // the note may be an initialized one, for which we should
                        // scan.
                        !handled.contains(ciph_id) && encrypted_data.view_tag == view_tag
                    })
                    .filter_map(move |(ciph_id, encrypted_data)| {
                        let ciphertext = &encrypted_data.ciphertext;
                        let commitment = &new_commitments[ciph_id];
                        let shared_secret =
                            key_chain.calculate_shared_secret_receiver(&encrypted_data.epk)?;

                        lee_core::EncryptionScheme::decrypt(
                            ciphertext,
                            &shared_secret,
                            commitment,
                            ciph_id
                                .try_into()
                                .expect("Ciphertext ID is expected to fit in u32"),
                        )
                        .map(|(kind, res_acc)| {
                            let npk = &key_chain.nullifier_public_key;
                            let account_id = lee::AccountId::for_private_account(
                                npk,
                                &key_chain.authorization_public_key,
                                &key_chain.viewing_public_key,
                                &kind,
                            );
                            let nsk = key_chain.private_key_holder.nullifier_secret_key;
                            (account_id, kind, res_acc, nsk)
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        for (affected_account_id, kind, new_acc, nsk) in affected_accounts {
            info!(
                "Received new account for account_id {affected_account_id:#?} with account object {new_acc:#?}"
            );
            // Await the account's next update by its nullifier, so later updates
            // to it are caught without tag matching.
            index.track(affected_account_id, &new_acc, &nsk);
            self.storage
                .key_chain_mut()
                .insert_private_account(affected_account_id, kind, new_acc)
                .expect("Account Id should exist");
        }

        // Scan for updates to shared accounts (GMS-derived).
        self.sync_shared_private_accounts_with_tx(message, index, handled);
    }

    fn sync_shared_private_accounts_with_tx(
        &mut self,
        message: &Message,
        index: &mut NullifierIndex,
        handled: &HashSet<usize>,
    ) {
        let shared_keys: Vec<_> = self
            .storage
            .key_chain()
            .shared_private_accounts_iter()
            .filter_map(|(&account_id, entry)| {
                let keys = self.storage.key_chain().derive_shared_account_keys(entry)?;
                let npk = keys.generate_nullifier_public_key();
                let vpk = keys.generate_viewing_public_key();
                let nsk = keys.nullifier_secret_key;
                let vsk = keys.viewing_secret_key;
                Some((account_id, npk, vpk, vsk, nsk))
            })
            .collect();

        for (account_id, npk, vpk, vsk, nsk) in shared_keys {
            let view_tag = EncryptedAccountData::compute_view_tag(&npk, &vpk);

            for (ciph_id, encrypted_data) in
                message.encrypted_private_post_states.iter().enumerate()
            {
                // If already decrypted or the tag does not match, skip.
                if handled.contains(&ciph_id) || encrypted_data.view_tag != view_tag {
                    continue;
                }

                let Some(shared_secret) =
                    SharedSecretKey::decapsulate(&encrypted_data.epk, &vsk.d, &vsk.z)
                else {
                    continue;
                };
                let commitment = &message.new_commitments[ciph_id];

                if let Some((_kind, new_acc)) = lee_core::EncryptionScheme::decrypt(
                    &encrypted_data.ciphertext,
                    &shared_secret,
                    commitment,
                    ciph_id
                        .try_into()
                        .expect("Ciphertext ID is expected to fit in u32"),
                ) {
                    info!("Synced shared account {account_id:#?} with new state {new_acc:#?}");
                    index.track(account_id, &new_acc, &nsk);
                    self.storage
                        .key_chain_mut()
                        .update_shared_private_account_state(&account_id, new_acc);
                }
            }
        }
    }

    #[must_use]
    pub const fn config_path(&self) -> &PathBuf {
        &self.config_path
    }

    #[must_use]
    pub const fn storage_path(&self) -> &PathBuf {
        &self.storage_path
    }

    #[must_use]
    pub const fn config_overrides(&self) -> &Option<WalletConfigOverrides> {
        &self.config_overrides
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::CString, str::FromStr as _};

    use bip39::Mnemonic;

    #[test]
    fn mnemonic_roundtrip() {
        let mnemonic =
            Mnemonic::from_entropy(&[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]).unwrap();

        let c_mnemonic_string = CString::new(mnemonic.to_string()).unwrap();
        let c_mnemonic_string_raw = c_mnemonic_string.into_raw();
        // Safety: Will be safe, pointer is created from CString
        let c_str = unsafe { CString::from_raw(c_mnemonic_string_raw) };
        let mn_string = c_str.to_str().unwrap();

        let mn_ret = Mnemonic::from_str(mn_string).unwrap();

        assert_eq!(mnemonic, mn_ret);
    }
}
