#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "This is a CLI application, printing to stdout and stderr is expected and convenient"
)]
#![expect(
    clippy::shadow_unrelated,
    reason = "Most of the shadows come from args parsing which is ok"
)]

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use bip39::Mnemonic;
use chain_storage::WalletChainStore;
use common::{HashType, transaction::NSSATransaction};
use config::WalletConfig;
use key_protocol::key_management::key_tree::chain_index::ChainIndex;
use log::info;
use nssa::{
    Account, AccountId, PrivacyPreservingTransaction,
    privacy_preserving_transaction::{
        circuit::{ProgramWithDependencies, Proof},
        message::EncryptedAccountData,
    },
};
use nssa_core::{
    Commitment, MembershipProof, PrivateAccountKind, SharedSecretKey, account::Nonce,
    program::InstructionData,
};
pub use privacy_preserving_tx::PrivacyPreservingAccount;
use sequencer_service_rpc::{RpcClient as _, SequencerClient, SequencerClientBuilder};
use tokio::io::AsyncWriteExt as _;

use crate::{
    config::{PersistentStorage, WalletConfigOverrides},
    helperfunctions::produce_data_for_storage,
    poller::TxPoller,
};

pub mod chain_storage;
pub mod cli;
pub mod config;
pub mod helperfunctions;
pub mod poller;
mod privacy_preserving_tx;
pub mod program_facades;

pub const HOME_DIR_ENV_VAR: &str = "NSSA_WALLET_HOME_DIR";

pub enum AccDecodeData {
    Skip,
    Decode(nssa_core::SharedSecretKey, AccountId),
}

/// Info returned when creating a shared account.
pub struct SharedAccountInfo {
    pub account_id: AccountId,
    pub npk: nssa_core::NullifierPublicKey,
    pub vpk: nssa_core::encryption::ViewingPublicKey,
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
    TransactionBuildError(#[from] nssa::error::NssaError),
    #[error(transparent)]
    KeycardError(#[from] pyo3::PyErr),
}

#[expect(clippy::partial_pub_fields, reason = "TODO: make all fields private")]
pub struct WalletCore {
    config_path: PathBuf,
    config_overrides: Option<WalletConfigOverrides>,
    storage: WalletChainStore,
    storage_path: PathBuf,
    poller: TxPoller,
    pub sequencer_client: SequencerClient,
    pub last_synced_block: u64,
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
        let PersistentStorage {
            accounts: persistent_accounts,
            last_synced_block,
            labels,
            group_key_holders,
            shared_private_accounts,
            sealing_secret_key,
        } = PersistentStorage::from_path(&storage_path).with_context(|| {
            format!(
                "Failed to read persistent storage at {}",
                storage_path.display()
            )
        })?;

        Self::new(
            config_path,
            storage_path,
            config_overrides,
            |config| {
                let mut store = WalletChainStore::new(config, persistent_accounts, labels)?;
                store.user_data.group_key_holders = group_key_holders;
                store.user_data.shared_private_accounts = shared_private_accounts;
                store.user_data.sealing_secret_key = sealing_secret_key;
                Ok(store)
            },
            last_synced_block,
        )
    }

    pub fn new_init_storage(
        config_path: PathBuf,
        storage_path: PathBuf,
        config_overrides: Option<WalletConfigOverrides>,
        password: &str,
    ) -> Result<(Self, Mnemonic)> {
        let mut mnemonic_out = None;
        let wallet = Self::new(
            config_path,
            storage_path,
            config_overrides,
            |config| {
                let (storage, mnemonic) = WalletChainStore::new_storage(config, password)?;
                mnemonic_out = Some(mnemonic);
                Ok(storage)
            },
            0,
        )?;
        Ok((
            wallet,
            mnemonic_out.expect("mnemonic should be set after new_storage"),
        ))
    }

    fn new(
        config_path: PathBuf,
        storage_path: PathBuf,
        config_overrides: Option<WalletConfigOverrides>,
        storage_ctor: impl FnOnce(WalletConfig) -> Result<WalletChainStore>,
        last_synced_block: u64,
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

        let storage = storage_ctor(config)?;

        Ok(Self {
            config_path,
            storage_path,
            storage,
            poller: tx_poller,
            sequencer_client,
            last_synced_block,
            config_overrides,
        })
    }

    /// Get configuration with applied overrides.
    #[must_use]
    pub const fn config(&self) -> &WalletConfig {
        &self.storage.wallet_config
    }

    /// Get storage.
    #[must_use]
    pub const fn storage(&self) -> &WalletChainStore {
        &self.storage
    }

    /// Restore storage from an existing mnemonic phrase.
    pub fn restore_storage(&mut self, mnemonic: &Mnemonic, password: &str) -> Result<()> {
        self.storage = WalletChainStore::restore_storage(
            self.storage.wallet_config.clone(),
            mnemonic,
            password,
        )?;
        Ok(())
    }

    /// Store persistent data at home.
    pub async fn store_persistent_data(&self) -> Result<()> {
        let data = produce_data_for_storage(
            &self.storage.user_data,
            self.last_synced_block,
            self.storage.labels.clone(),
        );
        let storage = serde_json::to_vec_pretty(&data)?;

        let mut storage_file = tokio::fs::File::create(&self.storage_path).await?;
        storage_file.write_all(&storage).await?;
        // Ensure data is flushed to disk before returning to prevent race conditions
        storage_file.sync_all().await?;

        println!(
            "Stored persistent accounts at {}",
            self.storage_path.display()
        );

        Ok(())
    }

    /// Store persistent data at home.
    pub async fn store_config_changes(&self) -> Result<()> {
        let config = serde_json::to_vec_pretty(&self.storage.wallet_config)?;

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
            .user_data
            .generate_new_public_transaction_private_key(chain_index)
    }

    pub fn create_private_accounts_key(&mut self, chain_index: Option<ChainIndex>) -> ChainIndex {
        self.storage
            .user_data
            .create_private_accounts_key(chain_index)
    }

    pub fn create_new_account_private(
        &mut self,
        chain_index: Option<ChainIndex>,
    ) -> (AccountId, ChainIndex) {
        let cci = self
            .storage
            .user_data
            .create_private_accounts_key(chain_index);
        let identifier: nssa_core::Identifier = rand::random();
        let npk = self
            .storage
            .user_data
            .private_key_tree
            .key_map
            .get(&cci)
            .expect("Node was just inserted")
            .value
            .0
            .nullifier_public_key;
        let account_id = AccountId::for_regular_private_account(&npk, identifier);
        self.storage.insert_private_account_data(
            account_id,
            &PrivateAccountKind::Regular(identifier),
            Account::default(),
        );
        (account_id, cci)
    }

    /// Insert a group key holder into storage.
    pub fn insert_group_key_holder(
        &mut self,
        name: String,
        holder: key_protocol::key_management::group_key_holder::GroupKeyHolder,
    ) {
        self.storage.user_data.insert_group_key_holder(name, holder);
    }

    /// Set the wallet's dedicated sealing secret key.
    pub const fn set_sealing_secret_key(&mut self, key: nssa_core::encryption::Scalar) {
        self.storage.user_data.sealing_secret_key = Some(key);
    }

    /// Resolve an `AccountId` to the appropriate `PrivacyPreservingAccount` variant.
    /// Checks the key tree first, then shared private accounts.
    #[must_use]
    pub fn resolve_private_account(
        &self,
        account_id: nssa::AccountId,
    ) -> Option<PrivacyPreservingAccount> {
        // Check key tree first
        if self
            .storage
            .user_data
            .get_private_account(account_id)
            .is_some()
        {
            return Some(PrivacyPreservingAccount::PrivateOwned(account_id));
        }

        // Check shared private accounts
        let entry = self.storage.user_data.shared_private_account(&account_id)?;
        let holder = self
            .storage
            .user_data
            .group_key_holder(&entry.group_label)?;

        if let (Some(pda_seed), Some(program_id)) = (entry.pda_seed, entry.pda_program_id) {
            let keys = holder.derive_keys_for_pda(&program_id, &pda_seed);
            Some(PrivacyPreservingAccount::PrivatePdaShared {
                account_id,
                nsk: keys.nullifier_secret_key,
                npk: keys.generate_nullifier_public_key(),
                vpk: keys.generate_viewing_public_key(),
                identifier: entry.identifier,
            })
        } else {
            let derivation_seed = {
                use sha2::Digest as _;
                let mut hasher = sha2::Sha256::new();
                hasher.update(b"/LEE/v0.3/SharedAccountTag/\x00\x00\x00\x00\x00");
                hasher.update(entry.identifier.to_le_bytes());
                let result: [u8; 32] = hasher.finalize().into();
                result
            };
            let keys = holder.derive_keys_for_shared_account(&derivation_seed);
            Some(PrivacyPreservingAccount::PrivateShared {
                nsk: keys.nullifier_secret_key,
                npk: keys.generate_nullifier_public_key(),
                vpk: keys.generate_viewing_public_key(),
                identifier: entry.identifier,
            })
        }
    }

    /// Remove a group key holder from storage. Returns the removed holder if it existed.
    pub fn remove_group_key_holder(
        &mut self,
        name: &str,
    ) -> Option<key_protocol::key_management::group_key_holder::GroupKeyHolder> {
        self.storage.user_data.group_key_holders.remove(name)
    }

    /// Register a shared account in storage for sync tracking.
    fn register_shared_account(
        &mut self,
        account_id: AccountId,
        group_label: String,
        identifier: nssa_core::Identifier,
        pda_seed: Option<nssa_core::program::PdaSeed>,
        pda_program_id: Option<nssa_core::program::ProgramId>,
    ) {
        use key_protocol::key_protocol_core::SharedAccountEntry;
        self.storage.user_data.insert_shared_private_account(
            account_id,
            SharedAccountEntry {
                group_label,
                identifier,
                pda_seed,
                pda_program_id,
                account: Account::default(),
            },
        );
    }

    /// Create a shared PDA account from a group's GMS. Returns the `AccountId` and derived keys.
    pub fn create_shared_pda_account(
        &mut self,
        group_name: &str,
        pda_seed: nssa_core::program::PdaSeed,
        program_id: nssa_core::program::ProgramId,
        identifier: nssa_core::Identifier,
    ) -> Result<SharedAccountInfo> {
        let holder = self
            .storage
            .user_data
            .group_key_holder(group_name)
            .context(format!("Group '{group_name}' not found"))?;

        let keys = holder.derive_keys_for_pda(&program_id, &pda_seed);
        let npk = keys.generate_nullifier_public_key();
        let vpk = keys.generate_viewing_public_key();
        let account_id = AccountId::for_private_pda(&program_id, &pda_seed, &npk, identifier);

        self.register_shared_account(
            account_id,
            String::from(group_name),
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
    pub fn create_shared_regular_account(&mut self, group_name: &str) -> Result<SharedAccountInfo> {
        let identifier: nssa_core::Identifier = rand::random();
        let derivation_seed = {
            use sha2::Digest as _;
            let mut hasher = sha2::Sha256::new();
            hasher.update(b"/LEE/v0.3/SharedAccountTag/\x00\x00\x00\x00\x00");
            hasher.update(identifier.to_le_bytes());
            let result: [u8; 32] = hasher.finalize().into();
            result
        };

        let holder = self
            .storage
            .user_data
            .group_key_holder(group_name)
            .context(format!("Group '{group_name}' not found"))?;

        let keys = holder.derive_keys_for_shared_account(&derivation_seed);
        let npk = keys.generate_nullifier_public_key();
        let vpk = keys.generate_viewing_public_key();
        let account_id = AccountId::from((&npk, identifier));

        self.register_shared_account(account_id, String::from(group_name), identifier, None, None);

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

    /// Get account.
    pub async fn get_account_public(&self, account_id: AccountId) -> Result<Account> {
        Ok(self.sequencer_client.get_account(account_id).await?)
    }

    #[must_use]
    pub fn get_account_public_signing_key(
        &self,
        account_id: AccountId,
    ) -> Option<&nssa::PrivateKey> {
        self.storage
            .user_data
            .get_pub_account_signing_key(account_id)
    }

    #[must_use]
    pub fn get_account_private(&self, account_id: AccountId) -> Option<Account> {
        self.storage
            .user_data
            .get_private_account(account_id)
            .map(|(_keys, account, _identifier)| account)
    }

    #[must_use]
    pub fn get_private_account_commitment(&self, account_id: AccountId) -> Option<Commitment> {
        let account = self
            .storage
            .user_data
            .get_private_account(account_id)
            .map(|(_keys, account, _identifier)| account)
            .or_else(|| {
                self.storage
                    .user_data
                    .shared_private_account(&account_id)
                    .map(|entry| entry.account.clone())
            })?;
        Some(Commitment::new(&account_id, &account))
    }

    /// Poll transactions.
    pub async fn poll_native_token_transfer(&self, hash: HashType) -> Result<NSSATransaction> {
        self.poller.poll_tx(hash).await
    }

    pub async fn check_private_account_initialized(
        &self,
        account_id: AccountId,
    ) -> Result<Option<MembershipProof>> {
        if let Some(acc_comm) = self.get_private_account_commitment(account_id) {
            self.sequencer_client
                .get_proof_for_commitment(acc_comm)
                .await
                .map_err(Into::into)
        } else {
            Ok(None)
        }
    }

    pub fn decode_insert_privacy_preserving_transaction_results(
        &mut self,
        tx: &nssa::privacy_preserving_transaction::PrivacyPreservingTransaction,
        acc_decode_mask: &[AccDecodeData],
    ) -> Result<()> {
        for (output_index, acc_decode_data) in acc_decode_mask.iter().enumerate() {
            match acc_decode_data {
                AccDecodeData::Decode(secret, acc_account_id) => {
                    let acc_ead = tx.message.encrypted_private_post_states[output_index].clone();
                    let acc_comm = tx.message.new_commitments[output_index].clone();

                    let (kind, res_acc) = nssa_core::EncryptionScheme::decrypt(
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
                        .insert_private_account_data(*acc_account_id, &kind, res_acc);
                }
                AccDecodeData::Skip => {}
            }
        }

        println!("Transaction data is {:?}", tx.message);
        Ok(())
    }

    pub async fn send_privacy_preserving_tx(
        &self,
        accounts: Vec<PrivacyPreservingAccount>,
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
        accounts: Vec<PrivacyPreservingAccount>,
        instruction_data: InstructionData,
        program: &ProgramWithDependencies,
        tx_pre_check: impl FnOnce(&[&Account]) -> Result<(), ExecutionFailureKind>,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let acc_manager = privacy_preserving_tx::AccountManager::new(self, accounts).await?;

        let pre_states = acc_manager.pre_states();
        tx_pre_check(
            &pre_states
                .iter()
                .map(|pre| &pre.account)
                .collect::<Vec<_>>(),
        )?;

        let private_account_keys = acc_manager.private_account_keys();
        let (output, proof) = nssa::privacy_preserving_transaction::circuit::execute_and_prove(
            pre_states,
            instruction_data,
            acc_manager.account_identities(),
            &program.to_owned(),
        )
        .unwrap();

        let message =
            nssa::privacy_preserving_transaction::message::Message::try_from_circuit_output(
                acc_manager.public_account_ids(),
                Vec::from_iter(acc_manager.public_account_nonces()),
                private_account_keys
                    .iter()
                    .map(|keys| (keys.npk, keys.vpk.clone(), keys.epk.clone()))
                    .collect(),
                output,
            )
            .unwrap();

        let witness_set = Self::sign_privacy_message(&message, proof.clone(), &acc_manager);
        let tx = PrivacyPreservingTransaction::new(message, witness_set);

        let shared_secrets: Vec<_> = private_account_keys
            .into_iter()
            .map(|keys| keys.ssk)
            .collect();

        Ok((
            self.sequencer_client
                .send_transaction(NSSATransaction::PrivacyPreserving(tx))
                .await?,
            shared_secrets,
        ))
    }

    pub async fn sync_to_block(&mut self, block_id: u64) -> Result<()> {
        use futures::TryStreamExt as _;

        if self.last_synced_block >= block_id {
            return Ok(());
        }

        let before_polling = std::time::Instant::now();
        let num_of_blocks = block_id.saturating_sub(self.last_synced_block);
        if num_of_blocks == 0 {
            return Ok(());
        }

        println!("Syncing to block {block_id}. Blocks to sync: {num_of_blocks}");

        let poller = self.poller.clone();
        let mut blocks = std::pin::pin!(
            poller.poll_block_range(self.last_synced_block.saturating_add(1)..=block_id)
        );

        let bar = indicatif::ProgressBar::new(num_of_blocks);
        while let Some(block) = blocks.try_next().await? {
            for tx in block.body.transactions {
                self.sync_private_accounts_with_tx(tx);
            }

            self.last_synced_block = block.header.block_id;
            self.store_persistent_data().await?;
            bar.inc(1);
        }
        bar.finish();

        println!(
            "Synced to block {block_id} in {:?}",
            before_polling.elapsed()
        );

        Ok(())
    }

    fn sync_private_accounts_with_tx(&mut self, tx: NSSATransaction) {
        let NSSATransaction::PrivacyPreserving(tx) = tx else {
            return;
        };

        let private_account_key_chains = self
            .storage
            .user_data
            .default_user_private_accounts
            .values()
            .map(|entry| (&entry.key_chain, None))
            .chain(
                self.storage
                    .user_data
                    .private_key_tree
                    .key_map
                    .iter()
                    .map(|(chain_index, keys_node)| (&keys_node.value.0, chain_index.index())),
            );

        let affected_accounts = private_account_key_chains
            .flat_map(|(key_chain, index)| {
                let view_tag = EncryptedAccountData::compute_view_tag(
                    &key_chain.nullifier_public_key,
                    &key_chain.viewing_public_key,
                );
                let new_commitments = &tx.message.new_commitments;

                tx.message()
                    .encrypted_private_post_states
                    .iter()
                    .enumerate()
                    .filter(move |(_, encrypted_data)| encrypted_data.view_tag == view_tag)
                    .filter_map(move |(ciph_id, encrypted_data)| {
                        let ciphertext = &encrypted_data.ciphertext;
                        let commitment = &new_commitments[ciph_id];
                        let shared_secret =
                            key_chain.calculate_shared_secret_receiver(&encrypted_data.epk, index);

                        nssa_core::EncryptionScheme::decrypt(
                            ciphertext,
                            &shared_secret,
                            commitment,
                            ciph_id
                                .try_into()
                                .expect("Ciphertext ID is expected to fit in u32"),
                        )
                        .map(|(kind, res_acc)| {
                            let npk = &key_chain.nullifier_public_key;
                            let account_id = nssa::AccountId::for_private_account(npk, &kind);
                            (account_id, kind, res_acc)
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        for (affected_account_id, kind, new_acc) in affected_accounts {
            info!(
                "Received new account for account_id {affected_account_id:#?} with account object {new_acc:#?}"
            );
            self.storage
                .insert_private_account_data(affected_account_id, &kind, new_acc);
        }

        // Scan for updates to shared accounts (GMS-derived).
        self.sync_shared_private_accounts_with_tx(&tx);
    }

    fn sync_shared_private_accounts_with_tx(&mut self, tx: &PrivacyPreservingTransaction) {
        let shared_keys: Vec<_> = self
            .storage
            .user_data
            .shared_private_accounts_iter()
            .filter_map(|(&account_id, entry)| {
                let holder = self
                    .storage
                    .user_data
                    .group_key_holder(&entry.group_label)?;

                let keys = match (&entry.pda_seed, &entry.pda_program_id) {
                    (Some(pda_seed), Some(program_id)) => {
                        holder.derive_keys_for_pda(program_id, pda_seed)
                    }
                    (Some(_), None) => return None, // PDA without program_id, skip
                    _ => {
                        let derivation_seed = {
                            use sha2::Digest as _;
                            let mut hasher = sha2::Sha256::new();
                            hasher.update(b"/LEE/v0.3/SharedAccountTag/\x00\x00\x00\x00\x00");
                            hasher.update(entry.identifier.to_le_bytes());
                            let result: [u8; 32] = hasher.finalize().into();
                            result
                        };
                        holder.derive_keys_for_shared_account(&derivation_seed)
                    }
                };
                let npk = keys.generate_nullifier_public_key();
                let vpk = keys.generate_viewing_public_key();
                let vsk = keys.viewing_secret_key;
                Some((account_id, npk, vpk, vsk))
            })
            .collect();

        for (account_id, npk, vpk, vsk) in shared_keys {
            let view_tag = EncryptedAccountData::compute_view_tag(&npk, &vpk);

            for (ciph_id, encrypted_data) in tx
                .message()
                .encrypted_private_post_states
                .iter()
                .enumerate()
            {
                if encrypted_data.view_tag != view_tag {
                    continue;
                }

                let shared_secret = SharedSecretKey::new(&vsk, &encrypted_data.epk);
                let commitment = &tx.message.new_commitments[ciph_id];

                if let Some((_kind, new_acc)) = nssa_core::EncryptionScheme::decrypt(
                    &encrypted_data.ciphertext,
                    &shared_secret,
                    commitment,
                    ciph_id
                        .try_into()
                        .expect("Ciphertext ID is expected to fit in u32"),
                ) {
                    info!("Synced shared account {account_id:#?} with new state {new_acc:#?}");
                    self.storage
                        .user_data
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

    pub fn sign_public_message(
        &self,
        message: &nssa::public_transaction::Message,
        account_ids: &[AccountId],
    ) -> Result<nssa::public_transaction::WitnessSet, ExecutionFailureKind> {
        let mut private_keys = Vec::new();

        for &account_id in account_ids {
            let key = self
                .storage
                .user_data
                .get_pub_account_signing_key(account_id)
                .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
            private_keys.push(key);
        }

        Ok(nssa::public_transaction::WitnessSet::for_message(
            message,
            &private_keys,
        ))
    }

    #[must_use]
    pub fn sign_privacy_message(
        message: &nssa::privacy_preserving_transaction::Message,
        proof: Proof,
        acc_manager: &privacy_preserving_tx::AccountManager,
    ) -> nssa::privacy_preserving_transaction::witness_set::WitnessSet {
        nssa::privacy_preserving_transaction::witness_set::WitnessSet::for_message(
            message,
            proof,
            &acc_manager.public_account_auth(),
        )
    }

    #[must_use]
    pub fn filter_owned_accounts(&self, account_ids: &[nssa::AccountId]) -> Vec<nssa::AccountId> {
        account_ids
            .iter()
            .filter(|&&account_id| self.get_account_public_signing_key(account_id).is_some())
            .copied()
            .collect()
    }
}
