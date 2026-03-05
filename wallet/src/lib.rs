use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chain_storage::WalletChainStore;
use common::{
    HashType, error::ExecutionFailureKind, rpc_primitives::requests::SendTxResponse,
    sequencer_client::SequencerClient, transaction::NSSATransaction,
};
use config::WalletConfig;
use key_protocol::key_management::key_tree::{chain_index::ChainIndex, traits::KeyNode as _};
use log::info;
use nssa::{
    Account, AccountId, PrivacyPreservingTransaction,
    privacy_preserving_transaction::{
        circuit::ProgramWithDependencies, message::EncryptedAccountData,
    },
};
use nssa_core::{Commitment, MembershipProof, SharedSecretKey, program::InstructionData};
pub use privacy_preserving_tx::PrivacyPreservingAccount;
use tokio::io::AsyncWriteExt;

use crate::{
    config::{PersistentStorage, WalletConfigOverrides},
    helperfunctions::{produce_data_for_storage, produce_random_nonces},
    poller::TxPoller,
};

pub const HOME_DIR_ENV_VAR: &str = "NSSA_WALLET_HOME_DIR";

pub mod chain_storage;
pub mod cli;
pub mod config;
pub mod helperfunctions;
pub mod poller;
mod privacy_preserving_tx;
pub mod program_facades;

pub enum AccDecodeData {
    Skip,
    Decode(nssa_core::SharedSecretKey, AccountId),
}

pub struct WalletCore {
    config_path: PathBuf,
    config_overrides: Option<WalletConfigOverrides>,
    storage: WalletChainStore,
    storage_path: PathBuf,
    poller: TxPoller,
    // TODO: Make all fields private
    pub sequencer_client: Arc<SequencerClient>,
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
        } = PersistentStorage::from_path(&storage_path)
            .with_context(|| format!("Failed to read persistent storage at {storage_path:#?}"))?;

        Self::new(
            config_path,
            storage_path,
            config_overrides,
            |config| WalletChainStore::new(config, persistent_accounts, labels),
            last_synced_block,
        )
    }

    pub fn new_init_storage(
        config_path: PathBuf,
        storage_path: PathBuf,
        config_overrides: Option<WalletConfigOverrides>,
        password: String,
    ) -> Result<Self> {
        Self::new(
            config_path,
            storage_path,
            config_overrides,
            |config| WalletChainStore::new_storage(config, password),
            0,
        )
    }

    fn new(
        config_path: PathBuf,
        storage_path: PathBuf,
        config_overrides: Option<WalletConfigOverrides>,
        storage_ctor: impl FnOnce(WalletConfig) -> Result<WalletChainStore>,
        last_synced_block: u64,
    ) -> Result<Self> {
        let mut config = WalletConfig::from_path_or_initialize_default(&config_path)
            .with_context(|| format!("Failed to deserialize wallet config at {config_path:#?}"))?;
        if let Some(config_overrides) = config_overrides.clone() {
            config.apply_overrides(config_overrides);
        }

        let sequencer_client = Arc::new(SequencerClient::new_with_auth(
            config.sequencer_addr.clone(),
            config.basic_auth.clone(),
        )?);
        let tx_poller = TxPoller::new(config.clone(), Arc::clone(&sequencer_client));

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

    /// Get configuration with applied overrides
    pub fn config(&self) -> &WalletConfig {
        &self.storage.wallet_config
    }

    /// Get storage
    pub fn storage(&self) -> &WalletChainStore {
        &self.storage
    }

    /// Reset storage
    pub fn reset_storage(&mut self, password: String) -> Result<()> {
        self.storage = WalletChainStore::new_storage(self.storage.wallet_config.clone(), password)?;
        Ok(())
    }

    /// Store persistent data at home
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

        println!("Stored persistent accounts at {:#?}", self.storage_path);

        Ok(())
    }

    /// Store persistent data at home
    pub async fn store_config_changes(&self) -> Result<()> {
        let config = serde_json::to_vec_pretty(&self.storage.wallet_config)?;

        let mut config_file = tokio::fs::File::create(&self.config_path).await?;
        config_file.write_all(&config).await?;
        // Ensure data is flushed to disk before returning to prevent race conditions
        config_file.sync_all().await?;

        info!("Stored data at {:#?}", self.config_path);

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

    pub fn create_new_account_private(
        &mut self,
        chain_index: Option<ChainIndex>,
    ) -> (AccountId, ChainIndex) {
        self.storage
            .user_data
            .generate_new_privacy_preserving_transaction_key_chain(chain_index)
    }

    /// Get account balance
    pub async fn get_account_balance(&self, acc: AccountId) -> Result<u128> {
        Ok(self
            .sequencer_client
            .get_account_balance(acc)
            .await?
            .balance)
    }

    /// Get accounts nonces
    pub async fn get_accounts_nonces(&self, accs: Vec<AccountId>) -> Result<Vec<u128>> {
        Ok(self
            .sequencer_client
            .get_accounts_nonces(accs)
            .await?
            .nonces)
    }

    /// Get account
    pub async fn get_account_public(&self, account_id: AccountId) -> Result<Account> {
        let response = self.sequencer_client.get_account(account_id).await?;
        Ok(response.account)
    }

    pub fn get_account_public_signing_key(
        &self,
        account_id: AccountId,
    ) -> Option<&nssa::PrivateKey> {
        self.storage
            .user_data
            .get_pub_account_signing_key(account_id)
    }

    pub fn get_account_private(&self, account_id: AccountId) -> Option<Account> {
        self.storage
            .user_data
            .get_private_account(account_id)
            .map(|value| value.1.clone())
    }

    pub fn get_private_account_commitment(&self, account_id: AccountId) -> Option<Commitment> {
        let (keys, account) = self.storage.user_data.get_private_account(account_id)?;
        Some(Commitment::new(&keys.nullifer_public_key, account))
    }

    /// Poll transactions
    pub async fn poll_native_token_transfer(&self, hash: HashType) -> Result<NSSATransaction> {
        let transaction_encoded = self.poller.poll_tx(hash).await?;
        let tx_base64_decode = BASE64.decode(transaction_encoded)?;
        let pub_tx = borsh::from_slice::<NSSATransaction>(&tx_base64_decode).unwrap();

        Ok(pub_tx)
    }

    pub async fn check_private_account_initialized(
        &self,
        account_id: AccountId,
    ) -> Result<Option<MembershipProof>> {
        if let Some(acc_comm) = self.get_private_account_commitment(account_id) {
            self.sequencer_client
                .get_proof_for_commitment(acc_comm)
                .await
                .map_err(anyhow::Error::from)
        } else {
            Ok(None)
        }
    }

    pub fn decode_insert_privacy_preserving_transaction_results(
        &mut self,
        tx: nssa::privacy_preserving_transaction::PrivacyPreservingTransaction,
        acc_decode_mask: &[AccDecodeData],
    ) -> Result<()> {
        for (output_index, acc_decode_data) in acc_decode_mask.iter().enumerate() {
            match acc_decode_data {
                AccDecodeData::Decode(secret, acc_account_id) => {
                    let acc_ead = tx.message.encrypted_private_post_states[output_index].clone();
                    let acc_comm = tx.message.new_commitments[output_index].clone();

                    let res_acc = nssa_core::EncryptionScheme::decrypt(
                        &acc_ead.ciphertext,
                        secret,
                        &acc_comm,
                        output_index as u32,
                    )
                    .unwrap();

                    println!("Received new acc {res_acc:#?}");

                    self.storage
                        .insert_private_account_data(*acc_account_id, res_acc);
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
    ) -> Result<(SendTxResponse, Vec<SharedSecretKey>), ExecutionFailureKind> {
        // TODO: handle large Err-variant properly
        #[allow(clippy::result_large_err)]
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
    ) -> Result<(SendTxResponse, Vec<SharedSecretKey>), ExecutionFailureKind> {
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
            acc_manager.visibility_mask().to_vec(),
            produce_random_nonces(private_account_keys.len()),
            private_account_keys
                .iter()
                .map(|keys| (keys.npk.clone(), keys.ssk))
                .collect::<Vec<_>>(),
            acc_manager.private_account_auth(),
            acc_manager.private_account_membership_proofs(),
            &program.to_owned(),
        )
        .unwrap();

        let message =
            nssa::privacy_preserving_transaction::message::Message::try_from_circuit_output(
                acc_manager.public_account_ids(),
                Vec::from_iter(acc_manager.public_account_nonces()),
                private_account_keys
                    .iter()
                    .map(|keys| (keys.npk.clone(), keys.vpk.clone(), keys.epk.clone()))
                    .collect(),
                output,
            )
            .unwrap();

        let witness_set =
            nssa::privacy_preserving_transaction::witness_set::WitnessSet::for_message(
                &message,
                proof,
                &acc_manager.public_account_auth(),
            );
        let tx = PrivacyPreservingTransaction::new(message, witness_set);

        let shared_secrets: Vec<_> = private_account_keys
            .into_iter()
            .map(|keys| keys.ssk)
            .collect();

        Ok((
            self.sequencer_client.send_tx_private(tx).await?,
            shared_secrets,
        ))
    }

    pub async fn sync_to_block(&mut self, block_id: u64) -> Result<()> {
        use futures::TryStreamExt as _;

        if self.last_synced_block >= block_id {
            return Ok(());
        }

        let before_polling = std::time::Instant::now();
        let num_of_blocks = block_id - self.last_synced_block;
        println!("Syncing to block {block_id}. Blocks to sync: {num_of_blocks}");

        let poller = self.poller.clone();
        let mut blocks =
            std::pin::pin!(poller.poll_block_range(self.last_synced_block + 1..=block_id));

        let bar = indicatif::ProgressBar::new(num_of_blocks);
        while let Some(block) = blocks.try_next().await? {
            for tx in block.transactions {
                self.sync_private_accounts_with_tx(tx);
            }

            self.last_synced_block = block.block_id;
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
            .iter()
            .map(|(acc_account_id, (key_chain, _))| (*acc_account_id, key_chain, None))
            .chain(self.storage.user_data.private_key_tree.key_map.iter().map(
                |(chain_index, keys_node)| {
                    (
                        keys_node.account_id(),
                        &keys_node.value.0,
                        chain_index.index(),
                    )
                },
            ));

        let affected_accounts = private_account_key_chains
            .flat_map(|(acc_account_id, key_chain, index)| {
                let view_tag = EncryptedAccountData::compute_view_tag(
                    key_chain.nullifer_public_key.clone(),
                    key_chain.viewing_public_key.clone(),
                );

                tx.message()
                    .encrypted_private_post_states
                    .iter()
                    .enumerate()
                    .filter(move |(_, encrypted_data)| encrypted_data.view_tag == view_tag)
                    .filter_map(|(ciph_id, encrypted_data)| {
                        let ciphertext = &encrypted_data.ciphertext;
                        let commitment = &tx.message.new_commitments[ciph_id];
                        let shared_secret = key_chain
                            .calculate_shared_secret_receiver(encrypted_data.epk.clone(), index);

                        nssa_core::EncryptionScheme::decrypt(
                            ciphertext,
                            &shared_secret,
                            commitment,
                            ciph_id as u32,
                        )
                    })
                    .map(move |res_acc| (acc_account_id, res_acc))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        for (affected_account_id, new_acc) in affected_accounts {
            info!(
                "Received new account for account_id {affected_account_id:#?} with account object {new_acc:#?}"
            );
            self.storage
                .insert_private_account_data(affected_account_id, new_acc);
        }
    }

    pub fn config_path(&self) -> &PathBuf {
        &self.config_path
    }

    pub fn storage_path(&self) -> &PathBuf {
        &self.storage_path
    }

    pub fn config_overrides(&self) -> &Option<WalletConfigOverrides> {
        &self.config_overrides
    }
}
