#![expect(
    clippy::print_stdout,
    reason = "This is a CLI application, printing to stdout and stderr is expected and convenient"
)]
#![expect(
    clippy::shadow_unrelated,
    reason = "Most of the shadows come from args parsing which is ok"
)]

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::PathBuf,
};

pub use account_manager::{AccountIdentity, AccountMention, CIPHERTEXT_PAD_SIZE, SelectedShard};
use anyhow::{Context as _, Result};
use bip39::Mnemonic;
use common::{HashType, block::Block, transaction::LeeTransaction};
use config::WalletConfig;
use key_protocol::key_management::key_tree::chain_index::ChainIndex;
use lee::{
    Account, AccountId, Assumption, Declared, PrivacyPreservingTransaction, ProgramId,
    ProvingInput, PublicIdentity, Simulation,
    privacy_preserving_transaction::{
        circuit::ProgramCatalog,
        message::{EncryptedAccountData, Message},
    },
};
use lee_core::{
    BlockId, Commitment, CommitmentSetDigest, MembershipProof, SharedSecretKey,
    account::{Actor, Nonce},
    execution_state::TransactionEntry,
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{MessageData, MessageId, StoredMessage},
};
use log::warn;
use sequencer_service_rpc::{RpcClient as _, SequencerClient};
use storage::Storage;
use tokio::io::AsyncWriteExt as _;
use url::Url;

use crate::{
    account::{AccountIdWithPrivacy, Label},
    config::WalletConfigOverrides,
    multi_client::{MultiSequencerClient, Statistics, extract_statistics_from_path},
    poller::{TxPoller, multi_poll},
    storage::key_chain::{NullifierIndex, SharedAccountEntry},
};

pub mod account;
mod account_manager;
pub mod cli;
pub mod config;
pub mod helperfunctions;
pub mod multi_client;
pub mod poller;
pub mod program_facades;
pub mod storage;

pub const SUPPRESS_VERBOSE_PRINTS: &str = "SUPPRESS_VERBOSE_PRINTS";

pub const HOME_DIR_ENV_VAR: &str = "LEE_WALLET_HOME_DIR";

/// Default execution gas limit for wallet-built public transactions: roughly
/// three times the widest measured program call, one fifth of the per-block cap.
pub const DEFAULT_GAS_LIMIT: u64 = 2_000_000;

/// Base fee the default `max_fee` is sized against: 8x the genesis minimum,
/// so defaults survive early congestion without re-signing.
const ASSUMED_BASE_FEE: u128 = 64;

/// Serialized-size allowance the default `max_fee` is sized against.
const ASSUMED_DATA_BYTES: u128 = 100_000;

/// Default cap on the fee reservation for wallet-built public transactions.
pub const DEFAULT_MAX_FEE: u128 = max_fee_for(DEFAULT_GAS_LIMIT);

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
    #[error("Sequencer client error: {0}")]
    SequencerClientError(#[from] sequencer_service_rpc::ClientError),
    #[error("Can not pay for operation")]
    InsufficientFundsError,
    #[error("Account {0} data is invalid")]
    AccountDataError(AccountId),
    #[error("Account {0} is mentioned with conflicting identities")]
    ConflictingAccountIdentity(AccountId),
    #[error("Account {0} holds state but has no membership proof to update it")]
    MissingMembershipProof(AccountId),
    #[error("Program bytecode splits into {expected} segment(s) but {actual} were supplied")]
    SegmentCountMismatch { expected: usize, actual: usize },
    #[error("Program bytecode is not a valid RISC0 program binary")]
    InvalidProgramBinary(#[source] anyhow::Error),
    #[error(
        "Program uses a non-default kernel ELF; only programs built with the protocol's \
         default kernel can be deployed"
    )]
    UnsupportedKernelElf,
    #[error("Failed to build transaction: {0}")]
    TransactionBuildError(#[from] lee::error::LeeError),
    #[error("Failed to sign transaction: {0}")]
    SignError(anyhow::Error),
    #[error("Sending transaction failed for each client")]
    MultiSequencerTransactionSendError,
    #[error("Failed to join a task: {0}")]
    JoinError(#[from] tokio::task::JoinError),
}

pub struct WalletCore {
    config_path: PathBuf,
    config_overrides: Option<WalletConfigOverrides>,
    config: WalletConfig,

    storage: Storage,
    storage_path: PathBuf,

    statistics_path: PathBuf,
    statistics: HashMap<Url, Statistics>,

    multi_sequencer_client: MultiSequencerClient,
}

impl WalletCore {
    /// Construct wallet using [`HOME_DIR_ENV_VAR`] env var for paths or user home dir if not set.
    pub async fn from_env() -> Result<Self> {
        let config_path = helperfunctions::fetch_config_path()?;
        let storage_path = helperfunctions::fetch_persistent_storage_path()?;
        let statistics_path = helperfunctions::fetch_statistics_path()?;

        Self::new_update_chain(config_path, storage_path, statistics_path, None).await
    }

    pub async fn new_update_chain(
        config_path: PathBuf,
        storage_path: PathBuf,
        statistics_path: PathBuf,
        config_overrides: Option<WalletConfigOverrides>,
    ) -> Result<Self> {
        let storage = Storage::from_path(&storage_path)
            .with_context(|| format!("Failed to load storage from {}", storage_path.display()))?;

        Self::new(
            config_path,
            storage_path,
            statistics_path,
            config_overrides,
            storage,
        )
        .await
    }

    pub async fn new_init_storage(
        config_path: PathBuf,
        storage_path: PathBuf,
        statistics_path: PathBuf,
        config_overrides: Option<WalletConfigOverrides>,
        password: &str,
    ) -> Result<(Self, Mnemonic)> {
        let (storage, mnemonic) = Storage::new(password).context("Failed to create storage")?;
        let wallet = Self::new(
            config_path,
            storage_path,
            statistics_path,
            config_overrides,
            storage,
        )
        .await?;

        Ok((wallet, mnemonic))
    }

    async fn new(
        config_path: PathBuf,
        storage_path: PathBuf,
        statistics_path: PathBuf,
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

        let mut statistics = extract_statistics_from_path(&statistics_path)?;

        let multi_sequencer_client = MultiSequencerClient::new(
            &config.sequencers,
            &mut statistics,
            config.multi_sequencer_client_config.clone(),
        )
        .await?;

        Ok(Self {
            config_path,
            config_overrides,
            config,
            storage,
            storage_path,
            statistics_path,
            statistics,
            multi_sequencer_client,
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

    #[must_use]
    pub fn poller_vec(&self) -> Vec<TxPoller> {
        self.leaders()
            .iter()
            .take(self.multi_sequencer_client.config().distribution_limit)
            .map(|(leader, _)| TxPoller::new(self.config(), leader.clone()))
            .collect()
    }

    #[must_use]
    pub fn poller_helm(&self) -> TxPoller {
        TxPoller::new(self.config(), self.helm_owned())
    }

    #[must_use]
    pub fn helm_owned(&self) -> SequencerClient {
        self.multi_sequencer_client.helm().0.clone()
    }

    #[must_use]
    pub fn helm_url(&self) -> Url {
        self.multi_sequencer_client.helm().1.clone()
    }

    #[must_use]
    pub fn leaders(&self) -> &[(SequencerClient, Url)] {
        self.multi_sequencer_client.leaders()
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

    /// Rotates multi-client and stores metrics.
    pub async fn client_rotation(&mut self) -> Result<()> {
        self.multi_sequencer_client
            .update_statistics(&mut self.statistics)
            .await?;

        self.multi_sequencer_client
            .rotate(
                &self.config.sequencers,
                &mut self.statistics,
                &self.config.multi_sequencer_client_config,
            )
            .await?;

        let statistics_serialized = serde_json::to_vec_pretty(&self.statistics)?;
        let mut file = tokio::fs::File::create(&self.statistics_path)
            .await
            .context("Failed to create file")?;
        file.write_all(&statistics_serialized)
            .await
            .context("Failed to write to file")?;
        file.sync_all().await.context("Failed to sync file")?;

        println!("Stored statistics at {}", self.statistics_path.display());

        Ok(())
    }

    /// Store persistent data at home.
    pub async fn store_config_changes(&self) -> Result<()> {
        let config = serde_json::to_vec_pretty(&self.config)?;

        let mut config_file = tokio::fs::File::create(&self.config_path).await?;
        config_file.write_all(&config).await?;
        // Ensure data is flushed to disk before returning to prevent race conditions
        config_file.sync_all().await?;

        log::info!("Stored data at {}", self.config_path.display());

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
        let vpk = keys.generate_viewing_public_key();
        let identifier = entry.identifier;

        if let Some(seed) = entry.pda_seed {
            Some(AccountIdentity::PrivatePdaShared {
                authority: AccountId::from_builtin_program(entry.authority_program_id?),
                seed,
                nsk: keys.nullifier_secret_key(),
                vpk,
                identifier,
            })
        } else {
            Some(AccountIdentity::PrivateShared {
                ask: keys.authorization_secret_key,
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

    /// Re-derive a shared account's state by scanning its keypair from genesis to the current
    /// synced block. The init note's nullifier is deterministic on ID, so we await it and let
    /// the nullifier pass decode the init and every subsequent update.
    ///
    /// If no initialization is found, will return `Ok` and default to usual hot-sync.
    async fn catch_up_shared_account(&mut self, account_id: AccountId) -> Result<()> {
        use futures::TryStreamExt as _;

        let cursor = self.storage.last_synced_block();
        if cursor == 0
            || self
                .storage
                .key_chain()
                .shared_private_account(account_id)
                .is_none()
        {
            return Ok(());
        }

        log::info!("Scanning shared account {account_id:#?} from genesis to block {cursor}");

        let mut index = NullifierIndex::default();
        index.track_initialization(account_id);

        let poller = self.poller_helm();
        let mut blocks = std::pin::pin!(poller.poll_block_range(1..=cursor));
        while let Some(block) = blocks.try_next().await? {
            for tx in block.body.transactions {
                let LeeTransaction::PrivacyPreserving(pp_tx) = &tx else {
                    continue;
                };
                // Sync updates while watching only the init nullifier.
                self.storage
                    .key_chain_mut()
                    .sync_updates_via_nullifiers(&pp_tx.message, &mut index);
            }
        }

        let now = self.storage.last_synced_block();
        // This is a defence-in-depth. Currently during the async update the cursor
        // cannot advance. However, de-sync can be possible later. This hard error
        // will signal this.
        if now != cursor {
            return Err(anyhow::anyhow!(
                "Shared-account catched-up to {cursor} with a cursor de-sync advancing to {now}"
            ));
        }

        Ok(())
    }

    /// Create a shared PDA account from a group's GMS. Returns the `AccountId` and derived keys.
    pub async fn create_shared_pda_account(
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
        let vpk = keys.generate_viewing_public_key();
        let account_id = AccountId::for_private_pda(
            &AccountId::from_builtin_program(program_id),
            &pda_seed,
            &npk,
            &vpk,
            identifier,
        );

        self.register_shared_account(
            account_id,
            group_name,
            identifier,
            Some(pda_seed),
            Some(program_id),
        );
        self.catch_up_shared_account(account_id).await?;

        Ok(SharedAccountInfo {
            account_id,
            npk,
            vpk,
        })
    }

    /// Create a shared regular private account from a group's GMS under the given `identifier`.
    pub async fn create_shared_regular_account_with_identifier(
        &mut self,
        group_name: Label,
        identifier: lee_core::Identifier,
    ) -> Result<SharedAccountInfo> {
        let holder = self
            .storage
            .key_chain()
            .group_key_holder(&group_name)
            .context(format!("Group '{group_name}' not found"))?;

        let keys = holder.derive_regular_shared_account_keys_from_identifier(identifier);
        let npk = keys.generate_nullifier_public_key();
        let vpk = keys.generate_viewing_public_key();
        let account_id = AccountId::from((&npk, &vpk, identifier));

        self.register_shared_account(account_id, group_name, identifier, None, None);
        self.catch_up_shared_account(account_id).await?;

        Ok(SharedAccountInfo {
            account_id,
            npk,
            vpk,
        })
    }

    #[must_use]
    pub fn get_statistics(&self, sequencer_url: &Url) -> Option<&Statistics> {
        self.statistics.get(sequencer_url)
    }

    /// Get account balance.
    pub async fn get_account_balance(&self, acc: AccountId) -> Result<u128> {
        Ok(self
            .multi_sequencer_client
            .metered_get(async |client: &SequencerClient| client.get_account_balance(acc).await)
            .await?)
    }

    /// Get accounts nonces.
    pub async fn get_accounts_nonces(&self, accs: &[AccountId]) -> Result<Vec<Nonce>> {
        Ok(self
            .multi_sequencer_client
            .metered_get(async |client: &SequencerClient| {
                client.get_accounts_nonces(accs.to_vec()).await
            })
            .await?)
    }

    /// Returns the account's nonce and the selected shard; its balance is the shard at the
    /// native token program.
    pub async fn get_account_view(&self, shard_selector: Actor) -> Result<Account> {
        let mut account = self
            .multi_sequencer_client
            .metered_get(async |client: &SequencerClient| {
                client.get_account_view(shard_selector).await
            })
            .await?;

        // RPC projections include empty shards; the wallet omits them.
        account.data.shards.retain(|_, shard| !shard.is_empty());

        Ok(account)
    }

    pub async fn get_pending_messages(
        &self,
        from_sequence: u128,
        limit: u32,
    ) -> Result<Vec<StoredMessage>> {
        Ok(self
            .multi_sequencer_client
            .metered_get(async |client: &SequencerClient| {
                client.get_pending_messages(from_sequence, limit).await
            })
            .await?)
    }

    pub async fn owned_pending_messages(&self) -> Result<Vec<StoredMessage>> {
        let owned: HashSet<AccountId> = {
            let key_chain = self.storage.key_chain();
            key_chain
                .public_account_ids()
                .chain(key_chain.private_account_ids())
                .map(|(account_id, _)| account_id)
                .collect()
        };

        self.pending_messages_where(|record| owned.contains(&record.body.to.account_id))
            .await
    }

    pub async fn find_pending_message(&self, id: MessageId) -> Result<Option<StoredMessage>> {
        Ok(self
            .pending_messages_where(|record| record.id() == id)
            .await?
            .pop())
    }

    async fn pending_messages_where(
        &self,
        keep: impl Fn(&StoredMessage) -> bool,
    ) -> Result<Vec<StoredMessage>> {
        const PAGE: u16 = 256;
        let mut records = Vec::new();
        let mut from_sequence = 0;
        loop {
            let page = self
                .get_pending_messages(from_sequence, u32::from(PAGE))
                .await?;
            let last_page = page.len() < usize::from(PAGE);
            if let Some(last) = page.last() {
                from_sequence = last.sequence.saturating_add(1);
            }
            records.extend(page.into_iter().filter(&keep));
            if last_page {
                return Ok(records);
            }
        }
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

    pub async fn get_last_block_id(&self) -> Result<u64> {
        Ok(self
            .multi_sequencer_client
            .metered_get(async |client: &SequencerClient| client.get_last_block_id().await)
            .await?)
    }

    pub async fn get_block(&self, block_id: u64) -> Result<Option<Block>> {
        Ok(self
            .multi_sequencer_client
            .metered_get(async |client: &SequencerClient| client.get_block(block_id).await)
            .await?)
    }

    pub async fn get_transaction(
        &self,
        hash: HashType,
    ) -> Result<Option<(LeeTransaction, BlockId)>> {
        Ok(self
            .multi_sequencer_client
            .metered_get(async |client: &SequencerClient| client.get_transaction(hash).await)
            .await?)
    }

    /// Get public account.
    pub async fn get_account_public(&self, account_id: AccountId) -> Result<Account> {
        Ok(self
            .multi_sequencer_client
            .metered_get(async |client: &SequencerClient| client.get_account(account_id).await)
            .await?)
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
    pub fn private_account_state(&self, account_id: AccountId) -> Option<&Account> {
        self.storage
            .key_chain()
            .private_account(account_id)
            .map(|acc| acc.account)
            .or_else(|| {
                self.storage
                    .key_chain()
                    .shared_private_account(account_id)
                    .map(|entry| &entry.account)
            })
    }

    #[must_use]
    pub fn get_private_account_commitment(&self, account_id: AccountId) -> Option<Commitment> {
        self.private_account_state(account_id)
            .map(|account| Commitment::new(&account_id, account))
    }

    pub async fn get_program_ids(&self) -> Result<BTreeMap<String, ProgramId>> {
        Ok(self
            .multi_sequencer_client
            .metered_get(async |client: &SequencerClient| client.get_program_ids().await)
            .await?)
    }

    /// Poll transactions.
    pub async fn poll_transaction(&self, tx_hash: HashType) -> Result<(LeeTransaction, BlockId)> {
        multi_poll(self.poller_vec(), tx_hash).await
    }

    pub async fn get_proofs_and_root(
        &self,
        commitments: &[Commitment],
    ) -> Result<(Vec<Option<MembershipProof>>, CommitmentSetDigest)> {
        Ok(self
            .multi_sequencer_client
            .metered_get(async |client: &SequencerClient| {
                client.get_proofs_and_root(commitments.to_vec()).await
            })
            .await?)
    }

    pub fn decode_insert_privacy_preserving_transaction_results(
        &mut self,
        tx: &lee::privacy_preserving_transaction::PrivacyPreservingTransaction,
        acc_decode_mask: &[AccDecodeData],
    ) -> Result<()> {
        let note_count = tx.message.execution.private_actions.len();
        anyhow::ensure!(
            note_count >= acc_decode_mask.len(),
            "Decode mask has {} entries but the transaction has {note_count} notes",
            acc_decode_mask.len(),
        );
        for acc_decode_data in acc_decode_mask {
            match acc_decode_data {
                AccDecodeData::Decode(secret, acc_account_id) => {
                    let Some(output_index) = self
                        .storage
                        .key_chain()
                        .locate_spend(*acc_account_id, &tx.message)
                    else {
                        warn!(
                            "No note located for {acc_account_id}; cached state stays stale until the next sync"
                        );
                        continue;
                    };
                    let (kind, res_acc) =
                        decrypt_note_at(&tx.message, output_index, secret).unwrap();

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
        let (tx, block_id) = self.poll_transaction(tx_hash).await?;
        println!("Transaction is included in block {block_id}");
        if std::env::var_os(SUPPRESS_VERBOSE_PRINTS).is_none() {
            println!("Transaction data is {tx:?}");
        }
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
        let (tx, block_id) = self.poll_transaction(tx_hash).await?;
        println!("Transaction is included in block {block_id}");
        if std::env::var_os(SUPPRESS_VERBOSE_PRINTS).is_none() {
            println!("Transaction data is {tx:?}");
        }
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
        accounts: Vec<AccountMention>,
        root: usize,
        message: MessageData,
        programs: &ProgramCatalog,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        self.send_privacy_preserving_tx_with_pre_check(
            accounts,
            root,
            message,
            programs,
            |_| Ok(()),
        )
        .await
    }

    // Public when every account is, privacy-preserving otherwise; the prover derives the boundary.
    pub async fn send_tx(
        &self,
        accounts: Vec<AccountMention>,
        root: usize,
        message: MessageData,
        programs: &ProgramCatalog,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        if accounts.iter().any(|mention| mention.identity.is_private()) {
            self.send_privacy_preserving_tx(accounts, root, message, programs)
                .await
        } else {
            self.send_pub_tx(accounts, root, message)
                .await
                .map(|tx_hash| (tx_hash, Vec::new()))
        }
    }

    pub async fn send_privacy_preserving_tx_with_pre_check(
        &self,
        accounts: Vec<AccountMention>,
        root: usize,
        message: MessageData,
        programs: &ProgramCatalog,
        tx_pre_check: impl FnOnce(&[SelectedShard]) -> Result<(), ExecutionFailureKind>,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let root = TransactionEntry::Call {
            to: root_actor(&accounts, root)?,
            message,
        };
        self.send_proven(accounts, root, Vec::new(), programs, None, tx_pre_check)
            .await
    }

    // Proves under `assumed` instead of deriving it from current public state: a conditional
    // promise, such as a fixed offer's payout, that settlement checks against live execution.
    pub async fn send_privacy_preserving_tx_assuming(
        &self,
        accounts: Vec<AccountMention>,
        root: usize,
        message: MessageData,
        assumed: Vec<Vec<Assumption>>,
        programs: &ProgramCatalog,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let root = TransactionEntry::Call {
            to: root_actor(&accounts, root)?,
            message,
        };
        self.send_proven(accounts, root, Vec::new(), programs, Some(assumed), |_| {
            Ok(())
        })
        .await
    }

    async fn send_proven(
        &self,
        accounts: Vec<AccountMention>,
        root: TransactionEntry<StoredMessage>,
        identities: Vec<PublicIdentity>,
        programs: &ProgramCatalog,
        assumed: Option<Vec<Vec<Assumption>>>,
        tx_pre_check: impl FnOnce(&[SelectedShard]) -> Result<(), ExecutionFailureKind>,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let acc_manager = account_manager::AccountManager::new(self, accounts).await?;

        tx_pre_check(&acc_manager.selected_shards())?;

        for account_id in acc_manager.accounts_outgrowing_pad() {
            warn!(
                "Account {account_id} exceeds the {CIPHERTEXT_PAD_SIZE}-byte note pad; its note is \
                 identifiable by length in this transaction"
            );
        }

        let private_account_keys = acc_manager.private_account_keys();
        let input = ProvingInput {
            root,
            declared: Declared::new(acc_manager.public_actors(), acc_manager.signers()),
            private_witnesses: acc_manager.private_witnesses()?,
            dummy_inputs: acc_manager.dummy_inputs_default(),
            ciphertext_padding: Some(CIPHERTEXT_PAD_SIZE),
        };

        let programs = programs.clone();
        let (output, proof) = match assumed {
            None => {
                let simulation = Simulation {
                    public_shards: acc_manager.public_shards(),
                    proven_public_accounts: identities
                        .iter()
                        .map(PublicIdentity::account_id)
                        .collect(),
                };
                tokio::task::spawn_blocking(move || {
                    lee::execute_and_prove(input, &simulation, &programs)
                })
            }
            Some(assumed) => tokio::task::spawn_blocking(move || {
                lee::execute_and_prove_assuming(input, assumed, &programs)
            }),
        }
        .await??;

        let message = Message {
            identities,
            ..Message::from_circuit_output(acc_manager.public_account_nonces(), output)
        };

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

        let call_res = first_success_or_error(
            self.multi_sequencer_client
                .metered_send_transaction(LeeTransaction::PrivacyPreserving(tx))
                .await,
        );

        Ok((call_res?, shared_secrets))
    }

    pub async fn send_pub_tx(
        &self,
        accounts: Vec<AccountMention>,
        root: usize,
        message: MessageData,
    ) -> Result<HashType, ExecutionFailureKind> {
        self.send_pub_tx_paid_by(accounts, root, message, None)
            .await
    }

    /// Like [`Self::send_pub_tx`], but `payer` (if given) covers the fee instead of the wallet's
    /// self-pay selection. See [`Self::send_pub_tx_with_pre_check`].
    pub async fn send_pub_tx_paid_by(
        &self,
        accounts: Vec<AccountMention>,
        root: usize,
        message: MessageData,
        payer: Option<AccountId>,
    ) -> Result<HashType, ExecutionFailureKind> {
        self.send_pub_tx_with_pre_check(accounts, root, message, payer, |_| Ok(()))
            .await
    }

    /// Sends a public transaction over `accounts`, paid by `payer` if given.
    ///
    /// `payer: None` picks the first funded signing account in `accounts`, or the first signing
    /// account if none is funded (see [`AccountManager::fee_payer_account_id`]).
    ///
    /// An explicit payer may be one of `accounts`' signing entries, or any other public account
    /// whose signing key the wallet holds: the latter co-signs (nonce and signature appended
    /// after `accounts`' own) without joining the message's `account_ids`, so programs with a
    /// fixed account shape (like the `program_loader`, whose accounts are all freshly claimed
    /// and unfunded) can still be paid for.
    pub async fn send_pub_tx_with_pre_check(
        &self,
        accounts: Vec<AccountMention>,
        root: usize,
        message: MessageData,
        payer: Option<AccountId>,
        tx_pre_check: impl FnOnce(&[SelectedShard]) -> Result<(), ExecutionFailureKind>,
    ) -> Result<HashType, ExecutionFailureKind> {
        let root = TransactionEntry::Call {
            to: root_actor(&accounts, root)?,
            message,
        };
        self.send_public(accounts, root, Vec::new(), payer, tx_pre_check)
            .await
    }

    async fn send_public(
        &self,
        accounts: Vec<AccountMention>,
        root: TransactionEntry<MessageId>,
        identities: Vec<PublicIdentity>,
        payer: Option<AccountId>,
        tx_pre_check: impl FnOnce(&[SelectedShard]) -> Result<(), ExecutionFailureKind>,
    ) -> Result<HashType, ExecutionFailureKind> {
        // Public transaction, all accounts must be public
        if accounts.iter().any(|mention| mention.identity.is_private()) {
            return Err(ExecutionFailureKind::TransactionBuildError(
                lee::error::LeeError::InvalidInput(
                    "Private accounts are not allowed in public transactions".to_owned(),
                ),
            ));
        }

        let mut acc_manager = account_manager::AccountManager::new(self, accounts).await?;

        tx_pre_check(&acc_manager.selected_shards())?;

        let public_actors = acc_manager.public_actors();
        let account_ids = acc_manager.public_account_ids();
        let mut nonces = acc_manager.public_account_nonces();

        let invalid_input = |msg: &str| {
            ExecutionFailureKind::TransactionBuildError(lee::error::LeeError::InvalidInput(
                msg.to_owned(),
            ))
        };
        let (payer, co_signer) = match payer {
            None => (
                acc_manager
                    .fee_payer_account_id(self)
                    .await?
                    .ok_or_else(|| {
                        invalid_input("Public transaction has no signing account to pay its fees")
                    })?,
                None,
            ),
            Some(payer) if acc_manager.signs_for(payer) => (payer, None),
            Some(payer) if account_ids.contains(&payer) => {
                return Err(invalid_input(
                    "Fee payer is a non-signing account of this transaction",
                ));
            }
            Some(payer) => {
                let key = self.get_account_public_signing_key(payer).ok_or_else(|| {
                    invalid_input("Fee payer's signing key is not held by this wallet")
                })?;
                let account = self
                    .get_account_view(Actor::native_balance(payer))
                    .await
                    .map_err(ExecutionFailureKind::SequencerError)?;
                nonces.push(account.nonce);
                (payer, Some(key))
            }
        };

        let message = lee::public_transaction::Message::new(
            root,
            public_actors,
            nonces,
            Some(lee::FeeDeclaration::new(
                payer,
                self.config.gas_limit,
                0,
                max_fee_for(self.config.gas_limit),
            )),
            identities,
        );

        let message_hash = message.hash();
        let mut signatures_public_keys = acc_manager
            .sign_message(message_hash)
            .map_err(ExecutionFailureKind::SignError)?;
        if let Some(key) = co_signer {
            signatures_public_keys.push((
                lee::Signature::new(key, &message_hash),
                lee::PublicKey::new_from_private_key(key),
            ));
        }

        let witness_set =
            lee::public_transaction::WitnessSet::from_raw_parts(signatures_public_keys);

        let tx = lee::public_transaction::PublicTransaction::new(message, witness_set);

        first_success_or_error(
            self.multi_sequencer_client
                .metered_send_transaction(LeeTransaction::Public(tx))
                .await,
        )
    }

    pub async fn receive_pending_message(
        &self,
        record: StoredMessage,
        payer: Option<AccountId>,
        evidence: Option<PublicIdentity>,
        programs: &ProgramCatalog,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        check_receivable(&record)?;
        let to = record.body.to;
        if let Some(identity) = self.resolve_private_account(to.account_id) {
            let accounts = vec![
                identity
                    .select_program_shard(to.program_account_id)
                    .without_authorization(),
            ];
            return self
                .send_proven(
                    accounts,
                    TransactionEntry::Receive(record),
                    Vec::new(),
                    programs,
                    None,
                    |_| Ok(()),
                )
                .await;
        }

        let (identity, evidence) = match (
            self.get_account_public_signing_key(to.account_id),
            payer,
            evidence,
        ) {
            (Some(_), None, _) => (AccountIdentity::Public(to.account_id), None),
            (Some(key), Some(_), _) => (
                AccountIdentity::PublicNoSign(to.account_id),
                Some(PublicIdentity::Key(lee::PublicKey::new_from_private_key(
                    key,
                ))),
            ),
            (None, Some(_), Some(evidence)) if evidence.account_id() == to.account_id => {
                (AccountIdentity::PublicNoSign(to.account_id), Some(evidence))
            }
            (None, _, _) => {
                return Err(ExecutionFailureKind::TransactionBuildError(
                    lee::error::LeeError::InvalidInput(format!(
                        "Message destination {} is not this wallet's; receiving it needs a payer \
                         and evidence of its identity",
                        to.account_id
                    )),
                ));
            }
        };
        self.send_public(
            vec![identity.select_program_shard(to.program_account_id)],
            TransactionEntry::Receive(record.id()),
            evidence.into_iter().collect(),
            payer,
            |_| Ok(()),
        )
        .await
        .map(|tx_hash| (tx_hash, Vec::new()))
    }

    pub async fn sync_to_latest_block(&mut self) -> Result<u64> {
        let latest_block_id = self.get_last_block_id().await?;
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

        let poller = self.poller_helm();
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
                message
                    .execution
                    .private_actions
                    .iter()
                    .enumerate()
                    .filter(move |(ciph_id, action)| {
                        // If we have not decrypted the update using the nullifiers,
                        // the note may be an initialized one, for which we should
                        // scan.
                        !handled.contains(ciph_id)
                            && action.encrypted_post_state.view_tag == view_tag
                    })
                    .filter_map(move |(ciph_id, action)| {
                        let shared_secret = key_chain
                            .calculate_shared_secret_receiver(&action.encrypted_post_state.epk)?;

                        decrypt_note_at(message, ciph_id, &shared_secret).map(|(kind, res_acc)| {
                            let npk = &key_chain.nullifier_public_key;
                            let account_id = lee::AccountId::for_private_account(
                                npk,
                                &key_chain.viewing_public_key,
                                &kind,
                            );
                            let nsk = key_chain.private_key_holder.nullifier_secret_key();
                            (account_id, kind, res_acc, nsk)
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        for (affected_account_id, kind, new_acc, nsk) in affected_accounts {
            log::info!(
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
                let nsk = keys.nullifier_secret_key();
                let vsk = keys.viewing_secret_key;
                Some((account_id, npk, vpk, vsk, nsk))
            })
            .collect();

        for (account_id, npk, vpk, vsk, nsk) in shared_keys {
            let view_tag = EncryptedAccountData::compute_view_tag(&npk, &vpk);

            for (ciph_id, action) in message.execution.private_actions.iter().enumerate() {
                // If already decrypted or the tag does not match, skip.
                if handled.contains(&ciph_id) || action.encrypted_post_state.view_tag != view_tag {
                    continue;
                }

                let Some(shared_secret) =
                    SharedSecretKey::decapsulate(&action.encrypted_post_state.epk, &vsk.d, &vsk.z)
                else {
                    continue;
                };
                if let Some((_kind, new_acc)) = decrypt_note_at(message, ciph_id, &shared_secret) {
                    log::info!("Synced shared account {account_id:#?} with new state {new_acc:#?}");
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

/// Sizes a fee cap for a given gas limit: a wallet that raises its gas limit
/// must raise its fee cap in step, or the reservation cannot cover the gas.
#[must_use]
#[expect(
    clippy::as_conversions,
    reason = "u128::from is not const; the widening is lossless"
)]
#[expect(
    clippy::arithmetic_side_effects,
    reason = "gas_limit and ASSUMED_DATA_BYTES both fit well within u128::MAX, so the widened \
              sum and product cannot overflow"
)]
pub const fn max_fee_for(gas_limit: u64) -> u128 {
    (gas_limit as u128 + ASSUMED_DATA_BYTES) * ASSUMED_BASE_FEE
}

/// Collapses the per-sequencer send results into one outcome: the first
/// success, or — when every sequencer refused — the first refusal, so the
/// caller sees *why* (e.g. a fee-admission `PayerCannotFund`) instead of a
/// generic failure. Only an empty leader set yields
/// [`ExecutionFailureKind::MultiSequencerTransactionSendError`].
fn first_success_or_error(
    results: Vec<Result<HashType, ExecutionFailureKind>>,
) -> Result<HashType, ExecutionFailureKind> {
    let mut first_error = None;
    for result in results {
        match result {
            Ok(hash) => return Ok(hash),
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }
    Err(first_error.unwrap_or(ExecutionFailureKind::MultiSequencerTransactionSendError))
}

fn decrypt_note_at(
    message: &Message,
    i: usize,
    secret: &SharedSecretKey,
) -> Option<(lee_core::PrivateAccountKind, Account)> {
    lee_core::EncryptionScheme::decrypt(
        &message.execution.private_actions[i]
            .encrypted_post_state
            .ciphertext,
        secret,
        &message.execution.private_actions[i].nullifier,
    )
}

// The root is one of the transaction's accounts, so it runs with the placement declared for it.
fn root_actor(accounts: &[AccountMention], root: usize) -> Result<Actor, ExecutionFailureKind> {
    accounts
        .get(root)
        .map(AccountMention::actor)
        .ok_or_else(|| {
            ExecutionFailureKind::TransactionBuildError(lee::error::LeeError::InvalidInput(
                format!("Root index {root} is not one of the transaction's accounts"),
            ))
        })
}

fn check_receivable(record: &StoredMessage) -> Result<(), ExecutionFailureKind> {
    let body = &record.body;
    let token = programs::token_account_id();
    let plain_credit = if body.to.program_account_id == token && body.source == token {
        matches!(
            borsh::from_slice::<token_core::Message>(&body.message),
            Ok(token_core::Message::Credit { notify: None, .. })
        )
    } else {
        body.to.program_account_id == NATIVE_TOKEN_PROGRAM_ID
            && body.source == NATIVE_TOKEN_PROGRAM_ID
            && matches!(
                borsh::from_slice::<native_token::Message>(&body.message),
                Ok(native_token::Message::Credit(_))
            )
    };
    if plain_credit {
        Ok(())
    } else {
        Err(ExecutionFailureKind::TransactionBuildError(
            lee::error::LeeError::InvalidInput(
                "This wallet only receives native credits and token credits without a notification"
                    .to_owned(),
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::CString, str::FromStr as _};

    use bip39::Mnemonic;
    use lee::AccountId;
    use lee_core::{
        account::Actor,
        program::{MessageBody, StoredMessage},
    };
    use token_core::{Delivery, Message, Notify, TokenDescriptor, TokenKind};

    use super::{ExecutionFailureKind, NATIVE_TOKEN_PROGRAM_ID, check_receivable, native_token};

    const DESCRIPTOR: TokenDescriptor = TokenDescriptor {
        definition_id: AccountId::new([2; 32]),
        kind: TokenKind::Fungible,
    };

    fn record(
        source: AccountId,
        to_program: AccountId,
        message: &impl borsh::BorshSerialize,
    ) -> StoredMessage {
        StoredMessage {
            sequence: 0,
            body: MessageBody {
                source,
                to: Actor::new(AccountId::new([1; 32]), to_program),
                message: borsh::to_vec(message).unwrap(),
            },
        }
    }

    const fn credit(notify: Option<Notify>) -> Message {
        Message::Credit {
            descriptor: DESCRIPTOR,
            amount: 5,
            notify,
        }
    }

    #[test]
    fn a_plain_token_credit_is_receivable() {
        let token = programs::token_account_id();
        assert!(check_receivable(&record(token, token, &credit(None))).is_ok());
    }

    #[test]
    fn a_transfer_a_notifying_credit_and_a_foreign_credit_are_not_receivable() {
        let token = programs::token_account_id();
        let transfer = Message::Transfer {
            to: AccountId::new([3; 32]),
            descriptor: DESCRIPTOR,
            amount: 5,
            notify: None,
            delivery: Delivery::Call,
        };
        let notifying = credit(Some(Notify {
            to: Actor::new(AccountId::new([4; 32]), AccountId::new([5; 32])),
            payload: Vec::new(),
        }));

        for refused in [
            record(token, token, &transfer),
            record(token, token, &notifying),
            record(AccountId::new([6; 32]), token, &credit(None)),
        ] {
            assert!(
                matches!(
                    check_receivable(&refused),
                    Err(ExecutionFailureKind::TransactionBuildError(
                        lee::error::LeeError::InvalidInput(_)
                    ))
                ),
                "{refused:?} must not be receivable"
            );
        }
    }

    #[test]
    fn a_native_credit_is_receivable() {
        let native = NATIVE_TOKEN_PROGRAM_ID;
        assert!(
            check_receivable(&record(native, native, &native_token::Message::Credit(5))).is_ok()
        );
    }

    #[test]
    fn native_spending_and_a_foreign_native_credit_are_not_receivable() {
        let native = NATIVE_TOKEN_PROGRAM_ID;
        let to = AccountId::new([3; 32]);
        for refused in [
            record(
                native,
                native,
                &native_token::Message::Transfer { to, amount: 5 },
            ),
            record(
                native,
                native,
                &native_token::Message::CastTransfer { to, amount: 5 },
            ),
            record(
                AccountId::new([6; 32]),
                native,
                &native_token::Message::Credit(5),
            ),
        ] {
            assert!(
                matches!(
                    check_receivable(&refused),
                    Err(ExecutionFailureKind::TransactionBuildError(
                        lee::error::LeeError::InvalidInput(_)
                    ))
                ),
                "{refused:?} must not be receivable"
            );
        }
    }

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
