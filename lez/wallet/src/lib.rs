#![expect(
    clippy::print_stdout,
    reason = "This is a CLI application, printing to stdout and stderr is expected and convenient"
)]
#![expect(
    clippy::shadow_unrelated,
    reason = "Most of the shadows come from args parsing which is ok"
)]

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    path::PathBuf,
};

pub use account_manager::{
    AccountIdentity, AccountMention, CIPHERTEXT_PAD_SIZE, SelectedActorState,
};
use anyhow::{Context as _, Result, ensure};
use bip39::Mnemonic;
use common::{HashType, block::Block, transaction::LeeTransaction};
use config::WalletConfig;
use futures::TryFutureExt as _;
use key_protocol::key_management::key_tree::chain_index::ChainIndex;
use lee::{
    Account, AccountId, EncryptedNote, PredictedCrossMessages, PrivacyPreservingTransaction,
    ProgramId, ProvingInput, PublicExecutionContext, Recipient, RecipientEncryption, Simulation,
    privacy_preserving_transaction::{circuit::ProgramCatalog, message::Message},
};
use lee_core::{
    BlockId, Commitment, CommitmentSetDigest, EphemeralSecretKey, MembershipProof, MessageWitness,
    Nullifier, NullifierSecretKey, RootCall, SharedSecretKey,
    account::{Actor, Nonce},
    execution_state::TransactionEntry,
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{MessageBody, MessageData, Publication},
};
use log::warn;
use sequencer_service_rpc::{RpcClient as _, SequencerClient};
use storage::{Storage, spent_nullifiers::SpentNullifiers};
use tokio::io::AsyncWriteExt as _;
use url::Url;

use crate::{
    account::{AccountIdWithPrivacy, Label},
    config::WalletConfigOverrides,
    multi_client::{MultiSequencerClient, Statistics, extract_statistics_from_path},
    poller::{TxPoller, multi_poll},
    storage::key_chain::{SharedAccountDerivation, SharedAccountEntry, UserKeyChain},
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

/// Info returned when creating a shared account.
pub struct SharedAccountInfo {
    pub account_id: AccountId,
    pub npk: lee_core::NullifierPublicKey,
    pub vpk: lee_core::encryption::ViewingPublicKey,
}

#[derive(Default)]
pub struct CastDelivery {
    pub recoveries: Vec<RecipientEncryption>,
    pub seals: Vec<Recipient>,
    pub promotions: CastPromotions,
}

// The Casts to execute at once: the listed candidates and, unless `listed_only`, each Cast to an
// account this transaction witnesses.
#[derive(Default)]
pub struct CastPromotions {
    pub public: BTreeSet<u64>,
    pub private: BTreeSet<u64>,
    pub listed_only: bool,
}

// A pending message's body as this wallet reads it, and the recipient its recovery note or seal
// names.
pub struct PendingMessage {
    pub position: u64,
    pub publication: Publication,
    pub body: MessageBody,
    pub recipient: Recipient,
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
    #[error("Account {0} is a foreign private account, which this wallet cannot witness")]
    ForeignPrivateAccount(AccountId),
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
    #[error("Failed to store wallet data")]
    StorageError(#[source] anyhow::Error),
    #[error("Failed to join a task: {0}")]
    JoinError(#[from] tokio::task::JoinError),
}

/// A received message a transaction starts from. Its membership path comes with the proofs of the
/// transaction's accounts, so every action spends under one root.
struct Receipt {
    body: MessageBody,
    position: u64,
    rho: Option<[u8; 32]>,
    commitment: Commitment,
}

pub struct WalletCore {
    config_path: PathBuf,
    config_overrides: Option<WalletConfigOverrides>,
    config: WalletConfig,

    storage: Storage,
    storage_path: PathBuf,
    spent_nullifiers: SpentNullifiers,

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
        let spent_nullifiers = SpentNullifiers::open(storage_path.with_extension("nullifiers"))?;

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
            spent_nullifiers,
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

        Some(match entry.kind {
            lee_core::PrivateAccountKind::Pda {
                account_id: authority,
                seed,
            } => AccountIdentity::PrivatePdaShared {
                authority,
                seed,
                nsk: keys.nullifier_secret_key(),
                vpk,
            },
            lee_core::PrivateAccountKind::Regular => AccountIdentity::PrivateShared {
                ask: keys.authorization_secret_key,
                vpk,
            },
        })
    }

    /// Remove a group key holder from storage. Returns the removed holder if it existed.
    pub fn remove_group_key_holder(
        &mut self,
        name: &Label,
    ) -> Option<key_protocol::key_management::group_key_holder::GroupKeyHolder> {
        self.storage.key_chain_mut().remove_group_key_holder(name)
    }

    /// Records an account through `record`, at the state it has reached: the history from genesis
    /// to the chain's current tip, and at least to the last synced block, is scanned for its
    /// initialization's nullifier, and the nullifier pass decodes the init and every subsequent
    /// update. Nothing is recorded unless the scan covers every block and the record is saved.
    async fn record_caught_up(
        &mut self,
        record: impl FnOnce(&mut UserKeyChain) -> Result<()>,
        account_id: AccountId,
        nsk: &lee_core::NullifierSecretKey,
    ) -> Result<(), ExecutionFailureKind> {
        let tip = self
            .get_last_block_id()
            .await
            .map_err(ExecutionFailureKind::SequencerError)?
            .max(self.storage.last_synced_block());
        log::info!("Scanning account {account_id:#?} from genesis to block {tip}");
        let poller = self.poller_helm();
        let unrecorded = self.storage.key_chain().clone();
        self.storage
            .key_chain_mut()
            .record_caught_up(
                record,
                account_id,
                nsk,
                tip,
                poller.poll_block_range(1..=tip),
            )
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;
        self.store_persistent_data().map_err(|err| {
            *self.storage.key_chain_mut() = unrecorded;
            ExecutionFailureKind::StorageError(err)
        })
    }

    /// Create a shared PDA account from a group's GMS. Returns the `AccountId` and derived keys.
    pub async fn create_shared_pda_account(
        &mut self,
        group_name: Label,
        pda_seed: lee_core::program::PdaSeed,
        program_id: lee_core::program::ProgramId,
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
        );

        let entry = SharedAccountEntry {
            group_label: group_name,
            derivation: SharedAccountDerivation::Pda {
                seed: pda_seed,
                program_id,
            },
            kind: lee_core::PrivateAccountKind::Pda {
                account_id: AccountId::from_builtin_program(program_id),
                seed: pda_seed,
            },
            account: Account::default(),
        };
        self.record_caught_up(
            |key_chain| {
                key_chain.insert_shared_private_account(account_id, entry);
                Ok(())
            },
            account_id,
            &keys.nullifier_secret_key(),
        )
        .await?;

        Ok(SharedAccountInfo {
            account_id,
            npk,
            vpk,
        })
    }

    /// Create a shared regular private account from a group's GMS under the given wallet-local
    /// `derivation_id`.
    pub async fn create_shared_regular_account(
        &mut self,
        group_name: Label,
        derivation_id: [u8; 32],
    ) -> Result<SharedAccountInfo> {
        let holder = self
            .storage
            .key_chain()
            .group_key_holder(&group_name)
            .context(format!("Group '{group_name}' not found"))?;

        let keys = holder.derive_regular_shared_account_keys(&derivation_id);
        let npk = keys.generate_nullifier_public_key();
        let vpk = keys.generate_viewing_public_key();
        let account_id = AccountId::from((&npk, &vpk));

        let entry = SharedAccountEntry {
            group_label: group_name,
            derivation: SharedAccountDerivation::Regular { derivation_id },
            kind: lee_core::PrivateAccountKind::Regular,
            account: Account::default(),
        };
        self.record_caught_up(
            |key_chain| {
                key_chain.insert_shared_private_account(account_id, entry);
                Ok(())
            },
            account_id,
            &keys.nullifier_secret_key(),
        )
        .await?;

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

    /// Returns the account's nonce and the selected actor state; its balance is the actor state at
    /// the native token program.
    pub async fn get_account_view(&self, actor_state_selector: Actor) -> Result<Option<Account>> {
        // RPC projections include empty actor states; the wallet omits them.
        Ok(self
            .multi_sequencer_client
            .metered_get(async |client: &SequencerClient| {
                client.get_account_view(actor_state_selector).await
            })
            .await?
            .map(|mut account| {
                account
                    .data
                    .actor_states
                    .retain(|_, actor_state| !actor_state.is_empty());
                account
            }))
    }

    pub async fn get_publications(
        &self,
        from_position: u64,
        limit: u32,
    ) -> Result<Vec<(u64, Publication)>> {
        Ok(self
            .multi_sequencer_client
            .metered_get(async |client: &SequencerClient| {
                client.get_publications(from_position, limit).await
            })
            .await?)
    }

    // Messages that one of this wallet's key pairs opens: a private address's recovery note, or a
    // sealed message.
    pub async fn owned_pending_messages(&mut self) -> Result<Vec<PendingMessage>> {
        const PAGE: u32 = 256;
        self.sync_to_latest_block().await?;
        let mut records = Vec::new();
        let mut from_position = 0;
        loop {
            let page = self.get_publications(from_position, PAGE).await?;
            let Some((last, _)) = page.last() else {
                return Ok(records);
            };
            from_position = last.saturating_add(1);
            records.extend(
                self.unreceived(
                    page.into_iter()
                        .filter_map(|(position, publication)| self.read(position, publication)),
                ),
            );
        }
    }

    // The body, recipient, sealed record's commitment randomness and nullifier key of a
    // publication one of this wallet's key pairs opens.
    fn private_receipt(
        &self,
        publication: &Publication,
    ) -> Option<(MessageBody, Recipient, Option<[u8; 32]>, NullifierSecretKey)> {
        match publication {
            Publication::Clear { body, recovery } => {
                let (recipient, nsk) = self
                    .storage
                    .key_chain()
                    .recover(body.to.account_id, recovery)?;
                Some((body.clone(), recipient, None, nsk))
            }
            Publication::Sealed(sealed) => {
                let (body, recipient, rho, nsk) = self.storage.key_chain().open(sealed)?;
                Some((body, recipient, Some(rho), nsk))
            }
        }
    }

    fn read(&self, position: u64, publication: Publication) -> Option<(PendingMessage, Nullifier)> {
        let (body, recipient, _, nsk) = self.private_receipt(&publication)?;
        let receipt = Nullifier::for_message(&nsk, &publication.commitment(), position);
        Some((
            PendingMessage {
                position,
                publication,
                body,
                recipient,
            },
            receipt,
        ))
    }

    pub async fn find_pending_message(&mut self, position: u64) -> Result<Option<PendingMessage>> {
        self.sync_to_latest_block().await?;
        let found = self
            .get_publications(position, 1)
            .await?
            .into_iter()
            .filter(|(found, _)| *found == position)
            .filter_map(|(found, publication)| self.read(found, publication));
        Ok(self.unreceived(found).last())
    }

    // Drops the records whose receipt this wallet sees spent.
    fn unreceived(
        &self,
        records: impl IntoIterator<Item = (PendingMessage, Nullifier)>,
    ) -> impl Iterator<Item = PendingMessage> {
        records
            .into_iter()
            .filter(|(_, receipt)| !self.spent_nullifiers.contains(receipt))
            .map(|(pending, _)| pending)
    }

    pub async fn get_account(&self, account_id: AccountIdWithPrivacy) -> Result<Account> {
        match account_id {
            AccountIdWithPrivacy::Public(acc_id) => {
                Ok(self.get_account_public(acc_id).await?.unwrap_or_default())
            }
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
    pub async fn get_account_public(&self, account_id: AccountId) -> Result<Option<Account>> {
        Ok(self
            .multi_sequencer_client
            .metered_get(async |client: &SequencerClient| client.get_account(account_id).await)
            .await?)
    }

    pub async fn get_recovery_binding(&self, address: AccountId) -> Result<Option<EncryptedNote>> {
        Ok(self
            .multi_sequencer_client
            .metered_get(async |client: &SequencerClient| {
                client.get_recovery_binding(address).await
            })
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
        self.private_account_state(account_id).cloned()
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
        message_position: Option<u64>,
    ) -> Result<(
        Vec<Option<MembershipProof>>,
        Option<MembershipProof>,
        CommitmentSetDigest,
    )> {
        Ok(self
            .multi_sequencer_client
            .metered_get(async |client: &SequencerClient| {
                client
                    .get_proofs_and_root(commitments.to_vec(), message_position)
                    .await
            })
            .await?)
    }

    pub(crate) async fn await_inclusion(
        &self,
        tx_hash: HashType,
    ) -> Result<(LeeTransaction, BlockId)> {
        println!("Transaction hash is {tx_hash}");
        let (tx, block_id) = self.poll_transaction(tx_hash).await?;
        println!("Transaction is included in block {block_id}");
        if std::env::var_os(SUPPRESS_VERBOSE_PRINTS).is_none() {
            println!("Transaction data is {tx:?}");
        }
        Ok((tx, block_id))
    }

    // The included transaction updates the recorded accounts whose current nullifier it spends;
    // the sync cursor stays where it was.
    pub(crate) async fn finish_transaction(
        &mut self,
        tx_hash: HashType,
    ) -> Result<cli::SubcommandReturnValue> {
        let (tx, block_id) = self.await_inclusion(tx_hash).await?;
        if let LeeTransaction::PrivacyPreserving(tx) = tx {
            let key_chain = self.storage.key_chain_mut();
            let mut index = key_chain.build_latest_nullifier_index();
            key_chain.sync_updates_via_nullifiers(&tx.message, &mut index);
        }
        self.store_persistent_data().with_context(|| {
            format!("Transaction {tx_hash} is included in block {block_id}, but storing the wallet failed")
        })?;
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

    pub async fn send_tx(
        &self,
        accounts: Vec<AccountMention>,
        root: usize,
        message: MessageData,
        programs: &ProgramCatalog,
        cross_messages: Option<PredictedCrossMessages>,
        casts: CastDelivery,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        self.send_tx_with_pre_check(
            accounts,
            root,
            message,
            programs,
            cross_messages,
            casts,
            |_| Ok(()),
        )
        .await
    }

    // Public when every account is, no recovery binding is new and no candidate is selected,
    // privacy-preserving otherwise. A proof derives its boundary from current public state unless
    // `cross_messages` gives a conditional promise that settlement checks against live execution.
    #[expect(
        clippy::too_many_arguments,
        reason = "send_tx's arguments and the check of the accounts it reads"
    )]
    pub async fn send_tx_with_pre_check(
        &self,
        accounts: Vec<AccountMention>,
        root: usize,
        message: MessageData,
        programs: &ProgramCatalog,
        cross_messages: Option<PredictedCrossMessages>,
        casts: CastDelivery,
        tx_pre_check: impl FnOnce(&[SelectedActorState]) -> Result<(), ExecutionFailureKind>,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let to = root_actor(&accounts, root)?;
        let casts = CastDelivery {
            recoveries: self.unbound(casts.recoveries).await?,
            ..casts
        };
        if casts.recoveries.is_empty()
            && casts.seals.is_empty()
            && casts.promotions.public.is_empty()
            && casts.promotions.private.is_empty()
            && !accounts.iter().any(|mention| mention.identity.is_private())
        {
            self.send_public(accounts, to, message, None, tx_pre_check)
                .await
                .map(|tx_hash| (tx_hash, Vec::new()))
        } else {
            self.send_proven(
                accounts,
                TransactionEntry::Call(RootCall { to, message }),
                casts,
                programs,
                cross_messages,
                tx_pre_check,
            )
            .await
        }
    }

    // A binding already on chain is reused: settlement attaches it to every publication.
    async fn unbound(
        &self,
        recoveries: Vec<RecipientEncryption>,
    ) -> Result<Vec<RecipientEncryption>, ExecutionFailureKind> {
        let mut unbound: Vec<RecipientEncryption> = Vec::new();
        for recovery in recoveries {
            let address = recovery.recipient.address();
            let bound = self
                .get_recovery_binding(address)
                .await
                .map_err(ExecutionFailureKind::SequencerError)?;
            if bound.is_none()
                && !unbound
                    .iter()
                    .any(|kept| kept.recipient.address() == address)
            {
                unbound.push(recovery);
            }
        }
        Ok(unbound)
    }

    // What settlement needs for a Cast to `destination`: a public account to execute it, declared,
    // or a private account's recovery binding to publish it.
    pub fn cast_destination(
        &self,
        destination: AccountMention,
    ) -> Result<(Option<AccountMention>, CastDelivery), ExecutionFailureKind> {
        if destination.identity.is_public() {
            return Ok((
                Some(AccountMention {
                    identity: destination.identity.without_signing(),
                    ..destination
                }),
                CastDelivery::default(),
            ));
        }
        let recipient = account_manager::recipient(self, &destination.identity)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
        Ok((
            None,
            CastDelivery {
                recoveries: vec![RecipientEncryption {
                    recipient,
                    esk: EphemeralSecretKey(account_manager::random_bytes()),
                }],
                ..CastDelivery::default()
            },
        ))
    }

    // A Cast that private execution sends to `destination`: a private destination's recipient
    // material seals it, and no recovery binding publishes the destination.
    pub fn seal_destination(
        &self,
        destination: AccountMention,
    ) -> Result<(Option<AccountMention>, CastDelivery), ExecutionFailureKind> {
        if destination.identity.public_account_id().is_some() {
            return self.cast_destination(destination);
        }
        let recipient = account_manager::recipient(self, &destination.identity)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
        Ok((
            None,
            CastDelivery {
                seals: vec![recipient],
                ..CastDelivery::default()
            },
        ))
    }

    pub async fn send_privacy_preserving_tx_with_pre_check(
        &self,
        accounts: Vec<AccountMention>,
        root: usize,
        message: MessageData,
        programs: &ProgramCatalog,
        tx_pre_check: impl FnOnce(&[SelectedActorState]) -> Result<(), ExecutionFailureKind>,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let root = TransactionEntry::Call(RootCall {
            to: root_actor(&accounts, root)?,
            message,
        });
        self.send_proven(
            accounts,
            root,
            CastDelivery::default(),
            programs,
            None,
            tx_pre_check,
        )
        .await
    }

    async fn send_proven(
        &self,
        accounts: Vec<AccountMention>,
        root: TransactionEntry<Receipt>,
        casts: CastDelivery,
        programs: &ProgramCatalog,
        cross_messages: Option<PredictedCrossMessages>,
        tx_pre_check: impl FnOnce(&[SelectedActorState]) -> Result<(), ExecutionFailureKind>,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let CastDelivery {
            recoveries,
            seals,
            promotions:
                CastPromotions {
                    public,
                    private,
                    listed_only,
                },
        } = casts;
        let message = match &root {
            TransactionEntry::Cast(receipt) => Some((receipt.position, receipt.commitment)),
            TransactionEntry::Call(_) => None,
        };
        let acc_manager = account_manager::AccountManager::new(self, accounts, message).await?;

        tx_pre_check(&acc_manager.selected_actor_states())?;

        for account_id in acc_manager.accounts_outgrowing_pad() {
            warn!(
                "Account {account_id} exceeds the {CIPHERTEXT_PAD_SIZE}-byte note pad; its note is \
                 identifiable by length in this transaction"
            );
        }

        let shared_secrets = acc_manager.shared_secrets();
        let input = ProvingInput {
            root: root.map(
                |Receipt {
                     body,
                     position,
                     rho,
                     ..
                 }| MessageWitness {
                    body,
                    position,
                    rho,
                    path: acc_manager
                        .message_path()
                        .expect("a received message's path is fetched with its accounts")
                        .1
                        .clone(),
                    filler: account_manager::dummy_output(),
                },
            ),
            context: PublicExecutionContext {
                cast_promotions: public,
                ..PublicExecutionContext::new(acc_manager.public_actors(), acc_manager.signers())
            },
            private_witnesses: acc_manager.private_witnesses()?,
            dummy_inputs: acc_manager.dummy_inputs_default(),
            ciphertext_padding: Some(CIPHERTEXT_PAD_SIZE),
            recoveries,
            private_cast_promotions: private,
        };
        let witnessed: HashSet<AccountId> = input
            .private_witnesses
            .iter()
            .flat_map(|witness| {
                let account_id = witness.account_id();
                std::iter::once(account_id).chain(
                    witness
                        .openings
                        .iter()
                        .map(move |opening| account_id.blinded(opening)),
                )
            })
            .collect();
        let select =
            move |_, body: &MessageBody| !listed_only && witnessed.contains(&body.to.account_id);
        let choose_seal = move |body: &MessageBody| {
            let to = body.to.account_id;
            seals
                .iter()
                .find(|recipient| recipient.address() == to)
                .map(|recipient| RecipientEncryption {
                    recipient: recipient.clone(),
                    esk: EphemeralSecretKey(account_manager::random_bytes()),
                })
                .ok_or_else(|| {
                    lee::error::LeeError::InvalidInput(format!(
                        "No recipient material seals a Cast to {to}"
                    ))
                })
        };

        let programs = programs.clone();
        let present = acc_manager.presenter();
        let (output, proof) = match cross_messages {
            None => {
                let simulation = Simulation {
                    public_actor_states: acc_manager.public_actor_states(),
                    admitted_accounts: Some(acc_manager.admitted_accounts()),
                };
                tokio::task::spawn_blocking(move || {
                    lee::execute_and_prove(
                        input,
                        &simulation,
                        &programs,
                        present,
                        select,
                        choose_seal,
                    )
                })
            }
            Some(cross_messages) => tokio::task::spawn_blocking(move || {
                lee::execute_and_prove_with_cross_messages(
                    input,
                    cross_messages,
                    &programs,
                    present,
                    select,
                    choose_seal,
                )
            }),
        }
        .await??;

        let message = Message {
            admission_evidence: acc_manager.admission_evidence(),
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
        tx_pre_check: impl FnOnce(&[SelectedActorState]) -> Result<(), ExecutionFailureKind>,
    ) -> Result<HashType, ExecutionFailureKind> {
        let to = root_actor(&accounts, root)?;
        self.send_public(accounts, to, message, payer, tx_pre_check)
            .await
    }

    async fn send_public(
        &self,
        accounts: Vec<AccountMention>,
        to: Actor,
        message: MessageData,
        payer: Option<AccountId>,
        tx_pre_check: impl FnOnce(&[SelectedActorState]) -> Result<(), ExecutionFailureKind>,
    ) -> Result<HashType, ExecutionFailureKind> {
        // Public transaction, all accounts must be public
        if accounts.iter().any(|mention| mention.identity.is_private()) {
            return Err(ExecutionFailureKind::TransactionBuildError(
                lee::error::LeeError::InvalidInput(
                    "Private accounts are not allowed in public transactions".to_owned(),
                ),
            ));
        }

        let mut acc_manager = account_manager::AccountManager::new(self, accounts, None).await?;

        tx_pre_check(&acc_manager.selected_actor_states())?;

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
                    .map_err(ExecutionFailureKind::SequencerError)?
                    .unwrap_or_default();
                nonces.insert(payer, account.nonce);
                (payer, Some(key))
            }
        };

        let message = lee::public_transaction::Message::new(
            to,
            message,
            public_actors,
            nonces,
            Some(lee::FeeDeclaration::new(
                payer,
                self.config.gas_limit,
                0,
                max_fee_for(self.config.gas_limit),
            )),
            acc_manager.admission_evidence(),
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
        &mut self,
        PendingMessage {
            position,
            publication,
            ..
        }: PendingMessage,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let Some((body, recipient, rho, nsk)) = self.private_receipt(&publication) else {
            return Err(ExecutionFailureKind::TransactionBuildError(
                lee::error::LeeError::InvalidInput(format!(
                    "No key pair of this wallet opens the message published at {position}"
                )),
            ));
        };
        check_receivable(&body)?;
        let to = body.to;
        let programs = receipt_programs(to.program_account_id);
        let account_id = recipient.account_id();
        if self.resolve_private_account(account_id).is_none() {
            self.record_caught_up(
                |key_chain| key_chain.record_received(&recipient),
                account_id,
                &nsk,
            )
            .await?;
        }
        let identity = self
            .resolve_private_account(account_id)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
        let accounts = vec![AccountMention {
            openings: recipient.opening.into_iter().collect(),
            ..identity
                .select_program_actor_state(to.program_account_id)
                .without_authorization()
        }];
        let receipt = Receipt {
            body,
            position,
            rho,
            commitment: publication.commitment(),
        };
        self.send_proven(
            accounts,
            TransactionEntry::Cast(receipt),
            CastDelivery::default(),
            &programs,
            None,
            |_| Ok(()),
        )
        .await
    }

    pub async fn sync_to_latest_block(&mut self) -> Result<u64> {
        let latest_block_id = self.get_last_block_id().await?;
        println!("Latest block is {latest_block_id}");
        self.sync_to_block(latest_block_id).await?;
        Ok(latest_block_id)
    }

    pub async fn sync_to_block(&mut self, block_id: u64) -> Result<()> {
        self.sync(block_id, false).await
    }

    /// Syncs to the latest block like [`Self::sync_to_latest_block`], also trial-decrypting with
    /// every owned key pair each note no followed nullifier claims. Restoration needs this for the
    /// private PDAs under its keys, which no record names.
    pub async fn restore_to_latest_block(&mut self) -> Result<()> {
        let latest_block_id = self.get_last_block_id().await?;
        self.sync(latest_block_id, true).await
    }

    pub async fn restore_keys(&mut self, depth: u32) -> Result<()> {
        self.storage.key_chain_mut().generate_trees_for_depth(depth);

        println!(
            "Public tree generated\n\
             Private tree generated"
        );

        self.restore_to_latest_block().await?;

        // A key a pending message names stays, though the account it credits is not initialized
        // yet.
        let awaited = self
            .owned_pending_messages()
            .await?
            .into_iter()
            .map(|pending| {
                lee::AccountId::for_regular_private_account(
                    &pending.recipient.npk,
                    &pending.recipient.vpk,
                )
            })
            .collect();
        let leader_client = self.helm_owned();

        self.storage
            .key_chain_mut()
            .cleanup_trees_remove_uninit_layered(
                depth,
                |account_id| {
                    leader_client
                        .get_account(account_id)
                        .map_ok(Option::unwrap_or_default)
                        .map_err(Into::into)
                },
                &awaited,
            )
            .await?;

        println!(
            "Public tree cleaned up\n\
             Private tree cleaned up"
        );

        self.store_persistent_data()?;

        Ok(())
    }

    async fn sync(&mut self, block_id: u64, discover: bool) -> Result<()> {
        use futures::TryStreamExt as _;

        // The cursor and the spent-nullifier cache claim the same blocks.
        let cursor = self.storage.last_synced_block();
        self.spent_nullifiers.keep(cursor)?;
        self.storage
            .set_last_synced_block(cursor.min(self.spent_nullifiers.covered()));
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

        // Watch every recorded account, initialized or not, for its next transition's nullifier.
        let mut index = self.storage.key_chain().build_latest_nullifier_index();
        let bar = indicatif::ProgressBar::new(num_of_blocks);
        let mut expected = last_synced_block.saturating_add(1)..=block_id;
        while let Some(block) = blocks.try_next().await? {
            ensure!(
                expected.next() == Some(block.header.block_id),
                "History reaches block {} out of sequence",
                block.header.block_id
            );
            let mut spent = Vec::new();
            for tx in block.body.transactions {
                let LeeTransaction::PrivacyPreserving(pp_tx) = &tx else {
                    continue;
                };
                spent.extend(
                    pp_tx
                        .message
                        .execution
                        .private_actions
                        .iter()
                        .map(|action| action.nullifier),
                );
                let key_chain = self.storage.key_chain_mut();
                let followed = key_chain.sync_updates_via_nullifiers(&pp_tx.message, &mut index);
                if discover {
                    key_chain.discover_unfollowed(&pp_tx.message, &followed, &mut index);
                }
            }

            self.spent_nullifiers.append(spent)?;
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

/// The programs a receipt of a message for `program` runs: none for the native program, which runs
/// as protocol code, and the token program for a token credit or holding. [`check_receivable`]
/// admits no other.
fn receipt_programs(program: AccountId) -> ProgramCatalog {
    if program == NATIVE_TOKEN_PROGRAM_ID {
        ProgramCatalog::default()
    } else {
        ProgramCatalog::from([(program, programs::token())])
    }
}

fn check_receivable(body: &MessageBody) -> Result<(), ExecutionFailureKind> {
    let token = programs::token_account_id();
    let source = body.from.program_account_id;
    let receivable = if body.to.program_account_id == token && source == token {
        let message = borsh::from_slice::<token_core::Message>(&body.message);
        matches!(
            message,
            Ok(token_core::Message::Credit { notify: None, .. })
        ) || matches!(&message, Ok(token_core::Message::Create(state))
                if token_core::TokenHolding::try_from(state).is_ok())
    } else {
        body.to.program_account_id == NATIVE_TOKEN_PROGRAM_ID
            && source == NATIVE_TOKEN_PROGRAM_ID
            && matches!(
                borsh::from_slice::<native_token::Message>(&body.message),
                Ok(native_token::Message::Credit(_))
            )
    };
    if receivable {
        Ok(())
    } else {
        Err(ExecutionFailureKind::TransactionBuildError(
            lee::error::LeeError::InvalidInput(
                "This wallet only receives native credits, token credits without a notification \
                 and new token holdings"
                    .to_owned(),
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::CString,
        str::FromStr as _,
        sync::{Arc, Mutex},
    };

    use bip39::Mnemonic;
    use common::{block::Block, test_utils::produce_dummy_block, transaction::LeeTransaction};
    use jsonrpsee::{
        RpcModule,
        server::{Server, ServerHandle},
        types::ErrorObjectOwned,
    };
    use lee::AccountId;
    use lee_core::{
        EncryptedNote, EphemeralSecretKey, Nullifier, PrivateAccountKind, Recipient,
        RecipientEncryption, RecoveryBinding,
        account::{Account, Actor, ActorState},
        program::{MessageBody, PdaSeed, Publication},
    };
    use sequencer_stake_core::{SequencerKey, StakeRecord, ed25519_dalek::SigningKey};
    use token_core::{
        Message, MetadataStandard, Notify, TokenDescriptor, TokenHolding, TokenKind, TokenMetadata,
    };

    use super::{
        AccountIdentity, ExecutionFailureKind, NATIVE_TOKEN_PROGRAM_ID, PendingMessage, WalletCore,
        check_receivable, native_token,
    };
    use crate::{
        cli::SubcommandReturnValue,
        config::{SequencerConnectionData, WalletConfig},
        program_facades::{CreditDelivery, credit_destination, sequencer_stake::SequencerStake},
        storage::{
            Storage,
            key_chain::tests::{block_of, transition_message},
        },
    };

    const DESCRIPTOR: TokenDescriptor = TokenDescriptor {
        definition_id: AccountId::new([2; 32]),
        kind: TokenKind::Fungible,
    };

    #[derive(Default)]
    struct Served {
        blocks: Vec<Block>,
        publications: Vec<(u64, Publication)>,
    }

    fn body(
        source_program: AccountId,
        to_program: AccountId,
        message: &impl borsh::BorshSerialize,
    ) -> MessageBody {
        MessageBody {
            from: Actor::new(AccountId::new([7; 32]), source_program),
            to: Actor::new(AccountId::new([1; 32]), to_program),
            message: borsh::to_vec(message).unwrap(),
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
        assert!(check_receivable(&body(token, token, &credit(None))).is_ok());
    }

    #[test]
    fn a_transfer_a_notifying_credit_and_a_foreign_credit_are_not_receivable() {
        let token = programs::token_account_id();
        let transfer = Message::Transfer {
            to: AccountId::new([3; 32]),
            descriptor: DESCRIPTOR,
            amount: 5,
            notify: None,
        };
        let notifying = credit(Some(Notify {
            to: Actor::new(AccountId::new([4; 32]), AccountId::new([5; 32])),
            payload: Vec::new(),
        }));

        for refused in [
            body(token, token, &transfer),
            body(token, token, &notifying),
            body(AccountId::new([6; 32]), token, &credit(None)),
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
    fn a_token_holding_creation_is_receivable() {
        let token = programs::token_account_id();
        let definition_id = DESCRIPTOR.definition_id;
        for holding in [
            TokenHolding::Fungible {
                definition_id,
                balance: 0,
            },
            TokenHolding::NftMaster {
                definition_id,
                print_balance: 1,
            },
            TokenHolding::NftPrintedCopy {
                definition_id,
                owned: true,
            },
        ] {
            let create = Message::Create(ActorState::from(&holding));
            assert!(
                check_receivable(&body(token, token, &create)).is_ok(),
                "{holding:?} must be receivable"
            );
        }
    }

    #[test]
    fn a_metadata_or_unreadable_creation_and_one_outside_the_token_program_are_not_receivable() {
        let token = programs::token_account_id();
        let holding = Message::Create(ActorState::from(&TokenHolding::Fungible {
            definition_id: DESCRIPTOR.definition_id,
            balance: 0,
        }));
        let metadata = Message::Create(ActorState::from(&TokenMetadata {
            definition_id: DESCRIPTOR.definition_id,
            standard: MetadataStandard::Simple,
            uri: "uri".to_owned(),
            creators: "creators".to_owned(),
            primary_sale_date: 0,
        }));
        let unreadable = Message::Create(ActorState::from(vec![9; 5]));

        for refused in [
            body(token, token, &metadata),
            body(token, token, &unreadable),
            body(AccountId::new([6; 32]), token, &holding),
            body(token, NATIVE_TOKEN_PROGRAM_ID, &holding),
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
        assert!(check_receivable(&body(native, native, &native_token::Message::Credit(5))).is_ok());
    }

    #[test]
    fn native_spending_and_a_foreign_native_credit_are_not_receivable() {
        let native = NATIVE_TOKEN_PROGRAM_ID;
        let to = AccountId::new([3; 32]);
        for refused in [
            body(
                native,
                native,
                &native_token::Message::Transfer { to, amount: 5 },
            ),
            body(
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

    // A wallet in a fresh home whose one sequencer serves `sequencer`.
    async fn served_wallet<Context: Send + Sync + 'static>(
        sequencer: RpcModule<Context>,
    ) -> (WalletCore, tempfile::TempDir, ServerHandle) {
        let server = Server::builder().build("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let handle = server.start(sequencer);
        let home = tempfile::tempdir().unwrap();
        let config_path = home.path().join("wallet_config.json");
        std::fs::write(
            &config_path,
            serde_json::to_vec(&WalletConfig {
                sequencers: vec![SequencerConnectionData {
                    sequencer_addr: format!("http://{address}").parse().unwrap(),
                    basic_auth: None,
                }],
                ..WalletConfig::default()
            })
            .unwrap(),
        )
        .unwrap();
        let (wallet, _) = WalletCore::new_init_storage(
            config_path,
            home.path().join("storage.json"),
            home.path().join("statistics.json"),
            None,
            "password",
        )
        .await
        .unwrap();
        (wallet, home, handle)
    }

    #[tokio::test]
    async fn a_destination_is_recorded_as_of_the_tip_and_saved_before_its_receipt() {
        let history: Arc<Mutex<Vec<Block>>> = Arc::default();
        let mut sequencer = RpcModule::new(Arc::clone(&history));
        sequencer
            .register_method("getLastBlockId", |_, _, _| Ok::<_, ErrorObjectOwned>(2_u64))
            .unwrap();
        sequencer
            .register_method("getBlockRange", |params, history, _| {
                let (start, end) = params.parse::<(u64, u64)>()?;
                Ok::<_, ErrorObjectOwned>(
                    history
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|block| (start..=end).contains(&block.header.block_id))
                        .cloned()
                        .collect::<Vec<_>>(),
                )
            })
            .unwrap();
        let (mut wallet, home, _sequencer) = served_wallet(sequencer).await;
        let storage_path = wallet.storage_path.clone();
        // Synced to block 1; the destination is initialized in block 2, past the cursor.
        wallet.storage.set_last_synced_block(1);
        let (_, chain_index) = wallet
            .storage
            .key_chain_mut()
            .generate_new_privacy_preserving_transaction_key_chain(None);
        let key_chain = wallet
            .storage
            .key_chain()
            .private_account_key_chain_by_index(&chain_index)
            .unwrap()
            .clone();
        let nsk = key_chain.private_key_holder.nullifier_secret_key();
        let recipient = Recipient {
            npk: key_chain.nullifier_public_key,
            vpk: key_chain.viewing_public_key.clone(),
            kind: PrivateAccountKind::Pda {
                account_id: AccountId::new([4; 32]),
                seed: PdaSeed::new([5; 32]),
            },
            opening: None,
        };
        let pda_id = recipient.account_id();
        let initialized = Account::funded(70);
        let initialization = transition_message(
            pda_id,
            &recipient.kind,
            &recipient.vpk,
            Nullifier::for_account_initialization(&pda_id, &nsk),
            &initialized,
        );
        *history.lock().unwrap() = vec![
            produce_dummy_block(1, None, Vec::new()),
            block_of(2, initialization),
        ];
        wallet.storage_path = home.path().join("missing").join("storage.json");

        assert!(matches!(
            wallet
                .record_caught_up(
                    |key_chain| key_chain.record_received(&recipient),
                    pda_id,
                    &nsk,
                )
                .await,
            Err(ExecutionFailureKind::StorageError(_))
        ));
        assert!(wallet.resolve_private_account(pda_id).is_none());

        wallet.storage_path = storage_path.clone();
        wallet
            .record_caught_up(
                |key_chain| key_chain.record_received(&recipient),
                pda_id,
                &nsk,
            )
            .await
            .unwrap();

        for key_chain in [
            wallet.storage.key_chain(),
            Storage::from_path(&storage_path).unwrap().key_chain(),
        ] {
            assert_eq!(
                key_chain.private_account(pda_id).unwrap().account,
                &initialized
            );
        }
    }

    #[tokio::test]
    async fn completion_applies_the_included_transaction_without_moving_the_cursor() {
        let included: Arc<Mutex<Option<LeeTransaction>>> = Arc::default();
        let mut sequencer = RpcModule::new(Arc::clone(&included));
        sequencer
            .register_method("getLastBlockId", |_, _, _| Ok::<_, ErrorObjectOwned>(2_u64))
            .unwrap();
        sequencer
            .register_method("getTransaction", |_, included, _| {
                Ok::<_, ErrorObjectOwned>(included.lock().unwrap().clone().map(|tx| (tx, 2_u64)))
            })
            .unwrap();
        let (mut wallet, _home, _sequencer) = served_wallet(sequencer).await;
        wallet.storage.set_last_synced_block(1);
        let (account_id, chain_index) = wallet
            .storage
            .key_chain_mut()
            .generate_new_privacy_preserving_transaction_key_chain(None);
        let key_chain = wallet
            .storage
            .key_chain()
            .private_account_key_chain_by_index(&chain_index)
            .unwrap()
            .clone();
        let initialized = Account::funded(1);
        let tx = block_of(
            2,
            transition_message(
                account_id,
                &PrivateAccountKind::Regular,
                &key_chain.viewing_public_key,
                Nullifier::for_account_initialization(
                    &account_id,
                    &key_chain.private_key_holder.nullifier_secret_key(),
                ),
                &initialized,
            ),
        )
        .body
        .transactions
        .into_iter()
        .next()
        .unwrap();
        let tx_hash = tx.hash();
        *included.lock().unwrap() = Some(tx);

        assert!(matches!(
            wallet.finish_transaction(tx_hash).await.unwrap(),
            SubcommandReturnValue::TransactionExecuted { tx_hash: executed } if executed == tx_hash
        ));
        assert_eq!(wallet.storage.last_synced_block(), 1);
        for storage in [
            &wallet.storage,
            &Storage::from_path(&wallet.storage_path).unwrap(),
        ] {
            assert_eq!(
                storage
                    .key_chain()
                    .private_account(account_id)
                    .unwrap()
                    .account,
                &initialized
            );
        }

        // Completing it again leaves the newer state the account has moved on to.
        let newer = Account::funded(2);
        wallet
            .storage
            .key_chain_mut()
            .insert_private_account(account_id, PrivateAccountKind::Regular, newer.clone())
            .unwrap();
        wallet.finish_transaction(tx_hash).await.unwrap();
        assert_eq!(
            wallet
                .storage
                .key_chain()
                .private_account(account_id)
                .unwrap()
                .account,
            &newer
        );
    }

    #[tokio::test]
    async fn a_credit_takes_part_at_once_only_for_a_controlled_recipient_it_does_not_defer() {
        let mut sequencer = RpcModule::new(());
        sequencer
            .register_method("getLastBlockId", |_, (), _| {
                Ok::<_, ErrorObjectOwned>(1_u64)
            })
            .unwrap();
        let (mut wallet, _home, _sequencer) = served_wallet(sequencer).await;
        let key_chain = wallet.storage.key_chain_mut();
        let (sender_id, _) = key_chain.generate_new_privacy_preserving_transaction_key_chain(None);
        let (recipient_id, recipient_index) =
            key_chain.generate_new_privacy_preserving_transaction_key_chain(None);
        let recipient_keys = key_chain
            .private_account_key_chain_by_index(&recipient_index)
            .unwrap()
            .clone();
        let (sender, recipient) = (
            AccountIdentity::PrivateOwned(sender_id),
            AccountIdentity::PrivateOwned(recipient_id),
        );
        let public = AccountIdentity::Public(AccountId::new([1; 32]));
        let recipient_material = Recipient {
            npk: recipient_keys.nullifier_public_key,
            vpk: recipient_keys.viewing_public_key,
            kind: PrivateAccountKind::Regular,
            opening: None,
        };
        let route = |sender: &AccountIdentity, recipient: AccountIdentity, delivery| {
            credit_destination(
                &wallet,
                sender,
                recipient,
                NATIVE_TOKEN_PROGRAM_ID,
                delivery,
            )
            .unwrap()
        };

        // A controlled recipient takes part, without spending authority.
        let (declared, casts) = route(&public, recipient.clone(), CreditDelivery::Automatic);
        let declared = declared.unwrap();
        assert!(declared.identity == recipient && !declared.authorizes);
        assert!(casts.seals.is_empty() && casts.recoveries.is_empty());

        // Deferred, its credit is sealed and stays pending even where the account takes part.
        let (declared, casts) = route(&sender, recipient, CreditDelivery::DeferredPrivate);
        assert!(declared.is_none() && casts.promotions.listed_only);
        assert_eq!(casts.seals, std::slice::from_ref(&recipient_material));

        // A recipient named by its keys stays pending, even when they are this wallet's.
        let (declared, casts) = route(
            &public,
            AccountIdentity::PrivateForeign {
                npk: recipient_material.npk,
                vpk: recipient_material.vpk.clone(),
                kind: PrivateAccountKind::Regular,
            },
            CreditDelivery::Automatic,
        );
        assert!(declared.is_none() && casts.promotions.listed_only);
        assert_eq!(casts.recoveries.len(), 1);
        assert_eq!(casts.recoveries[0].recipient, recipient_material);

        // A public recipient takes part either way, as the caller named it.
        let (declared, _) = route(&sender, public.clone(), CreditDelivery::DeferredPrivate);
        let declared = declared.unwrap();
        assert!(declared.identity == public && declared.authorizes);

        // A sender crediting itself takes part once.
        let (declared, _) = route(&sender, sender.clone(), CreditDelivery::Automatic);
        assert!(declared.is_none());
    }

    #[tokio::test]
    async fn an_unstake_request_is_refused_before_submission_only_for_an_unpayable_destination() {
        let owner_key = lee::PrivateKey::try_new([3; 32]).unwrap();
        let ownership = AccountId::from(&lee::PublicKey::new_from_private_key(&owner_key));
        let public = AccountId::new([7; 32]);
        let bound = AccountId::new([8; 32]);
        let absent = AccountId::new([9; 32]);
        let sequencer_key =
            SequencerKey::new(SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes()).unwrap();
        let staked = Account::default().with_actor_state(
            programs::sequencer_stake_account_id(),
            ActorState::from(StakeRecord { sequencer_key }.to_bytes()),
        );
        let submitted: Arc<Mutex<Vec<LeeTransaction>>> = Arc::default();
        let mut sequencer = RpcModule::new(Arc::clone(&submitted));
        sequencer
            .register_method("getLastBlockId", |_, _, _| Ok::<_, ErrorObjectOwned>(2_u64))
            .unwrap();
        sequencer
            .register_method("getAccount", move |params, _, _| {
                let account_id = params.one::<AccountId>()?;
                Ok::<_, ErrorObjectOwned>((account_id == public).then(Account::default))
            })
            .unwrap();
        sequencer
            .register_method("getRecoveryBinding", move |params, _, _| {
                let address = params.one::<AccountId>()?;
                Ok::<_, ErrorObjectOwned>((address == bound).then(EncryptedNote::default))
            })
            .unwrap();
        sequencer
            .register_method("getAccountView", move |params, _, _| {
                let actor = params.one::<Actor>()?;
                Ok::<_, ErrorObjectOwned>((actor.account_id == ownership).then(|| staked.clone()))
            })
            .unwrap();
        sequencer
            .register_method("getProofsAndRoot", |_, _, _| {
                Ok::<_, ErrorObjectOwned>((
                    Vec::<Option<lee_core::MembershipProof>>::new(),
                    None::<lee_core::MembershipProof>,
                    [0_u8; 32],
                ))
            })
            .unwrap();
        sequencer
            .register_method("sendTransaction", |params, submitted, _| {
                let tx = params.one::<LeeTransaction>()?;
                let hash = tx.hash();
                submitted.lock().unwrap().push(tx);
                Ok::<_, ErrorObjectOwned>(hash)
            })
            .unwrap();
        let (mut wallet, _home, _sequencer) = served_wallet(sequencer).await;
        wallet
            .storage
            .key_chain_mut()
            .add_imported_public_account(owner_key);

        for destination in [public, bound] {
            SequencerStake(&wallet)
                .send_unstake_request(ownership, 5, destination)
                .await
                .unwrap();
            let Some(LeeTransaction::Public(tx)) = submitted.lock().unwrap().pop() else {
                panic!("the request to {destination} should have been submitted publicly");
            };
            assert!(matches!(
                borsh::from_slice(&tx.message.execution.root.message),
                Ok(sequencer_stake_core::Message::UnstakeRequest { destination: requested, .. })
                    if requested == destination
            ));
        }

        assert!(matches!(
            SequencerStake(&wallet)
                .send_unstake_request(ownership, 5, absent)
                .await,
            Err(ExecutionFailureKind::TransactionBuildError(
                lee::error::LeeError::InvalidInput(message)
            )) if message.contains("FinalizeUnstake cannot pay")
        ));
        assert!(submitted.lock().unwrap().is_empty());
    }

    async fn wallet_with_a_received_message() -> (
        WalletCore,
        tempfile::TempDir,
        ServerHandle,
        Arc<Mutex<Served>>,
    ) {
        let served: Arc<Mutex<Served>> = Arc::default();
        let mut sequencer = RpcModule::new(Arc::clone(&served));
        sequencer
            .register_method("getLastBlockId", |_, _, _| Ok::<_, ErrorObjectOwned>(3_u64))
            .unwrap();
        sequencer
            .register_method("getBlockRange", |params, served, _| {
                let (start, end) = params.parse::<(u64, u64)>()?;
                Ok::<_, ErrorObjectOwned>(
                    served
                        .lock()
                        .unwrap()
                        .blocks
                        .iter()
                        .filter(|block| (start..=end).contains(&block.header.block_id))
                        .cloned()
                        .collect::<Vec<_>>(),
                )
            })
            .unwrap();
        sequencer
            .register_method("getPublications", |params, served, _| {
                let (from_position, limit) = params.parse::<(u64, u32)>()?;
                Ok::<_, ErrorObjectOwned>(
                    served
                        .lock()
                        .unwrap()
                        .publications
                        .iter()
                        .filter(|(position, _)| *position >= from_position)
                        .take(usize::try_from(limit).unwrap())
                        .cloned()
                        .collect::<Vec<_>>(),
                )
            })
            .unwrap();
        let (mut wallet, home, handle) = served_wallet(sequencer).await;
        let (_, chain_index) = wallet
            .storage
            .key_chain_mut()
            .generate_new_privacy_preserving_transaction_key_chain(None);
        let key_chain = wallet
            .storage
            .key_chain()
            .private_account_key_chain_by_index(&chain_index)
            .unwrap()
            .clone();
        let RecoveryBinding { address, note } = RecipientEncryption {
            recipient: Recipient {
                npk: key_chain.nullifier_public_key,
                vpk: key_chain.viewing_public_key.clone(),
                kind: PrivateAccountKind::Regular,
                opening: None,
            },
            esk: EphemeralSecretKey([5; 32]),
        }
        .bind_recovery();
        let publications: Vec<_> = (0..2)
            .map(|position| {
                let body = MessageBody {
                    from: Actor::native_balance(AccountId::new([1; 32])),
                    to: Actor::native_balance(address),
                    message: borsh::to_vec(&native_token::Message::Credit(u128::from(position)))
                        .unwrap(),
                };
                (
                    position,
                    Publication::Clear {
                        body,
                        recovery: note.clone(),
                    },
                )
            })
            .collect();
        let receipt = Nullifier::for_message(
            &key_chain.private_key_holder.nullifier_secret_key(),
            &publications[0].1.commitment(),
            0,
        );
        *served.lock().unwrap() = Served {
            blocks: vec![
                produce_dummy_block(1, None, Vec::new()),
                block_of(
                    2,
                    transition_message(
                        AccountId::new([6; 32]),
                        &PrivateAccountKind::Regular,
                        &key_chain.viewing_public_key,
                        receipt,
                        &Account::default(),
                    ),
                ),
                produce_dummy_block(3, None, Vec::new()),
            ],
            publications,
        };
        (wallet, home, handle, served)
    }

    fn positions(pending: Vec<PendingMessage>) -> Vec<u64> {
        pending
            .into_iter()
            .map(|pending| pending.position)
            .collect()
    }

    #[tokio::test]
    async fn a_message_received_in_a_synced_block_is_no_longer_pending() {
        let (mut wallet, _home, _sequencer, _served) = wallet_with_a_received_message().await;

        assert_eq!(
            positions(wallet.owned_pending_messages().await.unwrap()),
            [1]
        );
        assert!(wallet.find_pending_message(0).await.unwrap().is_none());
        assert!(wallet.find_pending_message(1).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn the_nullifier_cache_and_the_cursor_recover_together_from_a_torn_cache_or_a_reset() {
        let (mut wallet, home, _sequencer, _served) = wallet_with_a_received_message().await;
        wallet.owned_pending_messages().await.unwrap();
        let cache_path = home.path().join("storage.nullifiers");
        let synced = std::fs::read(&cache_path).unwrap();

        // Block 1's record and the start of block 2's.
        std::fs::write(&cache_path, &synced[..6]).unwrap();
        let mut restarted = WalletCore::new_update_chain(
            wallet.config_path.clone(),
            wallet.storage_path.clone(),
            wallet.statistics_path.clone(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            positions(restarted.owned_pending_messages().await.unwrap()),
            [1]
        );
        assert_eq!(std::fs::read(&cache_path).unwrap(), synced);

        for cursor in [2, 0] {
            restarted.storage.set_last_synced_block(cursor);
            assert_eq!(
                positions(restarted.owned_pending_messages().await.unwrap()),
                [1]
            );
            assert_eq!(std::fs::read(&cache_path).unwrap(), synced);
        }
    }

    #[tokio::test]
    async fn a_gap_in_the_served_history_stops_the_sync_before_it() {
        let (mut wallet, _home, _sequencer, served) = wallet_with_a_received_message().await;
        served.lock().unwrap().blocks.remove(1);

        assert_eq!(
            wallet.sync_to_latest_block().await.unwrap_err().to_string(),
            "History reaches block 3 out of sequence"
        );
        assert_eq!(wallet.storage.last_synced_block(), 1);
        assert_eq!(wallet.spent_nullifiers.covered(), 1);
    }
}
