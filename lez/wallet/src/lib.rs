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
use common::{HashType, PageLimit, block::Block, transaction::LeeTransaction};
use config::WalletConfig;
use futures::TryFutureExt as _;
use key_protocol::key_management::key_tree::chain_index::ChainIndex;
use lee::{
    Account, AccountId, EncryptedNote, PredictedCrossMessages, PrivacyPreservingTransaction,
    ProgramId, ProvingInput, PublicExecutionContext, Recipient, RecipientEncryption, Simulation,
    privacy_preserving_transaction::{
        circuit::{Dependency, ProgramCatalog, ProgramKind},
        message::Message,
    },
};
use lee_core::{
    BlockId, Commitment, CommitmentPosition, CommitmentSetDigest, EphemeralSecretKey, FeeTransfer,
    MembershipProof, MessageWitness, Nullifier, NullifierSecretKey, PrivateAccountKind, RootCall,
    SharedSecretKey,
    account::{Actor, Nonce},
    execution_state::TransactionEntry,
    native_token::NATIVE_TOKEN_PROGRAM_ID,
    program::{MessageBody, MessageData, Publication},
};
use log::warn;
use sequencer_service_rpc::{RpcClient as _, SequencerClient, SequencerClientBuilder};
use storage::{Storage, StorageKey, spent_nullifiers::SpentNullifiers};
use tokio::io::AsyncWriteExt as _;
use url::Url;

use crate::{
    account::{AccountIdWithPrivacy, Label},
    config::WalletConfigOverrides,
    poller::TxPoller,
    program_facades::program_loader::ProgramLoader,
    storage::key_chain::{SharedAccountDerivation, SharedAccountEntry, UserKeyChain},
};

pub mod account;
mod account_manager;
pub mod cli;
pub mod config;
pub mod poller;
pub mod program_facades;
pub mod storage;
pub mod utils;

pub const SUPPRESS_VERBOSE_PRINTS: &str = "SUPPRESS_VERBOSE_PRINTS";

pub const HOME_DIR_ENV_VAR: &str = "LEE_WALLET_HOME_DIR";

/// Env var holding the storage password, read instead of prompting for it.
pub const PASSWORD_ENV_VAR: &str = "LEE_WALLET_PASSWORD";

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

/// The most pending credits one send claims: with its accounts and a received root, a
/// transaction stays within the private actions the wallet pads to.
const MAX_SWEPT_CLAIMS: usize = 4;

/// The most blocks past the sync cursor a send scans for spent receipts before claiming pending
/// credits.
const MAX_SWEEP_SCAN_BLOCKS: u64 = 64;

/// How many times a send prices its reserve again after the screen finds it below the head fee.
const MAX_REPRICES: u32 = 2;

/// Info returned when creating a shared account.
pub struct SharedAccountInfo {
    pub account_id: AccountId,
    pub npk: lee_core::NullifierPublicKey,
    pub vpk: lee_core::encryption::ViewingPublicKey,
}

#[derive(Default)]
pub struct AsyncDelivery {
    pub recoveries: Vec<RecipientEncryption>,
    pub seals: Vec<Recipient>,
    pub promotions: Promotions,
}

// The async messages to execute at once: the listed candidates and, unless `listed_only`, each
// async message to an account this transaction witnesses.
#[derive(Default)]
pub struct Promotions {
    pub public: BTreeSet<u64>,
    pub private: BTreeSet<u64>,
    pub listed_only: bool,
}

// A pending message's body as this wallet reads it, and the recipient its recovery note or seal
// names.
pub struct PendingMessage {
    pub position: CommitmentPosition,
    pub publication: Publication,
    pub body: MessageBody,
    pub recipient: Recipient,
    /// A sealed message's commitment randomness.
    pub rho: Option<[u8; 32]>,
    /// The nullifier receiving it.
    pub receipt: Nullifier,
}

impl PendingMessage {
    /// The amount this message credits its recipient's native balance with,
    /// if it is a native credit.
    #[must_use]
    pub fn native_credit(&self) -> Option<u128> {
        if self.body.to.program_account_id != NATIVE_TOKEN_PROGRAM_ID {
            return None;
        }
        match borsh::from_slice(&self.body.message).ok()? {
            lee_core::native_token::Message::Credit(amount) => Some(amount),
            lee_core::native_token::Message::Transfer { .. }
            | lee_core::native_token::Message::ReadState => None,
        }
    }
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
    #[error("A claimed message reaches {0}, which the transaction does not witness")]
    UnwitnessedClaim(AccountId),
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
    #[error("Dry run: the transaction was simulated and not sent")]
    DryRun,
    #[error("Sending transaction failed for each client")]
    MultiSequencerTransactionSendError,
    #[error("Failed to store wallet data")]
    StorageError(#[source] anyhow::Error),
    #[error("Failed to join a task: {0}")]
    JoinError(#[from] tokio::task::JoinError),
}

/// The reserve a send prices at a quote, see [`WalletCore::reserve_pricing`].
struct ReservePricing {
    fee_at_head: u128,
    exec_ceiling: u64,
    stor_ceiling: u64,
    headroom_reserve: u128,
}

/// A received message a transaction starts from. Its membership path comes with the proofs of the
/// transaction's accounts, so every action spends under one root.
struct Receipt {
    body: MessageBody,
    position: CommitmentPosition,
    rho: Option<[u8; 32]>,
    commitment: Commitment,
}

pub struct WalletCore {
    config_path: PathBuf,
    config_overrides: Option<WalletConfigOverrides>,
    config: WalletConfig,

    storage: Storage,
    storage_path: PathBuf,
    storage_key: Option<StorageKey>,
    spent_nullifiers: SpentNullifiers,

    sequencer_client: SequencerClient,

    /// Simulate transactions and report their cost instead of sending them.
    dry_run: bool,
    /// The owned private account paying every in-proof fee, unless a send names one.
    fee_payer: Option<AccountId>,
    /// The public account every in-proof fee's surplus is refunded to, instead of the payer's
    /// alias.
    refund_to: Option<AccountId>,
    /// Receipts of the pending messages each send of this process claimed, by its transaction,
    /// which a later send leaves alone until the spent-nullifier cache covers them. A
    /// transaction seen reverted or not included gives its claims back.
    swept: std::sync::Mutex<HashMap<HashType, Vec<Nullifier>>>,
}

impl WalletCore {
    /// Construct wallet using [`HOME_DIR_ENV_VAR`] env var for paths or user home dir if not set,
    /// reading the password with [`utils::read_password`].
    pub fn from_env() -> Result<Self> {
        let config_path = utils::fetch_config_path()?;
        let storage_path = utils::fetch_persistent_storage_path()?;
        let password = utils::read_password(&storage_path)?;

        Self::new_update_chain(config_path, storage_path, None, &password)
    }

    /// Opens the wallet whose storage is encrypted under `password`, or unencrypted for an empty
    /// one.
    pub fn new_update_chain(
        config_path: PathBuf,
        storage_path: PathBuf,
        config_overrides: Option<WalletConfigOverrides>,
        password: &str,
    ) -> Result<Self> {
        let (storage, storage_key) = Storage::from_path(&storage_path, password)
            .with_context(|| format!("Failed to load storage from {}", storage_path.display()))?;

        Self::new(
            config_path,
            storage_path,
            config_overrides,
            storage,
            storage_key,
        )
    }

    /// Creates a wallet from a fresh mnemonic, its storage encrypted under `password`, or
    /// unencrypted for an empty one.
    pub fn new_init_storage(
        config_path: PathBuf,
        storage_path: PathBuf,
        config_overrides: Option<WalletConfigOverrides>,
        password: &str,
    ) -> Result<(Self, Mnemonic)> {
        let (storage, mnemonic) = Storage::new();
        let storage_key = storage::storage_key_for(password)?;
        let wallet = Self::new(
            config_path,
            storage_path,
            config_overrides,
            storage,
            storage_key,
        )?;

        Ok((wallet, mnemonic))
    }

    fn new(
        config_path: PathBuf,
        storage_path: PathBuf,
        config_overrides: Option<WalletConfigOverrides>,
        storage: Storage,
        storage_key: Option<StorageKey>,
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

        let spent_nullifiers = SpentNullifiers::open(storage_path.with_extension("nullifiers"))?;

        let mut builder = SequencerClientBuilder::default();
        if let Some(basic_auth) = &config.sequencer.basic_auth {
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
        let sequencer_client = builder
            .build(&config.sequencer.sequencer_addr)
            .context("Failed to create sequencer client")?;

        Ok(Self {
            config_path,
            config_overrides,
            config,
            storage,
            storage_path,
            storage_key,
            spent_nullifiers,
            sequencer_client,
            dry_run: false,
            fee_payer: None,
            refund_to: None,
            swept: std::sync::Mutex::new(HashMap::new()),
        })
    }

    /// Pays every in-proof fee from `fee_payer`, an owned private account, unless a send names
    /// its own; `None` lets each send pick its payer.
    pub const fn set_private_fee_payer(&mut self, fee_payer: Option<AccountId>) {
        self.fee_payer = fee_payer;
    }

    /// Refunds every in-proof fee's surplus to `target`, a public account, instead of the payer's
    /// alias: for a transaction that already credits `target` publicly (a deshield), which then
    /// leaves nothing behind. Any other target links the transaction to it.
    pub const fn set_private_refund_target(&mut self, target: Option<AccountId>) {
        self.refund_to = target;
    }

    /// Reserves every in-proof fee at the base fees after `blocks` of the steepest climb past
    /// the quote, instead of the configured headroom.
    pub const fn set_private_fee_headroom_blocks(&mut self, blocks: u64) {
        self.config.private_fee_headroom_blocks = blocks;
    }

    /// The private account to pay `reserve` when no mentioned private account is authorized and
    /// holds it: an owned regular private account holding it, outside the root call, else the
    /// first mentioned owned regular private account, which pays out of what the root credits it
    /// (a shielding into a fresh account).
    fn auto_fee_payer(&self, mentions: &[AccountMention], reserve: u128) -> Option<AccountId> {
        let holds = |account: &Account| {
            account
                .data
                .native_balance()
                .is_ok_and(|balance| balance >= reserve)
        };
        let owned_regular = |account_id: AccountId| {
            self.storage
                .key_chain()
                .managed_private_account(account_id)
                .filter(|managed| *managed.kind == PrivateAccountKind::Regular)
        };
        let mentioned_candidate = mentions.iter().any(|mention| {
            mention.authorizes
                && match &mention.identity {
                    AccountIdentity::PrivateOwned(account_id) => {
                        owned_regular(*account_id).is_some_and(|managed| holds(managed.account))
                    }
                    AccountIdentity::PrivateShared { .. } => true,
                    AccountIdentity::Public(_)
                    | AccountIdentity::PublicNoSign(_)
                    | AccountIdentity::PublicForeign(_)
                    | AccountIdentity::PublicPda { .. }
                    | AccountIdentity::PublicKeycard { .. }
                    | AccountIdentity::PrivateForeign { .. }
                    | AccountIdentity::PrivatePdaShared { .. } => false,
                }
        });
        if mentioned_candidate {
            return None;
        }
        self.storage
            .key_chain()
            .private_accounts()
            .filter(|found| *found.kind == PrivateAccountKind::Regular && holds(found.account))
            .map(|found| {
                AccountId::from((
                    &found.key_chain.nullifier_public_key,
                    &found.key_chain.viewing_public_key,
                ))
            })
            .next()
            .or_else(|| {
                mentions.iter().find_map(|mention| match mention.identity {
                    AccountIdentity::PrivateOwned(account_id) => {
                        owned_regular(account_id).map(|_| account_id)
                    }
                    AccountIdentity::Public(_)
                    | AccountIdentity::PublicNoSign(_)
                    | AccountIdentity::PublicForeign(_)
                    | AccountIdentity::PublicPda { .. }
                    | AccountIdentity::PublicKeycard { .. }
                    | AccountIdentity::PrivateForeign { .. }
                    | AccountIdentity::PrivateShared { .. }
                    | AccountIdentity::PrivatePdaShared { .. } => None,
                })
            })
    }

    /// Simulate transactions and report their cost instead of sending them; a send then ends
    /// with [`ExecutionFailureKind::DryRun`].
    pub const fn set_dry_run(&mut self, dry_run: bool) {
        self.dry_run = dry_run;
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
    pub fn poller(&self) -> TxPoller {
        TxPoller::new(self.config(), self.client_owned())
    }

    #[must_use]
    pub const fn client(&self) -> &SequencerClient {
        &self.sequencer_client
    }

    #[must_use]
    pub fn client_owned(&self) -> SequencerClient {
        self.sequencer_client.clone()
    }

    #[must_use]
    pub fn client_url(&self) -> Url {
        self.config.sequencer.sequencer_addr.clone()
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
    pub fn restore_storage(&mut self, mnemonic: &Mnemonic) {
        self.storage.restore(mnemonic);
    }

    /// Saves the storage encrypted under `password`, or unencrypted for an empty one, and keeps
    /// saving it so.
    pub fn set_password(&mut self, password: &str) -> Result<()> {
        let storage_key = storage::storage_key_for(password)?;
        self.storage
            .save_to_path(&self.storage_path, storage_key.as_ref())
            .with_context(|| {
                format!(
                    "Failed to store persistent accounts at {}",
                    self.storage_path.display()
                )
            })?;
        self.storage_key = storage_key;
        Ok(())
    }

    /// Store persistent data at home.
    pub fn store_persistent_data(&self) -> Result<()> {
        self.storage
            .save_to_path(&self.storage_path, self.storage_key.as_ref())
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
    pub fn set_sealing_secret_key(
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
        let poller = self.poller();
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

    /// Get account balance.
    pub async fn get_account_balance(&self, acc: AccountId) -> Result<u128> {
        Ok(self.sequencer_client.get_account_balance(acc).await?)
    }

    /// Get accounts nonces.
    pub async fn get_accounts_nonces(&self, accs: &[AccountId]) -> Result<Vec<Nonce>> {
        Ok(self
            .sequencer_client
            .get_accounts_nonces(accs.to_vec())
            .await?)
    }

    /// Returns the account's nonce and the selected actor state; its balance is the actor state at
    /// the native token program.
    pub async fn get_account_view(&self, actor_state_selector: Actor) -> Result<Option<Account>> {
        // RPC projections include empty actor states; the wallet omits them.
        Ok(self
            .sequencer_client
            .get_account_view(actor_state_selector)
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
        from_position: CommitmentPosition,
        limit: PageLimit,
    ) -> Result<Vec<(CommitmentPosition, Publication)>> {
        Ok(self
            .sequencer_client
            .get_publications(from_position, limit)
            .await?)
    }

    // Messages that one of this wallet's key pairs opens: a private address's recovery note, or a
    // sealed message.
    pub async fn owned_pending_messages(&mut self) -> Result<Vec<PendingMessage>> {
        self.sync_to_latest_block().await?;
        self.pending_messages().await
    }

    // The messages one of this wallet's key pairs opens that the spent-nullifier cache, as it
    // stands, does not see received.
    async fn pending_messages(&self) -> Result<Vec<PendingMessage>> {
        const PAGE: PageLimit = 256;
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

    fn read(
        &self,
        position: CommitmentPosition,
        publication: Publication,
    ) -> Option<(PendingMessage, Nullifier)> {
        let (body, recipient, rho, nsk) = self.private_receipt(&publication)?;
        let receipt = Nullifier::for_message(&nsk, &publication.commitment(), position);
        Some((
            PendingMessage {
                position,
                publication,
                body,
                recipient,
                rho,
                receipt,
            },
            receipt,
        ))
    }

    pub async fn find_pending_message(
        &mut self,
        position: CommitmentPosition,
    ) -> Result<Option<PendingMessage>> {
        self.sync_to_latest_block().await?;
        let found = self
            .get_publications(position, 1)
            .await?
            .into_iter()
            .filter(|(found, _)| *found == position)
            .filter_map(|(found, publication)| self.read(found, publication));
        Ok(self.unreceived(found).last())
    }

    // Drops the records whose receipt this wallet sees spent, or claimed by a send of this
    // process.
    fn unreceived(
        &self,
        records: impl IntoIterator<Item = (PendingMessage, Nullifier)>,
    ) -> impl Iterator<Item = PendingMessage> {
        let swept: HashSet<Nullifier> = self
            .swept
            .lock()
            .expect("the swept set is not poisoned")
            .values()
            .flatten()
            .copied()
            .collect();
        records
            .into_iter()
            .filter(move |(_, receipt)| {
                !self.spent_nullifiers.contains(receipt) && !swept.contains(receipt)
            })
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
        Ok(self.sequencer_client.get_last_block_id().await?)
    }

    pub async fn get_block(&self, block_id: u64) -> Result<Option<Block>> {
        Ok(self.sequencer_client.get_block(block_id).await?)
    }

    pub async fn get_transaction(
        &self,
        hash: HashType,
    ) -> Result<Option<(LeeTransaction, BlockId)>> {
        Ok(self.sequencer_client.get_transaction(hash).await?)
    }

    /// Get public account.
    pub async fn get_account_public(&self, account_id: AccountId) -> Result<Option<Account>> {
        Ok(self.sequencer_client.get_account(account_id).await?)
    }

    pub async fn get_recovery_binding(&self, address: AccountId) -> Result<Option<EncryptedNote>> {
        Ok(self.sequencer_client.get_recovery_binding(address).await?)
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
        Ok(self.sequencer_client.get_program_ids().await?)
    }

    /// Poll transactions.
    pub async fn poll_transaction(&self, tx_hash: HashType) -> Result<(LeeTransaction, BlockId)> {
        self.poller().poll_tx(tx_hash).await
    }

    /// The membership paths of `commitments` and of the message leaves at `message_positions`,
    /// all under the root returned with them.
    pub async fn get_proofs_and_root(
        &self,
        commitments: &[Commitment],
        message_positions: Vec<CommitmentPosition>,
    ) -> Result<(
        Vec<Option<MembershipProof>>,
        Vec<Option<MembershipProof>>,
        CommitmentSetDigest,
    )> {
        Ok(self
            .sequencer_client
            .get_proofs_and_root(commitments.to_vec(), message_positions)
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
        let (tx, block_id) = match self.await_inclusion(tx_hash).await {
            Ok(included) => included,
            Err(error) => {
                self.forget_swept(tx_hash);
                return Err(error);
            }
        };
        if let LeeTransaction::PrivacyPreserving(tx) = tx {
            let block = self
                .get_block(block_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Block {block_id} including {tx_hash} not found"))?;
            let reverted = block
                .body
                .transactions
                .iter()
                .position(|included| included.hash() == tx_hash)
                .is_some_and(|position| block.body.is_reverted(position));
            if reverted {
                println!("Transaction reverted: its fee was charged and nothing else applied");
                self.forget_swept(tx_hash);
            }
            let key_chain = self.storage.key_chain_mut();
            let mut index = key_chain.build_latest_nullifier_index();
            key_chain.follow_transaction(&tx.message, reverted, false, &mut index);
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
            None,
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
        async_delivery: AsyncDelivery,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        self.send_tx_with_pre_check(
            accounts,
            root,
            message,
            programs,
            cross_messages,
            async_delivery,
            None,
            |_| Ok(()),
        )
        .await
    }

    // Public when every account is, no recovery binding is new and no candidate is selected,
    // privacy-preserving otherwise. A proof derives its boundary from current public state unless
    // `cross_messages` gives a conditional promise that settlement checks against live execution.
    // A proof pays its fee from `fee_payer` if given, see
    // [`Self::send_privacy_preserving_tx_with_pre_check`].
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
        async_delivery: AsyncDelivery,
        fee_payer: Option<AccountId>,
        tx_pre_check: impl FnOnce(&[SelectedActorState]) -> Result<(), ExecutionFailureKind>,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let to = root_actor(&accounts, root)?;
        let async_delivery = AsyncDelivery {
            recoveries: self.unbound(async_delivery.recoveries).await?,
            ..async_delivery
        };
        if async_delivery.recoveries.is_empty()
            && async_delivery.seals.is_empty()
            && async_delivery.promotions.public.is_empty()
            && async_delivery.promotions.private.is_empty()
            && !accounts.iter().any(|mention| mention.identity.is_private())
        {
            self.send_public(accounts, to, message, None, tx_pre_check)
                .await
                .map(|tx_hash| (tx_hash, Vec::new()))
        } else {
            self.send_proven(
                accounts,
                TransactionEntry::Sync(RootCall { to, message }),
                async_delivery,
                programs,
                cross_messages,
                fee_payer,
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

    // What settlement needs for an async message to `destination`: a public account to execute it,
    // declared, or a private account's recovery binding to publish it.
    pub fn async_destination(
        &self,
        destination: AccountMention,
    ) -> Result<(Option<AccountMention>, AsyncDelivery), ExecutionFailureKind> {
        if destination.identity.is_public() {
            return Ok((
                Some(AccountMention {
                    identity: destination.identity.without_signing(),
                    ..destination
                }),
                AsyncDelivery::default(),
            ));
        }
        Ok((
            None,
            AsyncDelivery {
                recoveries: self
                    .recipients(&destination)?
                    .into_iter()
                    .map(|recipient| RecipientEncryption {
                        recipient,
                        esk: EphemeralSecretKey(account_manager::random_bytes()),
                    })
                    .collect(),
                ..AsyncDelivery::default()
            },
        ))
    }

    // An async message that private execution sends to `destination`: a private destination's
    // recipient material seals it, and no recovery binding publishes the destination.
    pub fn seal_destination(
        &self,
        destination: AccountMention,
    ) -> Result<(Option<AccountMention>, AsyncDelivery), ExecutionFailureKind> {
        if destination.identity.public_account_id().is_some() {
            return self.async_destination(destination);
        }
        Ok((
            None,
            AsyncDelivery {
                seals: self.recipients(&destination)?,
                ..AsyncDelivery::default()
            },
        ))
    }

    // A private destination's recipient material at each blinded address it is mentioned at, or at
    // its canonical address.
    fn recipients(
        &self,
        destination: &AccountMention,
    ) -> Result<Vec<Recipient>, ExecutionFailureKind> {
        let recipient = account_manager::recipient(self, &destination.identity)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
        if destination.address_openings.is_empty() {
            return Ok(vec![recipient]);
        }
        Ok(destination
            .address_openings
            .iter()
            .map(|opening| Recipient {
                opening: Some(*opening),
                ..recipient.clone()
            })
            .collect())
    }

    // `async_destination` for each of `async_destinations` and `seal_destination` for each of
    // `seal_destinations`, joined.
    pub fn async_destinations(
        &self,
        async_destinations: Vec<AccountMention>,
        seal_destinations: Vec<AccountMention>,
    ) -> Result<(Vec<AccountMention>, AsyncDelivery), ExecutionFailureKind> {
        let mut declared = Vec::new();
        let mut joined = AsyncDelivery::default();
        let destinations = async_destinations
            .into_iter()
            .map(|destination| self.async_destination(destination))
            .chain(
                seal_destinations
                    .into_iter()
                    .map(|destination| self.seal_destination(destination)),
            );
        for destination in destinations {
            let (
                mention,
                AsyncDelivery {
                    recoveries, seals, ..
                },
            ) = destination?;
            declared.extend(mention);
            joined.recoveries.extend(recoveries);
            joined.seals.extend(seals);
        }
        Ok((declared, joined))
    }

    /// Sends a privacy-preserving transaction over `accounts`.
    ///
    /// The in-proof fee is reserved from `fee_payer` if given: an owned private account that need
    /// not be one of `accounts`. Otherwise the first authorized private account in `accounts`
    /// that can afford the reserve pays, else the first authorized one (see
    /// [`AccountManager::private_fee_payer_account_id`]).
    pub async fn send_privacy_preserving_tx_with_pre_check(
        &self,
        accounts: Vec<AccountMention>,
        root: usize,
        message: MessageData,
        programs: &ProgramCatalog,
        fee_payer: Option<AccountId>,
        tx_pre_check: impl FnOnce(&[SelectedActorState]) -> Result<(), ExecutionFailureKind>,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let root = TransactionEntry::Sync(RootCall {
            to: root_actor(&accounts, root)?,
            message,
        });
        self.send_proven(
            accounts,
            root,
            AsyncDelivery::default(),
            programs,
            None,
            fee_payer,
            tx_pre_check,
        )
        .await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the proven send threads every input of the transaction it builds"
    )]
    async fn send_proven(
        &self,
        accounts: Vec<AccountMention>,
        root: TransactionEntry<Receipt>,
        async_delivery: AsyncDelivery,
        programs: &ProgramCatalog,
        cross_messages: Option<PredictedCrossMessages>,
        fee_payer: Option<AccountId>,
        tx_pre_check: impl FnOnce(&[SelectedActorState]) -> Result<(), ExecutionFailureKind>,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let AsyncDelivery {
            recoveries,
            seals,
            promotions:
                Promotions {
                    public,
                    private,
                    listed_only,
                },
        } = async_delivery;
        let message = match &root {
            TransactionEntry::Async(receipt) => Some((receipt.position, receipt.commitment)),
            TransactionEntry::Sync(_) => None,
        };
        let mut quote = self.sequencer_client.get_fee_state().await?;
        let fee_payer = fee_payer.or(self.fee_payer).or_else(|| {
            self.auto_fee_payer(&accounts, self.reserve_pricing(&quote, 0).headroom_reserve)
        });
        // Pending native credits to the transaction's private accounts are claimed before the
        // root, so they count as balance; they take the action slots its accounts and root leave.
        let private_states: HashSet<AccountId> = accounts
            .iter()
            .filter(|mention| mention.identity.is_private())
            .map(|mention| mention.identity.account_id())
            .chain(fee_payer)
            .collect();
        let slots = account_manager::AccountManager::PADDED_PRIVATE_ACTIONS
            .saturating_sub(private_states.len())
            .saturating_sub(usize::from(message.is_some()));
        let claims = self
            .sweepable(
                &accounts,
                fee_payer,
                message.map(|(position, _)| position),
                slots.min(MAX_SWEPT_CLAIMS),
            )
            .await?;
        if !claims.is_empty() {
            log::info!(
                "Claiming {} pending credit(s) before the root: {:?}",
                claims.len(),
                claims
                    .iter()
                    .map(|claim| (claim.position, claim.native_credit()))
                    .collect::<Vec<_>>()
            );
        }
        let acc_manager =
            account_manager::AccountManager::new(self, accounts, message, fee_payer, &claims)
                .await?;

        tx_pre_check(&acc_manager.selected_actor_states())?;

        for account_id in acc_manager.accounts_outgrowing_pad() {
            warn!(
                "Account {account_id} exceeds the {CIPHERTEXT_PAD_SIZE}-byte note pad; its note is \
                 identifiable by length in this transaction"
            );
        }

        let shared_secrets = acc_manager.shared_secrets();
        let mut input = ProvingInput {
            root: root.map(|Receipt { body, rho, .. }| MessageWitness {
                body,
                rho,
                membership_proof: acc_manager
                    .message_path()
                    .expect("a received message's path is fetched with its accounts")
                    .clone(),
                filler: account_manager::dummy_output(),
            }),
            claims: claims
                .iter()
                .zip(acc_manager.claim_paths())
                .map(|(claim, path)| MessageWitness {
                    body: claim.body.clone(),
                    rho: claim.rho,
                    membership_proof: path.clone(),
                    filler: account_manager::dummy_output(),
                })
                .collect(),
            public_context: PublicExecutionContext {
                promotions: public,
                ..PublicExecutionContext::new(acc_manager.public_actors(), acc_manager.signers())
            },
            private_witnesses: acc_manager.private_witnesses()?,
            dummy_inputs: acc_manager.dummy_inputs_default(),
            ciphertext_padding: Some(CIPHERTEXT_PAD_SIZE),
            recoveries,
            private_promotions: private,
            fee: None,
        };
        let witnessed: HashSet<AccountId> = input
            .private_witnesses
            .iter()
            .flat_map(|witness| {
                let account_id = witness.account_id();
                std::iter::once(account_id).chain(
                    witness
                        .address_openings
                        .iter()
                        .map(move |opening| account_id.blinded(opening)),
                )
            })
            .collect();
        let select =
            move |_, body: &MessageBody| !listed_only && witnessed.contains(&body.to.account_id);
        let choose_seal_with = |seals: Vec<Recipient>| {
            move |body: &MessageBody| {
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
                            "No recipient material seals an async message to {to}"
                        ))
                    })
            }
        };

        let programs = programs.clone();

        // The in-proof fee: the inbox is a declared public actor so the reserve crosses to it,
        // priced off a simulation of the public part and paid under a fresh alias bound for
        // the refund.
        let fee_inbox = system_accounts::fee_inbox_account_id();
        let inbox_actor = Actor::native_balance(fee_inbox);
        input.public_context.actors.insert(inbox_actor);
        let mut simulation = Simulation {
            public_actor_states: acc_manager.public_actor_states(),
            admitted_accounts: Some(acc_manager.admitted_accounts()),
        };
        simulation.public_actor_states.insert(
            inbox_actor,
            self.get_account_view(inbox_actor)
                .await
                .map_err(ExecutionFailureKind::SequencerError)?
                .unwrap_or_default()
                .data
                .actor_state(NATIVE_TOKEN_PROGRAM_ID)
                .clone(),
        );
        if let Some(admitted) = &mut simulation.admitted_accounts {
            admitted.insert(fee_inbox);
        }
        let (mut input, simulation, programs, cycles) = match cross_messages {
            None => {
                let (mut present, mut select) = (acc_manager.presenter(None), select.clone());
                tokio::task::spawn_blocking(move || {
                    let cycles =
                        lee::simulate(&input, &simulation, &programs, &mut present, &mut select)?;
                    Ok::<_, lee::error::LeeError>((input, simulation, programs, cycles))
                })
                .await??
            }
            // Given cross messages stand in for the simulation; the public part is priced free.
            Some(_) => (input, simulation, programs, 0),
        };
        let payer = acc_manager
            .private_fee_payer_account_id(self.reserve_pricing(&quote, cycles).headroom_reserve)
            .ok_or_else(|| {
                ExecutionFailureKind::TransactionBuildError(lee::error::LeeError::InvalidInput(
                    "Privacy-preserving transaction has no private account to pay its fee"
                        .to_owned(),
                ))
            })?;
        // What the payer holds before the root: its note plus the credits it claims.
        let swept: u128 = claims
            .iter()
            .filter(|claim| claim.recipient.account_id() == payer)
            .filter_map(PendingMessage::native_credit)
            .sum();
        let balance = acc_manager.native_balance(payer).saturating_add(swept);
        let refund_to = self.refund_to;
        if let Some(target) = refund_to
            && !acc_manager
                .public_actors()
                .contains(&Actor::native_balance(target))
        {
            warn!(
                "Refund target {target} is not credited publicly by this transaction; the refund \
                 links the transaction to it"
            );
        }
        let opening = account_manager::random_bytes();
        input
            .recoveries
            .push(acc_manager.fee_recovery(payer, opening)?);

        // Base fees move between the quote and inclusion; a reserve the screen finds below the
        // head fee is priced again off a fresh quote and proven again.
        let mut reprices = 0;
        loop {
            let ReservePricing {
                fee_at_head,
                exec_ceiling,
                stor_ceiling,
                headroom_reserve,
            } = self.reserve_pricing(&quote, cycles);
            // Never reserve more than the payer holds, nor less than the fee at head.
            let reserve = headroom_reserve.min(balance).max(fee_at_head);
            if self.dry_run {
                let blocks = self.config.private_fee_headroom_blocks;
                println!("Dry run: nothing proven or sent");
                println!("  public cycles:  {cycles}");
                println!(
                    "  base fees:      exec {} / stor {} (height {})",
                    quote.base_fee_exec, quote.base_fee_stor, quote.height
                );
                println!("  fee at head:    {fee_at_head}");
                println!(
                    "  headroom:       {blocks} blocks, up to exec {exec_ceiling} / stor \
                     {stor_ceiling} ({headroom_reserve})"
                );
                println!("  reserve:        {reserve} (surplus refunded)");
                println!("  fee payer:      {payer}");
                println!(
                    "  claims:         {} pending credit(s), {swept} to the payer",
                    claims.len()
                );
                println!(
                    "  refund to:      {}",
                    refund_to.map_or_else(|| "the payer's alias".to_owned(), |t| t.to_string())
                );
                return Err(ExecutionFailureKind::DryRun);
            }

            let mut priced = input.clone();
            priced.fee = Some(FeeTransfer {
                payer,
                recipient: fee_inbox,
                amount: reserve,
                refund_to,
            });
            let present = acc_manager.presenter(Some((payer, opening)));
            let (select, choose_seal) = (select.clone(), choose_seal_with(seals.clone()));
            let (programs, simulation) = (programs.clone(), simulation.clone());
            let (output, proof) = match cross_messages.clone() {
                None => tokio::task::spawn_blocking(move || {
                    lee::execute_and_prove(
                        priced,
                        &simulation,
                        &programs,
                        present,
                        select,
                        choose_seal,
                    )
                })
                .await?
                .map_err(|error| {
                    // The transaction simulated without its fee, so the reserve is what broke it.
                    if let lee::error::LeeError::InvalidProgramBehavior(cause) = error {
                        lee::error::LeeError::InvalidInput(format!(
                            "Fee reserve of {reserve} from payer {payer} fails, though the \
                             transaction runs without it: {cause}"
                        ))
                    } else {
                        error
                    }
                })?,
                Some(cross_messages) => {
                    tokio::task::spawn_blocking(move || {
                        lee::execute_and_prove_with_cross_messages(
                            priced,
                            cross_messages,
                            &programs,
                            present,
                            select,
                            choose_seal,
                        )
                    })
                    .await??
                }
            };

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

            match self
                .sequencer_client
                .send_transaction(LeeTransaction::PrivacyPreserving(tx))
                .await
            {
                Ok(tx_hash) => {
                    if !claims.is_empty() {
                        self.swept
                            .lock()
                            .expect("the swept set is not poisoned")
                            .insert(tx_hash, claims.iter().map(|claim| claim.receipt).collect());
                    }
                    return Ok((tx_hash, shared_secrets));
                }
                Err(rejection) if reprices < MAX_REPRICES && reserve_below_head(&rejection) => {
                    reprices = reprices.saturating_add(1);
                    warn!(
                        "The sequencer prices the fee above the {reserve} reserved; pricing it \
                         again off a fresh quote ({reprices} of {MAX_REPRICES})"
                    );
                    quote = self.sequencer_client.get_fee_state().await?;
                }
                Err(rejection) => return Err(rejection.into()),
            }
        }
    }

    /// The reserve a privacy-preserving transaction of `cycles` public cycles takes at `quote`:
    /// the fee at the head and at the base fees after the configured blocks of full blocks,
    /// the steepest climb allowed.
    fn reserve_pricing(
        &self,
        quote: &sequencer_service_rpc::FeeStateQuote,
        cycles: u64,
    ) -> ReservePricing {
        let blocks = self.config.private_fee_headroom_blocks;
        let climb = |base, max_gas, target, damping, lo, hi| {
            (0..blocks).fold(base, |fee, _| {
                fee_core::market::next_base_fee(fee, max_gas, target, damping, lo, hi)
            })
        };
        let exec_ceiling = climb(
            quote.base_fee_exec,
            fee_core::market::MAX_GAS_EXEC,
            fee_core::market::TARGET_GAS_EXEC,
            fee_core::market::D_EXEC,
            fee_core::market::BASE_FEE_EXEC_MIN,
            fee_core::market::BASE_FEE_EXEC_MAX,
        );
        let stor_ceiling = climb(
            quote.base_fee_stor,
            fee_core::market::MAX_GAS_STOR,
            fee_core::market::TARGET_GAS_STOR,
            fee_core::market::D_STOR,
            fee_core::market::BASE_FEE_STOR_MIN,
            fee_core::market::BASE_FEE_STOR_MAX,
        );
        ReservePricing {
            fee_at_head: fee_core::assess::private_fee_required(
                cycles,
                quote.base_fee_exec,
                quote.base_fee_stor,
            ),
            exec_ceiling,
            stor_ceiling,
            headroom_reserve: fee_core::assess::private_fee_required(
                cycles,
                exec_ceiling,
                stor_ceiling,
            ),
        }
    }

    /// Gives the claims of `tx_hash` back to the pending messages: it reverted or was not
    /// included.
    fn forget_swept(&self, tx_hash: HashType) {
        self.swept
            .lock()
            .expect("the swept set is not poisoned")
            .remove(&tx_hash);
    }

    /// The pending native credits a transaction over `mentions`, paid by `fee_payer`, claims
    /// before its root, the message at `root` if it receives one: those reaching its authorized
    /// private accounts this wallet manages, largest first, up to `limit`. The blocks past the
    /// sync cursor are scanned for receipts spent since; none is claimed when they exceed
    /// [`MAX_SWEEP_SCAN_BLOCKS`].
    async fn sweepable(
        &self,
        mentions: &[AccountMention],
        fee_payer: Option<AccountId>,
        root: Option<CommitmentPosition>,
        limit: usize,
    ) -> Result<Vec<PendingMessage>, ExecutionFailureKind> {
        use futures::TryStreamExt as _;

        let claimants: HashSet<AccountId> = mentions
            .iter()
            .filter(|mention| mention.authorizes && mention.identity.is_private())
            .map(|mention| mention.identity.account_id())
            .chain(fee_payer)
            .filter(|account_id| {
                self.storage
                    .key_chain()
                    .managed_private_account(*account_id)
                    .is_some()
            })
            .collect();
        if claimants.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        let head = self
            .get_last_block_id()
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;
        let synced = self.storage.last_synced_block();
        if head.saturating_sub(synced) > MAX_SWEEP_SCAN_BLOCKS {
            log::info!(
                "Pending credits are not claimed: the wallet is synced to block {synced} of {head}"
            );
            return Ok(Vec::new());
        }
        let mut spent_since = HashSet::new();
        if synced < head {
            let poller = self.poller();
            let mut blocks =
                std::pin::pin!(poller.poll_block_range(synced.saturating_add(1)..=head));
            while let Some(block) = blocks
                .try_next()
                .await
                .map_err(ExecutionFailureKind::SequencerError)?
            {
                spent_since.extend(spent_in(&block));
            }
        }
        let mut credits: Vec<PendingMessage> = self
            .pending_messages()
            .await
            .map_err(ExecutionFailureKind::SequencerError)?
            .into_iter()
            .filter(|pending| {
                Some(pending.position) != root
                    && claimants.contains(&pending.recipient.account_id())
                    && pending.native_credit().is_some()
                    && !spent_since.contains(&pending.receipt)
            })
            .collect();
        credits.sort_by_key(|pending| std::cmp::Reverse(pending.native_credit()));
        credits.truncate(limit);
        Ok(credits)
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

        let mut acc_manager =
            account_manager::AccountManager::new(self, accounts, None, None, &[]).await?;

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
        if self.dry_run {
            self.report_public_dry_run(tx).await?;
            return Err(ExecutionFailureKind::DryRun);
        }

        Ok(self
            .sequencer_client
            .send_transaction(LeeTransaction::Public(tx))
            .await?)
    }

    /// Simulates `tx` on the sequencer and prints what it would cost at the head fee state.
    async fn report_public_dry_run(
        &self,
        tx: lee::PublicTransaction,
    ) -> Result<(), ExecutionFailureKind> {
        let fee = tx
            .message()
            .execution
            .fee
            .expect("the wallet always declares a fee");
        // Storage gas is the wire size settlement sees: the whole `LeeTransaction`.
        let tx = LeeTransaction::Public(tx);
        let data_bytes = u128::try_from(
            borsh::to_vec(&tx)
                .map_err(|err| ExecutionFailureKind::SignError(err.into()))?
                .len(),
        )
        .expect("transaction size fits u128");
        let run = self.sequencer_client.dry_run_public_transaction(tx).await?;
        let quote = self.sequencer_client.get_fee_state().await?;
        let actual_fee = u128::from(run.cycles)
            .saturating_mul(u128::from(quote.base_fee_exec))
            .saturating_add(data_bytes.saturating_mul(u128::from(quote.base_fee_stor)))
            .saturating_add(u128::from(fee.tip));

        println!("Dry run: nothing sent");
        println!("  fee payer:        {}", fee.payer);
        println!("  declared gas:     {}", fee.gas_limit);
        println!("  metered cycles:   {}", run.cycles);
        println!("  wire bytes:       {data_bytes}");
        println!(
            "  base fees:        exec {} / stor {} (height {})",
            quote.base_fee_exec, quote.base_fee_stor, quote.height
        );
        println!("  fee at head:      {actual_fee} (tip {})", fee.tip);
        match run.revert {
            Some(reason) => println!("  action REVERTS:   {reason} (fee is still charged)"),
            None => println!("  action:           applies"),
        }
        Ok(())
    }

    pub async fn receive_pending_message(
        &mut self,
        pending: PendingMessage,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        self.receive_pending_message_with(
            pending,
            Vec::new(),
            &ProgramCatalog::default(),
            None,
            AsyncDelivery::default(),
        )
        .await
    }

    // Executes the message as published. Its recipient takes part as `accounts` declare its
    // account, unauthorized otherwise, and each declared program missing from `programs` runs
    // from its deployment. Authorization is per account: authorizing the recipient's account
    // authorizes the published message too.
    pub async fn receive_pending_message_with(
        &mut self,
        PendingMessage {
            position,
            publication,
            ..
        }: PendingMessage,
        mut accounts: Vec<AccountMention>,
        programs: &ProgramCatalog,
        cross_messages: Option<PredictedCrossMessages>,
        async_delivery: AsyncDelivery,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let Some((body, recipient, rho, nsk)) = self.private_receipt(&publication) else {
            return Err(ExecutionFailureKind::TransactionBuildError(
                lee::error::LeeError::InvalidInput(format!(
                    "No key pair of this wallet opens the message published at {position}"
                )),
            ));
        };
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
        let receiver = Actor::new(account_id, body.to.program_account_id);
        let index = accounts
            .iter()
            .position(|mention| mention.actor() == receiver)
            .unwrap_or_else(|| {
                let mention = accounts
                    .iter()
                    .find(|mention| mention.identity.account_id() == account_id)
                    .map_or_else(
                        || {
                            identity
                                .select_program_actor_state(receiver.program_account_id)
                                .without_authorization()
                        },
                        |declared| AccountMention {
                            program_account_id: receiver.program_account_id,
                            ..declared.clone()
                        },
                    );
                accounts.insert(0, mention);
                0
            });
        accounts[index].address_openings.extend(recipient.opening);

        let mut programs = programs.clone();
        let declared: BTreeSet<AccountId> = accounts
            .iter()
            .map(|mention| mention.program_account_id)
            .collect();
        // The native program runs as protocol code.
        for program in declared {
            if program != NATIVE_TOKEN_PROGRAM_ID
                && !programs.programs.contains_key(&program)
                && let Some(deployed) = ProgramLoader(self)
                    .program(program)
                    .await
                    .map_err(ExecutionFailureKind::SequencerError)?
            {
                programs.programs.insert(
                    program,
                    Dependency {
                        program: deployed,
                        kind: ProgramKind::Disclosed,
                    },
                );
            }
        }

        let async_delivery = AsyncDelivery {
            recoveries: self.unbound(async_delivery.recoveries).await?,
            ..async_delivery
        };
        let receipt = Receipt {
            body,
            position,
            rho,
            commitment: publication.commitment(),
        };
        self.send_proven(
            accounts,
            TransactionEntry::Async(receipt),
            async_delivery,
            &programs,
            cross_messages,
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

    /// Rediscovers the private accounts this wallet's keys hold from genesis through the current
    /// tip, keeping every other record, the sync cursor and the spent-nullifier cache. A failed
    /// scan changes nothing.
    pub async fn rescan_private_accounts(&mut self) -> Result<()> {
        let tip = self
            .get_last_block_id()
            .await?
            .max(self.storage.last_synced_block());
        log::info!("Rescanning private accounts from genesis to block {tip}");
        let poller = self.poller();
        let rescanned = self
            .storage
            .key_chain()
            .clone()
            .rescan(tip, poller.poll_block_range(1..=tip))
            .await?;
        let unscanned = std::mem::replace(self.storage.key_chain_mut(), rescanned);
        self.store_persistent_data().inspect_err(|_| {
            *self.storage.key_chain_mut() = unscanned;
        })
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
        let leader_client = self.client_owned();

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

        let poller = self.poller();
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
            let spent = spent_in(&block);
            for (position, tx) in block.body.transactions.iter().enumerate() {
                let LeeTransaction::PrivacyPreserving(pp_tx) = tx else {
                    continue;
                };
                self.storage.key_chain_mut().follow_transaction(
                    &pp_tx.message,
                    block.body.is_reverted(position),
                    discover,
                    &mut index,
                );
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

/// The nullifiers `block` spends: a reverted transaction's fee fallback alone, every private
/// action of the others.
fn spent_in(block: &Block) -> Vec<Nullifier> {
    block
        .body
        .transactions
        .iter()
        .enumerate()
        .filter_map(|(position, tx)| match tx {
            LeeTransaction::PrivacyPreserving(pp_tx) => Some((position, &pp_tx.message.execution)),
            LeeTransaction::Public(_) => None,
        })
        .flat_map(|(position, execution)| {
            let fallback = execution.fee.as_ref().and_then(|fee| fee.fallback.as_ref());
            match (block.body.is_reverted(position), fallback) {
                (true, Some(fallback)) => vec![fallback.action.nullifier],
                (true, None) => Vec::new(),
                (false, _) => execution
                    .private_actions
                    .iter()
                    .map(|action| action.nullifier)
                    .collect(),
            }
        })
        .collect()
}

/// Whether the sequencer turned a transaction away for a reserve below the fee at its head.
fn reserve_below_head(rejection: &sequencer_service_rpc::ClientError) -> bool {
    matches!(
        rejection,
        sequencer_service_rpc::ClientError::Call(object)
            if object.code() == sequencer_service_rpc::PRIVATE_FEE_BELOW_HEAD_ERROR_CODE
    )
}

fn decrypt_note(
    action: &lee_core::PrivateAction,
    secret: &SharedSecretKey,
) -> Option<(lee_core::PrivateAccountKind, Account)> {
    lee_core::EncryptionScheme::decrypt(
        &action.encrypted_post_state.ciphertext,
        secret,
        &action.nullifier,
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

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeSet, HashMap},
        ffi::CString,
        str::FromStr as _,
        sync::{Arc, Mutex},
    };

    use bip39::Mnemonic;
    use common::{
        PageLimit, block::Block, test_utils::produce_dummy_block, transaction::LeeTransaction,
    };
    use jsonrpsee::{
        RpcModule,
        server::{Server, ServerHandle},
        types::ErrorObjectOwned,
    };
    use lee::{
        AccountId, BoundaryStep, privacy_preserving_transaction::circuit::ProgramCatalog,
        program::Program,
    };
    use lee_core::{
        Commitment, CommitmentPosition, EncryptedNote, EphemeralSecretKey, MembershipProof,
        Nullifier, PrivateAccountKind, ProgramImageClaim, Recipient, RecipientEncryption,
        RecoveryBinding,
        account::{Account, Actor, ActorState},
        compute_digest_for_path, native_token,
        program::{
            MessageBody, PROGRAM_LOADER_ACCOUNT_ID, PdaSeed, ProgramHeader, ProgramSegment,
            Publication,
        },
    };
    use program_loader_core::MAX_SEGMENT_DATA_LEN;
    use sequencer_stake_core::{SequencerKey, StakeRecord, ed25519_dalek::SigningKey};
    use test_guest_core::Script;

    use super::{
        AccountIdentity, AccountMention, AsyncDelivery, ExecutionFailureKind,
        NATIVE_TOKEN_PROGRAM_ID, PendingMessage, WalletCore,
    };
    use crate::{
        account::{AccountIdWithPrivacy, Label},
        cli::SubcommandReturnValue,
        config::{SequencerConnectionData, WalletConfig},
        program_facades::{CreditDelivery, credit_destination, sequencer_stake::SequencerStake},
        storage::{
            Storage, WrongPassword,
            key_chain::tests::{block_of, transition_message},
        },
    };

    #[derive(Default)]
    struct Served {
        blocks: Vec<Block>,
        publications: Vec<(CommitmentPosition, Publication)>,
        accounts: HashMap<AccountId, Account>,
        submitted: Vec<LeeTransaction>,
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
                sequencer: SequencerConnectionData {
                    sequencer_addr: format!("http://{address}").parse().unwrap(),
                    basic_auth: None,
                },
                ..WalletConfig::default()
            })
            .unwrap(),
        )
        .unwrap();
        let (wallet, _) = WalletCore::new_init_storage(
            config_path,
            home.path().join("storage.json"),
            None,
            "password",
        )
        .unwrap();
        (wallet, home, handle)
    }

    #[tokio::test]
    async fn a_set_password_reopens_the_storage_and_an_empty_one_leaves_it_unencrypted() {
        let (mut wallet, _home, _sequencer) = served_wallet(RpcModule::new(())).await;
        let (config_path, storage_path) = (wallet.config_path.clone(), wallet.storage_path.clone());
        let reopen = |password: &str| {
            WalletCore::new_update_chain(config_path.clone(), storage_path.clone(), None, password)
        };

        wallet.set_password("new password").unwrap();
        assert!(reopen("password").is_err());
        assert!(reopen("new password").is_ok());

        wallet.set_password("").unwrap();
        assert!(!Storage::is_encrypted(&storage_path).unwrap());
        assert!(reopen("").is_ok());
    }

    #[tokio::test]
    async fn opening_with_a_password_that_does_not_open_the_storage_is_a_wrong_password() {
        let (mut wallet, _home, _sequencer) = served_wallet(RpcModule::new(())).await;
        let (config_path, storage_path) = (wallet.config_path.clone(), wallet.storage_path.clone());
        let reopen = |password: &str| {
            WalletCore::new_update_chain(config_path.clone(), storage_path.clone(), None, password)
                .err()
                .unwrap()
        };
        wallet.store_persistent_data().unwrap();

        assert!(reopen("wrong password").is::<WrongPassword>());
        assert!(reopen("").is::<WrongPassword>());

        wallet.set_password("").unwrap();
        assert!(reopen("password").is::<WrongPassword>());
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
            Storage::from_path(&storage_path, "password")
                .unwrap()
                .0
                .key_chain(),
        ] {
            assert_eq!(
                key_chain.private_account(pda_id).unwrap().account,
                &initialized
            );
        }
    }

    #[tokio::test]
    async fn completion_applies_the_included_transaction_without_moving_the_cursor() {
        let included: Arc<Mutex<Option<Block>>> = Arc::default();
        let mut sequencer = RpcModule::new(Arc::clone(&included));
        sequencer
            .register_method("getLastBlockId", |_, _, _| Ok::<_, ErrorObjectOwned>(2_u64))
            .unwrap();
        sequencer
            .register_method("getTransaction", |_, included, _| {
                Ok::<_, ErrorObjectOwned>(
                    included
                        .lock()
                        .unwrap()
                        .as_ref()
                        .map(|block| (block.body.transactions[0].clone(), 2_u64)),
                )
            })
            .unwrap();
        sequencer
            .register_method("getBlock", |_, included, _| {
                Ok::<_, ErrorObjectOwned>(included.lock().unwrap().clone())
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
        let block = block_of(
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
        );
        let tx_hash = block.body.transactions[0].hash();
        *included.lock().unwrap() = Some(block);

        assert!(matches!(
            wallet.finish_transaction(tx_hash).await.unwrap(),
            SubcommandReturnValue::TransactionExecuted { tx_hash: executed } if executed == tx_hash
        ));
        assert_eq!(wallet.storage.last_synced_block(), 1);
        for storage in [
            &wallet.storage,
            &Storage::from_path(&wallet.storage_path, "password")
                .unwrap()
                .0,
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
        let (declared, async_delivery) =
            route(&public, recipient.clone(), CreditDelivery::Automatic);
        let declared = declared.unwrap();
        assert!(declared.identity == recipient && !declared.authorizes);
        assert!(async_delivery.seals.is_empty() && async_delivery.recoveries.is_empty());

        // Deferred, its credit is sealed and stays pending even where the account takes part.
        let (declared, async_delivery) = route(&sender, recipient, CreditDelivery::DeferredPrivate);
        assert!(declared.is_none() && async_delivery.promotions.listed_only);
        assert_eq!(
            async_delivery.seals,
            std::slice::from_ref(&recipient_material)
        );

        // A recipient named by its keys stays pending, even when they are this wallet's.
        let (declared, async_delivery) = route(
            &public,
            AccountIdentity::PrivateForeign {
                npk: recipient_material.npk,
                vpk: recipient_material.vpk.clone(),
                kind: PrivateAccountKind::Regular,
            },
            CreditDelivery::Automatic,
        );
        assert!(declared.is_none() && async_delivery.promotions.listed_only);
        assert_eq!(async_delivery.recoveries.len(), 1);
        assert_eq!(async_delivery.recoveries[0].recipient, recipient_material);

        // A public recipient takes part either way, as the caller named it.
        let (declared, _) = route(&sender, public.clone(), CreditDelivery::DeferredPrivate);
        let declared = declared.unwrap();
        assert!(declared.identity == public && declared.authorizes);

        // A sender crediting itself takes part once.
        let (declared, _) = route(&sender, sender.clone(), CreditDelivery::Automatic);
        assert!(declared.is_none());

        // Mentioned at a blinded address, a destination is sealed and bound there instead.
        let blinded = AccountMention {
            address_openings: BTreeSet::from([[4; 32]]),
            ..AccountIdentity::PrivateOwned(recipient_id).balance()
        };
        let addressed = Recipient {
            opening: Some([4; 32]),
            ..recipient_material
        };
        let (_, sealed) = wallet.seal_destination(blinded.clone()).unwrap();
        assert_eq!(sealed.seals, std::slice::from_ref(&addressed));
        let (_, bound) = wallet.async_destination(blinded).unwrap();
        assert_eq!(bound.recoveries.len(), 1);
        assert_eq!(bound.recoveries[0].recipient, addressed);
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
                    Vec::<Option<lee_core::MembershipProof>>::new(),
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
                let (from_position, limit) = params.parse::<(CommitmentPosition, PageLimit)>()?;
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
        sequencer
            .register_method("getAccountView", |params, served, _| {
                let actor = params.one::<Actor>()?;
                Ok::<_, ErrorObjectOwned>(
                    served
                        .lock()
                        .unwrap()
                        .accounts
                        .get(&actor.account_id)
                        .cloned(),
                )
            })
            .unwrap();
        sequencer
            .register_method("getFeeState", |_, _, _| {
                Ok::<_, ErrorObjectOwned>(sequencer_service_rpc::FeeStateQuote {
                    height: 3,
                    base_fee_exec: 0,
                    base_fee_stor: 0,
                    next_base_fee_exec_floor: 0,
                    next_base_fee_exec_ceiling: 0,
                    next_base_fee_stor_floor: 0,
                    next_base_fee_stor_ceiling: 0,
                    max_gas_exec: u64::MAX,
                    max_gas_stor: u64::MAX,
                })
            })
            .unwrap();
        sequencer
            .register_method("getProofsAndRoot", |params, served, _| {
                let (commitments, positions) =
                    params.parse::<(Vec<Commitment>, Vec<CommitmentPosition>)>()?;
                // One message path is served, under a root computed from it.
                let paths: Vec<Option<MembershipProof>> = positions
                    .iter()
                    .map(|position| Some((*position, vec![[0; 32]])))
                    .collect();
                let root = positions.first().map_or([0; 32], |position| {
                    let served = served.lock().unwrap();
                    let (_, publication) = served
                        .publications
                        .iter()
                        .find(|(published, _)| published == position)
                        .unwrap();
                    compute_digest_for_path(&publication.commitment(), *position, &[[0; 32]])
                        .unwrap()
                });
                Ok::<_, ErrorObjectOwned>((
                    vec![None::<MembershipProof>; commitments.len()],
                    paths,
                    root,
                ))
            })
            .unwrap();
        sequencer
            .register_method("sendTransaction", |params, served, _| {
                let tx = params.one::<LeeTransaction>()?;
                let hash = tx.hash();
                served.lock().unwrap().submitted.push(tx);
                Ok::<_, ErrorObjectOwned>(hash)
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
            ..Served::default()
        };
        (wallet, home, handle, served)
    }

    // A wallet synced past a private PDA's history under its key without discovering it, which
    // knows its own account at a newer state than that account's note, and holds a label and an
    // imported key.
    async fn wallet_past_an_undiscovered_pda() -> (
        WalletCore,
        tempfile::TempDir,
        ServerHandle,
        Arc<Mutex<Served>>,
        AccountId,
        PrivateAccountKind,
    ) {
        let (mut wallet, home, handle, served) = wallet_with_a_received_message().await;
        let found = wallet
            .storage
            .key_chain()
            .private_accounts()
            .next()
            .unwrap();
        let npk = found.key_chain.nullifier_public_key;
        let vpk = found.key_chain.viewing_public_key.clone();
        let nsk = found.key_chain.private_key_holder.nullifier_secret_key();
        let regular = AccountId::for_private_account(&npk, &vpk, &PrivateAccountKind::Regular);
        let pda_kind = PrivateAccountKind::Pda {
            account_id: AccountId::new([4; 32]),
            seed: PdaSeed::new([5; 32]),
        };
        let pda = AccountId::for_private_account(&npk, &vpk, &pda_kind);
        let funded = Account::funded(70);
        served.lock().unwrap().blocks = vec![
            block_of(
                1,
                transition_message(
                    pda,
                    &pda_kind,
                    &vpk,
                    Nullifier::for_account_initialization(&pda, &nsk),
                    &funded,
                ),
            ),
            block_of(
                2,
                transition_message(
                    pda,
                    &pda_kind,
                    &vpk,
                    Nullifier::for_account_update(&Commitment::new(&pda, &funded), &nsk),
                    &Account::funded(90),
                ),
            ),
            block_of(
                3,
                transition_message(
                    regular,
                    &PrivateAccountKind::Regular,
                    &vpk,
                    Nullifier::for_account_initialization(&regular, &nsk),
                    &Account::funded(5),
                ),
            ),
        ];
        wallet.sync_to_latest_block().await.unwrap();
        assert!(wallet.storage.key_chain().private_account(pda).is_none());

        let key_chain = wallet.storage.key_chain_mut();
        key_chain
            .insert_private_account(regular, PrivateAccountKind::Regular, Account::funded(9))
            .unwrap();
        key_chain.add_imported_public_account(lee::PrivateKey::try_new([3; 32]).unwrap());
        wallet
            .storage
            .add_label(
                Label::new("owner".to_owned()),
                AccountIdWithPrivacy::Private(regular),
            )
            .unwrap();
        wallet.store_persistent_data().unwrap();
        (wallet, home, handle, served, pda, pda_kind)
    }

    // Serves `program` deployed at the header `[tag; 32]`, its user ELF chained over segments.
    fn deploy(served: &Mutex<Served>, program: &Program, tag: u8) -> AccountId {
        let loader = |bytes| {
            Account::default().with_actor_state(PROGRAM_LOADER_ACCOUNT_ID, ActorState::from(bytes))
        };
        let user_elf = program.user_elf().unwrap();
        let chunks: Vec<&[u8]> = user_elf.chunks(MAX_SEGMENT_DATA_LEN).collect();
        let segments: Vec<AccountId> = (0..chunks.len())
            .map(|index| {
                let mut account_id = [tag; 32];
                account_id[0] = u8::try_from(index).unwrap();
                AccountId::new(account_id)
            })
            .collect();
        let next_segments = segments.iter().skip(1).copied().map(Some).chain([None]);
        let header = AccountId::new([tag; 32]);
        let mut served = served.lock().unwrap();
        for ((segment, bytecode), next_segment) in segments.iter().zip(chunks).zip(next_segments) {
            let segment_state = ProgramSegment {
                bytecode: bytecode.to_vec(),
                next_segment,
            };
            served
                .accounts
                .insert(*segment, loader(segment_state.to_bytes()));
        }
        let header_state = ProgramHeader {
            image_id: program.id(),
            program_first_segment: segments[0],
            immutable: false,
        };
        served
            .accounts
            .insert(header, loader(header_state.to_bytes()));
        header
    }

    // Replaces the pending message with `message` from `from` to its recipient at `program`.
    fn publish(
        served: &Mutex<Served>,
        from: Actor,
        program: AccountId,
        message: &impl borsh::BorshSerialize,
    ) {
        let mut served = served.lock().unwrap();
        let Publication::Clear { body, .. } = &mut served.publications[1].1 else {
            panic!("the fixture publishes in the clear");
        };
        *body = MessageBody {
            from,
            to: Actor::new(body.to.account_id, program),
            message: borsh::to_vec(message).unwrap(),
        };
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
            None,
            "password",
        )
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

    #[tokio::test]
    async fn a_message_to_a_program_deployed_anywhere_is_received_from_that_deployment() {
        let (mut wallet, _home, _sequencer, served) = wallet_with_a_received_message().await;
        let listener = deploy(&served, &test_programs::listener(), 0x40);
        publish(
            &served,
            Actor::new(AccountId::new([1; 32]), listener),
            listener,
            &(),
        );
        let pending = wallet.find_pending_message(1).await.unwrap().unwrap();

        wallet.receive_pending_message(pending).await.unwrap();

        let Some(LeeTransaction::PrivacyPreserving(receipt)) =
            served.lock().unwrap().submitted.pop()
        else {
            panic!("the receipt should have been submitted privately");
        };
        assert_eq!(
            receipt.message.execution.program_image_claims,
            [ProgramImageClaim::Disclosed {
                account_id: listener,
                image_id: test_programs::listener().id(),
            }]
        );
    }

    #[tokio::test]
    async fn a_received_message_is_executed_with_its_subcall_to_the_declared_listener() {
        let (mut wallet, _home, _sequencer, served) = wallet_with_a_received_message().await;
        let scripted = deploy(&served, &test_programs::scripted(), 0x40);
        let listener = Actor::new(
            AccountId::new([9; 32]),
            deploy(&served, &test_programs::listener(), 0x80),
        );
        served
            .lock()
            .unwrap()
            .accounts
            .insert(listener.account_id, Account::default());
        publish(
            &served,
            Actor::new(AccountId::new([1; 32]), scripted),
            scripted,
            &Script::default().send_sync(listener, &7_u8),
        );
        let pending = wallet.find_pending_message(1).await.unwrap().unwrap();

        wallet
            .receive_pending_message_with(
                pending,
                vec![
                    AccountIdentity::PublicNoSign(listener.account_id)
                        .select_program_actor_state(listener.program_account_id),
                ],
                &ProgramCatalog::default(),
                None,
                AsyncDelivery::default(),
            )
            .await
            .unwrap();

        let Some(LeeTransaction::PrivacyPreserving(receipt)) =
            served.lock().unwrap().submitted.pop()
        else {
            panic!("the receipt should have been submitted privately");
        };
        assert!(
            receipt
                .message
                .execution
                .boundary
                .iter()
                .any(|step| matches!(
                    step,
                    BoundaryStep::PrivateToPublic(delivery)
                        if delivery.envelope.to == listener && delivery.envelope.message == [7]
                ))
        );
    }

    // The recipient pays the receipt's fee, and a fee payer authorizes its account: the transfer
    // the message asks of it runs whether or not the caller mentions it as authorizing.
    #[tokio::test]
    async fn a_receipt_runs_authorized_by_its_recipient_paying_the_fee() {
        let (mut wallet, _home, _sequencer, served) = wallet_with_a_received_message().await;
        let recipient = wallet
            .find_pending_message(1)
            .await
            .unwrap()
            .unwrap()
            .recipient
            .account_id();
        publish(
            &served,
            Actor::native_balance(AccountId::new([1; 32])),
            NATIVE_TOKEN_PROGRAM_ID,
            &native_token::Message::Transfer {
                to: recipient,
                amount: 0,
            },
        );

        let pending = wallet.find_pending_message(1).await.unwrap().unwrap();
        wallet.receive_pending_message(pending).await.unwrap();

        let pending = wallet.find_pending_message(1).await.unwrap().unwrap();
        wallet
            .receive_pending_message_with(
                pending,
                vec![AccountIdentity::PrivateOwned(recipient).balance()],
                &ProgramCatalog::default(),
                None,
                AsyncDelivery::default(),
            )
            .await
            .unwrap();
        assert!(matches!(
            served.lock().unwrap().submitted.as_slice(),
            [
                LeeTransaction::PrivacyPreserving(_),
                LeeTransaction::PrivacyPreserving(_)
            ]
        ));
    }

    #[tokio::test]
    async fn a_rescan_discovers_a_private_pda_below_the_cursor_and_keeps_every_other_record() {
        let (mut wallet, home, _sequencer, _served, pda, pda_kind) =
            wallet_past_an_undiscovered_pda().await;
        let cache_path = home.path().join("storage.nullifiers");
        let cache = std::fs::read(&cache_path).unwrap();
        let mut expected = Storage::from_path(&wallet.storage_path, "password")
            .unwrap()
            .0;
        expected
            .key_chain_mut()
            .insert_private_account(pda, pda_kind, Account::funded(90))
            .unwrap();

        wallet.rescan_private_accounts().await.unwrap();

        assert_eq!(wallet.storage, expected);
        assert_eq!(
            Storage::from_path(&wallet.storage_path, "password")
                .unwrap()
                .0,
            expected
        );
        assert_eq!(std::fs::read(&cache_path).unwrap(), cache);
    }

    #[tokio::test]
    async fn an_incomplete_rescan_leaves_the_account_records_unchanged() {
        let (mut wallet, _home, _sequencer, served, ..) = wallet_past_an_undiscovered_pda().await;
        let recorded = Storage::from_path(&wallet.storage_path, "password")
            .unwrap()
            .0;
        let history = served.lock().unwrap().blocks.clone();

        for remaining in [[0, 2], [0, 1]] {
            served.lock().unwrap().blocks = remaining.map(|i| history[i].clone()).into();

            assert!(wallet.rescan_private_accounts().await.is_err());
            assert_eq!(wallet.storage, recorded);
            assert_eq!(
                Storage::from_path(&wallet.storage_path, "password")
                    .unwrap()
                    .0,
                recorded
            );
        }
    }
}
