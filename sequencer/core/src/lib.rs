use std::{path::Path, time::Instant};

use anyhow::{Context as _, Result, anyhow};
use bedrock_client::SignedMantleTx;
#[cfg(feature = "testnet")]
use common::PINATA_BASE58;
use common::{
    HashType,
    block::{BedrockStatus, Block, HashableBlockData},
    transaction::NSSATransaction,
};
use config::SequencerConfig;
use log::{error, info, warn};
use logos_blockchain_key_management_system_service::keys::{ED25519_SECRET_KEY_SIZE, Ed25519Key};
use mempool::{MemPool, MemPoolHandle};
#[cfg(feature = "mock")]
pub use mock::SequencerCoreWithMockClients;
pub use storage::error::DbError;

use crate::{
    block_settlement_client::{BlockSettlementClient, BlockSettlementClientTrait, MsgId},
    block_store::SequencerStore,
    indexer_client::{IndexerClient, IndexerClientTrait},
};

pub mod block_settlement_client;
pub mod block_store;
pub mod config;
pub mod indexer_client;

#[cfg(feature = "mock")]
pub mod mock;

pub struct SequencerCore<
    BC: BlockSettlementClientTrait = BlockSettlementClient,
    IC: IndexerClientTrait = IndexerClient,
> {
    state: nssa::V02State,
    store: SequencerStore,
    mempool: MemPool<NSSATransaction>,
    sequencer_config: SequencerConfig,
    chain_height: u64,
    block_settlement_client: BC,
    indexer_client: IC,
}

impl<BC: BlockSettlementClientTrait, IC: IndexerClientTrait> SequencerCore<BC, IC> {
    /// Starts the sequencer using the provided configuration.
    /// If an existing database is found, the sequencer state is loaded from it and
    /// assumed to represent the correct latest state consistent with Bedrock-finalized data.
    /// If no database is found, the sequencer performs a fresh start from genesis,
    /// initializing its state with the accounts defined in the configuration file.
    pub async fn start_from_config(
        config: SequencerConfig,
    ) -> (Self, MemPoolHandle<NSSATransaction>) {
        let hashable_data = HashableBlockData {
            block_id: config.genesis_id,
            transactions: vec![],
            prev_block_hash: HashType([0; 32]),
            timestamp: 0,
        };

        let signing_key = nssa::PrivateKey::try_new(config.signing_key).unwrap();
        let genesis_parent_msg_id = [0; 32];
        let genesis_block = hashable_data.into_pending_block(&signing_key, genesis_parent_msg_id);

        let bedrock_signing_key =
            load_or_create_signing_key(&config.home.join("bedrock_signing_key"))
                .expect("Failed to load or create bedrock signing key");

        let block_settlement_client = BC::new(&config.bedrock_config, bedrock_signing_key)
            .expect("Failed to initialize Block Settlement Client");

        let indexer_client = IC::new(&config.indexer_rpc_url)
            .await
            .expect("Failed to create Indexer Client");

        let (_tx, genesis_msg_id) = block_settlement_client
            .create_inscribe_tx(&genesis_block)
            .expect("Failed to create inscribe tx for genesis block");

        // Sequencer should panic if unable to open db,
        // as fixing this issue may require actions non-native to program scope
        let store = SequencerStore::open_db_with_genesis(
            &config.home.join("rocksdb"),
            &genesis_block,
            genesis_msg_id.into(),
            signing_key,
        )
        .unwrap();
        let latest_block_meta = store
            .latest_block_meta()
            .expect("Failed to read latest block meta from store");

        #[cfg_attr(not(feature = "testnet"), allow(unused_mut))]
        let mut state = if let Some(state) = store.get_nssa_state() {
            info!("Found local database. Loading state and pending blocks from it.");
            state
        } else {
            info!(
                "No database found when starting the sequencer. Creating a fresh new with the initial data in config"
            );
            let initial_commitments: Vec<nssa_core::Commitment> = config
                .initial_commitments
                .iter()
                .map(|init_comm_data| {
                    let npk = &init_comm_data.npk;

                    let mut acc = init_comm_data.account.clone();

                    acc.program_owner =
                        nssa::program::Program::authenticated_transfer_program().id();

                    nssa_core::Commitment::new(npk, &acc)
                })
                .collect();

            let init_accs: Vec<(nssa::AccountId, u128)> = config
                .initial_accounts
                .iter()
                .map(|acc_data| (acc_data.account_id, acc_data.balance))
                .collect();

            nssa::V02State::new_with_genesis_accounts(&init_accs, &initial_commitments)
        };

        #[cfg(feature = "testnet")]
        state.add_pinata_program(PINATA_BASE58.parse().unwrap());

        let (mempool, mempool_handle) = MemPool::new(config.mempool_max_size);

        let sequencer_core = Self {
            state,
            store,
            mempool,
            chain_height: latest_block_meta.id,
            sequencer_config: config,
            block_settlement_client,
            indexer_client,
        };

        (sequencer_core, mempool_handle)
    }

    fn execute_check_transaction_on_state(
        &mut self,
        tx: NSSATransaction,
    ) -> Result<NSSATransaction, nssa::error::NssaError> {
        match &tx {
            NSSATransaction::Public(tx) => self.state.transition_from_public_transaction(tx),
            NSSATransaction::PrivacyPreserving(tx) => self
                .state
                .transition_from_privacy_preserving_transaction(tx),
            NSSATransaction::ProgramDeployment(tx) => self
                .state
                .transition_from_program_deployment_transaction(tx),
        }
        .inspect_err(|err| warn!("Error at transition {err:#?}"))?;

        Ok(tx)
    }

    pub async fn produce_new_block(&mut self) -> Result<u64> {
        let (tx, _msg_id) = self
            .produce_new_block_with_mempool_transactions()
            .context("Failed to produce new block with mempool transactions")?;
        match self
            .block_settlement_client
            .submit_inscribe_tx_to_bedrock(tx)
            .await
        {
            Ok(()) => {}
            Err(err) => {
                error!("Failed to post block data to Bedrock with error: {err:#}");
            }
        }

        Ok(self.chain_height)
    }

    /// Produces new block from transactions in mempool and packs it into a `SignedMantleTx`.
    pub fn produce_new_block_with_mempool_transactions(
        &mut self,
    ) -> Result<(SignedMantleTx, MsgId)> {
        let now = Instant::now();

        let new_block_height = self
            .chain_height
            .checked_add(1)
            .with_context(|| format!("Max block height reached: {}", self.chain_height))?;

        let mut valid_transactions = vec![];

        let max_block_size = usize::try_from(self.sequencer_config.max_block_size.as_u64())
            .expect("`max_block_size` should fit into usize");

        let latest_block_meta = self
            .store
            .latest_block_meta()
            .context("Failed to get latest block meta from store")?;

        let curr_time = u64::try_from(chrono::Utc::now().timestamp_millis())
            .expect("Timestamp must be positive");

        while let Some(tx) = self.mempool.pop() {
            let tx_hash = tx.hash();

            // Check if block size exceeds limit
            let temp_valid_transactions =
                [valid_transactions.as_slice(), std::slice::from_ref(&tx)].concat();
            let temp_hashable_data = HashableBlockData {
                block_id: new_block_height,
                transactions: temp_valid_transactions,
                prev_block_hash: latest_block_meta.hash,
                timestamp: curr_time,
            };

            let block_size = borsh::to_vec(&temp_hashable_data)
                .context("Failed to serialize block for size check")?
                .len();

            if block_size > max_block_size {
                // Block would exceed size limit, remove last transaction and push back
                warn!(
                    "Transaction with hash {tx_hash} deferred to next block: \
                     block size {block_size} bytes would exceed limit of {max_block_size} bytes",
                );

                self.mempool.push_front(tx);
                break;
            }

            match self.execute_check_transaction_on_state(tx) {
                Ok(valid_tx) => {
                    valid_transactions.push(valid_tx);

                    info!("Validated transaction with hash {tx_hash}, including it in block");

                    if valid_transactions.len() >= self.sequencer_config.max_num_tx_in_block {
                        break;
                    }
                }
                Err(err) => {
                    error!(
                        "Transaction with hash {tx_hash} failed execution check with error: {err:#?}, skipping it",
                    );
                    // TODO: Probably need to handle unsuccessful transaction execution?
                }
            }
        }

        let hashable_data = HashableBlockData {
            block_id: new_block_height,
            transactions: valid_transactions,
            prev_block_hash: latest_block_meta.hash,
            timestamp: curr_time,
        };

        let block = hashable_data
            .clone()
            .into_pending_block(self.store.signing_key(), latest_block_meta.msg_id);

        let (tx, msg_id) = self
            .block_settlement_client
            .create_inscribe_tx(&block)
            .with_context(|| {
                format!(
                    "Failed to create inscribe transaction for block with id {}",
                    block.header.block_id
                )
            })?;

        self.store.update(&block, msg_id.into(), &self.state)?;

        self.chain_height = new_block_height;

        log::info!(
            "Created block with {} transactions in {} seconds",
            hashable_data.transactions.len(),
            now.elapsed().as_secs()
        );
        Ok((tx, msg_id))
    }

    pub const fn state(&self) -> &nssa::V02State {
        &self.state
    }

    pub const fn block_store(&self) -> &SequencerStore {
        &self.store
    }

    pub const fn chain_height(&self) -> u64 {
        self.chain_height
    }

    pub const fn sequencer_config(&self) -> &SequencerConfig {
        &self.sequencer_config
    }

    /// Deletes finalized blocks from the sequencer's pending block list.
    /// This method must be called when new blocks are finalized on Bedrock.
    /// All pending blocks with an ID less than or equal to `last_finalized_block_id`
    /// are removed from the database.
    pub fn clean_finalized_blocks_from_db(&mut self, last_finalized_block_id: u64) -> Result<()> {
        self.get_pending_blocks()?
            .iter()
            .map(|block| block.header.block_id)
            .min()
            .map_or(Ok(()), |first_pending_block_id| {
                info!("Clearing pending blocks up to id: {last_finalized_block_id}");
                // TODO: Delete blocks instead of marking them as finalized.
                // Current approach is used because we still have `GetBlockDataRequest`.
                (first_pending_block_id..=last_finalized_block_id)
                    .try_for_each(|id| self.store.mark_block_as_finalized(id))
            })
    }

    /// Returns the list of stored pending blocks.
    pub fn get_pending_blocks(&self) -> Result<Vec<Block>> {
        Ok(self
            .store
            .get_all_blocks()
            .collect::<Result<Vec<Block>>>()?
            .into_iter()
            .filter(|block| matches!(block.bedrock_status, BedrockStatus::Pending))
            .collect())
    }

    pub fn block_settlement_client(&self) -> BC {
        self.block_settlement_client.clone()
    }

    pub fn indexer_client(&self) -> IC {
        self.indexer_client.clone()
    }
}

/// Load signing key from file or generate a new one if it doesn't exist.
fn load_or_create_signing_key(path: &Path) -> Result<Ed25519Key> {
    if path.exists() {
        let key_bytes = std::fs::read(path)?;

        let key_array: [u8; ED25519_SECRET_KEY_SIZE] = key_bytes
            .try_into()
            .map_err(|_bytes| anyhow!("Found key with incorrect length"))?;

        Ok(Ed25519Key::from_bytes(&key_array))
    } else {
        let mut key_bytes = [0_u8; ED25519_SECRET_KEY_SIZE];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key_bytes);
        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, key_bytes)?;
        Ok(Ed25519Key::from_bytes(&key_bytes))
    }
}

#[cfg(test)]
#[cfg(feature = "mock")]
mod tests {
    #![expect(clippy::shadow_unrelated, reason = "We don't care about it in tests")]

    use std::{pin::pin, str::FromStr as _, time::Duration};

    use base58::ToBase58 as _;
    use bedrock_client::BackoffConfig;
    use common::{
        block::AccountInitialData, test_utils::sequencer_sign_key_for_testing,
        transaction::NSSATransaction,
    };
    use logos_blockchain_core::mantle::ops::channel::ChannelId;
    use mempool::MemPoolHandle;
    use nssa::{AccountId, PrivateKey};

    use crate::{
        config::{BedrockConfig, SequencerConfig},
        mock::SequencerCoreWithMockClients,
    };

    fn setup_sequencer_config_variable_initial_accounts(
        initial_accounts: Vec<AccountInitialData>,
    ) -> SequencerConfig {
        let tempdir = tempfile::tempdir().unwrap();
        let home = tempdir.path().to_path_buf();

        SequencerConfig {
            home,
            genesis_id: 1,
            is_genesis_random: false,
            max_num_tx_in_block: 10,
            max_block_size: bytesize::ByteSize::mib(1),
            mempool_max_size: 10000,
            block_create_timeout: Duration::from_secs(1),
            initial_accounts,
            initial_commitments: vec![],
            signing_key: *sequencer_sign_key_for_testing().value(),
            bedrock_config: BedrockConfig {
                backoff: BackoffConfig {
                    start_delay: Duration::from_millis(100),
                    max_retries: 5,
                },
                channel_id: ChannelId::from([0; 32]),
                node_url: "http://not-used-in-unit-tests".parse().unwrap(),
                auth: None,
            },
            retry_pending_blocks_timeout: Duration::from_secs(60 * 4),
            indexer_rpc_url: "ws://localhost:8779".parse().unwrap(),
        }
    }

    fn setup_sequencer_config() -> SequencerConfig {
        let acc1_account_id: Vec<u8> = vec![
            148, 179, 206, 253, 199, 51, 82, 86, 232, 2, 152, 122, 80, 243, 54, 207, 237, 112, 83,
            153, 44, 59, 204, 49, 128, 84, 160, 227, 216, 149, 97, 102,
        ];

        let acc2_account_id: Vec<u8> = vec![
            30, 145, 107, 3, 207, 73, 192, 230, 160, 63, 238, 207, 18, 69, 54, 216, 103, 244, 92,
            94, 124, 248, 42, 16, 141, 19, 119, 18, 14, 226, 140, 204,
        ];

        let initial_acc1 = AccountInitialData {
            account_id: AccountId::from_str(&acc1_account_id.to_base58()).unwrap(),
            balance: 10000,
        };

        let initial_acc2 = AccountInitialData {
            account_id: AccountId::from_str(&acc2_account_id.to_base58()).unwrap(),
            balance: 20000,
        };

        let initial_accounts = vec![initial_acc1, initial_acc2];

        setup_sequencer_config_variable_initial_accounts(initial_accounts)
    }

    fn create_signing_key_for_account1() -> nssa::PrivateKey {
        nssa::PrivateKey::try_new([1; 32]).unwrap()
    }

    fn create_signing_key_for_account2() -> nssa::PrivateKey {
        nssa::PrivateKey::try_new([2; 32]).unwrap()
    }

    async fn common_setup() -> (SequencerCoreWithMockClients, MemPoolHandle<NSSATransaction>) {
        let config = setup_sequencer_config();
        common_setup_with_config(config).await
    }

    async fn common_setup_with_config(
        config: SequencerConfig,
    ) -> (SequencerCoreWithMockClients, MemPoolHandle<NSSATransaction>) {
        let (mut sequencer, mempool_handle) =
            SequencerCoreWithMockClients::start_from_config(config).await;

        let tx = common::test_utils::produce_dummy_empty_transaction();
        mempool_handle.push(tx).await.unwrap();

        sequencer
            .produce_new_block_with_mempool_transactions()
            .unwrap();

        (sequencer, mempool_handle)
    }

    #[tokio::test]
    async fn start_from_config() {
        let config = setup_sequencer_config();
        let (sequencer, _mempool_handle) =
            SequencerCoreWithMockClients::start_from_config(config.clone()).await;

        assert_eq!(sequencer.chain_height, config.genesis_id);
        assert_eq!(sequencer.sequencer_config.max_num_tx_in_block, 10);

        let acc1_account_id = config.initial_accounts[0].account_id;
        let acc2_account_id = config.initial_accounts[1].account_id;

        let balance_acc_1 = sequencer.state.get_account_by_id(acc1_account_id).balance;
        let balance_acc_2 = sequencer.state.get_account_by_id(acc2_account_id).balance;

        assert_eq!(10000, balance_acc_1);
        assert_eq!(20000, balance_acc_2);
    }

    #[tokio::test]
    async fn start_different_intial_accounts_balances() {
        let acc1_account_id: Vec<u8> = vec![
            27, 132, 197, 86, 123, 18, 100, 64, 153, 93, 62, 213, 170, 186, 5, 101, 215, 30, 24,
            52, 96, 72, 25, 255, 156, 23, 245, 233, 213, 221, 7, 143,
        ];

        let acc2_account_id: Vec<u8> = vec![
            77, 75, 108, 209, 54, 16, 50, 202, 155, 210, 174, 185, 217, 0, 170, 77, 69, 217, 234,
            216, 10, 201, 66, 51, 116, 196, 81, 167, 37, 77, 7, 102,
        ];

        let initial_acc1 = AccountInitialData {
            account_id: AccountId::from_str(&acc1_account_id.to_base58()).unwrap(),
            balance: 10000,
        };

        let initial_acc2 = AccountInitialData {
            account_id: AccountId::from_str(&acc2_account_id.to_base58()).unwrap(),
            balance: 20000,
        };

        let initial_accounts = vec![initial_acc1, initial_acc2];

        let config = setup_sequencer_config_variable_initial_accounts(initial_accounts);
        let (sequencer, _mempool_handle) =
            SequencerCoreWithMockClients::start_from_config(config.clone()).await;

        let acc1_account_id = config.initial_accounts[0].account_id;
        let acc2_account_id = config.initial_accounts[1].account_id;

        assert_eq!(
            10000,
            sequencer.state.get_account_by_id(acc1_account_id).balance
        );
        assert_eq!(
            20000,
            sequencer.state.get_account_by_id(acc2_account_id).balance
        );
    }

    #[test]
    fn transaction_pre_check_pass() {
        let tx = common::test_utils::produce_dummy_empty_transaction();
        let result = tx.transaction_stateless_check();

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn transaction_pre_check_native_transfer_valid() {
        let (sequencer, _mempool_handle) = common_setup().await;

        let acc1 = sequencer.sequencer_config.initial_accounts[0].account_id;
        let acc2 = sequencer.sequencer_config.initial_accounts[1].account_id;

        let sign_key1 = create_signing_key_for_account1();

        let tx = common::test_utils::create_transaction_native_token_transfer(
            acc1, 0, acc2, 10, &sign_key1,
        );
        let result = tx.transaction_stateless_check();

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn transaction_pre_check_native_transfer_other_signature() {
        let (mut sequencer, _mempool_handle) = common_setup().await;

        let acc1 = sequencer.sequencer_config.initial_accounts[0].account_id;
        let acc2 = sequencer.sequencer_config.initial_accounts[1].account_id;

        let sign_key2 = create_signing_key_for_account2();

        let tx = common::test_utils::create_transaction_native_token_transfer(
            acc1, 0, acc2, 10, &sign_key2,
        );

        // Signature is valid, stateless check pass
        let tx = tx.transaction_stateless_check().unwrap();

        // Signature is not from sender. Execution fails
        let result = sequencer.execute_check_transaction_on_state(tx);

        assert!(matches!(
            result,
            Err(nssa::error::NssaError::ProgramExecutionFailed(_))
        ));
    }

    #[tokio::test]
    async fn transaction_pre_check_native_transfer_sent_too_much() {
        let (mut sequencer, _mempool_handle) = common_setup().await;

        let acc1 = sequencer.sequencer_config.initial_accounts[0].account_id;
        let acc2 = sequencer.sequencer_config.initial_accounts[1].account_id;

        let sign_key1 = create_signing_key_for_account1();

        let tx = common::test_utils::create_transaction_native_token_transfer(
            acc1, 0, acc2, 10_000_000, &sign_key1,
        );

        let result = tx.transaction_stateless_check();

        // Passed pre-check
        assert!(result.is_ok());

        let result = sequencer.execute_check_transaction_on_state(result.unwrap());
        let is_failed_at_balance_mismatch = matches!(
            result.err().unwrap(),
            nssa::error::NssaError::ProgramExecutionFailed(_)
        );

        assert!(is_failed_at_balance_mismatch);
    }

    #[tokio::test]
    async fn transaction_execute_native_transfer() {
        let (mut sequencer, _mempool_handle) = common_setup().await;

        let acc1 = sequencer.sequencer_config.initial_accounts[0].account_id;
        let acc2 = sequencer.sequencer_config.initial_accounts[1].account_id;

        let sign_key1 = create_signing_key_for_account1();

        let tx = common::test_utils::create_transaction_native_token_transfer(
            acc1, 0, acc2, 100, &sign_key1,
        );

        sequencer.execute_check_transaction_on_state(tx).unwrap();

        let bal_from = sequencer.state.get_account_by_id(acc1).balance;
        let bal_to = sequencer.state.get_account_by_id(acc2).balance;

        assert_eq!(bal_from, 9900);
        assert_eq!(bal_to, 20100);
    }

    #[tokio::test]
    async fn push_tx_into_mempool_blocks_until_mempool_is_full() {
        let config = SequencerConfig {
            mempool_max_size: 1,
            ..setup_sequencer_config()
        };
        let (mut sequencer, mempool_handle) = common_setup_with_config(config).await;

        let tx = common::test_utils::produce_dummy_empty_transaction();

        // Fill the mempool
        mempool_handle.push(tx.clone()).await.unwrap();

        // Check that pushing another transaction will block
        let mut push_fut = pin!(mempool_handle.push(tx.clone()));
        let poll = futures::poll!(push_fut.as_mut());
        assert!(poll.is_pending());

        // Empty the mempool by producing a block
        sequencer
            .produce_new_block_with_mempool_transactions()
            .unwrap();

        // Resolve the pending push
        assert!(push_fut.await.is_ok());
    }

    #[tokio::test]
    async fn produce_new_block_with_mempool_transactions() {
        let (mut sequencer, mempool_handle) = common_setup().await;
        let genesis_height = sequencer.chain_height;

        let tx = common::test_utils::produce_dummy_empty_transaction();
        mempool_handle.push(tx).await.unwrap();

        let result = sequencer.produce_new_block_with_mempool_transactions();
        assert!(result.is_ok());
        assert_eq!(sequencer.chain_height, genesis_height + 1);
    }

    #[tokio::test]
    async fn replay_transactions_are_rejected_in_the_same_block() {
        let (mut sequencer, mempool_handle) = common_setup().await;

        let acc1 = sequencer.sequencer_config.initial_accounts[0].account_id;
        let acc2 = sequencer.sequencer_config.initial_accounts[1].account_id;

        let sign_key1 = create_signing_key_for_account1();

        let tx = common::test_utils::create_transaction_native_token_transfer(
            acc1, 0, acc2, 100, &sign_key1,
        );

        let tx_original = tx.clone();
        let tx_replay = tx.clone();
        // Pushing two copies of the same tx to the mempool
        mempool_handle.push(tx_original).await.unwrap();
        mempool_handle.push(tx_replay).await.unwrap();

        // Create block
        sequencer
            .produce_new_block_with_mempool_transactions()
            .unwrap();
        let block = sequencer
            .store
            .get_block_at_id(sequencer.chain_height)
            .unwrap()
            .unwrap();

        // Only one should be included in the block
        assert_eq!(block.body.transactions, vec![tx.clone()]);
    }

    #[tokio::test]
    async fn replay_transactions_are_rejected_in_different_blocks() {
        let (mut sequencer, mempool_handle) = common_setup().await;

        let acc1 = sequencer.sequencer_config.initial_accounts[0].account_id;
        let acc2 = sequencer.sequencer_config.initial_accounts[1].account_id;

        let sign_key1 = create_signing_key_for_account1();

        let tx = common::test_utils::create_transaction_native_token_transfer(
            acc1, 0, acc2, 100, &sign_key1,
        );

        // The transaction should be included the first time
        mempool_handle.push(tx.clone()).await.unwrap();
        sequencer
            .produce_new_block_with_mempool_transactions()
            .unwrap();
        let block = sequencer
            .store
            .get_block_at_id(sequencer.chain_height)
            .unwrap()
            .unwrap();
        assert_eq!(block.body.transactions, vec![tx.clone()]);

        // Add same transaction should fail
        mempool_handle.push(tx.clone()).await.unwrap();
        sequencer
            .produce_new_block_with_mempool_transactions()
            .unwrap();
        let block = sequencer
            .store
            .get_block_at_id(sequencer.chain_height)
            .unwrap()
            .unwrap();
        assert!(block.body.transactions.is_empty());
    }

    #[tokio::test]
    async fn restart_from_storage() {
        let config = setup_sequencer_config();
        let acc1_account_id = config.initial_accounts[0].account_id;
        let acc2_account_id = config.initial_accounts[1].account_id;
        let balance_to_move = 13;

        // In the following code block a transaction will be processed that moves `balance_to_move`
        // from `acc_1` to `acc_2`. The block created with that transaction will be kept stored in
        // the temporary directory for the block storage of this test.
        {
            let (mut sequencer, mempool_handle) =
                SequencerCoreWithMockClients::start_from_config(config.clone()).await;
            let signing_key = PrivateKey::try_new([1; 32]).unwrap();

            let tx = common::test_utils::create_transaction_native_token_transfer(
                acc1_account_id,
                0,
                acc2_account_id,
                balance_to_move,
                &signing_key,
            );

            mempool_handle.push(tx.clone()).await.unwrap();
            sequencer
                .produce_new_block_with_mempool_transactions()
                .unwrap();
            let block = sequencer
                .store
                .get_block_at_id(sequencer.chain_height)
                .unwrap()
                .unwrap();
            assert_eq!(block.body.transactions, vec![tx.clone()]);
        }

        // Instantiating a new sequencer from the same config. This should load the existing block
        // with the above transaction and update the state to reflect that.
        let (sequencer, _mempool_handle) =
            SequencerCoreWithMockClients::start_from_config(config.clone()).await;
        let balance_acc_1 = sequencer.state.get_account_by_id(acc1_account_id).balance;
        let balance_acc_2 = sequencer.state.get_account_by_id(acc2_account_id).balance;

        // Balances should be consistent with the stored block
        assert_eq!(
            balance_acc_1,
            config.initial_accounts[0].balance - balance_to_move
        );
        assert_eq!(
            balance_acc_2,
            config.initial_accounts[1].balance + balance_to_move
        );
    }

    #[tokio::test]
    async fn get_pending_blocks() {
        let config = setup_sequencer_config();
        let (mut sequencer, _mempool_handle) =
            SequencerCoreWithMockClients::start_from_config(config).await;
        sequencer
            .produce_new_block_with_mempool_transactions()
            .unwrap();
        sequencer
            .produce_new_block_with_mempool_transactions()
            .unwrap();
        sequencer
            .produce_new_block_with_mempool_transactions()
            .unwrap();
        assert_eq!(sequencer.get_pending_blocks().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn delete_blocks() {
        let config = setup_sequencer_config();
        let (mut sequencer, _mempool_handle) =
            SequencerCoreWithMockClients::start_from_config(config).await;
        sequencer
            .produce_new_block_with_mempool_transactions()
            .unwrap();
        sequencer
            .produce_new_block_with_mempool_transactions()
            .unwrap();
        sequencer
            .produce_new_block_with_mempool_transactions()
            .unwrap();

        let last_finalized_block = 3;
        sequencer
            .clean_finalized_blocks_from_db(last_finalized_block)
            .unwrap();

        assert_eq!(sequencer.get_pending_blocks().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn produce_block_with_correct_prev_meta_after_restart() {
        let config = setup_sequencer_config();
        let acc1_account_id = config.initial_accounts[0].account_id;
        let acc2_account_id = config.initial_accounts[1].account_id;

        // Step 1: Create initial database with some block metadata
        let expected_prev_meta = {
            let (mut sequencer, mempool_handle) =
                SequencerCoreWithMockClients::start_from_config(config.clone()).await;

            let signing_key = PrivateKey::try_new([1; 32]).unwrap();

            // Add a transaction and produce a block to set up block metadata
            let tx = common::test_utils::create_transaction_native_token_transfer(
                acc1_account_id,
                0,
                acc2_account_id,
                100,
                &signing_key,
            );

            mempool_handle.push(tx).await.unwrap();
            sequencer
                .produce_new_block_with_mempool_transactions()
                .unwrap();

            // Get the metadata of the last block produced
            sequencer.store.latest_block_meta().unwrap()
        };

        // Step 2: Restart sequencer from the same storage
        let (mut sequencer, mempool_handle) =
            SequencerCoreWithMockClients::start_from_config(config.clone()).await;

        // Step 3: Submit a new transaction
        let signing_key = PrivateKey::try_new([1; 32]).unwrap();
        let tx = common::test_utils::create_transaction_native_token_transfer(
            acc1_account_id,
            1, // Next nonce
            acc2_account_id,
            50,
            &signing_key,
        );

        mempool_handle.push(tx.clone()).await.unwrap();

        // Step 4: Produce new block
        sequencer
            .produce_new_block_with_mempool_transactions()
            .unwrap();

        // Step 5: Verify the new block has correct previous block metadata
        let new_block = sequencer
            .store
            .get_block_at_id(sequencer.chain_height)
            .unwrap()
            .unwrap();

        assert_eq!(
            new_block.header.prev_block_hash, expected_prev_meta.hash,
            "New block's prev_block_hash should match the stored metadata hash"
        );
        assert_eq!(
            new_block.bedrock_parent_id, expected_prev_meta.msg_id,
            "New block's bedrock_parent_id should match the stored metadata msg_id"
        );
        assert_eq!(
            new_block.body.transactions,
            vec![tx],
            "New block should contain the submitted transaction"
        );
    }

    #[tokio::test]
    async fn start_from_config_uses_db_height_not_config_genesis() {
        let mut config = setup_sequencer_config();
        let original_genesis_id = config.genesis_id;

        // Step 1: Create initial database and produce some blocks
        let expected_chain_height = {
            let (mut sequencer, mempool_handle) =
                SequencerCoreWithMockClients::start_from_config(config.clone()).await;

            // Verify we start with the genesis_id from config
            assert_eq!(sequencer.chain_height, original_genesis_id);

            // Produce multiple blocks to advance chain height
            let tx = common::test_utils::produce_dummy_empty_transaction();
            mempool_handle.push(tx).await.unwrap();
            sequencer
                .produce_new_block_with_mempool_transactions()
                .unwrap();

            let tx = common::test_utils::produce_dummy_empty_transaction();
            mempool_handle.push(tx).await.unwrap();
            sequencer
                .produce_new_block_with_mempool_transactions()
                .unwrap();

            // Return the current chain height (should be genesis_id + 2)
            sequencer.chain_height
        };

        // Step 2: Modify the config to have a DIFFERENT genesis_id
        let different_genesis_id = original_genesis_id + 100;
        config.genesis_id = different_genesis_id;

        // Step 3: Restart sequencer with the modified config (different genesis_id)
        let (sequencer, _mempool_handle) =
            SequencerCoreWithMockClients::start_from_config(config.clone()).await;

        // Step 4: Verify chain_height comes from database, NOT from the new config.genesis_id
        assert_eq!(
            sequencer.chain_height, expected_chain_height,
            "Chain height should be loaded from database metadata, not config.genesis_id"
        );
        assert_ne!(
            sequencer.chain_height, different_genesis_id,
            "Chain height should NOT match the modified config.genesis_id"
        );
    }
}
