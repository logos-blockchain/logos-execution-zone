use std::{collections::{BTreeMap, HashSet}, sync::Arc};

use chrono;
use common::transaction::{NSSATransaction, TransactionMalformationError};
use jsonrpsee::{
    core::async_trait,
    types::{ErrorCode, ErrorObjectOwned},
};
use log::warn;
use mempool::MemPoolHandle;
use nssa::{self, program::Program};
use sequencer_core::{
    DbError, SequencerCore, block_settlement_client::BlockSettlementClientTrait,
    indexer_client::IndexerClientTrait,
};
use sequencer_service_protocol::{
    Account, AccountId, Block, BlockId, Commitment, HashType, MembershipProof, Nonce, ProgramId,
};
use tokio::sync::Mutex;

const NOT_FOUND_ERROR_CODE: i32 = -31999;

pub struct SequencerService<BC: BlockSettlementClientTrait, IC: IndexerClientTrait> {
    sequencer: Arc<Mutex<SequencerCore<BC, IC>>>,
    mempool_handle: MemPoolHandle<NSSATransaction>,
    max_block_size: u64,
    pending_txs: Arc<Mutex<HashSet<HashType>>>,
}

impl<BC: BlockSettlementClientTrait, IC: IndexerClientTrait> SequencerService<BC, IC> {
    pub fn new(
        sequencer: Arc<Mutex<SequencerCore<BC, IC>>>,
        mempool_handle: MemPoolHandle<NSSATransaction>,
        max_block_size: u64,
    ) -> Self {
        Self {
            sequencer,
            mempool_handle,
            max_block_size,
            pending_txs: Arc::new(Mutex::new(HashSet::new())),
        }
    }
}

#[async_trait]
impl<BC: BlockSettlementClientTrait + Send + 'static, IC: IndexerClientTrait + Send + 'static>
    sequencer_service_rpc::RpcServer for SequencerService<BC, IC>
{
    async fn send_transaction(&self, tx: NSSATransaction) -> Result<HashType, ErrorObjectOwned> {
        // Reserve ~200 bytes for block header overhead
        const BLOCK_HEADER_OVERHEAD: u64 = 200;

        let tx_hash = tx.hash();

        let encoded_tx = borsh::to_vec(&tx).map_err(|_| {
            ErrorObjectOwned::from(TransactionMalformationError::FailedToDecode { tx: tx_hash })
        })?;
        let tx_size = u64::try_from(encoded_tx.len()).unwrap_or(u64::MAX);

        let max_tx_size = self.max_block_size.saturating_sub(BLOCK_HEADER_OVERHEAD);

        if tx_size > max_tx_size {
            return Err(ErrorObjectOwned::from(
                TransactionMalformationError::TransactionTooLarge {
                    size: encoded_tx.len(),
                    max: usize::try_from(max_tx_size).unwrap_or(usize::MAX),
                },
            ));
        }

        let authenticated_tx = tx
            .transaction_stateless_check()
            .inspect_err(|err| warn!("Error at pre_check {err:#?}"))
            .map_err(ErrorObjectOwned::from)?;

        self.mempool_handle
            .push(authenticated_tx)
            .await
            .expect("Mempool is closed, this is a bug");

        self.pending_txs.lock().await.insert(tx_hash);

        Ok(tx_hash)
    }

    async fn check_health(&self) -> Result<(), ErrorObjectOwned> {
        Ok(())
    }

    async fn get_block(&self, block_id: BlockId) -> Result<Option<Block>, ErrorObjectOwned> {
        let sequencer = self.sequencer.lock().await;
        sequencer
            .block_store()
            .get_block_at_id(block_id)
            .map_err(|err| internal_error(&err))
    }

    async fn get_block_range(
        &self,
        start_block_id: BlockId,
        end_block_id: BlockId,
    ) -> Result<Vec<Block>, ErrorObjectOwned> {
        let sequencer = self.sequencer.lock().await;
        (start_block_id..=end_block_id)
            .map(|block_id| {
                let block = sequencer
                    .block_store()
                    .get_block_at_id(block_id)
                    .map_err(|err| internal_error(&err))?;
                block.ok_or_else(|| {
                    ErrorObjectOwned::owned(
                        NOT_FOUND_ERROR_CODE,
                        format!("Block with id {block_id} not found"),
                        None::<()>,
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()
    }

    async fn get_last_block_id(&self) -> Result<BlockId, ErrorObjectOwned> {
        let sequencer = self.sequencer.lock().await;
        Ok(sequencer.chain_height())
    }

    async fn get_account_balance(&self, account_id: AccountId) -> Result<u128, ErrorObjectOwned> {
        let sequencer = self.sequencer.lock().await;
        let account = sequencer.state().get_account_by_id(account_id);
        Ok(account.balance)
    }

    async fn get_transaction(
        &self,
        tx_hash: HashType,
    ) -> Result<Option<NSSATransaction>, ErrorObjectOwned> {
        let sequencer = self.sequencer.lock().await;
        Ok(sequencer.block_store().get_transaction_by_hash(tx_hash))
    }

    async fn get_transaction_receipt(
        &self,
        tx_hash: HashType,
    ) -> Result<common::receipt::TxReceipt, ErrorObjectOwned> {
        use common::receipt::{TxReceipt, TxStatus};

        // Check durable tiers under the sequencer lock, then release it before
        // touching `pending_txs` to preserve lock-ordering invariants.
        let terminal_receipt = {
            let sequencer = self.sequencer.lock().await;

            // 1. Rejected store: durable, survives restarts.
            if let Some(record) = sequencer.block_store().get_rejected_tx(tx_hash) {
                Some(TxReceipt {
                    tx_hash,
                    status: TxStatus::Rejected { reason: record.reason },
                    timestamp_ms: Some(record.timestamp_ms),
                })
            // 2. Block store: finalized and pending blocks.
            } else if let Some(block_id) = sequencer.block_store().get_block_id_for_tx(tx_hash) {
                let timestamp_ms = sequencer
                    .block_store()
                    .get_block_at_id(block_id)
                    .ok()
                    .flatten()
                    .map(|b| b.header.timestamp);
                Some(TxReceipt {
                    tx_hash,
                    status: TxStatus::Included { block_id },
                    timestamp_ms,
                })
            } else {
                None
            }
            // Sequencer lock released here.
        };

        if let Some(receipt) = terminal_receipt {
            // Lazy eviction: TX has reached a terminal state; prune it from the
            // pending set so `pending_txs` does not grow without bound.
            self.pending_txs.lock().await.remove(&tx_hash);
            return Ok(receipt);
        }

        // 3. Pending set: submitted to mempool but not yet in a block.
        if self.pending_txs.lock().await.contains(&tx_hash) {
            return Ok(TxReceipt { tx_hash, status: TxStatus::Pending, timestamp_ms: None });
        }

        // 4. Unknown: never submitted, invalid hash, or set was evicted.
        Ok(TxReceipt { tx_hash, status: TxStatus::Unknown, timestamp_ms: None })
    }

    async fn simulate_transaction(
        &self,
        tx: NSSATransaction,
    ) -> Result<common::simulation::SimulationResult, ErrorObjectOwned> {
        use common::simulation::SimulationResult;

        // 1. Stateless check -- no lock required.
        let tx = tx
            .transaction_stateless_check()
            .inspect_err(|err| warn!("simulate_transaction: stateless check failed: {err:#?}"))
            .map_err(ErrorObjectOwned::from)?;

        // 2. Clone state under lock, then release immediately.
        let (state_clone, block_id, timestamp_ms) = {
            let sequencer = self.sequencer.lock().await;
            let block_id = sequencer.chain_height() + 1;
            let timestamp_ms = u64::try_from(chrono::Utc::now().timestamp_millis())
                .expect("current timestamp must be positive");
            (sequencer.state().clone(), block_id, timestamp_ms)
        };
        // Lock is released here. Simulation runs concurrently with block production.

        // 3. Execute on the cloned state -- never committed.
        match tx.validate_on_state(&state_clone, block_id, timestamp_ms) {
            Ok(diff) => Ok(SimulationResult {
                success: true,
                error: None,
                accounts_modified: diff.public_diff().into_iter().collect(),
                nullifiers_created: diff.new_nullifiers().to_vec(),
                commitments_created: diff.new_commitments().to_vec(),
            }),
            Err(err) => Ok(SimulationResult {
                success: false,
                error: Some(err.to_string()),
                accounts_modified: vec![],
                nullifiers_created: vec![],
                commitments_created: vec![],
            }),
        }
    }

    async fn get_accounts_nonces(
        &self,
        account_ids: Vec<AccountId>,
    ) -> Result<Vec<Nonce>, ErrorObjectOwned> {
        let sequencer = self.sequencer.lock().await;
        let nonces = account_ids
            .into_iter()
            .map(|account_id| sequencer.state().get_account_by_id(account_id).nonce)
            .collect();
        Ok(nonces)
    }

    async fn get_proof_for_commitment(
        &self,
        commitment: Commitment,
    ) -> Result<Option<MembershipProof>, ErrorObjectOwned> {
        let sequencer = self.sequencer.lock().await;
        Ok(sequencer.state().get_proof_for_commitment(&commitment))
    }

    async fn get_account(&self, account_id: AccountId) -> Result<Account, ErrorObjectOwned> {
        let sequencer = self.sequencer.lock().await;
        Ok(sequencer.state().get_account_by_id(account_id))
    }

    async fn get_program_ids(&self) -> Result<BTreeMap<String, ProgramId>, ErrorObjectOwned> {
        let mut program_ids = BTreeMap::new();
        program_ids.insert(
            "authenticated_transfer".to_owned(),
            Program::authenticated_transfer_program().id(),
        );
        program_ids.insert("token".to_owned(), Program::token().id());
        program_ids.insert("pinata".to_owned(), Program::pinata().id());
        program_ids.insert("amm".to_owned(), Program::amm().id());
        program_ids.insert(
            "privacy_preserving_circuit".to_owned(),
            nssa::PRIVACY_PRESERVING_CIRCUIT_ID,
        );
        Ok(program_ids)
    }
}

fn internal_error(err: &DbError) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(ErrorCode::InternalError.code(), err.to_string(), None::<()>)
}

#[cfg(test)]
mod tests {
    #![expect(clippy::shadow_unrelated, reason = "We don't care about it in tests")]

    use std::{sync::Arc, time::Duration};

    use bedrock_client::BackoffConfig;
    use common::test_utils::sequencer_sign_key_for_testing;
    use jsonrpsee::types::ErrorCode;
    use logos_blockchain_core::mantle::ops::channel::ChannelId;
    use sequencer_core::{
        config::{BedrockConfig, SequencerConfig},
        mock::SequencerCoreWithMockClients,
    };
    use tokio::sync::Mutex;

    use super::*;

    fn test_config() -> SequencerConfig {
        let tempdir = tempfile::tempdir().unwrap();
        SequencerConfig {
            home: tempdir.into_path(),
            genesis_id: 1,
            is_genesis_random: false,
            max_num_tx_in_block: 10,
            max_block_size: bytesize::ByteSize::b(512),
            mempool_max_size: 10000,
            block_create_timeout: Duration::from_secs(1),
            signing_key: *sequencer_sign_key_for_testing().value(),
            bedrock_config: BedrockConfig {
                backoff: BackoffConfig {
                    start_delay: Duration::from_millis(100),
                    max_retries: 5,
                },
                channel_id: ChannelId::from([0; 32]),
                node_url: "http://not-used-in-tests".parse().unwrap(),
                auth: None,
            },
            retry_pending_blocks_timeout: Duration::from_mins(4),
            indexer_rpc_url: "ws://localhost:8779".parse().unwrap(),
            initial_public_accounts: None,
            initial_private_accounts: None,
        }
    }

    async fn make_service(
    ) -> SequencerService<
        sequencer_core::mock::MockBlockSettlementClient,
        sequencer_core::mock::MockIndexerClient,
    > {
        let config = test_config();
        let (core, mempool_handle) =
            SequencerCoreWithMockClients::start_from_config(config).await;
        let arc_core = Arc::new(Mutex::new(core));
        SequencerService::new(arc_core, mempool_handle, 512)
    }

    #[tokio::test]
    async fn send_transaction_too_large_returns_invalid_params() {
        use sequencer_service_rpc::RpcServer as _;
        let tiny_service = {
            let config2 = SequencerConfig {
                max_block_size: bytesize::ByteSize::b(1),
                ..test_config()
            };
            let (core2, mh2) =
                SequencerCoreWithMockClients::start_from_config(config2).await;
            SequencerService::new(Arc::new(Mutex::new(core2)), mh2, 1)
        };
        let tx = common::test_utils::produce_dummy_empty_transaction();
        let result = tiny_service.send_transaction(tx).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidParams.code());
        assert!(err.message().contains("too large") || err.message().contains("exceeds maximum"));
    }

    #[tokio::test]
    async fn send_valid_transaction_returns_hash() {
        use sequencer_service_rpc::RpcServer as _;
        let service = make_service().await;
        let tx = common::test_utils::produce_dummy_empty_transaction();
        let expected_hash = tx.hash();
        let result = service.send_transaction(tx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_hash);
    }

    #[tokio::test]
    async fn get_receipt_returns_pending_after_submit() {
        use sequencer_service_rpc::RpcServer as _;
        let service = make_service().await;
        let tx = common::test_utils::produce_dummy_empty_transaction();
        let tx_hash = tx.hash();
        service.send_transaction(tx).await.unwrap();
        let receipt = service.get_transaction_receipt(tx_hash).await.unwrap();
        assert!(
            matches!(receipt.status, common::receipt::TxStatus::Pending)
                || matches!(receipt.status, common::receipt::TxStatus::Included { .. }),
            "Expected Pending or Included, got {:?}",
            receipt.status
        );
    }

    #[tokio::test]
    async fn get_receipt_returns_unknown_for_unseen_hash() {
        use sequencer_service_rpc::RpcServer as _;
        let service = make_service().await;
        let receipt = service
            .get_transaction_receipt(HashType([0xff; 32]))
            .await
            .unwrap();
        assert!(matches!(receipt.status, common::receipt::TxStatus::Unknown));
    }

    #[tokio::test]
    async fn simulate_valid_transaction_returns_success() {
        use sequencer_service_rpc::RpcServer as _;
        let service = make_service().await;
        let tx = common::test_utils::produce_dummy_empty_transaction();
        let result = service.simulate_transaction(tx).await.unwrap();
        assert!(result.success, "Expected success, got error: {:?}", result.error);
    }

    #[tokio::test]
    async fn simulate_does_not_modify_state() {
        use sequencer_service_rpc::RpcServer as _;
        let service = make_service().await;
        let tx = common::test_utils::produce_dummy_empty_transaction();

        // Simulate the transaction.
        let sim_result = service.simulate_transaction(tx.clone()).await.unwrap();
        assert!(sim_result.success);

        // The state read via get_account should be unchanged after simulation.
        use testnet_initial_state::initial_pub_accounts_private_keys;
        let keys = initial_pub_accounts_private_keys();
        let account_id = keys[0].account_id;
        let account_before = service.get_account(account_id).await.unwrap();

        // Simulate again -- state should not change.
        let tx2 = common::test_utils::produce_dummy_empty_transaction();
        let sim_result2 = service.simulate_transaction(tx2).await.unwrap();
        assert!(sim_result2.success);

        let account_after = service.get_account(account_id).await.unwrap();
        assert_eq!(account_before.nonce, account_after.nonce, "Simulation must not modify state");
    }
}
