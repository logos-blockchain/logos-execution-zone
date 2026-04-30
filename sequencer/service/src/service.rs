use std::{collections::BTreeMap, sync::Arc};

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
}

impl<BC: BlockSettlementClientTrait, IC: IndexerClientTrait> SequencerService<BC, IC> {
    pub const fn new(
        sequencer: Arc<Mutex<SequencerCore<BC, IC>>>,
        mempool_handle: MemPoolHandle<NSSATransaction>,
        max_block_size: u64,
    ) -> Self {
        Self {
            sequencer,
            mempool_handle,
            max_block_size,
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
}
