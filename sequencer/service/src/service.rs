use std::{collections::BTreeMap, sync::Arc};

use common::transaction::NSSATransaction;
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

        let encoded_tx =
            borsh::to_vec(&tx).expect("Transaction borsh serialization should not fail");
        let tx_size = u64::try_from(encoded_tx.len()).expect("Transaction size should fit in u64");

        let max_tx_size = self.max_block_size.saturating_sub(BLOCK_HEADER_OVERHEAD);

        if tx_size > max_tx_size {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::InvalidParams.code(),
                format!("Transaction too large: size {tx_size}, max {max_tx_size}"),
                None::<()>,
            ));
        }

        let authenticated_tx = tx
            .transaction_stateless_check()
            .inspect_err(|err| warn!("Error at pre_check {err:#?}"))
            .map_err(|err| {
                ErrorObjectOwned::owned(
                    ErrorCode::InvalidParams.code(),
                    format!("{err:?}"),
                    None::<()>,
                )
            })?;

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
