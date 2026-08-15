use std::collections::BTreeMap;

use bytesize::ByteSize;
use common::transaction::LeeTransaction;
use jsonrpsee::{
    core::async_trait,
    types::{ErrorCode, ErrorObjectOwned},
};
use kameo::actor::ActorRef;
use log::{error, warn};
use sequencer_core::block_publisher::BlockPublisherTrait;
use sequencer_service_protocol::{
    Account, AccountId, Block, BlockId, ChannelId, Commitment, CommitmentSetDigest,
    CrossZoneDeadLetter, CrossZoneDeadLetterReport, HashType, MembershipProof, Nonce, ProgramId,
};

pub struct Service<BP: BlockPublisherTrait + Send + 'static> {
    executor_ref: ActorRef<sequencer_executor_actor::ExecutorActor<BP>>,
    max_block_size: ByteSize,
}

impl<BP: BlockPublisherTrait + Send + 'static> Service<BP> {
    pub fn new(
        executor_ref: ActorRef<sequencer_executor_actor::ExecutorActor<BP>>,
        max_block_size: ByteSize,
    ) -> Self {
        sequencer_rpc_server_actor_metrics::init();

        Self {
            executor_ref,
            max_block_size,
        }
    }
}

#[async_trait]
impl<BP: BlockPublisherTrait + Send + 'static> sequencer_service_rpc::RpcServer for Service<BP> {
    async fn send_transaction(&self, tx: LeeTransaction) -> Result<HashType, ErrorObjectOwned> {
        sequencer_rpc_server_actor_metrics::increment_submitted_transactions_total();

        let tx_hash = tx.hash();

        let res = async move {
            // Reserve ~200 bytes for block header overhead
            const BLOCK_HEADER_OVERHEAD: u64 = 200;

            let encoded_tx =
                borsh::to_vec(&tx).expect("Transaction borsh serialization should not fail");
            let tx_size =
                u64::try_from(encoded_tx.len()).expect("Transaction size should fit in u64");

            let max_tx_size = self
                .max_block_size
                .as_u64()
                .saturating_sub(BLOCK_HEADER_OVERHEAD);

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

            // Sequencer-only programs (the cross-zone inbox) are injected by the
            // watcher; a user must not invoke them top-level, or anyone could forge
            // an inbound cross-zone delivery. Chained user calls are already rejected
            // by the inbox guest's caller-is-none assertion.
            if let LeeTransaction::Public(public_tx) = &authenticated_tx
                && sequencer_core::is_sequencer_only_program(public_tx.message().program_account_id)
            {
                return Err(ErrorObjectOwned::owned(
                    ErrorCode::InvalidParams.code(),
                    "Program is sequencer-only and cannot be invoked by a user transaction"
                        .to_owned(),
                    None::<()>,
                ));
            }

            Ok(authenticated_tx)
        };

        let authenticated_tx = res.await.inspect_err(|err| {
            sequencer_rpc_server_actor_metrics::increment_before_mempool_failed_transactions_total(
            );
            error!("Transaction failed before reaching mempool: {err:#?}");
        })?;

        self.executor_ref
            .ask(sequencer_executor_actor::protocol::Transaction {
                transaction: authenticated_tx,
            })
            .await
            .map_err(internal_error)?;

        Ok(tx_hash)
    }

    async fn check_health(&self) -> Result<(), ErrorObjectOwned> {
        Ok(())
    }

    async fn get_block(&self, block_id: BlockId) -> Result<Option<Block>, ErrorObjectOwned> {
        self.executor_ref
            .ask(sequencer_executor_actor::protocol::GetBlock { block_id })
            .await
            .map_err(internal_error)
    }

    async fn get_block_range(
        &self,
        start_block_id: BlockId,
        end_block_id: BlockId,
    ) -> Result<Vec<Block>, ErrorObjectOwned> {
        self.executor_ref
            .ask(sequencer_executor_actor::protocol::GetBlockRange {
                range: (start_block_id..=end_block_id),
            })
            .await
            .map_err(internal_error)
    }

    async fn get_last_block_id(&self) -> Result<BlockId, ErrorObjectOwned> {
        self.executor_ref
            .ask(sequencer_executor_actor::protocol::GetLastBlockId)
            .await
            .map_err(internal_error)
    }

    async fn get_account_balance(&self, account_id: AccountId) -> Result<u128, ErrorObjectOwned> {
        self.executor_ref
            .ask(sequencer_executor_actor::protocol::GetAccountBalance { account_id })
            .await
            .map_err(internal_error)
    }

    async fn get_transaction(
        &self,
        tx_hash: HashType,
    ) -> Result<Option<(LeeTransaction, BlockId)>, ErrorObjectOwned> {
        self.executor_ref
            .ask(sequencer_executor_actor::protocol::GetTransaction { tx_hash })
            .await
            .map_err(internal_error)
    }

    async fn get_accounts_nonces(
        &self,
        account_ids: Vec<AccountId>,
    ) -> Result<Vec<Nonce>, ErrorObjectOwned> {
        self.executor_ref
            .ask(sequencer_executor_actor::protocol::GetAccountNonces { account_ids })
            .await
            .map_err(internal_error)
    }

    async fn get_proofs_and_root(
        &self,
        commitments: Vec<Commitment>,
    ) -> Result<(Vec<Option<MembershipProof>>, CommitmentSetDigest), ErrorObjectOwned> {
        self.executor_ref
            .ask(sequencer_executor_actor::protocol::GetProofsAndRoot { commitments })
            .await
            .map_err(internal_error)
    }

    async fn get_account(&self, account_id: AccountId) -> Result<Account, ErrorObjectOwned> {
        self.executor_ref
            .ask(sequencer_executor_actor::protocol::GetAccount { account_id })
            .await
            .map(|reply| reply.account)
            .map_err(internal_error)
    }

    async fn get_program_ids(&self) -> Result<BTreeMap<String, ProgramId>, ErrorObjectOwned> {
        // TODO: Get programs from state
        let mut program_ids = BTreeMap::new();
        program_ids.insert(
            "authenticated_transfer".to_owned(),
            programs::authenticated_transfer().id(),
        );
        program_ids.insert("token".to_owned(), programs::token().id());
        program_ids.insert("pinata".to_owned(), programs::pinata().id());
        program_ids.insert("amm".to_owned(), programs::amm().id());
        program_ids.insert(
            "privacy_preserving_circuit".to_owned(),
            lee::PRIVACY_PRESERVING_CIRCUIT_ID,
        );
        Ok(program_ids)
    }

    async fn get_channel_id(&self) -> Result<ChannelId, ErrorObjectOwned> {
        self.executor_ref
            .ask(sequencer_executor_actor::protocol::GetChannelId)
            .await
            .map(|reply| ChannelId(reply.channel_id))
            .map_err(internal_error)
    }

    async fn get_cross_zone_dead_letters(
        &self,
    ) -> Result<CrossZoneDeadLetterReport, ErrorObjectOwned> {
        let sequencer_executor_actor::protocol::GetCrossZoneDeadLettersReply {
            total_retired,
            retained,
        } = self
            .executor_ref
            .ask(sequencer_executor_actor::protocol::GetCrossZoneDeadLetters)
            .await
            .map_err(internal_error)?;

        Ok(CrossZoneDeadLetterReport {
            total_retired,
            retained: retained
                .into_iter()
                .map(|record| CrossZoneDeadLetter {
                    message_key: HashType(record.message_key),
                    src_zone: ChannelId(record.origin.src_zone),
                    src_block_id: record.origin.src_block_id,
                    src_tx_index: record.origin.src_tx_index,
                    failed_attempts: record.failed_attempts,
                    transaction_bytes: record.transaction_bytes,
                })
                .collect(),
        })
    }
}

fn internal_error(err: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(ErrorCode::InternalError.code(), err.to_string(), None::<()>)
}
