use std::{collections::BTreeMap, sync::Arc};

use common::transaction::LeeTransaction;
use jsonrpsee::{
    core::async_trait,
    types::{ErrorCode, ErrorObjectOwned},
};
use lee;
use log::{error, warn};
use mempool::MemPoolHandle;
use sequencer_core::{
    DbError, SequencerCore, TransactionOrigin, block_publisher::BlockPublisherTrait,
};
use sequencer_service_protocol::{
    Account, AccountId, Block, BlockId, ChannelId, Commitment, CommitmentSetDigest, FeeStateQuote,
    HashType, MembershipProof, Nonce, ProgramId,
};
use tokio::sync::Mutex;

use crate::fees;

const NOT_FOUND_ERROR_CODE: i32 = -31999;

pub struct SequencerService<BC: BlockPublisherTrait> {
    sequencer: Arc<Mutex<SequencerCore<BC>>>,
    mempool_handle: MemPoolHandle<(TransactionOrigin, LeeTransaction)>,
    max_block_size: u64,
}

impl<BC: BlockPublisherTrait> SequencerService<BC> {
    pub const fn new(
        sequencer: Arc<Mutex<SequencerCore<BC>>>,
        mempool_handle: MemPoolHandle<(TransactionOrigin, LeeTransaction)>,
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
impl<BC: BlockPublisherTrait + Send + Sync + 'static> sequencer_service_rpc::RpcServer
    for SequencerService<BC>
{
    async fn send_transaction(&self, tx: LeeTransaction) -> Result<HashType, ErrorObjectOwned> {
        sequencer_service_metrics::increment_submitted_transactions_total();

        let tx_hash = tx.hash();

        let admitted = {
            // FIXME(fees-edges): `main_loop` holds this lock across `produce_new_block`, so ingest
            // stalls for a whole build; `with_state` needs only `&self`, so handing the service a
            // direct state handle would drop the outer lock.
            let sequencer = self.sequencer.lock().await;
            sequencer.with_state(|state| admit(tx, self.max_block_size, state))
        };

        let authenticated_tx = admitted.inspect_err(|err| {
            sequencer_service_metrics::increment_before_mempool_failed_transactions_total();
            error!("Transaction failed before reaching mempool: {err:#?}");
        })?;

        self.mempool_handle
            .push((TransactionOrigin::User, authenticated_tx))
            .await
            .expect("Mempool is closed, this is a bug");

        Ok(tx_hash)
    }

    async fn check_health(&self) -> Result<(), ErrorObjectOwned> {
        Ok(())
    }

    async fn get_fee_state(&self) -> Result<FeeStateQuote, ErrorObjectOwned> {
        let sequencer = self.sequencer.lock().await;
        Ok(sequencer.with_state(|state| fees::fee_quote(state.fee_state())))
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
        let balance = sequencer.with_state(|state| state.get_account_by_id(account_id).balance);
        Ok(balance)
    }

    async fn get_transaction(
        &self,
        tx_hash: HashType,
    ) -> Result<Option<(LeeTransaction, BlockId)>, ErrorObjectOwned> {
        let sequencer = self.sequencer.lock().await;
        Ok(sequencer.block_store().get_transaction_by_hash(tx_hash))
    }

    async fn get_accounts_nonces(
        &self,
        account_ids: Vec<AccountId>,
    ) -> Result<Vec<Nonce>, ErrorObjectOwned> {
        let sequencer = self.sequencer.lock().await;
        let nonces = sequencer.with_state(|state| {
            account_ids
                .into_iter()
                .map(|account_id| state.get_account_by_id(account_id).nonce)
                .collect()
        });
        Ok(nonces)
    }

    async fn get_proofs_and_root(
        &self,
        commitments: Vec<Commitment>,
    ) -> Result<(Vec<Option<MembershipProof>>, CommitmentSetDigest), ErrorObjectOwned> {
        let sequencer = self.sequencer.lock().await;
        Ok(sequencer.with_state(|state| {
            let proofs = commitments
                .iter()
                .map(|commitment| state.get_proof_for_commitment(commitment))
                .collect();
            (proofs, state.commitment_root())
        }))
    }

    async fn get_account(&self, account_id: AccountId) -> Result<Account, ErrorObjectOwned> {
        let sequencer = self.sequencer.lock().await;
        Ok(sequencer.with_state(|state| state.get_account_by_id(account_id)))
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
        let channel_id = self.sequencer.lock().await.block_publisher().channel_id();
        Ok(ChannelId(*channel_id.as_ref()))
    }
}

/// Everything a submitted transaction must clear before it reaches the mempool: it has to fit a
/// block on its own, be well-formed and signed, not impersonate a sequencer injection, and pass
/// fee admission against the head `state`.
///
/// One gate rather than a sequence of them at the call site, so nothing can reach
/// [`sequencer_service_rpc::RpcServer::send_transaction`]'s mempool push having passed only part
/// of it.
fn admit(
    tx: LeeTransaction,
    max_block_size: u64,
    state: &lee::V03State,
) -> Result<LeeTransaction, ErrorObjectOwned> {
    // Reserve ~200 bytes for block header overhead
    const BLOCK_HEADER_OVERHEAD: u64 = 200;

    let encoded_tx = borsh::to_vec(&tx).expect("Transaction borsh serialization should not fail");
    let tx_size = u64::try_from(encoded_tx.len()).expect("Transaction size should fit in u64");

    let max_tx_size = max_block_size.saturating_sub(BLOCK_HEADER_OVERHEAD);

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
        && sequencer_core::is_sequencer_only_program(public_tx.message().program_id)
    {
        return Err(ErrorObjectOwned::owned(
            ErrorCode::InvalidParams.code(),
            "Program is sequencer-only and cannot be invoked by a user transaction".to_owned(),
            None::<()>,
        ));
    }

    // Fee admission: what no block of this chain would include, or what the payer visibly cannot
    // afford right now (see `fees::screen`).
    fees::screen(&authenticated_tx, state)
        .map_err(|rejection| fees::rejection_error(&rejection))?;

    Ok(authenticated_tx)
}

fn internal_error(err: &DbError) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(ErrorCode::InternalError.code(), err.to_string(), None::<()>)
}

/// The ingest path, exercised where it is decided: `send_transaction` does nothing but call
/// [`admit`] and push what it returns, so a fee-invalid transaction being refused here is the same
/// refusal a client sees.
#[cfg(test)]
mod tests {
    use common::test_utils::create_transaction_native_token_transfer_with_fees;
    use lee::FeeFields;
    use sequencer_service_protocol::AdmissionRejection;
    use testnet_initial_state::{initial_pub_accounts_private_keys, initial_state};

    use super::*;

    /// Generous enough that the size check never decides these tests.
    const MAX_BLOCK_SIZE: u64 = 0x0010_0000;

    #[test]
    fn the_ingest_path_admits_a_funded_transfer() {
        let state = initial_state();
        let accounts = initial_pub_accounts_private_keys();
        let tx = common::test_utils::create_transaction_native_token_transfer(
            accounts[0].account_id,
            0,
            accounts[1].account_id,
            10,
            &accounts[0].pub_sign_key,
        );

        admit(tx, MAX_BLOCK_SIZE, &state).expect("a well-formed, funded transfer is admitted");
    }

    /// The fee screen is part of the ingest path, not something only `fees::screen`'s own tests
    /// reach: a transaction that is perfectly well-formed and correctly signed, and fails nothing
    /// but fee admission, must not reach the mempool.
    #[test]
    fn the_ingest_path_rejects_a_fee_invalid_transaction() {
        let state = initial_state();
        let accounts = initial_pub_accounts_private_keys();
        let payer = accounts[0].account_id;
        let tx = create_transaction_native_token_transfer_with_fees(
            payer,
            0,
            accounts[1].account_id,
            10,
            &accounts[0].pub_sign_key,
            FeeFields::new(payer, common::test_utils::TEST_GAS_LIMIT, 0, 1),
        );

        let err = admit(tx, MAX_BLOCK_SIZE, &state).expect_err("its max_fee covers nothing");
        assert_eq!(
            err.code(),
            AdmissionRejection::MaxFeeBelowReserve {
                fee_reserve: 0,
                max_fee: 0,
            }
            .code(),
            "the rejection must arrive under the max_fee check's own code",
        );
        assert!(
            err.data().is_some(),
            "and carry the structured rejection in `data`",
        );
    }
}
