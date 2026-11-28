use std::{
    collections::BTreeMap,
    sync::{Arc, PoisonError, RwLock, Weak},
};

use anyhow::Result;
use kameo::{actor::ActorRef, error::SendError};
use lee::Actor;
use lee_core::CommitmentPosition;
use sequencer_executor_actor::protocol::{
    GetAccount, GetAccountBalance, GetAccountNonces, GetAccountView, GetBlock, GetBlockRange,
    GetFeeQuote, GetLastBlockId, GetProofsAndRoot, GetPublications, GetRecoveryBinding,
    GetTransaction, GetTransactionReceipt, Transaction, TransactionOrigin,
};
use sequencer_gossip_actor::{GossipActor, protocol::Publish};
use sequencer_service::{ExecutorActor, SequencerHandle};
use wallet::{ExecutionFailureKind, WalletSequencerClient};

use crate::sequencer::SequencerServiceFFI;

/// Talks to a sequencer in this process, without keeping it alive.
///
/// The sequencer may be stopped; calls then fail with [`FfiSequencerClientError::SequencerStopped`]
/// until [`rebind`](Self::rebind) points this at another. Clones share what they talk to.
#[derive(Clone)]
pub struct SequencerServiceFFIWrapper(Arc<RwLock<Weak<SequencerHandle>>>);

impl SequencerServiceFFIWrapper {
    #[must_use]
    pub fn wrap(sequencer: &SequencerServiceFFI) -> Self {
        Self(Arc::new(RwLock::new(Arc::downgrade(
            sequencer.shared_handle(),
        ))))
    }

    /// Talks to `sequencer` from now on, or with `None` to none.
    pub fn rebind(&self, sequencer: Option<&SequencerServiceFFI>) {
        let handle = sequencer.map_or_else(Weak::new, |sequencer| {
            Arc::downgrade(sequencer.shared_handle())
        });
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = handle;
    }

    /// Clones what `pick` returns out of the sequencer, if it still runs. Nothing keeps a strong
    /// reference to it past this call: stopping it must find its handle unshared to shut it down.
    fn with_handle<T>(
        &self,
        pick: impl FnOnce(&SequencerHandle) -> T,
    ) -> Result<T, FfiSequencerClientError> {
        let handle = self
            .0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .upgrade()
            .ok_or(FfiSequencerClientError::SequencerStopped)?;
        Ok(pick(&handle))
    }

    fn executor(&self) -> Result<ActorRef<ExecutorActor>, FfiSequencerClientError> {
        self.with_handle(|handle| handle.executor_ref().clone())
    }

    fn gossip(&self) -> Result<Option<ActorRef<GossipActor>>, FfiSequencerClientError> {
        self.with_handle(|handle| handle.gossip_ref().cloned())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FfiSequencerClientError {
    #[error("The sequencer is not running")]
    SequencerStopped,
    #[error("Sequencer executor actor failed")]
    SequencerExecutorError(#[from] sequencer_executor_actor::error::Error),
    #[error("Failed to send request to actor")]
    ActorSendError(#[source] anyhow::Error),
    #[error("Call arguments are incorrect")]
    ArgumentError(#[source] anyhow::Error),
}

impl<T: Send + Sync + 'static> From<SendError<T>> for FfiSequencerClientError {
    fn from(value: SendError<T>) -> Self {
        Self::ActorSendError(anyhow::Error::from(value))
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "It is by design, other variants of no use to wallet"
)]
impl<T: Send + Sync + 'static> From<SendError<T, sequencer_executor_actor::error::Error>>
    for FfiSequencerClientError
{
    fn from(value: SendError<T, sequencer_executor_actor::error::Error>) -> Self {
        match value {
            SendError::HandlerError(e) => Self::SequencerExecutorError(e),
            other => Self::ActorSendError(anyhow::Error::from(other)),
        }
    }
}

impl From<FfiSequencerClientError> for ExecutionFailureKind {
    fn from(value: FfiSequencerClientError) -> Self {
        match value {
            FfiSequencerClientError::SequencerExecutorError(
                val @ sequencer_executor_actor::error::Error::PrivateFeeBelowHead { .. },
            ) => Self::PrivateFeeBelowHead(val.to_string()),
            FfiSequencerClientError::SequencerExecutorError(val) => {
                Self::SequencerClientError(val.to_string())
            }
            FfiSequencerClientError::ArgumentError(val) => {
                Self::SequencerClientError(val.to_string())
            }
            FfiSequencerClientError::ActorSendError(val) => Self::SequencerError(val),
            val @ FfiSequencerClientError::SequencerStopped => {
                Self::SequencerError(anyhow::Error::from(val))
            }
        }
    }
}

impl WalletSequencerClient for SequencerServiceFFIWrapper {
    type Error = FfiSequencerClientError;

    async fn get_account(
        &self,
        account_id: lee::AccountId,
    ) -> Result<Option<lee::Account>, Self::Error> {
        Ok(self
            .executor()?
            .ask(GetAccount { account_id })
            .send()
            .await?)
    }

    async fn get_account_balance(&self, account_id: lee::AccountId) -> Result<u128, Self::Error> {
        Ok(self
            .executor()?
            .ask(GetAccountBalance { account_id })
            .send()
            .await?)
    }

    async fn get_accounts_nonces(
        &self,
        account_ids: Vec<lee::AccountId>,
    ) -> Result<Vec<lee_core::account::Nonce>, Self::Error> {
        Ok(self
            .executor()?
            .ask(GetAccountNonces { account_ids })
            .send()
            .await?)
    }

    async fn get_block(
        &self,
        block_id: lee_core::BlockId,
    ) -> Result<Option<common::block::Block>, Self::Error> {
        Ok(self.executor()?.ask(GetBlock { block_id }).send().await?)
    }

    async fn get_block_range(
        &self,
        start_block_id: lee_core::BlockId,
        end_block_id: lee_core::BlockId,
    ) -> Result<Vec<common::block::Block>, Self::Error> {
        Ok(self
            .executor()?
            .ask(GetBlockRange {
                range: (start_block_id..=end_block_id).try_into().map_err(|err| {
                    FfiSequencerClientError::ArgumentError(anyhow::Error::from(err))
                })?,
            })
            .send()
            .await?)
    }

    async fn get_last_block_id(&self) -> Result<lee_core::BlockId, Self::Error> {
        Ok(self.executor()?.ask(GetLastBlockId {}).send().await?)
    }

    async fn get_transaction(
        &self,
        tx_hash: common::HashType,
    ) -> Result<Option<(common::transaction::LeeTransaction, lee_core::BlockId)>, Self::Error> {
        Ok(self
            .executor()?
            .ask(GetTransaction { tx_hash })
            .send()
            .await?)
    }

    async fn get_transaction_receipt(
        &self,
        tx_hash: common::HashType,
    ) -> Result<Option<common::block::TransactionReceipt>, Self::Error> {
        Ok(self
            .executor()?
            .ask(GetTransactionReceipt { tx_hash })
            .send()
            .await?)
    }

    async fn send_transaction(
        &self,
        tx: common::transaction::LeeTransaction,
    ) -> Result<common::HashType, Self::Error> {
        let tx_hash = tx.hash();

        // TODO: Fix that code duplication, when `RpcServerActor` becomes real actor.

        let checked_tx = tx
            .transaction_stateless_check()
            .map_err(anyhow::Error::from)
            .map_err(FfiSequencerClientError::ArgumentError)?;

        if let Some((to, _)) = checked_tx.public_call()
            && sequencer_core::is_sequencer_only_program(to.program_account_id)
        {
            return Err(FfiSequencerClientError::ArgumentError(anyhow::anyhow!(
                "Program is sequencer-only and cannot be invoked by a user transaction"
            )));
        }

        self.executor()?
            .ask(Transaction {
                transaction: checked_tx.clone(),
                origin: TransactionOrigin::User,
            })
            .send()
            .await?;

        if let Some(gossip_ref) = self.gossip()? {
            gossip_ref
                .tell(Publish::Transaction(Box::new(checked_tx)))
                .await?;
        }

        Ok(tx_hash)
    }

    async fn get_account_view(
        &self,
        actor_state_selector: Actor,
    ) -> Result<Option<lee::Account>, Self::Error> {
        Ok(self
            .executor()?
            .ask(GetAccountView {
                actor_state_selector,
            })
            .send()
            .await?)
    }

    async fn get_program_ids(
        &self,
    ) -> Result<std::collections::BTreeMap<String, lee::ProgramId>, Self::Error> {
        // TODO: Sequencer RPC don't read programs from state. Need to update both.
        let mut program_ids = BTreeMap::new();
        program_ids.insert(
            "privacy_preserving_circuit".to_owned(),
            lee::PRIVACY_PRESERVING_CIRCUIT_ID,
        );
        Ok(program_ids)
    }

    async fn get_proofs_and_root(
        &self,
        commitments: Vec<lee_core::Commitment>,
        message_positions: Vec<CommitmentPosition>,
    ) -> Result<
        (
            Vec<Option<lee_core::MembershipProof>>,
            Vec<Option<lee_core::MembershipProof>>,
            lee_core::CommitmentSetDigest,
        ),
        Self::Error,
    > {
        let reply = self
            .executor()?
            .ask(GetProofsAndRoot {
                commitments,
                message_positions,
            })
            .send()
            .await?;
        Ok((reply.proofs, reply.message_paths, reply.root))
    }

    async fn get_fee_state(&self) -> Result<wallet::FeeStateQuote, Self::Error> {
        let quote = self.executor()?.ask(GetFeeQuote).send().await?;
        Ok(wallet::FeeStateQuote {
            height: quote.height,
            base_fee_exec: quote.base_fee_exec,
            base_fee_stor: quote.base_fee_stor,
            next_base_fee_exec_floor: quote.next_base_fee_exec_floor,
            next_base_fee_exec_ceiling: quote.next_base_fee_exec_ceiling,
            next_base_fee_stor_floor: quote.next_base_fee_stor_floor,
            next_base_fee_stor_ceiling: quote.next_base_fee_stor_ceiling,
            max_gas_exec: quote.max_gas_exec,
            max_gas_stor: quote.max_gas_stor,
        })
    }

    async fn get_publications(
        &self,
        from_position: CommitmentPosition,
        limit: common::PageLimit,
    ) -> Result<lee::PublicationsPage, Self::Error> {
        Ok(self
            .executor()?
            .ask(GetPublications {
                from_position,
                limit,
            })
            .send()
            .await?
            .page)
    }

    async fn get_recovery_binding(
        &self,
        address: lee::AccountId,
    ) -> Result<Option<lee::EncryptedNote>, Self::Error> {
        Ok(self
            .executor()?
            .ask(GetRecoveryBinding { address })
            .send()
            .await?)
    }
}
