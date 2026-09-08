use std::future::Future;

use common::{block::Block, transaction::LeeTransaction};
use futures::{
    FutureExt as _, StreamExt as _, TryFutureExt as _, TryStreamExt as _, future::ready, stream,
};
use kameo::{
    Actor,
    actor::{ActorRef, WeakActorRef},
    error::{ActorStopReason, Infallible},
    mailbox::{MailboxReceiver, Signal},
    message::{Context, Message},
    reply::DelegatedReply,
};
use lee_core::{
    BlockId,
    account::{Balance, Nonce},
};
use log::{info, warn};
use mempool::MemPoolHandle;
use sequencer_actors_common::EraseMessage as _;
use sequencer_bedrock_actor::BedrockActorTrait;
use sequencer_core::{
    MsgId, PinBehindTip, SequencerCore, TransactionOrigin, config::SequencerConfig,
    task_group::TaskGroup,
};
use sequencer_storage_actor::StorageActorTrait;

use crate::{
    ExecutorActorTrait, Result,
    error::Error,
    protocol::{
        ChannelId, FeeStateQuote, GetAccount, GetAccountBalance, GetAccountNonces, GetAccountReply,
        GetBlock, GetBlockRange, GetChannelId, GetCrossZoneDeadLetters,
        GetCrossZoneDeadLettersReply, GetFeeQuote, GetLastBlockId, GetProofsAndRoot,
        GetTransaction, ProduceBlock, RequeueCrossZoneDeadLetter, RequeueCrossZoneDeadLetterReply,
        Transaction,
    },
};

mod conversions;
#[cfg(test)]
mod tests;

/// How many block lookups a single [`GetBlockRange`] keeps in flight.
const BLOCK_RANGE_CONCURRENCY: usize = 16;

/// Skips behind an unchanging tip past which this is a stuck pin, not catch-up.
const BLOCKED_ATTEMPTS_BEFORE_WEDGED: u32 = 4;

pub struct ExecutorActor<S: StorageActorTrait, B: BedrockActorTrait> {
    mempool_handle: MemPoolHandle<(TransactionOrigin, LeeTransaction)>,
    sequencer: SequencerCore<S, B>,
    storage_ref: ActorRef<S>,
    bedrock_ref: ActorRef<B>,

    /// Is it our turn to produce a blocks.
    is_our_turn: bool,

    // TODO: Remove this field
    background_task: TaskGroup,

    blocked_attempts: BlockedAttempts,
    /// Consecutive production turns that failed outright. A run of these looks
    /// exactly like an idle node in every other signal, so it gets its own.
    failed_attempts: u32,
}

/// Consecutive production attempts skipped because the pin trailed the tip.
/// The run restarts on a new tip, so its length separates catching up from
/// being stuck.
#[derive(Default)]
pub(crate) struct BlockedAttempts {
    count: u32,
    behind: Option<MsgId>,
}

impl BlockedAttempts {
    /// Counts a skipped attempt and returns the run's new length.
    pub(crate) fn record(&mut self, tip: MsgId) -> u32 {
        if self.behind == Some(tip) {
            self.count = self.count.saturating_add(1);
        } else {
            self.behind = Some(tip);
            self.count = 1;
        }
        self.count
    }

    /// Ends the run, reporting whether there was one to end.
    pub(crate) fn clear(&mut self) -> bool {
        let blocked = self.behind.is_some();
        *self = Self::default();
        blocked
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> ExecutorActor<S, B> {
    pub fn new(
        config: SequencerConfig,
        storage_ref: ActorRef<S>,
        bedrock_ref: ActorRef<B>,
    ) -> impl Future<Output = Result<Self>> + Send + 'static {
        sequencer_executor_actor_metrics::init();

        async move {
            // TODO: Leave storage_ref as a top-level field only in `ExecutorActor`,
            // while moving `SequencerCore` code into this actor.
            let (sequencer, mempool_handle) = SequencerCore::<S, B>::start_from_config(
                config,
                storage_ref.clone(),
                bedrock_ref.clone(),
            )
            .await
            .map_err(Error::SequencerStartFailed)?;

            let is_our_turn = bedrock_ref
                .ask(sequencer_bedrock_actor::protocol::CheckIsOurTurn)
                .await
                .map_err(|err| {
                    let err = err.map_err(|_: Infallible| unreachable!());
                    Error::BedrockRequestFailed(err.erase_message())
                })?;

            let background_task = sequencer.background_task();

            Ok(Self {
                mempool_handle,
                sequencer,
                storage_ref,
                bedrock_ref,
                is_our_turn,
                background_task,
                blocked_attempts: BlockedAttempts::default(),
                failed_attempts: 0,
            })
        }
    }

    /// Ends a blocked run, reporting the drop to zero only if there was one.
    fn clear_blocked_attempts(&mut self) {
        if self.blocked_attempts.clear() {
            sequencer_executor_actor_metrics::record_publish_blocked_attempts(0);
        }
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> ExecutorActorTrait for ExecutorActor<S, B> {}

impl<S: StorageActorTrait, B: BedrockActorTrait> Actor for ExecutorActor<S, B> {
    type Args = Self;
    type Error = Error;

    async fn on_start(args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self> {
        Ok(args)
    }

    async fn next(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        mailbox_rx: &mut MailboxReceiver<Self>,
    ) -> Result<Option<Signal<Self>>> {
        // TODO: Remove this please
        if self.background_task.any_finished() {
            return Err(Error::BackgroundTaskFinishedUnexpectedly);
        }

        Ok(mailbox_rx.recv().await)
    }

    async fn on_stop(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        _reason: ActorStopReason,
    ) -> Result<()> {
        self.background_task.shutdown().await;

        Ok(())
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<ProduceBlock> for ExecutorActor<S, B> {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        ProduceBlock: ProduceBlock,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // Only produce on our turn. Losing the seat ends any blocked run: a node
        // dropped from the committee is not wedged, and would otherwise hold the
        // gauge non-zero forever.
        if !self.is_our_turn {
            info!("Not our turn to produce a block, skipping");
            self.clear_blocked_attempts();
            return Ok(());
        }

        // Never inscribe a second block at a height we already published: the
        // channel would carry two chains from there and nothing resolves that.
        if let Some(high_water) = self.sequencer.rewound_below_published().await {
            warn!(
                "Skipping turn: head rewound to {} but block {high_water} is already inscribed; \
                 waiting for the channel to restore it",
                self.sequencer.next_block_height().await.saturating_sub(1),
            );
            // The count is only for skips behind a frozen pin, so keeping it
            // here would warn about the wrong problem.
            self.clear_blocked_attempts();
            return Ok(());
        }

        // The channel moved past our pin, so every publish this turn would be refused.
        if let Some(PinBehindTip { pin, tip }) = self.sequencer.pin_behind_channel_tip().await {
            let attempts = self.blocked_attempts.record(tip);
            sequencer_executor_actor_metrics::record_publish_blocked_attempts(attempts);
            if attempts >= BLOCKED_ATTEMPTS_BEFORE_WEDGED {
                warn!(
                    "Skipped {attempts} production attempts behind an unchanging channel tip \
                     {tip}: our pin {pin} is frozen and cannot recover on its own. Land any \
                     inscription on the channel to trigger recovery, or reset the store.",
                );
            } else {
                info!(
                    "Skipping turn: channel tip {tip} moved past our pin {pin}; catching up first"
                );
            }
            return Ok(());
        }
        self.clear_blocked_attempts();

        info!("Our turn: producing a block and any committee update");
        // A failed turn costs this block only. Returning the error would stop
        // this actor, and the scheduler's interval task gives up for good the
        // first time it finds us not running — the node then looks healthy and
        // never produces again.
        match self.sequencer.run_production_turn().await {
            Ok(id) => {
                // The count is how many turns failed in a row, so a success
                // clears it and the gauge drops to zero, unless it was zero
                // already.
                if std::mem::take(&mut self.failed_attempts) != 0 {
                    sequencer_executor_actor_metrics::record_production_failed_attempts(0);
                }
                log::info!(
                    "Block with id {id} created by {}",
                    self.sequencer.bedrock_public_key_hex()
                );
            }
            Err(err) => {
                self.failed_attempts = self.failed_attempts.saturating_add(1);
                sequencer_executor_actor_metrics::record_production_failed_attempts(
                    self.failed_attempts,
                );
                warn!(
                    "Skipping turn: block production failed ({} in a row): {err:#}",
                    self.failed_attempts
                );
            }
        }

        Ok(())
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<Transaction> for ExecutorActor<S, B> {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        Transaction {
            transaction,
            origin,
        }: Transaction,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // Fee admission against the head state, before the mempool sees it.
        // Advisory (base fees and balances move), but everything it turns
        // away would have been refused by the block builder anyway.
        self.sequencer
            .with_state(|state| sequencer_core::fees::screen(&transaction, state))
            .await
            .map_err(|err| Error::IncorrectFee(err.into()))?;

        self.mempool_handle
            .try_push((origin.into(), transaction))
            .map_err(|_err| Error::MempoolIsFull)?;
        Ok(())
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<GetBlock> for ExecutorActor<S, B> {
    type Reply = Result<Option<Block>>;

    async fn handle(
        &mut self,
        GetBlock { block_id }: GetBlock,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.storage_ref
            .ask(sequencer_storage_actor::protocol::GetBlock { block_id })
            .await
            .map_err(Into::into)
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<GetBlockRange> for ExecutorActor<S, B> {
    type Reply = DelegatedReply<Result<Vec<Block>>>;

    async fn handle(
        &mut self,
        GetBlockRange { range }: GetBlockRange,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let storage_ref = self.storage_ref.clone();

        ctx.spawn(async move {
            stream::iter(range.into_inner())
                .map(|block_id| {
                    storage_ref
                        .ask(sequencer_storage_actor::protocol::GetBlock { block_id })
                        .into_future()
                        .map_err(Into::into)
                })
                .buffered(BLOCK_RANGE_CONCURRENCY)
                .try_take_while(|block_opt| ready(Ok(block_opt.is_some())))
                .try_filter_map(|block_opt| ready(Ok(block_opt)))
                .try_collect()
                .await
        })
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<GetLastBlockId> for ExecutorActor<S, B> {
    type Reply = Result<BlockId>;

    async fn handle(
        &mut self,
        GetLastBlockId: GetLastBlockId,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self.sequencer.chain_height().await)
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<GetAccountBalance>
    for ExecutorActor<S, B>
{
    type Reply = Balance;

    async fn handle(
        &mut self,
        GetAccountBalance { account_id }: GetAccountBalance,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.sequencer
            .with_state(|state| state.get_account_by_id(account_id).balance)
            .await
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<GetFeeQuote> for ExecutorActor<S, B> {
    type Reply = FeeStateQuote;

    async fn handle(
        &mut self,
        GetFeeQuote: GetFeeQuote,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.sequencer
            .with_state(sequencer_core::fees::fee_quote)
            .map(Into::into)
            .await
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<GetTransaction> for ExecutorActor<S, B> {
    type Reply = Result<Option<(LeeTransaction, BlockId)>>;

    async fn handle(
        &mut self,
        GetTransaction { tx_hash }: GetTransaction,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.storage_ref
            .ask(sequencer_storage_actor::protocol::GetTransactionByHash { hash: tx_hash })
            .await
            .map_err(Into::into)
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<GetAccountNonces> for ExecutorActor<S, B> {
    type Reply = Vec<Nonce>;

    async fn handle(
        &mut self,
        GetAccountNonces { account_ids }: GetAccountNonces,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.sequencer
            .with_state(|state| {
                account_ids
                    .into_iter()
                    .map(|account_id| state.get_account_by_id(account_id).nonce)
                    .collect()
            })
            .await
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<GetProofsAndRoot> for ExecutorActor<S, B> {
    type Reply = (
        Vec<Option<lee_core::MembershipProof>>,
        lee_core::CommitmentSetDigest,
    );

    async fn handle(
        &mut self,
        GetProofsAndRoot { commitments }: GetProofsAndRoot,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.sequencer
            .with_state(|state| {
                let proofs = commitments
                    .iter()
                    .map(|commitment| state.get_proof_for_commitment(commitment))
                    .collect();
                (proofs, state.commitment_root())
            })
            .await
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<GetAccount> for ExecutorActor<S, B> {
    type Reply = GetAccountReply;

    async fn handle(
        &mut self,
        GetAccount { account_id }: GetAccount,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        GetAccountReply {
            account: self
                .sequencer
                .with_state(|state| state.get_account_by_id(account_id))
                .await,
        }
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<GetChannelId> for ExecutorActor<S, B> {
    type Reply = Result<ChannelId>;

    async fn handle(
        &mut self,
        GetChannelId: GetChannelId,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let channel_id = self
            .bedrock_ref
            .ask(sequencer_bedrock_actor::protocol::GetChannelId)
            .await
            .map_err(|err| {
                let err = err.map_err(|_: Infallible| unreachable!());
                Error::BedrockRequestFailed(err.erase_message())
            })?;

        Ok(*channel_id.channel_id.as_ref())
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<GetCrossZoneDeadLetters>
    for ExecutorActor<S, B>
{
    type Reply = Result<GetCrossZoneDeadLettersReply>;

    async fn handle(
        &mut self,
        GetCrossZoneDeadLetters: GetCrossZoneDeadLetters,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let (total_retired, retained) = self
            .sequencer
            .cross_zone_dead_letters()
            .await
            .map_err(Error::CrossZoneDeadLettersUnavailable)?;
        Ok(GetCrossZoneDeadLettersReply {
            total_retired,
            retained: retained.into_iter().collect(),
        })
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<RequeueCrossZoneDeadLetter>
    for ExecutorActor<S, B>
{
    type Reply = Result<RequeueCrossZoneDeadLetterReply>;

    async fn handle(
        &mut self,
        RequeueCrossZoneDeadLetter { message_key }: RequeueCrossZoneDeadLetter,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let outcome = self
            .sequencer
            .requeue_cross_zone_dead_letter(message_key)
            .await
            .map_err(Error::CrossZoneDeadLetterRequeueFailed)?;
        Ok(RequeueCrossZoneDeadLetterReply { outcome })
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait>
    Message<sequencer_bedrock_actor::protocol::ChannelEvent> for ExecutorActor<S, B>
{
    type Reply = ();

    async fn handle(
        &mut self,
        msg: sequencer_bedrock_actor::protocol::ChannelEvent,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        match msg {
            sequencer_bedrock_actor::protocol::ChannelEvent::Update(channel_update) => {
                self.sequencer.on_channel_update(*channel_update).await;
            }
            sequencer_bedrock_actor::protocol::ChannelEvent::Turn { our_turn_to_write } => {
                self.is_our_turn = our_turn_to_write;
            }
        }
    }
}
