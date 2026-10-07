use std::future::Future;

use common::{PageLimit, block::Block, transaction::LeeTransaction};
use fee_core::validity::FeeError;
use futures::{
    FutureExt as _, StreamExt as _, TryFutureExt as _, TryStreamExt as _, future::ready, stream,
};
use kameo::{
    actor::{ActorRef, WeakActorRef},
    error::ActorStopReason,
    mailbox::{MailboxReceiver, Signal},
    message::{Context, Message},
    reply::DelegatedReply,
};
use kameo_actors::pubsub::PubSub;
use lee::Account;
use lee_core::{
    BlockId, CommitmentPosition, EncryptedNote, MembershipProof,
    account::{Actor, Balance, Nonce},
    program::Publication,
};
use log::{debug, warn};
use sequencer_actors_common::Reply;
use sequencer_bedrock_actor::{
    BedrockActorTrait,
    protocol::{ChannelEvent, ChannelEventKind, Ed25519Key, PublisherEvent},
};
use sequencer_channel_signing_actor::{ChannelSigningActor, protocol as channel_signing_protocol};
use sequencer_core::{StakeConfigUpdate, config::SequencerConfig};
use sequencer_slasher_actor::SlasherActor;
use sequencer_storage_actor::StorageActorTrait;
use sharding_pool_actor::ShardingPoolActor;

use crate::{
    ExecutorActorTrait, Result,
    actor::state::State,
    error::Error,
    protocol::{
        ChannelId, FeeStateQuote, GetAccount, GetAccountBalance, GetAccountNonces,
        GetAccountTransactions, GetAccountView, GetBlock, GetBlockByHash, GetBlockRange,
        GetChannelId, GetCrossZoneDeadLetters, GetCrossZoneDeadLettersReply, GetFeeQuote,
        GetLastBlockId, GetMessagePath, GetProofsAndRoot, GetProofsAndRootReply, GetPublications,
        GetRecoveryBinding, GetTransaction, ProduceBlock, RequeueCrossZoneDeadLetter,
        RequeueCrossZoneDeadLetterReply, Transaction,
    },
};

mod conversions;
mod state;
#[cfg(test)]
mod tests;

/// How many block lookups a single [`GetBlockRange`] keeps in flight.
const BLOCK_RANGE_CONCURRENCY: usize = 16;
const MAX_PUBLICATIONS_PER_REQUEST: PageLimit = 256;

pub struct ExecutorActor<S: StorageActorTrait, B: BedrockActorTrait> {
    state: State<S, B>,
    channel_id: ChannelId,
    storage_ref: ActorRef<S>,

    /// Consecutive production turns that failed outright. A run of these looks
    /// exactly like an idle node in every other signal, so it gets its own.
    failed_attempts: u32,
}

impl<S: StorageActorTrait, B: BedrockActorTrait> ExecutorActor<S, B> {
    pub fn new(
        config: SequencerConfig,
        channel_signing_key: Ed25519Key,
        storage_ref: ActorRef<S>,
        bedrock_pool_ref: ActorRef<ShardingPoolActor<B, ChannelId>>,
        stake_config_pubsub_ref: ActorRef<PubSub<StakeConfigUpdate>>,
        slasher_ref: ActorRef<SlasherActor<S>>,
        channel_signer_ref: ActorRef<ChannelSigningActor>,
    ) -> impl Future<Output = Result<Self>> + Send + 'static {
        sequencer_executor_actor_metrics::init();

        async move {
            let channel_id = config.bedrock_config.channel_id;
            let state = State::initialize(
                config,
                channel_signing_key,
                storage_ref.clone(),
                bedrock_pool_ref,
                stake_config_pubsub_ref,
                slasher_ref,
                channel_signer_ref,
            )
            .await?;

            Ok(Self {
                state,
                channel_id,
                storage_ref,
                failed_attempts: 0,
            })
        }
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> ExecutorActorTrait for ExecutorActor<S, B> {}

impl<S: StorageActorTrait, B: BedrockActorTrait> kameo::Actor for ExecutorActor<S, B> {
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
        if let State::Online(online) = &self.state
            && online.background_tasks().any_finished()
        {
            return Err(Error::BackgroundTaskFinishedUnexpectedly);
        }

        Ok(mailbox_rx.recv().await)
    }

    async fn on_stop(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        _reason: ActorStopReason,
    ) -> Result<()> {
        if let State::Online(online) = &self.state {
            online.background_tasks().shutdown().await;
        }

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
        let online = match &mut self.state {
            State::Error(details) => {
                panic!("Actor has encountered an error state: {details}");
            }
            State::Online(online) => online,
            State::Bootstrapping(_) => {
                debug!("Not online yet, skipping the production turn");
                return Ok(());
            }
        };
        if !online.is_our_turn() {
            debug!("Not our turn to produce a block, skipping");
            return Ok(());
        }

        debug!("Our turn: producing a block and any committee update");
        // A failed turn costs this block only. Returning the error would stop
        // this actor, and the scheduler's interval task gives up for good the
        // first time it finds us not running — the node then looks healthy and
        // never produces again.
        match online.sequencer_mut().run_production_turn().await {
            Ok(id) => {
                // The count is how many turns failed in a row, so a success
                // clears it and the gauge drops to zero, unless it was zero
                // already.
                if std::mem::take(&mut self.failed_attempts) != 0 {
                    sequencer_executor_actor_metrics::record_production_failed_attempts(0);
                }
                log::info!(
                    "Block with id {id} created by {}",
                    online.sequencer().channel_signing_public_key_hex()
                );
            }
            Err(err) if err.is::<sequencer_core::ChannelMovedWhileBuilding>() => {
                // Skipping turn until next time hoping to catch up all missed updates
                warn!("Skipping turn: {err}");
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

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<channel_signing_protocol::SubmitConfig>
    for ExecutorActor<S, B>
{
    type Reply = ();

    async fn handle(
        &mut self,
        channel_signing_protocol::SubmitConfig(submission): channel_signing_protocol::SubmitConfig,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        // Told, not asked, so an error here would only stop this actor.
        let online = match &mut self.state {
            State::Error(details) => {
                panic!("Actor has encountered an error state: {details}");
            }
            State::Online(online) => online,
            State::Bootstrapping(_) => {
                warn!("Dropping a signed channel config: not online yet");
                return;
            }
        };
        online
            .sequencer_mut()
            .submit_signed_config(*submission)
            .await;
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
        let online = self.state.online()?;

        let size = u64::try_from(
            borsh::object_length(&transaction)
                .expect("Transaction borsh serialization should not fail"),
        )
        .expect("Transaction size should fit in u64");
        if let Some(max) = online
            .sequencer()
            .with_state(sequencer_core::max_transaction_size)
            .await
            && size > max
        {
            return Err(Error::TransactionTooLarge { size, max });
        }

        // Fee admission against the head state, before the mempool sees it.
        // Advisory (base fees and balances move), but everything it turns
        // away would have been refused by the block builder anyway.
        online
            .sequencer()
            .with_state(|state| sequencer_core::fees::screen(&transaction, state))
            .await
            .map_err(|err| {
                if let sequencer_core::fees::Error::FeeCore(FeeError::PrivateFeeBelowRequired {
                    required,
                    reserve,
                }) = err
                {
                    Error::PrivateFeeBelowHead { required, reserve }
                } else {
                    Error::IncorrectFee(err.into())
                }
            })?;

        online
            .mempool_handle()
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
        Ok(self.state.online()?.sequencer().chain_height().await)
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<GetAccountBalance>
    for ExecutorActor<S, B>
{
    type Reply = Result<Balance>;

    async fn handle(
        &mut self,
        GetAccountBalance { account_id }: GetAccountBalance,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .state
            .online()?
            .sequencer()
            .with_state(|state| {
                state
                    .get_account_by_id_ref(account_id)
                    .map_or(0, |account| {
                        account.data.native_balance().unwrap_or_default()
                    })
            })
            .await)
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<GetFeeQuote> for ExecutorActor<S, B> {
    type Reply = Result<FeeStateQuote>;

    async fn handle(
        &mut self,
        GetFeeQuote: GetFeeQuote,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .state
            .online()?
            .sequencer()
            .with_state(sequencer_core::fees::fee_quote)
            .map(Into::into)
            .await)
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
    type Reply = Result<Vec<Nonce>>;

    async fn handle(
        &mut self,
        GetAccountNonces { account_ids }: GetAccountNonces,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .state
            .online()?
            .sequencer()
            .with_state(|state| {
                account_ids
                    .into_iter()
                    .map(|account_id| {
                        state
                            .get_account_by_id_ref(account_id)
                            .map_or_else(Nonce::default, |account| account.nonce)
                    })
                    .collect()
            })
            .await)
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<GetProofsAndRoot> for ExecutorActor<S, B> {
    type Reply = Result<GetProofsAndRootReply>;

    async fn handle(
        &mut self,
        GetProofsAndRoot {
            commitments,
            message_positions,
        }: GetProofsAndRoot,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .state
            .online()?
            .sequencer()
            .with_state(|state| {
                let proofs = commitments
                    .iter()
                    .map(|commitment| state.get_proof_for_commitment(commitment))
                    .collect();
                let message_paths = message_positions
                    .iter()
                    .map(|position| state.get_proof_for_position(*position))
                    .collect();
                GetProofsAndRootReply {
                    proofs,
                    message_paths,
                    root: state.commitment_root(),
                }
            })
            .await)
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<GetAccount> for ExecutorActor<S, B> {
    type Reply = Result<Option<Account>>;

    async fn handle(
        &mut self,
        GetAccount { account_id }: GetAccount,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .state
            .online()?
            .sequencer()
            .with_state(|state| state.get_account_by_id_ref(account_id).cloned())
            .await)
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<GetAccountView> for ExecutorActor<S, B> {
    type Reply = Result<Option<Account>>;

    async fn handle(
        &mut self,
        GetAccountView {
            actor_state_selector:
                Actor {
                    account_id,
                    program_account_id,
                },
        }: GetAccountView,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .state
            .online()?
            .sequencer()
            .with_state(|state| {
                state
                    .get_account_by_id_ref(account_id)
                    .map(|account| account.project([program_account_id]))
            })
            .await)
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<GetPublications> for ExecutorActor<S, B> {
    type Reply = Result<Vec<(CommitmentPosition, Publication)>>;

    async fn handle(
        &mut self,
        GetPublications {
            from_position,
            limit,
        }: GetPublications,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let limit = usize::try_from(limit.min(MAX_PUBLICATIONS_PER_REQUEST))
            .expect("the request limit fits in usize");
        Ok(self
            .state
            .online()?
            .sequencer()
            .with_state(|state| state.publications_from(from_position).take(limit).collect())
            .await)
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<GetMessagePath> for ExecutorActor<S, B> {
    type Reply = Result<Option<MembershipProof>>;

    async fn handle(
        &mut self,
        GetMessagePath { position }: GetMessagePath,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .state
            .online()?
            .sequencer()
            .with_state(|state| state.get_proof_for_position(position))
            .await)
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<GetRecoveryBinding>
    for ExecutorActor<S, B>
{
    type Reply = Result<Option<EncryptedNote>>;

    async fn handle(
        &mut self,
        GetRecoveryBinding { address }: GetRecoveryBinding,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .state
            .online()?
            .sequencer()
            .with_state(|state| state.recovery_binding(address).cloned())
            .await)
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<GetChannelId> for ExecutorActor<S, B> {
    type Reply = Reply<ChannelId>;

    async fn handle(
        &mut self,
        GetChannelId: GetChannelId,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Reply(self.channel_id)
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
            .state
            .online()?
            .sequencer()
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
            .state
            .online()?
            .sequencer()
            .requeue_cross_zone_dead_letter(message_key)
            .await
            .map_err(Error::CrossZoneDeadLetterRequeueFailed)?;
        Ok(RequeueCrossZoneDeadLetterReply { outcome })
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<GetBlockByHash> for ExecutorActor<S, B> {
    type Reply = Result<Option<u64>>;

    async fn handle(
        &mut self,
        msg: GetBlockByHash,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.storage_ref
            .ask::<sequencer_storage_actor::protocol::GetBlockByHash>(msg.into())
            .await
            .map_err(Into::into)
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<GetAccountTransactions>
    for ExecutorActor<S, B>
{
    type Reply = Result<Option<Vec<LeeTransaction>>>;

    async fn handle(
        &mut self,
        msg: GetAccountTransactions,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.storage_ref
            .ask::<sequencer_storage_actor::protocol::GetAccountTransactions>(msg.into())
            .await
            .map_err(Into::into)
    }
}

impl<S: StorageActorTrait, B: BedrockActorTrait> Message<ChannelEvent> for ExecutorActor<S, B> {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        msg: ChannelEvent,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        match msg.event {
            ChannelEventKind::FinalizedBlock(finalized_block) => {
                self.state
                    .modify(|state| async {
                        match state {
                            State::Error(details) => {
                                panic!("Actor has encountered an error state: {details}")
                            }
                            State::Bootstrapping(bootstrapping) => {
                                bootstrapping.on_finalized_block(*finalized_block).await
                            }
                            State::Online(_) => {
                                // Online state listens for Publisher events
                                Ok(state)
                            }
                        }
                    })
                    .await
                    .expect("Failed to handle finalized block, Executor cannot recover from that");
            }
            ChannelEventKind::Publisher(publisher_event) => match &mut self.state {
                State::Error(details) => panic!("Actor has encountered an error state: {details}"),
                State::Bootstrapping(_) => {
                    panic!("Publisher should not be running while executor is bootstrapping");
                }
                State::Online(online) => match publisher_event {
                    PublisherEvent::Update(channel_update) => {
                        online
                            .sequencer_mut()
                            .on_channel_update(*channel_update)
                            .await;
                    }
                    PublisherEvent::Turn { our_turn_to_write } => {
                        online.set_is_our_turn(our_turn_to_write);
                    }
                    PublisherEvent::Config(live_channel_config) => {
                        online
                            .sequencer_mut()
                            .on_channel_config_update(live_channel_config)
                            .await;
                    }
                    PublisherEvent::Deposits(deposits) => {
                        online.sequencer_mut().on_observed_deposits(deposits).await;
                    }
                },
            },
        }

        Ok(())
    }
}
