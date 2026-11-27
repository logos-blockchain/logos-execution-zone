use std::ops::ControlFlow;

use common::{
    PageLimit,
    block::{Block, TransactionReceipt},
    transaction::LeeTransaction,
};
use fee_core::validity::FeeError;
use futures::FutureExt as _;
use kameo::{
    actor::{ActorId, ActorRef, WeakActorRef},
    error::ActorStopReason,
    message::{Context, Message},
    reply::DelegatedReply,
};
use kameo_actors::pubsub::PubSub;
use lee::Account;
use lee_core::{
    BlockId, EncryptedNote, MembershipProof,
    account::{Actor, Balance, Nonce},
};
use sequencer_actors_common::{Reply, SendErrorExt};
use sequencer_bedrock_actor::{
    BedrockActorTrait,
    protocol::{ChannelEvent, ChannelEventKind, Ed25519Key},
};
use sequencer_channel_signing_actor::{ChannelSigningActor, protocol as channel_signing_protocol};
use sequencer_core::{
    StakeConfigUpdate,
    config::SequencerConfig,
    storage::{
        CoreStorage,
        blocks::{BlockIdByHashRecord, BlockRecord},
    },
};
use sequencer_slasher_actor::SlasherActorTrait;
use sequencer_storage_actor::{
    encoding::BigEndian,
    protocol::{Get, GetRange},
};
use sharding_pool_actor::{
    ShardingPoolActor,
    protocol::{Link, Reset, Unlink},
};
use tracing::{Instrument as _, debug, warn};

use crate::{
    ExecutorActorTrait, Result,
    actor::state::State,
    error::Error,
    protocol::{
        ChannelId, ExecutorStatus, FeeStateQuote, GetAccount, GetAccountBalance, GetAccountNonces,
        GetAccountTransactions, GetAccountView, GetBlock, GetBlockByHash, GetBlockRange,
        GetChannelId, GetFeeQuote, GetLastBlockId, GetMessagePath, GetProofsAndRoot,
        GetProofsAndRootReply, GetPublications, GetPublicationsReply, GetRecoveryBinding,
        GetStatus, GetSystemProposals, GetSystemProposalsReply, GetTransaction,
        GetTransactionReceipt, ProduceBlock, SubmitSystemApproval, Transaction,
    },
};

mod conversions;
mod queries;
mod state;
#[cfg(test)]
mod tests;

const MAX_PUBLICATIONS_PER_REQUEST: PageLimit = 256;

/// What [`ExecutorActor`] starts from, on every start.
pub struct Args<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> {
    pub config: SequencerConfig,
    pub channel_signing_key: Ed25519Key,
    pub storage_ref: ActorRef<S>,
    pub bedrock_pool_ref: ActorRef<ShardingPoolActor<B, ChannelId>>,
    pub stake_config_pubsub_ref: ActorRef<PubSub<StakeConfigUpdate>>,
    pub slasher_ref: ActorRef<Sl>,
    pub channel_signer_ref: ActorRef<ChannelSigningActor>,
}

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Clone for Args<S, B, Sl> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            channel_signing_key: self.channel_signing_key.clone(),
            storage_ref: self.storage_ref.clone(),
            bedrock_pool_ref: self.bedrock_pool_ref.clone(),
            stake_config_pubsub_ref: self.stake_config_pubsub_ref.clone(),
            slasher_ref: self.slasher_ref.clone(),
            channel_signer_ref: self.channel_signer_ref.clone(),
        }
    }
}

/// Marks where the channel events of the Bedrock actor of an earlier start end in the mailbox.
struct ChannelEventsResumed;

/// Restarts along with the Bedrock actor of its channel, so it is meant to be supervised.
pub struct ExecutorActor<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> {
    state: State<S, B, Sl>,
    channel_id: ChannelId,
    storage_ref: ActorRef<S>,
    /// Whether [`ChannelEventsResumed`] was handled. A restart keeps the mailbox, so the events
    /// ahead of it come from the Bedrock actor of an earlier start.
    channel_events_resumed: bool,

    /// Consecutive production turns that failed outright. A run of these looks
    /// exactly like an idle node in every other signal, so it gets its own.
    failed_attempts: u32,
}

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> ExecutorActorTrait
    for ExecutorActor<S, B, Sl>
{
}

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> kameo::Actor
    for ExecutorActor<S, B, Sl>
{
    type Args = Args<S, B, Sl>;
    type Error = Error;

    async fn on_start(args: Self::Args, actor_ref: ActorRef<Self>) -> Result<Self> {
        sequencer_executor_actor_metrics::init();

        let channel_id = args.config.bedrock_config.channel_id;
        let bedrock_pool_ref = args.bedrock_pool_ref.clone();

        // A Bedrock actor of an earlier start holds that start's publisher. Unlinked first, as its
        // death must not stop this start.
        bedrock_pool_ref
            .ask(Unlink {
                key: channel_id,
                sibling: actor_ref.clone(),
            })
            .await
            .map_err(Error::from_infallible_bedrock_error)?;
        bedrock_pool_ref
            .ask(Reset { key: channel_id })
            .await
            .map_err(Error::from_infallible_bedrock_error)?;

        // The reset stopped that actor, so its events are all in the mailbox, ahead of the marker.
        actor_ref
            .tell(ChannelEventsResumed)
            .await
            .map_err(Error::from_infallible_bedrock_error)?;

        let bedrock_started = bedrock_pool_ref
            .ask(Link {
                key: channel_id,
                sibling: actor_ref.clone(),
            })
            .await
            .map_err(Error::from_infallible_bedrock_error)?;
        if !bedrock_started {
            return Err(Error::BedrockActorStartFailed);
        }
        let follow_start = bedrock_pool_ref
            .ask(sequencer_bedrock_actor::protocol::FollowChannel {
                channel_id,
                recipient: actor_ref.clone().reply_recipient(),
            })
            .await
            .map_err(SendErrorExt::flatten)?;

        let storage_ref = args.storage_ref.clone();
        let state = State::initialize(args, follow_start).await?;

        Ok(Self {
            state,
            channel_id,
            storage_ref,
            channel_events_resumed: false,
            failed_attempts: 0,
        })
    }

    async fn on_link_died(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        id: ActorId,
        reason: ActorStopReason,
    ) -> Result<ControlFlow<ActorStopReason>> {
        // The only link is the Bedrock actor of the channel, whose publisher this start set up.
        warn!(
            channel_id = %self.channel_id,
            %reason,
            "Bedrock actor of the channel stopped, so the executor restarts with a fresh one"
        );
        Ok(ControlFlow::Break(ActorStopReason::LinkDied {
            id,
            reason: Box::new(reason),
        }))
    }
}

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<ChannelEventsResumed>
    for ExecutorActor<S, B, Sl>
{
    type Reply = ();

    async fn handle(
        &mut self,
        ChannelEventsResumed: ChannelEventsResumed,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.channel_events_resumed = true;
    }
}

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<ProduceBlock>
    for ExecutorActor<S, B, Sl>
{
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
                tracing::info!(
                    block_id = id,
                    producer = %online.sequencer().channel_signing_public_key_hex(),
                    "Block created"
                );
            }
            Err(err) if err.is::<sequencer_core::ChannelMovedWhileBuilding>() => {
                // Skipping turn until next time hoping to catch up all missed updates
                warn!(error = %err, "Skipping turn");
            }
            Err(err) => {
                self.failed_attempts = self.failed_attempts.saturating_add(1);
                sequencer_executor_actor_metrics::record_production_failed_attempts(
                    self.failed_attempts,
                );
                warn!(
                    failed_attempts = self.failed_attempts,
                    error = format_args!("{err:#}"),
                    "Skipping turn: block production failed"
                );
            }
        }

        Ok(())
    }
}

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait>
    Message<channel_signing_protocol::SubmitConfig> for ExecutorActor<S, B, Sl>
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

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<Transaction>
    for ExecutorActor<S, B, Sl>
{
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        Transaction {
            transaction,
            origin,
        }: Transaction,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let online = self.state.online_mut()?;

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

        // Admission against the head state and the pending slots, before the
        // mempool sees it: the fee screen first, so an unfundable transaction
        // costs no signature verification, then authentication, then the slots
        // (first seen wins). Only a malformed transaction is refused definitively
        // (see `Error::is_definitive`); the rest depend on this node's head and
        // mempool. An identical re-send is already pending.
        let admission = online
            .sequencer_mut()
            .admit(&transaction)
            .await
            .map_err(admission_error)?;
        if admission == sequencer_core::pending::Admission::Duplicate {
            return Ok(());
        }

        online
            .mempool_handle()
            .try_push((origin.into(), transaction.clone()))
            .map_err(|_err| Error::MempoolIsFull)?;
        online.sequencer_mut().record_pending(&transaction);
        Ok(())
    }
}

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<GetBlock>
    for ExecutorActor<S, B, Sl>
{
    type Reply = Result<Option<Block>>;

    async fn handle(
        &mut self,
        GetBlock { block_id }: GetBlock,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .storage_ref
            .ask(Get::<BlockRecord>::new(BigEndian::new(&block_id)))
            .await?
            .map(|record| record.block))
    }
}

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<GetBlockRange>
    for ExecutorActor<S, B, Sl>
{
    type Reply = DelegatedReply<Result<Vec<Block>>>;

    async fn handle(
        &mut self,
        GetBlockRange { range }: GetBlockRange,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let storage_ref = self.storage_ref.clone();
        // Not inside the handler's span, which would stay open, and timed,
        // until the read ends.
        let read = tracing::info_span!(parent: None, "block_range_read");
        read.follows_from(tracing::Span::current());

        let ids = range.into_inner();
        ctx.spawn(async move {
            let records = storage_ref
                .ask(GetRange::<BlockRecord>::new(
                    Some(BigEndian::new(ids.start())),
                    Some(BigEndian::new(ids.end())),
                    // We're sure that range is not too big thanks to [`BoundedRangeInclusive`]
                    usize::MAX,
                ))
                .into_future()
                .instrument(read)
                .await?;
            // Up to the first missing block.
            Ok(records
                .into_iter()
                .map(|(_block_id, record)| record.block)
                .zip(ids)
                .take_while(|(block, block_id)| block.header.block_id == *block_id)
                .map(|(block, _)| block)
                .collect())
        })
    }
}

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<GetLastBlockId>
    for ExecutorActor<S, B, Sl>
{
    type Reply = Result<BlockId>;

    async fn handle(
        &mut self,
        GetLastBlockId: GetLastBlockId,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self.state.online()?.sequencer().chain_height().await)
    }
}

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<GetAccountBalance>
    for ExecutorActor<S, B, Sl>
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

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<GetFeeQuote>
    for ExecutorActor<S, B, Sl>
{
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

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<GetTransaction>
    for ExecutorActor<S, B, Sl>
{
    type Reply = Result<Option<(LeeTransaction, BlockId)>>;

    async fn handle(
        &mut self,
        GetTransaction { tx_hash }: GetTransaction,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(queries::block_with_transaction(&self.storage_ref, tx_hash)
            .await?
            .map(|(mut block, position)| {
                (
                    block.body.transactions.swap_remove(position),
                    block.header.block_id,
                )
            }))
    }
}

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<GetTransactionReceipt>
    for ExecutorActor<S, B, Sl>
{
    type Reply = Result<Option<TransactionReceipt>>;

    async fn handle(
        &mut self,
        GetTransactionReceipt { tx_hash }: GetTransactionReceipt,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // `None` also for a block's trailing fee and clock transactions, which have no receipt.
        Ok(queries::block_with_transaction(&self.storage_ref, tx_hash)
            .await?
            .and_then(|(block, position)| block.body.receipts.get(position).copied()))
    }
}

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<GetAccountNonces>
    for ExecutorActor<S, B, Sl>
{
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

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<GetProofsAndRoot>
    for ExecutorActor<S, B, Sl>
{
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

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<GetAccount>
    for ExecutorActor<S, B, Sl>
{
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

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<GetAccountView>
    for ExecutorActor<S, B, Sl>
{
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

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<GetPublications>
    for ExecutorActor<S, B, Sl>
{
    type Reply = Result<GetPublicationsReply>;

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
        Ok(GetPublicationsReply {
            page: self
                .state
                .online()?
                .sequencer()
                .with_state(|state| state.publications_page(from_position, limit))
                .await,
        })
    }
}

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<GetMessagePath>
    for ExecutorActor<S, B, Sl>
{
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

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<GetRecoveryBinding>
    for ExecutorActor<S, B, Sl>
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

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<GetChannelId>
    for ExecutorActor<S, B, Sl>
{
    type Reply = Reply<ChannelId>;

    async fn handle(
        &mut self,
        GetChannelId: GetChannelId,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Reply(self.channel_id)
    }
}

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<GetStatus>
    for ExecutorActor<S, B, Sl>
{
    type Reply = ExecutorStatus;

    async fn handle(
        &mut self,
        GetStatus: GetStatus,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        match &self.state {
            State::Error(details) => panic!("Actor has encountered an error state: {details}"),
            State::Bootstrapping(bootstrapping) => ExecutorStatus::Bootstrapping {
                target: bootstrapping.bootstrap_to(),
                replayed_up_to: bootstrapping.replayed_up_to(),
                height: bootstrapping.chain().head_tip().map(|tip| tip.block_id),
            },
            State::Online(online) => ExecutorStatus::Online {
                height: online.sequencer().chain_height().await,
                is_our_turn: online.is_our_turn(),
            },
        }
    }
}

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<GetSystemProposals>
    for ExecutorActor<S, B, Sl>
{
    type Reply = Result<GetSystemProposalsReply>;

    async fn handle(
        &mut self,
        GetSystemProposals: GetSystemProposals,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let sequencer_core::system_approvals::SystemProposals {
            threshold,
            proposals,
        } = self
            .state
            .online()?
            .sequencer()
            .system_proposals()
            .await
            .map_err(Error::SystemProposalsUnavailable)?;
        Ok(GetSystemProposalsReply {
            threshold,
            proposals,
        })
    }
}

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<SubmitSystemApproval>
    for ExecutorActor<S, B, Sl>
{
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        SubmitSystemApproval { approval }: SubmitSystemApproval,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let State::Online(online) = &mut self.state else {
            return Err(Error::NotOnline);
        };
        online
            .sequencer_mut()
            .submit_system_approval(approval)
            .await
            .map_err(Error::SystemApprovalRefused)
    }
}

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<GetBlockByHash>
    for ExecutorActor<S, B, Sl>
{
    type Reply = Result<Option<u64>>;

    async fn handle(
        &mut self,
        GetBlockByHash { block_hash }: GetBlockByHash,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self
            .storage_ref
            .ask(Get::<BlockIdByHashRecord>::new(block_hash))
            .await?
            .map(|record| record.block_id))
    }
}

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<GetAccountTransactions>
    for ExecutorActor<S, B, Sl>
{
    type Reply = Result<Option<Vec<LeeTransaction>>>;

    async fn handle(
        &mut self,
        GetAccountTransactions {
            account_id,
            offset,
            limit,
        }: GetAccountTransactions,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        queries::account_transactions(&self.storage_ref, account_id, offset, limit).await
    }
}

impl<S: CoreStorage, B: BedrockActorTrait, Sl: SlasherActorTrait> Message<ChannelEvent>
    for ExecutorActor<S, B, Sl>
{
    /// An `Err` stops the Bedrock actor, and so this one, as they are linked.
    type Reply = std::result::Result<(), sequencer_bedrock_actor::protocol::ChannelEventFailed>;

    async fn handle(
        &mut self,
        msg: ChannelEvent,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        if !self.channel_events_resumed {
            debug!("Dropping a channel event of the Bedrock actor of an earlier start");
            return Ok(());
        }

        if msg.channel_id != self.channel_id {
            warn!(
                channel_id = %msg.channel_id,
                "Received a channel event for a different channel"
            );
        }

        let event = msg.event;
        match &mut self.state {
            State::Error(details) => panic!("Actor has encountered an error state: {details}"),
            State::Bootstrapping(_) => {
                // A failure can leave the chain ahead of the store, so it ends in the error state.
                Box::pin(self.state.modify(|state| async move {
                    match state {
                        State::Bootstrapping(bootstrapping) => {
                            Box::pin(bootstrapping.on_channel_event(&event)).await
                        }
                        State::Error(_) | State::Online(_) => Ok(state),
                    }
                }))
                .await
                .map_err(anyhow::Error::from)?;
            }
            State::Online(online) => match &event {
                ChannelEventKind::Update(channel_update) => {
                    online
                        .sequencer_mut()
                        .on_channel_update(channel_update)
                        .await;
                }
                ChannelEventKind::Ready => {}
                ChannelEventKind::Turn {
                    our_turn_to_write,
                    starting_slot,
                } => {
                    online.update_turn(*our_turn_to_write, *starting_slot);
                }
                ChannelEventKind::Config(live_channel_config) => {
                    online
                        .sequencer_mut()
                        .on_channel_config_update(live_channel_config)
                        .await;
                }
            },
        }

        Ok(())
    }
}

fn admission_error(err: sequencer_core::AdmissionError) -> Error {
    match err {
        sequencer_core::AdmissionError::Fee(sequencer_core::fees::Error::FeeCore(
            FeeError::PrivateFeeBelowRequired { required, reserve },
        )) => Error::PrivateFeeBelowHead { required, reserve },
        sequencer_core::AdmissionError::Fee(err) => Error::IncorrectFee(err.into()),
        sequencer_core::AdmissionError::Authentication(lee::HeadAuthError::Definitive(err)) => {
            Error::InvalidTransaction(err)
        }
        sequencer_core::AdmissionError::Authentication(lee::HeadAuthError::AtHead(err)) => {
            Error::RefusedAtHead(err)
        }
        sequencer_core::AdmissionError::Authentication(lee::HeadAuthError::Pending(err)) => {
            Error::PendingAuthentication(err)
        }
        sequencer_core::AdmissionError::Pending(refusal) => Error::PendingSlot(refusal.into()),
        sequencer_core::AdmissionError::InvalidProof => {
            Error::InvalidTransaction(lee::error::LeeError::InvalidPrivacyPreservingProof)
        }
    }
}
