use std::{
    collections::{BTreeSet, HashMap, HashSet},
    num::NonZero,
    time::Duration,
};

use anyhow::anyhow;
use chain_state::timeout_node::TimeoutNode;
use common::block::Block;
use kameo::{
    Actor,
    actor::{ActorRef, WeakActorRef},
    mailbox::{MailboxReceiver, Signal},
    message::{Context, Message},
};
use logos_blockchain_zone_sdk::{
    CommonHttpClient,
    adapter::{Node as _, NodeHttpClient},
    common_http_client::BasicAuthCredentials,
    core::mantle::NoteId,
    sequencer::{InscriptionInfo, PendingTx},
};
use sequencer_storage_actor::protocol::{Get, Store};
use tokio::select;
use tracing::{info_span, warn};

#[cfg(feature = "test-utils")]
use crate::protocol::PublishRawInscription;
use crate::{
    BedrockActorTrait, Result, Url,
    actor::finality::{BlockSummary, ConfigIndex, L1Reader},
    error::Error,
    protocol::{
        AccreditedKeys, ChangeChannelConfig, ChannelId, CheckChannelExists, CheckIsOurTurn,
        CreateChannel, Ed25519PublicKey, FilterFinallyAbsent, FollowChannel, FollowStart,
        GetAccreditedKeys, GetChannelNotes, GetChannelTipMessageId, GetChannelTipSlot, HeaderId,
        InitializeChannelPublisher, LiveChannelConfig, MsgId, PendingBlock, PrepareConfig,
        PreparePin, PreparedConfig, PreparedPin, PublishBlock, PublishOutcome, PublishPin,
        SequencerCheckpoint, SequencerKey, Slot, UnverifiedEd25519PublicKey,
    },
    storage::{BedrockStorage, FinalConfigs, ZoneCheckpoint},
};

mod channel;
mod delivery;
pub(crate) mod finality;
#[cfg(test)]
mod tests;

/// Time one [`FilterFinallyAbsent`] may hold the actor; the blocks and configs it read are kept.
const FILTER_FINALLY_ABSENT_BUDGET: Duration = Duration::from_secs(10);

pub struct Args<S: BedrockStorage> {
    pub node_url: Url,
    pub basic_auth: Option<BasicAuthCredentials>,
    pub channel_id: ChannelId,
    /// Slots of finalized history each read covers.
    pub backfill_batch_slots: NonZero<u64>,
    pub storage_ref: ActorRef<S>,
}

/// Bedrock Actor responsible for interacting with the Bedrock node and managing channel events.
///
/// This actor is expected to be used together with [`sharding_pool_actor`]. However it can be used
/// on its own but make sure to provide the correct `channel_id` in every message. Passing
/// unexpected `channel_id` will lead to a panic.
///
/// To be able to submit channel updates, you must first submit an [`InitializeChannelPublisher`]
/// message, otherwise [`Error::ChannelPublisherIsNotInitialized`] will be returned.
///
/// Once the channel is followed with [`FollowChannel`], [`BedrockActor`] asks its recipient each
/// [`ChannelEvent`](crate::protocol::ChannelEvent) in turn, reading the channel on only once the
/// recipient replied. Messages are still handled while it waits, as the recipient may ask some of
/// its own on the way.
pub struct BedrockActor<S: BedrockStorage> {
    channel_id: ChannelId,
    backfill_batch_slots: NonZero<u64>,
    node: TimeoutNode<NodeHttpClient>,
    /// [`Some`] after [`FollowChannel`] or [`InitializeChannelPublisher`] has been handled.
    channel: Option<channel::Channel>,
    /// The channel's events on their way to the [`FollowChannel::recipient`].
    deliveries: delivery::Deliveries,
    storage_ref: ActorRef<S>,
    /// Summaries of the L1 blocks [`FilterFinallyAbsent`] walked, by id.
    block_summary_cache: HashMap<HeaderId, BlockSummary>,
    /// The channel's final configs, from zone-sdk's finalized events and [`FilterFinallyAbsent`]
    /// reads.
    config_index: ConfigIndex,
}

impl<S: BedrockStorage> BedrockActor<S> {
    fn assert_channel_id(&self, channel_id: ChannelId) {
        assert_eq!(self.channel_id, channel_id, "Channel ID mismatch");
    }

    const fn publishing_channel(&mut self) -> Result<&mut channel::PublishingChannel> {
        match &mut self.channel {
            Some(channel::Channel::Publishing(publishing)) => Ok(publishing),
            Some(channel::Channel::Followed(_)) | None => {
                Err(Error::ChannelPublisherIsNotInitialized)
            }
        }
    }

    /// Starts following the channel from the stored checkpoint, returning it with the last config
    /// entry that checkpoint holds final.
    async fn follow(&mut self) -> Result<(channel::FollowedChannel, MsgId)> {
        let checkpoint = self.resume_checkpoint().await?;
        let finalized_config = checkpoint
            .as_ref()
            .map_or_else(MsgId::root, |checkpoint| checkpoint.finalized_config);
        let followed = channel::FollowedChannel::follow(
            self.channel_id,
            self.node.clone(),
            self.backfill_batch_slots,
            checkpoint,
        )
        .await?;
        self.store_config_index().await;
        Ok((followed, finalized_config))
    }

    /// The stored checkpoint, with the config index read up to its LIB, as zone-sdk's events
    /// resumed from it start after it.
    async fn resume_checkpoint(&mut self) -> Result<Option<SequencerCheckpoint>> {
        let Some(ZoneCheckpoint(checkpoint)) = self
            .storage_ref
            .ask(Get::<ZoneCheckpoint>::default())
            .await?
        else {
            return Ok(None);
        };
        let mut reader = NodeReader {
            node: &self.node,
            block_summary_cache: &mut self.block_summary_cache,
            channel_id: self.channel_id,
        };
        self.config_index
            .cover_through(&mut reader, checkpoint.lib_slot.into_inner())
            .await?;
        Ok(Some(checkpoint))
    }

    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "Helps to make returned future Send"
    )]
    async fn store_checkpoint(&mut self, checkpoint: &SequencerCheckpoint) {
        if let Err(err) = self
            .storage_ref
            .ask(Store::from_value(ZoneCheckpoint(checkpoint.clone())))
            .await
        {
            warn!(error = %err, "Failed to store the zone checkpoint");
        }
    }

    /// Stores the checkpoint of `published` and hands back its outcome.
    async fn stored(&mut self, published: channel::Published) -> PublishOutcome {
        self.store_checkpoint(&published.checkpoint).await;
        published.outcome
    }

    /// Stores the config index when it is due.
    async fn store_config_index(&mut self) {
        if !self.config_index.due_to_store() {
            return;
        }
        if let Err(err) = self
            .storage_ref
            .ask(Store::from_value(FinalConfigs(self.config_index.clone())))
            .await
        {
            warn!(error = %err, "Failed to store the channel's final configs");
        }
    }
}

impl<S: BedrockStorage> BedrockActorTrait for BedrockActor<S> {}

impl<S: BedrockStorage> Actor for BedrockActor<S> {
    type Args = Args<S>;
    type Error = Error;

    async fn on_start(args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self> {
        let Args {
            node_url,
            basic_auth,
            channel_id,
            storage_ref,
            backfill_batch_slots,
        } = args;

        let node = TimeoutNode::new(NodeHttpClient::new(
            CommonHttpClient::new(basic_auth),
            node_url,
        ));

        // Following starts zone-sdk from this stored checkpoint: a cold start backfills from
        // slot 0, a restart's events start after its LIB.
        let config_index = match storage_ref.ask(Get::<ZoneCheckpoint>::default()).await? {
            None => ConfigIndex::starting_at(0),
            Some(ZoneCheckpoint(checkpoint)) => storage_ref
                .ask(Get::<FinalConfigs>::default())
                .await?
                .map_or_else(
                    || ConfigIndex::starting_at(checkpoint.lib_slot.into_inner().saturating_add(1)),
                    |FinalConfigs(index)| index,
                ),
        };

        Ok(Self {
            channel_id,
            node,
            channel: None,
            deliveries: delivery::Deliveries::new(channel_id, None),
            storage_ref,
            backfill_batch_slots,
            block_summary_cache: HashMap::new(),
            config_index,
        })
    }

    async fn next(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        mailbox_rx: &mut MailboxReceiver<Self>,
    ) -> Result<Option<Signal<Self>>> {
        #[expect(
            clippy::integer_division_remainder_used,
            reason = "Generated by select! macro, can't be easily rewritten to avoid this lint"
        )]
        loop {
            if self.deliveries.start_next() {
                select! {
                    // A handled delivery goes first, so a publish its recipient sent after
                    // replying is not refused for the update it already applied.
                    biased;

                    checkpoint = self.deliveries.delivered() => {
                        if let Some(checkpoint) = checkpoint? {
                            self.store_checkpoint(&checkpoint).await;
                        }
                    }
                    signal = mailbox_rx.recv() => {
                        return Ok(signal)
                    }
                }
            } else if let Some(channel) = self.channel.as_mut() {
                let followed = channel.followed_mut();
                select! {
                    // Messages go before new zone-sdk events, so a run of events cannot hold
                    // them up.
                    biased;

                    signal = mailbox_rx.recv() => {
                        return Ok(signal)
                    }
                    event = followed.next_event() => {
                        let span = info_span!("bedrock_event", otel.name = channel::span_name(&event));
                        span.in_scope(|| {
                            followed.on_event(event, &mut self.config_index, &mut self.deliveries)
                        })?;
                        self.store_config_index().await;
                    }
                }
            } else {
                return Ok(mailbox_rx.recv().await);
            }
        }
    }
}

impl<S: BedrockStorage> Message<FollowChannel> for BedrockActor<S> {
    type Reply = Result<FollowStart>;

    async fn handle(
        &mut self,
        FollowChannel {
            channel_id,
            recipient,
        }: FollowChannel,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);
        if self.channel.is_some() {
            return Err(Error::ChannelAlreadyFollowed);
        }

        let lib_slot = self
            .node
            .consensus_info()
            .await
            .inspect_err(|err| warn!(error = %err, "Failed to read the node's LIB"))
            .ok()
            .map(|info| info.cryptarchia_info.lib_slot);
        let (followed, finalized_config) = self.follow().await?;
        self.channel = Some(channel::Channel::Followed(followed));
        self.deliveries = delivery::Deliveries::new(channel_id, Some(recipient));
        Ok(FollowStart {
            finalized_config,
            lib_slot,
        })
    }
}

impl<S: BedrockStorage> Message<InitializeChannelPublisher> for BedrockActor<S> {
    type Reply = Result<Vec<PendingBlock>>;

    async fn handle(
        &mut self,
        InitializeChannelPublisher {
            channel_id,
            channel_signing_key,
            funding_pk,
            priority_fee_percent,
            resubmit_interval,
            stale_refund_slots,
        }: InitializeChannelPublisher,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        if let Some(channel::Channel::Publishing(publishing)) = &self.channel {
            return Ok(publishing.pending_blocks());
        }
        let followed = match self.channel.take() {
            None => self.follow().await?.0,
            Some(channel::Channel::Followed(followed)) => followed,
            Some(channel::Channel::Publishing(_)) => unreachable!("Returned above"),
        };

        let mut publishing = followed.into_publishing(channel::PublishConfig {
            channel_signing_key,
            funding_pk,
            priority_fee_percent,
            resubmit_interval,
            stale_refund_slots,
        });
        let ready = publishing
            .wait_until_ready(&mut self.config_index, &mut self.deliveries)
            .await;
        let pending_blocks = publishing.pending_blocks();
        self.channel = Some(channel::Channel::Publishing(publishing));
        self.store_config_index().await;
        ready.map(|()| pending_blocks)
    }
}

impl<S: BedrockStorage> Message<CreateChannel> for BedrockActor<S> {
    type Reply = Result<PublishOutcome>;

    async fn handle(
        &mut self,
        CreateChannel {
            channel_id,
            genesis,
            keys,
            channel_params,
            configuration_threshold,
            transfer_threshold,
        }: CreateChannel,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        let published = self
            .publishing_channel()?
            .create_channel(
                genesis,
                keys,
                channel_params,
                configuration_threshold,
                transfer_threshold,
            )
            .await?;
        Ok(self.stored(published).await)
    }
}

impl<S: BedrockStorage> Message<PublishBlock> for BedrockActor<S> {
    type Reply = Result<PublishOutcome>;

    async fn handle(
        &mut self,
        PublishBlock {
            channel_id,
            block,
            withdrawals,
            parent,
        }: PublishBlock,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);
        self.deliveries.check_not_moved()?;

        let published = self
            .publishing_channel()?
            .publish_block(block, withdrawals, parent)
            .await?;
        Ok(self.stored(published).await)
    }
}

impl<S: BedrockStorage> Message<PreparePin> for BedrockActor<S> {
    type Reply = Result<PreparedPin>;

    async fn handle(
        &mut self,
        PreparePin {
            channel_id,
            block,
            parent,
            notes,
        }: PreparePin,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);
        self.deliveries.check_not_moved()?;

        self.publishing_channel()?
            .prepare_pin(block, parent, &notes)
            .await
    }
}

impl<S: BedrockStorage> Message<PublishPin> for BedrockActor<S> {
    type Reply = Result<PublishOutcome>;

    async fn handle(
        &mut self,
        PublishPin {
            channel_id,
            prepared,
            signatures,
        }: PublishPin,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);
        self.deliveries.check_not_moved()?;

        let published = self
            .publishing_channel()?
            .publish_pin(prepared, signatures)?;
        Ok(self.stored(published).await)
    }
}

impl<S: BedrockStorage> Message<PrepareConfig> for BedrockActor<S> {
    type Reply = Result<PreparedConfig>;

    async fn handle(
        &mut self,
        PrepareConfig {
            channel_id,
            keys,
            posting_timeframe,
            posting_timeout,
            configuration_threshold,
            transfer_threshold,
        }: PrepareConfig,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        self.publishing_channel()?
            .prepare_config(
                keys,
                posting_timeframe,
                posting_timeout,
                configuration_threshold,
                transfer_threshold,
            )
            .await
    }
}

impl<S: BedrockStorage> Message<ChangeChannelConfig> for BedrockActor<S> {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        ChangeChannelConfig {
            channel_id,
            prepared,
            signatures,
        }: ChangeChannelConfig,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        self.publishing_channel()?
            .change_channel_config(prepared, signatures)
    }
}

impl<S: BedrockStorage> Message<CheckChannelExists> for BedrockActor<S> {
    type Reply = Result<bool>;

    async fn handle(
        &mut self,
        CheckChannelExists { channel_id }: CheckChannelExists,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        Ok(self
            .node
            .channel_state(channel_id)
            .await
            .map_err(|err| Error::NodeRequestFailed(err.into()))?
            .is_some())
    }
}

impl<S: BedrockStorage> Message<CheckIsOurTurn> for BedrockActor<S> {
    type Reply = Result<bool>;

    async fn handle(
        &mut self,
        CheckIsOurTurn { channel_id }: CheckIsOurTurn,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        Ok(self.publishing_channel()?.check_is_our_turn())
    }
}

impl<S: BedrockStorage> Message<GetAccreditedKeys> for BedrockActor<S> {
    type Reply = Result<Option<AccreditedKeys>>;

    async fn handle(
        &mut self,
        GetAccreditedKeys { channel_id }: GetAccreditedKeys,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        self.node
            .channel_state(self.channel_id)
            .await
            .map_err(|err| Error::NodeRequestFailed(err.into()))?
            .map(|state| -> Result<AccreditedKeys> {
                Ok(AccreditedKeys {
                    keys: verified_keys(&state.accredited_keys)?,
                    config_tip: state.config_tip_hash,
                    tip_sequencer: state.tip_sequencer,
                    tip_slot: state.tip_slot,
                })
            })
            .transpose()
    }
}

impl<S: BedrockStorage> Message<GetChannelNotes> for BedrockActor<S> {
    type Reply = Result<HashSet<NoteId>>;

    async fn handle(
        &mut self,
        GetChannelNotes { channel_id }: GetChannelNotes,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        Ok(self.publishing_channel()?.channel_notes())
    }
}

impl<S: BedrockStorage> Message<GetChannelTipSlot> for BedrockActor<S> {
    type Reply = Result<Option<Slot>>;

    async fn handle(
        &mut self,
        GetChannelTipSlot { channel_id }: GetChannelTipSlot,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        Ok(self
            .node
            .channel_state(self.channel_id)
            .await
            .map_err(|err| Error::NodeRequestFailed(err.into()))?
            .map(|state| state.tip_slot))
    }
}

impl<S: BedrockStorage> Message<GetChannelTipMessageId> for BedrockActor<S> {
    type Reply = Result<Option<MsgId>>;

    async fn handle(
        &mut self,
        GetChannelTipMessageId { channel_id }: GetChannelTipMessageId,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        Ok(self
            .node
            .channel_state(self.channel_id)
            .await
            .map_err(|err| Error::NodeRequestFailed(err.into()))?
            .map(|state| state.tip_message))
    }
}

impl<S: BedrockStorage> Message<FilterFinallyAbsent> for BedrockActor<S> {
    type Reply = Result<BTreeSet<SequencerKey>>;

    async fn handle(
        &mut self,
        FilterFinallyAbsent {
            channel_id,
            at,
            keys,
            depth,
        }: FilterFinallyAbsent,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        let mut reader = NodeReader {
            node: &self.node,
            block_summary_cache: &mut self.block_summary_cache,
            channel_id,
        };
        let walk =
            finality::filter_finally_absent(&mut reader, &mut self.config_index, at, &keys, depth);
        let verdict = tokio::time::timeout(FILTER_FINALLY_ABSENT_BUDGET, walk)
            .await
            .unwrap_or(Err(Error::VerdictTimedOut));
        self.store_config_index().await;
        if verdict.is_ok() && self.block_summary_cache.len() >= NodeReader::CACHE_CAPACITY {
            keep_newest_block_summaries(&mut self.block_summary_cache);
        }
        verdict
    }
}

/// [`L1Reader`] over the node, caching the block summaries it reads by id.
struct NodeReader<'actor> {
    node: &'actor TimeoutNode<NodeHttpClient>,
    block_summary_cache: &'actor mut HashMap<HeaderId, BlockSummary>,
    channel_id: ChannelId,
}

impl NodeReader<'_> {
    /// Block summaries cached before a walk that returns a verdict drops all but the newest
    /// [`Self::CACHE_KEPT`].
    const CACHE_CAPACITY: usize = 4096;
    /// Block summaries a full cache keeps, the newest by slot, so a walk over fewer blocks stays
    /// cached.
    const CACHE_KEPT: usize = 2048;

    fn summarize(&self, block: &logos_blockchain_zone_sdk::node_types::ApiBlock) -> BlockSummary {
        BlockSummary::new(
            block.header.id,
            block.header.parent_block,
            block.header.slot.into_inner(),
            &block.transactions,
            self.channel_id,
        )
    }
}

impl L1Reader for NodeReader<'_> {
    async fn tip_block_summary(&mut self) -> Result<BlockSummary> {
        let tip = self
            .node
            .consensus_info()
            .await
            .map_err(|err| Error::NodeRequestFailed(err.into()))?
            .cryptarchia_info
            .tip;
        self.block_summary(tip).await
    }

    async fn block_summary(&mut self, id: HeaderId) -> Result<BlockSummary> {
        if let Some(block_summary) = self.block_summary_cache.get(&id) {
            return Ok(block_summary.clone());
        }
        let block = self
            .node
            .block(id)
            .await
            .map_err(|err| Error::NodeRequestFailed(err.into()))?
            .ok_or(Error::BlockMissing(id))?;
        let block_summary = self.summarize(&block);
        self.block_summary_cache
            .insert(block_summary.id, block_summary.clone());
        Ok(block_summary)
    }

    async fn final_block_summaries(&mut self, from: u64, to: u64) -> Result<Vec<BlockSummary>> {
        let lib_slot = self
            .node
            .consensus_info()
            .await
            .map_err(|err| Error::NodeRequestFailed(err.into()))?
            .cryptarchia_info
            .lib_slot
            .into_inner();
        // A slot past the node's LIB is refused, not read as empty.
        if to > lib_slot {
            return Err(Error::SlotNotFinal(to));
        }
        let blocks = self
            .node
            .immutable_blocks(Slot::from(from), Slot::from(to))
            .await
            .map_err(|err| Error::NodeRequestFailed(err.into()))?;
        Ok(blocks
            .into_iter()
            .map(|block| self.summarize(&block))
            .collect())
    }
}

#[cfg(feature = "test-utils")]
impl<S: BedrockStorage> Message<PublishRawInscription> for BedrockActor<S> {
    type Reply = Result<PublishOutcome>;

    async fn handle(
        &mut self,
        PublishRawInscription { channel_id, data }: PublishRawInscription,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        let published = self
            .publishing_channel()?
            .publish_raw_inscription(data)
            .await?;
        Ok(self.stored(published).await)
    }
}

impl TryFrom<&logos_blockchain_zone_sdk::node_types::ChannelState> for LiveChannelConfig {
    type Error = Error;

    fn try_from(state: &logos_blockchain_zone_sdk::node_types::ChannelState) -> Result<Self> {
        Ok(Self {
            keys: verified_keys(&state.accredited_keys)?,
            config_tip: state.config_tip_hash,
            required_signatures: state.configuration_threshold,
            transfer_threshold: state.transfer_threshold,
            posting_timeframe: state.posting_timeframe.clone().into(),
            posting_timeout: state.posting_timeout.clone().into(),
        })
    }
}

/// Drops all but the newest [`NodeReader::CACHE_KEPT`] summaries of `cache` by slot.
fn keep_newest_block_summaries(cache: &mut HashMap<HeaderId, BlockSummary>) {
    let mut slots: Vec<u64> = cache
        .values()
        .map(|block_summary| block_summary.slot)
        .collect();
    let Some(oldest_kept) = slots.len().checked_sub(NodeReader::CACHE_KEPT) else {
        return;
    };
    let (_, &mut cutoff, _) = slots.select_nth_unstable(oldest_kept);
    cache.retain(|_, block_summary| block_summary.slot >= cutoff);
}

/// Deserialize an inscription payload into `(this_msg, Block)`. Bad payloads are
/// logged and skipped.
fn block_from_inscription(inscription: &InscriptionInfo) -> Option<Block> {
    borsh::from_slice::<Block>(&inscription.payload)
        .inspect_err(|err| {
            warn!(error = ?err, "Failed to deserialize block from inscription");
        })
        .ok()
}

/// Channel notes the withdraws bundled with a published tx release; empty for a
/// plain inscription. See [`PublishOutcome::released_notes`].
fn released_notes(tx: &PendingTx) -> Vec<NoteId> {
    match tx {
        PendingTx::Inscription(_) | PendingTx::PinDeposit(_) => Vec::new(),
        PendingTx::AtomicWithdraw(bundle) => bundle
            .withdraws
            .iter()
            .flat_map(|withdraw| withdraw.op.inputs.iter().copied())
            .collect(),
    }
}

fn verified_keys(keys: &[UnverifiedEd25519PublicKey]) -> Result<Vec<Ed25519PublicKey>> {
    keys.iter()
        .map(|key| {
            Ed25519PublicKey::try_from(*key)
                .map_err(|err| Error::InvalidChannelKeyList(anyhow!("{err:?}")))
        })
        .collect()
}
