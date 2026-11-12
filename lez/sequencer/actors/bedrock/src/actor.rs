use std::{
    collections::{BTreeSet, HashMap, HashSet},
    num::NonZero,
    time::Duration,
};

use anyhow::anyhow;
use chain_state::timeout_node::TimeoutNode;
use common::block::Block;
use futures::{
    StreamExt as _,
    future::{Either, OptionFuture},
};
use kameo::{
    Actor,
    actor::{ActorRef, WeakActorRef},
    mailbox::{MailboxReceiver, Signal},
    message::{Context, Message},
};
use kameo_actors::broker::Broker;
use logos_blockchain_common_http_client::BasicAuthCredentials;
use logos_blockchain_core::mantle::NoteId;
use logos_blockchain_zone_sdk::{
    CommonHttpClient,
    adapter::{Node as _, NodeHttpClient},
    sequencer::{InscriptionInfo, PendingTx},
};
use sequencer_storage_actor::{
    StorageActorTrait,
    protocol::{GetFinalConfigsBytes, GetZoneCheckpoint, PutFinalConfigsBytes},
};
use tokio::select;
use tracing::{Instrument as _, info_span, warn};

#[cfg(feature = "test-utils")]
use crate::protocol::PublishRawInscription;
use crate::{
    BedrockActorTrait, Result, Url,
    actor::finality::{BlockSummary, ConfigIndex, L1Reader},
    error::Error,
    protocol::{
        AccreditedKeys, ChangeChannelConfig, ChannelEvent, ChannelId, ChannelReadStream,
        ChannelSeq, CheckChannelExists, CheckIsOurTurn, CreateChannel, DeserializeOp as _,
        Ed25519PublicKey, FilterFinallyAbsent, FollowChannel, GetAccreditedKeys, GetChannelNotes,
        GetChannelTipMessageId, GetChannelTipSlot, HeaderId, InitializeChannelPublisher,
        LiveChannelConfig, MsgId, PrepareConfig, PreparePin, PreparedConfig, PreparedPin,
        PublishBlock, PublishOutcome, PublishPin, ReadChannel, SequencerCheckpoint, SequencerKey,
        Slot, UnverifiedEd25519PublicKey,
    },
};

mod finality;
mod node_stream;
mod publisher;
#[cfg(test)]
mod tests;

/// Time one [`FilterFinallyAbsent`] may hold the actor; the blocks and configs it read are kept.
const FILTER_FINALLY_ABSENT_BUDGET: Duration = Duration::from_secs(10);

pub struct Args<S: StorageActorTrait> {
    pub node_url: Url,
    pub basic_auth: Option<BasicAuthCredentials>,
    pub channel_id: ChannelId,
    /// Slots of finalized history each read covers.
    pub backfill_batch_slots: NonZero<u64>,
    pub storage_ref: ActorRef<S>,
    pub broker_ref: ActorRef<Broker<ChannelEvent>>,
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
/// [`BedrockActor`] will post [`ChannelEvent`]s to the provided broker using the following topics:
/// - If the channel is followed with [`FollowChannel`]:
///   - `channel/<channel_id>/finalized_block`: for
///     [`ChannelEventKind::FinalizedBlock`](crate::protocol::ChannelEventKind::FinalizedBlock).
///   - `channel/<channel_id>/finalized_deposit`: for
///     [`ChannelEventKind::FinalizedDeposit`](crate::protocol::ChannelEventKind::FinalizedDeposit).
///   - `channel/<channel_id>/finalized_withdrawal`: for
///     [`ChannelEventKind::FinalizedWithdrawal`](crate::protocol::ChannelEventKind::FinalizedWithdrawal).
///   - `channel/<channel_id>/finalized_up_to`: for
///     [`ChannelEventKind::FinalizedUpTo`](crate::protocol::ChannelEventKind::FinalizedUpTo).
/// - If publisher was initialized with [`InitializeChannelPublisher`]:
///   - `channel/<channel_id>/publisher/update`: for
///     [`PublisherEvent::Update`](crate::protocol::PublisherEvent::Update)
///   - `channel/<channel_id>/publisher/turn`: for
///     [`PublisherEvent::Turn`](crate::protocol::PublisherEvent::Turn)
///   - `channel/<channel_id>/publisher/config`: for
///     [`PublisherEvent::Config`](crate::protocol::PublisherEvent::Config)
///   - `channel/<channel_id>/publisher/deposits`: for
///     [`PublisherEvent::Deposits`](crate::protocol::PublisherEvent::Deposits)
pub struct BedrockActor<S: StorageActorTrait> {
    channel_id: ChannelId,
    backfill_batch_slots: NonZero<u64>,
    node: TimeoutNode<NodeHttpClient>,
    /// [`Some`] after [`FollowChannel`] has been handled.
    node_stream: Option<node_stream::NodeStream>,
    /// [`Some`] after [`InitializeChannelPublisher`] has been handled.
    publisher: Option<publisher::Publisher>,
    broker_ref: ActorRef<Broker<ChannelEvent>>,
    storage_ref: ActorRef<S>,
    /// Summaries of the L1 blocks [`FilterFinallyAbsent`] walked, by id.
    block_summary_cache: HashMap<HeaderId, BlockSummary>,
    /// The channel's final configs, from zone-sdk's finalized events and [`FilterFinallyAbsent`]
    /// reads.
    config_index: ConfigIndex,
}

impl<S: StorageActorTrait> BedrockActor<S> {
    fn assert_channel_id(&self, channel_id: ChannelId) {
        assert_eq!(self.channel_id, channel_id, "Channel ID mismatch");
    }

    fn publisher(&mut self) -> Result<&mut publisher::Publisher> {
        self.publisher
            .as_mut()
            .ok_or(Error::ChannelPublisherIsNotInitialized)
    }

    /// Stores the config index when its bytes are due.
    async fn store_config_index(&mut self) {
        let Some(bytes) = self.config_index.bytes_to_store() else {
            return;
        };
        if let Err(err) = self.storage_ref.ask(PutFinalConfigsBytes { bytes }).await {
            warn!("Failed to store the channel's final configs: {err}");
        }
    }
}

impl<S: StorageActorTrait> BedrockActorTrait for BedrockActor<S> {}

impl<S: StorageActorTrait> Actor for BedrockActor<S> {
    type Args = Args<S>;
    type Error = Error;

    async fn on_start(args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self> {
        let Args {
            node_url,
            basic_auth,
            channel_id,
            storage_ref,
            broker_ref,
            backfill_batch_slots,
        } = args;

        let node = TimeoutNode::new(NodeHttpClient::new(
            CommonHttpClient::new(basic_auth),
            node_url,
        ));

        // The publisher starts zone-sdk from this stored checkpoint: a cold start backfills from
        // slot 0, a restart's events start after its LIB.
        let config_index = match storage_ref.ask(GetZoneCheckpoint).await? {
            None => ConfigIndex::starting_at(0),
            Some(stored) => {
                let restored = storage_ref
                    .ask(GetFinalConfigsBytes)
                    .await?
                    .and_then(|bytes| ConfigIndex::from_bytes(&bytes));
                if let Some(index) = restored {
                    index
                } else {
                    let checkpoint = SequencerCheckpoint::from_bytes(&stored.bytes)?;
                    ConfigIndex::starting_at(checkpoint.lib_slot.into_inner().saturating_add(1))
                }
            }
        };

        Ok(Self {
            channel_id,
            node_stream: None,
            node,
            publisher: None,
            broker_ref,
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
            select! {
                Some(Some(item)) = OptionFuture::from(self.node_stream.as_mut().map(node_stream::NodeStream::next_item)) => {
                    let item = item?;
                    let span = info_span!("bedrock_event", otel.name = item.span_name());
                    self.node_stream.as_mut().expect("Channel is followed").on_item(item).instrument(span).await?;
                }
                Some(event) = OptionFuture::from(self.publisher.as_mut().map(publisher::Publisher::next_event)) => {
                    let span = info_span!("bedrock_event", otel.name = publisher::span_name(&event));
                    self.publisher
                        .as_mut()
                        .expect("Publisher is initialized")
                        .on_event(event, &mut self.config_index)
                        .instrument(span)
                        .await?;
                    self.store_config_index().await;
                }
                signal = mailbox_rx.recv() => {
                    return Ok(signal)
                }
            }
        }
    }
}

impl<S: StorageActorTrait> Message<FollowChannel> for BedrockActor<S> {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        FollowChannel { channel_id, anchor }: FollowChannel,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        self.node_stream = Some(
            node_stream::NodeStream::new(
                self.node.clone(),
                channel_id,
                anchor,
                self.broker_ref.clone(),
                self.backfill_batch_slots,
            )
            .await?,
        );
        Ok(())
    }
}

impl<S: StorageActorTrait> Message<InitializeChannelPublisher> for BedrockActor<S> {
    type Reply = Result<Option<ChannelSeq>>;

    async fn handle(
        &mut self,
        InitializeChannelPublisher {
            channel_id,
            channel_signing_key,
            funding_pk,
            priority_fee_percent,
            resubmit_interval,
            stale_refund_slots,
            replayed_up_to,
        }: InitializeChannelPublisher,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        if self.publisher.is_some() {
            return Ok(None);
        }

        let initial_checkpoint = self.storage_ref.ask(GetZoneCheckpoint).await?;
        // zone-sdk's events start after the checkpoint's LIB, so the index is read up to it.
        if let Some(stored) = &initial_checkpoint {
            let lib_slot = SequencerCheckpoint::from_bytes(&stored.bytes)?
                .lib_slot
                .into_inner();
            let mut reader = NodeReader {
                node: &self.node,
                block_summary_cache: &mut self.block_summary_cache,
                channel_id,
            };
            self.config_index
                .cover_through(&mut reader, lib_slot)
                .await?;
        }

        let (publisher, start_seq) = publisher::Publisher::new(
            publisher::PublisherConfig {
                channel_id: self.channel_id,
                channel_signing_key,
                funding_pk,
                priority_fee_percent,
                resubmit_interval,
                stale_refund_slots,
                backfill_batch_slots: self.backfill_batch_slots,
            },
            self.node.clone(),
            initial_checkpoint,
            replayed_up_to,
            self.broker_ref.clone(),
            &mut self.config_index,
        )
        .await?;
        self.publisher = Some(publisher);
        self.store_config_index().await;
        Ok(Some(start_seq))
    }
}

impl<S: StorageActorTrait> Message<CreateChannel> for BedrockActor<S> {
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

        self.publisher()?
            .create_channel(
                genesis,
                keys,
                channel_params,
                configuration_threshold,
                transfer_threshold,
            )
            .await
    }
}

impl<S: StorageActorTrait> Message<PublishBlock> for BedrockActor<S> {
    type Reply = Result<PublishOutcome>;

    async fn handle(
        &mut self,
        PublishBlock {
            channel_id,
            block,
            withdrawals,
            parent,
            expected_seq,
        }: PublishBlock,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        self.publisher()?
            .publish_block(block, withdrawals, parent, expected_seq)
            .await
    }
}

impl<S: StorageActorTrait> Message<PreparePin> for BedrockActor<S> {
    type Reply = Result<PreparedPin>;

    async fn handle(
        &mut self,
        PreparePin {
            channel_id,
            block,
            parent,
            notes,
            expected_seq,
        }: PreparePin,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        self.publisher()?
            .prepare_pin(block, parent, &notes, expected_seq)
            .await
    }
}

impl<S: StorageActorTrait> Message<PublishPin> for BedrockActor<S> {
    type Reply = Result<PublishOutcome>;

    async fn handle(
        &mut self,
        PublishPin {
            channel_id,
            prepared,
            signatures,
            expected_seq,
        }: PublishPin,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        self.publisher()?
            .publish_pin(prepared, signatures, expected_seq)
    }
}

impl<S: StorageActorTrait> Message<PrepareConfig> for BedrockActor<S> {
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

        self.publisher()?
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

impl<S: StorageActorTrait> Message<ChangeChannelConfig> for BedrockActor<S> {
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

        self.publisher()?
            .change_channel_config(prepared, signatures)
    }
}

impl<S: StorageActorTrait> Message<CheckChannelExists> for BedrockActor<S> {
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

impl<S: StorageActorTrait> Message<CheckIsOurTurn> for BedrockActor<S> {
    type Reply = Result<bool>;

    async fn handle(
        &mut self,
        CheckIsOurTurn { channel_id }: CheckIsOurTurn,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        Ok(self.publisher()?.check_is_our_turn())
    }
}

impl<S: StorageActorTrait> Message<GetAccreditedKeys> for BedrockActor<S> {
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

impl<S: StorageActorTrait> Message<GetChannelNotes> for BedrockActor<S> {
    type Reply = Result<HashSet<NoteId>>;

    async fn handle(
        &mut self,
        GetChannelNotes { channel_id }: GetChannelNotes,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        Ok(self.publisher()?.channel_notes())
    }
}

impl<S: StorageActorTrait> Message<GetChannelTipSlot> for BedrockActor<S> {
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

impl<S: StorageActorTrait> Message<GetChannelTipMessageId> for BedrockActor<S> {
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

impl<S: StorageActorTrait> Message<FilterFinallyAbsent> for BedrockActor<S> {
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
            self.block_summary_cache.clear();
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
    /// Block summaries cached before a walk that returns a verdict empties the cache.
    const CACHE_CAPACITY: usize = 4096;

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

// TODO: Remove when cross zones become actor(-s)
impl<S: StorageActorTrait> Message<ReadChannel> for BedrockActor<S> {
    type Reply = Result<ChannelReadStream>;

    async fn handle(
        &mut self,
        ReadChannel { channel_id, after }: ReadChannel,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        let lib_slot = self
            .node
            .consensus_info()
            .await
            .map_err(|err| Error::NodeRequestFailed(err.into()))?
            .cryptarchia_info
            .lib_slot;
        let start_slot = after.map_or_else(Slot::genesis, |s| s.strict_add(1.into()));

        let node = self.node.clone();
        let batch_slots = self.backfill_batch_slots.get();
        let stream = futures::stream::unfold(Some(start_slot), move |next| {
            let node = node.clone();
            async move {
                let current_slot = next?;
                if current_slot > lib_slot {
                    return None;
                }

                let end_slot = (Slot::from(
                    current_slot
                        .into_inner()
                        .saturating_add(batch_slots)
                        .checked_sub(1)
                        .expect("slot shouldn't overflow"),
                ))
                .min(lib_slot);

                match node
                    .zone_messages_in_blocks(current_slot, end_slot, channel_id)
                    .await
                {
                    Ok(messages) => Some((
                        Either::Left(messages.map(Ok)),
                        Some(end_slot.strict_add(1.into())),
                    )),
                    Err(cause) => Some((
                        Either::Right(futures::stream::once(std::future::ready(Err(
                            Error::ChannelReadFailed {
                                from: current_slot,
                                to: end_slot,
                                cause: cause.into(),
                            },
                        )))),
                        None,
                    )),
                }
            }
        })
        .flatten();

        Ok(Box::pin(stream))
    }
}

#[cfg(feature = "test-utils")]
impl<S: StorageActorTrait> Message<PublishRawInscription> for BedrockActor<S> {
    type Reply = Result<PublishOutcome>;

    async fn handle(
        &mut self,
        PublishRawInscription { channel_id, data }: PublishRawInscription,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        self.publisher()?.publish_raw_inscription(data).await
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
        })
    }
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
