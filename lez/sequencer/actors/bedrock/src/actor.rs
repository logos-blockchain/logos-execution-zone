use std::time::Duration;

use anyhow::anyhow;
use common::block::Block;
use futures::{Stream, StreamExt as _, TryStreamExt as _, future::OptionFuture};
use kameo::{
    Actor,
    actor::{ActorRef, WeakActorRef},
    mailbox::{MailboxReceiver, Signal},
    message::{Context, Message},
};
use kameo_actors::broker::Broker;
use lee_core::BlockId;
use log::{info, warn};
use logos_blockchain_common_http_client::{BasicAuthCredentials, ProcessedBlockEvent};
use logos_blockchain_core::mantle::NoteId;
use logos_blockchain_zone_sdk::{
    CommonHttpClient,
    adapter::{Node as _, NodeHttpClient},
    sequencer::{InscriptionInfo, PendingTx},
};
use sequencer_actors_common::SendErrorExt as _;
use sequencer_storage_actor::{
    StorageActorTrait,
    protocol::{GetZoneAnchor, GetZoneCheckpoint},
};
use tokio::select;

#[cfg(feature = "test-utils")]
use crate::protocol::PublishRawInscription;
use crate::{
    BedrockActorTrait, Result, Url,
    error::Error,
    protocol::{
        AccreditedKeys, BlockData, BoxStream, ChangeChannelConfig, ChannelEvent, ChannelEventKind,
        ChannelId, ChannelSeq, CheckChannelExists, CheckIsOurTurn, CreateChannel, Ed25519PublicKey,
        FinalizedBlock, GetAccreditedKeys, GetChannelTipMessageId, GetChannelTipSlot,
        InitializeChannelPublisher, LiveChannelConfig, MsgId, PrepareConfig, PreparedConfig,
        PublishBlock, PublishOutcome, ReadChannel, Slot, UnverifiedEd25519PublicKey, ZoneMessage,
    },
};

mod publisher;
#[cfg(test)]
mod tests;

pub struct Args<S: StorageActorTrait> {
    pub node_url: Url,
    pub basic_auth: Option<BasicAuthCredentials>,
    pub channel_id: ChannelId,
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
/// - `channel/<channel_id>/finalized_block`: for [`ChannelEventKind::FinalizedBlock`].
/// - If publisher was initialized with [`InitializeChannelPublisher`]:
///   - `channel/<channel_id>/publisher/update`: for
///     [`PublisherEvent::Update`](crate::protocol::PublisherEvent::Update)
///   - `channel/<channel_id>/publisher/turn`: for
///     [`PublisherEvent::Turn`](crate::protocol::PublisherEvent::Turn)
///   - `channel/<channel_id>/publisher/config`: for
///     [`PublisherEvent::Config`](crate::protocol::PublisherEvent::Config)
pub struct BedrockActor<S: StorageActorTrait> {
    channel_id: ChannelId,
    node: NodeHttpClient,
    node_stream: BoxStream<Result<(ZoneMessage, Slot)>>,
    last_seen_block: Option<BlockId>,
    /// [`Some`] after [`InitializeChannelPublisher`] has been handled.
    publisher: Option<publisher::Publisher>,
    broker_ref: ActorRef<Broker<ChannelEvent>>,
    storage_ref: ActorRef<S>,
}

impl<S: StorageActorTrait> BedrockActor<S> {
    async fn node_stream(
        node: NodeHttpClient,
        last_seen_slot: Option<Slot>,
        channel_id: ChannelId,
    ) -> Result<impl Stream<Item = Result<(ZoneMessage, Slot)>>> {
        const BATCH_SIZE: Slot = Slot::new(100);
        const STREAM_ATTEMPT_LIMIT: usize = 5;
        const STREAM_RETRY_TIMEOUT: Duration = Duration::from_millis(100);

        struct StreamState {
            last_processed_slot: Option<Slot>,
            last_known_lib_slot: Slot,
            real_time_stream: BoxStream<ProcessedBlockEvent>,
        }

        let lib_slot = node
            .consensus_info()
            .await
            .map_err(|err| Error::NodeRequestFailed(err.into()))?
            .cryptarchia_info
            .lib_slot;

        let real_time_stream = node
            .block_stream()
            .await
            .map_err(|err| Error::NodeRequestFailed(err.into()))?;

        let initial_state = StreamState {
            last_processed_slot: last_seen_slot,
            last_known_lib_slot: lib_slot,
            real_time_stream,
        };

        let stream = futures::stream::try_unfold(initial_state, move |mut stream_state| {
            let node = node.clone();
            async move {
                // Fetch new lib_slot once caught up with the known one
                while stream_state
                    .last_processed_slot
                    .is_some_and(|slot| slot >= stream_state.last_known_lib_slot)
                {
                    let mut attempt_count: usize = 0;
                    let block_event = loop {
                        if let Some(block_event) = stream_state.real_time_stream.next().await {
                            break block_event;
                        }
                        attempt_count = attempt_count.saturating_add(1);
                        if attempt_count < STREAM_ATTEMPT_LIMIT {
                            tokio::time::sleep(STREAM_RETRY_TIMEOUT).await;

                            stream_state.real_time_stream = node
                                .block_stream()
                                .await
                                .map_err(|err| Error::NodeRequestFailed(err.into()))?;
                        } else {
                            return Err(Error::NodeRequestFailed(anyhow!(
                                "Stream attempt limit reached"
                            )));
                        }
                    };
                    stream_state.last_known_lib_slot =
                        stream_state.last_known_lib_slot.max(block_event.lib_slot);
                }

                // Backfilling from last processed slot
                let start_slot = stream_state
                    .last_processed_slot
                    .map_or_else(Slot::genesis, |slot| slot.strict_add(1.into()));
                let end_slot = (Slot::from(
                    start_slot
                        .into_inner()
                        .saturating_add(BATCH_SIZE.into_inner()),
                ))
                .min(stream_state.last_known_lib_slot);

                let backfill_stream = node
                    .zone_messages_in_blocks(start_slot, end_slot, channel_id)
                    .await
                    .map_err(|err| Error::NodeRequestFailed(err.into()))?
                    .map(Ok);

                stream_state.last_processed_slot = Some(end_slot);
                Ok(Some((backfill_stream.boxed(), stream_state)))
            }
        })
        .try_flatten();

        Ok(stream)
    }

    async fn on_node_stream_message(&mut self, msg: ZoneMessage, slot: Slot) -> Result<()> {
        match msg {
            ZoneMessage::Block(zone_block) => {
                let block = match borsh::from_slice::<Block>(&zone_block.data) {
                    Ok(block) => {
                        let block_id = block.header.block_id;
                        if let Some(last_seen_block) = self.last_seen_block
                            && last_seen_block > block_id
                        {
                            info!(
                                "Skipping block with ID {block_id} as it is older than the last seen block {last_seen_block}",
                            );
                            return Ok(());
                        }
                        self.last_seen_block = Some(block_id);

                        BlockData::Block(block)
                    }
                    Err(_) => BlockData::Undecodable(zone_block.data.into()),
                };

                self.broker_ref
                    .tell(kameo_actors::broker::Publish {
                        topic: format!("channel/{}/finalized_block", self.channel_id),
                        message: ChannelEvent {
                            channel_id: self.channel_id,
                            event: ChannelEventKind::FinalizedBlock(Box::new(FinalizedBlock {
                                block,
                                msg_id: zone_block.id,
                                slot,
                            })),
                        },
                    })
                    .await
                    .map_err(|err| Error::BrokerPublishFailed(err.erase_message()))
            }
            ZoneMessage::Deposit(_) | ZoneMessage::Withdraw(_) => {
                // TODO: Report deposit and withdraw events to the broker.
                // After that we can make publisher ignore events up to the latest processed slot.
                Ok(())
            }
        }
    }

    fn assert_channel_id(&self, channel_id: ChannelId) {
        assert_eq!(self.channel_id, channel_id, "Channel ID mismatch");
    }

    fn publisher(&mut self) -> Result<&mut publisher::Publisher> {
        self.publisher
            .as_mut()
            .ok_or(Error::ChannelPublisherIsNotInitialized)
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
        } = args;
        let anchor = storage_ref.ask(GetZoneAnchor).await?;

        let node = NodeHttpClient::new(CommonHttpClient::new(basic_auth), node_url);

        Ok(Self {
            channel_id,
            node_stream: Box::pin(
                Self::node_stream(
                    node.clone(),
                    anchor.as_ref().map(|anchor| Slot::from(anchor.slot)),
                    channel_id,
                )
                .await?,
            ),
            last_seen_block: anchor.as_ref().map(|anchor| anchor.block_id),
            node,
            publisher: None,
            broker_ref,
            storage_ref,
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
                Some(res) = self.node_stream.next() => {
                    let (msg, slot) = res?;
                    self.on_node_stream_message(msg, slot).await?;
                }
                Some(event) = OptionFuture::from(self.publisher.as_mut().map(publisher::Publisher::next_event)) => {
                    self.publisher().expect("Publisher is initialized").on_event(event).await?;
                }
                signal = mailbox_rx.recv() => {
                    return Ok(signal)
                }
            }
        }
    }
}

impl<S: StorageActorTrait> Message<InitializeChannelPublisher> for BedrockActor<S> {
    type Reply = Result<Option<ChannelSeq>>;

    async fn handle(
        &mut self,
        InitializeChannelPublisher {
            channel_id,
            bedrock_signing_key,
            funding_pk,
            priority_fee_percent,
            resubmit_interval,
        }: InitializeChannelPublisher,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        if self.publisher.is_some() {
            return Ok(None);
        }

        let initial_checkpoint = self.storage_ref.ask(GetZoneCheckpoint).await?;

        let (publisher, start_seq) = publisher::Publisher::new(
            publisher::PublisherConfig {
                channel_id: self.channel_id,
                bedrock_signing_key,
                funding_pk,
                priority_fee_percent,
                resubmit_interval,
            },
            self.node.clone(),
            initial_checkpoint,
            self.broker_ref.clone(),
        )
        .await?;
        self.publisher = Some(publisher);
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
        }: CreateChannel,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.assert_channel_id(channel_id);

        self.publisher()?
            .create_channel(genesis, keys, channel_params, configuration_threshold)
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

// TODO: Remove when cross zones become actor(-s)
impl<S: StorageActorTrait> Message<ReadChannel> for BedrockActor<S> {
    type Reply = Result<BoxStream<(ZoneMessage, Slot)>>;

    async fn handle(
        &mut self,
        ReadChannel { channel_id, after }: ReadChannel,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        const BATCH_SIZE: Slot = Slot::new(100);

        self.assert_channel_id(channel_id);

        let lib_slot = self
            .node
            .consensus_info()
            .await
            .map_err(|err| Error::NodeRequestFailed(err.into()))?
            .cryptarchia_info
            .lib_slot;
        let lib_slot = self
            .ready_lib_slot
            .map_or(node_lib_slot, |ready| ready.min(node_lib_slot));
        let start_slot = after.map_or_else(Slot::genesis, |s| s.strict_add(1.into()));

        let node = self.node.clone();
        let stream = futures::stream::unfold(start_slot, move |current_slot| {
            let node = node.clone();
            async move {
                if current_slot > lib_slot {
                    return None;
                }

                let end_slot = (Slot::from(
                    current_slot
                        .into_inner()
                        .saturating_add(BATCH_SIZE.into_inner())
                        .checked_sub(1)
                        .expect("slot shouldn't overflow"),
                ))
                .min(lib_slot);

                match node
                    .zone_messages_in_blocks(current_slot, end_slot, channel_id)
                    .await
                {
                    Ok(messages) => Some((messages, end_slot.strict_add(1.into()))),
                    Err(e) => {
                        log::warn!(
                            "Failed to fetch zone messages from blocks {current_slot:?}..={end_slot:?}: {e}",
                        );
                        None
                    }
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
        })
    }
}

/// Deserialize an inscription payload into `(this_msg, Block)`. Bad payloads are
/// logged and skipped.
fn block_from_inscription(inscription: &InscriptionInfo) -> Option<Block> {
    borsh::from_slice::<Block>(&inscription.payload)
        .inspect_err(|err| {
            warn!("Failed to deserialize block from inscription: {err:?}");
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
