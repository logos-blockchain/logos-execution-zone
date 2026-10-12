//! The channel's finalized history, read from the node and published to the broker.

use std::{sync::Arc, time::Duration};

use anyhow::anyhow;
use common::block::Block;
use futures::{Stream, StreamExt as _, TryStreamExt as _};
use kameo::actor::ActorRef;
use kameo_actors::broker::Broker;
use lee_core::BlockId;
use log::info;
use logos_blockchain_common_http_client::ProcessedBlockEvent;
use logos_blockchain_core::mantle::ops::channel::withdraw::ChannelWithdrawOp;
use logos_blockchain_zone_sdk::{
    Deposit, Withdraw,
    adapter::{Node as _, NodeHttpClient},
};
use sequencer_actors_common::SendErrorExt as _;
use sequencer_storage_actor::protocol::ZoneAnchorRecord;

use crate::{
    Result,
    error::Error,
    protocol::{
        BlockData, BoxStream, ChannelEvent, ChannelEventKind, ChannelId, DepositInfo,
        FinalizedBlock, Slot, WithdrawInfo, ZoneMessage,
    },
};

/// Follows the channel's finalized history from the stored anchor on, publishing it to the
/// `channel/<channel_id>/finalized_*` topics.
pub struct NodeStream {
    channel_id: ChannelId,
    stream: BoxStream<Result<(ZoneMessage, Slot)>>,
    /// Slot of the block the store was anchored at on start. It is read again, but only for the
    /// deposits and withdrawals following that block, which may not have been persisted.
    anchor_slot: Option<Slot>,
    last_seen_block: Option<BlockId>,
    broker_ref: ActorRef<Broker<ChannelEvent>>,
}

impl NodeStream {
    /// Starts reading at the slot of the stored `anchor`, or at genesis without one.
    pub async fn new(
        node: NodeHttpClient,
        channel_id: ChannelId,
        anchor: Option<ZoneAnchorRecord>,
        broker_ref: ActorRef<Broker<ChannelEvent>>,
    ) -> Result<Self> {
        let stream = Self::stream(
            node,
            anchor
                .as_ref()
                .and_then(|anchor| anchor.slot.checked_sub(1))
                .map(Slot::from),
            channel_id,
        )
        .await?;

        Ok(Self {
            channel_id,
            stream: Box::pin(stream),
            anchor_slot: anchor.as_ref().map(|anchor| Slot::from(anchor.slot)),
            last_seen_block: anchor.as_ref().map(|anchor| anchor.block_id),
            broker_ref,
        })
    }

    /// The next finalized message and the slot it was read at. Cancel safe, unlike
    /// [`Self::on_message`].
    pub async fn next_message(&mut self) -> Option<Result<(ZoneMessage, Slot)>> {
        self.stream.next().await
    }

    async fn stream(
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

    /// Publishes what `msg`, read at `slot`, reports to the broker.
    pub async fn on_message(&mut self, msg: ZoneMessage, slot: Slot) -> Result<()> {
        match msg {
            ZoneMessage::Block(_) if self.anchor_slot.is_some_and(|anchor| slot <= anchor) => {
                Ok(())
            }
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

                self.publish(
                    "finalized_block",
                    ChannelEventKind::FinalizedBlock(Arc::new(FinalizedBlock {
                        block,
                        msg_id: zone_block.id,
                        slot,
                    })),
                )
                .await
            }
            ZoneMessage::Deposit(deposit) => {
                let deposit = deposit_info(deposit, self.channel_id);
                self.publish(
                    "finalized_deposit",
                    ChannelEventKind::FinalizedDeposit(Arc::new(deposit)),
                )
                .await
            }
            ZoneMessage::Withdraw(withdraw) => {
                let withdraw = withdraw_info(withdraw, self.channel_id);
                self.publish(
                    "finalized_withdrawal",
                    ChannelEventKind::FinalizedWithdrawal(Arc::new(withdraw)),
                )
                .await
            }
        }
    }

    /// Publishes `event` to `channel/<channel_id>/<topic>`.
    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "Helps to make returned future Send"
    )]
    async fn publish(&mut self, topic: &str, event: ChannelEventKind) -> Result<()> {
        self.broker_ref
            .tell(kameo_actors::broker::Publish {
                topic: format!("channel/{}/{topic}", self.channel_id),
                message: ChannelEvent {
                    channel_id: self.channel_id,
                    event,
                },
            })
            .await
            .map_err(|err| Error::BrokerPublishFailed(err.erase_message()))
    }
}

/// The deposit `deposit` reports on `channel_id`, as the publisher reports it.
fn deposit_info(deposit: Deposit, channel_id: ChannelId) -> DepositInfo {
    let Deposit {
        tx_hash,
        op_id,
        inputs,
        notes,
        amount,
        metadata,
    } = deposit;
    DepositInfo {
        tx_hash,
        op_id,
        channel_id,
        inputs,
        notes,
        amount,
        metadata,
    }
}

/// The withdrawal `withdraw` reports on `channel_id`, as the publisher reports it.
fn withdraw_info(withdraw: Withdraw, channel_id: ChannelId) -> WithdrawInfo {
    WithdrawInfo {
        tx_hash: withdraw.tx_hash,
        op: ChannelWithdrawOp {
            channel_id,
            inputs: withdraw.inputs,
        },
    }
}
