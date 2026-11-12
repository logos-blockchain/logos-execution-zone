//! The channel's finalized history, read from the node and published to the broker.

use std::{num::NonZero, sync::Arc, time::Duration};

use anyhow::anyhow;
use chain_state::timeout_node::TimeoutNode;
use common::block::DigestedBlock;
use futures::{Stream, StreamExt as _, TryStreamExt as _};
use kameo::actor::ActorRef;
use kameo_actors::broker::Broker;
use log::warn;
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
        Ed25519PublicKey, FinalizedBlock, FinalizedUpTo, Slot, WithdrawInfo, ZoneMessage,
    },
};

/// Attempts a node request gets before its failure ends the stream.
const NODE_REQUEST_ATTEMPTS: u32 = 8;
/// Wait before the first retry, doubling up to [`MAX_RETRY_DELAY`].
const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(200);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(5);

/// What [`NodeStream`] reads from the node.
#[expect(
    clippy::large_enum_variant,
    reason = "Nearly every item is a message, so boxing it only adds an allocation"
)]
pub enum StreamItem {
    /// A finalized message and the slot it was read at.
    Message(ZoneMessage, Slot),
    /// Every finalized message up to a slot has been read.
    ReadUpTo(FinalizedUpTo),
}

/// Follows the channel's finalized history from the stored anchor on, publishing it to the
/// `channel/<channel_id>/finalized_*` topics.
pub struct NodeStream {
    channel_id: ChannelId,
    stream: BoxStream<Result<StreamItem>>,
    broker_ref: ActorRef<Broker<ChannelEvent>>,
}

impl NodeStream {
    /// Starts reading at the slot of the stored `anchor`, or at genesis without one. The anchor
    /// block is read again, so a warm start can check it against the store, along with the deposits
    /// and withdrawals following it, which may not have been persisted.
    pub async fn new(
        node: TimeoutNode<NodeHttpClient>,
        channel_id: ChannelId,
        anchor: Option<ZoneAnchorRecord>,
        broker_ref: ActorRef<Broker<ChannelEvent>>,
        batch_slots: NonZero<u64>,
    ) -> Result<Self> {
        let stream = Self::stream(
            node,
            anchor
                .as_ref()
                .and_then(|anchor| anchor.slot.checked_sub(1))
                .map(Slot::from),
            channel_id,
            batch_slots,
        )
        .await?;

        Ok(Self {
            channel_id,
            stream: Box::pin(stream),
            broker_ref,
        })
    }

    /// The next item read from the node. Cancel safe, unlike [`Self::on_item`].
    pub async fn next_item(&mut self) -> Option<Result<StreamItem>> {
        self.stream.next().await
    }

    async fn stream(
        node: TimeoutNode<NodeHttpClient>,
        last_seen_slot: Option<Slot>,
        channel_id: ChannelId,
        batch_slots: NonZero<u64>,
    ) -> Result<impl Stream<Item = Result<StreamItem>>> {
        struct StreamState {
            last_processed_slot: Option<Slot>,
            last_known_lib_slot: Slot,
            real_time_stream: BoxStream<ProcessedBlockEvent>,
        }

        let lib_slot = with_retries("Reading consensus info", || node.consensus_info())
            .await?
            .cryptarchia_info
            .lib_slot;

        let real_time_stream =
            with_retries("Opening the block stream", || node.block_stream()).await?;

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
                    let mut backoff = Backoff::default();
                    let block_event = loop {
                        if let Some(block_event) = stream_state.real_time_stream.next().await {
                            break block_event;
                        }
                        backoff
                            .wait("Following the block stream", anyhow!("The stream ended"))
                            .await?;
                        stream_state.real_time_stream =
                            with_retries("Reopening the block stream", || node.block_stream())
                                .await?;
                    };
                    stream_state.last_known_lib_slot =
                        stream_state.last_known_lib_slot.max(block_event.lib_slot);
                }

                // Backfilling from last processed slot
                let start_slot = stream_state
                    .last_processed_slot
                    .map_or_else(Slot::genesis, |slot| slot.strict_add(1.into()));
                let last_finalized_slot = stream_state.last_known_lib_slot;
                let end_slot =
                    (Slot::from(start_slot.into_inner().saturating_add(batch_slots.get())))
                        .min(last_finalized_slot);

                let backfill_stream = with_retries("Reading finalized zone messages", || {
                    node.zone_messages_in_blocks(start_slot, end_slot, channel_id)
                })
                .await?
                .map(|(msg, slot)| Ok(StreamItem::Message(msg, slot)))
                .chain(futures::stream::once(async move {
                    Ok(StreamItem::ReadUpTo(FinalizedUpTo {
                        slot: end_slot,
                        last_finalized_slot,
                    }))
                }));

                stream_state.last_processed_slot = Some(end_slot);
                Ok::<_, Error>(Some((backfill_stream.boxed(), stream_state)))
            }
        })
        .try_flatten();

        Ok(stream)
    }

    /// Publishes what `item` reports to the broker.
    pub async fn on_item(&mut self, item: StreamItem) -> Result<()> {
        match item {
            StreamItem::Message(msg, slot) => self.on_message(msg, slot).await,
            StreamItem::ReadUpTo(up_to) => {
                self.publish("finalized_up_to", ChannelEventKind::FinalizedUpTo(up_to))
                    .await
            }
        }
    }

    /// Publishes what `msg`, read at `slot`, reports to the broker.
    async fn on_message(&mut self, msg: ZoneMessage, slot: Slot) -> Result<()> {
        match msg {
            ZoneMessage::Block(zone_block) => {
                let block = match DigestedBlock::from_inscription(&zone_block.data) {
                    Ok(block) => BlockData::Block(block),
                    Err(_) => BlockData::Undecodable(zone_block.data.into()),
                };

                self.publish(
                    "finalized_block",
                    ChannelEventKind::FinalizedBlock(Arc::new(FinalizedBlock {
                        block,
                        msg_id: zone_block.id,
                        slot,
                        signer: Ed25519PublicKey::try_from(zone_block.signer).ok(),
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

/// Retry delays of one node request, so a node restart does not end the stream.
struct Backoff {
    failures: u32,
    delay: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            failures: 0,
            delay: INITIAL_RETRY_DELAY,
        }
    }
}

impl Backoff {
    /// Waits out the delay after `what` failed with `err`, or fails once the attempts run out.
    async fn wait(&mut self, what: &str, err: anyhow::Error) -> Result<()> {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= NODE_REQUEST_ATTEMPTS {
            return Err(Error::NodeRequestFailed(
                err.context(format!("{what} failed {} times", self.failures)),
            ));
        }
        warn!(
            "{what} failed ({}/{NODE_REQUEST_ATTEMPTS}), retrying in {:?}: {err:#}",
            self.failures, self.delay
        );
        tokio::time::sleep(self.delay).await;
        self.delay = self.delay.saturating_mul(2).min(MAX_RETRY_DELAY);
        Ok(())
    }
}

/// Runs `request` until it succeeds, waiting out a [`Backoff`] between failures.
async fn with_retries<T, E, Fut>(what: &str, mut request: impl FnMut() -> Fut) -> Result<T>
where
    Fut: Future<Output = std::result::Result<T, E>>,
    E: Into<anyhow::Error>,
{
    let mut backoff = Backoff::default();
    loop {
        match request().await {
            Ok(value) => return Ok(value),
            Err(err) => backoff.wait(what, err.into()).await?,
        }
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

#[cfg(test)]
mod tests {
    use common::{
        HashType,
        block::{Block, HashableBlockData},
    };
    use kameo::{
        Actor,
        actor::Spawn as _,
        message::{Context, Message},
    };
    use kameo_actors::{DeliveryStrategy, broker::Subscribe};
    use logos_blockchain_key_management_system_service::keys::Ed25519Key;
    use logos_blockchain_zone_sdk::{ZoneBlock, node_types::Inscription};
    use tokio::sync::mpsc;

    use super::*;
    use crate::protocol::MsgId;

    #[derive(Debug, PartialEq, Eq)]
    enum Published {
        Block(MsgId),
        UpTo(FinalizedUpTo),
    }

    #[derive(Actor)]
    struct Recorder(mpsc::UnboundedSender<Published>);

    impl Message<ChannelEvent> for Recorder {
        type Reply = ();

        async fn handle(&mut self, msg: ChannelEvent, _ctx: &mut Context<Self, ()>) {
            let published = match msg.event {
                ChannelEventKind::FinalizedBlock(finalized) => Published::Block(finalized.msg_id),
                ChannelEventKind::FinalizedUpTo(up_to) => Published::UpTo(up_to),
                ChannelEventKind::FinalizedDeposit(_)
                | ChannelEventKind::FinalizedWithdrawal(_)
                | ChannelEventKind::Publisher(_) => return,
            };
            self.0.send(published).expect("the test is listening");
        }
    }

    fn block(block_id: u64) -> Block {
        HashableBlockData {
            reverted: Vec::new(),
            block_id,
            prev_block_hash: HashType([0; 32]),
            timestamp: 0,
            transactions: Vec::new(),
        }
        .into_pending_block()
    }

    /// A node stream over no node, and the finalized blocks and slots it publishes.
    async fn node_stream(
        channel_id: ChannelId,
    ) -> (NodeStream, mpsc::UnboundedReceiver<Published>) {
        let broker_ref = Broker::spawn(Broker::new(DeliveryStrategy::Guaranteed));
        let (sender, published) = mpsc::unbounded_channel();
        broker_ref
            .tell(Subscribe {
                topic: glob::Pattern::new(&format!("channel/{channel_id}/**"))
                    .expect("a valid topic pattern"),
                recipient: Recorder::spawn(Recorder(sender)).recipient(),
            })
            .await
            .expect("the broker is running");
        let node_stream = NodeStream {
            channel_id,
            stream: futures::stream::empty().boxed(),
            broker_ref,
        };

        (node_stream, published)
    }

    async fn read(node_stream: &mut NodeStream, msg_id: MsgId, block: &Block, slot: u64) {
        node_stream
            .on_message(
                ZoneMessage::Block(ZoneBlock {
                    id: msg_id,
                    data: Inscription::new_unchecked(
                        block.digested().to_inscription().expect("serialize"),
                    ),
                    signer: Ed25519Key::from_bytes(&[3; 32])
                        .public_key()
                        .into_unverified(),
                }),
                Slot::from(slot),
            )
            .await
            .expect("the broker is running");
    }

    async fn next_published(
        published: &mut mpsc::UnboundedReceiver<Published>,
    ) -> Option<Published> {
        tokio::time::timeout(Duration::from_secs(5), published.recv())
            .await
            .expect("an event is published")
    }

    #[tokio::test]
    async fn a_block_numbered_below_an_earlier_one_is_published() {
        let (mut node_stream, mut published) = node_stream(ChannelId::from([1; 32])).await;
        read(&mut node_stream, MsgId::from([2; 32]), &block(7), 42).await;
        next_published(&mut published).await;

        // A misplaced block, which only the consumer can judge.
        let misplaced = MsgId::from([4; 32]);
        read(&mut node_stream, misplaced, &block(5), 43).await;

        assert_eq!(
            next_published(&mut published).await,
            Some(Published::Block(misplaced))
        );
    }

    #[tokio::test]
    async fn the_slot_read_up_to_is_published_after_the_blocks_it_covers() {
        let (mut node_stream, mut published) = node_stream(ChannelId::from([1; 32])).await;
        let msg_id = MsgId::from([2; 32]);
        read(&mut node_stream, msg_id, &block(7), 42).await;
        let up_to = FinalizedUpTo {
            slot: Slot::from(50),
            last_finalized_slot: Slot::from(60),
        };
        node_stream
            .on_item(StreamItem::ReadUpTo(up_to))
            .await
            .expect("the broker is running");

        assert_eq!(
            next_published(&mut published).await,
            Some(Published::Block(msg_id))
        );
        assert_eq!(
            next_published(&mut published).await,
            Some(Published::UpTo(up_to))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_node_request_is_retried_until_it_succeeds() {
        let mut failures_left = NODE_REQUEST_ATTEMPTS - 1;
        let result = with_retries("Test request", || {
            let fail = failures_left > 0;
            failures_left = failures_left.saturating_sub(1);
            async move {
                if fail {
                    Err(anyhow!("node down"))
                } else {
                    Ok(7)
                }
            }
        })
        .await;

        assert_eq!(result.ok(), Some(7));
    }

    #[tokio::test(start_paused = true)]
    async fn a_node_request_fails_once_its_attempts_run_out() {
        let mut attempts = 0_u32;
        let result: Result<()> = with_retries("Test request", || {
            attempts = attempts.saturating_add(1);
            async { Err(anyhow!("node down")) }
        })
        .await;

        assert!(matches!(result, Err(Error::NodeRequestFailed(_))));
        assert_eq!(attempts, NODE_REQUEST_ATTEMPTS);
    }
}
