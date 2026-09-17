use std::time::Duration;

use common::block::Block;
use kameo::Reply;
pub use logos_blockchain_core::{codec::DeserializeOp, mantle::NoteId};
pub use logos_blockchain_key_management_system_service::keys::{Ed25519Key, ZkPublicKey};
pub use logos_blockchain_zone_sdk::{
    Ed25519PublicKey, Slot, ZoneMessage,
    adapter::BoxStream,
    node_types::{ChannelId, HeaderId, MsgId},
    sequencer::{
        DepositInfo, SequencerCheckpoint as Checkpoint, SequencerCheckpoint, WithdrawArg,
        WithdrawInfo,
    },
};
pub use sequencer_stake_core::ChannelParams;
use sharding_pool_actor::ShardingKey;

/// Event happened on configured chain and published to the broker.
#[derive(Debug, Clone)]
pub struct ChannelEvent {
    pub channel_id: ChannelId,
    pub event: ChannelEventKind,
}

/// Concrete kinds of events that can happen on a channel.
#[derive(Debug, Clone)]
pub enum ChannelEventKind {
    /// A block that has been finalized on chain since configured `stream_from` arriving to
    /// `channel/<channel_id>/finalized_block` topic.
    FinalizedBlock(FinalizedBlock),

    /// Events related to the channel publisher arriving to `channel/<channel_id>/publisher/`
    /// topics.
    Publisher(PublisherEvent),
}

#[derive(Debug, Clone)]
pub struct FinalizedBlock {
    pub block: BlockData,
    pub msg_id: MsgId,
}

#[derive(Debug, Clone)]
pub enum BlockData {
    /// Successfully decoded block.
    Block(Block),
    /// Raw bytes of a block that could not be decoded.
    Undecodable(Vec<u8>),
}

/// Events related to the channel publisher, published to the broker.
///
/// Will arrive only if [`InitializeChannelPublisher`] has been successfully handled.
#[derive(Debug, Clone)]
pub enum PublisherEvent {
    /// Message arriving to `channel/<channel_id>/publisher/update` topic.
    Update(Box<ChannelUpdate>),

    /// Message arriving to `channel/<channel_id>/publisher/turn` topic.
    Turn { our_turn_to_write: bool },
}

/// Everything one channel update carries.
#[derive(Debug, Clone)]
pub struct ChannelUpdate {
    /// Resume cursor for this event. Persist only together with the effects
    /// below, never ahead of them. Its `last_msg_id` is the channel tip on
    /// the view this update leaves behind — non-block entries and the rewind
    /// after an orphan included — and is what the next publish pins on.
    pub checkpoint: Checkpoint,
    /// Blocks newly on the followed L1 branch, in channel order; they extend
    /// or replace part of the `head` tier. Non-block entries (garbage, a
    /// config op) surface only through the checkpoint's tip. No inscription
    /// ids ride along: blocks correlate by hash (a re-inscription changes the
    /// id, never the hash), and the only publishable id is the checkpoint's.
    pub adopted: Vec<Block>,
    /// Blocks dropped from the branch by an L1 reorg: reverted from the
    /// `head`, their user txs resubmitted to the mempool.
    pub orphaned: Vec<Block>,
    /// Blocks whose containing L1 block reached finality, each with that L1
    /// block's slot: they move into the irreversible `final` tier.
    pub finalized: Vec<(Block, Slot)>,
    /// Finalized Bedrock deposit events, to record and mint on L2.
    pub deposits: Vec<DepositInfo>,
    /// Finalized Bedrock withdraw events, to reconcile against local intents.
    pub withdrawals: Vec<WithdrawInfo>,
    /// Finalized inscriptions that are not blocks, with the key that signed each.
    pub undecodable: Vec<(MsgId, Ed25519PublicKey)>,
}

/// Initialize the channel publisher. This will make using messages like [`PublishBlock`] possible.
///
/// If no previous channel publisher exists, this will initialize it and return `true`; otherwise,
/// it will just return `false` without reinitializing the channel publisher.
pub struct InitializeChannelPublisher {
    pub channel_id: ChannelId,
    pub bedrock_signing_key: Ed25519Key,
    pub funding_pk: ZkPublicKey,
    pub priority_fee_percent: u64,
    pub initial_checkpoint: Option<SequencerCheckpoint>,
    pub resubmit_interval: Duration,
}

impl ShardingKey for InitializeChannelPublisher {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
    }
}

/// Create the channel and write `genesis` into it in one Mantle tx.
///
/// Only valid while the channel does not exist, and `keys[0]` must be this sequencer's own key,
/// since creation hands the first turn to index 0.
pub struct CreateChannel {
    pub channel_id: ChannelId,
    pub genesis: Block,
    pub keys: Vec<Ed25519PublicKey>,
    pub channel_params: ChannelParams,
}

impl ShardingKey for CreateChannel {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
    }
}

/// Publish block to the configured channel.
pub struct PublishBlock {
    pub channel_id: ChannelId,
    pub block: Block,
    pub withdrawals: Vec<WithdrawArg>,
    /// Parent message ID to inscribe the block on.
    /// If [`None`] then the block is inscribed on top of channel tip.
    pub parent: Option<MsgId>,
}

impl ShardingKey for PublishBlock {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
    }
}

/// Outcome of a publish operation.
pub struct PublishOutcome {
    /// The `MsgId` zone-sdk assigned the published inscription.
    pub this_msg: MsgId,
    /// The checkpoint that now holds the inscription as pending.
    pub checkpoint: Checkpoint,
    /// Channel notes the bundled withdrawals release, empty for a plain
    /// publish.
    pub released_notes: Vec<NoteId>,
}

/// Inscribe raw bytes on top of the channel tip. Only a test that provokes an
/// offence needs it.
#[cfg(feature = "test-utils")]
pub struct PublishRawInscription {
    pub channel_id: ChannelId,
    pub data: Vec<u8>,
}

#[cfg(feature = "test-utils")]
impl ShardingKey for PublishRawInscription {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
    }
}

/// Change the configuration of the channel.
pub struct ChangeChannelConfig {
    pub channel_id: ChannelId,
    pub new_keys: Vec<Ed25519PublicKey>,
    /// How long one sequencer's posting turn lasts, in slots.
    pub posting_timeframe: u32,
    /// Idle slots after which a turn nobody posted in passes on. Must stay
    /// above `block_create_timeout`, or a healthy sequencer loses its turn
    /// between its own blocks.
    pub posting_timeout: u32,
    pub configuration_threshold: u16,
    pub transfer_threshold: u16,
}

impl ShardingKey for ChangeChannelConfig {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
    }
}

/// Check if configured channel exists.
pub struct CheckChannelExists {
    pub channel_id: ChannelId,
}

impl ShardingKey for CheckChannelExists {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
    }
}

/// Whether this sequencer is currently authorized to write to the channel.
///
/// Prefer subscribing to `channel/<channel_id>/turn` topic instead of polling this.
pub struct CheckIsOurTurn {
    pub channel_id: ChannelId,
}

impl ShardingKey for CheckIsOurTurn {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
    }
}

/// Get live (adopted, possibly not yet finalized) accredited-key snapshot for
/// this channel with the config entry it comes from.
///
/// The config entry is what tells a caller whether this committee is the
/// finalized one: compare it to the checkpoint's `finalized_config`.
pub struct GetAccreditedKeys {
    pub channel_id: ChannelId,
}

impl ShardingKey for GetAccreditedKeys {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
    }
}

/// The channel's accredited keys, the config entry they come from, and whose
/// turn the tip was written on.
#[derive(Reply)]
pub struct AccreditedKeys {
    pub keys: Vec<Ed25519PublicKey>,
    pub config_tip: MsgId,
    /// Position in `keys` of the sequencer whose turn the tip was written on.
    pub tip_sequencer: u16,
    /// Channel frontier slot at the time the keys were read.
    pub tip_slot: Slot,
}

impl AccreditedKeys {
    /// The key whose turn the tip was written on; [`None`] when the channel
    /// names a position no key sits at.
    #[must_use]
    pub fn whose_turn(&self) -> Option<Ed25519PublicKey> {
        self.keys.get(usize::from(self.tip_sequencer)).copied()
    }
}

/// Get current channel frontier slot on the connected chain.
pub struct GetChannelTipSlot {
    pub channel_id: ChannelId,
}

impl ShardingKey for GetChannelTipSlot {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
    }
}

/// Get live channel tip message id.
pub struct GetChannelTipMessageId {
    pub channel_id: ChannelId,
}

impl ShardingKey for GetChannelTipMessageId {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
    }
}

/// Finalized channel messages from `after` (exclusive) up to LIB.
pub struct ReadChannel {
    pub channel_id: ChannelId,
    /// Passing [`None`] will read from the channel's genesis.
    pub after: Option<Slot>,
}

impl ShardingKey for ReadChannel {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
    }
}
