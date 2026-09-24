use std::sync::Arc;

use common::block::Block;
use kameo::Reply;
pub use logos_blockchain_core::mantle::NoteId;
pub use logos_blockchain_zone_sdk::{
    Ed25519PublicKey, Slot, ZoneMessage,
    node_types::{ChannelId, HeaderId, MsgId},
    sequencer::{
        DepositInfo, Ed25519Key, IndexedSignature, PreparedChannelConfig,
        SequencerCheckpoint as Checkpoint, WithdrawArg, WithdrawInfo,
    },
};
pub use sequencer_channel_config_actor::protocol::ConfigTarget;
pub use sequencer_stake_core::ChannelParams;

/// A boxed, pinned, Send stream.
pub type BoxStream<T> = std::pin::Pin<Box<dyn futures::Stream<Item = T> + Send>>;

/// Version of the channel view the actor holds, bumped by everything that mints
/// a checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Reply)]
pub struct ChannelSeq(u64);

impl ChannelSeq {
    /// The sequence a channel nothing has been read from yet sits at.
    #[cfg(feature = "actor")]
    pub(crate) const ZERO: Self = Self(0);

    /// Resumes at `raw`, which only a sequence this actor persisted can be.
    #[cfg(feature = "actor")]
    pub(crate) const fn resumed(raw: u64) -> Self {
        Self(raw)
    }

    /// The next one along.
    #[cfg(feature = "actor")]
    pub(crate) const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    #[must_use]
    pub const fn into_inner(self) -> u64 {
        self.0
    }

    /// A sequence conjured outside the actor, for a mocked channel to serve.
    #[cfg(feature = "mock")]
    #[must_use]
    pub const fn mocked(raw: u64) -> Self {
        Self(raw)
    }
}

impl std::fmt::Display for ChannelSeq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Event happened on configured chain.
#[derive(Debug, Clone)]
pub enum ChannelEvent {
    Update(
        /// Arc is used to not to deep-clone the update for each broker consumer.
        Arc<ChannelUpdate>,
    ),

    Turn {
        our_turn_to_write: bool,
    },

    Config(LiveChannelConfig),
}
/// Everything one channel update carries.
#[derive(Debug, Clone)]
pub struct ChannelUpdate {
    /// Resume cursor for this event. Persist only together with the effects
    /// below, never ahead of them. Its `last_msg_id` is the channel tip on
    /// the view this update leaves behind — non-block entries and the rewind
    /// after an orphan included — and is what the next publish pins on.
    pub checkpoint: Checkpoint,
    /// The channel sequence this update leaves the actor at. A consumer that
    /// wants to publish echoes the last one it applied back in
    /// [`PublishBlock::expected_seq`].
    pub seq: ChannelSeq,
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

/// The live channel config, as much of it as a config update needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveChannelConfig {
    /// Accredited keys in index order; a signature names its index here.
    pub keys: Vec<Ed25519PublicKey>,
    /// The config tip a new op must chain on.
    pub config_tip: MsgId,
    /// Signatures Bedrock demands of the next config op, exactly.
    pub required_signatures: u16,
}

/// Create the channel and write `genesis` into it in one Mantle tx.
///
/// Only valid while the channel does not exist, and `keys[0]` must be this sequencer's own key,
/// since creation hands the first turn to index 0.
pub struct CreateChannel {
    pub genesis: Block,
    pub keys: Vec<Ed25519PublicKey>,
    pub channel_params: ChannelParams,
    pub configuration_threshold: u16,
}

/// Publish block to the configured channel.
pub struct PublishBlock {
    pub block: Block,
    pub withdrawals: Vec<WithdrawArg>,
    /// Parent message ID to inscribe the block on.
    /// If [`None`] then the block is inscribed on top of channel tip.
    pub parent: Option<MsgId>,
    /// The channel sequence the caller built this block on. The publish is
    /// refused when it is not the actor's current one, which means an update
    /// the caller has not applied yet moved the channel under it.
    ///
    /// [`None`] will omit the check.
    pub expected_seq: Option<ChannelSeq>,
}

/// Outcome of a publish operation.
pub struct PublishOutcome {
    /// The `MsgId` zone-sdk assigned the published inscription.
    pub this_msg: MsgId,
    /// The checkpoint that now holds the inscription as pending.
    pub checkpoint: Checkpoint,
    /// The channel sequence this publish leaves the actor at.
    pub seq: ChannelSeq,
    /// Channel notes the bundled withdrawals release, empty for a plain
    /// publish.
    pub released_notes: Vec<NoteId>,
}

/// Inscribe raw bytes on top of the channel tip. Only a test that provokes an
/// offence needs it.
#[cfg(feature = "test-utils")]
pub struct PublishRawInscription {
    pub data: Vec<u8>,
}

pub struct PrepareConfig {
    pub target: ConfigTarget,
}

/// Change the configuration of the channel.
pub struct ChangeChannelConfig {
    pub prepared: PreparedChannelConfig,
    pub signatures: Vec<IndexedSignature>,
}

/// Check if configured channel exists.
pub struct CheckChannelExists;

/// Get the ID of the configured channel.
pub struct GetChannelId;

#[derive(Reply)]
pub struct GetChannelIdReply {
    pub channel_id: ChannelId,
}

/// Whether this sequencer is currently authorized to write to the channel.
///
/// Prefer subscribing to `channel/<channel_id>/turn` topic instead of polling this.
pub struct CheckIsOurTurn;

/// Get live (adopted, possibly not yet finalized) accredited-key snapshot for
/// this channel with the config entry it comes from.
///
/// The config entry is what tells a caller whether this committee is the
/// finalized one: compare it to the checkpoint's `finalized_config`.
pub struct GetAccreditedKeys;

/// The channel's accredited keys, the config entry they come from, and whose
/// turn the tip was written on.
#[derive(Reply)]
pub struct AccreditedKeys {
    pub keys: Vec<Ed25519PublicKey>,
    pub config_tip: MsgId,
    /// Position in `keys` of the sequencer whose turn the tip was written on.
    pub tip_sequencer: u16,
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
pub struct GetChannelTipSlot;

/// Get live channel tip message id.
pub struct GetChannelTipMessageId;

/// Finalized channel messages from `after` (exclusive) up to LIB.
pub struct ReadChannel {
    /// Passing [`None`] will read from the channel's genesis.
    pub after: Option<Slot>,
}
