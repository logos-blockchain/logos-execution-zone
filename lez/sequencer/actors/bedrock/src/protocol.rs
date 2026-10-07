use std::time::Duration;

pub use chain_state::ChannelEntry;
use common::block::Block;
use kameo::Reply;
pub use logos_blockchain_binary_codec::bincode::{DeserializeOp, SerializeOp};
pub use logos_blockchain_core::mantle::{NoteId, transactions::Ops};
pub use logos_blockchain_key_management_system_service::keys::{
    Ed25519Key, Ed25519PublicKey, ZkPublicKey,
};
use logos_blockchain_zone_sdk::sequencer::PreparedChannelConfig;
pub use logos_blockchain_zone_sdk::{
    Slot, UnverifiedEd25519PublicKey, ZoneMessage,
    adapter::BoxStream,
    node_types::{ChannelId, HeaderId, MsgId},
    sequencer::{
        DepositInfo, IndexedSignature, SequencerCheckpoint as Checkpoint, SequencerCheckpoint,
        WithdrawArg, WithdrawInfo,
    },
};
pub use sequencer_stake_core::ChannelParams;
use sharding_pool_actor::ShardingKey;

/// Version of the channel view the actor holds, bumped by every broadcast update
/// and every publish.
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

/// How the unfinalized message lineage moved across one update.
#[derive(Debug, Clone)]
pub enum ViewChange {
    /// Entries appended to the view.
    Extension(Vec<ChannelEntry>),
    /// Entries left the view; `canonical` is the whole view at the new tip.
    Conflict {
        canonical: Vec<ChannelEntry>,
        orphaned: Vec<ChannelEntry>,
    },
}

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
    FinalizedBlock(Box<FinalizedBlock>),

    /// Events related to the channel publisher arriving to `channel/<channel_id>/publisher/`
    /// topics.
    Publisher(PublisherEvent),
}

#[derive(Debug, Clone)]
pub struct FinalizedBlock {
    pub block: BlockData,
    pub msg_id: MsgId,
    pub slot: Slot,
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

    /// Message arriving to `channel/<channel_id>/publisher/config` topic.
    Config(LiveChannelConfig),
}

/// Everything one channel update carries.
#[derive(Debug, Clone)]
pub struct ChannelUpdate {
    /// Resume cursor for this event. Persist only together with the effects
    /// below, never ahead of them.
    pub checkpoint: Checkpoint,
    /// The channel sequence this update leaves the actor at. A consumer that
    /// wants to publish echoes the last one it applied back in
    /// [`PublishBlock::expected_seq`].
    pub seq: ChannelSeq,
    /// How the unfinalized message lineage moved.
    pub view: ViewChange,
    /// Message-lineage entries whose L1 block reached finality, in channel order.
    pub finalized: Vec<ChannelEntry>,
    /// Finalized Bedrock deposit events, to record and mint on L2.
    pub deposits: Vec<DepositInfo>,
    /// Finalized Bedrock withdraw events, to reconcile against local intents.
    pub withdrawals: Vec<WithdrawInfo>,
    /// Finalized inscriptions that are not blocks, with the key that signed each.
    pub undecodable: Vec<(MsgId, Ed25519PublicKey)>,
    /// The key that signed each finalized entry carrying a block.
    pub finalized_signers: Vec<(MsgId, Ed25519PublicKey)>,
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

/// Initialize the channel publisher. This will make using messages like [`PublishBlock`] possible.
///
/// If no previous channel publisher exists, this will initialize it and return `true`; otherwise,
/// it will just return `false` without reinitializing the channel publisher.
#[derive(Debug, Clone)]
pub struct InitializeChannelPublisher {
    pub channel_id: ChannelId,
    pub bedrock_signing_key: Ed25519Key,
    pub funding_pk: ZkPublicKey,
    pub priority_fee_percent: u64,
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
#[derive(Debug, Clone)]
pub struct CreateChannel {
    pub channel_id: ChannelId,
    pub genesis: Block,
    pub keys: Vec<Ed25519PublicKey>,
    pub channel_params: ChannelParams,
    pub configuration_threshold: u16,
}

impl ShardingKey for CreateChannel {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
    }
}

/// Publish block to the configured channel.
#[derive(Debug, Clone)]
pub struct PublishBlock {
    pub channel_id: ChannelId,
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

impl ShardingKey for PublishBlock {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
    }
}

/// Outcome of a publish operation.
#[derive(Debug, Clone)]
pub struct PublishOutcome {
    /// The `MsgId` zone-sdk assigned the published inscription.
    pub this_msg: MsgId,
    /// The entry the inscription chains on.
    pub parent: MsgId,
    /// The checkpoint that now holds the inscription as pending.
    pub checkpoint: Checkpoint,
    /// The channel sequence this publish leaves the actor at.
    pub seq: ChannelSeq,
    /// Channel notes the bundled withdrawals release, empty for a plain
    /// publish.
    pub released_notes: Vec<NoteId>,
}

/// Fund a channel config moving the channel to the config described here, ready to be signed.
#[derive(Debug, Clone)]
pub struct PrepareConfig {
    pub channel_id: ChannelId,
    /// The committee to install, in the order the op will carry it.
    pub keys: Vec<Ed25519PublicKey>,
    pub posting_timeframe: u32,
    pub posting_timeout: u32,
    /// Signatures the *next* config will have to carry, not this one.
    pub configuration_threshold: u16,
    pub transfer_threshold: u16,
}

impl ShardingKey for PrepareConfig {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
    }
}

/// A channel config funded by [`PrepareConfig`], waiting for the accredited signatures
/// [`ChangeChannelConfig`] submits it with.
#[derive(Debug, Clone, Reply)]
pub struct PreparedConfig {
    prepared: PreparedChannelConfig,
    accredited_keys: Vec<Ed25519PublicKey>,
}

impl PreparedConfig {
    #[cfg(feature = "actor")]
    pub(crate) const fn new(
        prepared: PreparedChannelConfig,
        accredited_keys: Vec<Ed25519PublicKey>,
    ) -> Self {
        Self {
            prepared,
            accredited_keys,
        }
    }

    /// The funded transaction the signatures are over.
    #[must_use]
    pub const fn tx(&self) -> &Ops {
        self.prepared.tx()
    }

    /// The channel's accredited keys, in the index order a signature names.
    #[must_use]
    pub fn accredited_keys(&self) -> &[Ed25519PublicKey] {
        &self.accredited_keys
    }

    /// How many of [`Self::accredited_keys`] must sign.
    #[must_use]
    pub const fn signing_threshold(&self) -> u16 {
        self.prepared.signing_threshold
    }

    #[cfg(feature = "actor")]
    pub(crate) fn into_inner(self) -> PreparedChannelConfig {
        self.prepared
    }
}

/// Change the configuration of the channel.
#[derive(Debug, Clone)]
pub struct ChangeChannelConfig {
    pub channel_id: ChannelId,
    pub prepared: PreparedConfig,
    pub signatures: Vec<IndexedSignature>,
}

impl ShardingKey for ChangeChannelConfig {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
    }
}

/// Check if configured channel exists.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone, Reply)]
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct GetChannelTipMessageId {
    pub channel_id: ChannelId,
}

impl ShardingKey for GetChannelTipMessageId {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
    }
}

/// Finalized channel messages from `after` (exclusive) up to LIB, capped at
/// zone-sdk's LIB when it became ready.
#[derive(Debug, Clone)]
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

/// Inscribe raw bytes on top of the channel tip. Only a test that provokes an
/// offence needs it.
#[cfg(feature = "test-utils")]
#[derive(Debug, Clone)]
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
