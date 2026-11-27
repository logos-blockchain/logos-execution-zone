use std::{collections::BTreeSet, num::NonZero, time::Duration};

pub use chain_state::ChannelEntry;
use common::block::Block;
use kameo::{Reply, actor::ReplyRecipient};
pub use logos_blockchain_zone_sdk::{
    Slot, UnverifiedEd25519PublicKey, ZoneMessage,
    adapter::BoxStream,
    binary_codec::bincode::{DeserializeOp, SerializeOp},
    core::mantle::{NoteId, transactions::Ops},
    key_management_system_service::keys::{Ed25519Key, Ed25519PublicKey, ZkPublicKey},
    node_types::{ChannelId, HeaderId, MsgId},
    sequencer::{
        DepositInfo, IndexedSignature, IndexedSignatures, SequencerCheckpoint as Checkpoint,
        SequencerCheckpoint, WithdrawArg, WithdrawInfo,
    },
};
use logos_blockchain_zone_sdk::{core::mantle::OpProof, sequencer::PreparedChannelConfig};
pub use sequencer_stake_core::{ChannelParams, SequencerKey};
use sharding_pool_actor::ShardingKey;

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

/// Where the events of a followed channel go. The channel is read on only once the recipient has
/// replied, and an `Err` reply stops the Bedrock actor.
pub type ChannelEventRecipient = ReplyRecipient<ChannelEvent, (), ChannelEventFailed>;

/// Why the recipient failed to handle a [`ChannelEvent`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ChannelEventFailed(#[from] pub anyhow::Error);

/// Event happened on the followed channel, asked of the [`ChannelEventRecipient`].
#[derive(Debug, Clone)]
pub struct ChannelEvent {
    pub channel_id: ChannelId,
    pub event: ChannelEventKind,
}

/// Concrete kinds of events that can happen on a channel.
///
/// Arrive once the channel is followed with [`FollowChannel`].
#[derive(Debug, Clone)]
pub enum ChannelEventKind {
    /// The channel moved, or the L1 blocks it is read from carry something about it.
    Update(Box<ChannelUpdate>),

    /// The finalized history is read up to the node's LIB and the live chain is followed. Arrives
    /// again after a reconnect.
    Ready,

    /// Whose turn it is to write to the channel.
    Turn {
        our_turn_to_write: bool,
        /// Slot the current turn started at, if known. A new one is a new turn,
        /// even when it is ours again.
        starting_slot: Option<Slot>,
    },

    /// The live channel config, sent on every live block.
    Config(LiveChannelConfig),
}

/// Everything one channel update carries.
#[derive(Debug, Clone)]
pub struct ChannelUpdate {
    /// The last slot the node had finalized when this update was read.
    pub lib_slot: Slot,
    /// The last config entry that reached finality.
    pub finalized_config: MsgId,
    /// How the unfinalized message lineage moved.
    pub view: ViewChange,
    /// Message-lineage entries whose L1 block reached finality, in channel order.
    pub finalized: Vec<ChannelEntry>,
    /// Finalized Bedrock deposit events, to record and mint on L2.
    pub deposits: Vec<DepositInfo>,
    /// Deposits seen in L1 blocks before finality. Observations, not view: a reorg can drop one
    /// or deliver it again.
    pub pending_deposits: Vec<DepositInfo>,
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
    /// Signatures Bedrock demands of a channel transfer, exactly.
    pub transfer_threshold: u16,
    /// Slots one sequencer's posting turn lasts.
    pub posting_timeframe: u32,
    /// Idle slots after which Bedrock passes a turn on.
    pub posting_timeout: u32,
}

/// Start following the channel from the stored checkpoint, asking `recipient` each
/// [`ChannelEvent`] in turn.
///
/// Fails with [`Error::ChannelAlreadyFollowed`](crate::error::Error::ChannelAlreadyFollowed)
/// when the channel is followed already.
#[derive(Clone)]
pub struct FollowChannel {
    pub channel_id: ChannelId,
    pub recipient: ChannelEventRecipient,
}

impl std::fmt::Debug for FollowChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FollowChannel")
            .field("channel_id", &self.channel_id)
            .finish_non_exhaustive()
    }
}

impl ShardingKey for FollowChannel {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
    }
}

/// Where [`FollowChannel`] started.
#[derive(Debug, Clone, Copy, Reply)]
pub struct FollowStart {
    /// The last config entry that reached finality, as of the checkpoint following started from.
    pub finalized_config: MsgId,
    /// The last slot the node had finalized when following started, [`None`] if it could not be
    /// read.
    pub lib_slot: Option<Slot>,
}

/// Initialize the channel publisher. This will make using messages like [`PublishBlock`] possible.
///
/// Restarts following under `channel_signing_key` from the checkpoint of the last update
/// reported. When the channel is not followed yet, starts from the stored checkpoint instead.
/// Does nothing when the publisher is initialized already.
///
/// Replies with the [`PendingBlock`]s zone-sdk holds, which a node that stopped before recording
/// them can recover, as zone-sdk refuses any other block on their parents.
#[derive(Debug, Clone)]
pub struct InitializeChannelPublisher {
    pub channel_id: ChannelId,
    pub channel_signing_key: Ed25519Key,
    pub funding_pk: ZkPublicKey,
    pub priority_fee_percent: u64,
    pub resubmit_interval: Duration,
    pub stale_refund_slots: u64,
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
    pub configuration_threshold: NonZero<u16>,
    pub transfer_threshold: NonZero<u16>,
}

impl ShardingKey for CreateChannel {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
    }
}

/// Publish block to the configured channel.
///
/// Expected to be sent by the [`FollowChannel::recipient`], as the publish is refused with
/// [`Error::ChannelMoved`](crate::error::Error::ChannelMoved) while an update it has not applied
/// yet moved the channel.
#[derive(Debug, Clone)]
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

/// Funds `block` chained on `parent` and bundled with a transfer re-creating
/// `notes` unchanged, so it lands only where they exist; submits nothing.
#[derive(Debug, Clone)]
pub struct PreparePin {
    pub channel_id: ChannelId,
    pub block: Block,
    pub parent: MsgId,
    /// Deposited channel notes the block mints from.
    pub notes: Vec<NoteId>,
}

/// A funded pinned block, short of the signatures its transfer needs.
#[derive(Debug, Clone)]
pub struct PreparedPin {
    pub(crate) tx: Ops,
    pub(crate) msg_id: MsgId,
    pub(crate) parent: MsgId,
    /// Proof of the fee transfer the wallet appended, if it appended one.
    #[cfg_attr(
        not(feature = "actor"),
        expect(dead_code, reason = "Only the actor publishes a pin")
    )]
    pub(crate) fee_proof: Option<OpProof>,
    /// Id of the pinned block, for the publish log.
    #[cfg_attr(
        not(feature = "actor"),
        expect(dead_code, reason = "Only the actor publishes a pin")
    )]
    pub(crate) block_id: u64,
    /// Encoded size of the pinned block in bytes, for the publish log.
    #[cfg_attr(
        not(feature = "actor"),
        expect(dead_code, reason = "Only the actor publishes a pin")
    )]
    pub(crate) block_size: usize,
}

impl ShardingKey for PreparePin {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
    }
}

impl PreparedPin {
    /// The transaction the transfer's signers sign.
    #[must_use]
    pub const fn tx(&self) -> &Ops {
        &self.tx
    }

    #[must_use]
    pub const fn msg_id(&self) -> MsgId {
        self.msg_id
    }

    #[must_use]
    pub const fn parent(&self) -> MsgId {
        self.parent
    }

    /// A pin conjured outside the actor, for a mocked channel to serve.
    #[cfg(feature = "mock")]
    #[must_use]
    pub fn mocked(msg_id: MsgId, parent: MsgId) -> Self {
        Self {
            tx: Ops::new(
                logos_blockchain_zone_sdk::core::era::ForkDigest::new([0; 32]),
                logos_blockchain_zone_sdk::core::mantle::transactions::TxList::new_unchecked(
                    Vec::new(),
                ),
            ),
            msg_id,
            parent,
            fee_proof: None,
            block_id: 0,
            block_size: 0,
        }
    }
}

/// Publishes a prepared pin with exactly the channel's transfer threshold of
/// signatures.
#[derive(Debug, Clone)]
pub struct PublishPin {
    pub channel_id: ChannelId,
    pub prepared: PreparedPin,
    pub signatures: Vec<IndexedSignature>,
}

impl ShardingKey for PublishPin {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
    }
}

/// A block of ours that zone-sdk holds as published, its inscription not finalized yet.
#[derive(Debug, Clone)]
pub struct PendingBlock {
    pub block: Block,
    pub outcome: PublishOutcome,
}

/// Outcome of a publish operation.
#[derive(Debug, Clone)]
pub struct PublishOutcome {
    /// The `MsgId` zone-sdk assigned the published inscription.
    pub this_msg: MsgId,
    /// The entry the inscription chains on.
    pub parent: MsgId,
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
    pub configuration_threshold: NonZero<u16>,
    pub transfer_threshold: NonZero<u16>,
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
    pub signatures: IndexedSignatures,
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
/// Prefer [`ChannelEventKind::Turn`] events instead of polling this.
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

/// The channel's notes on the current L1 branch, finalized or not.
#[derive(Debug, Clone)]
pub struct GetChannelNotes {
    pub channel_id: ChannelId,
}

impl ShardingKey for GetChannelNotes {
    type Key = ChannelId;

    fn sharding_key(&self) -> Self::Key {
        self.channel_id
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

/// Where on L1 a block to judge sits, as far as the asker knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L1Position {
    /// Not on L1 yet.
    Unknown,
    /// In the L1 block holding the inscription with this id, final or not.
    Msg(MsgId),
    /// In the final L1 block at this slot.
    FinalSlot(u64),
    /// In the final L1 block holding the inscription `msg`, at or under the final block at
    /// `descendant_slot`.
    FinalAncestor { msg: MsgId, descendant_slot: u64 },
}

/// The keys of `keys` the L1 block at `at` may release in full: those absent from the config in
/// effect `depth` L1 blocks under it and from every config since.
#[derive(Debug, Clone)]
pub struct FilterFinallyAbsent {
    pub channel_id: ChannelId,
    pub at: L1Position,
    pub keys: BTreeSet<SequencerKey>,
    pub depth: u64,
}

impl ShardingKey for FilterFinallyAbsent {
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
