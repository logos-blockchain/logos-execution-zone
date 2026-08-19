//! Startup check that a local store still belongs to the chain the connected
//! channel serves.

use anyhow::Result;
use common::{HashType, block::Block};
use futures::{Stream, StreamExt};
use lee_core::BlockId;
use log::warn;
use logos_blockchain_core::mantle::{
    gas::GasCost,
    ops::{OpId, channel::ChannelId},
};
use logos_blockchain_zone_sdk::{
    Deposit, Slot, Withdraw, ZoneBlock, ZoneMessage, adapter,
    sequencer::{
        DepositInfo, Event, FinalizedOp, FundingConfig, InscriptionInfo, SequencerCheckpoint,
        WithdrawInfo, ZoneSequencer,
    },
};

/// Upper bound on the channel reads of the startup consistency check.
const CHANNEL_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Default signing key bytes, necessary after merging zone indexer and sequecner.
pub const DEFULT_SIGNING_KEY_BYTES: [u8; 32] = [13; 32];

/// Result of comparing a caller's stored chain against the channel.
pub enum ChainConsistency {
    /// Channel still serves our anchor block (the stored tip position, or the
    /// parked block while stalled).
    Consistent,
    /// We could not determine the outcome due to one of:
    ///
    /// - cold store (no anchor to compare at)
    /// - the channel served only blocks newer than the anchor
    /// - or the channel read was inconclusive (timeout / error / empty stream)
    ///
    /// NOTE: None of these prove a reset, so the caller proceeds.
    /// A genuine divergence is still caught later when applying the channel history.
    Inconclusive,
    /// Positive evidence that the channel is a different chain than the store.
    ///
    /// Details in [`ChainMismatch`], and impl's Display trait.
    Inconsistent(ChainMismatch),
}

/// The evidence behind a [`ChainConsistency::Inconsistent`].
pub enum ChainMismatch {
    /// The channel serves a different block at the anchor's id.
    Block {
        ours: (BlockId, HashType),
        channel: (BlockId, HashType),
    },
    /// The channel serves a block at/below the anchor's id past the anchor
    /// slot; on the same chain those ids live at earlier slots.
    ReinscribedBlock {
        channel: (BlockId, HashType),
        slot: Slot,
        anchor_slot: Slot,
    },
    /// The channel has content past the anchor slot but no longer the
    /// inscription we anchored on.
    AnchorSlotChanged { anchor_slot: Slot },
    /// The channel does not exist on the connected chain.
    ChannelMissing,
    /// The channel's history ends before the anchor slot.
    ChannelBehindAnchor { tip_slot: Slot, anchor_slot: Slot },
}

impl std::fmt::Display for ChainMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Block { ours, channel } => write!(
                f,
                "stored block {} {} != channel block {} {}",
                ours.0, ours.1, channel.0, channel.1
            ),
            Self::ReinscribedBlock {
                channel,
                slot,
                anchor_slot,
            } => write!(
                f,
                "channel re-serves block {} {} at slot {} past our anchor slot {}",
                channel.0,
                channel.1,
                slot.into_inner(),
                anchor_slot.into_inner()
            ),
            Self::AnchorSlotChanged { anchor_slot } => write!(
                f,
                "channel content at slot {} no longer includes the inscription we parked on",
                anchor_slot.into_inner()
            ),
            Self::ChannelMissing => write!(f, "channel does not exist on the connected chain"),
            Self::ChannelBehindAnchor {
                tip_slot,
                anchor_slot,
            } => write!(
                f,
                "channel tip slot {} is behind our anchor slot {}",
                tip_slot.into_inner(),
                anchor_slot.into_inner()
            ),
        }
    }
}

/// A block that must still be inscribed at `checkpoint` if the channel is the chain
/// the store was built from: the tip at the read cursor, or the recorded
/// parked block while stalled.
#[derive(Debug, Clone)]
pub struct Anchor {
    checkpoint: SequencerCheckpoint,
    /// The anchor block's `(id, hash)`.
    ///
    /// `None` when anchored on an undeserializable inscription (no header was recorded).
    block: Option<(BlockId, HashType)>,
}

impl Anchor {
    /// Builds an anchor at `checkpoint` on the block `(id, hash)`, or a headerless
    /// anchor (`None`) when only the checkpoint is known.
    #[must_use]
    pub const fn new(checkpoint: SequencerCheckpoint, block: Option<(BlockId, HashType)>) -> Self {
        Self { checkpoint, block }
    }

    #[must_use]
    pub const fn slot(&self) -> Slot {
        self.checkpoint.lib_slot
    }

    /// Probes a channel message read at/after the anchor slot.
    /// See [`verify_chain_consistency`].
    fn probe_anchor_slot(&self, msg: &ZoneMessage, slot: Slot) -> AnchorProbe {
        if slot < self.slot() {
            return AnchorProbe::KeepLooking;
        }
        let Some((anchor_id, anchor_hash)) = self.block else {
            // Anchored on an undeserializable inscription: any message still
            // present at that slot means the history is intact.
            return if slot == self.slot() {
                AnchorProbe::SameChain
            } else {
                AnchorProbe::Mismatch(ChainMismatch::AnchorSlotChanged {
                    anchor_slot: self.slot(),
                })
            };
        };
        let ZoneMessage::Block(zone_block) = msg else {
            return AnchorProbe::KeepLooking;
        };
        let Ok(block) = borsh::from_slice::<Block>(&zone_block.data) else {
            return AnchorProbe::KeepLooking;
        };
        let (id, hash) = (block.header.block_id, block.header.hash);
        if id == anchor_id {
            return if hash == anchor_hash {
                AnchorProbe::SameChain
            } else {
                AnchorProbe::Mismatch(ChainMismatch::Block {
                    ours: (anchor_id, anchor_hash),
                    channel: (id, hash),
                })
            };
        }
        if id > anchor_id {
            return AnchorProbe::Bail;
        }
        if slot == self.slot() {
            // Older ids can share the anchor's slot on the same chain.
            return AnchorProbe::KeepLooking;
        }
        // An id below the anchor served past the anchor slot is impossible on the
        // same chain, even if the content is identical (deterministic genesis).
        AnchorProbe::Mismatch(ChainMismatch::ReinscribedBlock {
            channel: (id, hash),
            slot,
            anchor_slot: self.slot(),
        })
    }
}

/// Classifies a stored chain against the channel one message at a time.
///
/// The shared driver behind both consistency consumers:
/// [`verify_chain_consistency`] runs it over a channel it reads itself, while a
/// caller that already streams the channel history (e.g. a reconstructing
/// sequencer) feeds it the same messages it replays. Run [`Self::check_frontier`]
/// once the channel tip is known, then feed messages in slot order via
/// [`Self::observe`] until a verdict is reached.
pub struct AnchorConsistencyCheck {
    anchor: Anchor,
    verdict: Option<ChainConsistency>,
}

impl AnchorConsistencyCheck {
    /// New checker for `anchor` with an undetermined verdict.
    #[must_use]
    pub const fn new(anchor: Anchor) -> Self {
        Self {
            anchor,
            verdict: None,
        }
    }

    /// Applies the frontier check against a known channel tip. Skip it when the
    /// tip could not be read, leaving the verdict to the message scan.
    pub fn check_frontier(&mut self, channel_tip_slot: Option<Slot>) {
        if self.verdict.is_none() {
            self.verdict = frontier_verdict(self.anchor.slot(), channel_tip_slot)
                .map(ChainConsistency::Inconsistent);
        }
    }

    /// Feeds the next channel message in slot order. Returns the verdict once it
    /// is known so the caller can stop, or `None` while still undetermined.
    pub fn observe(&mut self, msg: &ZoneMessage, slot: Slot) -> Option<&ChainConsistency> {
        if self.verdict.is_none() {
            self.verdict = match self.anchor.probe_anchor_slot(msg, slot) {
                AnchorProbe::SameChain => Some(ChainConsistency::Consistent),
                AnchorProbe::Mismatch(mismatch) => Some(ChainConsistency::Inconsistent(mismatch)),
                AnchorProbe::Bail => Some(ChainConsistency::Inconclusive),
                AnchorProbe::KeepLooking => None,
            };
        }
        self.verdict.as_ref()
    }

    /// The verdict reached so far, or `None` while undetermined.
    #[must_use]
    pub const fn verdict(&self) -> Option<&ChainConsistency> {
        self.verdict.as_ref()
    }

    /// Consumes the checker, defaulting an undetermined verdict (the anchor slot
    /// was never observed) to [`ChainConsistency::Inconclusive`].
    #[must_use]
    pub fn finish(self) -> ChainConsistency {
        self.verdict.unwrap_or(ChainConsistency::Inconclusive)
    }
}

/// What a single channel message tells the anchored consistency check.
enum AnchorProbe {
    /// The anchor is still in place: same chain.
    SameChain,
    Mismatch(ChainMismatch),
    /// Only newer ids past the anchor: plausible on the same chain, so stop
    /// scanning without a verdict.
    Bail,
    KeepLooking,
}

/// Migration of indexer-specific functionality after indexer removal.
///
/// Reads all finalized blocks into a stream.
pub async fn next_messages<N>(
    indexer: &mut ZoneSequencer<N>,
) -> impl Stream<Item = (ZoneMessage, SequencerCheckpoint)>
where
    N: adapter::Node + Clone + Sync + Send + 'static,
{
    async_stream::stream! {
        loop {
            match indexer.next_event().await {
                Event::BlocksProcessed {
                    checkpoint, finalized: batch, ..
                } => {
                    for fin_tx in batch {
                        for op in fin_tx.ops {
                            let zone_msg = match op {
                                FinalizedOp::Deposit(DepositInfo {
                                    tx_hash,
                                    op_id,
                                    channel_id: _,
                                    inputs,
                                    notes,
                                    amount,
                                    metadata,
                                }) => ZoneMessage::Deposit(Deposit {
                                    tx_hash,
                                    op_id,
                                    inputs,
                                    notes,
                                    amount,
                                    metadata,
                                }),
                                FinalizedOp::Withdraw(WithdrawInfo { tx_hash, op }) => {
                                    ZoneMessage::Withdraw(Withdraw {
                                        tx_hash,
                                        op_id: op.op_id(),
                                        inputs: op.inputs,
                                    })
                                }
                                FinalizedOp::Inscription(InscriptionInfo {
                                    tx_hash: _,
                                    parent_msg: _,
                                    this_msg,
                                    payload,
                                }) => ZoneMessage::Block(ZoneBlock {
                                        id: this_msg,
                                        data: payload,
                                }),
                            };

                            // Clonuing checkpoint here can be a costly operation.
                            // ToDo: Consider refactoring, right now, we need checkpoint here to
                            // fully anchor an indexer, which in turn is needed for old interfaces.
                            yield (zone_msg, checkpoint.clone());
                        }
                    }
                },
                Event::Ready => break,
                Event::MempoolPending(_) | Event::TurnNotification { .. } => {}
            }
        }
    }
}

/// Placeholder funding config for indexer, must be provided after merging zone indexer and
/// sequencer.
pub fn funding_placeholder() -> FundingConfig {
    FundingConfig {
        funding_pk: num_bigint::BigUint::new_const(1).into(),
        max_tx_fee: GasCost::new(u64::MAX),
        priority_fee_percent: FundingConfig::DEFAULT_PRIORITY_FEE_PERCENT,
    }
}

/// Placeholder signing_key for indexer, must be provided after merging zone indexer and sequencer.
///
/// NOT AN EXACT STRUCT, have conversion into necessary key type.
///
/// ToDo: Replace, when zone-sdk keys crate is accesable.
pub fn signing_key_placeholder() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&DEFULT_SIGNING_KEY_BYTES)
}

/// Initialize indexer from a checkpoint.
pub fn new_indexer<N>(
    channel_id: ChannelId,
    node: N,
    checkpoint: Option<SequencerCheckpoint>,
) -> ZoneSequencer<N>
where
    N: adapter::Node + Clone + Sync + Send + 'static,
{
    ZoneSequencer::init(
        channel_id,
        signing_key_placeholder().into(),
        node,
        funding_placeholder(),
        checkpoint,
    )
}

/// Detects when a local store belongs to a different chain than the connected
/// L1 (e.g. a wiped/restarted Bedrock) so startup can react instead of silently
/// diverging.
///
/// Verifies the channel still carries the anchor block at its slot. The anchor
/// was finalized at `anchor.slot`, so the same chain must still serve it there,
/// while a reset chain re-inscribes its content only at later wall-clock slots.
/// Only positive evidence of a different chain yields
/// [`ChainConsistency::Inconsistent`]; absence of data stays
/// [`ChainConsistency::Inconclusive`].
///
/// `node` need only implement the zone-sdk [`adapter::Node`] trait; a throwaway
/// [`ZoneIndexer`] is built internally for the channel read.
pub async fn verify_chain_consistency<N>(
    node: &N,
    channel_id: ChannelId,
    anchor: &Anchor,
) -> Result<ChainConsistency>
where
    N: adapter::Node + Clone + Sync + Send + 'static,
{
    let mut check = AnchorConsistencyCheck::new(anchor.clone());
    match node.channel_state(channel_id).await {
        Ok(state) => check.check_frontier(state.map(|s| s.tip_slot)),
        Err(err) => warn!("Failed to read channel state for the consistency check: {err:#}"),
    }
    if check.verdict().is_some() {
        return Ok(check.finish());
    }

    let mut zone_indexer = ZoneSequencer::init(
        channel_id,
        signing_key_placeholder().into(),
        node.clone(),
        funding_placeholder(),
        Some(anchor.checkpoint.clone()),
    );

    let scan = async {
        let stream = next_messages(&mut zone_indexer).await;
        let mut stream = std::pin::pin!(stream);

        while let Some((
            msg,
            SequencerCheckpoint {
                last_msg_id: _,
                pending_txs: _,
                lib: _,
                lib_slot: slot,
            },
        )) = stream.next().await
        {
            if check.observe(&msg, slot).is_some() {
                break;
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    match tokio::time::timeout(CHANNEL_READ_TIMEOUT, scan).await {
        Ok(Ok(())) => Ok(check.finish()),
        Ok(Err(err)) => {
            warn!("Failed to read the anchor slot for the consistency check; proceeding: {err:#}");
            Ok(ChainConsistency::Inconclusive)
        }
        Err(_elapsed) => {
            warn!("Timed out reading the anchor slot for the consistency check; proceeding");
            Ok(ChainConsistency::Inconclusive)
        }
    }
}

/// Checks the channel frontier against the anchor slot.
///
/// The anchor block was finalized at `anchor_slot`, so on the same chain the
/// channel tip can never be behind it, and the channel must exist.
fn frontier_verdict(anchor_slot: Slot, channel_tip_slot: Option<Slot>) -> Option<ChainMismatch> {
    match channel_tip_slot {
        None => Some(ChainMismatch::ChannelMissing),
        Some(tip_slot) if tip_slot < anchor_slot => Some(ChainMismatch::ChannelBehindAnchor {
            tip_slot,
            anchor_slot,
        }),
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use common::block::HashableBlockData;
    use logos_blockchain_core::mantle::ops::channel::{MsgId, inscribe::Inscription};
    use logos_blockchain_zone_sdk::ZoneBlock;

    use super::*;

    fn test_block(block_id: BlockId, timestamp: u64) -> Block {
        HashableBlockData {
            block_id,
            prev_block_hash: HashType([0; 32]),
            timestamp,
            transactions: vec![],
        }
        .into_pending_block(&lee::PrivateKey::try_new([7; 32]).expect("valid key"))
    }

    fn block_msg(block: &Block) -> ZoneMessage {
        let bytes = borsh::to_vec(block).expect("serialize");
        ZoneMessage::Block(ZoneBlock {
            id: MsgId::from([0_u8; 32]),
            data: Inscription::try_from(bytes.as_slice()).expect("inscription"),
        })
    }

    fn anchor_for(block: &Block, slot: Slot) -> Anchor {
        let test_checkpoint = SequencerCheckpoint {
            last_msg_id: MsgId::from([0_u8; 32]),
            pending_txs: vec![],
            lib: [1_u8; 32].into(),
            lib_slot: slot,
        };

        Anchor::new(
            test_checkpoint,
            Some((block.header.block_id, block.header.hash)),
        )
    }

    #[test]
    fn probe_finds_anchor_block_at_slot() {
        let tip = test_block(5, 42);
        let anchor = anchor_for(&tip, Slot::from(1_000));
        assert!(matches!(
            anchor.probe_anchor_slot(&block_msg(&tip), Slot::from(1_000)),
            AnchorProbe::SameChain
        ));
    }

    #[test]
    fn probe_flags_different_block_at_anchor_id() {
        let tip = test_block(5, 42);
        let anchor = anchor_for(&tip, Slot::from(1_000));
        // Same id, different content (timestamp) => different hash.
        let other = test_block(5, 43);
        assert!(matches!(
            anchor.probe_anchor_slot(&block_msg(&other), Slot::from(1_000)),
            AnchorProbe::Mismatch(ChainMismatch::Block { .. })
        ));
    }

    #[test]
    fn probe_flags_old_id_reinscribed_past_the_anchor_slot() {
        // A reset chain re-inscribes from genesis at later slots. Even if the
        // content is byte-identical (deterministic genesis), an id at/below
        // the anchor past the anchor slot is impossible on the same chain.
        let tip = test_block(5, 42);
        let anchor = anchor_for(&tip, Slot::from(1_000));
        let genesis = test_block(1, 0);
        assert!(matches!(
            anchor.probe_anchor_slot(&block_msg(&genesis), Slot::from(1_001)),
            AnchorProbe::Mismatch(ChainMismatch::ReinscribedBlock { .. })
        ));
    }

    #[test]
    fn probe_skips_older_blocks_sharing_the_anchor_slot() {
        let tip = test_block(5, 42);
        let anchor = anchor_for(&tip, Slot::from(1_000));
        let earlier = test_block(4, 41);
        assert!(matches!(
            anchor.probe_anchor_slot(&block_msg(&earlier), Slot::from(1_000)),
            AnchorProbe::KeepLooking
        ));
    }

    #[test]
    fn probe_bails_on_newer_ids_past_the_anchor() {
        // Blocks newer than the anchor are plausible on the same chain (e.g.
        // published while we were down), so they must never count as evidence.
        let tip = test_block(5, 42);
        let anchor = anchor_for(&tip, Slot::from(1_000));
        let newer = test_block(6, 43);
        assert!(matches!(
            anchor.probe_anchor_slot(&block_msg(&newer), Slot::from(1_001)),
            AnchorProbe::Bail
        ));
    }

    #[test]
    fn probe_skips_undeserializable_inscriptions() {
        let tip = test_block(5, 42);
        let anchor = anchor_for(&tip, Slot::from(1_000));
        let garbage = ZoneMessage::Block(ZoneBlock {
            id: MsgId::from([0_u8; 32]),
            data: Inscription::try_from(&[1_u8, 2, 3][..]).expect("inscription"),
        });
        assert!(matches!(
            anchor.probe_anchor_slot(&garbage, Slot::from(1_000)),
            AnchorProbe::KeepLooking
        ));
    }

    #[test]
    fn probe_accepts_any_message_for_a_headerless_anchor() {
        // A deserialize park records no header: any message still present at
        // the anchor slot means the history is intact.
        let test_checkpoint = SequencerCheckpoint {
            last_msg_id: MsgId::from([0_u8; 32]),
            pending_txs: vec![],
            lib: [1_u8; 32].into(),
            lib_slot: Slot::from(1_000),
        };

        let anchor = Anchor::new(test_checkpoint, None);
        let garbage = ZoneMessage::Block(ZoneBlock {
            id: MsgId::from([0_u8; 32]),
            data: Inscription::try_from(&[1_u8, 2, 3][..]).expect("inscription"),
        });
        assert!(matches!(
            anchor.probe_anchor_slot(&garbage, Slot::from(1_000)),
            AnchorProbe::SameChain
        ));
        assert!(matches!(
            anchor.probe_anchor_slot(&garbage, Slot::from(1_001)),
            AnchorProbe::Mismatch(ChainMismatch::AnchorSlotChanged { .. })
        ));
    }

    #[test]
    fn frontier_flags_missing_channel_and_short_history() {
        assert!(matches!(
            frontier_verdict(Slot::from(1_000), None),
            Some(ChainMismatch::ChannelMissing)
        ));
        assert!(matches!(
            frontier_verdict(Slot::from(1_000), Some(Slot::from(999))),
            Some(ChainMismatch::ChannelBehindAnchor { .. })
        ));
        assert!(frontier_verdict(Slot::from(1_000), Some(Slot::from(1_000))).is_none());
        assert!(frontier_verdict(Slot::from(1_000), Some(Slot::from(2_000))).is_none());
    }
}
