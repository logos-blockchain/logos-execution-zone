//! Startup check that the local store still belongs to the chain the
//! connected channel serves.

use anyhow::Result;
use common::{HashType, block::Block};
use futures::StreamExt as _;
use log::warn;
use logos_blockchain_zone_sdk::{Slot, ZoneMessage, adapter::Node as _};

use crate::IndexerCore;

/// Upper bound on the channel reads of the startup consistency check.
const CHANNEL_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Result of comparing the indexer's stored chain against the channel.
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
    /// A genuine divergence is still caught later when the ingest loop tries to apply and parks.
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
        ours: (u64, HashType),
        channel: (u64, HashType),
    },
    /// The channel serves a block at/below the anchor's id past the anchor
    /// slot; on the same chain those ids live at earlier slots.
    ReinscribedBlock {
        channel: (u64, HashType),
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

/// A block that must still be inscribed at `slot` if the channel is the chain
/// the store was built from: the tip at the read cursor, or the recorded
/// parked block while stalled.
struct Anchor {
    slot: Slot,
    /// The anchor block's `(id, hash)`.
    ///
    /// `None` when parked on an undeserializable inscription (no header was recorded).
    block: Option<(u64, HashType)>,
}

impl Anchor {
    /// Probes a channel message read at/after the anchor slot.
    /// See [`IndexerCore::verify_chain_at_anchor`].
    pub fn probe_anchor_slot(&self, msg: &ZoneMessage, slot: Slot) -> AnchorProbe {
        if slot < self.slot {
            return AnchorProbe::KeepLooking;
        }
        let Some((anchor_id, anchor_hash)) = self.block else {
            // Anchored on an undeserializable inscription: any message still
            // present at that slot means the history is intact.
            return if slot == self.slot {
                AnchorProbe::SameChain
            } else {
                AnchorProbe::Mismatch(ChainMismatch::AnchorSlotChanged {
                    anchor_slot: self.slot,
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
        if slot == self.slot {
            // Older ids can share the anchor's slot on the same chain.
            return AnchorProbe::KeepLooking;
        }
        // An id below the anchor served past the anchor slot is impossible on the
        // same chain, even if the content is identical (deterministic genesis).
        AnchorProbe::Mismatch(ChainMismatch::ReinscribedBlock {
            channel: (id, hash),
            slot,
            anchor_slot: self.slot,
        })
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

#[expect(
    clippy::multiple_inherent_impl,
    reason = "split for clarity & isolation of relevant code"
)]
impl IndexerCore {
    /// Verifies whether the channel still serves the same chain the store was built from.
    /// This may change frequently during development where we reset the chain from time to
    /// time in devnet/testnet, but we do not expect [`ChainConsistency::Inconsistent`] in
    /// production.
    ///
    /// To compare the chains, we use an [`Anchor`] block that is either the parked L2 block
    /// while stalled, or the tip L2 block at its own inscription L1 slot.
    pub(crate) async fn verify_chain_consistency(&self) -> Result<ChainConsistency> {
        let Some(anchor) = self.get_startup_anchor()? else {
            // empty or cold store: nothing to compare
            return Ok(ChainConsistency::Inconclusive);
        };

        self.verify_chain_at_anchor(&anchor).await
    }

    /// Builds the anchor for the startup check.
    ///
    /// - If stalled, returns the recorded _parked_ block
    /// - If not stalled, returns the validated tip at its _own_ inscription slot.
    /// - If the store is empty, returns `None`.
    fn get_startup_anchor(&self) -> Result<Option<Anchor>> {
        if let Some(stall) = self.store.get_stall_reason()? {
            return Ok(Some(Anchor {
                slot: stall.l1_slot,
                block: stall.block_id.zip(stall.block_hash),
            }));
        }

        // not stalled, so anchor on the tip at its own inscription slot
        let Some(slot) = self.store.get_tip_slot()?.or(self.store.get_zone_cursor()?) else {
            return Ok(None);
        };
        let Some(tip_id) = self.store.get_last_block_id()? else {
            return Ok(None);
        };
        let Some(tip) = self.store.get_block_at_id(tip_id)? else {
            return Ok(None);
        };
        Ok(Some(Anchor {
            slot,
            block: Some((tip_id, tip.header.hash)),
        }))
    }

    /// Verifies the channel still carries the anchor block at its slot.
    ///
    /// The anchor was finalized at `anchor.slot`, so the same chain must still
    /// serve it there, while a reset chain re-inscribes its content only at
    /// later wall-clock slots.
    ///
    /// Only positive evidence of a different chain yields `Inconsistent`.
    /// Absence of data stays `Inconclusive`.
    async fn verify_chain_at_anchor(&self, anchor: &Anchor) -> Result<ChainConsistency> {
        match self.node.channel_state(self.config.channel_id).await {
            Ok(state) => {
                if let Some(mismatch) = frontier_verdict(anchor.slot, state.map(|s| s.tip_slot)) {
                    return Ok(ChainConsistency::Inconsistent(mismatch));
                }
            }
            Err(err) => {
                warn!("Failed to read channel state for the consistency check: {err:#}");
            }
        }

        // `next_messages` is exclusive, so `slot - 1` includes the anchor slot.
        let Some(from_slot) = anchor.slot.into_inner().checked_sub(1) else {
            return Ok(ChainConsistency::Inconclusive);
        };

        let scan = async {
            let stream = self
                .zone_indexer
                .next_messages(Some(Slot::from(from_slot)))
                .await?;
            let mut stream = std::pin::pin!(stream);

            while let Some((msg, slot)) = stream.next().await {
                match anchor.probe_anchor_slot(&msg, slot) {
                    AnchorProbe::SameChain => return Ok(Some(ChainConsistency::Consistent)),
                    AnchorProbe::Mismatch(mismatch) => {
                        return Ok(Some(ChainConsistency::Inconsistent(mismatch)));
                    }
                    AnchorProbe::Bail => return Ok(Some(ChainConsistency::Inconclusive)),
                    AnchorProbe::KeepLooking => { /* dont do anything */ }
                }
            }
            Ok::<_, anyhow::Error>(None)
        };

        match tokio::time::timeout(CHANNEL_READ_TIMEOUT, scan).await {
            Ok(Ok(Some(outcome))) => Ok(outcome),
            Ok(Ok(None)) => Ok(ChainConsistency::Inconclusive),
            Ok(Err(err)) => {
                warn!(
                    "Failed to read the anchor slot for the consistency check; proceeding: {err:#}"
                );
                Ok(ChainConsistency::Inconclusive)
            }
            Err(_elapsed) => {
                warn!("Timed out reading the anchor slot for the consistency check; proceeding");
                Ok(ChainConsistency::Inconclusive)
            }
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
    use std::time::Duration;

    use common::block::HashableBlockData;
    use logos_blockchain_core::mantle::ops::channel::{MsgId, inscribe::Inscription};
    use logos_blockchain_zone_sdk::ZoneBlock;

    use super::*;
    use crate::{
        AcceptOutcome, BlockIngestError,
        config::{ChannelId, ClientConfig, IndexerConfig},
    };

    fn unreachable_core(dir: &std::path::Path) -> IndexerCore {
        let config = IndexerConfig {
            consensus_info_polling_interval: Duration::from_secs(1),
            bedrock_config: ClientConfig {
                addr: "http://localhost:1".parse().expect("url"),
                auth: None,
            },
            channel_id: ChannelId::from([1; 32]),
            allow_chain_reset: false,
            cross_zone: None,
            bridge_lock_holdings: Vec::new(),
        };
        IndexerCore::open(config, dir).expect("open core")
    }

    fn test_block(block_id: u64, timestamp: u64) -> Block {
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
        Anchor {
            slot,
            block: Some((block.header.block_id, block.header.hash)),
        }
    }

    #[tokio::test]
    async fn cold_store_is_inconclusive() {
        // An empty store has no cursor, so there is nothing to compare: the check
        // must be Inconclusive (not Consistent), and it returns before any L1 read.
        let dir = tempfile::tempdir().expect("tempdir");
        let core = unreachable_core(dir.path());
        assert!(matches!(
            core.verify_chain_consistency().await.expect("verify"),
            ChainConsistency::Inconclusive
        ));
    }

    #[tokio::test]
    async fn parked_store_with_unreachable_node_is_inconclusive() {
        // Network failure is not evidence of a reset: a parked store must stay
        // parked (Inconclusive), not error out or trip the wipe path.
        let dir = tempfile::tempdir().expect("tempdir");
        let core = unreachable_core(dir.path());
        let parked = test_block(5, 42);
        core.store
            .record_stall(
                Some(&parked.header),
                Slot::from(1_000),
                BlockIngestError::EmptyBlock,
            )
            .expect("record stall");
        assert!(matches!(
            core.verify_chain_consistency().await.expect("verify"),
            ChainConsistency::Inconclusive
        ));
    }

    #[tokio::test]
    async fn caught_up_store_with_unreachable_node_is_inconclusive() {
        let dir = tempfile::tempdir().expect("tempdir");
        let core = unreachable_core(dir.path());
        let genesis = common::test_utils::produce_dummy_block(1, None, vec![]);
        assert!(matches!(
            core.store
                .accept_block(&genesis, Slot::from(1_000))
                .await
                .expect("accept"),
            AcceptOutcome::Applied
        ));
        core.store
            .set_zone_cursor(&Slot::from(1_000))
            .expect("set cursor");
        assert!(matches!(
            core.verify_chain_consistency().await.expect("verify"),
            ChainConsistency::Inconclusive
        ));
    }

    #[tokio::test]
    async fn startup_anchor_prefers_tip_slot_over_lagging_cursor() {
        // Cursor persist failures are warn-only, so the read cursor can lag the
        // tip by several blocks. The anchor must pair the tip with its own
        // inscription slot; pairing it with the stale cursor would make the scan
        // misread the chain's intermediate blocks as re-inscriptions.
        let dir = tempfile::tempdir().expect("tempdir");
        let core = unreachable_core(dir.path());

        let genesis = common::test_utils::produce_dummy_block(1, None, vec![]);
        core.store
            .accept_block(&genesis, Slot::from(1_000))
            .await
            .expect("accept");
        let block2 = common::test_utils::produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        core.store
            .accept_block(&block2, Slot::from(1_005))
            .await
            .expect("accept");
        let block3 = common::test_utils::produce_dummy_block(3, Some(block2.header.hash), vec![]);
        core.store
            .accept_block(&block3, Slot::from(1_010))
            .await
            .expect("accept");

        // Cursor last persisted at the genesis slot: two blocks behind the tip.
        core.store
            .set_zone_cursor(&Slot::from(1_000))
            .expect("set cursor");

        let anchor = core.get_startup_anchor().expect("anchor").expect("present");
        assert_eq!(anchor.slot, Slot::from(1_010));
        assert_eq!(anchor.block, Some((3, block3.header.hash)));
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
        let anchor = Anchor {
            slot: Slot::from(1_000),
            block: None,
        };
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
