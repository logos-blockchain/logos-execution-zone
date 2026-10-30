//! Whether a key's removal config is final under a given L1 block.
//!
//! A removal is final under block `B` when no config in `B` or its `depth - 1` ancestors names
//! the key, and the newest config at or below the `depth`-th ancestor does not name it.

use std::{collections::BTreeSet, future::Future};

use chain_state::L1Position;
use logos_blockchain_core::mantle::{
    SignedOps,
    ledger::verification_mode::StandardMode,
    ops::{
        OpRef,
        channel::{ChannelId, MsgId, config::ChannelConfigOp},
    },
    transactions::states::Unverified,
};
use logos_blockchain_zone_sdk::node_types::HeaderId;
use sequencer_stake_core::SequencerKey;

pub use self::config_index::ConfigIndex;
use crate::{Result, error::Error, protocol::Ed25519PublicKey};

mod config_index;

/// The parts of an L1 block the walk reads.
#[derive(Clone, Debug)]
pub struct BlockSummary {
    pub id: HeaderId,
    pub parent: HeaderId,
    pub slot: u64,
    /// Ids of the channel's inscriptions, in chain order.
    pub inscription_msgs: Vec<MsgId>,
    /// Key lists of the channel's config ops, in chain order.
    pub config_keys: Vec<Vec<[u8; 32]>>,
}

impl BlockSummary {
    pub fn new(
        id: HeaderId,
        parent: HeaderId,
        slot: u64,
        transactions: &[SignedOps<Unverified, StandardMode>],
        channel_id: ChannelId,
    ) -> Self {
        let inscription_msgs = transactions
            .iter()
            .flat_map(SignedOps::op_refs)
            .filter_map(|op| {
                if let OpRef::ChannelInscribe(inscription) = op
                    && inscription.channel_id == channel_id
                {
                    Some(inscription.id())
                } else {
                    None
                }
            })
            .collect();
        let config_keys = transactions
            .iter()
            .flat_map(SignedOps::op_refs)
            .filter_map(|op| {
                if let OpRef::ChannelConfig(config) = op
                    && config.channel() == channel_id
                {
                    Some(config_key_bytes(config))
                } else {
                    None
                }
            })
            .collect();
        Self {
            id,
            parent,
            slot,
            inscription_msgs,
            config_keys,
        }
    }

    fn names(&self, key: SequencerKey) -> bool {
        self.config_keys
            .iter()
            .any(|keys| keys.contains(&key.to_bytes()))
    }
}

/// The L1 reads the walk makes.
pub trait L1Reader: Send {
    /// The summary of the node's tip.
    fn tip_block_summary(&mut self) -> impl Future<Output = Result<BlockSummary>> + Send;

    /// The summary of the block `id`, `None` when the node has none.
    fn block_summary(
        &mut self,
        id: HeaderId,
    ) -> impl Future<Output = Result<Option<BlockSummary>>> + Send;

    /// The summaries of the final blocks in the slot range, inclusive.
    fn final_block_summaries(
        &mut self,
        from: u64,
        to: u64,
    ) -> impl Future<Output = Result<Vec<BlockSummary>>> + Send;
}

/// The keys `config` accredits.
pub fn config_key_bytes(config: &ChannelConfigOp) -> Vec<[u8; 32]> {
    config
        .keys()
        .iter()
        .map(Ed25519PublicKey::to_bytes)
        .collect()
}

/// The keys of `keys` absent from the config in effect `depth` blocks under the block at `at` and
/// from every config since.
///
/// A block not yet on L1 is judged at the tip.
pub async fn filter_finally_absent<R: L1Reader>(
    reader: &mut R,
    index: &mut ConfigIndex,
    at: L1Position,
    keys: &BTreeSet<SequencerKey>,
    depth: u64,
) -> Result<BTreeSet<SequencerKey>> {
    if keys.is_empty() {
        return Ok(BTreeSet::new());
    }
    let mut block_summary = match at {
        L1Position::FinalSlot(slot) => final_block_summary(reader, slot).await?,
        L1Position::Msg { msg, parent } => {
            let tip_block_summary = reader.tip_block_summary().await?;
            block_summary_holding(reader, &tip_block_summary, msg, parent)
                .await?
                .unwrap_or(tip_block_summary)
        }
        L1Position::Unknown => reader.tip_block_summary().await?,
    };
    let mut result = keys.clone();
    for _ in 0..depth {
        result.retain(|key| !block_summary.names(*key));
        if result.is_empty() {
            return Ok(BTreeSet::new());
        }
        // The walk reached genesis before covering `depth` blocks, so no key is finally absent.
        if block_summary.slot == 0 {
            return Ok(BTreeSet::new());
        }
        match reader.block_summary(block_summary.parent).await? {
            Some(parent_block_summary) => block_summary = parent_block_summary,
            None => return Ok(BTreeSet::new()),
        }
    }
    let Some(config_keys) = index
        .config_keys_in_effect(reader, block_summary.slot)
        .await?
    else {
        return Ok(BTreeSet::new());
    };
    result.retain(|key| !config_keys.contains(&key.to_bytes()));
    Ok(result)
}

/// The summary of the final block at `slot`.
async fn final_block_summary<R: L1Reader>(reader: &mut R, slot: u64) -> Result<BlockSummary> {
    reader
        .final_block_summaries(slot, slot)
        .await?
        .into_iter()
        .next()
        .ok_or(Error::FinalBlockMissing(slot))
}

/// The summary of the block holding the inscription `msg`, among `from_block_summary`'s block and
/// the blocks under it down to the one holding `parent_msg`.
async fn block_summary_holding<R: L1Reader>(
    reader: &mut R,
    from_block_summary: &BlockSummary,
    msg: MsgId,
    parent_msg: MsgId,
) -> Result<Option<BlockSummary>> {
    let mut block_summary = from_block_summary.clone();
    loop {
        if block_summary.inscription_msgs.contains(&msg) {
            return Ok(Some(block_summary));
        }
        // `msg` chains on `parent_msg`, so no block under the one holding `parent_msg` holds it.
        if block_summary.inscription_msgs.contains(&parent_msg) || block_summary.slot == 0 {
            return Ok(None);
        }
        match reader.block_summary(block_summary.parent).await? {
            Some(parent_block_summary) => block_summary = parent_block_summary,
            None => return Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPTH: u64 = 3;

    /// A chain of blocks at slots 0, 2, 4, …, the block at height `h` holding the inscription
    /// `msg(h)`.
    struct Chain {
        block_summaries: Vec<BlockSummary>,
        reads: usize,
        /// The read that fails once, counted from 1.
        failing_read: Option<usize>,
    }

    impl Chain {
        fn new(height: u64) -> Self {
            let block_summaries = (0..=height)
                .map(|h| BlockSummary {
                    id: header(h.saturating_add(1)),
                    parent: header(h),
                    slot: h.saturating_mul(2),
                    inscription_msgs: vec![msg(h)],
                    config_keys: Vec::new(),
                })
                .collect();
            Self {
                block_summaries,
                reads: 0,
                failing_read: None,
            }
        }

        fn config_at(mut self, height: u64, keys: &[SequencerKey]) -> Self {
            self.block_summaries[usize::try_from(height).unwrap()]
                .config_keys
                .push(keys.iter().map(|key| key.to_bytes()).collect());
            self
        }

        fn count_read(&mut self) -> Result<()> {
            self.reads = self.reads.saturating_add(1);
            if self.failing_read == Some(self.reads) {
                self.failing_read = None;
                return Err(Error::NodeRequestFailed(anyhow::anyhow!("read failed")));
            }
            Ok(())
        }
    }

    impl L1Reader for Chain {
        async fn tip_block_summary(&mut self) -> Result<BlockSummary> {
            let tip = self.block_summaries.last().unwrap().id;
            Ok(self.block_summary(tip).await?.unwrap())
        }

        async fn block_summary(&mut self, id: HeaderId) -> Result<Option<BlockSummary>> {
            self.count_read()?;
            Ok(self
                .block_summaries
                .iter()
                .find(|block_summary| block_summary.id == id)
                .cloned())
        }

        async fn final_block_summaries(&mut self, from: u64, to: u64) -> Result<Vec<BlockSummary>> {
            self.count_read()?;
            Ok(self
                .block_summaries
                .iter()
                .filter(|block_summary| (from..=to).contains(&block_summary.slot))
                .cloned()
                .collect())
        }
    }

    fn key(seed: u8) -> SequencerKey {
        let signing = sequencer_stake_core::ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        SequencerKey::new(signing.verifying_key().to_bytes()).expect("a derived key is valid")
    }

    fn header(n: u64) -> HeaderId {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&n.to_le_bytes());
        HeaderId::from(bytes)
    }

    fn msg(n: u64) -> MsgId {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&n.to_le_bytes());
        MsgId::from(bytes)
    }

    /// Where the inscription `msg(height)` sits.
    fn msg_at_height(height: u64) -> L1Position {
        L1Position::Msg {
            msg: msg(height),
            parent: msg(height.saturating_sub(1)),
        }
    }

    fn judge(
        chain: &mut Chain,
        index: &mut ConfigIndex,
        at: L1Position,
        keys: &[SequencerKey],
    ) -> Result<BTreeSet<SequencerKey>> {
        let keys = keys.iter().copied().collect();
        futures::executor::block_on(filter_finally_absent(chain, index, at, &keys, DEPTH))
    }

    /// The index zone-sdk's events build after a cold start, final through `lib_slot`.
    fn reported_through(chain: &Chain, lib_slot: u64) -> ConfigIndex {
        let mut index = ConfigIndex::starting_at(0);
        let config_keys = chain
            .block_summaries
            .iter()
            .filter(|block_summary| block_summary.slot <= lib_slot)
            .flat_map(|block_summary| {
                block_summary
                    .config_keys
                    .iter()
                    .map(|keys| (block_summary.slot, keys.clone()))
            });
        index.extend_final(config_keys, lib_slot);
        index
    }

    fn verdict(chain: &mut Chain, at: L1Position, keys: &[SequencerKey]) -> BTreeSet<SequencerKey> {
        let mut index = reported_through(chain, chain.block_summaries.last().unwrap().slot);
        judge(chain, &mut index, at, keys).unwrap()
    }

    fn at_height(height: u64) -> L1Position {
        L1Position::FinalSlot(height.saturating_mul(2))
    }

    #[test]
    fn a_removal_depth_blocks_down_is_final() {
        // The removal at height 5 sits 3 blocks under height 8.
        let mut chain = Chain::new(10)
            .config_at(1, &[key(1), key(2)])
            .config_at(5, &[key(2)]);
        assert_eq!(
            verdict(&mut chain, at_height(8), &[key(1)]),
            [key(1)].into()
        );
    }

    #[test]
    fn a_removal_less_than_depth_blocks_down_is_not_final() {
        let mut chain = Chain::new(10)
            .config_at(1, &[key(1), key(2)])
            .config_at(6, &[key(2)]);
        assert!(verdict(&mut chain, at_height(8), &[key(1)]).is_empty());
    }

    #[test]
    fn a_readd_since_the_removal_is_not_final() {
        let mut chain = Chain::new(10)
            .config_at(1, &[key(1), key(2)])
            .config_at(2, &[key(2)])
            .config_at(7, &[key(1), key(2)]);
        assert!(verdict(&mut chain, at_height(8), &[key(1)]).is_empty());
    }

    #[test]
    fn the_last_config_in_a_block_is_in_effect() {
        let mut chain = Chain::new(10)
            .config_at(5, &[key(1), key(2)])
            .config_at(5, &[key(2)]);
        assert_eq!(
            verdict(&mut chain, at_height(8), &[key(1)]),
            [key(1)].into()
        );
    }

    #[test]
    fn a_key_the_config_in_effect_names_is_not_final() {
        let mut chain = Chain::new(10).config_at(1, &[key(1), key(2)]);
        assert!(verdict(&mut chain, at_height(8), &[key(1)]).is_empty());
    }

    #[test]
    fn no_config_under_the_window_finalizes_nothing() {
        let mut chain = Chain::new(10).config_at(7, &[key(2)]);
        assert!(verdict(&mut chain, at_height(8), &[key(1)]).is_empty());
    }

    #[test]
    fn a_chain_shorter_than_depth_finalizes_nothing() {
        let mut chain = Chain::new(10).config_at(0, &[key(2)]);
        assert!(verdict(&mut chain, at_height(2), &[key(1)]).is_empty());
    }

    #[test]
    fn each_key_is_judged_on_its_own() {
        let mut chain = Chain::new(10)
            .config_at(1, &[key(1), key(2), key(3)])
            .config_at(4, &[key(2), key(3)])
            .config_at(7, &[key(3)]);
        assert_eq!(
            verdict(&mut chain, at_height(8), &[key(1), key(2)]),
            [key(1)].into()
        );
    }

    #[test]
    fn an_inscription_is_judged_at_the_block_holding_it() {
        // Height 8 holds `msg(8)`; the tip at 10 would put the removal at 6 deep enough.
        let mut chain = Chain::new(10)
            .config_at(1, &[key(1), key(2)])
            .config_at(6, &[key(2)]);
        assert!(verdict(&mut chain, msg_at_height(8), &[key(1)]).is_empty());
        assert_eq!(
            verdict(&mut chain, L1Position::Unknown, &[key(1)]),
            [key(1)].into()
        );
    }

    #[test]
    fn an_inscription_more_than_depth_blocks_under_the_tip_is_found() {
        // Height 8 is 12 blocks under the tip, where the removal at 6 would be deep enough.
        let mut chain = Chain::new(20)
            .config_at(1, &[key(1), key(2)])
            .config_at(6, &[key(2)]);
        assert!(verdict(&mut chain, msg_at_height(8), &[key(1)]).is_empty());
    }

    #[test]
    fn an_inscription_not_above_its_parent_is_judged_at_the_tip() {
        let mut chain = Chain::new(10)
            .config_at(1, &[key(1), key(2)])
            .config_at(6, &[key(2)]);
        let unmined = L1Position::Msg {
            msg: msg(99),
            parent: msg(9),
        };
        assert_eq!(verdict(&mut chain, unmined, &[key(1)]), [key(1)].into());
        assert_eq!(
            chain.reads, 5,
            "the tip, the parent's block and three parents of the tip"
        );
    }

    #[test]
    fn reported_configs_need_no_read() {
        let mut chain = Chain::new(400).config_at(1, &[key(2)]);
        let mut index = reported_through(&chain, 800);
        assert_eq!(
            judge(&mut chain, &mut index, at_height(300), &[key(1)]).unwrap(),
            [key(1)].into()
        );
        assert_eq!(chain.reads, 4, "the anchor and three parents");
    }

    #[test]
    fn a_config_past_the_reported_slots_is_read_from_l1() {
        // The re-add at height 200 is final but not reported yet.
        let mut chain = Chain::new(400)
            .config_at(1, &[key(2)])
            .config_at(200, &[key(1), key(2)]);
        let mut index = reported_through(&chain, 300);
        assert!(
            judge(&mut chain, &mut index, at_height(250), &[key(1)])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_restart_reads_each_slot_once() {
        let mut chain = Chain::new(400).config_at(1, &[key(2)]);
        // The checkpoint was final through slot 600.
        let mut index = ConfigIndex::starting_at(601);
        let keys = [key(1)];

        assert_eq!(
            judge(&mut chain, &mut index, at_height(300), &keys).unwrap(),
            keys.into()
        );
        assert_eq!(
            chain.reads, 10,
            "the anchor, three parents and six scans down to the config"
        );

        chain.reads = 0;
        assert_eq!(
            judge(&mut chain, &mut index, at_height(250), &keys).unwrap(),
            keys.into()
        );
        assert_eq!(chain.reads, 4, "the anchor and three parents");
    }

    #[test]
    fn a_search_cut_short_resumes_where_it_stopped() {
        let mut chain = Chain::new(400).config_at(1, &[key(2)]);
        // The third scan down fails.
        chain.failing_read = Some(7);
        let mut index = ConfigIndex::starting_at(601);
        let keys = [key(1)];

        assert!(judge(&mut chain, &mut index, at_height(300), &keys).is_err());

        chain.reads = 0;
        assert_eq!(
            judge(&mut chain, &mut index, at_height(300), &keys).unwrap(),
            keys.into()
        );
        assert_eq!(
            chain.reads, 8,
            "the anchor, three parents and the four scans not made yet"
        );
    }

    #[test]
    fn nothing_is_read_for_no_keys() {
        let mut chain = Chain::new(10);
        assert!(verdict(&mut chain, at_height(8), &[]).is_empty());
        assert_eq!(chain.reads, 0);
    }
}
