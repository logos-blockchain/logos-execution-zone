//! The skip rule folded over a channel's L1-final entries by structure alone.

use common::block::DigestedBlock;
use logos_blockchain_core::mantle::ops::channel::MsgId;
use logos_blockchain_zone_sdk::{Slot, ZoneMessage};

use crate::{
    ChannelEntry, Tip,
    chain::{BlockRecord, Placed, Placement, Record, Status, cut, placement, window_passed},
    zone_indexer::Batch,
};

/// A channel's L1-final entries folded by the skip rule, every placed block taken as valid.
pub struct StructuralChain {
    skip_window: u64,
    settled: Option<Tip>,
    lib_slot: Slot,
    pin: MsgId,
    record: Record,
    blocks: Vec<(DigestedBlock, Slot)>,
}

/// What folding one [`Batch`] did.
pub struct BatchFold {
    /// The blocks it settled, in order.
    pub settled: Vec<(DigestedBlock, Slot)>,
    /// The last slot read whole: the batch's watermark, or the one before an undecodable block.
    pub read: Option<Slot>,
    /// The first block that did not decode, which ends the fold, at its slot.
    pub undecodable: Option<(Slot, std::io::Error)>,
    /// The blocks folded.
    pub blocks: usize,
}

impl StructuralChain {
    /// A fold of a channel whose skip window is `skip_window` slots, settled up to `settled`.
    #[must_use]
    pub fn new(skip_window: u32, settled: Option<Tip>) -> Self {
        Self {
            skip_window: u64::from(skip_window),
            settled,
            lib_slot: Slot::from(0),
            pin: MsgId::root(),
            record: Record::default(),
            blocks: Vec::new(),
        }
    }

    /// Folds `entries`, the channel read through `lib_slot`; returns newly settled blocks in order.
    pub fn apply_finalized(
        &mut self,
        entries: &[ChannelEntry],
        lib_slot: Slot,
    ) -> Vec<(DigestedBlock, Slot)> {
        self.lib_slot = lib_slot.max(self.lib_slot);
        for entry in entries {
            self.fold(entry);
        }
        self.settle()
    }

    /// Folds `batch`'s blocks up to the first that does not decode, the slots before it read whole.
    pub fn apply_batch(&mut self, batch: Batch) -> BatchFold {
        let mut entries: Vec<ChannelEntry> = Vec::new();
        let mut undecodable = None;
        for (msg, slot) in batch.messages {
            let ZoneMessage::Block(zone_block) = msg else {
                continue;
            };
            match DigestedBlock::from_inscription(&zone_block.data) {
                Ok(block) => entries.push(ChannelEntry {
                    msg: zone_block.id,
                    parent: entries.last().map_or(self.pin, |prev| prev.msg),
                    signer: Some(zone_block.signer.to_bytes()),
                    slot: Some(slot),
                    block: Some(block),
                }),
                Err(err) => {
                    undecodable = Some((slot, err));
                    break;
                }
            }
        }
        let read = undecodable
            .as_ref()
            .map_or(Some(batch.watermark), |(slot, _)| {
                slot.checked_sub(Slot::from(1))
            });
        BatchFold {
            settled: self.apply_finalized(&entries, read.unwrap_or_else(Slot::genesis)),
            read,
            undecodable,
            blocks: entries.len(),
        }
    }

    #[must_use]
    pub fn settled_tip(&self) -> Option<Tip> {
        self.settled.clone()
    }

    /// The slot of the oldest unsettled entry, which a rebuild from the settled tip re-reads.
    #[must_use]
    pub fn reread_from(&self) -> Option<Slot> {
        self.blocks.first().map(|&(_, slot)| slot)
    }

    /// The message the next entry chains on: the last one folded.
    #[must_use]
    pub const fn pin(&self) -> MsgId {
        self.pin
    }

    fn fold(&mut self, entry: &ChannelEntry) {
        self.pin = entry.msg;
        let (Some(block), Some(slot)) = (&entry.block, entry.slot) else {
            return;
        };
        if block.recompute_hash() != block.header.hash {
            return;
        }
        let (delta, lib) = (self.skip_window, self.lib_slot);
        let passed = |start| window_passed(start, delta, entry.slot, lib);
        match placement(&self.record, self.settled.as_ref(), entry, block, passed) {
            Placement::Extends => self.place(entry, block, slot),
            Placement::Skips(at) => {
                cut(&mut self.record, at);
                self.blocks.truncate(at);
                self.place(entry, block, slot);
            }
            Placement::Late | Placement::Misplaced(_) | Placement::Ignored => {}
        }
        self.record.prune_run(self.settled.as_ref(), passed);
    }

    fn place(&mut self, entry: &ChannelEntry, block: &DigestedBlock, slot: Slot) {
        self.record.confirm(entry.signer);
        let placed = BlockRecord::new(entry, block);
        self.record.run.push(placed.clone());
        self.record.branch.push(Placed {
            entry: entry.msg,
            block: placed,
            status: Status::Executed,
            confirmed: false,
        });
        self.blocks.push((block.clone(), slot));
    }

    fn settle(&mut self) -> Vec<(DigestedBlock, Slot)> {
        let (delta, lib) = (self.skip_window, self.lib_slot);
        let settling = self
            .record
            .branch
            .iter()
            .take_while(|placed| {
                !placed.block.private
                    || placed.confirmed
                    || window_passed(placed.block.slot, delta, None, lib)
            })
            .count();
        if let Some(last) = settling.checked_sub(1) {
            self.settled = Some(self.record.branch[last].tip());
        }
        self.record.branch.drain(..settling);
        self.blocks.drain(..settling).collect()
    }
}

#[cfg(test)]
mod tests {
    use common::{
        HashType,
        block::{Block, HashableBlockData},
        test_utils::{produce_dummy_block, produce_dummy_empty_transaction},
        transaction::LeeTransaction,
    };
    use lee::{
        PrivacyPreservingTransaction, V03State,
        privacy_preserving_transaction::{Message, WitnessSet, circuit::Proof},
    };

    use super::*;
    use crate::{BlockIngestError, apply_block, test_utils::lineage};

    const SKIP_WINDOW: u32 = 10;
    const WRITER: [u8; 32] = [1; 32];
    const OTHER: [u8; 32] = [2; 32];

    fn genesis() -> Block {
        produce_dummy_block(1, None, vec![])
    }

    fn private_on(genesis: &Block) -> Block {
        produce_dummy_block(
            2,
            Some(genesis.header.hash),
            vec![LeeTransaction::PrivacyPreserving(
                PrivacyPreservingTransaction::new(
                    Message::default(),
                    WitnessSet::from_raw_parts(vec![], Proof::from_inner(vec![7; 32])),
                ),
            )],
        )
    }

    fn plain_on(genesis: &Block) -> Block {
        produce_dummy_block(
            2,
            Some(genesis.header.hash),
            vec![produce_dummy_empty_transaction()],
        )
    }

    fn skip_of(genesis: &Block) -> Block {
        produce_dummy_block(2, Some(genesis.header.hash), vec![])
    }

    fn hashes(settled: &[(DigestedBlock, Slot)]) -> Vec<HashType> {
        settled.iter().map(|(block, _)| block.header.hash).collect()
    }

    #[test]
    fn a_skip_cuts_only_a_private_block_within_its_window_and_for_good() {
        let genesis = genesis();
        let (private, plain, skip) = (private_on(&genesis), plain_on(&genesis), skip_of(&genesis));
        let late = u64::from(2 + SKIP_WINDOW + 1);
        for (target, slot, kept) in [
            (&private, 3, &skip),
            (&private, late, &private),
            (&plain, 3, &plain),
        ] {
            let mut chain = StructuralChain::new(SKIP_WINDOW, None);

            let settled = chain.apply_finalized(
                &lineage(&[
                    (&genesis, WRITER, 1),
                    (target, WRITER, 2),
                    (&skip, OTHER, slot),
                ]),
                Slot::from(slot),
            );

            assert_eq!(
                hashes(&settled),
                vec![genesis.header.hash, kept.header.hash]
            );
            assert!(chain.apply_finalized(&[], Slot::from(100)).is_empty());
            assert_eq!(chain.settled_tip(), Some(Tip::from(kept)));
        }
    }

    #[test]
    fn a_private_block_settles_once_another_signer_builds_on_it() {
        let genesis = genesis();
        let private = private_on(&genesis);
        let on_private = produce_dummy_block(3, Some(private.header.hash), vec![]);
        let all = lineage(&[
            (&genesis, WRITER, 1),
            (&private, WRITER, 2),
            (&on_private, OTHER, 3),
        ]);
        let mut chain = StructuralChain::new(SKIP_WINDOW, None);

        assert_eq!(
            hashes(&chain.apply_finalized(&all[..2], Slot::from(2))),
            vec![genesis.header.hash]
        );
        assert_eq!(
            hashes(&chain.apply_finalized(&all[2..], Slot::from(3))),
            vec![private.header.hash, on_private.header.hash]
        );
    }

    #[test]
    fn a_block_whose_hash_does_not_match_its_contents_is_dropped() {
        let genesis = genesis();
        let plain = plain_on(&genesis);
        let mut tampered = plain.clone();
        tampered.header.hash = HashType([9; 32]);
        let mut chain = StructuralChain::new(SKIP_WINDOW, None);

        let settled = chain.apply_finalized(
            &lineage(&[
                (&genesis, WRITER, 1),
                (&tampered, WRITER, 2),
                (&plain, WRITER, 3),
            ]),
            Slot::from(3),
        );

        assert_eq!(
            hashes(&settled),
            vec![genesis.header.hash, plain.header.hash]
        );
    }

    #[test]
    fn a_private_block_that_would_fail_execution_is_taken_as_valid_and_settles_by_timeout() {
        let genesis = genesis();
        let mut without_clock_tail = HashableBlockData::from(private_on(&genesis));
        without_clock_tail.transactions.pop();
        let failing = without_clock_tail.into_pending_block();
        assert!(matches!(
            apply_block(Some(&Tip::from(&genesis)), &failing, &mut V03State::new()),
            Err(BlockIngestError::InvalidClockTransaction)
        ));
        let mut chain = StructuralChain::new(SKIP_WINDOW, None);

        chain.apply_finalized(
            &lineage(&[(&genesis, WRITER, 1), (&failing, WRITER, 2)]),
            Slot::from(2),
        );

        assert!(
            chain
                .apply_finalized(&[], Slot::from(u64::from(1 + SKIP_WINDOW)))
                .is_empty()
        );
        assert_eq!(
            hashes(&chain.apply_finalized(&[], Slot::from(u64::from(2 + SKIP_WINDOW)))),
            vec![failing.header.hash]
        );
    }
}
