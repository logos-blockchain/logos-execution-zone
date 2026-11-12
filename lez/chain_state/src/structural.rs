//! The skip rule folded over a channel's L1-final entries by structure alone.

use common::block::DigestedBlock;
use logos_blockchain_core::mantle::ops::channel::MsgId;
use logos_blockchain_zone_sdk::Slot;

use crate::{
    ChannelEntry, Tip,
    chain::{BlockRecord, Placed, Placement, Record, Status, cut, placement, window_passed},
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
