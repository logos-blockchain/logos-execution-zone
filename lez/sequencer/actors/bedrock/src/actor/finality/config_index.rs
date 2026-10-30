//! The channel's final configs, as zone-sdk reports them, with the slots it has not reported read
//! from L1.

use std::{collections::BTreeMap, ops::Range};

use super::L1Reader;
use crate::Result;

/// Slots one read of final blocks spans while looking for a config outside the covered range.
const CONFIG_SCAN_SLOTS: u64 = 100;

/// The channel's configs in an unbroken range of final slots.
#[derive(Clone, Debug)]
pub struct ConfigIndex {
    /// The final slots whose configs are all in `configs`.
    covered: Range<u64>,
    /// The key list of the last config in each final block holding one, by slot.
    config_keys: BTreeMap<u64, Vec<[u8; 32]>>,
}

impl ConfigIndex {
    /// An index covering no slot, whose first covered slot will be `slot`.
    #[must_use]
    pub const fn starting_at(slot: u64) -> Self {
        Self {
            covered: slot..slot,
            config_keys: BTreeMap::new(),
        }
    }

    /// Adds the configs zone-sdk reported final, as slot and key list in chain order, in the slots
    /// after the covered ones through `lib_slot`.
    pub fn extend_final(
        &mut self,
        config_keys: impl IntoIterator<Item = (u64, Vec<[u8; 32]>)>,
        lib_slot: u64,
    ) {
        self.config_keys.extend(config_keys);
        self.covered.end = self.covered.end.max(lib_slot.saturating_add(1));
    }

    /// The key list of the latest config at or below the final slot `slot`.
    ///
    /// Slots outside the covered range are read from L1 next to it, each once.
    pub async fn config_keys_in_effect<R: L1Reader>(
        &mut self,
        reader: &mut R,
        slot: u64,
    ) -> Result<Option<Vec<[u8; 32]>>> {
        let span = CONFIG_SCAN_SLOTS.saturating_sub(1);
        loop {
            let covered = self.covered.clone();
            if slot >= covered.end {
                let to = covered.end.saturating_add(span).min(slot);
                self.read(reader, covered.end, to).await?;
            } else if slot >= covered.start
                && let Some((_, keys)) = self.config_keys.range(covered.start..=slot).next_back()
            {
                return Ok(Some(keys.clone()));
            } else if let Some(to) = covered.start.checked_sub(1) {
                self.read(reader, to.saturating_sub(span), to).await?;
            } else {
                return Ok(None);
            }
        }
    }

    /// Reads the final blocks in `from..=to`, next to the covered slots, into the index.
    async fn read<R: L1Reader>(&mut self, reader: &mut R, from: u64, to: u64) -> Result<()> {
        for block_summary in reader.final_block_summaries(from, to).await? {
            if let Some(keys) = block_summary.config_keys.last() {
                self.config_keys.insert(block_summary.slot, keys.clone());
            }
        }
        self.covered = self.covered.start.min(from)..self.covered.end.max(to.saturating_add(1));
        Ok(())
    }
}
