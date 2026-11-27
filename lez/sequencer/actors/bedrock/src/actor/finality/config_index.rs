//! The channel's final configs, as zone-sdk reports them, with the slots it has not reported read
//! from L1.

use std::{collections::BTreeMap, io, ops::Range};

use borsh::BorshDeserialize;

use super::L1Reader;
use crate::Result;

/// Slots one read of final blocks spans while looking for a config outside the covered range.
const CONFIG_SCAN_SLOTS: u64 = 100;

/// Slots one read spans past its first.
const SCAN_SPAN: u64 = CONFIG_SCAN_SLOTS.saturating_sub(1);

/// Covered final slots an index gains before [`ConfigIndex::due_to_store`] returns `true` again.
const STORE_SLOTS: u64 = 1000;

/// The channel's configs in an unbroken range of final slots.
#[derive(Clone, Debug, borsh::BorshSerialize)]
pub struct ConfigIndex {
    /// The final slots whose configs are all in `config_keys`.
    covered: Range<u64>,
    /// The key list of the last config in each final block holding one, by slot.
    config_keys: BTreeMap<u64, Vec<[u8; 32]>>,
    /// The covered slots and config count when [`Self::due_to_store`] last returned `true`, or
    /// when the index was read back.
    #[borsh(skip)]
    stored: (Range<u64>, usize),
}

impl ConfigIndex {
    /// An index covering no slot, whose first covered slot will be `slot`.
    #[must_use]
    pub const fn starting_at(slot: u64) -> Self {
        Self {
            covered: slot..slot,
            config_keys: BTreeMap::new(),
            stored: (slot..slot, 0),
        }
    }

    /// Whether the index starts lower, holds other configs, or covers [`STORE_SLOTS`] more slots
    /// than when this last returned `true`.
    pub fn due_to_store(&mut self) -> bool {
        let (stored_covered, stored_configs) = &self.stored;
        let due = self.covered.start < stored_covered.start
            || self.config_keys.len() != *stored_configs
            || self.covered.end >= stored_covered.end.saturating_add(STORE_SLOTS);
        if due {
            self.stored = (self.covered.clone(), self.config_keys.len());
        }
        due
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
        self.cover_through(reader, slot).await?;
        loop {
            let covered = self.covered.clone();
            if slot >= covered.start
                && let Some((_, keys)) = self.config_keys.range(covered.start..=slot).next_back()
            {
                return Ok(Some(keys.clone()));
            } else if let Some(to) = covered.start.checked_sub(1) {
                self.read(reader, to.saturating_sub(SCAN_SPAN), to).await?;
            } else {
                return Ok(None);
            }
        }
    }

    /// Reads from L1 the final slots after the covered ones through `slot`.
    pub async fn cover_through<R: L1Reader>(&mut self, reader: &mut R, slot: u64) -> Result<()> {
        while slot >= self.covered.end {
            let from = self.covered.end;
            let to = from.saturating_add(SCAN_SPAN).min(slot);
            self.read(reader, from, to).await?;
        }
        Ok(())
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

/// Read back as stored, so it is not due to store again right away.
impl BorshDeserialize for ConfigIndex {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let covered = Range::<u64>::deserialize_reader(reader)?;
        let config_keys = BTreeMap::deserialize_reader(reader)?;
        let stored = (covered.clone(), BTreeMap::len(&config_keys));
        Ok(Self {
            covered,
            config_keys,
            stored,
        })
    }
}
