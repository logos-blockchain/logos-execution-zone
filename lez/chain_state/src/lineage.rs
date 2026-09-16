//! The unfinalized channel entries, as the sdk last reported them, and the
//! verdict the produce path reads off them.

use std::collections::HashMap;

use common::HashType;
use logos_blockchain_core::mantle::ops::channel::MsgId;

/// The block an entry inscribes, as far as its header goes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InscribedBlock {
    pub block_id: u64,
    pub hash: HashType,
    pub prev_hash: HashType,
}

/// One channel entry: what it chains on, and the block it carries, if any.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LineageEntry {
    pub parent: MsgId,
    /// `None` for an entry carrying no block (garbage, an undecodable payload).
    pub block: Option<InscribedBlock>,
}

/// Why a production turn may not publish.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PublishVerdict {
    /// The pin chains back to the head with no block in between.
    Allowed,
    /// A block the head does not hold sits between the head and the pin.
    HeadTrailsPin { block_id: u64 },
    /// The walk ran out of entries before reaching the head.
    LineageGap,
}

/// The unfinalized channel entries keyed by their own id. Empty means the sdk
/// reported none, which is also the state before the first update of a run.
#[derive(Clone, Default, Debug)]
pub struct ChannelLineage(HashMap<MsgId, LineageEntry>);

impl ChannelLineage {
    #[must_use]
    pub const fn new(entries: HashMap<MsgId, LineageEntry>) -> Self {
        Self(entries)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn get(&self, msg: &MsgId) -> Option<&LineageEntry> {
        self.0.get(msg)
    }

    /// The entry carrying this exact block, if the sdk still reports it.
    #[must_use]
    pub fn entry_carrying(&self, block_id: u64, hash: HashType) -> Option<MsgId> {
        self.0
            .iter()
            .find(|(_, entry)| {
                entry
                    .block
                    .is_some_and(|block| block.block_id == block_id && block.hash == hash)
            })
            .map(|(msg, _)| *msg)
    }

    /// Adds an entry of our own, so the walk reaches it before the next
    /// snapshot arrives.
    pub fn insert(&mut self, msg: MsgId, entry: LineageEntry) {
        self.0.insert(msg, entry);
    }
}
