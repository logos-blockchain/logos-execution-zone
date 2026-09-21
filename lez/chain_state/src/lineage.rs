//! The unfinalized channel entries, as the sdk last reported them, and the
//! verdict the produce path reads off them.

use std::collections::HashMap;

use common::{HashType, block::Block};
use logos_blockchain_core::mantle::ops::channel::MsgId;

/// One channel entry: what it chains on, and the block it carries, if any.
///
/// The block is carried whole. An entry's bytes reach a node once, in the
/// update that reports it, so a header-only entry would leave the head knowing
/// a block belongs to it without being able to build it.
#[derive(Clone, Debug)]
pub struct LineageEntry {
    pub parent: MsgId,
    /// `None` for an entry carrying no block (garbage, an undecodable payload).
    pub block: Option<Block>,
}

/// Why the above-LIB chain could not be derived from the reported entries.
///
/// Soft by construction: every update re-derives from a fresh checkpoint, so a
/// failed derivation keeps the previous chain and is retried on the next one.
/// It never discards state and never blocks the finalized tier.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stale {
    /// The walk left the reported entries before reaching the finalized
    /// boundary: an entry on the chain is one this checkpoint does not carry.
    /// A peer's `Custom`-shaped inscription lands here, the genesis block
    /// included, because the sdk never mirrors those into its pending set.
    LineageGap { at: MsgId },
    /// The walk ran longer than the reported entries can account for, so they
    /// describe a cycle rather than a chain.
    Unbounded,
    /// The chain does not carry a block the head holds, and no orphan report
    /// says it left. A checkpoint older than the state it is applied to looks
    /// exactly like this, so believing it would silently drop finalized-bound
    /// work; the head is kept and the next update is tried instead.
    Regressed { dropped: HashType },
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

}
