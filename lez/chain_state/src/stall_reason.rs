use common::{HashType, block::BlockHeader};
use logos_blockchain_zone_sdk::sequencer::SequencerCheckpoint;
use serde::{Deserialize, Serialize};

use crate::ingest_error::BlockIngestError;

/// Diagnostic record of the first block that broke the L2 chain.
///
/// The block-derived fields are `None` for a deserialize break (no header was
/// ever parsed). `l1_slot` is the L1 slot the breaking inscription was read at.
/// `first_seen` is the breaking block's L2 timestamp (`None` for a deserialize break).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StallReason {
    pub block_id: Option<u64>,
    pub block_hash: Option<HashType>,
    pub prev_block_hash: Option<HashType>,
    pub checkpoint: SequencerCheckpoint,
    pub error: BlockIngestError,
    pub first_seen: Option<u64>,
    /// Number of later non-chaining blocks (orphans, since the tip is frozen).
    ///
    /// TODO: We could store a different "branch" of blocks following this break, but for now we
    /// just count them.
    pub orphans_since: u64,
}

impl StallReason {
    /// First stall for a break, built from the breaking block's header
    /// (`None` for a deserialize break).
    #[must_use]
    pub fn new(
        header: Option<&BlockHeader>,
        checkpoint: SequencerCheckpoint,
        error: BlockIngestError,
    ) -> Self {
        Self {
            block_id: header.map(|header| header.block_id),
            block_hash: header.map(|header| header.hash),
            prev_block_hash: header.map(|header| header.prev_block_hash),
            first_seen: header.map(|header| header.timestamp),
            checkpoint,
            error,
            orphans_since: 0,
        }
    }

    /// A later stall on the same break: bumps `orphans_since`, preserving the
    /// original cause.
    #[must_use]
    pub const fn escalate(mut self) -> Self {
        self.orphans_since = self.orphans_since.saturating_add(1);
        self
    }
}
