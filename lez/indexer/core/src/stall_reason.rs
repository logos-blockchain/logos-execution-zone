use common::HashType;
use logos_blockchain_zone_sdk::Slot;
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
    pub l1_slot: Slot,
    pub error: BlockIngestError,
    pub first_seen: Option<u64>,
    /// Number of later non-chaining blocks (orphans, since the tip is frozen).
    ///
    /// TODO: We could store a different "branch" of blocks following this break, but for now we
    /// just count them.
    pub orphans_since: u64,
}
