use common::HashType;
use serde::{Deserialize, Serialize};

use crate::ingest_error::BlockIngestError;

/// Diagnostic record of the first block that broke the L2 chain.
///
/// The block-derived fields are `None` for a deserialize break (no header was
/// ever parsed). `l1_slot` is the zone-sdk cursor position captured as JSON.
/// `first_seen` is the breaking block's L2 timestamp (`None` for a deserialize break).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StallReason {
    pub block_id: Option<u64>,
    pub block_hash: Option<HashType>,
    pub prev_block_hash: Option<HashType>,
    pub l1_slot: serde_json::Value,
    pub error: BlockIngestError,
    pub first_seen: Option<u64>,
    /// Number of later non-chaining blocks (orphans, since the tip is frozen).
    ///
    /// TODO: We could store a different "branch" of blocks following this sta
    pub orphans_since: u64,
}
