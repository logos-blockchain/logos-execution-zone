use serde::Serialize;

use crate::stall_reason::StallReason;

/// Coarse lifecycle state of the indexer's ingestion loop, so a client can tell
/// "still catching up" apart from "something went wrong".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum IndexerSyncState {
    /// Booted; no ingestion cycle has run yet.
    Starting,
    /// Streaming finalized messages toward the L1 frontier.
    Syncing,
    /// Drained the stream up to LIB; idle until new blocks finalize.
    CaughtUp,
    /// The last cycle failed (e.g. the L1 node is unreachable). See `last_error`.
    Error,
    /// Parked on a stall reason: the validated tip is frozen awaiting a valid
    /// continuation. See `last_error` and the snapshot's `stall_reason`.
    Stalled,
}

/// Live ingestion status owned by the ingest loop: the coarse `state` plus the
/// reason when it is `Error`.
#[derive(Debug, Clone, Serialize)]
pub struct IndexerSyncStatus {
    pub state: IndexerSyncState,
    pub last_error: Option<String>,
}

impl IndexerSyncStatus {
    /// Initial status before any ingestion cycle has run.
    pub(crate) const fn starting() -> Self {
        Self {
            state: IndexerSyncState::Starting,
            last_error: None,
        }
    }

    /// Actively streaming finalized messages toward the L1 frontier.
    pub(crate) const fn syncing() -> Self {
        Self {
            state: IndexerSyncState::Syncing,
            last_error: None,
        }
    }

    /// Drained the stream up to LIB; idle until new blocks finalize.
    pub(crate) const fn caught_up() -> Self {
        Self {
            state: IndexerSyncState::CaughtUp,
            last_error: None,
        }
    }

    /// The last cycle failed; `reason` explains why.
    pub(crate) const fn error(reason: String) -> Self {
        Self {
            state: IndexerSyncState::Error,
            last_error: Some(reason),
        }
    }

    /// Parked on a stall reason; `reason` mirrors the stall's error message.
    /// The full stall is attached to the [`IndexerStatus`] snapshot.
    pub(crate) const fn stalled(reason: String) -> Self {
        Self {
            state: IndexerSyncState::Stalled,
            last_error: Some(reason),
        }
    }
}

/// Full status snapshot returned to callers (FFI/RPC): the live [`IndexerSyncStatus`]
/// plus the L2 tip (`indexed_block_id`) read fresh from the store at query time.
///
/// The tip is tracked by the store, not the ingest loop, so it lives here on the
/// returned snapshot rather than inside the shared [`IndexerSyncStatus`].
#[derive(Debug, Clone, Serialize)]
pub struct IndexerStatus {
    #[serde(flatten)]
    pub sync: IndexerSyncStatus,
    pub indexed_block_id: Option<u64>,
    pub stall_reason: Option<StallReason>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexer_status_serializes_to_flat_object() {
        let status = IndexerStatus {
            sync: IndexerSyncStatus::error("boom".to_owned()),
            indexed_block_id: Some(7),
            stall_reason: None,
        };
        let value = serde_json::to_value(&status).expect("serialize");
        assert_eq!(
            value,
            serde_json::json!({
                "state": "Error",
                "last_error": "boom",
                "indexed_block_id": 7,
                "stall_reason": null,
            })
        );
    }

    #[test]
    fn caught_up_clears_error() {
        let value = serde_json::to_value(IndexerSyncStatus::caught_up()).expect("serialize");
        assert_eq!(
            value,
            serde_json::json!({ "state": "CaughtUp", "last_error": null })
        );
    }

    #[test]
    fn stalled_status_serializes_with_stall_reason() {
        use logos_blockchain_zone_sdk::Slot;

        use crate::{ingest_error::BlockIngestError, stall_reason::StallReason};

        let status = IndexerStatus {
            sync: IndexerSyncStatus::stalled("broken chain link".to_owned()),
            indexed_block_id: Some(41),
            stall_reason: Some(StallReason {
                block_id: Some(42),
                block_hash: None,
                prev_block_hash: None,
                l1_slot: Slot::from(0),
                error: BlockIngestError::StateTransition("boom".to_owned()),
                first_seen: None,
                orphans_since: 2,
            }),
        };
        let value = serde_json::to_value(&status).expect("serialize");
        assert_eq!(value["state"], serde_json::json!("Stalled"));
        assert_eq!(value["last_error"], serde_json::json!("broken chain link"));
        assert_eq!(value["indexed_block_id"], serde_json::json!(41));
        assert_eq!(value["stall_reason"]["orphans_since"], serde_json::json!(2));
    }
}
