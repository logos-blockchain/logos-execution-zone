use std::fmt::{self, Display, Formatter};

use chain_state::StallReason;
use common::HashType;
use serde::{Deserialize, Serialize};

/// Durable record of a cross-zone verification halt.
///
/// Carries the local block whose dispatch failed re-derivation, the dispatch's
/// source coordinates, and the verdict. Persisted so a restart reports
/// [`IndexerSyncState::Halted`] with the original reason instead of silently
/// re-deriving the same halt. Cleared only when the recorded block applies
/// (verified or operator accept-listed), when a block applies at the recorded
/// id under a different hash, or when the store is reset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossZoneHalt {
    /// The local block whose dispatch failed.
    pub block_id: u64,
    pub block_hash: HashType,
    /// Hex id of the dispatch's source zone.
    pub src_zone: String,
    pub src_block_id: u64,
    pub src_tx_index: u32,
    pub verdict: String,
}

impl Display for CrossZoneHalt {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cross-zone verification failed at block {} ({}): dispatch from zone {} block {} tx {}: {}",
            self.block_id,
            self.block_hash,
            self.src_zone,
            self.src_block_id,
            self.src_tx_index,
            self.verdict
        )
    }
}

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
    /// Ingestion ended on a cross-zone verdict. See `last_error` and the
    /// snapshot's `cross_zone_halt`.
    Halted,
}

/// Coarse health of one peer-zone reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PeerHealth {
    /// The last pass drained with no stall and the cursor at the channel tip.
    Live,
    /// No caught-up evidence yet.
    Lagging,
    /// Stuck on a slot it cannot read.
    Holed,
    /// The peer's live committee is below the configured floor; reading is
    /// suspended until it recovers.
    Suspended,
    /// A verified-absence verdict was issued against this peer's chain.
    Halted,
}

/// One peer reader's snapshot: how far the peer chain is verified, where the
/// read cursor is, and a coarse health classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerStatus {
    /// Hex id of the peer zone.
    pub zone: String,
    pub verified_tip_block_id: Option<u64>,
    pub cursor_slot: Option<u64>,
    pub stuck_slot_attempts: u32,
    pub health: PeerHealth,
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

    /// Ingestion ended on a cross-zone verdict; `reason` mirrors the halt
    /// record attached to the [`IndexerStatus`] snapshot.
    pub(crate) const fn halted(reason: String) -> Self {
        Self {
            state: IndexerSyncState::Halted,
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
    /// Present while ingestion is halted on a cross-zone verdict.
    pub cross_zone_halt: Option<CrossZoneHalt>,
    /// One snapshot per configured peer zone; empty with cross-zone disabled.
    pub cross_zone_peers: Vec<PeerStatus>,
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
            cross_zone_halt: None,
            cross_zone_peers: Vec::new(),
        };
        let value = serde_json::to_value(&status).expect("serialize");
        assert_eq!(
            value,
            serde_json::json!({
                "state": "Error",
                "last_error": "boom",
                "indexed_block_id": 7,
                "stall_reason": null,
                "cross_zone_halt": null,
                "cross_zone_peers": [],
            })
        );
    }

    #[test]
    fn cross_zone_halt_round_trips_through_json() {
        let halt = CrossZoneHalt {
            block_id: 9,
            block_hash: HashType([0xAB; 32]),
            src_zone: hex::encode([2_u8; 32]),
            src_block_id: 5,
            src_tx_index: 1,
            verdict: "re-derivation mismatch".to_owned(),
        };
        let bytes = serde_json::to_vec(&halt).expect("serialize");
        let back: CrossZoneHalt = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(back, halt);
    }

    #[test]
    fn halted_status_carries_the_halt_record() {
        let halt = CrossZoneHalt {
            block_id: 9,
            block_hash: HashType([0xAB; 32]),
            src_zone: hex::encode([2_u8; 32]),
            src_block_id: 5,
            src_tx_index: 1,
            verdict: "re-derivation mismatch".to_owned(),
        };
        let status = IndexerStatus {
            sync: IndexerSyncStatus::halted(halt.to_string()),
            indexed_block_id: Some(8),
            stall_reason: None,
            cross_zone_halt: Some(halt),
            cross_zone_peers: vec![PeerStatus {
                zone: hex::encode([2_u8; 32]),
                verified_tip_block_id: Some(4),
                cursor_slot: Some(70),
                stuck_slot_attempts: 0,
                health: PeerHealth::Live,
            }],
        };
        let value = serde_json::to_value(&status).expect("serialize");
        assert_eq!(value["state"], serde_json::json!("Halted"));
        assert_eq!(value["cross_zone_halt"]["block_id"], serde_json::json!(9));
        assert_eq!(
            value["cross_zone_peers"][0]["health"],
            serde_json::json!("Live")
        );
    }

    /// The status string a suspended peer shows, the one clients key on.
    #[test]
    fn a_suspended_peer_serializes_as_suspended() {
        let status = PeerStatus {
            zone: hex::encode([2_u8; 32]),
            verified_tip_block_id: Some(4),
            cursor_slot: Some(70),
            stuck_slot_attempts: 0,
            health: PeerHealth::Suspended,
        };
        let value = serde_json::to_value(&status).expect("serialize");
        assert_eq!(value["health"], serde_json::json!("Suspended"));
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
        use chain_state::{BlockIngestError, StallReason};
        use logos_blockchain_zone_sdk::Slot;

        let status = IndexerStatus {
            sync: IndexerSyncStatus::stalled("broken chain link".to_owned()),
            indexed_block_id: Some(41),
            stall_reason: Some(StallReason {
                block_id: Some(42),
                block_hash: None,
                prev_block_hash: None,
                l1_slot: Slot::from(0),
                error: BlockIngestError::StateTransition {
                    tx_index: 0,
                    reason: String::default(),
                },
                first_seen: None,
                orphans_since: 2,
            }),
            cross_zone_halt: None,
            cross_zone_peers: Vec::new(),
        };
        let value = serde_json::to_value(&status).expect("serialize");
        assert_eq!(value["state"], serde_json::json!("Stalled"));
        assert_eq!(value["last_error"], serde_json::json!("broken chain link"));
        assert_eq!(value["indexed_block_id"], serde_json::json!(41));
        assert_eq!(value["stall_reason"]["orphans_since"], serde_json::json!(2));
    }
}
