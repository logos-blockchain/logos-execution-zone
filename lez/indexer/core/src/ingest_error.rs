use common::HashType;
use serde::{Deserialize, Serialize};

/// Why the indexer could not apply an L2 block from the channel. Stored inside a
/// [`crate::stall_reason::StallReason`] and surfaced on the status snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "camelCase")]
pub enum BlockIngestError {
    #[error("failed to deserialize L2 block: {0}")]
    Deserialize(String),
    #[error("unexpected block id: expected {expected}, got {got}")]
    UnexpectedBlockId { expected: u64, got: u64 },
    #[error("broken chain link: expected prev {expected_prev}, got {got_prev}")]
    BrokenChainLink {
        expected_prev: HashType,
        got_prev: HashType,
    },
    #[error("block hash mismatch: computed {computed}, header {header}")]
    HashMismatch {
        computed: HashType,
        header: HashType,
    },
    #[error("state transition failed: {0}")]
    StateTransition(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_and_round_trips_externally_tagged() {
        let err = BlockIngestError::UnexpectedBlockId {
            expected: 5,
            got: 7,
        };
        let value = serde_json::to_value(&err).expect("serialize");
        assert_eq!(
            value,
            serde_json::json!({ "unexpectedBlockId": { "expected": 5, "got": 7 } })
        );
        let back: BlockIngestError = serde_json::from_value(value).expect("deserialize");
        assert!(matches!(
            back,
            BlockIngestError::UnexpectedBlockId {
                expected: 5,
                got: 7
            }
        ));
    }

    #[test]
    fn display_is_human_readable() {
        let err = BlockIngestError::StateTransition("nonce too low".to_owned());
        assert_eq!(err.to_string(), "state transition failed: nonce too low");
    }
}
