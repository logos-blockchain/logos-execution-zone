use common::HashType;
use serde::{Deserialize, Serialize};

/// Why the indexer could not apply an L2 block from the channel.
///
/// Persisted in `RocksDB`, so every variant must have the following
/// traits: `Clone + Serialize + Deserialize`.
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum BlockIngestError {
    #[error("Failed to deserialize L2 block: {0}")]
    /// Here we store the error string that is derived from [`borsh::from_slice`]'s [`Err`].
    Deserialize(String),
    #[error("Unexpected block id: expected {expected}, got {got}")]
    UnexpectedBlockId { expected: u64, got: u64 },
    #[error("Broken chain link: expected prev {expected_prev}, got {got_prev}")]
    BrokenChainLink {
        expected_prev: HashType,
        got_prev: HashType,
    },
    #[error("Block hash mismatch: computed {computed}, header {header}")]
    HashMismatch {
        computed: HashType,
        header: HashType,
    },
    #[error("Block has no transactions")]
    EmptyBlock,
    #[error("Last transaction must be the public clock invocation for the block timestamp")]
    InvalidClockTransaction,
    #[error("Genesis block must contain only public transactions")]
    NonPublicGenesisTransaction,
    #[error("State transition failed at transaction {tx_index}: {reason}")]
    StateTransition {
        /// Index of the failing transaction within the block body.
        tx_index: u64,
        /// Reason string from `lee::Error` to `anyhow::Error` to `{:#}`.
        ///
        /// This is required because `lee::Error` is not `Clone + Serialize + Deserialize`, so we
        /// cannot store it directly.
        reason: String,
    },
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
            serde_json::json!({ "UnexpectedBlockId": { "expected": 5, "got": 7 } })
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
}
