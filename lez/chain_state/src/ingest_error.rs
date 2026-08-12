use common::HashType;
use serde::{Deserialize, Serialize};

/// Why an L2 block from the channel could not be applied.
///
/// Persisted in `RocksDB` (as part of [`crate::StallReason`]), so every variant
/// must be `Clone + Serialize + Deserialize`.
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
    #[error("Block signature is not by the producer {producer} named in the header")]
    InvalidProducerSignature { producer: lee::PublicKey },
    #[error("Block has no transactions")]
    EmptyBlock,
    #[error("Last transaction must be the public clock invocation for the block timestamp")]
    InvalidClockTransaction,
    #[error("Genesis block must contain only public transactions")]
    NonPublicGenesisTransaction,
    #[error("Fee validity failed at transaction {tx_index}: {reason}")]
    FeeValidity {
        /// Index of the offending transaction within the block body.
        tx_index: u64,
        /// The `fee_core` (or reservation) rejection, rendered.
        reason: String,
    },
    #[error("Block exceeds a gas cap: {reason}")]
    GasCapExceeded {
        /// The `fee_core` cap rejection, rendered.
        reason: String,
    },
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

impl BlockIngestError {
    /// Whether the failure may be transient rather than a property of the block.
    ///
    /// FIXME: `StateTransition` is too coarse — its `reason` string mixes genuine
    /// state-transition rejections with infra failures (risc0 executor teardown,
    /// storage errors). Once it carries a structured cause, narrow this so only
    /// infra failures retry.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::StateTransition { .. })
    }
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

    #[test]
    fn invalid_producer_signature_round_trips() {
        // Stall reasons are persisted, so the producer key has to survive a
        // storage round trip.
        let producer = lee::PublicKey::new_from_private_key(
            &lee::PrivateKey::try_new([7_u8; 32]).expect("valid key"),
        );
        let err = BlockIngestError::InvalidProducerSignature {
            producer: producer.clone(),
        };
        let value = serde_json::to_value(&err).expect("serialize");
        let back: BlockIngestError = serde_json::from_value(value).expect("deserialize");
        let BlockIngestError::InvalidProducerSignature { producer: back } = back else {
            panic!("wrong variant");
        };
        assert_eq!(back, producer);
    }
}
