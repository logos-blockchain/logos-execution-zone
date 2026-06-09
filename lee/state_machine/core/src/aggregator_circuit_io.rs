use serde::{Deserialize, Serialize};

use crate::{BlockId, PrivacyPreservingCircuitOutput, Timestamp, program::ProgramId};

/// Input to the aggregator circuit.
#[derive(Serialize, Deserialize)]
pub struct AggregatorCircuitInput {
    /// Image ID of the privacy-preserving circuit. Passed as a runtime value so the
    /// guest does not need a compile-time dependency on the image ID.
    pub privacy_preserving_circuit_id: ProgramId,
    pub block_id: BlockId,
    pub timestamp: Timestamp,
    pub circuit_outputs: Vec<PrivacyPreservingCircuitOutput>,
}

/// Output committed to the journal by the aggregator circuit.
///
/// Preserves the full `PrivacyPreservingCircuitOutput` for each transaction so observers
/// can perform state-dependent checks (nonces, commitment freshness, nullifier uniqueness)
/// independently. Only the individual proofs are dropped.
#[derive(Serialize, Deserialize)]
#[cfg_attr(any(feature = "host", test), derive(Debug, PartialEq, Eq))]
pub struct AggregatorCircuitOutput {
    pub block_id: BlockId,
    pub timestamp: Timestamp,
    pub circuit_outputs: Vec<PrivacyPreservingCircuitOutput>,
}

#[cfg(feature = "host")]
impl AggregatorCircuitOutput {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        bytemuck::cast_slice(&risc0_zkvm::serde::to_vec(self).unwrap()).to_vec()
    }
}
