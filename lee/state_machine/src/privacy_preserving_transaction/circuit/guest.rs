//! STF prototype: the guest's view of a privacy-preserving proof, checked by composition.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{ProvenExecution, execution_state::PublicExecutionContext};
use risc0_zkvm::guest::env;

use crate::PRIVACY_PRESERVING_CIRCUIT_ID;

/// Proof of the privacy preserving execution circuit.
#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Proof(pub(crate) Vec<u8>);

impl std::fmt::Debug for Proof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[proof redacted for brevity ({} bytes)]", self.0.len())
    }
}

impl Proof {
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    #[must_use]
    pub const fn size(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub const fn from_inner(inner: Vec<u8>) -> Self {
        Self(inner)
    }

    /// The host supplies the receipt as an assumption; the seal bytes are not read here.
    pub(crate) fn is_valid_for(
        &self,
        public_context: &PublicExecutionContext,
        execution: &ProvenExecution,
    ) -> bool {
        env::verify(
            PRIVACY_PRESERVING_CIRCUIT_ID,
            &lee_core::to_borsh_frame(&(public_context, execution)),
        )
        .is_ok()
    }
}
