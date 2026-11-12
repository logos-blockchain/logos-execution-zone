//! Storage-free chain-state core shared by the LEZ sequencer and indexer:
//! the [`apply_block`] entry point plus [`BlockIngestError`], [`StallReason`]
//! and [`Tip`]. See [`ChainState`] for the two-tier model.

pub use apply::{Tip, apply_block, apply_block_to_state, validate_against_tip};
pub use chain::{Blocker, ChainState, ChannelEntry, Judged, PublishRecord, Verdict};
pub use consistency::{
    Anchor, AnchorConsistencyCheck, ChainConsistency, ChainMismatch, verify_chain_consistency,
};
pub use ingest_error::BlockIngestError;
pub use proof_store::ProofStore;
pub use stall_reason::StallReason;
pub use structural::StructuralChain;

pub mod apply;
pub mod chain;
pub mod classify;
pub mod consistency;
pub mod ingest_error;
pub mod proof_store;
pub mod stake_config;
pub mod stall_reason;
pub mod structural;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
pub mod timeout_node;
pub mod zone_indexer;
