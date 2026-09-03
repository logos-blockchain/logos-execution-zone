//! Storage-free chain-state core shared by the LEZ sequencer and indexer:
//! the [`apply_block`] entry point plus [`BlockIngestError`], [`StallReason`],
//! [`Tip`], and [`AcceptOutcome`]. See [`ChainState`] for the two-tier model.

pub use apply::{AcceptOutcome, Tip, apply_block, apply_block_to_state, validate_against_tip};
pub use chain::{ChainState, FollowOutcome};
pub use consistency::{
    Anchor, AnchorConsistencyCheck, ChainConsistency, ChainMismatch, verify_chain_consistency,
};
pub use ingest_error::BlockIngestError;
pub use stall_reason::StallReason;

pub mod apply;
pub mod chain;
pub mod classify;
pub mod consistency;
pub mod ingest_error;
pub mod stall_reason;
pub mod zone_indexer;
