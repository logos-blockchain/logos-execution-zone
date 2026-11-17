//! Storage-free chain-state core shared by the LEZ sequencer and indexer:
//! the [`apply_block`] entry point plus [`BlockIngestError`], [`StallReason`],
//! [`Tip`], and [`AcceptOutcome`]. See [`ChainState`] for the two-tier model.

pub use apply::{
    AcceptOutcome, Tip, apply_block, apply_block_to_state, apply_judged_block_to_state,
    validate_against_tip,
};
#[cfg(feature = "node")]
pub use chain::{ChainState, ChannelEntry, PublishRecord};
#[cfg(feature = "node")]
pub use consistency::{
    Anchor, AnchorConsistencyCheck, ChainConsistency, ChainMismatch, verify_chain_consistency,
};
pub use ingest_error::BlockIngestError;
#[cfg(feature = "node")]
pub use stall_reason::StallReason;

pub mod apply;
#[cfg(feature = "node")]
pub mod chain;
pub mod classify;
#[cfg(feature = "node")]
pub mod consistency;
pub mod full_stake_releases;
pub mod ingest_error;
#[cfg(feature = "node")]
pub mod stall_reason;
#[cfg(feature = "node")]
pub mod timeout_node;
#[cfg(feature = "node")]
pub mod zone_indexer;
