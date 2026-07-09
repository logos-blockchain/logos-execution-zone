//! Storage-free chain-state core shared by the LEZ sequencer and indexer:
//! the [`apply_block`] entry point plus [`BlockIngestError`], [`StallReason`],
//! [`Tip`], and [`AcceptOutcome`]. See `DESIGN.md` for the two-tier model.

pub use apply::{AcceptOutcome, Tip, apply_block};
pub use chain::{ChainState, HeadEntry};
pub use ingest_error::BlockIngestError;
pub use stall_reason::StallReason;

pub mod apply;
pub mod chain;
pub mod ingest_error;
pub mod stall_reason;
