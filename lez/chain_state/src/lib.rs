//! Storage-free chain-state core shared by the LEZ sequencer and indexer:
//! the [`apply_block`] entry point plus [`BlockIngestError`], [`StallReason`],
//! [`Tip`], and [`AcceptOutcome`]. See `DESIGN.md` for the two-tier model.

pub mod apply;
pub mod ingest_error;
pub mod stall_reason;

pub use apply::{AcceptOutcome, Tip, apply_block};
pub use ingest_error::BlockIngestError;
pub use stall_reason::StallReason;
