//! Shared, storage-free chain-state core for the LEZ sequencer and indexer.
//!
//! Hosts the single validate-then-apply entry point ([`apply_block`]) plus the
//! shared types ([`BlockIngestError`], [`StallReason`], [`Tip`],
//! [`AcceptOutcome`]) that both the sequencer and the indexer build on. The
//! crate performs no I/O: callers own their storage and drive the
//! `scratch → persist → commit` ordering around these primitives.
//!
//! See `DESIGN.md` in this crate for the two-tier chain-state model this backs.

pub mod apply;
pub mod ingest_error;
pub mod stall_reason;

pub use apply::{AcceptOutcome, Tip, apply_block};
pub use ingest_error::BlockIngestError;
pub use stall_reason::StallReason;
