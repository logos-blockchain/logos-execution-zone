#![allow(clippy::undocumented_unsafe_blocks, reason = "It is an FFI")]

pub use errors::OperationStatus;
pub use indexer::IndexerServiceFFI;

pub mod api;
mod errors;
mod indexer;
