#![allow(clippy::undocumented_unsafe_blocks, reason = "It is an FFI")]

pub use errors::OperationStatus;
pub use indexer::IndexerServiceFFI;
pub use runtime::Runtime;

pub mod api;
mod errors;
mod indexer;
mod runtime;

/// Largest block span a single `query_events` range request may cover.
// Spelled as a literal so cbindgen can emit it into the header for C callers; the
// assertion below makes any drift from the protocol crate's value a compile error.
pub const MAX_EVENT_QUERY_BLOCK_SPAN: u64 = 1000;
const _: () = assert!(
    MAX_EVENT_QUERY_BLOCK_SPAN == indexer_service_protocol::MAX_EVENT_QUERY_BLOCK_SPAN,
    "FFI event-query span cap must match the protocol crate's"
);
