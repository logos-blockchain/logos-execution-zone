#![allow(clippy::undocumented_unsafe_blocks, reason = "It is an FFI")]

pub use service::SequencerServiceFFI;

pub mod api;
mod service;
