#![allow(clippy::undocumented_unsafe_blocks, reason = "It is an FFI")]

pub use sequencer::SequencerServiceFFI;

pub mod api;
mod sequencer;
mod reexports;
