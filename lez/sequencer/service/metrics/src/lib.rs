//! This crate provides all metrics exposed by the sequencer service, and the
//! attributes of the spans it exports as traces.

#[cfg(feature = "record")]
pub use record::*;

pub mod names;
pub mod traces;

#[cfg(feature = "record")]
pub mod instances;
#[cfg(feature = "record")]
pub mod record;
