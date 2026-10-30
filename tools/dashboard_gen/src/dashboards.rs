//! One module per dashboard, each exposing a `dashboard()` builder.

pub mod network;
pub mod sequencer;

/// Tag on every sequencer dashboard, which their top-bar links list.
const TAG: &str = "sequencer";
