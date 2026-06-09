//! `cycle_bench` library: per-program executor/prover cycle measurement helpers
//! shared between the `cycle_bench` binary and the `verify` criterion bench.

#![expect(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_precision_loss,
    clippy::float_arithmetic,
    clippy::print_literal,
    clippy::print_stdout,
    reason = "Bench library: stats arithmetic and table printing are bench-style"
)]
#![cfg_attr(
    feature = "ppe",
    expect(
        clippy::arbitrary_source_item_ordering,
        reason = "PPE module: re-export ordering trips strict lints"
    )
)]
#![cfg_attr(
    any(feature = "ppe", feature = "aggregator"),
    expect(
        clippy::print_stderr,
        reason = "PPE/aggregator bench: eprintln progress messages"
    )
)]

pub mod aggregator;
pub mod ppe;
pub mod stats;
