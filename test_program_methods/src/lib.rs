#![expect(
    clippy::print_stderr,
    reason = "fixture loaders print a skip notice when fixture files are absent"
)]

pub use fixtures::{PpeFixture, PpeTxFixtureBundle};
pub mod fixtures;

include!(concat!(env!("OUT_DIR"), "/methods.rs"));
