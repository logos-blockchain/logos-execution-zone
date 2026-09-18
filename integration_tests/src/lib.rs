//! Integration test helpers, re-exported from `test_fixtures` for backwards
//! compatibility. The actual fixtures live in the `test_fixtures` crate so that
//! non-test consumers (e.g. `integration_bench`) can depend on them without
//! pulling in the test files.

/// Cucumber world, configuration, and step support for integration tests.
#[cfg(feature = "cucumber")]
pub mod cucumber;
/// Testing-framework application deployments and lifecycle helpers.
pub mod testing_framework;
/// Shared integration-test utility functions.
pub mod utils;

pub use test_fixtures::*;
pub use utils::*;
