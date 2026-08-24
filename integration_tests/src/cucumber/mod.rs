/// Cucumber context containing handles for a deployed LEZ stack.
pub mod context;
/// Cucumber runner configuration and filesystem helpers.
pub mod default;
mod error;
/// Node-level (L3) scenario state for the stake lifecycle scenarios.
pub mod stake_scenario;
/// Cucumber step implementations.
pub mod steps;
/// Per-scenario Cucumber world and lifecycle management.
pub mod world;

pub const TARGET: &str = "cucumber";
