//! Executor Actor performs the main logic of the Sequencer.

pub use actor::ExecutorActor;

pub mod actor;
pub mod error;
pub mod protocol;
#[cfg(test)]
mod tests;

pub type Result<T> = std::result::Result<T, error::Error>;
