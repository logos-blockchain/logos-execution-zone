//! Executor Actor performs the main logic of the Sequencer.

#[cfg(feature = "actor")]
pub use actor::ExecutorActor;
pub use r#trait::ExecutorActorTrait;

#[cfg(feature = "actor")]
pub mod actor;
pub mod error;
#[cfg(feature = "mock")]
pub mod mock;
pub mod protocol;
pub mod r#trait;

pub type Result<T> = std::result::Result<T, error::Error>;
