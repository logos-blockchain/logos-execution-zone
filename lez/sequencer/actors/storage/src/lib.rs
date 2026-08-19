//! Storage Actor is responsible for persisting data in local database.

pub use actor::StorageActor;
pub use r#trait::StorageActorTrait;

pub mod actor;
pub mod error;
#[cfg(feature = "mock")]
pub mod mock;
pub mod protocol;
#[cfg(test)]
mod tests;
pub mod r#trait;

pub type Result<T> = std::result::Result<T, error::Error>;
