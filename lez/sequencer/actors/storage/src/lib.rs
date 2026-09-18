//! Storage Actor is responsible for persisting data in local database.

#[cfg(feature = "actor")]
pub use actor::StorageActor;
pub use r#trait::StorageActorTrait;

#[cfg(feature = "actor")]
pub mod actor;
pub mod error;
#[cfg(feature = "mock")]
pub mod mock;
pub mod protocol;
pub mod r#trait;

pub type Result<T> = std::result::Result<T, error::Error>;
