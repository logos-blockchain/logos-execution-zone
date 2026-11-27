//! Storage Actor is responsible for persisting data in local database.

#[cfg(feature = "actor")]
pub use actor::StorageActor;
pub use storable::{ColumnFamily, Storable};
pub use r#trait::{StorageActorTrait, Stores};
pub use writes::Writes;

#[cfg(feature = "actor")]
pub mod actor;
pub mod encoding;
pub mod error;
#[cfg(feature = "mock")]
pub mod mock;
pub mod protocol;
pub mod storable;
pub mod r#trait;
pub mod utils;
pub mod writes;

pub type Result<T> = std::result::Result<T, error::Error>;
