//! Sharding Pool provides a pool of actors where each request is routed to a specific actor based
//! on a sharding key.

use std::hash::Hash;

#[cfg(feature = "actor")]
pub use actor::ShardingPoolActor;

#[cfg(feature = "actor")]
pub mod actor;
pub mod protocol;

/// A trait for messages that can provide a sharding key.
pub trait ShardingKey {
    type Key: Hash + Eq;

    fn sharding_key(&self) -> Self::Key;
}
