//! Sharding Pool provides a pool of actors where each request is routed to a specific actor based
//! on a sharding key.
//!
//! Each child actor is supervised by pool according to the specified restart config.
//! If a child actor fails the pool will try to restart it and resend the message.

use std::hash::Hash;

#[cfg(feature = "actor")]
pub use actor::{Key, RestartConfig, ShardingPoolActor};

#[cfg(feature = "actor")]
pub mod actor;
pub mod protocol;

/// A trait for messages that can provide a sharding key.
pub trait ShardingKey {
    type Key: Hash + Eq;

    fn sharding_key(&self) -> Self::Key;
}
