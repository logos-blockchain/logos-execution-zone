//! Sharding Pool provides a pool of actors where each request is routed to a specific actor based
//! on a sharding key.
//!
//! Each child actor is supervised by pool according to the restart config of its key.
//! If a child actor fails the pool will try to restart it and resend the message. Once it gives up
//! on a child it was restarting, the pool stops with [`LinkDied`] for that child, so the pool's own
//! supervisor learns of the failure. A child the pool never restarts is left to the actors linked
//! to it, and stays in place, failing its messages, until its key is reset.
//!
//! [`LinkDied`]: kameo::error::ActorStopReason::LinkDied

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
