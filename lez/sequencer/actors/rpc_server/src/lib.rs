//! RPC Server Actor serves RPC queries and forwards them to Executor.

pub use actor::{GossipPublishers, RpcServerActor};

pub mod actor;
pub mod error;

pub type Result<T> = std::result::Result<T, error::Error>;
