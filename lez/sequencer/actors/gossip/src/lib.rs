//! Sequencer p2p gossip as an actor: a libp2p swarm that discovers peers via
//! Kademlia, Identify, and bootstrap (plus mDNS behind a cargo feature).
//!
//! p2p is a latency optimization, never a source of truth: gossip being
//! down degrades to L1-only behavior, and a gossip failure after startup
//! never halts the node.

#[cfg(all(test, feature = "actor"))]
pub use actor::unscreened_mempool_submit;
#[cfg(feature = "actor")]
pub use actor::{GossipActor, IngestSubmit, WatchdogGuard, spawn_gossip_outage_watchdog};
#[cfg(feature = "actor")]
pub use libp2p::Multiaddr;
pub use protocol::{GetConnectedPeers, GossipTxPublisher, PublishTransaction};

pub mod accreditation;
#[cfg(feature = "actor")]
pub mod actor;
pub mod protocol;
pub mod seen_cache;
pub mod validation;

#[cfg(feature = "actor")]
#[cfg(test)]
mod tests;
