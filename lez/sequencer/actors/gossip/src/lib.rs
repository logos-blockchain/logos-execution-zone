//! Sequencer p2p gossip as an actor: a libp2p swarm that discovers peers via
//! Kademlia, Identify, and bootstrap (plus mDNS behind a cargo feature).
//!
//! p2p is a latency optimization, never a source of truth: gossip being
//! down degrades to L1-only behavior, and a gossip failure after startup
//! never halts the node.

#[cfg(test)]
pub use actor::unscreened_mempool_submit;
pub use actor::{
    GetConnectedPeers, GossipActor, GossipTxPublisher, IngestSubmit, PublishTransaction,
    WatchdogGuard, spawn_gossip_outage_watchdog,
};
pub use libp2p::Multiaddr;

pub mod accreditation;
pub mod actor;
pub mod seen_cache;
pub mod validation;

#[cfg(test)]
mod tests;
