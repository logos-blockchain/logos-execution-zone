//! Sequencer p2p gossip: a libp2p swarm that discovers peers via Kademlia,
//! Identify, and bootstrap (plus mDNS behind a cargo feature).
//!
//! p2p is a latency optimization, never a source of truth: gossip being
//! down degrades to L1-only behavior, and a gossip failure after startup
//! never halts the node.

pub use libp2p::Multiaddr;
pub use network::{GossipNetwork, GossipTxPublisher};

pub mod accreditation;
pub mod network;
pub mod seen_cache;
pub mod validation;

#[cfg(test)]
mod tests;
