//! Sequencer p2p gossip: a libp2p swarm that discovers peers via Kademlia,
//! Identify, and bootstrap (plus mDNS behind a cargo feature).
//!
//! p2p is a latency optimization, never a source of truth: gossip being
//! down degrades to L1-only behavior, and a gossip failure after startup
//! never halts the node.

use std::collections::HashSet;

pub use libp2p::Multiaddr;
#[cfg(test)]
pub use network::unscreened_mempool_submit;
pub use network::{GossipNetwork, GossipTxPublisher, IngestSubmit};
use tokio::sync::watch;

pub mod network;
pub mod seen_cache;
pub mod validation;

#[cfg(test)]
mod tests;

/// Keys the mesh accepts a slash approval from, fed from the `sequencer_stake`
/// config by `refresh_committee`.
pub type AccreditedKeys = HashSet<[u8; 32]>;

/// Written by `refresh_committee` on every head move.
pub type AccreditedKeysSender = watch::Sender<Option<AccreditedKeys>>;

/// Read by the gossip drive task per inbound approval.
pub type AccreditedKeysReceiver = watch::Receiver<Option<AccreditedKeys>>;

/// The mesh's accredited-key channel: `None` filters nothing, `Some` of an
/// empty set filters everything.
#[must_use]
pub fn accredited_keys_channel() -> (AccreditedKeysSender, AccreditedKeysReceiver) {
    watch::channel(None)
}
