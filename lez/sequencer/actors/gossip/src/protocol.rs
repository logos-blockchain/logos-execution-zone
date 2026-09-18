//! Messages the gossip actor accepts.

use common::transaction::LeeTransaction;

/// Ed25519 public keys of currently connected, identified peers.
pub struct GetConnectedPeers;

/// Publish a locally-submitted transaction to the gossip mesh.
pub struct PublishTransaction(pub LeeTransaction);

/// Re-dial the configured bootstrap peers if the node has no connected
/// peers; sent periodically by the scheduler.
#[derive(Copy, Clone)]
pub struct RetryBootstrap;
