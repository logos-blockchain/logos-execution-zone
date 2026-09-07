//! Messages the gossip actor accepts, consumable without the `actor` feature.

use common::transaction::LeeTransaction;
use kameo::actor::Recipient;

/// Ask: Ed25519 public keys of currently connected peers.
pub struct GetConnectedPeers;

/// Tell: publish a locally-submitted transaction to the mesh.
pub struct PublishTransaction(pub LeeTransaction);

/// Handle for publishing locally-submitted transactions to the gossip mesh.
/// `publish` is non-blocking: a full mailbox drops the transaction rather
/// than back-pressuring the caller.
///
/// Type-erased ([`Recipient`]), so clients need only this protocol, not the
/// actor implementation.
#[derive(Clone)]
pub struct GossipTxPublisher(Recipient<PublishTransaction>);

impl GossipTxPublisher {
    #[must_use]
    pub const fn new(recipient: Recipient<PublishTransaction>) -> Self {
        Self(recipient)
    }

    pub fn publish(&self, tx: LeeTransaction) {
        if let Err(err) = self.0.tell(PublishTransaction(tx)).try_send() {
            log::debug!("Dropping local tx publish: gossip mailbox full or closed: {err}");
        }
    }
}
