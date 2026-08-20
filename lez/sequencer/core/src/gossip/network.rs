use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::Duration,
};

use anyhow::{Context as _, Result, anyhow};
use common::transaction::LeeTransaction;
use futures::StreamExt as _;
#[cfg(feature = "mdns")]
use libp2p::mdns;
use libp2p::{
    Multiaddr, PeerId, SwarmBuilder, gossipsub, identify,
    identity::Keypair,
    kad,
    multiaddr::Protocol,
    swarm::{NetworkBehaviour, Swarm, SwarmEvent},
};
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use mempool::MemPoolHandle;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::{
    TransactionOrigin,
    config::GossipConfig,
    gossip::{message::GossipMessage, seen_cache::SeenCache},
    slashing::SlashRecord,
};

/// How long to wait for the first listen address before failing startup.
const LISTEN_TIMEOUT: Duration = Duration::from_secs(5);
/// How often the watchdog warns that the driver is down and the node is L1-only.
const DRIVER_OUTAGE_WARN_INTERVAL: Duration = Duration::from_secs(300);
/// Recently-seen gossiped transaction hashes kept for dedup.
const SEEN_CACHE_CAPACITY: usize = 4096;
/// Outbound local-publish channel depth; `try_send` drops on overflow.
const TX_PUBLISH_CHANNEL_CAPACITY: usize = 1024;
/// Headroom over `max_block_size` for `GossipSub` protobuf framing (signature,
/// source, seqno, topic) so a maximum-size transaction still fits the transmit
/// limit instead of being dropped at the transport before validation.
const GOSSIP_FRAME_MARGIN: u64 = 4096;
/// How often to re-dial bootstrap peers while the node has no connected
/// peers, so a node that starts before its bootstrap peer still joins.
const BOOTSTRAP_RETRY_INTERVAL: Duration = Duration::from_secs(30);
/// Local transactions whose publish failed (e.g. `InsufficientPeers` while
/// the mesh is still forming), kept for republish once a peer subscribes.
const PENDING_PUBLISH_CAPACITY: usize = 256;
/// How often this node rebroadcasts its own slash approvals, so peers that
/// missed one or joined later still collect it.
const APPROVAL_BROADCAST_INTERVAL: Duration = Duration::from_secs(10);

#[derive(NetworkBehaviour)]
struct GossipBehaviour {
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
    #[cfg(feature = "mdns")]
    mdns: mdns::tokio::Behaviour,
}

/// Handle to the running gossip network. Dropping it stops the drive task.
pub struct GossipNetwork {
    connected_rx: watch::Receiver<Vec<[u8; 32]>>,
    shutdown: CancellationToken,
    listen_addrs: Vec<Multiaddr>,
    local_peer_id: PeerId,
    tx_tx: mpsc::Sender<LeeTransaction>,
}

/// Handle for publishing locally-submitted transactions to the gossip mesh.
/// `publish` is non-blocking: a full channel drops the transaction rather
/// than back-pressuring the caller.
#[derive(Clone)]
pub struct GossipTxPublisher(mpsc::Sender<LeeTransaction>);

impl GossipTxPublisher {
    pub fn publish(&self, tx: LeeTransaction) {
        if let Err(err) = self.0.try_send(tx) {
            log::debug!("Dropping local tx publish: outbound gossip channel full or closed: {err}");
        }
    }
}

impl GossipNetwork {
    /// Builds the swarm, binds `listen_addr`, seeds Kademlia and dials
    /// bootstrap peers, and spawns the drive task.
    pub async fn start(
        config: GossipConfig,
        channel_id: [u8; 32],
        signing_key: Ed25519Key,
        mempool_handle: MemPoolHandle<(TransactionOrigin, LeeTransaction)>,
        max_block_size: u64,
        slash_record: Option<SlashRecord>,
    ) -> Result<Self> {
        // Reuse the node's L1 bedrock signing key as the libp2p identity. The
        // secret stays in a `Zeroizing` buffer that both `ed25519_from_bytes`
        // and drop wipe.
        //
        // FIXME: get rid of `unsecure` here when we introduce accredited key
        // handling, and a separete `Gossip node key -> Bedrock signing key` mapping.
        let approver = signing_key.clone();
        let mut secret = signing_key.into_unsecured().to_bytes();
        let keypair = Keypair::ed25519_from_bytes(&mut *secret)
            .map_err(|err| anyhow!("Invalid bedrock signing key for libp2p identity: {err}"))?;
        let local_peer_id = keypair.public().to_peer_id();

        let listen_addr = config.listen_addr;
        let bootstrap = config.bootstrap_peers;

        let message_id_fn = |msg: &gossipsub::Message| {
            // Undecodable messages still need a message-id, but it must be a
            // deterministic digest, not the attacker-controlled bytes
            // themselves and not a process-local hash (`DefaultHasher`):
            // every peer has to derive the same id from the same data.
            let id = match borsh::from_slice::<GossipMessage>(&msg.data) {
                Ok(GossipMessage::Transaction(tx)) => tx.hash().0.to_vec(),
                _ => common::block::OwnHasher::hash(&msg.data).0.to_vec(),
            };
            gossipsub::MessageId::from(id)
        };
        // Derived from this node's `max_block_size`, so all nodes on a channel
        // must agree on it: a node configured smaller would drop a larger frame
        // its peers send at the codec (an inbound-stream close, not a clean
        // application-level Reject), i.e. a near-invisible partial partition.
        // `max_block_size` is already effectively a channel-wide parameter
        // (block validation depends on it), so this inherits that requirement.
        let max_transmit_size = usize::try_from(max_block_size.saturating_add(GOSSIP_FRAME_MARGIN))
            .unwrap_or(usize::MAX);
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(message_id_fn)
            .validate_messages()
            .max_transmit_size(max_transmit_size)
            .build()
            .map_err(|err| anyhow!("Failed to build gossipsub config: {err}"))?;

        let gossipsub_behaviour = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keypair.clone()),
            gossipsub_config,
        )
        .map_err(|err| anyhow!("Failed to build gossipsub behaviour: {err}"))?;
        let identify_behaviour =
            identify::Behaviour::new(identify::Config::new("/lez/1".to_owned(), keypair.public()));
        let kademlia_behaviour = {
            let store = kad::store::MemoryStore::new(local_peer_id);
            let mut kademlia = kad::Behaviour::new(local_peer_id, store);
            kademlia.set_mode(Some(kad::Mode::Server));
            kademlia
        };
        #[cfg(feature = "mdns")]
        let mdns_behaviour = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
            .map_err(|err| anyhow!("Failed to build mdns behaviour: {err}"))?;

        let mut swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_quic()
            .with_behaviour(|_key| GossipBehaviour {
                gossipsub: gossipsub_behaviour,
                identify: identify_behaviour,
                kademlia: kademlia_behaviour,
                #[cfg(feature = "mdns")]
                mdns: mdns_behaviour,
            })
            .expect("behaviour constructor is infallible")
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        // subscribe to topic for the selected channel
        let topic = Self::get_topic_for_channel(channel_id);
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&topic)
            .context("Failed to subscribe to gossip tx topic")?;

        swarm
            .listen_on(listen_addr)
            .context("Failed to listen on gossip address")?;

        // Fail fast on bind errors: wait for the first listen address.
        let listen_addrs = wait_for_listen_addr(&mut swarm).await?;
        log::info!("Gossip listening on {listen_addrs:?} as {local_peer_id}");

        // Seed Kademlia with bootstrap peers that carry an embedded peer id;
        // dial the rest directly, since Kademlia can't route to an address
        // without a known peer id.
        for addr in &bootstrap {
            let embedded_peer_id = match addr.iter().last() {
                Some(Protocol::P2p(peer_id)) => Some(peer_id),
                _ => None,
            };
            if let Some(peer_id) = embedded_peer_id {
                swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, addr.clone());
                continue;
            }
            if let Err(err) = swarm.dial(addr.clone()) {
                log::warn!("Failed to dial gossip bootstrap peer {addr}: {err}");
            }
        }
        if let Err(err) = swarm.behaviour_mut().kademlia.bootstrap() {
            log::debug!("Kademlia bootstrap skipped (no known peers yet): {err}");
        }

        let (connected_tx, connected_rx) = watch::channel(Vec::new());
        let shutdown = CancellationToken::new();
        let (tx_tx, tx_rx) = mpsc::channel::<LeeTransaction>(TX_PUBLISH_CHANNEL_CAPACITY);

        let driver = tokio::spawn(run_drive_task(DriveTask {
            swarm,
            connected: HashSet::new(),
            pubkeys: HashMap::new(),
            connected_tx,
            shutdown: shutdown.clone(),
            topic,
            mempool: mempool_handle,
            seen: SeenCache::new(SEEN_CACHE_CAPACITY),
            max_block_size,
            tx_rx,
            bootstrap,
            pending_publish: VecDeque::new(),
            slash_record,
            approver,
        }));
        spawn_driver_watchdog(driver, shutdown.clone());

        Ok(Self {
            connected_rx,
            shutdown,
            listen_addrs,
            local_peer_id,
            tx_tx,
        })
    }

    #[must_use]
    pub fn get_topic_for_channel(channel_id: [u8; 32]) -> gossipsub::IdentTopic {
        gossipsub::IdentTopic::new(format!("/lez/{}/v2/gossip", hex::encode(channel_id)))
    }

    #[must_use]
    pub fn listen_addrs(&self) -> Vec<Multiaddr> {
        self.listen_addrs.clone()
    }

    /// Listen addresses with the `/p2p/` peer id appended — the form other
    /// nodes put in `bootstrap_peers`.
    #[must_use]
    pub fn bootstrap_addrs(&self) -> Vec<Multiaddr> {
        self.listen_addrs
            .iter()
            .map(|addr| addr.clone().with(Protocol::P2p(self.local_peer_id)))
            .collect()
    }

    #[must_use]
    pub const fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Handle for publishing locally-submitted transactions to the mesh.
    #[must_use]
    pub fn tx_publisher(&self) -> GossipTxPublisher {
        GossipTxPublisher(self.tx_tx.clone())
    }

    /// Ed25519 public keys of currently connected peers.
    #[must_use]
    pub fn connected_peers(&self) -> Vec<[u8; 32]> {
        self.connected_rx.borrow().clone()
    }

    /// Cancelled when a graceful shutdown is requested (the handle is dropped).
    /// Observers must NOT halt the node on it.
    #[must_use]
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }
}

impl Drop for GossipNetwork {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Everything the drive task owns.
struct DriveTask {
    swarm: Swarm<GossipBehaviour>,
    connected: HashSet<PeerId>,
    /// Ed25519 public keys of peers seen via Identify, keyed by `PeerId`.
    pubkeys: HashMap<PeerId, [u8; 32]>,
    connected_tx: watch::Sender<Vec<[u8; 32]>>,
    shutdown: CancellationToken,
    topic: gossipsub::IdentTopic,
    mempool: MemPoolHandle<(TransactionOrigin, LeeTransaction)>,
    seen: SeenCache,
    max_block_size: u64,
    tx_rx: mpsc::Receiver<LeeTransaction>,
    /// Configured bootstrap peers, re-dialed while the node is isolated.
    bootstrap: Vec<Multiaddr>,
    /// Local transactions whose publish failed, retried when a peer
    /// subscribes to the topic. Bounded; the oldest is dropped on overflow.
    pending_publish: VecDeque<LeeTransaction>,
    /// Absent when slashing collection is not wired in.
    slash_record: Option<SlashRecord>,
    approver: Ed25519Key,
}

impl DriveTask {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "SwarmEvent is non_exhaustive; only connection and behaviour events are handled"
    )]
    fn on_swarm_event(&mut self, event: SwarmEvent<GossipBehaviourEvent>) {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                self.connected.insert(peer_id);
                self.update_connected_watch();
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established: 0,
                ..
            } => {
                self.connected.remove(&peer_id);
                self.pubkeys.remove(&peer_id);
                self.update_connected_watch();
            }
            SwarmEvent::Behaviour(behaviour_event) => self.on_behaviour_event(behaviour_event),
            _ => {}
        }
    }

    // `GossipBehaviourEvent` is generated by `#[derive(NetworkBehaviour)]`;
    // clippy does not flag wildcard matches against macro-generated enums,
    // so no `#[expect(clippy::wildcard_enum_match_arm)]` is needed here.
    fn on_behaviour_event(&mut self, event: GossipBehaviourEvent) {
        match event {
            GossipBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            }) => {
                self.on_gossip_message(propagation_source, &message_id, &message.data);
            }
            GossipBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { topic, .. })
                if topic == self.topic.hash() =>
            {
                self.flush_pending_publishes();
            }
            GossipBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }) => {
                if let Ok(ed25519_pubkey) = info.public_key.try_into_ed25519() {
                    self.pubkeys.insert(peer_id, ed25519_pubkey.to_bytes());
                    self.update_connected_watch();
                }
                for addr in info
                    .listen_addrs
                    .into_iter()
                    .filter(|addr| !is_unspecified(addr))
                {
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr);
                }
            }
            #[cfg(feature = "mdns")]
            GossipBehaviourEvent::Mdns(mdns::Event::Discovered(peers)) => {
                for (peer_id, addr) in peers {
                    if let Err(err) = self.swarm.dial(addr) {
                        log::debug!("Failed to dial mdns-discovered peer {peer_id}: {err}");
                    }
                }
            }
            _ => {}
        }
    }

    fn update_connected_watch(&self) {
        let mut peers: Vec<[u8; 32]> = self
            .connected
            .iter()
            .filter_map(|peer_id| self.pubkeys.get(peer_id).copied())
            .collect();
        peers.sort_unstable();
        self.connected_tx.send_if_modified(|current| {
            if *current == peers {
                false
            } else {
                *current = peers;
                true
            }
        });
    }

    /// Validates an inbound gossiped transaction and reports the mesh
    /// acceptance decision, admitting it to the mempool on first sight.
    fn on_gossip_message(
        &mut self,
        source: PeerId,
        message_id: &gossipsub::MessageId,
        data: &[u8],
    ) {
        use crate::gossip::validation::{Evaluation, evaluate_message};

        let acceptance = match evaluate_message(data, self.max_block_size) {
            Evaluation::Reject(reason) => {
                log::debug!("Rejecting gossiped message from {source}: {reason}");
                gossipsub::MessageAcceptance::Reject
            }
            Evaluation::SlashApproval(approval) => {
                if let Some(record) = &self.slash_record {
                    record.record_approval(&approval);
                }
                gossipsub::MessageAcceptance::Accept
            }
            Evaluation::Transaction(tx) => {
                let hash = tx.hash();
                if self.seen.contains(&hash) {
                    gossipsub::MessageAcceptance::Ignore
                } else {
                    match self.mempool.try_push((TransactionOrigin::Gossip, tx)) {
                        Ok(()) => {
                            // mark seen only on successful pushes, so that if mempool is full we
                            // can later receive the same tx from gossip and try pushing it again
                            self.seen.insert(hash);
                        }
                        Err(_) => {
                            log::debug!("Mempool full; forwarding tx {hash:?} without admitting");
                        }
                    }

                    gossipsub::MessageAcceptance::Accept
                }
            }
        };

        _ = self
            .swarm
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(message_id, &source, acceptance);
    }

    /// Publishes a locally-submitted transaction to the mesh. Marked seen
    /// only once actually published; a failed publish (e.g.
    /// `InsufficientPeers` while the mesh is still forming) is queued and
    /// retried when a peer subscribes to the topic.
    fn publish_transaction(&mut self, tx: LeeTransaction) {
        let hash = tx.hash();
        let bytes = borsh::to_vec(&GossipMessage::Transaction(tx.clone()))
            .expect("tx borsh serialization should not fail");
        match self
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.topic.clone(), bytes)
        {
            // Duplicate means the mesh already carries this message.
            Ok(_) | Err(gossipsub::PublishError::Duplicate) => {
                self.seen.insert(hash);
            }
            Err(err) => {
                log::debug!("Queueing local tx publish {hash:?} for retry: {err}");
                if self.pending_publish.len() >= PENDING_PUBLISH_CAPACITY
                    && let Some(dropped) = self.pending_publish.pop_front()
                {
                    log::debug!(
                        "Pending publish queue full; dropping oldest tx {:?}",
                        dropped.hash()
                    );
                }
                self.pending_publish.push_back(tx);
            }
        }
    }

    /// Publishes this node's approval of every offence it has attributed.
    fn broadcast_own_approvals(&mut self) {
        let Some(record) = &self.slash_record else {
            return;
        };
        for approval in record.own_approvals(&self.approver) {
            let bytes = borsh::to_vec(&GossipMessage::SlashApproval(approval))
                .expect("approval borsh serialization should not fail");
            if let Err(err) = self
                .swarm
                .behaviour_mut()
                .gossipsub
                .publish(self.topic.clone(), bytes)
            {
                log::debug!("Failed to publish a slash approval: {err}");
            }
        }
    }

    /// Retries queued local publishes; still-failing ones are re-queued by
    /// `publish_transaction`.
    fn flush_pending_publishes(&mut self) {
        for tx in std::mem::take(&mut self.pending_publish) {
            self.publish_transaction(tx);
        }
    }

    /// Re-dials bootstrap peers while the node is isolated. The startup
    /// attempt runs once, so a node that starts before its bootstrap peer
    /// would otherwise never join the mesh.
    fn retry_bootstrap(&mut self) {
        if !self.connected.is_empty() || self.bootstrap.is_empty() {
            return;
        }
        log::debug!(
            "No connected gossip peers; retrying {} bootstrap peer(s)",
            self.bootstrap.len()
        );
        for addr in self.bootstrap.clone() {
            if let Err(err) = self.swarm.dial(addr.clone()) {
                log::debug!("Failed to dial gossip bootstrap peer {addr}: {err}");
            }
        }
        _ = self.swarm.behaviour_mut().kademlia.bootstrap();
    }
}

/// True if `addr` carries an unspecified (`0.0.0.0` / `::`) IP component.
/// Peers behind a default `0.0.0.0` listen address advertise these; feeding
/// them to Kademlia would pollute the routing table with unroutable entries.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Protocol is non_exhaustive; only the IP variants matter here"
)]
fn is_unspecified(addr: &Multiaddr) -> bool {
    addr.iter().any(|proto| match proto {
        Protocol::Ip4(ip) => ip.is_unspecified(),
        Protocol::Ip6(ip) => ip.is_unspecified(),
        _ => false,
    })
}

/// Derives the libp2p `PeerId` an Ed25519 public key produces.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unused by the mesh until a later gossip task; exercised by the identity test below"
    )
)]
pub(crate) fn peer_id_from_ed25519(
    pubkey: &[u8; 32],
) -> Result<PeerId, libp2p::identity::DecodingError> {
    libp2p::identity::ed25519::PublicKey::try_from_bytes(pubkey)
        .map(|key| libp2p::identity::PublicKey::from(key).to_peer_id())
}

#[expect(
    clippy::integer_division_remainder_used,
    reason = "Generated by select! macro, can't be easily rewritten to avoid this lint"
)]
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "SwarmEvent is non_exhaustive; only startup listener events are handled here"
)]
async fn wait_for_listen_addr(swarm: &mut Swarm<GossipBehaviour>) -> Result<Vec<Multiaddr>> {
    let deadline = tokio::time::sleep(LISTEN_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => return Ok(vec![address]),
                SwarmEvent::ListenerError { error, .. } => {
                    anyhow::bail!("Gossip listener error during startup: {error}");
                }
                SwarmEvent::ListenerClosed { reason, .. } => {
                    anyhow::bail!("Gossip listener closed during startup: {reason:?}");
                }
                _ => {}
            },
            () = &mut deadline => {
                anyhow::bail!("Timed out waiting for gossip listen address");
            }
        }
    }
}

#[expect(
    clippy::integer_division_remainder_used,
    reason = "Generated by select! macro, can't be easily rewritten to avoid this lint"
)]
async fn run_drive_task(mut task: DriveTask) {
    // `interval_at`: startup already dialed the bootstrap peers, so the
    // first tick waits a full interval instead of firing immediately.
    let mut bootstrap_retry = tokio::time::interval_at(
        tokio::time::Instant::now()
            .checked_add(BOOTSTRAP_RETRY_INTERVAL)
            .expect("bootstrap retry deadline within Instant range"),
        BOOTSTRAP_RETRY_INTERVAL,
    );
    let mut approval_broadcast = tokio::time::interval(APPROVAL_BROADCAST_INTERVAL);
    loop {
        tokio::select! {
            () = task.shutdown.cancelled() => break,
            event = task.swarm.select_next_some() => task.on_swarm_event(event),
            Some(tx) = task.tx_rx.recv() => task.publish_transaction(tx),
            _ = bootstrap_retry.tick() => task.retry_bootstrap(),
            _ = approval_broadcast.tick() => task.broadcast_own_approvals(),
        }
    }
}

/// Owns the driver handle so it can detect the task ending. A graceful shutdown
/// cancels `shutdown` first, so that path stays silent; a crash leaves it
/// uncancelled, and operators are warned the node is running L1-only until the
/// handle is dropped.
#[expect(
    clippy::integer_division_remainder_used,
    reason = "Generated by select! macro, can't be easily rewritten to avoid this lint"
)]
fn spawn_driver_watchdog(driver: tokio::task::JoinHandle<()>, shutdown: CancellationToken) {
    tokio::spawn(async move {
        _ = driver.await;
        if shutdown.is_cancelled() {
            return;
        }
        loop {
            log::error!(
                "Sequencer gossip network is down; continuing L1-only. \
                 Restart the node to restore p2p."
            );
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep(DRIVER_OUTAGE_WARN_INTERVAL) => {}
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use logos_blockchain_key_management_system_service::keys::Ed25519Key;

    use super::*;
    use crate::config::GossipConfig;

    const TEST_MAX_BLOCK_SIZE: u64 = 1 << 20;

    fn test_config() -> GossipConfig {
        GossipConfig {
            listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
            bootstrap_peers: vec![],
        }
    }

    fn test_mempool_handle() -> MemPoolHandle<(TransactionOrigin, LeeTransaction)> {
        mempool::MemPool::new(1000).1
    }

    #[test]
    fn libp2p_identity_matches_kms_public_key() {
        // The PeerId derived from an Ed25519 public key must equal the
        // PeerId the same secret produces as a libp2p identity.
        let secret = [9; 32];
        let kms_pubkey = Ed25519Key::from_bytes(&secret).public_key().to_bytes();
        let mut secret_for_libp2p = secret;
        let keypair =
            libp2p::identity::Keypair::ed25519_from_bytes(&mut secret_for_libp2p).unwrap();
        assert_eq!(
            peer_id_from_ed25519(&kms_pubkey).unwrap(),
            keypair.public().to_peer_id()
        );
    }

    #[tokio::test]
    async fn start_binds_and_reports_listen_addr() {
        let network = GossipNetwork::start(
            test_config(),
            [1; 32],
            Ed25519Key::from_bytes(&[9; 32]),
            test_mempool_handle(),
            TEST_MAX_BLOCK_SIZE,
            None,
        )
        .await
        .unwrap();
        let addrs = network.listen_addrs();
        assert!(!addrs.is_empty());
        assert!(addrs[0].to_string().contains("/udp/"));
        assert!(network.connected_peers().is_empty());
    }

    #[tokio::test]
    async fn drop_cancels_driver() {
        let network = GossipNetwork::start(
            test_config(),
            [1; 32],
            Ed25519Key::from_bytes(&[9; 32]),
            test_mempool_handle(),
            TEST_MAX_BLOCK_SIZE,
            None,
        )
        .await
        .unwrap();
        let token = network.shutdown_token();
        drop(network);
        tokio::time::timeout(std::time::Duration::from_secs(5), token.cancelled())
            .await
            .expect("driver should stop when the handle is dropped");
    }
}
