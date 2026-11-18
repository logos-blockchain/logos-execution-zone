use std::{
    convert::Infallible,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context as _;
use chain_state::ProofStore;
use common::{storage_cid::StorageCid, transaction::LeeTransaction};
use futures::StreamExt as _;
use kameo::{
    Actor,
    actor::{ActorRef, Spawn as _},
    message::{Context, Message},
};
use lee::privacy_preserving_transaction::circuit::{Proof, ProofDigest};
use libp2p::{request_response, swarm::SwarmEvent};
use logos_blockchain_zone_sdk::{
    core::proofs::channel_multi_sig_proof::IndexedSignature,
    key_management_system_service::keys::{Ed25519Key, Ed25519PublicKey},
};
use logos_storage::{
    Storage as _,
    memory::{MemoryNetwork, MemoryStorage},
};
use mempool::{MemPool, MemPoolHandle};
use sequencer_channel_signing_actor::protocol::{Signature, Wire};
use sequencer_core::{
    TransactionOrigin,
    availability::AvailabilityMessage,
    config::{GossipConfig, LogosStorageConfig, PROOF_STORE_CAPACITY},
    proof_objects::{MemoryRecords, ProofObjects},
};
use sequencer_slasher_actor::protocol::{Approval, Offence};
use sequencer_stake_core::SequencerKey;
use system_upgrader_core::SignedApproval;
use testnet_initial_state::{initial_pub_accounts_private_keys, initial_public_user_accounts};
use tokio::sync::mpsc;

use super::{
    AnnouncementScreen, GossipActor, IngestSubmit, MAILBOX_CAPACITY, SystemApprovalSubmit,
    locator_exchange, peer_id_from_ed25519,
};
use crate::protocol::{FetchProof, GetConnectedPeers, Publish, PublishConfig};

const CHANNEL: [u8; 32] = [1; 32];

/// A spawned gossip actor plus the identity captured before spawning.
struct TestNode {
    actor_ref: ActorRef<GossipActor>,
    listen_addrs: Vec<libp2p::Multiaddr>,
    local_peer_id: libp2p::PeerId,
}

/// The mempool and the gossip receivers a started node feeds.
struct NodeSinks {
    mempool: MemPool<(TransactionOrigin, LeeTransaction)>,
    approvals: mpsc::UnboundedReceiver<Approval>,
    configs: mpsc::UnboundedReceiver<Wire>,
    proofs: ProofStore,
    proof_objects: Arc<ProofObjects>,
    system_approvals: mpsc::UnboundedReceiver<SignedApproval>,
}

/// Forwards every approval the gossip actor delivers into a channel the
/// test can assert on; stands in for the slasher.
struct ApprovalSink(mpsc::UnboundedSender<Approval>);

impl Actor for ApprovalSink {
    type Args = Self;
    type Error = Infallible;

    async fn on_start(args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self, Infallible> {
        Ok(args)
    }
}

impl Message<Approval> for ApprovalSink {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: Approval,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        _ = self.0.send(msg);
    }
}

/// Forwards every availability message the gossip actor delivers into a channel the test can
/// assert on; stands in for the executor.
struct AvailabilitySink(mpsc::UnboundedSender<AvailabilityMessage>);

impl Actor for AvailabilitySink {
    type Args = Self;
    type Error = Infallible;

    async fn on_start(args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self, Infallible> {
        Ok(args)
    }
}

impl Message<AvailabilityMessage> for AvailabilitySink {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: AvailabilityMessage,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        _ = self.0.send(msg);
    }
}

/// Forwards every channel-config message the gossip actor delivers into a
/// channel the test can assert on; stands in for the channel-signing actor.
struct ConfigSink(mpsc::UnboundedSender<Wire>);

impl Actor for ConfigSink {
    type Args = Self;
    type Error = Infallible;

    async fn on_start(args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self, Infallible> {
        Ok(args)
    }
}

impl Message<Wire> for ConfigSink {
    type Reply = ();

    async fn handle(&mut self, msg: Wire, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        _ = self.0.send(msg);
    }
}

impl TestNode {
    async fn connected_peers(&self) -> Vec<Ed25519PublicKey> {
        self.actor_ref
            .ask(GetConnectedPeers)
            .await
            .expect("gossip actor should be alive")
    }

    fn publish(&self, tx: LeeTransaction) {
        self.actor_ref
            .tell(Publish::Transaction(Box::new(tx)))
            .try_send()
            .expect("gossip mailbox should accept the publish");
    }

    fn publish_approval(&self, approval: Approval) {
        self.actor_ref
            .tell(approval)
            .try_send()
            .expect("gossip mailbox should accept the approval publish");
    }

    fn publish_system_approval(&self, signed: SignedApproval) {
        self.actor_ref
            .tell(Publish::SystemApproval(signed))
            .try_send()
            .expect("gossip mailbox should accept the system approval publish");
    }

    fn publish_config(&self, message: Wire) {
        self.actor_ref
            .tell(PublishConfig(message))
            .try_send()
            .expect("gossip mailbox should accept the channel-config publish");
    }

    fn fetch_proof(&self, digest: ProofDigest) {
        self.actor_ref
            .tell(FetchProof(digest))
            .try_send()
            .expect("gossip mailbox should accept the proof fetch");
    }
}

/// An approval a peer would accept, signed by `secret` over `inscription`.
fn approval(secret: [u8; 32], inscription: [u8; 32]) -> Approval {
    let key = Ed25519Key::from_bytes(&secret);
    let signer = SequencerKey::new(key.public_key().to_bytes()).expect("valid key");
    let offence = Offence {
        offender: SequencerKey::new(pubkey([99; 32]).to_bytes()).expect("valid key"),
        inscription,
    };
    let message = sequencer_stake_core::slash_approval_message(
        CHANNEL,
        offence.offender,
        offence.inscription,
    );

    Approval {
        offence,
        signer,
        signature: key.sign_payload(&message).to_bytes(),
    }
}

fn pubkey(secret: [u8; 32]) -> Ed25519PublicKey {
    Ed25519Key::from_bytes(&secret).public_key()
}

/// An [`IngestSubmit`] that pushes straight into `mempool` unscreened.
/// Forwards every `system_upgrader` approval the gossip actor accepts into a channel; stands in for
/// the executor's approval pool.
fn channel_system_approval_submit(
    sink: mpsc::UnboundedSender<SignedApproval>,
) -> SystemApprovalSubmit {
    Arc::new(move |signed| {
        let sink = sink.clone();
        Box::pin(async move { sink.send(signed).context("the test dropped its receiver") })
    })
}

fn unscreened_announcements() -> AnnouncementScreen {
    Arc::new(|_transaction, _proof_len| Box::pin(async { Ok(()) }))
}

fn unscreened_mempool_submit(
    mempool: MemPoolHandle<(TransactionOrigin, LeeTransaction)>,
) -> IngestSubmit {
    Arc::new(move |tx| {
        let mempool = mempool.clone();
        Box::pin(async move {
            mempool
                .try_push((TransactionOrigin::Gossip, tx))
                .context("mempool is full")
        })
    })
}

fn spawn(actor: GossipActor) -> ActorRef<GossipActor> {
    GossipActor::spawn_with_mailbox(actor, kameo::mailbox::bounded(MAILBOX_CAPACITY))
}

fn test_config() -> GossipConfig {
    GossipConfig {
        listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        bootstrap_peers: vec![],
    }
}

fn test_mempool_handle() -> MemPoolHandle<(TransactionOrigin, LeeTransaction)> {
    MemPool::new(1000).handle().clone()
}

fn test_approval_sink() -> kameo::actor::Recipient<Approval> {
    ApprovalSink::spawn(ApprovalSink(mpsc::unbounded_channel().0)).recipient()
}

fn test_availability_sink() -> kameo::actor::Recipient<AvailabilityMessage> {
    AvailabilitySink::spawn(AvailabilitySink(mpsc::unbounded_channel().0)).recipient()
}

fn test_config_sink() -> kameo::actor::Recipient<Wire> {
    ConfigSink::spawn(ConfigSink(mpsc::unbounded_channel().0)).recipient()
}

/// A real, validly-signed transfer, reusing the same helper the RPC-side
/// admission tests use.
fn valid_transaction() -> LeeTransaction {
    let acc1 = initial_public_user_accounts()[0].account_id;
    let acc2 = initial_public_user_accounts()[1].account_id;
    let sign_key1 = initial_pub_accounts_private_keys()[0].pub_sign_key.clone();
    common::test_utils::create_transaction_native_token_transfer(acc1, 0, acc2, 10, &sign_key1)
}

/// Structurally well-formed but with a signature/public-key pair that does
/// not match, so it decodes but fails the stateless witness check; used to
/// exercise rejection through the real gossip pipeline rather than
/// `evaluate_transaction` directly.
fn invalidly_signed_transaction() -> LeeTransaction {
    let LeeTransaction::Public(mut tx) = valid_transaction() else {
        unreachable!("valid_transaction always builds a Public transaction");
    };
    let (signature, _correct_public_key) = tx.witness_set.signatures_and_public_keys()[0].clone();
    let wrong_public_key =
        lee::PublicKey::new_from_private_key(&initial_pub_accounts_private_keys()[1].pub_sign_key);
    tx.witness_set =
        lee::public_transaction::WitnessSet::from_raw_parts(vec![(signature, wrong_public_key)]);
    LeeTransaction::Public(tx)
}

async fn start_node(secret: [u8; 32], bootstrap: Vec<libp2p::Multiaddr>) -> (TestNode, NodeSinks) {
    start_node_on(secret, bootstrap, MemoryNetwork::default().node()).await
}

/// A node whose Logos Storage objects live on `storage`.
async fn start_node_on(
    secret: [u8; 32],
    bootstrap: Vec<libp2p::Multiaddr>,
    storage: MemoryStorage,
) -> (TestNode, NodeSinks) {
    let config = GossipConfig {
        listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        bootstrap_peers: bootstrap,
    };
    let mempool = MemPool::new(1000);
    let mempool_handle = mempool.handle().clone();
    let (approval_tx, approvals) = mpsc::unbounded_channel();
    let (config_tx, configs) = mpsc::unbounded_channel();
    let (system_approval_tx, system_approvals) = mpsc::unbounded_channel();
    let sink_ref = ApprovalSink::spawn(ApprovalSink(approval_tx));
    let config_sink_ref = ConfigSink::spawn(ConfigSink(config_tx));
    let proofs = ProofStore::new(PROOF_STORE_CAPACITY);
    let proof_objects = Arc::new(ProofObjects::new(
        Arc::new(storage),
        proofs.clone(),
        Arc::new(MemoryRecords::default()),
        &LogosStorageConfig::default(),
    ));
    let actor = GossipActor::new(
        config,
        CHANNEL,
        Ed25519Key::from_bytes(&secret),
        sink_ref.recipient(),
        unscreened_mempool_submit(mempool_handle),
        proofs.clone(),
        Arc::clone(&proof_objects),
        unscreened_announcements(),
        test_availability_sink(),
        config_sink_ref.recipient(),
        channel_system_approval_submit(system_approval_tx),
    )
    .await
    .expect("node should start");
    let listen_addrs = actor.listen_addrs();
    let local_peer_id = actor.local_peer_id();
    let actor_ref = spawn(actor);
    (
        TestNode {
            actor_ref,
            listen_addrs,
            local_peer_id,
        },
        NodeSinks {
            mempool,
            approvals,
            configs,
            proofs,
            proof_objects,
            system_approvals,
        },
    )
}

#[expect(
    clippy::integer_division_remainder_used,
    reason = "Generated by select! macro, can't be easily rewritten to avoid this lint"
)]
fn scripted_locator_peer(
    node: libp2p::Multiaddr,
    answer: Option<StorageCid>,
) -> (
    mpsc::UnboundedReceiver<ProofDigest>,
    mpsc::UnboundedSender<()>,
) {
    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_quic()
        .with_behaviour(|_key| locator_exchange(CHANNEL))
        .expect("behaviour constructor is infallible")
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    swarm
        .dial(node)
        .expect("scripted peer should dial the node");
    let (requests_tx, requests) = mpsc::unbounded_channel();
    let (release, mut released) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut held = Vec::new();
        let mut answering = false;
        loop {
            tokio::select! {
                event = swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(request_response::Event::Message {
                        message: request_response::Message::Request { request, channel, .. },
                        ..
                    }) = event
                    {
                        _ = requests_tx.send(request.0);
                        held.push(channel);
                    }
                }
                Some(()) = released.recv() => answering = true,
            }
            if answering {
                for channel in std::mem::take(&mut held) {
                    _ = swarm.behaviour_mut().send_response(channel, answer);
                }
            }
        }
    });
    (requests, release)
}

async fn wait_for(timeout: Duration, mut condition: impl AsyncFnMut() -> bool) -> bool {
    let deadline = Instant::now()
        .checked_add(timeout)
        .expect("deadline within Instant range");
    while Instant::now() < deadline {
        if condition().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

#[test]
fn a_peer_id_yields_the_channel_signing_key_it_was_derived_from() {
    let key = Ed25519Key::from_bytes(&[9; 32]);
    let mut secret = key.clone().into_unsecured().to_bytes();
    let peer_id = libp2p::identity::Keypair::ed25519_from_bytes(&mut *secret)
        .unwrap()
        .public()
        .to_peer_id();

    assert_eq!(
        super::inlined_ed25519_key(&peer_id),
        Some(key.public_key().to_bytes())
    );
}

#[test]
fn libp2p_identity_matches_kms_public_key() {
    // The PeerId derived from an Ed25519 public key must equal the
    // PeerId the same secret produces as a libp2p identity.
    let secret = [9; 32];
    let kms_pubkey = Ed25519Key::from_bytes(&secret).public_key().to_bytes();
    let mut secret_for_libp2p = secret;
    let keypair = libp2p::identity::Keypair::ed25519_from_bytes(&mut secret_for_libp2p).unwrap();
    assert_eq!(
        peer_id_from_ed25519(&kms_pubkey).unwrap(),
        keypair.public().to_peer_id()
    );
}

#[tokio::test]
async fn new_binds_and_reports_listen_addr() {
    let actor = GossipActor::new(
        test_config(),
        [1; 32],
        Ed25519Key::from_bytes(&[9; 32]),
        test_approval_sink(),
        unscreened_mempool_submit(test_mempool_handle()),
        ProofStore::new(PROOF_STORE_CAPACITY),
        Arc::new(ProofObjects::in_memory(ProofStore::new(
            PROOF_STORE_CAPACITY,
        ))),
        unscreened_announcements(),
        test_availability_sink(),
        test_config_sink(),
        channel_system_approval_submit(mpsc::unbounded_channel().0),
    )
    .await
    .unwrap();
    let addrs = actor.listen_addrs();
    assert!(!addrs.is_empty());
    assert!(addrs[0].to_string().contains("/udp/"));
    assert!(actor.connected_pubkeys().is_empty());
}

#[tokio::test]
async fn kill_stops_the_swarm_and_frees_the_socket() {
    let actor = GossipActor::new(
        test_config(),
        [1; 32],
        Ed25519Key::from_bytes(&[9; 32]),
        test_approval_sink(),
        unscreened_mempool_submit(test_mempool_handle()),
        ProofStore::new(PROOF_STORE_CAPACITY),
        Arc::new(ProofObjects::in_memory(ProofStore::new(
            PROOF_STORE_CAPACITY,
        ))),
        unscreened_announcements(),
        test_availability_sink(),
        test_config_sink(),
        channel_system_approval_submit(mpsc::unbounded_channel().0),
    )
    .await
    .unwrap();
    let bound_addr = actor.listen_addrs()[0].clone();
    let actor_ref = spawn(actor);
    actor_ref.kill();
    // `wait_for_shutdown_result` (unlike `wait_for_shutdown`) resolves only
    // after `on_stop` has run, i.e. after the swarm released its sockets.
    tokio::time::timeout(Duration::from_secs(5), actor_ref.wait_for_shutdown_result())
        .await
        .expect("actor should stop when killed")
        .expect("kill is a clean stop");

    // Rebinding the exact freed address proves `on_stop` released it.
    let rebound = GossipActor::new(
        GossipConfig {
            listen_addr: bound_addr.clone(),
            bootstrap_peers: vec![],
        },
        [1; 32],
        Ed25519Key::from_bytes(&[10; 32]),
        test_approval_sink(),
        unscreened_mempool_submit(test_mempool_handle()),
        ProofStore::new(PROOF_STORE_CAPACITY),
        Arc::new(ProofObjects::in_memory(ProofStore::new(
            PROOF_STORE_CAPACITY,
        ))),
        unscreened_announcements(),
        test_availability_sink(),
        test_config_sink(),
        channel_system_approval_submit(mpsc::unbounded_channel().0),
    )
    .await
    .expect("freed listen address should be rebindable");
    assert_eq!(rebound.listen_addrs()[0], bound_addr);
}

#[tokio::test]
async fn nodes_discover_each_other_via_bootstrap() {
    let secrets = [[10; 32], [11; 32], [12; 32]];
    let (node_a, _sinks_a) = start_node(secrets[0], vec![]).await;
    let a_addr = node_a.listen_addrs[0].clone();
    // B bootstraps with a `/p2p/`-suffixed address (the Kademlia-seeded
    // branch operators configure), C with a plain one (the direct-dial
    // branch), covering both paths in `GossipActor::new`.
    let a_addr_with_peer_id = a_addr
        .clone()
        .with(libp2p::multiaddr::Protocol::P2p(node_a.local_peer_id));
    let (node_b, _sinks_b) = start_node(secrets[1], vec![a_addr_with_peer_id]).await;
    let (node_c, _sinks_c) = start_node(secrets[2], vec![a_addr]).await;

    assert!(
        wait_for(Duration::from_secs(30), async || {
            let peers = node_a.connected_peers().await;
            peers.contains(&pubkey(secrets[1])) && peers.contains(&pubkey(secrets[2]))
        })
        .await,
        "A never connected to both B and C; A sees {:?}",
        node_a
            .connected_peers()
            .await
            .iter()
            .map(Ed25519PublicKey::to_bytes)
            .collect::<Vec<_>>()
    );
    drop((node_a, node_b, node_c));
}

#[tokio::test]
async fn transaction_submitted_to_one_node_reaches_others() {
    let secrets = [[20; 32], [21; 32], [22; 32]];
    let (node_a, _sinks_a) = start_node(secrets[0], vec![]).await;
    let a_addr = node_a.listen_addrs[0].clone();
    let (node_b, mut sinks_b) = start_node(secrets[1], vec![a_addr.clone()]).await;
    let (node_c, mut sinks_c) = start_node(secrets[2], vec![a_addr]).await;

    assert!(
        wait_for(Duration::from_secs(30), async || {
            let peers = node_a.connected_peers().await;
            peers.contains(&pubkey(secrets[1])) && peers.contains(&pubkey(secrets[2]))
        })
        .await,
        "A never connected to both B and C"
    );

    let tx = valid_transaction();
    let expected_hash = tx.hash();
    node_a.publish(tx.clone());

    assert!(
        wait_for(Duration::from_secs(30), async || {
            sinks_b
                .mempool
                .pop()
                .is_some_and(|(_, received)| received.hash() == expected_hash)
        })
        .await,
        "B never received the gossiped transaction"
    );
    assert!(
        wait_for(Duration::from_secs(30), async || {
            sinks_c
                .mempool
                .pop()
                .is_some_and(|(_, received)| received.hash() == expected_hash)
        })
        .await,
        "C never received the gossiped transaction"
    );
    drop((node_a, node_b, node_c));
}

#[tokio::test]
async fn invalid_transaction_is_not_propagated() {
    // `Publish::Transaction` only carries a `LeeTransaction`, so genuinely
    // undecodable bytes are not reachable through the public API; instead we
    // publish a structurally well-formed transaction with an invalid
    // signature, which still exercises the real gossip pipeline's rejection
    // path (`evaluate_transaction`'s stateless check, then
    // `MessageAcceptance::Reject`) end-to-end.
    let secrets = [[30; 32], [31; 32]];
    let (node_a, _sinks_a) = start_node(secrets[0], vec![]).await;
    let a_addr = node_a.listen_addrs[0].clone();
    let (node_b, mut sinks_b) = start_node(secrets[1], vec![a_addr]).await;

    assert!(
        wait_for(Duration::from_secs(30), async || {
            node_a.connected_peers().await.contains(&pubkey(secrets[1]))
        })
        .await,
        "A never connected to B"
    );

    // Publish a valid transaction first and wait for it to arrive: swarm
    // connectivity alone does not mean the gossipsub mesh has grafted, and
    // without proof the link is live the absence assertion below would pass
    // vacuously.
    let valid_tx = valid_transaction();
    let valid_hash = valid_tx.hash();
    node_a.publish(valid_tx);
    assert!(
        wait_for(Duration::from_secs(30), async || {
            sinks_b
                .mempool
                .pop()
                .is_some_and(|(_, received)| received.hash() == valid_hash)
        })
        .await,
        "B never received the valid transaction; gossip link not live"
    );

    node_a.publish(invalidly_signed_transaction());

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        sinks_b.mempool.pop().is_none(),
        "an invalidly-signed transaction must not reach the mempool"
    );
    drop((node_a, node_b));
}

#[tokio::test]
async fn slash_approval_published_by_one_node_reaches_others() {
    let secrets = [[40; 32], [41; 32], [42; 32]];
    let (node_a, _sinks_a) = start_node(secrets[0], vec![]).await;
    let a_addr = node_a.listen_addrs[0].clone();
    let (node_b, mut sinks_b) = start_node(secrets[1], vec![a_addr.clone()]).await;
    let (node_c, mut sinks_c) = start_node(secrets[2], vec![a_addr]).await;

    assert!(
        wait_for(Duration::from_secs(30), async || {
            let peers = node_a.connected_peers().await;
            peers.contains(&pubkey(secrets[1])) && peers.contains(&pubkey(secrets[2]))
        })
        .await,
        "A never connected to both B and C"
    );

    let sent = approval(secrets[0], [7; 32]);
    node_a.publish_approval(sent.clone());

    assert!(
        wait_for(Duration::from_secs(30), async || {
            sinks_b.approvals.try_recv().is_ok_and(|got| got == sent)
        })
        .await,
        "B never received the gossiped approval"
    );
    assert!(
        wait_for(Duration::from_secs(30), async || {
            sinks_c.approvals.try_recv().is_ok_and(|got| got == sent)
        })
        .await,
        "C never received the gossiped approval"
    );
    drop((node_a, node_b, node_c));
}

#[tokio::test]
async fn a_system_approval_published_by_one_node_reaches_the_others() {
    use sequencer_stake_core::ed25519_dalek::{Signer as _, SigningKey};
    use system_upgrader_core::{Approval, Proposal, SystemProgramName, approval_message};

    let secrets = [[60; 32], [61; 32]];
    let (node_a, _sinks_a) = start_node(secrets[0], vec![]).await;
    let (node_b, mut sinks_b) = start_node(secrets[1], vec![node_a.listen_addrs[0].clone()]).await;
    assert!(
        wait_for(Duration::from_secs(30), async || {
            node_a.connected_peers().await.contains(&pubkey(secrets[1]))
        })
        .await,
        "A never connected to B"
    );

    let proposal = Proposal::Schedule {
        name: SystemProgramName::new(b"clock"),
        first_segment: lee::AccountId::new([9; 32]),
        image_id: [7; 8],
        immutable: false,
        activation_height: 50,
    };
    let key = SigningKey::from_bytes(&[62; 32]);
    let sent = SignedApproval {
        proposal,
        approval: Approval {
            signer: SequencerKey::new(key.verifying_key().to_bytes()).expect("valid key"),
            valid_until: 40,
            signature: key
                .sign(&approval_message(CHANNEL, &proposal, 40))
                .to_bytes()
                .to_vec(),
        },
    };
    node_a.publish_system_approval(sent.clone());

    assert!(
        wait_for(Duration::from_secs(30), async || {
            sinks_b
                .system_approvals
                .try_recv()
                .is_ok_and(|got| got == sent)
        })
        .await,
        "B never received the gossiped system approval"
    );
    drop((node_a, node_b));
}

#[tokio::test]
async fn a_channel_config_signature_reaches_the_other_nodes() {
    let secrets = [[50; 32], [51; 32], [52; 32]];
    let (node_a, _sinks_a) = start_node(secrets[0], vec![]).await;
    let a_addr = node_a.listen_addrs[0].clone();
    let (node_b, mut sinks_b) = start_node(secrets[1], vec![a_addr.clone()]).await;
    let (node_c, mut sinks_c) = start_node(secrets[2], vec![a_addr]).await;

    assert!(
        wait_for(Duration::from_secs(30), async || {
            let peers = node_a.connected_peers().await;
            peers.contains(&pubkey(secrets[1])) && peers.contains(&pubkey(secrets[2]))
        })
        .await,
        "A never connected to both B and C"
    );

    let key = Ed25519Key::from_bytes(&secrets[0]);
    let sent = Wire::Signature(Signature {
        tx_hash: [7; 32],
        signature: IndexedSignature::new(0, key.sign_payload(&[7; 32])),
    });
    node_a.publish_config(sent.clone());

    for (name, sink) in [("B", &mut sinks_b.configs), ("C", &mut sinks_c.configs)] {
        assert!(
            wait_for(Duration::from_secs(30), async || {
                sink.try_recv()
                    .is_ok_and(|got| got.encode() == sent.encode())
            })
            .await,
            "{name} never received the gossiped channel-config message"
        );
    }
    drop((node_a, node_b, node_c));
}

/// The channel-signing actor re-announces the same draft byte-identically, so
/// a verbatim re-announcement has to reach peers rather than count as a
/// duplicate.
#[tokio::test]
async fn a_re_announced_channel_config_message_reaches_the_other_node_again() {
    let secrets = [[60; 32], [61; 32]];
    let (node_a, _sinks_a) = start_node(secrets[0], vec![]).await;
    let a_addr = node_a.listen_addrs[0].clone();
    let (node_b, mut sinks_b) = start_node(secrets[1], vec![a_addr]).await;

    assert!(
        wait_for(Duration::from_secs(30), async || {
            node_a.connected_peers().await.contains(&pubkey(secrets[1]))
        })
        .await,
        "A never connected to B"
    );

    let key = Ed25519Key::from_bytes(&secrets[0]);
    let sent = Wire::Signature(Signature {
        tx_hash: [7; 32],
        signature: IndexedSignature::new(0, key.sign_payload(&[7; 32])),
    });

    for attempt in 1..=2 {
        node_a.publish_config(sent.clone());
        assert!(
            wait_for(Duration::from_secs(30), async || {
                sinks_b
                    .configs
                    .try_recv()
                    .is_ok_and(|got| got.encode() == sent.encode())
            })
            .await,
            "B never received channel-config announcement {attempt}"
        );
    }
    assert!(
        sinks_b.configs.try_recv().is_err(),
        "two publishes should deliver exactly twice"
    );
    drop((node_a, node_b));
}

/// A asks a scripted peer first, which answers `answer` only once a peer
/// holding the proof has connected; A must then get the proof from that peer
/// within the same fetch. Returns A's store.
async fn fetch_past_a_bad_answer(
    secrets: [[u8; 32]; 2],
    answer: Option<StorageCid>,
    network: &MemoryNetwork,
) -> ProofStore {
    let proof = Proof::from_inner(vec![0; 32]);
    let (node_a, sinks_a) = start_node_on(secrets[0], vec![], network.node()).await;
    let (mut requests, release) = scripted_locator_peer(node_a.listen_addrs[0].clone(), answer);
    node_a.fetch_proof(proof.digest());
    assert!(
        wait_for(Duration::from_secs(30), async || {
            if requests
                .try_recv()
                .is_ok_and(|digest| digest == proof.digest())
            {
                return true;
            }
            node_a.fetch_proof(proof.digest());
            false
        })
        .await,
        "the scripted peer never received A's request"
    );

    let (node_h, sinks_h) = start_node_on(
        secrets[1],
        vec![node_a.listen_addrs[0].clone()],
        network.node(),
    )
    .await;
    sinks_h
        .proof_objects
        .seed(&proof)
        .await
        .expect("the holder should seed the proof");
    assert!(
        wait_for(Duration::from_secs(30), async || {
            node_a.connected_peers().await.contains(&pubkey(secrets[1]))
        })
        .await,
        "A never connected to the peer holding the proof"
    );
    release
        .send(())
        .expect("the scripted peer should be running");

    assert!(
        wait_for(Duration::from_secs(30), async || {
            sinks_a.proofs.contains(&proof.digest())
        })
        .await,
        "A never fetched the proof after the bad answer"
    );
    assert_eq!(sinks_a.proofs.get(&proof.digest()), Some(proof));
    drop((node_a, node_h));
    sinks_a.proofs
}

#[tokio::test]
async fn a_missing_proof_is_fetched_from_a_peer_that_holds_it_past_a_peer_without_it() {
    fetch_past_a_bad_answer([[72; 32], [73; 32]], None, &MemoryNetwork::default()).await;
}

#[tokio::test]
async fn a_proof_that_does_not_match_the_requested_digest_is_refused() {
    let network = MemoryNetwork::default();
    let wrong = Proof::from_inner(vec![1; 32]);
    let decoy = network
        .node()
        .upload(wrong.clone().into_inner(), true)
        .await
        .expect("the decoy should store the wrong proof");

    let store = fetch_past_a_bad_answer([[74; 32], [75; 32]], Some(decoy), &network).await;

    assert!(!store.contains(&wrong.digest()));
}

/// A private transaction carrying `proof`, whose receipt verifies for nothing.
fn unprovable_private_transaction(proof: Vec<u8>) -> LeeTransaction {
    LeeTransaction::PrivacyPreserving(lee::PrivacyPreservingTransaction::new(
        lee::privacy_preserving_transaction::Message::default(),
        lee::privacy_preserving_transaction::WitnessSet::from_raw_parts(
            vec![],
            Proof::from_inner(proof),
        ),
    ))
}

/// An announcement of `tx` under the CID `node` stored its proof at.
async fn announced(tx: &LeeTransaction, node: &MemoryStorage) -> super::Announcement {
    let proof = tx.proof().expect("a private transaction").clone();
    super::Announcement {
        transaction: tx.digested(),
        locator: node.upload(proof.into_inner(), true).await.unwrap(),
    }
}

/// Admission that records what reaches the mempool.
fn recording_submit(admitted: Arc<std::sync::Mutex<Vec<LeeTransaction>>>) -> IngestSubmit {
    Arc::new(move |tx| {
        admitted.lock().unwrap().push(tx);
        Box::pin(async { Ok(()) })
    })
}

#[tokio::test]
async fn an_announcement_the_fee_screen_refuses_downloads_no_payload() {
    let network = MemoryNetwork::default();
    let tx = unprovable_private_transaction(vec![5; 64]);
    let announcement = announced(&tx, &network.node()).await;
    let locator = announcement.locator;
    let fetching = network.node();
    let objects = ProofObjects::new(
        Arc::new(fetching.clone()),
        ProofStore::new(PROOF_STORE_CAPACITY),
        Arc::new(MemoryRecords::default()),
        &LogosStorageConfig::default(),
    );
    let state = testnet_initial_state::initial_state(false);
    let refusing: AnnouncementScreen = Arc::new(move |transaction, proof_len| {
        let screened = sequencer_core::fees::screen_announced(&transaction, proof_len, &state);
        Box::pin(async move { screened.map_err(Into::into) })
    });
    let admitted = Arc::default();

    let result = super::admit_announced(
        announcement,
        libp2p::PeerId::random(),
        &objects,
        &refusing,
        &recording_submit(Arc::clone(&admitted)),
    )
    .await;

    assert!(result.unwrap_err().to_string().contains("fee"));
    assert_eq!(fetching.downloads(), 0);
    assert!(!fetching.holds(locator));
    assert!(admitted.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_announced_proof_that_does_not_verify_is_neither_admitted_nor_served() {
    let network = MemoryNetwork::default();
    let tx = unprovable_private_transaction(vec![5; 64]);
    let announcement = announced(&tx, &network.node()).await;
    let fetching = network.node();
    let objects = ProofObjects::new(
        Arc::new(fetching.clone()),
        ProofStore::new(PROOF_STORE_CAPACITY),
        Arc::new(MemoryRecords::default()),
        &LogosStorageConfig::default(),
    );
    let admitted = Arc::default();
    let locator = announcement.locator;

    let result = super::admit_announced(
        announcement,
        libp2p::PeerId::random(),
        &objects,
        &unscreened_announcements(),
        &recording_submit(Arc::clone(&admitted)),
    )
    .await;

    assert!(result.unwrap_err().to_string().contains("does not verify"));
    assert!(admitted.lock().unwrap().is_empty());
    assert_eq!(objects.locator(&tx.proof().unwrap().digest()), None);
    assert!(!fetching.holds(locator));
}

#[test]
fn a_private_transaction_is_refused_on_the_transaction_topic() {
    let data = borsh::to_vec(&unprovable_private_transaction(vec![5; 64])).unwrap();

    assert!(matches!(
        super::validation::evaluate_transaction(&data, 1 << 20),
        super::validation::TxEvaluation::Reject(reason) if reason.contains("announcements")
    ));
}

#[tokio::test]
async fn an_announcement_is_accepted_by_its_digest_form_alone_and_refused_when_public_or_too_big() {
    let node = MemoryNetwork::default().node();
    let private = announced(&unprovable_private_transaction(vec![5; 64]), &node).await;
    let public = super::Announcement {
        transaction: valid_transaction().digested(),
        locator: private.locator,
    };
    let evaluate = |announcement: &super::Announcement, max_block_size| {
        super::validation::evaluate_announcement(
            &borsh::to_vec(announcement).unwrap(),
            max_block_size,
        )
    };

    assert!(matches!(
        evaluate(&private, 1 << 20),
        super::validation::AnnouncementEvaluation::Accept(_)
    ));
    assert!(matches!(
        evaluate(&public, 1 << 20),
        super::validation::AnnouncementEvaluation::Reject(_)
    ));
    assert!(matches!(
        evaluate(&private, sequencer_core::config::BLOCK_OVERHEAD + 1),
        super::validation::AnnouncementEvaluation::Reject(_)
    ));
}

#[test]
fn a_candidate_is_taken_only_from_its_accredited_producer_and_an_approval_only_signed_by_an_accredited_key()
 {
    use sequencer_core::availability::{AvailabilityApproval, Candidate, CandidateId};

    use super::validation::{AvailabilityEvaluation, evaluate_availability};

    let producer = Ed25519Key::from_bytes(&[11; 32]);
    let approver = Ed25519Key::from_bytes(&[12; 32]);
    let block = common::test_utils::produce_dummy_block(1, None, Vec::new()).digested();
    let candidate = Candidate {
        id: CandidateId {
            producer: SequencerKey::new(producer.public_key().to_bytes()).unwrap(),
            turn_start_slot: 60,
            parent: [2; 32],
            candidate_hash: block.header.hash.0,
            locators: Vec::new(),
        },
        block,
    };
    let approval = AvailabilityApproval::sign(candidate.id.clone(), CHANNEL, &approver);
    let forged = AvailabilityApproval {
        signature: [0; 64],
        ..approval.clone()
    };
    let committee: std::collections::HashSet<[u8; 32]> = [
        producer.public_key().to_bytes(),
        approver.public_key().to_bytes(),
    ]
    .into();
    let outsiders: std::collections::HashSet<[u8; 32]> = [[0; 32]].into();
    let evaluate = |message: AvailabilityMessage,
                    keys: &std::collections::HashSet<[u8; 32]>,
                    source: [u8; 32]| {
        evaluate_availability(
            &borsh::to_vec(&message).unwrap(),
            CHANNEL,
            Some(keys),
            Some(source),
        )
    };
    let proposed = || AvailabilityMessage::Candidate(Box::new(candidate.clone()));
    let producer_key = producer.public_key().to_bytes();
    let approver_key = approver.public_key().to_bytes();

    assert!(matches!(
        evaluate(proposed(), &committee, producer_key),
        AvailabilityEvaluation::Accept(_)
    ));
    assert!(matches!(
        evaluate(proposed(), &committee, approver_key),
        AvailabilityEvaluation::Reject(_)
    ));
    assert!(matches!(
        evaluate(proposed(), &outsiders, producer_key),
        AvailabilityEvaluation::Ignore(_)
    ));
    assert!(matches!(
        evaluate(
            AvailabilityMessage::Approval(Box::new(approval.clone())),
            &committee,
            producer_key
        ),
        AvailabilityEvaluation::Accept(_)
    ));
    assert!(matches!(
        evaluate(
            AvailabilityMessage::Approval(Box::new(approval)),
            &outsiders,
            producer_key
        ),
        AvailabilityEvaluation::Ignore(_)
    ));
    assert!(matches!(
        evaluate(
            AvailabilityMessage::Approval(Box::new(forged)),
            &committee,
            producer_key
        ),
        AvailabilityEvaluation::Reject(_)
    ));
}
