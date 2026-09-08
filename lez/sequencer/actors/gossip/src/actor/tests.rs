use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context as _;
use common::transaction::LeeTransaction;
use kameo::actor::{ActorRef, Spawn as _};
use logos_blockchain_key_management_system_service::keys::{Ed25519Key, Ed25519PublicKey};
use mempool::{MemPool, MemPoolHandle};
use sequencer_core::{TransactionOrigin, config::GossipConfig};
use testnet_initial_state::{initial_pub_accounts_private_keys, initial_public_user_accounts};

use super::{GossipActor, IngestSubmit, MAILBOX_CAPACITY, peer_id_from_ed25519};
use crate::protocol::{GetConnectedPeers, PublishTransaction};

const CHANNEL: [u8; 32] = [1; 32];
const TEST_MAX_BLOCK_SIZE: u64 = 1 << 20;

/// A spawned gossip actor plus the identity captured before spawning.
struct TestNode {
    actor_ref: ActorRef<GossipActor>,
    listen_addrs: Vec<libp2p::Multiaddr>,
    local_peer_id: libp2p::PeerId,
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
            .tell(PublishTransaction(tx))
            .try_send()
            .expect("gossip mailbox should accept the publish");
    }
}

fn pubkey(secret: [u8; 32]) -> Ed25519PublicKey {
    Ed25519Key::from_bytes(&secret).public_key()
}

/// An [`IngestSubmit`] that pushes straight into `mempool` unscreened.
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
    MemPool::new(1000).1
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

async fn start_node(
    secret: [u8; 32],
    bootstrap: Vec<libp2p::Multiaddr>,
) -> (TestNode, MemPool<(TransactionOrigin, LeeTransaction)>) {
    let config = GossipConfig {
        listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        bootstrap_peers: bootstrap,
    };
    let (mempool, mempool_handle) = MemPool::new(1000);
    let actor = GossipActor::new(
        config,
        CHANNEL,
        Ed25519Key::from_bytes(&secret),
        TEST_MAX_BLOCK_SIZE,
        unscreened_mempool_submit(mempool_handle),
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
        mempool,
    )
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
        TEST_MAX_BLOCK_SIZE,
        unscreened_mempool_submit(test_mempool_handle()),
    )
    .await
    .unwrap();
    let addrs = actor.listen_addrs();
    assert!(!addrs.is_empty());
    assert!(addrs[0].to_string().contains("/udp/"));
    assert!(actor.connected_pubkeys().is_empty());
}

#[tokio::test]
async fn kill_stops_the_swarm() {
    let actor = GossipActor::new(
        test_config(),
        [1; 32],
        Ed25519Key::from_bytes(&[9; 32]),
        TEST_MAX_BLOCK_SIZE,
        unscreened_mempool_submit(test_mempool_handle()),
    )
    .await
    .unwrap();
    let actor_ref = spawn(actor);
    actor_ref.kill();
    tokio::time::timeout(Duration::from_secs(5), actor_ref.wait_for_shutdown())
        .await
        .expect("actor should stop when killed");
}

#[tokio::test]
async fn nodes_discover_each_other_via_bootstrap() {
    let secrets = [[10; 32], [11; 32], [12; 32]];
    let (node_a, _mempool_a) = start_node(secrets[0], vec![]).await;
    let a_addr = node_a.listen_addrs[0].clone();
    // B bootstraps with a `/p2p/`-suffixed address (the Kademlia-seeded
    // branch operators configure), C with a plain one (the direct-dial
    // branch), covering both paths in `GossipActor::new`.
    let a_addr_with_peer_id = a_addr
        .clone()
        .with(libp2p::multiaddr::Protocol::P2p(node_a.local_peer_id));
    let (node_b, _mempool_b) = start_node(secrets[1], vec![a_addr_with_peer_id]).await;
    let (node_c, _mempool_c) = start_node(secrets[2], vec![a_addr]).await;

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
    let (node_a, _mempool_a) = start_node(secrets[0], vec![]).await;
    let a_addr = node_a.listen_addrs[0].clone();
    let (node_b, mut mempool_b) = start_node(secrets[1], vec![a_addr.clone()]).await;
    let (node_c, mut mempool_c) = start_node(secrets[2], vec![a_addr]).await;

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
            mempool_b
                .pop()
                .is_some_and(|(_, received)| received.hash() == expected_hash)
        })
        .await,
        "B never received the gossiped transaction"
    );
    assert!(
        wait_for(Duration::from_secs(30), async || {
            mempool_c
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
    // `PublishTransaction` only carries a `LeeTransaction`, so genuinely
    // undecodable bytes are not reachable through the public API; instead we
    // publish a structurally well-formed transaction with an invalid
    // signature, which still exercises the real gossip pipeline's rejection
    // path (`evaluate_transaction`'s stateless check, then
    // `MessageAcceptance::Reject`) end-to-end.
    let secrets = [[30; 32], [31; 32]];
    let (node_a, _mempool_a) = start_node(secrets[0], vec![]).await;
    let a_addr = node_a.listen_addrs[0].clone();
    let (node_b, mut mempool_b) = start_node(secrets[1], vec![a_addr]).await;

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
            mempool_b
                .pop()
                .is_some_and(|(_, received)| received.hash() == valid_hash)
        })
        .await,
        "B never received the valid transaction; gossip link not live"
    );

    node_a.publish(invalidly_signed_transaction());

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        mempool_b.pop().is_none(),
        "an invalidly-signed transaction must not reach the mempool"
    );
    drop((node_a, node_b));
}
