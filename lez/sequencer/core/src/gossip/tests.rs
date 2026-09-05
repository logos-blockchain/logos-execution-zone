use std::time::{Duration, Instant};

use common::transaction::LeeTransaction;
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use mempool::MemPool;
use testnet_initial_state::{initial_pub_accounts_private_keys, initial_public_user_accounts};

use logos_blockchain_core::proofs::channel_multi_sig_proof::IndexedSignature;
use sequencer_channel_config_actor::Outbound;
use tokio::sync::mpsc;

use crate::{TransactionOrigin, config::GossipConfig, gossip::GossipNetwork};

const CHANNEL: [u8; 32] = [1; 32];
const TEST_MAX_BLOCK_SIZE: u64 = 1 << 20;

/// The mempool and the channel-config receiver a started node feeds.
struct NodeSinks {
    mempool: MemPool<(TransactionOrigin, LeeTransaction)>,
    configs: mpsc::Receiver<Outbound>,
}


fn pubkey(secret: [u8; 32]) -> [u8; 32] {
    Ed25519Key::from_bytes(&secret).public_key().to_bytes()
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

async fn start_node(secret: [u8; 32], bootstrap: Vec<libp2p::Multiaddr>) -> (GossipNetwork, NodeSinks) {
    let config = GossipConfig {
        listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        bootstrap_peers: bootstrap,
    };
    let (mempool, mempool_handle) = MemPool::new(1000);
    let (config_tx, configs) = mpsc::channel(64);
    let network = GossipNetwork::start(
        config,
        CHANNEL,
        Ed25519Key::from_bytes(&secret),
        TEST_MAX_BLOCK_SIZE,
        crate::gossip::unscreened_mempool_submit(mempool_handle),
        config_tx,
    )
    .await
    .expect("node should start");
    (network, NodeSinks { mempool, configs })
}

async fn wait_for(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now()
        .checked_add(timeout)
        .expect("deadline within Instant range");
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

#[tokio::test]
async fn nodes_discover_each_other_via_bootstrap() {
    let secrets = [[10; 32], [11; 32], [12; 32]];
    let (node_a, _sinks_a) = start_node(secrets[0], vec![]).await;
    let a_addr = node_a.listen_addrs()[0].clone();
    // B bootstraps with a `/p2p/`-suffixed address (the Kademlia-seeded
    // branch operators configure), C with a plain one (the direct-dial
    // branch), covering both paths in `GossipNetwork::start`.
    let a_addr_with_peer_id = a_addr
        .clone()
        .with(libp2p::multiaddr::Protocol::P2p(node_a.local_peer_id()));
    let (node_b, _sinks_b) = start_node(secrets[1], vec![a_addr_with_peer_id]).await;
    let (node_c, _sinks_c) = start_node(secrets[2], vec![a_addr]).await;

    assert!(
        wait_for(Duration::from_secs(30), || {
            node_a.connected_peers().contains(&pubkey(secrets[1]))
                && node_a.connected_peers().contains(&pubkey(secrets[2]))
        })
        .await,
        "A never connected to both B and C; A sees {:?}",
        node_a.connected_peers()
    );
    drop((node_a, node_b, node_c));
}

#[tokio::test]
async fn transaction_submitted_to_one_node_reaches_others() {
    let secrets = [[20; 32], [21; 32], [22; 32]];
    let (node_a, _sinks_a) = start_node(secrets[0], vec![]).await;
    let a_addr = node_a.listen_addrs()[0].clone();
    let (node_b, mut sinks_b) = start_node(secrets[1], vec![a_addr.clone()]).await;
    let (node_c, mut sinks_c) = start_node(secrets[2], vec![a_addr]).await;

    assert!(
        wait_for(Duration::from_secs(30), || {
            node_a.connected_peers().contains(&pubkey(secrets[1]))
                && node_a.connected_peers().contains(&pubkey(secrets[2]))
        })
        .await,
        "A never connected to both B and C"
    );

    let tx = valid_transaction();
    let expected_hash = tx.hash();
    node_a.tx_publisher().publish(tx.clone());

    assert!(
        wait_for(Duration::from_secs(30), || {
            sinks_b.mempool
                .pop()
                .is_some_and(|(_, received)| received.hash() == expected_hash)
        })
        .await,
        "B never received the gossiped transaction"
    );
    assert!(
        wait_for(Duration::from_secs(30), || {
            sinks_c.mempool
                .pop()
                .is_some_and(|(_, received)| received.hash() == expected_hash)
        })
        .await,
        "C never received the gossiped transaction"
    );
    drop((node_a, node_b, node_c));
}

#[tokio::test]
async fn a_channel_config_signature_reaches_the_other_nodes() {
    let secrets = [[40; 32], [41; 32], [42; 32]];
    let (node_a, _sinks_a) = start_node(secrets[0], vec![]).await;
    let a_addr = node_a.listen_addrs()[0].clone();
    let (node_b, mut sinks_b) = start_node(secrets[1], vec![a_addr.clone()]).await;
    let (node_c, mut sinks_c) = start_node(secrets[2], vec![a_addr]).await;

    assert!(
        wait_for(Duration::from_secs(30), || {
            node_a.connected_peers().contains(&pubkey(secrets[1]))
                && node_a.connected_peers().contains(&pubkey(secrets[2]))
        })
        .await,
        "A never connected to both B and C"
    );

    let key = Ed25519Key::from_bytes(&secrets[0]);
    let sent = Outbound::Signature(sequencer_channel_config_actor::PeerSignature {
        tx_hash: [7; 32],
        signature: IndexedSignature::new(0, key.sign_payload(&[7; 32])),
    });
    node_a
        .config_publisher()
        .send(sent.clone())
        .await
        .expect("the config channel should accept a publish");

    for (name, sink) in [("B", &mut sinks_b.configs), ("C", &mut sinks_c.configs)] {
        assert!(
            wait_for(Duration::from_secs(30), || {
                sink.try_recv()
                    .is_ok_and(|got| got.encode() == sent.encode())
            })
            .await,
            "{name} never received the gossiped channel-config message"
        );
    }
    drop((node_a, node_b, node_c));
}

#[tokio::test]
async fn invalid_transaction_is_not_propagated() {
    // `TxPublisher::publish` only accepts a `LeeTransaction`, so genuinely
    // undecodable bytes are not reachable through the public API; instead we
    // publish a structurally well-formed transaction with an invalid
    // signature, which still exercises the real gossip pipeline's rejection
    // path (`evaluate_transaction`'s stateless check, then
    // `MessageAcceptance::Reject`) end-to-end.
    let secrets = [[30; 32], [31; 32]];
    let (node_a, _sinks_a) = start_node(secrets[0], vec![]).await;
    let a_addr = node_a.listen_addrs()[0].clone();
    let (node_b, mut sinks_b) = start_node(secrets[1], vec![a_addr]).await;

    assert!(
        wait_for(Duration::from_secs(30), || {
            node_a.connected_peers().contains(&pubkey(secrets[1]))
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
    node_a.tx_publisher().publish(valid_tx);
    assert!(
        wait_for(Duration::from_secs(30), || {
            sinks_b.mempool
                .pop()
                .is_some_and(|(_, received)| received.hash() == valid_hash)
        })
        .await,
        "B never received the valid transaction; gossip link not live"
    );

    node_a
        .tx_publisher()
        .publish(invalidly_signed_transaction());

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        sinks_b.mempool.pop().is_none(),
        "an invalidly-signed transaction must not reach the mempool"
    );
    drop((node_a, node_b));
}
