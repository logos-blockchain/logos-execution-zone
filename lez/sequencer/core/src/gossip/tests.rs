use std::time::{Duration, Instant};

use common::transaction::LeeTransaction;
use kameo::actor::Spawn as _;
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use mempool::MemPool;
use sequencer_stake_core::SequencerKey;
use sequencer_storage_actor::mock::MockStorageActor;
use testnet_initial_state::{initial_pub_accounts_private_keys, initial_public_user_accounts};

use crate::{
    TransactionOrigin, config::GossipConfig, gossip::GossipNetwork, slashing::SlashRecord,
};

const CHANNEL: [u8; 32] = [1; 32];
const TEST_MAX_BLOCK_SIZE: u64 = 1 << 20;

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

async fn start_node(
    secret: [u8; 32],
    bootstrap: Vec<libp2p::Multiaddr>,
) -> (GossipNetwork, MemPool<(TransactionOrigin, LeeTransaction)>) {
    let (network, mempool, _) =
        start_slashing_node(secret, bootstrap, SlashRecord::default()).await;
    (network, mempool)
}

async fn start_slashing_node(
    secret: [u8; 32],
    bootstrap: Vec<libp2p::Multiaddr>,
    record: SlashRecord,
) -> (
    GossipNetwork,
    MemPool<(TransactionOrigin, LeeTransaction)>,
    SlashRecord,
) {
    let config = GossipConfig {
        listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        bootstrap_peers: bootstrap,
    };
    let (mempool, mempool_handle) = MemPool::new(1000);
    let network = GossipNetwork::start(
        config,
        CHANNEL,
        Ed25519Key::from_bytes(&secret),
        mempool_handle,
        TEST_MAX_BLOCK_SIZE,
        Some(record.clone()),
    )
    .await
    .expect("node should start");
    (network, mempool, record)
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
    let (node_a, _mempool_a) = start_node(secrets[0], vec![]).await;
    let a_addr = node_a.listen_addrs()[0].clone();
    // B bootstraps with a `/p2p/`-suffixed address (the Kademlia-seeded
    // branch operators configure), C with a plain one (the direct-dial
    // branch), covering both paths in `GossipNetwork::start`.
    let a_addr_with_peer_id = a_addr
        .clone()
        .with(libp2p::multiaddr::Protocol::P2p(node_a.local_peer_id()));
    let (node_b, _mempool_b) = start_node(secrets[1], vec![a_addr_with_peer_id]).await;
    let (node_c, _mempool_c) = start_node(secrets[2], vec![a_addr]).await;

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
    let (node_a, _mempool_a) = start_node(secrets[0], vec![]).await;
    let a_addr = node_a.listen_addrs()[0].clone();
    let (node_b, mut mempool_b) = start_node(secrets[1], vec![a_addr.clone()]).await;
    let (node_c, mut mempool_c) = start_node(secrets[2], vec![a_addr]).await;

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
            mempool_b
                .pop()
                .is_some_and(|(_, received)| received.hash() == expected_hash)
        })
        .await,
        "B never received the gossiped transaction"
    );
    assert!(
        wait_for(Duration::from_secs(30), || {
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
    // `TxPublisher::publish` only accepts a `LeeTransaction`, so genuinely
    // undecodable bytes are not reachable through the public API; instead we
    // publish a structurally well-formed transaction with an invalid
    // signature, which still exercises the real gossip pipeline's rejection
    // path (`evaluate_transaction`'s stateless check, then
    // `MessageAcceptance::Reject`) end-to-end.
    let secrets = [[30; 32], [31; 32]];
    let (node_a, _mempool_a) = start_node(secrets[0], vec![]).await;
    let a_addr = node_a.listen_addrs()[0].clone();
    let (node_b, mut mempool_b) = start_node(secrets[1], vec![a_addr]).await;

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
            mempool_b
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
        mempool_b.pop().is_none(),
        "an invalidly-signed transaction must not reach the mempool"
    );
    drop((node_a, node_b));
}

/// An approval this node signed reaches a peer's record over the mesh.
#[tokio::test]
async fn slash_approval_reaches_a_peer() {
    const INSCRIPTION: [u8; 32] = [7; 32];
    let offender = SequencerKey::new(pubkey([31; 32])).expect("valid key");

    let mut mock = MockStorageActor::new();
    mock.expect_handle_put_slash_record_bytes()
        .returning(|_, _| Ok(()));
    let storage = MockStorageActor::spawn(mock);

    let reporter = SlashRecord::default();
    reporter
        .attribute(&storage, INSCRIPTION, 42, offender)
        .await;

    let (node_a, _mempool_a, _) = start_slashing_node([21; 32], vec![], reporter).await;
    let (_node_b, _mempool_b, collector) =
        start_slashing_node([22; 32], node_a.bootstrap_addrs(), SlashRecord::default()).await;

    let signer = pubkey([21; 32]);
    let collected = wait_for(Duration::from_secs(60), || {
        collector
            .approvals_for(offender, INSCRIPTION)
            .iter()
            .any(|approval| approval.signer.to_bytes() == signer)
    })
    .await;
    assert!(collected, "the peer should have collected the approval");
}
