#![expect(
    clippy::tests_outside_test_module,
    reason = "top-level test functions are conventional for integration tests"
)]

//! Live-testnet variant of the cross-zone wrapped-token bridge demo: two zones
//! settle on the REAL shared testnet Bedrock node
//! (`testnet.blockchain.logos.co:18080`, unauthenticated) instead of a local
//! throwaway node.
//!
//! Two scenarios, each ignored by default (they hit a live network and cost
//! faucet-funded Bedrock fees). Run via the `just` targets.
//!
//! - `lock_on_zone_a_mints_wrapped_token_on_zone_b_testnet` (happy path): a
//!   holder locks part of a genesis-seeded bridgeable balance on zone A; the
//!   watcher carries the mint to zone B, whose indexer verifies and mints the
//!   wrapped token to the recipient.
//! - `lock_without_route_is_refused_on_zone_b_testnet` (negative): the same lock,
//!   but zone B's inbox is not configured to allow the `bridge_lock ->
//!   wrapped_token` route. Zone A still locks (value moves into escrow on A), but
//!   zone B's watcher drops the message ("no route from that source program to
//!   that target") and nothing is minted on B. Shows the destination zone's
//!   authorization gate refusing an unauthorized crossing.
//!
//! Why genesis-seed the lockable balance rather than a live L1 deposit: in this
//! release a Bedrock deposit lands in a vault PDA owned by the vault program,
//! while `bridge_lock::Lock` can only debit a bridge_lock-owned holding keyed by
//! the holder id, and no runtime instruction bridges the two. So the lockable
//! balance is seeded at zone-A genesis; everything else is real.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use cross_zone_outbox_core::outbox_pda;
use integration_tests::{
    config::{self, SequencerPartialConfig},
    indexer_client::IndexerClient,
    setup::{SequencerSetup, indexer_client, sequencer_client, setup_indexer},
};
use lee::{
    AccountId, PrivateKey, PublicKey, PublicTransaction,
    public_transaction::{Message, WitnessSet},
};
use sequencer_core::config::{CrossZoneConfig, CrossZonePeer, CrossZoneRoute, GenesisAction};
use sequencer_service_rpc::RpcClient as _;
use tokio::test;

/// The live testnet Bedrock node's raw, unauthenticated HTTP API.
const TESTNET_BEDROCK_ADDR: &str = "65.109.51.37:18080";
/// Longer than the local test: the real Bedrock finalizes on its own cadence.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(1200);
/// How long to watch for a mint that must NOT happen (negative case), chosen well
/// above the happy path's typical delivery time so a still-zero holding is
/// convincing rather than merely slow.
const NON_DELIVERY_WINDOW: Duration = Duration::from_secs(240);
const INITIAL_BALANCE: u128 = 100;
const LOCK_AMOUNT: u128 = 30;
const RECIPIENT: [u8; 32] = [9; 32];
const ZONE_A_SIGNING_KEY: [u8; 32] = [0xA1; 32];
const ZONE_B_SIGNING_KEY: [u8; 32] = [0xB2; 32];

#[test]
#[ignore = "hits the live testnet Bedrock; run via just demo-cross-zone-bridge-testnet"]
async fn lock_on_zone_a_mints_wrapped_token_on_zone_b_testnet() -> Result<()> {
    let bedrock_addr = TESTNET_BEDROCK_ADDR
        .parse()
        .context("Failed to parse testnet Bedrock address")?;
    let funding_key = config::testnet_faucet_funding_key();
    let partial = SequencerPartialConfig::default();
    let (seed_a, seed_b) = unique_channel_seeds();
    let channel_a = config::channel_id_from_bytes(seed_a);
    let channel_b = config::channel_id_from_bytes(seed_b);
    let zone_b: [u8; 32] = *channel_b.as_ref();

    let holder_key = PrivateKey::try_new([7; 32]).expect("valid key");
    let holder_id = AccountId::from(&PublicKey::new_from_private_key(&holder_key));

    let wrapped_token_id = programs::wrapped_token().id();
    // Zone B authorizes the bridge_lock -> wrapped_token route from zone A.
    let cross_zone = CrossZoneConfig {
        peers: vec![CrossZonePeer {
            channel_id: *channel_a.as_ref(),
            allowed_routes: vec![CrossZoneRoute {
                src_program_id: programs::bridge_lock().id(),
                target_program_id: wrapped_token_id,
            }],
            expected_block_signing_pubkey: None,
        }],
    };

    let genesis_a = vec![GenesisAction::SupplyBridgeLockHolding {
        holder: holder_id,
        amount: INITIAL_BALANCE,
    }];
    let (seq_a, _seq_a_home) = SequencerSetup::new(partial, bedrock_addr)
        .with_channel_id(channel_a)
        .with_funding_key(funding_key)
        .with_bedrock_signing_key(ZONE_A_SIGNING_KEY)
        .with_genesis(genesis_a)
        .setup()
        .await
        .context("Failed to set up zone A sequencer")?;
    let (_seq_b, _seq_b_home) = SequencerSetup::new(partial, bedrock_addr)
        .with_channel_id(channel_b)
        .with_funding_key(funding_key)
        .with_bedrock_signing_key(ZONE_B_SIGNING_KEY)
        .with_genesis(vec![])
        .with_cross_zone(cross_zone.clone())
        .setup()
        .await
        .context("Failed to set up zone B sequencer")?;
    let (idx_b, _idx_b_home) = setup_indexer(bedrock_addr, channel_b, Some(cross_zone))
        .await
        .context("Failed to set up zone B indexer")?;

    // Lock LOCK_AMOUNT on zone A, addressed to the recipient on zone B.
    let lock = build_lock_tx(&holder_key, holder_id, zone_b);
    sequencer_client(seq_a.addr())?
        .send_transaction(lock)
        .await
        .context("Failed to submit lock on zone A")?;

    // Zone B mints the wrapped token to the recipient.
    let holding_id = wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT);
    let indexer = indexer_client(idx_b.addr())
        .await
        .context("Failed to build indexer client")?;
    let minted = wait_for_mint(&indexer, holding_id, DELIVERY_TIMEOUT).await?;
    assert_eq!(
        minted, LOCK_AMOUNT,
        "zone B must mint exactly the locked amount"
    );

    assert_lock_landed_on_zone_a(seq_a.addr(), holder_id).await?;
    Ok(())
}

#[test]
#[ignore = "hits the live testnet Bedrock; run via just demo-cross-zone-bridge-testnet-unauthorized"]
async fn lock_without_route_is_refused_on_zone_b_testnet() -> Result<()> {
    let bedrock_addr = TESTNET_BEDROCK_ADDR
        .parse()
        .context("Failed to parse testnet Bedrock address")?;
    let funding_key = config::testnet_faucet_funding_key();
    let partial = SequencerPartialConfig::default();
    let (seed_a, seed_b) = unique_channel_seeds();
    let channel_a = config::channel_id_from_bytes(seed_a);
    let channel_b = config::channel_id_from_bytes(seed_b);
    let zone_b: [u8; 32] = *channel_b.as_ref();

    let holder_key = PrivateKey::try_new([7; 32]).expect("valid key");
    let holder_id = AccountId::from(&PublicKey::new_from_private_key(&holder_key));

    let wrapped_token_id = programs::wrapped_token().id();
    // The mistake: zone B declares the peer but authorizes NO routes, so the
    // bridge_lock -> wrapped_token crossing is not permitted. The watcher drops
    // the message ("no route from that source program to that target").
    let cross_zone = CrossZoneConfig {
        peers: vec![CrossZonePeer {
            channel_id: *channel_a.as_ref(),
            allowed_routes: vec![],
            expected_block_signing_pubkey: None,
        }],
    };

    let genesis_a = vec![GenesisAction::SupplyBridgeLockHolding {
        holder: holder_id,
        amount: INITIAL_BALANCE,
    }];
    let (seq_a, _seq_a_home) = SequencerSetup::new(partial, bedrock_addr)
        .with_channel_id(channel_a)
        .with_funding_key(funding_key)
        .with_bedrock_signing_key(ZONE_A_SIGNING_KEY)
        .with_genesis(genesis_a)
        .setup()
        .await
        .context("Failed to set up zone A sequencer")?;
    let (_seq_b, _seq_b_home) = SequencerSetup::new(partial, bedrock_addr)
        .with_channel_id(channel_b)
        .with_funding_key(funding_key)
        .with_bedrock_signing_key(ZONE_B_SIGNING_KEY)
        .with_genesis(vec![])
        .with_cross_zone(cross_zone.clone())
        .setup()
        .await
        .context("Failed to set up zone B sequencer")?;
    let (idx_b, _idx_b_home) = setup_indexer(bedrock_addr, channel_b, Some(cross_zone))
        .await
        .context("Failed to set up zone B indexer")?;

    // The lock on zone A still succeeds: it is a zone-A operation, independent of
    // zone B's configuration.
    let lock = build_lock_tx(&holder_key, holder_id, zone_b);
    sequencer_client(seq_a.addr())?
        .send_transaction(lock)
        .await
        .context("Failed to submit lock on zone A")?;
    assert_lock_landed_on_zone_a(seq_a.addr(), holder_id).await?;

    // Zone B must NOT mint: the watcher drops the unauthorized message. Watch a
    // window comfortably longer than a normal delivery, then confirm still zero.
    let holding_id = wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT);
    let indexer = indexer_client(idx_b.addr())
        .await
        .context("Failed to build indexer client")?;
    match wait_for_mint(&indexer, holding_id, NON_DELIVERY_WINDOW).await {
        Err(_timed_out) => Ok(()), // Expected: no mint within the window.
        Ok(minted) => anyhow::bail!(
            "zone B minted {minted} despite no authorized route; the gate did not hold"
        ),
    }
}

/// A fresh, unique channel-id pair for this run: the seed is the wall-clock nanos
/// plus pid, with the last byte distinguishing zone A from zone B. A fresh
/// sequencer must never resume a Bedrock channel that already carries an earlier
/// run's blocks (its persisted checkpoint would not match), so every run mints a
/// new channel pair.
fn unique_channel_seeds() -> ([u8; 32], [u8; 32]) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let pid = std::process::id();
    let mut seed = [0_u8; 32];
    seed[0..16].copy_from_slice(&nanos.to_le_bytes());
    seed[16..20].copy_from_slice(&pid.to_le_bytes());
    let mut a = seed;
    let mut b = seed;
    a[31] = 0x0A;
    b[31] = 0x0B;
    (a, b)
}

/// Conservation on zone A: the escrow holds the locked amount and the holder is
/// debited by it. True whether or not zone B ever mints.
async fn assert_lock_landed_on_zone_a(
    seq_a_addr: std::net::SocketAddr,
    holder_id: AccountId,
) -> Result<()> {
    let seq_a_client = sequencer_client(seq_a_addr)?;
    let escrow_id = bridge_lock_core::escrow_account_id(programs::bridge_lock().id());
    let escrowed = seq_a_client.get_account(escrow_id).await?.balance;
    assert_eq!(
        escrowed, LOCK_AMOUNT,
        "zone A escrow must hold the locked amount"
    );
    let remaining = seq_a_client.get_account(holder_id).await?.balance;
    assert_eq!(
        remaining,
        INITIAL_BALANCE - LOCK_AMOUNT,
        "zone A holder must be debited by the locked amount"
    );
    Ok(())
}

/// Builds a signed `bridge_lock` Lock that forwards a wrapped-token Mint of the
/// locked amount to the recipient on the target zone.
fn build_lock_tx(
    holder_key: &PrivateKey,
    holder_id: AccountId,
    target_zone: [u8; 32],
) -> LeeTransaction {
    let bridge_lock_id = programs::bridge_lock().id();
    let wrapped_token_id = programs::wrapped_token().id();
    let outbox_id = programs::cross_zone_outbox().id();
    let ordinal = 0;

    let mint = wrapped_token_core::Instruction::Mint {
        recipient: RECIPIENT,
        amount: LOCK_AMOUNT,
    };
    let words = risc0_zkvm::serde::to_vec(&mint).expect("serialize mint");
    let payload: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();

    let target_accounts = vec![
        wrapped_token_core::config_account_id(wrapped_token_id).into_value(),
        wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT).into_value(),
    ];
    let lock = bridge_lock_core::Instruction::Lock {
        amount: LOCK_AMOUNT,
        target_zone,
        target_program_id: wrapped_token_id,
        target_accounts,
        payload,
        outbox_program_id: outbox_id,
        ordinal,
    };

    let accounts = vec![
        holder_id,
        bridge_lock_core::escrow_account_id(bridge_lock_id),
        outbox_pda(outbox_id, &target_zone, ordinal),
    ];
    // One nonce per signature: the holder signs, at its genesis nonce 0.
    let message = Message::try_new(bridge_lock_id, accounts, vec![0_u128.into()], lock)
        .expect("build lock message");
    let witness = WitnessSet::for_message(&message, &[holder_key]);
    LeeTransaction::Public(PublicTransaction::new(message, witness))
}

/// Polls zone B's indexer until the recipient's wrapped holding is non-zero, or
/// `timeout` elapses.
async fn wait_for_mint(
    indexer: &IndexerClient,
    holding_id: AccountId,
    timeout: Duration,
) -> Result<u128> {
    let account_id = indexer_service_protocol::AccountId {
        value: holding_id.into_value(),
    };
    let wait = async {
        loop {
            let account =
                indexer_service_rpc::RpcClient::get_account(&**indexer, account_id).await?;
            let balance = wrapped_token_core::read_balance(&account.data.0);
            if balance != 0 {
                return Ok::<u128, anyhow::Error>(balance);
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    };
    tokio::time::timeout(timeout, wait)
        .await
        .context("Zone B's indexer did not mint the wrapped token in time")?
}
