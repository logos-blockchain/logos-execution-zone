#![expect(
    clippy::tests_outside_test_module,
    reason = "top-level test functions are conventional for integration tests"
)]

//! Demo 2: a wrapped-token bridge over the cross-zone spine. A holder locks part
//! of their bridgeable balance on zone A; the watcher carries the emitted mint to
//! zone B, where the indexer re-derives and verifies it (Option B) before the
//! wrapped token is minted to the recipient. Reuses the M3/M4 spine unchanged;
//! only the source caller (`bridge_lock`) and target (`wrapped_token`) are new.
//!
//! A `ping_sender` send carrying a `wrapped_token::Mint` is refused as long as no
//! operator writes a `(ping_sender, wrapped_token)` route: the allowlist is a
//! source-and-target pair. Nothing forbids writing that route, and the token
//! still trusts the table rather than checking its own sources, which is #673.

use std::time::Duration;

use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use cross_zone_outbox_core::outbox_pda;
use integration_tests::{
    config::{self, SequencerPartialConfig},
    indexer_client::IndexerClient,
};
use lee::{
    AccountId, PrivateKey, PublicKey, PublicTransaction,
    public_transaction::{Message, WitnessSet},
};
use sequencer_core::config::{CrossZoneConfig, CrossZonePeer, CrossZoneRoute, GenesisAction};
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder, config::MultiNodeTestContextConfig,
};
use tokio::test;

const DELIVERY_TIMEOUT: Duration = Duration::from_secs(600);
const INITIAL_BALANCE: u128 = 100;
const LOCK_AMOUNT: u128 = 30;
const RECIPIENT: [u8; 32] = [9; 32];

#[test]
async fn lock_on_zone_a_mints_wrapped_token_on_zone_b() -> Result<()> {
    let partial = SequencerPartialConfig::default();
    let channel_a = config::bedrock_channel_id();
    let channel_b = config::bedrock_channel_id_b();
    let zone_b: [u8; 32] = *channel_b.as_ref();

    let holder_key = PrivateKey::try_new([7; 32]).expect("valid key");
    let holder_id = AccountId::from(&PublicKey::new_from_private_key(&holder_key));

    let wrapped_token_id = programs::wrapped_token().id();
    let cross_zone = CrossZoneConfig {
        peers: vec![CrossZonePeer {
            channel_id: *channel_a.as_ref(),
            allowed_routes: vec![CrossZoneRoute {
                src_account_id: loader_core::immutable_deploy_account_id(
                    programs::bridge_lock().id(),
                ),
                target_program_id: wrapped_token_id,
            }],
            expected_block_signing_pubkey: None,
        }],
    };

    // Zone A seeds the holder's bridgeable balance. Zone B runs the watcher on its
    // sequencer and the verifier on its indexer.
    let genesis_a = vec![GenesisAction::SupplyBridgeLockHolding {
        holder: holder_id,
        amount: INITIAL_BALANCE,
    }];

    let ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig {
                num_nodes: 1,
                bedrock_channel: channel_a,
            })
            .disable_wallet()
            .disable_indexer()
            .with_sequencer_partial_config(partial)
            .with_genesis(genesis_a),
        )
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig {
                num_nodes: 1,
                bedrock_channel: channel_b,
            })
            .disable_wallet()
            .with_sequencer_partial_config(partial)
            .with_genesis(vec![])
            .with_cross_zone(Some(cross_zone)),
        )
        .build()
        .await?;

    let seq_client_a = &ctx
        .zone_default_sequencer_component(channel_a)
        .sequencer_client;

    let ind_client_b = ctx.indexer_client_zone(channel_b).unwrap();

    // Lock LOCK_AMOUNT on zone A, addressed to the recipient on zone B.
    let lock = build_lock_tx(&holder_key, holder_id, zone_b);
    seq_client_a
        .send_transaction(lock)
        .await
        .context("Failed to submit lock on zone A")?;

    // Wait until zone B's indexer reflects the verified mint.
    let holding_id = wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT);

    let minted = wait_for_mint(ind_client_b, holding_id).await?;
    assert_eq!(
        minted, LOCK_AMOUNT,
        "zone B must mint exactly the locked amount"
    );

    // Conservation: the mint on B must be backed by an equal lock on A. The lock
    // has already landed (it preceded delivery), so zone A reflects the debit and
    // escrow now.
    let escrow_id = bridge_lock_core::escrow_account_id(programs::bridge_lock().id());
    let escrowed = seq_client_a.get_account(escrow_id).await?.balance;
    assert_eq!(
        escrowed, LOCK_AMOUNT,
        "zone A escrow must hold the locked amount"
    );
    let remaining = seq_client_a.get_account(holder_id).await?.balance;
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
        self_program_id: wrapped_token_id,
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
        self_program_id: bridge_lock_id,
        amount: LOCK_AMOUNT,
        target_zone,
        target_program_id: wrapped_token_id,
        target_accounts,
        payload,
        ordinal,
    };

    let accounts = vec![
        bridge_lock_core::config_account_id(bridge_lock_id),
        holder_id,
        bridge_lock_core::escrow_account_id(bridge_lock_id),
        outbox_pda(
            outbox_id,
            loader_core::immutable_deploy_account_id(bridge_lock_id),
            &target_zone,
            ordinal,
        ),
    ];
    // One nonce per signature: the holder signs, at its genesis nonce 0.
    let message = Message::try_new(
        loader_core::immutable_deploy_account_id(bridge_lock_id),
        accounts,
        vec![0_u128.into()],
        lock,
    )
    .expect("build lock message");
    let witness = WitnessSet::for_message(&message, &[holder_key]);
    LeeTransaction::Public(PublicTransaction::new(message, witness))
}

/// Polls zone B's indexer until the recipient's wrapped holding is non-zero.
async fn wait_for_mint(indexer: &IndexerClient, holding_id: AccountId) -> Result<u128> {
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
    tokio::time::timeout(DELIVERY_TIMEOUT, wait)
        .await
        .context("Zone B's indexer did not mint the wrapped token in time")?
}
