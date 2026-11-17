#![expect(
    clippy::tests_outside_test_module,
    reason = "top-level test functions are conventional for integration tests"
)]

//! Demo 2: a wrapped-token bridge over the cross-zone spine.

use std::{collections::BTreeMap, time::Duration};

use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use integration_tests::{
    config::{self, SequencerPartialConfig},
    indexer_client::IndexerClient,
};
use lee::{
    AccountId, Actor, PrivateKey, PublicAccountEvidence, PublicKey, PublicTransaction,
    public_transaction::{Message, WitnessSet},
};
use sequencer_core::config::{CrossZoneConfig, CrossZonePeer, CrossZoneRoute, GenesisAction};
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder,
    config::{MultiNodeTestContextConfig, source_only_cross_zone_locking_to},
};
use tokio::test;

const DELIVERY_TIMEOUT: Duration = Duration::from_secs(600);
const INITIAL_BALANCE: u64 = 10_000_000_000;
const LOCK_AMOUNT: u128 = 30;
const RECIPIENT: [u8; 32] = [9; 32];

#[test]
async fn lock_on_zone_a_mints_wrapped_token_on_zone_b() -> Result<()> {
    let partial = SequencerPartialConfig {
        priority_fee_percent: 150,
        ..SequencerPartialConfig::default()
    };
    let channel_a = config::bedrock_channel_id();
    let channel_b = config::bedrock_channel_id_b();
    let zone_b: [u8; 32] = *channel_b.as_ref();

    let holder_key = PrivateKey::try_new([7; 32]).expect("valid key");
    let holder_id = AccountId::from(&PublicKey::new_from_private_key(&holder_key));

    let wrapped_token_id = programs::wrapped_token_account_id();
    let cross_zone = CrossZoneConfig {
        peers: vec![CrossZonePeer {
            channel_id: *channel_a.as_ref(),
            allowed_routes: vec![CrossZoneRoute {
                src_account_id: programs::bridge_lock_account_id(),
                target_account_id: wrapped_token_id,
                mint_cap: None,
            }],
            min_committee_size: 0,
            genesis_hash: None,
        }],
        lock_target_zones: Vec::new(),
        source_authority: None,
        source_governance: None,
    };

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
            .with_sequencer_partial_config(partial)
            .with_genesis(genesis_a)
            .with_cross_zone(Some(source_only_cross_zone_locking_to(vec![zone_b]))),
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

    let lock = build_lock_tx(&holder_key, holder_id, zone_b);
    seq_client_a
        .send_transaction(lock)
        .await
        .context("Failed to submit lock on zone A")?;

    let holding_id = wrapped_token_core::holding_account_id(wrapped_token_id, &RECIPIENT);

    let minted = wait_for_mint(ind_client_b, holding_id).await?;
    assert_eq!(
        minted, LOCK_AMOUNT,
        "zone B must mint exactly the locked amount"
    );

    let escrow_id = bridge_lock_core::escrow_account_id(programs::bridge_lock_account_id());
    let escrowed = seq_client_a
        .get_account(escrow_id)
        .await?
        .unwrap_or_default()
        .data
        .native_balance()
        .unwrap();
    assert_eq!(
        escrowed, LOCK_AMOUNT,
        "zone A escrow must hold the locked amount"
    );
    let remaining = seq_client_a
        .get_account(bridge_lock_core::holding_account_id(
            programs::bridge_lock_account_id(),
            &holder_id.into_value(),
        ))
        .await?
        .unwrap_or_default()
        .data
        .native_balance()
        .unwrap();
    assert_eq!(
        remaining,
        u128::from(INITIAL_BALANCE) - LOCK_AMOUNT,
        "zone A holding must be debited by the locked amount"
    );

    let ind_client_a = ctx.indexer_client_zone(channel_a).unwrap();
    let holding_id_a = bridge_lock_core::holding_account_id(
        programs::bridge_lock_account_id(),
        &holder_id.into_value(),
    );
    tokio::try_join!(
        async {
            wait_for_balance(
                ind_client_a,
                holding_id_a,
                u128::from(INITIAL_BALANCE) - LOCK_AMOUNT,
            )
            .await
            .context("zone A's indexer must reconstruct the holding from the genesis block")
        },
        async {
            wait_for_balance(ind_client_a, escrow_id, LOCK_AMOUNT)
                .await
                .context("zone A's indexer must track the escrow too")
        },
    )?;
    Ok(())
}

fn build_lock_tx(
    holder_key: &PrivateKey,
    holder_id: AccountId,
    target_zone: [u8; 32],
) -> LeeTransaction {
    let bridge_lock_id = programs::bridge_lock_account_id();
    let wrapped_token_id = programs::wrapped_token_account_id();

    let mint = wrapped_token_core::Message::Mint {
        recipient: RECIPIENT,
        amount: LOCK_AMOUNT,
    };
    let payload = borsh::to_vec(&mint).expect("serialize mint");

    let holder = Actor::new(holder_id, bridge_lock_id);
    let lock = bridge_lock_core::Message::Lock {
        amount: LOCK_AMOUNT,
        target_zone,
        target_account_id: wrapped_token_id,
        payload,
    };

    let accounts = vec![
        holder,
        Actor::new(
            bridge_lock_core::config_account_id(bridge_lock_id),
            bridge_lock_id,
        ),
        Actor::native_balance(bridge_lock_core::holding_account_id(
            programs::bridge_lock_account_id(),
            &holder_id.into_value(),
        )),
        Actor::native_balance(bridge_lock_core::escrow_account_id(bridge_lock_id)),
    ];
    let message = Message {
        admission_evidence: vec![PublicAccountEvidence::Pda {
            program: bridge_lock_id,
            seed: bridge_lock_core::escrow_seed(),
        }],
        ..Message::try_new(
            holder,
            accounts,
            BTreeMap::from([(holder_id, 0_u128.into())]),
            lock,
        )
        .expect("build lock message")
    };
    let witness = WitnessSet::for_message(&message, &[holder_key]);
    LeeTransaction::Public(PublicTransaction::new(message, witness))
}

async fn wait_for_balance(
    indexer: &IndexerClient,
    account: AccountId,
    expected: u128,
) -> Result<u128> {
    let account_id = indexer_service_protocol::AccountId {
        value: account.into_value(),
    };
    let wait = async {
        loop {
            let held = indexer_service_rpc::RpcClient::get_account(&**indexer, account_id)
                .await?
                .unwrap_or_else(|| lee::Account::default().into());
            if held.data.balance() == Some(expected) {
                return Ok::<u128, anyhow::Error>(held.data.balance().unwrap());
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    };
    tokio::time::timeout(DELIVERY_TIMEOUT, wait)
        .await
        .context("the indexer did not reach the expected balance in time")?
}

async fn wait_for_mint(indexer: &IndexerClient, holding_id: AccountId) -> Result<u128> {
    let account_id = indexer_service_protocol::AccountId {
        value: holding_id.into_value(),
    };
    let wrapped_token_id = indexer_service_protocol::AccountId {
        value: programs::wrapped_token_account_id().into_value(),
    };
    let wait = async {
        loop {
            let account = indexer_service_rpc::RpcClient::get_account(&**indexer, account_id)
                .await?
                .unwrap_or_else(|| lee::Account::default().into());
            let balance = account
                .data
                .actor_states
                .get(&wrapped_token_id)
                .map_or(0, |data| wrapped_token_core::read_balance(&data.0));
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
