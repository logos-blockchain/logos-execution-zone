#![expect(
    clippy::tests_outside_test_module,
    reason = "top-level test functions are conventional for integration tests"
)]

//! End-to-end proof that a program which is not a builtin can emit across
//! zones: `zone_chat` is deployed at runtime on zone A, zone B registers it as
//! an emitter, and a top-level `Post` on A is delivered on B.
//!
//! One deployment and one finality wait, with the builtin `ping_receiver`
//! receiving: the guest's own receiving half and the registry's negative half
//! are covered faster elsewhere. It needs minutes of healthy finality, so a
//! stalling node fails it; the error reports zone B's dead letters to tell that
//! apart from a cross-zone defect.

use std::{collections::BTreeMap, time::Duration};

use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use integration_tests::{
    config::{self, SequencerPartialConfig},
    utils::wait_until,
};
use lee::{
    AccountId, Actor, PrivateKey, PublicKey, PublicTransaction,
    public_transaction::{Message, WitnessSet},
};
use logos_blockchain_core::mantle::ops::channel::ChannelId;
use ping_core::{ReceiverMessage, ping_record_pda, receiver_config_account_id};
use program_loader_core::MAX_SEGMENT_DATA_LEN;
use sequencer_core::config::{CrossZoneConfig, CrossZonePeer, CrossZoneRoute};
use sequencer_service_rpc::{RpcClient as _, SequencerClient};
use test_fixtures::{
    MultiZoneTestContextBuilder, TestContext, ZoneTestContextBuilder,
    config::{MultiNodeTestContextConfig, source_only_cross_zone},
};
use test_guest_core::chat::{ChatMessage, CrossZoneEmission};
use testnet_initial_state::initial_pub_accounts_private_keys;
use tokio::test;
use wallet::{WalletCore, program_facades::program_loader::ProgramLoader};

/// 600s like the other finality-bound cross-zone suites, plus a deployment.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(600);
const CHAT_PAYLOAD: &[u8] = b"hello-any-program";

/// A deterministic deploy-header seed, so zone B's config can name zone A's
/// emitter before either zone exists; segment seeds offset its last byte.
const fn header_seed(tag: u8) -> [u8; 32] {
    let mut seed = [tag; 32];
    seed[31] = 0;
    seed
}

fn key_of(seed: [u8; 32]) -> PrivateKey {
    PrivateKey::try_new(seed).expect("valid key")
}

fn account_of(seed: [u8; 32]) -> AccountId {
    AccountId::from(&PublicKey::new_from_private_key(&key_of(seed)))
}

/// Imports `seed`'s key so the loader can sign for the account.
fn imported_account(wallet: &mut WalletCore<SequencerClient>, seed: [u8; 32]) -> AccountId {
    let account_id = account_of(seed);
    wallet
        .storage_mut()
        .key_chain_mut()
        .add_imported_public_account(key_of(seed));
    account_id
}

/// Deploys the chat guest under `header_seed`'s account, fees paid by the
/// zone's funded account.
async fn deploy_chat(
    ctx: &mut TestContext,
    channel: ChannelId,
    header_seed: [u8; 32],
) -> Result<AccountId> {
    let payer = initial_pub_accounts_private_keys().swap_remove(0);
    let payer_id = payer.account_id;
    let program = test_programs::zone_chat();
    // Segments hold `user_elf` alone, the kernel is re-attached on read.
    let segment_count = program
        .user_elf()
        .expect("a test program decodes")
        .len()
        .div_ceil(MAX_SEGMENT_DATA_LEN);

    let wallet = ctx.wallet_mut_zone(channel).expect("the zone has a wallet");
    wallet
        .storage_mut()
        .key_chain_mut()
        .add_imported_public_account(payer.pub_sign_key);
    let header = imported_account(wallet, header_seed);
    let mut segments = Vec::new();
    for index in 1..=segment_count {
        let mut seed = header_seed;
        seed[31] = u8::try_from(index).expect("test programs stay under 255 segments");
        segments.push(imported_account(wallet, seed));
    }

    ProgramLoader(ctx.wallet_zone(channel).expect("the zone has a wallet"))
        .deploy(
            header,
            &segments,
            program.elf().to_vec(),
            true,
            Some(payer_id),
        )
        .await
}

/// A top-level `Post` to `ping_receiver` on `target_zone`. Declaring it is the
/// whole send: the watcher reads the emission off this instruction.
fn post_tx(
    emitter: AccountId,
    target_zone: [u8; 32],
    text: &[u8],
    payer: &testnet_initial_state::PublicAccountPrivateInitialData,
    nonce: lee_core::account::Nonce,
) -> LeeTransaction {
    let receiver = programs::ping_receiver_account_id();
    let root = Actor::new(emitter, emitter);
    let message = Message::try_new_with_fees(
        root,
        vec![root],
        BTreeMap::from([(payer.account_id, nonce)]),
        ChatMessage::post(CrossZoneEmission {
            target_zone,
            target_account_id: receiver,
            target_accounts: vec![
                Actor::new(receiver_config_account_id(receiver), receiver),
                Actor::new(ping_record_pda(receiver), receiver),
            ],
            payload: borsh::to_vec(&ReceiverMessage::Record {
                payload: text.to_vec(),
            })
            .expect("a Record payload serializes"),
            ordinal: 0,
        }),
        common::test_utils::test_fee_declaration(payer.account_id),
    )
    .expect("build Post message");
    let witness = WitnessSet::for_message(&message, &[&payer.pub_sign_key]);
    LeeTransaction::Public(PublicTransaction::new(message, witness))
}

/// `account`'s next nonce on `client`'s zone.
async fn account_nonce(
    client: &SequencerClient,
    account: AccountId,
) -> Result<lee_core::account::Nonce> {
    Ok(client.get_accounts_nonces(vec![account]).await?[0])
}

/// Submits `tx` and waits until the sequencer reports it in a block.
async fn submit_and_wait(client: &SequencerClient, what: &str, tx: LeeTransaction) -> Result<()> {
    let tx_hash = client
        .send_transaction(tx)
        .await
        .with_context(|| format!("Failed to submit {what}"))?;
    wait_until(&format!("{what} to be included"), || async {
        Ok(client.get_transaction(tx_hash).await?.is_some())
    })
    .await
}

/// Polls zone B until the builtin receiver's record holds the posted text.
async fn wait_for_delivery(client: &SequencerClient) -> Result<()> {
    let receiver = programs::ping_receiver_account_id();
    let record = ping_record_pda(receiver);
    let wait = async {
        loop {
            let account = client.get_account(record).await?.unwrap_or_default();
            if account.data.actor_state(receiver).as_ref() == CHAT_PAYLOAD {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    };
    if tokio::time::timeout(DELIVERY_TIMEOUT, wait).await.is_err() {
        // A dead letter means the receiver refused it; none means nothing was
        // ever recognized.
        let dead_letters = client.get_cross_zone_dead_letters().await?;
        anyhow::bail!(
            "zone B did not record the registered emitter's message in time; dead letters retired {} retained {}",
            dead_letters.total_retired,
            dead_letters.retained.len()
        );
    }
    Ok(())
}

#[test]
async fn a_registered_program_sends_and_receives_across_zones() -> Result<()> {
    let partial = SequencerPartialConfig::default();
    let channel_a = config::bedrock_channel_id();
    let channel_b = config::bedrock_channel_id_b();
    let zone_a: [u8; 32] = *channel_a.as_ref();
    let zone_b: [u8; 32] = *channel_b.as_ref();

    let chat_a = account_of(header_seed(0xA1));

    // The route seeds (zone_a, chat_a) into the receiver's sources at genesis,
    // exactly as it would for a builtin emitter.
    let cross_zone_b = CrossZoneConfig {
        lock_target_zones: Vec::new(),
        peers: vec![CrossZonePeer {
            channel_id: zone_a,
            allowed_routes: vec![CrossZoneRoute {
                src_account_id: chat_a,
                target_account_id: programs::ping_receiver_account_id(),
                mint_cap: None,
            }],
            min_committee_size: 0,
            genesis_hash: None,
        }],
        source_authority: None,
        source_governance: None,
    };

    let mut ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig {
                num_nodes: 1,
                bedrock_channel: channel_a,
            })
            .disable_indexer()
            .with_sequencer_partial_config(partial)
            .with_genesis(vec![])
            .with_cross_zone(Some(source_only_cross_zone())),
        )
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig {
                num_nodes: 1,
                bedrock_channel: channel_b,
            })
            .disable_indexer()
            .with_sequencer_partial_config(partial)
            .with_genesis(vec![])
            .with_cross_zone(Some(cross_zone_b)),
        )
        .build()
        .await?;

    // Host the emitter: one runtime deployment through the program loader.
    assert_eq!(
        deploy_chat(&mut ctx, channel_a, header_seed(0xA1)).await?,
        chat_a
    );

    let seq_a = &ctx
        .zone_default_sequencer_component(channel_a)
        .sequencer_client;
    let seq_b = &ctx
        .zone_default_sequencer_component(channel_b)
        .sequencer_client;

    let payer = initial_pub_accounts_private_keys().swap_remove(0);
    let post_nonce = account_nonce(seq_a, payer.account_id).await?;
    submit_and_wait(
        seq_a,
        "the registered Post",
        post_tx(chat_a, zone_b, CHAT_PAYLOAD, &payer, post_nonce),
    )
    .await?;

    wait_for_delivery(seq_b).await?;
    Ok(())
}
