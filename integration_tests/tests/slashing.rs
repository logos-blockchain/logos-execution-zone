#![expect(
    clippy::tests_outside_test_module,
    reason = "top-level test functions are conventional for integration tests"
)]

//! The follower inscribes a payload that is not a block and the leader burns
//! its stake.
//!
//! The follower never produces, so only the leader can slash it.

use std::{future::Future, time::Duration};

use anyhow::{Context as _, Result, ensure};
use integration_tests::{assert_same_chain, committee, get_account, init_logger, wait_until};
use lee::AccountId;
use log::info;
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use sequencer_core::{
    block_publisher::{BlockPublisherTrait as _, ZoneSdkPublisher},
    config::BedrockConfig,
};
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::{
    MultiZoneTestContextBuilder, TestContext, ZoneTestContextBuilder,
    config::{self, MultiNodeTestContextConfig, SequencerPartialConfig},
};
use tokio::test;

/// What genesis stakes each founding sequencer.
const STAKE: u128 = system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE;

/// Payload that never decodes as a block.
const GARBAGE: &[u8] = b"this is not a block";

/// The follower. Its Bedrock key is the seeded one, so a test can borrow it.
const OFFENDER_SEED: usize = 1;

async fn balance(ctx: &TestContext, account: AccountId) -> Result<u128> {
    Ok(get_account(ctx, account).await?.balance)
}

/// The sequencer stake config, decoded.
async fn stake_config(ctx: &TestContext) -> Result<sequencer_stake_core::SequencerStakeConfig> {
    let account = get_account(ctx, system_accounts::sequencer_stake_config_account_id())
        .await
        .context("Failed to read the sequencer stake config account")?;
    sequencer_stake_core::SequencerStakeConfig::from_bytes(account.data.as_ref())
        .context("Config account should decode as SequencerStakeConfig")
}

/// Like `wait_until` but with a longer budget, since the offender waits its turn.
async fn wait_for_slash<F, Fut>(mut check: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<bool>>,
{
    const BUDGET: Duration = Duration::from_secs(480);
    const POLL: Duration = Duration::from_secs(2);

    let wait = async {
        while !check().await? {
            tokio::time::sleep(POLL).await;
        }
        Ok::<(), anyhow::Error>(())
    };
    tokio::time::timeout(BUDGET, wait)
        .await
        .context("Timed out waiting for the leader to burn the offender's stake")?
}

#[test]
async fn a_sequencer_is_slashed_by_its_peer_for_inscribing_a_non_block() -> Result<()> {
    init_logger();

    let channel = config::bedrock_channel_id();

    // The follower never produces, so it cannot slash itself.
    let ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig {
                num_nodes: 2,
                bedrock_channel: channel,
            })
            .disable_wallet()
            .with_sequencer_partial_config(SequencerPartialConfig {
                block_create_timeout: Duration::from_secs(2),
                ..SequencerPartialConfig::default()
            })
            .with_follower_sequencer_partial_config(SequencerPartialConfig {
                block_create_timeout: Duration::from_secs(100_000),
                ..SequencerPartialConfig::default()
            }),
        )
        .build()
        .await
        .context("Failed to build the two-sequencer test context")?;

    let offender_key = Ed25519Key::from_bytes(&config::sequencer_signing_key_from_seed(
        u32::try_from(OFFENDER_SEED).context("The offender seed does not fit in a u32")?,
    ));
    let offender_stake_key =
        sequencer_stake_core::SequencerKey::new(offender_key.public_key().to_bytes())
            .context("The offender's Bedrock key is not a valid Ed25519 point")?;
    let offender_owner = config::founding_stake_owner_key(OFFENDER_SEED)?;
    let offender_account = AccountId::from(&lee::PublicKey::new_from_private_key(&offender_owner));
    let sink = sequencer_stake_core::slash_sink_account_id(programs::sequencer_stake().id());

    let bedrock_config = BedrockConfig {
        channel_id: channel,
        node_url: config::addr_to_url(config::UrlProtocol::Http, ctx.bedrock_addr())?,
        funding_key: config::bedrock_funding_key(),
        auth: None,
        priority_fee: sequencer_core::config::default_priority_fee(),
    };

    // An unaccredited key writes nothing that L1 accepts.
    wait_until("the offender's key to be accredited", || async {
        Ok(committee(&bedrock_config)
            .await?
            .0
            .contains(&offender_stake_key.to_bytes()))
    })
    .await?;
    ensure!(
        balance(&ctx, offender_account).await? == STAKE,
        "the offender should start with its genesis stake"
    );
    ensure!(
        balance(&ctx, sink).await? == 0,
        "nothing should be burned yet"
    );
    let staked_before = stake_config(&ctx)
        .await?
        .entries
        .get(&offender_stake_key)
        .context("the offender should start with a stake config entry")?
        .total_staked;
    ensure!(
        staked_before == STAKE,
        "the offender's entry should track its genesis stake, got {staked_before}"
    );

    let leader_client = ctx
        .sequencer_client_by_node_ids(channel, 0)
        .context("The leader has no sequencer client")?;
    let follower_client = ctx
        .sequencer_client_by_node_ids(channel, OFFENDER_SEED)
        .context("The follower has no sequencer client")?;
    let height_before_garbage = leader_client.get_last_block_id().await?;

    // The offender's node never publishes, so this is the only writer with its key.
    let offender = ZoneSdkPublisher::new(
        &bedrock_config,
        offender_key,
        Duration::from_secs(5),
        None,
        Box::new(|_update| {}),
    )
    .await
    .context("Failed to open a publisher for the offender")?;

    // Only admissible on the offender's turn, so keep offering.
    wait_for_slash(|| async {
        if balance(&ctx, sink).await? == STAKE {
            return Ok(true);
        }
        // L1 rejects a write out of turn, so only offer on our turn.
        if offender.is_our_turn() {
            let outcome = offender
                .publish_raw_inscription(GARBAGE.to_vec())
                .await
                .context("Failed to inscribe a non-block payload")?;
            info!("Offered a non-block payload as {}", outcome.this_msg);
        }
        Ok(false)
    })
    .await?;

    ensure!(
        balance(&ctx, offender_account).await? == 0,
        "the offender's whole tracked stake should be gone"
    );

    // A payload that is not a block never reaches chain state, so it takes no block id.
    let height_after_garbage = leader_client.get_last_block_id().await?;
    ensure!(
        height_after_garbage > height_before_garbage,
        "the leader should have produced blocks while the garbage was landing, \
         but the height stayed at {height_before_garbage}"
    );
    for id in 1..=height_after_garbage {
        ensure!(
            leader_client.get_block(id).await?.is_some(),
            "block id {id} is missing: the garbage opened a gap in the chain"
        );
    }
    assert_same_chain(leader_client, follower_client)
        .await
        .context("The two sequencers disagree about the chain after the slash")?;

    ensure!(
        !stake_config(&ctx)
            .await?
            .entries
            .contains_key(&offender_stake_key),
        "the offender's config entry should be gone"
    );

    wait_until("the offender to leave the accredited committee", || async {
        Ok(!committee(&bedrock_config)
            .await?
            .0
            .contains(&offender_stake_key.to_bytes()))
    })
    .await?;

    Ok(())
}
