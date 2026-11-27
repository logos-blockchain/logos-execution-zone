//! "Genesis follows config" checks for both the from-scratch and prebuilt `TestContext` paths.
//! Need Docker/Bedrock, like the integration tests.
#![expect(clippy::tests_outside_test_module, reason = "It's a tests module")]

use anyhow::{Context as _, Result};
use lee::test_utils::TestSigner;
use sequencer_service_rpc::RpcClient as _;
use sequencer_stake_core::SequencerStakeConfig;
use test_fixtures::{
    MultiZoneTestContextBuilder, TestContext, ZoneTestContextBuilder,
    config::{
        MultiNodeTestContextConfig, default_private_accounts_for_wallet,
        default_public_accounts_for_wallet,
    },
    verify_commitment_is_in_state,
};

/// Builds from genesis (no prebuilt database) and checks the on-chain state follows the config.
#[tokio::test]
async fn genesis_from_scratch_follows_config() -> Result<()> {
    let ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default()).from_scratch(),
        )
        .build()
        .await?;

    assert_context_follows_config(&ctx).await
}

/// Loads the prebuilt database via [`TestContext::new`] and checks the restored state follows the
/// config — i.e. the dump round-trips and all expected data persists.
#[tokio::test]
async fn prebuilt_context_follows_config() -> Result<()> {
    let ctx = TestContext::new().await?;
    assert_context_follows_config(&ctx).await
}

/// Assert every configured default account is funded with its configured balance, and every
/// configured private account's commitment is present in sequencer state. (The wallet also has an
/// unfunded default root account, so we check the configured accounts specifically.)
async fn assert_context_follows_config(ctx: &TestContext) -> Result<()> {
    for (private_key, expected_balance) in default_public_accounts_for_wallet() {
        let account_id = TestSigner::from(&private_key).account_id();
        let balance = ctx
            .sequencer_client()
            .get_account_balance(account_id)
            .await?;
        assert_eq!(
            balance, expected_balance,
            "public account {account_id} balance"
        );
    }

    let config_id = sequencer_stake_core::sequencer_stake_config_account_id(
        programs::sequencer_stake_account_id(),
    );
    let config_account = ctx
        .sequencer_client()
        .get_account(config_id)
        .await?
        .context("the sequencer-stake config account")?;
    let channel_params = SequencerStakeConfig::from_bytes(
        config_account
            .data
            .actor_state(programs::sequencer_stake_account_id())
            .as_ref(),
    )
    .context("decoding the sequencer-stake config")?
    .channel_params
    .context("genesis never ran InitChannelParams")?;
    assert_eq!(
        channel_params.posting_timeframe,
        test_fixtures::config::TEST_POSTING_TIMEFRAME,
        "the prebuilt fixture's posting_timeframe is stale; regenerate it"
    );

    for account in default_private_accounts_for_wallet() {
        let account_id = account.account_id();
        let commitment = ctx
            .wallet()
            .get_private_account_commitment(account_id)
            .with_context(|| format!("commitment for private account {account_id}"))?;
        assert!(
            verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await,
            "private commitment for {account_id} should be in sequencer state"
        );
    }

    Ok(())
}
