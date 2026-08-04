#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use indexer_service_rpc::RpcClient as _;
use integration_tests::{
    L2_TO_L1_TIMEOUT,
    config::SequencerPartialConfig,
    tf::{
        BedrockApp, BedrockCluster, IndexerApp, LezIndexerClient, LezLocalApp, LezRuntime,
        LezSequencerClient, LezWorld, SequencerApp, WalletApp,
    },
};
use sequencer_service_rpc::RpcClient as _;
use testing_framework_core::scenario::DynError;
use tokio::time::Instant;

#[tokio::test]
async fn complete_lez_stack_can_be_deployed_as_one_app() -> Result<(), DynError> {
    let mut world = LezWorld::default();

    world
        .deployment_mut()
        .deploy(LezLocalApp::new().with_bedrock_nodes(2))
        .await?;

    assert_lez_stack_works(&world).await
}

#[tokio::test]
async fn lez_apps_can_be_deployed_individually() -> Result<(), DynError> {
    let mut world = LezWorld::default();

    let bedrock = world
        .deployment_mut()
        .deploy_and_expose(BedrockApp::nodes(2))
        .await?;

    world
        .deployment_mut()
        .deploy_and_expose(IndexerApp::new(bedrock.primary_api_addr()))
        .await?;

    let sequencer = world
        .deployment_mut()
        .deploy_and_expose(SequencerApp::new(
            SequencerPartialConfig::default(),
            bedrock.primary_api_addr(),
        ))
        .await?;

    world
        .deployment_mut()
        .deploy_and_expose(WalletApp::from_sequencer(&sequencer))
        .await?;

    assert_lez_stack_works(&world).await
}

async fn assert_lez_stack_works(world: &LezWorld) -> Result<(), DynError> {
    let bedrock = world.deployment().require::<BedrockCluster>()?;
    let indexer = world.deployment().require::<LezIndexerClient>()?;
    let sequencer = world.deployment().require::<LezSequencerClient>()?;
    let wallet = world.deployment().require::<LezRuntime>()?;

    bedrock.cryptarchia_info().await?;
    sequencer.client().check_health().await?;

    let wallet_account = wallet.first_public_account()?;
    sequencer
        .client()
        .get_account_balance(wallet_account)
        .await?;

    wait_for_indexer_to_catch_up(&indexer, &sequencer).await?;

    Ok(())
}

async fn wait_for_indexer_to_catch_up(
    indexer: &LezIndexerClient,
    sequencer: &LezSequencerClient,
) -> Result<u64, DynError> {
    let target = sequencer.client().get_last_block_id().await?;
    let deadline = Instant::now()
        .checked_add(L2_TO_L1_TIMEOUT)
        .ok_or_else(|| anyhow::anyhow!("indexer catch-up deadline exceeds Instant range"))?;

    loop {
        let last_observed = indexer
            .client()
            .get_last_finalized_block_id()
            .await?
            .unwrap_or(0);
        if last_observed >= target && last_observed > 0 {
            return Ok(last_observed);
        }

        if Instant::now() >= deadline {
            return Err(anyhow::anyhow!(
                "indexer failed to catch up within {L2_TO_L1_TIMEOUT:?}; last observed block was \
                 {last_observed}, target was {target}"
            )
            .into());
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
