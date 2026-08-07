#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use integration_tests::{
    config::{
        SequencerPartialConfig, default_private_accounts_for_wallet,
        default_public_accounts_for_wallet,
    },
    tf::{
        BedrockApp, BedrockCluster, IndexerApp, LezIndexerClient, LezLocalApp, LezRuntime,
        LezSequencerClient, SequencerApp, WalletApp, shutdown_lez_deployment,
        wait_for_indexer_to_catch_up,
    },
};
use sequencer_service_rpc::RpcClient as _;
use tempfile::tempdir;
use testing_framework_app::{AppHostEnv, AppHostTopology, DeployContext};
use testing_framework_core::scenario::{DynError, NodeClients};

#[tokio::test]
async fn complete_lez_stack_can_be_deployed_as_one_app() -> Result<(), DynError> {
    let mut deployment = new_deployment();

    deployment
        .deploy(LezLocalApp::new().with_bedrock_nodes(2))
        .await?;

    assert_lez_stack_works(&deployment).await?;
    shutdown_lez_deployment(&deployment).await?;
    shutdown_lez_deployment(&deployment).await?;

    Ok(())
}

#[tokio::test]
async fn lez_apps_can_be_deployed_individually() -> Result<(), DynError> {
    let mut deployment = new_deployment();

    let bedrock = deployment.deploy_and_expose(BedrockApp::nodes(2)).await?;

    deployment
        .deploy_and_expose(IndexerApp::new(bedrock.primary_api_addr()))
        .await?;

    let sequencer = deployment
        .deploy_and_expose(SequencerApp::new(
            SequencerPartialConfig::default(),
            bedrock.primary_api_addr(),
        ))
        .await?;

    deployment
        .deploy_and_expose(WalletApp::from_sequencer(&sequencer))
        .await?;

    assert_lez_stack_works(&deployment).await?;
    shutdown_lez_deployment(&deployment).await?;
    shutdown_lez_deployment(&deployment).await?;

    Ok(())
}

#[tokio::test]
async fn lez_services_can_be_redeployed_after_explicit_shutdown() -> Result<(), DynError> {
    let state_dir = tempdir()?;
    let mut bedrock_deployment = new_deployment();
    let bedrock = bedrock_deployment
        .deploy_and_expose(BedrockApp::nodes(2))
        .await?;

    for _ in 0..2 {
        let mut deployment = new_deployment();
        deployment.expose(bedrock.clone())?;
        let bedrock_addr = bedrock.primary_api_addr();
        deployment
            .deploy_and_expose(
                IndexerApp::new(bedrock_addr).with_state_dir(state_dir.path().join("lez/indexer")),
            )
            .await?;
        let sequencer = deployment
            .deploy_and_expose(
                SequencerApp::new(SequencerPartialConfig::default(), bedrock_addr)
                    .with_state_dir(state_dir.path().join("lez/sequencer")),
            )
            .await?;

        bedrock.cryptarchia_info().await?;
        sequencer.client().check_health().await?;
        let indexer = deployment.require::<LezIndexerClient>()?;
        wait_for_indexer_to_catch_up(&indexer, &sequencer).await?;
        shutdown_lez_deployment(&deployment).await?;
    }

    Ok(())
}

fn new_deployment() -> DeployContext<AppHostEnv> {
    DeployContext::new(AppHostTopology, NodeClients::default())
}

async fn assert_lez_stack_works(deployment: &DeployContext<AppHostEnv>) -> Result<(), DynError> {
    let bedrock = deployment.require::<BedrockCluster>()?;
    let indexer = deployment.require::<LezIndexerClient>()?;
    let sequencer = deployment.require::<LezSequencerClient>()?;
    let wallet = deployment.require::<LezRuntime>()?;

    bedrock.cryptarchia_info().await?;
    sequencer.client().check_health().await?;

    let public_accounts = wallet.existing_public_accounts().await?;
    let expected_public_accounts = default_public_accounts_for_wallet()
        .into_iter()
        .map(|(private_key, balance)| {
            (
                lee::AccountId::from(&lee::PublicKey::new_from_private_key(&private_key)),
                balance,
            )
        })
        .collect::<Vec<_>>();
    for (account, _) in &expected_public_accounts {
        assert!(public_accounts.contains(account));
    }

    let private_accounts = wallet.existing_private_accounts().await?;
    let expected_private_accounts = default_private_accounts_for_wallet();
    for account in &expected_private_accounts {
        assert!(private_accounts.contains(&account.account_id()));
    }

    let (wallet_account, expected_balance) = expected_public_accounts
        .first()
        .copied()
        .expect("default public accounts should not be empty");
    assert_eq!(
        sequencer
            .client()
            .get_account_balance(wallet_account)
            .await?,
        expected_balance
    );

    let private_account = expected_private_accounts
        .first()
        .expect("default private accounts should not be empty");
    assert_eq!(
        wallet
            .private_account_balance(private_account.account_id())
            .await?,
        Some(private_account.balance)
    );

    wait_for_indexer_to_catch_up(&indexer, &sequencer).await?;

    Ok(())
}
