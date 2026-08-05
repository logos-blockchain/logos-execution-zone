#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use integration_tests::{
    config::{
        SequencerPartialConfig, default_private_accounts_for_wallet,
        default_public_accounts_for_wallet,
    },
    cucumber::world::CucumberWorld,
    tf::{
        BedrockApp, BedrockCluster, IndexerApp, LezIndexerClient, LezLocalApp, LezRuntime,
        LezSequencerClient, SequencerApp, WalletApp,
    },
};
use sequencer_service_rpc::RpcClient as _;
use testing_framework_core::scenario::DynError;

#[tokio::test]
async fn complete_lez_stack_can_be_deployed_as_one_app() -> Result<(), DynError> {
    let mut world = CucumberWorld::default();

    world
        .deployment_mut()
        .deploy(LezLocalApp::new().with_bedrock_nodes(2))
        .await?;

    assert_lez_stack_works(&world).await?;
    world.stop_runtime().await?;
    world
        .stop_runtime()
        .await
        .map_err(|error| error.to_string().into())
}

#[tokio::test]
async fn lez_apps_can_be_deployed_individually() -> Result<(), DynError> {
    let mut world = CucumberWorld::default();

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

    assert_lez_stack_works(&world).await?;
    world
        .stop_runtime()
        .await
        .map_err(|error| error.to_string().into())
}

async fn assert_lez_stack_works(world: &CucumberWorld) -> Result<(), DynError> {
    let bedrock = world.deployment().require::<BedrockCluster>()?;
    let _indexer = world.deployment().require::<LezIndexerClient>()?;
    let sequencer = world.deployment().require::<LezSequencerClient>()?;
    let wallet = world.deployment().require::<LezRuntime>()?;

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

    Ok(())
}
