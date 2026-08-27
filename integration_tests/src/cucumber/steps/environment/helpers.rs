use std::{net::SocketAddr, path::PathBuf, time::Duration};

use cucumber::gherkin::Step;
use sequencer_core::config::BedrockConfig;
use tracing::warn;

use super::super::TARGET;
use crate::{
    config::{self, SequencerPartialConfig, UrlProtocol},
    cucumber::{
        context::LezScenarioContext,
        error::{StepError, StepResult},
        world::CucumberWorld,
    },
    testing_framework::{BedrockApp, IndexerApp, LezLocalApp, LezSequencerRegistryApp},
};

/// Bedrock priority fee every Cucumber LEZ deployment publishes with.
const STACK_PRIORITY_FEE: u64 = 10_000;

/// Bedrock channel-read configuration for the deployed stack, shared by every
/// step that reads channel state directly. Sourced from the same fixtures the
/// stack deploys with — including [`STACK_PRIORITY_FEE`] — so the reads cannot
/// drift from the deployment.
pub(crate) fn bedrock_read_config(
    bedrock_api_addr: SocketAddr,
) -> Result<BedrockConfig, StepError> {
    Ok(BedrockConfig {
        channel_id: config::bedrock_channel_id(),
        node_url: config::addr_to_url(UrlProtocol::Http, bedrock_api_addr)
            .map_err(|source| StepError::QueryFailedSource { source })?,
        funding_key: config::bedrock_funding_key(),
        auth: None,
        priority_fee: STACK_PRIORITY_FEE,
    })
}

/// Base sequencer configuration for Cucumber LEZ deployments: framework
/// defaults plus the stack-wide Bedrock priority fee. Scenario configs start
/// from this base, so every field they set is honored as-is.
pub(crate) fn base_sequencer_config() -> SequencerPartialConfig {
    SequencerPartialConfig {
        priority_fee: STACK_PRIORITY_FEE,
        ..SequencerPartialConfig::default()
    }
}

pub(crate) async fn deploy_lez_stack(
    world: &mut CucumberWorld,
    bedrock: BedrockApp,
    initialize_private_accounts: bool,
    step: &Step,
) -> StepResult {
    deploy_lez_stack_with_config(world, bedrock, initialize_private_accounts, None, step).await
}

pub(crate) async fn deploy_lez_stack_with_config(
    world: &mut CucumberWorld,
    bedrock: BedrockApp,
    initialize_private_accounts: bool,
    sequencer_config: Option<SequencerPartialConfig>,
    step: &Step,
) -> StepResult {
    if world.lez.is_some() {
        return Err(StepError::FixtureAlreadyDeployed);
    }

    let entropy = world
        .test_context
        .clone()
        .unwrap_or_else(|| "unknown-time".to_owned());
    let scenario_base_dir = world.scenario_base_dir.join(entropy);
    let sequencer_config = sequencer_config.unwrap_or_else(base_sequencer_config);
    let app = LezLocalApp::new()
        .with_bedrock(bedrock)
        .with_scenario_base_dir(scenario_base_dir)
        .with_sequencer_config(sequencer_config);
    let app = if initialize_private_accounts {
        app
    } else {
        // The public smoke scenario deliberately exercises only the
        // public-account path. The private smoke scenario uses the default
        // fixture so private-account initialization is covered separately.
        app.without_private_account_initialization()
    };

    let stack = world.deployment_mut().deploy(app).await.map_err(|error| {
        warn!(target: TARGET,
            "Cucumber step '{}' failed during deployment: {error:?}",
            step.value
        );
        StepError::deployment_failed_boxed(error, "Cucumber LEZ stack deployment failed")
    })?;

    world.set_lez(LezScenarioContext::from_stack(stack, sequencer_config))
}

pub(crate) async fn deploy_lez_sequencer_registry(
    world: &mut CucumberWorld,
    bedrock: BedrockApp,
    step: &Step,
) -> StepResult {
    if world.lez.is_some() || world.sequencer_registry.is_some() {
        return Err(StepError::FixtureAlreadyDeployed);
    }
    let entropy = world
        .test_context
        .clone()
        .unwrap_or_else(|| "unknown-time".to_owned());
    let scenario_base_dir = world.scenario_base_dir.join(entropy);
    let bedrock = world
        .deployment_mut()
        .deploy_and_expose(bedrock.with_scenario_base_dir(scenario_base_dir.join("node")))
        .await
        .map_err(|error| {
            StepError::deployment_failed_boxed(
                error,
                format!(
                    "Cucumber step '{}' failed during Bedrock deployment",
                    step.value
                ),
            )
        })?;
    bedrock.wait_for_first_block().await.map_err(|error| {
        StepError::deployment_failed_boxed(
            error,
            format!(
                "Cucumber step '{}' failed waiting for Bedrock funding readiness",
                step.value
            ),
        )
    })?;
    let indexer = IndexerApp::new(bedrock.primary_api_addr())
        .with_state_dir(scenario_base_dir.join("lez/indexer"));
    world
        .deployment_mut()
        .deploy_and_expose(indexer)
        .await
        .map_err(|error| {
            StepError::deployment_failed_boxed(
                error,
                format!(
                    "Cucumber step '{}' failed during indexer deployment",
                    step.value
                ),
            )
        })?;
    let sequencer_config = SequencerPartialConfig {
        block_create_timeout: Duration::from_secs(5),
        ..base_sequencer_config()
    };
    let registry = LezSequencerRegistryApp::new(sequencer_config, bedrock.primary_api_addr())
        .with_scenario_base_dir(PathBuf::from(&scenario_base_dir));
    world
        .deployment_mut()
        .deploy_and_expose(registry)
        .await
        .map_err(|error| {
            StepError::deployment_failed_boxed(
                error,
                format!(
                    "Cucumber step '{}' failed during sequencer registry deployment",
                    step.value
                ),
            )
        })?;
    let context = crate::cucumber::context::LezSequencerRegistryScenarioContext::from_deployment(
        world.deployment(),
    )?;
    world.set_sequencer_registry(context)
}
