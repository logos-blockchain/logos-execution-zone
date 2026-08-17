use std::{path::PathBuf, time::Duration};

use cucumber::gherkin::Step;
use tracing::warn;

use super::super::TARGET;
use crate::{
    config::SequencerPartialConfig,
    cucumber::{
        context::LezScenarioContext,
        error::{StepError, StepResult},
        world::CucumberWorld,
    },
    tf::{BedrockApp, IndexerApp, LezLocalApp, LezSequencerRegistryApp},
};

pub(crate) async fn deploy_lez_stack(
    world: &mut CucumberWorld,
    bedrock: BedrockApp,
    initialize_private_accounts: bool,
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
    let app = LezLocalApp::new()
        .with_bedrock(bedrock)
        .with_scenario_base_dir(scenario_base_dir)
        .with_priority_fee(10_000);
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
        StepError::DeploymentFailed {
            message: format!("{error:?}"),
        }
    })?;

    world.set_lez(LezScenarioContext::from_stack(stack))
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
        .map_err(|error| StepError::DeploymentFailed {
            message: format!(
                "Cucumber step '{}' failed during Bedrock deployment: {error:?}",
                step.value
            ),
        })?;
    bedrock
        .wait_for_first_block()
        .await
        .map_err(|error| StepError::DeploymentFailed {
            message: format!(
                "Cucumber step '{}' failed waiting for Bedrock funding readiness: {error:?}",
                step.value
            ),
        })?;
    let indexer = IndexerApp::new(bedrock.primary_api_addr())
        .with_state_dir(scenario_base_dir.join("lez/indexer"));
    world
        .deployment_mut()
        .deploy_and_expose(indexer)
        .await
        .map_err(|error| StepError::DeploymentFailed {
            message: format!(
                "Cucumber step '{}' failed during indexer deployment: {error:?}",
                step.value
            ),
        })?;
    let sequencer_config = SequencerPartialConfig {
        block_create_timeout: Duration::from_secs(5),
        priority_fee: 10_000,
        ..SequencerPartialConfig::default()
    };
    let registry = LezSequencerRegistryApp::new(sequencer_config, bedrock.primary_api_addr())
        .with_scenario_base_dir(PathBuf::from(&scenario_base_dir));
    world
        .deployment_mut()
        .deploy_and_expose(registry)
        .await
        .map_err(|error| StepError::DeploymentFailed {
            message: format!(
                "Cucumber step '{}' failed during sequencer registry deployment: {error:?}",
                step.value
            ),
        })?;
    let context = crate::cucumber::context::LezSequencerRegistryScenarioContext::from_deployment(
        world.deployment(),
    )?;
    world.set_sequencer_registry(context)
}
