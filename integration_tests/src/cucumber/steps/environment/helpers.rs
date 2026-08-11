use cucumber::gherkin::Step;
use log::error;

use crate::{
    cucumber::{
        context::LezScenarioContext,
        error::{StepError, StepResult},
        world::CucumberWorld,
    },
    tf::{BedrockApp, LezLocalApp},
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

    world.deployment_mut().deploy(app).await.map_err(|error| {
        error!(
            "Cucumber step '{}' failed during deployment: {error:?}",
            step.value
        );
        StepError::DeploymentFailed {
            message: format!("{error:?}"),
        }
    })?;

    let context = LezScenarioContext::from_deployment(world.deployment())?;
    world.set_lez(context)
}
