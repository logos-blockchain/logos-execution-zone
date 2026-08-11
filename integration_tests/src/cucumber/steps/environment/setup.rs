use cucumber::{gherkin::Step, given};

use super::super::log_step;
use crate::{
    cucumber::{
        error::StepResult, steps::environment::helpers::deploy_lez_stack, world::CucumberWorld,
    },
    tf::BedrockApp,
};

#[given("a LEZ smoke stack")]
async fn deploy_lez_smoke_stack(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    deploy_lez_stack(
        world,
        BedrockApp::nodes_with_blend_core_nodes(1, 0, world.test_context()),
        false,
        step,
    )
    .await
}

#[given("a LEZ private smoke stack")]
async fn deploy_lez_private_smoke_stack(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    deploy_lez_stack(
        world,
        BedrockApp::nodes_with_blend_core_nodes(1, 0, world.test_context()),
        true,
        step,
    )
    .await
}

#[given("a LEZ stack with a multi-node Bedrock cluster")]
async fn deploy_lez_multi_node_stack(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    deploy_lez_stack(
        world,
        BedrockApp::nodes_with_blend_core_nodes(5, 2, world.test_context()),
        false,
        step,
    )
    .await
}

#[given("a LEZ stack with configured public accounts")]
async fn deploy_lez_configured_accounts(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    deploy_lez_stack(
        world,
        BedrockApp::nodes_with_blend_core_nodes(1, 0, world.test_context()),
        false,
        step,
    )
    .await
}

#[given("a LEZ stack with configured private accounts")]
async fn deploy_lez_configured_private_accounts(
    world: &mut CucumberWorld,
    step: &Step,
) -> StepResult {
    log_step(step);
    deploy_lez_stack(
        world,
        BedrockApp::nodes_with_blend_core_nodes(1, 0, world.test_context()),
        true,
        step,
    )
    .await
}
