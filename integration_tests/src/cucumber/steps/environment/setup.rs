use cucumber::{gherkin::Step, given};

use super::super::log_step;
use crate::{
    cucumber::{
        error::StepResult,
        steps::environment::helpers::{deploy_lez_sequencer_registry, deploy_lez_stack},
        world::CucumberWorld,
    },
    testing_framework::BedrockApp,
};

#[given("a LEZ smoke stack")]
#[given("a LEZ stack with configured public accounts")]
async fn deploy_lez_public_stack(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    deploy_lez_stack(
        world,
        BedrockApp::nodes_with_blend_core_nodes(1, 0, world.test_context()),
        false,
        step,
    )
    .await
}

#[given(expr = "a LEZ multi-sequencer environment with {int} validator and {int} Blend nodes")]
async fn deploy_lez_multi_sequencer_environment(
    world: &mut CucumberWorld,
    step: &Step,
    validators: usize,
    blend_core_nodes: usize,
) -> StepResult {
    log_step(step);
    deploy_lez_sequencer_registry(
        world,
        BedrockApp::nodes_with_committee_funding(
            validators,
            blend_core_nodes,
            world.test_context(),
        ),
        step,
    )
    .await
}

#[given("a LEZ private smoke stack")]
#[given("a LEZ stack with configured private accounts")]
async fn deploy_lez_private_stack(world: &mut CucumberWorld, step: &Step) -> StepResult {
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
