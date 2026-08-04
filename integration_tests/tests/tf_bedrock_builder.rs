#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use integration_tests::tf::{BedrockApp, LezWorld};
use logos_blockchain_testing_framework::{DeploymentBuilder, TopologyConfig};
use testing_framework_core::{scenario::DynError, topology::DeploymentSeed};

#[tokio::test]
async fn bedrock_can_be_deployed_from_a_configured_builder() -> Result<(), DynError> {
    let mut world = LezWorld::default();
    let builder = DeploymentBuilder::new(TopologyConfig::with_node_numbers(2))
        .with_deployment_seed(DeploymentSeed::new([0x4c; 32]))
        .with_test_context("lez-tf-bedrock-builder");

    let bedrock = world
        .deployment_mut()
        .deploy_and_expose(BedrockApp::from_builder(builder))
        .await?;

    bedrock.cryptarchia_info().await?;

    Ok(())
}
